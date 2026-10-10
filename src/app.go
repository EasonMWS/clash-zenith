package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	AppName    = "Zenith"
	AppVersion = "1.3.1"

	// coreStartGrace is how long the watchdog waits before it decides the core
	// is broken. A first run against an empty data directory downloads the rule
	// databases, which on a slow link takes a couple of minutes.
	coreStartGrace = 4 * time.Minute

	// coreRestartDelay is the much shorter window applied once a core has already
	// answered in this run. Long enough that a deliberate restart is not fought
	// over, short enough that a machine is not left offline for minutes.
	coreRestartDelay = 20 * time.Second
)

// ---------------------------------------------------------------------------
// App: ties the store, the core, the optimiser and the system proxy together.
// ---------------------------------------------------------------------------

type App struct {
	store    *Store
	core     *Core
	opt      *Optimizer
	sysproxy *SystemProxy

	dataDir    string
	logDir     string
	rootDir    string
	configPath string
	secret     string
	dnsPort    int
	// adoptedCorePID is a core this installation owns that this process did not
	// start - typically the one an elevated activation left running. Zero means
	// none.
	adoptedCorePID int
	// approvalWaitStart is when this process began waiting for the Windows
	// permission prompt. The interface counts from it, so the wait is a number on
	// screen rather than an open-ended promise.
	approvalWaitStart time.Time
	// helperPID is the elevated helper this process started, so a cancel can
	// stop it. Zero when there is none.
	helperPID int
	// proxyClearedAtStartup records that this run found a leftover proxy of ours
	// pointing at a dead port and cleared it, so the interface can say why the
	// setting changed from what the user last saw.
	proxyClearedAtStartup bool
	// coreStartedAt is when this process last started a core, so a port that is
	// not bound yet can be told apart from a port nothing will ever serve.
	coreStartedAt time.Time
	// coreEverCameUp records that a core has answered at least once in this run.
	// It is what separates a first start, which needs a long grace period
	// because a fresh data directory downloads its rule databases, from a
	// core that died after working, which needs to be replaced promptly.
	coreEverCameUp bool

	mu         sync.Mutex
	optimizing bool
	lastErr    string
	// pending auto-pick: a marginal win has to persist before it is acted on
	pickCandidate string
	pickSince     time.Time
	pickWatching  bool
	// the user's most recent deliberate node choice, respected for a while
	userPicked   string
	userPickedAt time.Time
	// why the last auto-pick declined to act, surfaced through the API
	lastPickDebug string

	// ---- health state -------------------------------------------------------
	//
	// These live behind healthView, published by healthLoop and read by everyone
	// else, rather than in maps that several goroutines touch directly.
	//
	// The earlier layout had healthLoop writing healthBanned and nodeFlaky under
	// the mutex while enforceFastest read them without it and the status handler
	// handed the raw map to the JSON encoder. A map read that overlaps a write is
	// a fatal runtime error in Go that recover cannot catch, so any of those
	// overlaps would take the whole process down - the exact "it just died"
	// failure this client is supposed to survive.
	healthFails  int
	healthLastAt time.Time
	healthLastEv string
	// consecutive measurements over slowNodeMS; two in a row triggers a switch
	slowStrikes int
	// how many forced switches happened without a successful check in between;
	// several in a row means the pool is stale, not just the current node
	healthSwitches int
	// when the last health-triggered rescan started, so rescans cannot loop
	lastHealthRescan time.Time
	// node name -> when it was last found dead
	healthBanned map[string]time.Time
	// node name -> how often it has failed a liveness check
	nodeFlaky map[string]int
	// healthView is an immutable snapshot of the two maps above, swapped whole.
	// Readers only ever load the pointer, so there is no map to race on.
	healthView atomic.Value // *healthSnapshot

	quitting    bool
	stopCh      chan struct{}
	onQuit      func()
	trafficSnap Connections

	// tunRun is the progress of an enable attempt, so the interface can show which
	// step it is on rather than an indeterminate spinner. Guarded by mu.
	tunRun *tunRun
}

func NewApp(rootDir string) (*App, error) {
	dataDir := filepath.Join(rootDir, "data")
	logDir := filepath.Join(rootDir, "logs")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	InitLog(logDir)

	// The rule databases ship with the repository, but a truncated copy (or a
	// clone that predates them) must be repaired before the core starts,
	// otherwise mihomo sits in a download loop and never comes up.
	if err := ensureGeodata(dataDir); err != nil {
		Log("geodata check: %v", err, "WARN")
	}

	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	st := store.Settings()

	// The control secret is owned by the data directory, not by this process.
	//
	// It used to be generated fresh on every start. That is fine for strength and
	// fatal for a handover: an elevated helper is a separate process reading the
	// same data directory, so it generated its own secret and the ordinary instance
	// was left holding one that no longer matched the running core - which is the
	// review's finding that a core can be up and still be called unavailable.
	//
	// Read once, here, and passed to everything that needs it, so there is exactly
	// one value for this data directory.
	secret, err := loadOrCreateSecret(dataDir)
	if err != nil {
		return nil, err
	}

	app := &App{
		store:      store,
		dataDir:    dataDir,
		rootDir:    rootDir,
		logDir:     logDir,
		configPath: filepath.Join(dataDir, "config.yaml"),
		// A cryptographic secret, not a timestamp. The control API is the one thing
		// that can reconfigure the core, and the previous value was
		// time.Now().UnixNano()%1_000_000 - a guessable value with a space of a
		// million, which a local process could brute force in seconds.
		secret:  secret,
		dnsPort: st.MixedPort + 300,
		stopCh:  make(chan struct{}),
	}
	app.core = NewCore(filepath.Join(rootDir, "core", "mihomo.exe"),
		dataDir, app.configPath, app.secret, st.ControlPort)
	app.opt = NewOptimizer(dataDir)
	app.sysproxy = NewSystemProxy(dataDir)
	return app, nil
}

func goVersion() string { return runtime.Version() }

// rebindDirs points the whole application at a different data directory and
// rebuilds everything that had the old path baked in.
//
// This exists so a test run can never touch the real data directory, ports or
// the registry: the store, the core, the optimiser and the system proxy helper
// are all replaced, not merely reconfigured.
func (a *App) rebindDirs(dataDir string) {
	store, err := NewStore(dataDir)
	if err != nil {
		Log("rebind failed: %v", err, "ERR")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store = store
	a.dataDir = dataDir
	a.configPath = filepath.Join(dataDir, "config.yaml")
	// The secret belongs to the directory, so a rebind reads the new one rather
	// than carrying the old secret into a tree it does not belong to.
	if s, err := loadOrCreateSecret(dataDir); err == nil {
		a.secret = s
	}
	st := store.Settings()
	a.dnsPort = st.MixedPort + 300
	// the core always lives next to the executable, never inside the data dir
	a.core = NewCore(filepath.Join(a.rootDir, "core", "mihomo.exe"),
		dataDir, a.configPath, a.secret, st.ControlPort)
	a.opt = NewOptimizer(dataDir)
	a.sysproxy = NewSystemProxy(dataDir)
	// Tell the dead-proxy guard which port is ours before anything can call it.
	//
	// Without this the guard cannot tell a registry entry pointing at a port we are
	// about to serve from one pointing at a port nothing will ever serve, so it
	// treats a core that has not started yet as a broken proxy and disables it. That
	// is what happened after a reboot: at 19:54:03 the proxy was disabled because the
	// core had not come up, and the machine had no internet until the core was
	// started by an elevated activation four minutes later.
	a.sysproxy.SetExpectedPort(st.MixedPort)
}

// ensureNotOfflineBecauseOfUs takes this program's own dead port out of the system
// proxy setting.
//
// The narrowest possible version of the idea, on purpose. It acts only when all of
// these hold:
//
//   - the core is not running, so the port it was serving is certainly dead;
//   - the system proxy is enabled and points at exactly the port this program is
//     configured to use, so the setting is ours and not another program's;
//   - that port has no listener, so nothing else has taken it over.
//
// Under those conditions the setting can only make the machine worse: every
// application that honours it is trying to reach a port with nothing behind it. It
// is cleared, and the reason is logged, because a user whose proxy just turned itself
// off is owed an explanation.
//
// It does NOT touch a proxy setting pointing anywhere else. Another program's
// configuration is not this program's to change, the same way another program's
// adapter is not ours to remove.
func (a *App) ensureNotOfflineBecauseOfUs() {
	sp := NewSystemProxy(a.dataDir)
	st := sp.Status()
	if !st.Enabled || st.Server == "" {
		return
	}
	port := portFromServer(st.Server)
	want := a.store.Settings().MixedPort
	if port == 0 || port != want {
		return // somebody else's setting
	}
	if portHasListener(port) {
		return // something is serving it after all
	}
	Log("core is down and the system proxy points at its dead port %d; "+
		"clearing the setting so the machine stays online", port, "WARN")
	sp.Disable()
	if _, err := a.store.UpdateSettings(map[string]interface{}{"systemProxy": false}); err != nil {
		Log("could not record that the system proxy was cleared: %v", err, "WARN")
	}
	a.lastErr = fmt.Sprintf("内核没有起来，已暂时关闭系统代理以免断网（端口 %d 没有响应）", port)
}

// ---- geodata bootstrap ----------------------------------------------------

// geodataFiles are the rule databases mihomo needs for GEOSITE / GEOIP rules.
// They ship with the repository so a fresh clone starts in a second instead of
// waiting on a download.
var geodataFiles = map[string]int64{
	"GeoSite.dat":  1 << 20, // 1 MB - the real file is ~4 MB
	"geoip.metadb": 1 << 20, // 1 MB - the real file is ~8 MB
}

// geodataMirrors are tried in order. mihomo itself fetches from GitHub, which
// times out on many networks (measured here: 40 s and zero bytes), so Zenith
// fetches through a mirror instead and only falls back to letting the core try.
var geodataMirrors = []string{
	"https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/%s",
	"https://ghproxy.net/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/%s",
}

// ensureGeodata makes sure the rule databases exist and are complete.
//
// A previous version only checked whether the files existed, so a truncated
// download (a 0-byte GeoSite.dat left behind by an interrupted run) kept mihomo
// in a download-retry loop and the core never came up.
func ensureGeodata(dataDir string) error {
	var missing []string
	for name, minSize := range geodataFiles {
		p := filepath.Join(dataDir, name)
		st, err := os.Stat(p)
		if err == nil && st.Size() >= minSize {
			continue
		}
		if err == nil {
			Log("%s is only %d bytes (truncated), removing it", name, st.Size(), "WARN")
			_ = os.Remove(p)
		}
		missing = append(missing, name)
	}
	if len(missing) == 0 {
		return nil
	}
	Log("first run: fetching %d rule database(s), this takes a few seconds", len(missing))
	for _, name := range missing {
		dest := filepath.Join(dataDir, name)
		if err := downloadGeodata(name, dest); err != nil {
			Log("could not fetch %s: %v", name, err, "WARN")
			// let the core try on its own; it may work on this network
			continue
		}
		if st, err := os.Stat(dest); err == nil {
			Log("%s ready (%d KB)", name, st.Size()/1024)
		}
	}
	return nil
}

func downloadGeodata(name, dest string) error {
	for _, pattern := range geodataMirrors {
		url := fmt.Sprintf(pattern, name)
		if err := downloadFile(url, dest); err != nil {
			Log("mirror failed for %s: %v", name, err, "WARN")
			continue
		}
		if st, err := os.Stat(dest); err == nil && st.Size() >= geodataFiles[name] {
			return nil
		}
		_ = os.Remove(dest)
	}
	return fmt.Errorf("所有镜像都失败了")
}

// downloadFile streams a URL to a file, writing to a temporary name first so an
// interrupted download can never leave a half written file behind.
func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	cerr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return cerr
	}
	if n == 0 {
		_ = os.Remove(tmp)
		return fmt.Errorf("收到 0 字节")
	}
	return os.Rename(tmp, dest)
}

// ---- settings translation ---
// copyPatch clones a settings patch so translating a key cannot mutate the
// caller's map.
func copyPatch(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ---- startup --------------------------------------------------------------

// Boot prepares the config and starts the core in the BACKGROUND.
//
// It deliberately does not block on the core: a fresh install has to unpack the
// geodata files on first run and that can take up to a minute. The window must
// appear immediately so the user sees progress instead of a frozen app.
func (a *App) Boot() {
	a.EnsureUsablePort()
	snap := a.store.Snapshot()
	st := snap.Settings

	a.writeConfig(a.mergedNodes(), st)
	go a.bootCore()
}

// coreOwnsDataDir reports whether a process is a mihomo belonging to this
// installation, judged by its command line naming this data directory.
//
// The test is the same one the orphan sweep uses, and for the same reason: the
// executable is called mihomo.exe for every client that ships one, so the name
// proves nothing. The data directory is what distinguishes our core from another
// product's or another installation's.
func coreOwnsDataDir(pid int, dataDir, rootDir string) bool {
	if pid <= 0 {
		return false
	}
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`(Get-CimInstance Win32_Process -Filter "ProcessId=%d" `+
			`-ErrorAction SilentlyContinue).CommandLine`, pid))
	if err != nil {
		return false
	}
	cmd := strings.ToLower(out)
	if cmd == "" {
		return false
	}
	want := strings.ToLower(filepath.ToSlash(dataDir))
	return strings.Contains(cmd, want) ||
		(dataDir != "" && strings.Contains(cmd, strings.ToLower(dataDir)))
}

// adoptRunningCore records that a core this installation owns is already running
// and is not this process's child.
//
// What that changes: the core cannot be stopped or restarted by this process, so
// anything that would do so must go through whatever started it - the resident
// service, or the elevated activation that is still finishing. Recording it means
// the rest of the program can tell "there is no core" from "there is a core I did
// not start", which are very different situations and were previously the same.
func (a *App) adoptRunningCore(pid int) {
	a.mu.Lock()
	a.adoptedCorePID = pid
	a.mu.Unlock()
	// The core answers on the configured port, so point the API client at the port
	// the settings name rather than inventing one.
	Log("adopted a running core (pid %d) on port %d; this process will not restart it",
		pid, a.store.Settings().MixedPort)
}

// EnsureUsablePort makes sure the mixed port is genuinely ours before the core
// starts.
//
// mihomo sets SO_REUSEADDR, so if another proxy already listens on 7890 it will
// bind anyway and the two then share incoming connections. That is silent and
// very confusing: half the traffic goes through a proxy the user did not choose.
// When the port is taken, Zenith moves itself aside and updates the system proxy
// to match.
func (a *App) EnsureUsablePort() {
	st := a.store.Settings()
	want := st.MixedPort
	if want <= 0 {
		want = 7890
	}
	if PortFreeToBind(want) {
		return
	}

	// PortFreeToBind can fail for reasons that are not "someone else has it":
	// a core that just exited keeps its socket in a lingering state for a
	// moment. Rotating the port in that case is actively harmful, because every
	// program that stored the old port - including the system proxy setting the
	// user's browser reads - silently loses its connection. So before giving up
	// on the configured port, check the real listener table and wait briefly for
	// the old owner to finish dying.
	if !portHasListener(want) {
		for i := 0; i < 20; i++ {
			time.Sleep(300 * time.Millisecond)
			if PortFreeToBind(want) {
				Log("mixed port %d was briefly busy but is ours again; keeping it", want)
				return
			}
			if portHasListener(want) {
				break // a real foreign program has it after all
			}
		}
	}

	// If the listener on the port is a core this installation owns, the correct
	// response is to adopt it, not to move aside.
	//
	// This case is not hypothetical and it is not a conflict. An activation needs
	// the rights to create the adapter, so the core that ends up holding the
	// configured port is the one the elevated helper started - and the interface
	// that starts afterwards finds its own core sitting on its own port. Rotating
	// there produces the state this was observed in: the tunnel up and carrying
	// traffic on the configured port, the settings pointing at a different one, and
	// the system proxy unable to follow because nothing was listening on the new
	// port yet. The tunnel worked and the program disagreed with itself.
	//
	// Ownership is established by the command line naming this data directory, which
	// is the same test the orphan sweep uses. A core belonging to another
	// installation, or another product, does not match and still gets the rotation.
	if pids := ListeningPids(want); len(pids) > 0 {
		for _, pid := range pids {
			if coreOwnsDataDir(pid, a.dataDir, a.rootDir) {
				Log("mixed port %d is held by this installation's own core (pid %d); "+
					"adopting it rather than moving aside", want, pid)
				// The core may be the one started by an elevated helper, which this
				// process cannot manage. Recording ownership means the rest of the
				// program asks the right thing rather than starting a second core on
				// top of a working one.
				a.adoptRunningCore(pid)
				return
			}
		}
	}

	// If the thing sitting on the port is another Zenith instance, this process
	// has no business running at all; the UI port check catches that case, so
	// reaching here means a foreign proxy holds it.
	var free int
	for p := want + 9; p <= want+99 && free == 0; p++ {
		if PortFreeToBind(p) {
			free = p
		}
	}
	if free == 0 {
		Log("mixed port %d is taken and no alternative was free; leaving it as is", want, "WARN")
		return
	}
	Log("mixed port %d is already in use by another program; moving Zenith to %d", want, free, "WARN")
	if _, err := a.store.UpdateSettings(map[string]interface{}{"mixedPort": free}); err != nil {
		Log("could not persist the new mixed port: %v", err, "WARN")
		return
	}
	// The system proxy has to follow the port. It did not, and the result was the
	// worst outcome this program can produce: the registry kept pointing at the
	// port nothing was listening on, so every application that honours the system
	// proxy was silently offline while the interface still reported the proxy as
	// on.
	//
	// Only a proxy this instance owns is repointed. Someone else's is left alone
	// and the user is told, because taking over another client's setting is worse
	// than leaving it.
	if st.SystemProxy {
		sp := NewSystemProxy(a.dataDir)
		owner := systemProxyOwner(a.dataDir)
		if sp.Status().Enabled && proxyOwnerIsOurs(owner) {
			if _, err := sp.Enable(free, st.ProxyBypass, true); err != nil {
				Log("mixed port moved to %d but the system proxy could not follow: %v", free, err, "ERR")
			} else {
				Log("system proxy followed the mixed port to %d", free)
			}
		} else if owner != "" {
			Log("mixed port moved to %d but the system proxy belongs to %q; leaving it "+
				"alone. Applications using it are offline until it is repointed or disabled",
				free, owner, "WARN")
			a.lastErr = fmt.Sprintf("端口 %d 被占用，已改用 %d。系统代理属于 %s，我没有改动它"+
				"——请手动把代理端口改成 %d，或关掉系统代理", want, free, owner, free)
			return
		}
	}
	a.lastErr = fmt.Sprintf("端口 %d 已被其他程序占用，已自动改用 %d（旧端口上的连接会断开，重启一下浏览器即可）", want, free)
}

// proxyOwnerIsOurs reports whether the current system proxy setting appears to be
// ours, so a port change may repoint it.
//
// An empty owner means the port has no listener, which is the case this whole
// path exists for. A named owner that is not us means another product holds the
// setting, and taking it over would be worse than leaving it: the user would
// silently lose the client they chose.
func proxyOwnerIsOurs(owner string) bool {
	if owner == "" {
		return true
	}
	return strings.EqualFold(owner, "zenith") || strings.EqualFold(owner, "mihomo")
}

// portHasListener reports whether something is really listening on the port,
// according to the OS rather than to a bind attempt.
func portHasListener(port int) bool {
	return len(ListeningPids(port)) > 0
}

func (a *App) bootCore() {
	st := a.store.Settings()
	// Ask who owns the core before starting one.
	//
	// This path used to start a core unconditionally. When the resident service already
	// held one - which is the whole point of the service - that produced a second core
	// on a rotated port, and the two then disagreed about the configuration and about
	// which port the system proxy should point at. The user sees a window that reports
	// a dead core while the machine is online, or the reverse, depending on which of
	// the two answered last.
	//
	// StartCoreThroughOwner starts one only when nobody else holds it, and asks the
	// service when the service is the owner.
	a.mu.Lock()
	a.coreStartedAt = time.Now()
	a.mu.Unlock()
	if err := a.StartCoreThroughOwner(nil, ""); err != nil {
		a.lastErr = err.Error()
		Log("core start failed: %v", err, "ERR")
		fmt.Fprintf(os.Stderr, "Zenith: core start failed: %v\n", err)
		// the UI stays open so the user can add a subscription or read the log
		return
	}
	a.lastErr = ""
	if a.store.Settings().SystemProxy {
		if _, err := a.sysproxy.Enable(st.MixedPort, st.ProxyBypass, false); err != nil {
			Log("system proxy not enabled: %v", err, "WARN")
		}
	}
	if st.OptimizeOnStart && len(a.store.Snapshot().Optimized) == 0 {
		a.StartOptimize()
	}
}

// noteCoreCameUp records that a core has answered in this run, so the long first-start
// grace period stops applying.
func (a *App) noteCoreCameUp() {
	a.mu.Lock()
	a.coreEverCameUp = true
	a.mu.Unlock()
}

// background runs the housekeeping loop: core watchdog, dead proxy guard,
// scheduled subscription refresh and scheduled optimisation.
func (a *App) background() {
	started := time.Now()
	lastSub := time.Now()
	lastOpt := time.Now()
	// Latch on whether the proxy is ALREADY ours at startup, rather than
	// assuming it is not. A normal shutdown hands the registry back or turns it
	// off, so on the next launch it must be taken again - but if a previous
	// instance is somehow still holding it, re-arming would fight over it.
	proxyArmed := a.sysproxy.Status().Owner == "zenith"
	if proxyArmed {
		Log("system proxy is already Zenith's; leaving it in place")
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
		}
		st := a.store.Settings()

		// An activation that has claimed the core owns it for the duration. This
		// instance steps back entirely: no core recovery, no liveness checking, no
		// switching, because all of those act on a core that is about to be
		// replaced. Checking this before the core is touched rather than after is
		// the point - doing either is what made the first real TUN attempt hang,
		// with the two instances spending the handover killing and restarting each
		// other's core.
		if a.activationYielded() {
			continue
		}

		// Track whether this core has ever answered, so the grace period can be told
		// apart from a failure. Set here rather than only after a recovery, because
		// the core that bootCore started also counts.
		if a.coreEverCameUp {
			// already known
		} else if a.core.IsUp() {
			a.noteCoreCameUp()
		}

		if !a.core.IsUp() {
			// Give the core room to finish its FIRST start. A brand new data
			// directory has no rule databases yet, so mihomo downloads them and that
			// takes far longer than the health check interval. Restarting it
			// mid-download looped forever, because every restart began the same
			// download again and the core never got to answer.
			//
			// But that reasoning only applies to a core that has never answered. Once
			// a core has been up in this run, a core that is down is a core that died,
			// and four minutes is not a grace period for that - it is four minutes of
			// the machine being offline while the proxy setting points at a port with
			// nothing behind it.
			//
			// Measured: the core died at 22:11:02 and the watchdog restarted it at
			// 22:13:56, because the grace period was measured from process start rather
			// than from the failure. Nearly three minutes, for no reason that applies
			// to a core that had already been serving.
			if !a.coreEverCameUp {
				if time.Since(started) < coreStartGrace {
					continue
				}
			} else if time.Since(started) < coreRestartDelay {
				// A short delay so a core that is being deliberately restarted - by a
				// settings change, by an activation - is not fought over.
				continue
			}
			// Only this process may recover a core it started. When the service owns
			// it, a window that restarted the core itself would be creating the second
			// core this design exists to prevent - and it would do it precisely when the
			// service is already dealing with the same problem.
			if a.coreOwnerNow() == ownerService {
				if a.serviceReachable() {
					a.lastErr = ""
				}
				continue
			}
			// Recovery, and then the part that was missing.
			//
			// A dead core was restarted here and nowhere was it asked what happened to
			// the system proxy in the meantime. Measured: the core exited at 21:59:46,
			// the registry still said `ProxyEnable=1` pointing at the port the core had
			// been using, and every application that honours the system proxy was
			// offline. The program's own interface showed the proxy as on, because the
			// registry said so. Recovery that only restarts the core leaves the machine
			// unusable for as long as it takes, and leaves it permanently unusable if
			// the restart keeps failing.
			//
			// So: bring the core back, and if it does not come back, take the dead port
			// out of the registry. Being online without a proxy is a worse experience
			// than being online through one, and it is enormously better than being
			// offline while a checkbox says otherwise.
			if a.core.Ensure() {
				a.lastErr = ""
				a.noteCoreCameUp()
				continue
			}
			a.ensureNotOfflineBecauseOfUs()
		}
		// take the system proxy once, as soon as the core is really listening.
		// Enable returns early when the proxy is already ours, so the flag is set
		// only on success - otherwise this line repeated every 10 seconds.
		if !proxyArmed && st.SystemProxy && a.core.IsUp() {
			if took, err := a.sysproxy.Enable(st.MixedPort, st.ProxyBypass, false); err != nil {
				Log("system proxy not enabled: %v", err, "WARN")
			} else if took {
				proxyArmed = true
			}
		}
		// re-arm when the user flips the switch back on in the UI
		if proxyArmed && !st.SystemProxy {
			proxyArmed = false
		}
		a.sysproxy.GuardDeadProxy()

		// Rank-based switching waits for a scan to finish, because a scan is
		// about to replace the numbers this would rank by.
		//
		// Keep the fastest verified node in use. The core's own url-test only
		// knows whether a node answers a 204 probe; Zenith knows the real
		// WebSocket handshake time it measured. This reuses that measurement so
		// "自动" means the fastest node Zenith actually proved, not the fastest
		// one that happens to answer a ping.
		if !st.AutoPickOff && a.core.IsUp() {
			if a.opt.Running() {
				a.pickDebug(10, "a scan is running; waiting for fresh measurements before re-ranking")
			} else if picked, changed := a.enforceFastest(); changed {
				Log("auto-pick: switched to the fastest verified node %q (%.0fms)", picked.Name, picked.delay)
			}
		}

		if st.SubscriptionAutoUpdate {
			due := lastSub.Add(time.Duration(st.SubscriptionIntervalHours) * time.Hour)
			if time.Now().After(due) {
				lastSub = time.Now()
				if id := a.store.ActiveSubscription(); id != "" {
					if _, err := a.UpdateSubscription(id); err != nil {
						Log("scheduled subscription refresh failed: %v", err, "WARN")
					}
				}
			}
		}
		if st.AutoOptimize && !a.opt.Running() && a.core.IsUp() {
			due := lastOpt.Add(time.Duration(st.OptimizeIntervalMin) * time.Minute)
			if time.Now().After(due) {
				lastOpt = time.Now()
				a.StartOptimize()
			}
		}
	}
}

// pickDebug records why auto-pick declined to act, and keeps it in the log at a
// low frequency. Without this, "auto-pick did nothing" is indistinguishable
// from "auto-pick is broken".
func (a *App) pickDebug(code int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	a.mu.Lock()
	line := fmt.Sprintf("auto-pick skip #%d: %s", code, msg)
	changed := line != a.lastPickDebug
	a.lastPickDebug = line
	a.mu.Unlock()
	if changed {
		Log("%s", line)
	}
}

// reactToSlowness moves off a node whose measured round trip has degraded.
//
// Ranking alone cannot catch this. Auto-pick compares nodes against each other,
// so when every node gets slower - which is exactly what happens when the
// network, not the node, is having a bad hour - the fastest of a bad set still
// wins and nothing changes. This compares the node against an absolute bar
// instead, and falls back to the hostname node because it is the one option that
// does not depend on any single address still being reachable.
func (a *App) reactToSlowness(current string, delay float64) {
	if delay < slowNodeMS {
		a.mu.Lock()
		// A fast measurement clears the count: the bar is about sustained
		// slowness, not about accumulating unrelated hiccups.
		a.slowStrikes = 0
		a.mu.Unlock()
		return
	}

	a.mu.Lock()
	// One slow measurement is noise; the bar is deliberately generous, so
	// crossing it twice in a row means something real.
	//
	// The counter must survive between calls for that to mean anything. An
	// earlier version reset it to zero in this same critical section - before the
	// threshold check - so strikes was always 1, the comparison below never
	// passed, and this whole function was dead code.
	a.slowStrikes++
	strikes := a.slowStrikes
	if strikes < slowStrikesNeeded {
		a.mu.Unlock()
		return
	}
	tooSoon := time.Since(a.healthLastAt) < healthRetryDelay
	if !tooSoon {
		// Reset only when the switch is actually going to happen, so a retry
		// delay does not silently consume the evidence.
		a.slowStrikes = 0
	}
	a.mu.Unlock()

	if tooSoon {
		return
	}

	optimized, _ := a.nodeSet()
	// Prefer the hostname node: a node that is merely far away is a worse bet
	// than one that follows Cloudflare's routing.
	target := ""
	for _, p := range optimized {
		if p.OriginNode && p.Name != current {
			target = p.Name
			break
		}
	}
	if target == "" {
		// Otherwise take the best-ranked alternative, which is the one the last
		// scan verified fastest after the reliability penalty.
		for _, p := range optimized {
			if p.Name != current && p.MeasuredMS > 0 {
				target = p.Name
				break
			}
		}
	}
	if target == "" {
		return
	}

	Log("health: %q measured %.0fms which is over the %dms bar; switching to %q",
		current, delay, slowNodeMS, target, "WARN")
	if err := a.core.Select("PROXY", target); err != nil {
		Log("health: slow-node switch failed: %v", err, "ERR")
		return
	}
	a.core.CloseConnections()
	_ = a.store.SetCurrent(target)
	a.mu.Lock()
	a.healthLastAt = time.Now()
	a.healthLastEv = fmt.Sprintf("%s was %.0fms, switched to %s", current, delay, target)
	a.mu.Unlock()
}

// healthLoop runs the liveness check on its own fast timer.
//
// It is deliberately separate from background(): the housekeeping tick is ten
// seconds and also carries subscription refreshes and proxy guards, none of
// which should delay noticing that the node in use has stopped answering.
func (a *App) healthLoop() {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
		}
		if a.store.Settings().AutoPickOff || !a.core.IsUp() {
			continue
		}
		a.healthCheck()
	}
}

// healthCheck measures the node that is actually in use and moves off it when
// it stops working.
//
// This exists because ranking alone is not enough. An edge that passed the
// WebSocket probe during the last scan can be unreachable an hour later, and
// ranking by stale numbers will happily keep sending traffic into a black hole.
// That is exactly what happened once: every foreign site timed out for minutes
// while auto-pick reported "already on the fastest node", because "fastest"
// was based on a measurement that was no longer true.
func (a *App) healthCheck() {
	optimized, _ := a.nodeSet()
	if len(optimized) < 1 {
		return
	}
	proxies, err := a.core.Proxies()
	if err != nil {
		return
	}
	current := ""
	if g, ok := proxies["PROXY"]; ok {
		current = g.Now
	}
	if current == "" {
		return
	}

	// A pass-through node the user picked by hand is not ours to judge.
	isOptimised := false
	for _, p := range optimized {
		if p.Name == current {
			isOptimised = true
			break
		}
	}
	if !isOptimised {
		return
	}

	delay, derr := a.core.Delay(current, healthTimeoutMS, "")
	if derr == nil && delay > 0 {
		a.mu.Lock()
		if a.healthFails > 0 {
			Log("health: %q is answering again (%dms)", current, delay)
		}
		a.healthFails = 0
		a.healthSwitches = 0
		a.healthLastEv = fmt.Sprintf("%s ok %dms", current, delay)
		a.mu.Unlock()

		// Answering is not the same as answering well. A node can stay reachable
		// while its real round trip degrades several times over, and ranking by
		// numbers measured half an hour ago will not notice. This is the check
		// that turns "delayed" into "switched".
		a.reactToSlowness(current, float64(delay))
		return
	}

	// A single failed probe is not a dead node.
	//
	// Measured over a three-hour run, and this is the defect the user reported as the
	// connection dropping for a little while: a healthy node alternated between
	// answering in 236ms and timing out, and the same was true of others. Six nodes
	// from one scan, tested twice each: four answered both times, one answered then
	// timed out, one failed both times. Only the last was actually dead.
	//
	// With a threshold of three consecutive failures at ten-second intervals, a
	// twenty-second burst of packet loss was enough to reach it. The health loop then
	// switched to the fallback hostname node, waited out the retry delay, and switched
	// back - about forty seconds during which the machine was worse off than if nothing
	// had happened. That is the whole of the reported outage, and it repeats on every
	// burst.
	//
	// So a failed probe is now re-tested before it counts. The confirmation runs
	// immediately rather than a tick later, because the question is whether the node is
	// answering right now, and a tick later is ten seconds of the user being stalled.
	if delay2, err2 := a.core.Delay(current, healthTimeoutMS, ""); err2 == nil && delay2 > 0 {
		// A blip, not a failure. Recorded so it is visible without being acted on: the
		// node count is not decremented, no switch happens, and the user keeps the
		// connection they had.
		a.mu.Lock()
		a.healthLastEv = fmt.Sprintf("%s flaked then answered %dms", current, delay2)
		a.healthFails = 0
		a.mu.Unlock()
		Log("health: %q missed one probe but answered %dms on an immediate retry; "+
			"treating it as a blip rather than a dead node", current, delay2)
		return
	}

	a.mu.Lock()
	a.healthFails++
	fails := a.healthFails
	if a.healthBanned == nil {
		a.healthBanned = map[string]time.Time{}
	}
	if a.nodeFlaky == nil {
		a.nodeFlaky = map[string]int{}
	}
	a.nodeFlaky[current]++
	flaky := a.nodeFlaky[current]
	a.healthBanned[current] = time.Now()
	a.healthLastEv = fmt.Sprintf("%s failed %d/%d (累计 %d 次)", current, fails, healthFailLimit, flaky)
	tooSoon := time.Since(a.healthLastAt) < healthRetryDelay
	// Publish the new counts as one immutable snapshot before releasing the lock,
	// so no reader can observe a map mid-update.
	a.publishHealth()
	a.mu.Unlock()

	reason := "timed out"
	if derr != nil {
		reason = derr.Error()
	}
	Log("health: %q did not answer (%s), failure %d/%d", current, reason, fails, healthFailLimit)

	if fails < healthFailLimit || tooSoon {
		return
	}

	// Pick the best node that is not known-dead and is not the one we are on.
	//
	// The hostname node is considered first. If the individual edge addresses are
	// being filtered, every pinned node fails in turn and switching between them
	// is pointless - the hostname node asks Cloudflare for a fresh edge on each
	// connection, so it keeps working when none of the pinned addresses do. It is
	// preferred here rather than ranked, because this path is only reached after
	// the fast options have already proved themselves dead.
	next := ""
	for _, p := range optimized {
		if p.OriginNode && p.Name != current {
			next = p.Name
			break
		}
	}
	if next == "" {
		// Walk the candidates and take the first one that actually answers.
		//
		// It used to take the first one that was not known-dead, which is a statement
		// about the past. Switching onto a node that cannot answer turns a single bad
		// node into an outage, and the user sees the network drop for as long as it takes
		// the next check to give up on the replacement too.
		//
		// One snapshot for the whole walk; it is immutable, so the answer cannot change
		// halfway through the loop. The probe is bounded and short: a candidate that
		// needs longer than this to answer is not an improvement on what we are leaving.
		view := a.HealthView()
		tried := 0
		for _, p := range optimized {
			if p.Name == current {
				continue
			}
			if view != nil {
				if bannedAt, banned := view.Banned[p.Name]; banned && time.Since(bannedAt) < 5*time.Minute {
					continue
				}
			}
			// Leave the hostname node alone here: it is the fallback of last resort and
			// is preferred above, before this loop, so reaching it means it was either
			// chosen already or is not usable.
			if tried >= 3 {
				// Three probes is enough to find an improvement; more than that and the
				// search costs the user more time than the switch saves.
				break
			}
			tried++
			if d, err := a.core.Delay(p.Name, healthTimeoutMS, ""); err == nil && d > 0 {
				next = p.Name
				break
			}
		}
	}
	if next == "" {
		Log("health: %q is dead but no alternative is known-good; will re-optimise", current, "WARN")
		a.mu.Lock()
		a.healthLastEv = "current node dead, no alternative available"
		a.mu.Unlock()
		a.StartOptimize()
		return
	}

	Log("health: switching away from the dead node %q to %q", current, next, "WARN")
	if err := a.core.Select("PROXY", next); err != nil {
		Log("health: switch failed: %v", err, "ERR")
		return
	}
	a.core.CloseConnections()
	_ = a.store.SetCurrent(next)
	a.mu.Lock()
	a.healthFails = 0
	a.healthLastAt = time.Now()
	a.healthLastEv = fmt.Sprintf("switched %s -> %s (previous node dead)", current, next)
	a.healthSwitches++
	switches := a.healthSwitches
	a.mu.Unlock()

	// If nodes keep dying one after another, the pool itself is stale - a fresh
	// scan is the only real fix.
	if switches >= healthRescanAfter && !a.opt.Running() {
		a.mu.Lock()
		rescanTooSoon := time.Since(a.lastHealthRescan) < healthRescanCooldown
		if !rescanTooSoon {
			a.lastHealthRescan = time.Now()
			a.healthSwitches = 0
		}
		a.healthLastEv = fmt.Sprintf("%d nodes failed in a row", switches)
		a.mu.Unlock()
		if rescanTooSoon {
			// A flapping network must not turn into a permanent scan loop: each
			// scan competes with real traffic, so repeated rescans make the very
			// problem they are trying to fix worse.
			Log("health: %d nodes failed in a row but a scan ran recently; not rescanning yet", switches, "WARN")
		} else {
			Log("health: %d nodes failed in a row, starting a fresh scan", switches, "WARN")
			a.StartOptimize()
		}
	}
}

// reason0 renders a delay error for a log line, or a default when there is none.
func reason0(err error) string {
	if err == nil {
		return "timed out"
	}
	return err.Error()
}

// healthSnapshot is the immutable view of health bookkeeping.
//
// The maps are copied on publish instead of shared. That costs a small
// allocation whenever the counts change - which is rare, on the order of once
// per liveness check - and in exchange no reader ever holds a reference to a map
// that a writer might be updating underneath it.
type healthSnapshot struct {
	Banned map[string]time.Time
	Flaky  map[string]int
}

// publishHealth copies the current bookkeeping into a fresh snapshot and swaps
// it in. Callers must hold a.mu.
func (a *App) publishHealth() {
	snap := &healthSnapshot{
		Banned: make(map[string]time.Time, len(a.healthBanned)),
		Flaky:  make(map[string]int, len(a.nodeFlaky)),
	}
	for k, v := range a.healthBanned {
		snap.Banned[k] = v
	}
	for k, v := range a.nodeFlaky {
		snap.Flaky[k] = v
	}
	a.healthView.Store(snap)
}

// HealthView returns the current snapshot. A nil result means nothing has been
// published yet, which callers treat as "no node is known bad".
func (a *App) HealthView() *healthSnapshot {
	if v := a.healthView.Load(); v != nil {
		if s, ok := v.(*healthSnapshot); ok {
			return s
		}
	}
	return nil
}

// flakyNodesCopy returns a detached copy of the per-node failure counts for
// reporting. Callers get their own map, so encoding it cannot race with the
// health loop updating the real one.
func (a *App) flakyNodesCopy() map[string]int {
	if h := a.HealthView(); h != nil {
		out := make(map[string]int, len(h.Flaky))
		for k, v := range h.Flaky {
			out[k] = v
		}
		return out
	}
	return map[string]int{}
}

// pickResult is what enforceFastest decided.
type pickResult struct {
	Name  string
	delay float64
}

// Auto-pick thresholds, in milliseconds.
//
// Two jobs pull in opposite directions: follow the fastest node, and do not
// bounce the user between near-identical nodes because of measurement noise.
// The compromise is tiered - a big win moves at once, a marginal win has to
// prove itself by holding for a while, and anything under noiseFloor is ignored
// outright.
const (
	pickNoiseFloorMS = 1 // differences below this are treated as noise
	pickForceMS      = 1 // a win this large switches immediately
	pickForceRatio   = 0.01
	pickPatience     = 1 * time.Second
	pickPatienceSecs = 1

	// userPickGrace is how long a deliberate node choice is left alone before
	// auto-pick resumes ranking. A fresh optimisation resets it immediately.
	userPickGrace = 10 * time.Minute

	// Health checking. Being the fastest node is worth nothing if it stopped
	// working, and an edge that answered a handshake an hour ago may be
	// unreachable now.
	//
	// The interval is a compromise that was tuned the hard way. Checking once a
	// second looked attractive and was actively harmful: the probes themselves
	// rate limited the check endpoint, the resulting 504s were read as "node is
	// dead", and the app then churned through nodes and rescans chasing a fault
	// it had created. Ten seconds notices a real outage quickly and is rare
	// enough not to cause one.
	healthInterval   = 10 * time.Second
	healthTimeoutMS  = 6000
	healthFailLimit  = 3                // consecutive failures before switching away
	healthRetryDelay = 30 * time.Second // minimum gap between forced switches
	// Each recent liveness failure adds this to a node's effective latency when
	// auto-pick ranks candidates.
	flakyPenaltyMS = 60.0
	// After this many forced switches in a row, stop shuffling nodes and rescan:
	// the whole pool is probably stale, not just the node we happened to be on.
	healthRescanAfter = 4
	// slowNodeMS is the absolute round trip above which the node in use is
	// considered degraded rather than merely not-the-fastest. Healthy values sit
	// near 250ms, so this only trips on a real collapse.
	slowNodeMS = 1200
	// slowStrikesNeeded is how many consecutive slow measurements are required
	// before the node is abandoned. Two, so a single spike is ignored.
	slowStrikesNeeded = 2
	// A rescan may not start again until this long after the previous one, so a
	// flapping network cannot put the app into a permanent scan loop.
	healthRescanCooldown = 10 * time.Minute

	// httpProbePath is the request used to prove an edge carries real traffic,
	// not merely that it accepts a WebSocket upgrade.
	httpProbePath = "/"
)

// resetPickWatch forgets any pending auto-pick. Called whenever the situation
// no longer calls for a switch, so the next candidate starts its wait fresh.
func (a *App) resetPickWatch() {
	a.mu.Lock()
	a.pickCandidate = ""
	a.pickSince = time.Time{}
	a.pickWatching = false
	a.mu.Unlock()
}

// enforceFastest makes sure the fastest verified node is the one in use.
//
// Ranking uses the handshake time the optimiser actually measured, not the
// core's url-test, which only learns whether a node answers a 204 probe.
func (a *App) enforceFastest() (pickResult, bool) {
	optimized, _ := a.nodeSet()
	if len(optimized) < 2 {
		a.pickDebug(1, "only %d optimised node(s)", len(optimized))
		return pickResult{}, false
	}

	// MeasuredMS is only set by scans run after this feature existed, so the
	// number embedded in the node name is used as a fallback for older nodes.
	best := Proxy{}
	bestMS := 0.0
	for _, p := range optimized {
		ms := p.MeasuredMS
		if ms <= 0 {
			ms = latencyFromName(p.Name)
		}
		if ms <= 0 {
			continue
		}
		// Reliability is part of being fast. Each recent failure adds a penalty
		// to the effective latency, so an edge that intermittently stops
		// answering loses to one that is a few milliseconds slower but steady.
		//
		// The snapshot is loaded once per pass, not per node: it is immutable, so
		// it stays consistent for the whole ranking even if healthLoop publishes a
		// newer one halfway through.
		if h := a.HealthView(); h != nil {
			if at, bad := h.Banned[p.Name]; bad && time.Since(at) < 2*time.Minute {
				continue // found dead moments ago, do not rank it at all
			}
			ms += float64(h.Flaky[p.Name]) * flakyPenaltyMS
		}
		if bestMS == 0 || ms < bestMS {
			best, bestMS = p, ms
		}
	}
	if bestMS == 0 {
		a.pickDebug(2, "no node has a usable measurement")
		return pickResult{}, false
	}

	proxies, err := a.core.Proxies()
	if err != nil {
		a.pickDebug(3, "core /proxies failed: %v", err)
		return pickResult{}, false
	}
	current := ""
	if g, ok := proxies["PROXY"]; ok {
		current = g.Now
	}
	if current == best.Name {
		a.pickDebug(4, "already on the fastest (%s)", current)
		a.resetPickWatch()
		return pickResult{}, false
	}

	// Honour a recent manual pick. Auto-pick exists to keep a good node in use,
	// not to argue with the person using the program; the next optimisation
	// produces fresh measurements and takes over again.
	a.mu.Lock()
	picked, pickedAt := a.userPicked, a.userPickedAt
	a.mu.Unlock()
	if picked != "" && current == picked {
		if held := time.Since(pickedAt); held < userPickGrace {
			a.pickDebug(5, "user picked %q %.0fs ago, inside the grace window", picked, held.Seconds())
			return pickResult{}, false
		}
		// the grace window expired: fall through and resume normal ranking
		a.mu.Lock()
		a.userPicked = ""
		a.mu.Unlock()
	}

	curMS := 0.0
	currentIsOptimised := false
	for _, p := range optimized {
		if p.Name == current {
			currentIsOptimised = true
			curMS = p.MeasuredMS
			if curMS <= 0 {
				curMS = latencyFromName(p.Name)
			}
			break
		}
	}
	if curMS <= 0 {
		if status, ok := proxies[current]; ok && status.Delay > 0 {
			curMS = float64(status.Delay)
		}
	}

	// A subscription node the user pinned by hand is left alone: this feature
	// chooses among verified edges, it does not override a deliberate choice.
	// A dead node is still replaced, because a dead node is not a choice.
	if !currentIsOptimised && current != "" && current != "AUTO" {
		if curMS > 0 {
			a.pickDebug(6, "current %q is not an optimised node (curMS=%.0f), leaving it", current, curMS)
			return pickResult{}, false
		}
	}

	// Nothing to fix when the current node is already effectively the fastest,
	// or when the difference is inside the noise band.
	if curMS > 0 {
		delta := curMS - bestMS
		if delta < pickNoiseFloorMS {
			a.pickDebug(7, "delta %.1fms is inside the noise floor", delta)
			a.resetPickWatch()
			return pickResult{}, false
		}
		if delta < pickForceMS && bestMS > curMS*(1-pickForceRatio) {
			// A win worth having, but not an emergency. Wait for it to persist,
			// so a single noisy measurement cannot move the user.
			a.mu.Lock()
			if !a.pickWatching || a.pickCandidate != best.Name {
				a.pickCandidate = best.Name
				a.pickSince = time.Now()
				a.pickWatching = true
				a.mu.Unlock()
				Log("auto-pick: %q is %.0fms faster than %q; confirming for %d seconds",
					best.Name, delta, current, pickPatienceSecs)
				return pickResult{}, false
			}
			held := time.Since(a.pickSince)
			a.mu.Unlock()
			if held < pickPatience {
				a.pickDebug(8, "marginal win, waiting %.1fs of %.1fs", held.Seconds(), pickPatience.Seconds())
				return pickResult{}, false
			}
		}
	}

	if err := a.core.Select("PROXY", best.Name); err != nil {
		a.pickDebug(9, "Select failed: %v", err)
		return pickResult{}, false
	}
	a.core.CloseConnections()
	_ = a.store.SetCurrent(best.Name)
	a.resetPickWatch()
	a.mu.Lock()
	a.lastPickDebug = ""
	a.mu.Unlock()
	return pickResult{Name: best.Name, delay: bestMS}, true
}

// latencyFromName reads the "123ms" suffix the optimiser writes into a node
// name. It exists so nodes stored before MeasuredMS was introduced still rank
// correctly instead of being ignored.
func latencyFromName(name string) float64 {
	i := strings.LastIndex(name, " · ")
	if i < 0 {
		return 0
	}
	tail := name[i+len(" · "):]
	tail = strings.TrimSuffix(strings.TrimSpace(tail), "ms")
	v, err := strconv.ParseFloat(tail, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// nodeSet returns the two node pools, with the optimised list capped by the
// user's keepNodes setting.
//
// The cap is applied HERE rather than inside the scan on purpose: the setting
// can then be changed with instant feedback, the verified results of a long
// scan are never thrown away, and the pools stay separate so the interface can
// show which nodes came from the subscription and which ones Zenith found.
func (a *App) nodeSet() (optimized []Proxy, base []Proxy) {
	snap := a.store.Snapshot()
	optimized = snap.Optimized
	base = snap.BaseNodes
	if n := snap.Settings.KeepNodes; n > 0 && len(optimized) > n {
		// Truncate the ranked list but never drop a hostname node. Those are the
		// safety net for a whole address range being filtered, and a display cap
		// must not be able to remove the one node that still works when every
		// pinned IP is dead. They are kept at the end so the fast nodes stay on
		// top of the list.
		var keep, origin []Proxy
		for _, p := range optimized {
			if p.OriginNode {
				origin = append(origin, p)
				continue
			}
			if len(keep) < n {
				keep = append(keep, p)
			}
		}
		if len(origin) > 0 {
			optimized = append(keep, origin...)
		} else {
			optimized = keep
		}
	}
	return optimized, base
}

// mergedNodes is the full list written into config.yaml: optimised edges first,
// then the subscription's own nodes.
//
// Both pools must be present. A subscription can carry direct nodes (Singapore
// / Japan / US) that the optimiser cannot produce - it only re-points one
// WebSocket template at different Cloudflare edges - and dropping them would
// silently remove choices from the interface.
func (a *App) mergedNodes() []Proxy {
	optimized, base := a.nodeSet()
	out := make([]Proxy, 0, len(optimized)+len(base))
	seen := make(map[string]bool, len(optimized)+len(base))
	hasOrigin := false
	for _, p := range optimized {
		if p.OriginNode {
			hasOrigin = true
		}
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p)
		}
	}
	for _, p := range base {
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p)
		}
	}
	// Guarantee a way out, always.
	//
	// The hostname node exists because a pinned edge address can be filtered while
	// the provider's own hostname keeps working - Cloudflare hands out a fresh edge per
	// connection, so it survives exactly the case where every pinned address fails.
	// The health loop prefers it for that reason.
	//
	// It was only ever produced by a successful optimisation, which leaves a gap that
	// only opens when things are already going wrong: an optimisation result that has
	// gone stale (the credential was rotated), followed by a subscription refresh that
	// fails (the provider is down). In that state there is no hostname node, the
	// previous one is gone with the stale list, the health loop reports "no alternative
	// is known-good", and the user is pinned to a dead address until the provider comes
	// back.
	//
	// Composing one from the current base node closes it: nothing to download, nothing
	// to measure, and it survives both of those failures because it depends on neither.
	if !hasOrigin {
		if fb, ok := hostnameFallback(base); ok {
			if !seen[fb.Name] {
				out = append(out, fb)
			}
		}
	}
	return out
}

// hostnameFallback builds a node that connects to the provider's own hostname rather
// than to a pinned edge address.
//
// It reports ok=false when there is nothing to build from, which is the honest answer
// for a subscription whose nodes are all pinned addresses: there is no hostname to
// fall back to, and inventing one would be a guess.
func hostnameFallback(base []Proxy) (Proxy, bool) {
	for _, p := range base {
		host := p.Server
		if host == "" || looksLikeIPv4(host) {
			continue
		}
		fb := p
		fb.OriginNode = true
		fb.OriginHost = host
		fb.MeasuredMS = 0
		if p.Servername != "" {
			fb.SNI = p.Servername
		}
		fb.Name = fmt.Sprintf("兜底 · %s · 域名", host)
		return fb, true
	}
	return Proxy{}, false
}

// SwitchNode selects one of the nodes this program offers.
//
// It exists next to Switch because Switch talks to the core, and the core's proxy
// table also holds the groups: PROXY, AUTO, DIRECT and anything a subscription brings
// with it. Passing one of those through produced a state the interface could not
// describe - PROXY set to "AUTO" is not a node, and every node in the list stopped
// matching, so none was shown as current.
//
// The check is against what this program offers rather than against a hardcoded list of
// group names, so a group a subscription happens to define is refused for the same
// reason and without anybody having to remember to add it.
func (a *App) SwitchNode(name string) error {
	optimized, base := a.nodeSet()
	for _, p := range optimized {
		if p.Name == name {
			return a.Switch(name)
		}
	}
	for _, p := range base {
		if p.Name == name {
			return a.Switch(name)
		}
	}
	return fmt.Errorf("没有这个节点：%q。它是内核的代理组，不是节点——"+
		"节点列表里的条目才能选中", name)
}

// ---- config ---------------------------------------------------------------

func (a *App) writeConfig(nodes []Proxy, st Settings) {
	// The AUTO group must only span nodes the optimiser verified, so its members
	// are passed separately from the full list.
	optimized, _ := a.nodeSet()
	optNames := make([]string, 0, len(optimized))
	for _, p := range optimized {
		optNames = append(optNames, p.Name)
	}
	cfg := BuildConfig(nodes, optNames, st, a.secret, a.store.Snapshot().Current, a.dnsPort)
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o644); err != nil {
		Log("could not write config: %v", err, "ERR")
	}

	// The generated configuration carries the control secret, every node UUID and
	// every WebSocket path. Narrowed here so every path that writes it is covered,
	// rather than each caller remembering.
	restrictSensitiveFiles(a.dataDir)
}

// applyConfig rewrites the configuration and hot reloads it. No process restart.
//
// Every caller goes through the transactional path, so a failure restores the
// last version that worked and reports the failure instead of leaving a broken
// file for the next start to trip over.
func (a *App) applyConfig() error {
	return a.applyConfigTransactional(a.mergedNodes(), a.store.Settings())
}

func (a *App) CurrentConfigPreview() string {
	raw, err := os.ReadFile(a.configPath)
	if err != nil {
		return ""
	}
	text := string(raw)
	if len(text) > 20000 {
		text = text[:20000] + "\n… (已截断)"
	}
	return text
}

// ---- status ---------------------------------------------------------------

func (a *App) Status() map[string]interface{} {
	snap := a.store.Snapshot()
	st := snap.Settings

	proxies, _ := a.core.Proxies()
	group := proxies["PROXY"]
	autoGroup := proxies["AUTO"]

	// What PROXY is set to, which may be a group rather than a node.
	pick := snap.Current
	if group != nil && group.Now != "" {
		pick = group.Now
	}
	// What is actually carrying the traffic.
	//
	// These are the same value until PROXY is set to AUTO, and then they are not:
	// PROXY.Now is the string "AUTO" while the connections go through whichever node
	// the url-test group last chose. Reporting the first as "the current node" meant
	// the interface could not name the node in use - the list marks an entry active by
	// matching this value against a node name, and "AUTO" matches nothing - so a user
	// who selected AUTO saw no current node at all.
	//
	// Resolved here rather than in the interface, because the interface would need to
	// know that one particular group name is special, and the next nested group would
	// not be handled.
	current := pick
	if group != nil && group.Now == "AUTO" && autoGroup != nil && autoGroup.Now != "" {
		current = autoGroup.Now
	}

	autoPick := ""
	if autoGroup != nil {
		autoPick = autoGroup.Now
	}

	optimized, base := a.nodeSet()
	isOptimized := len(optimized) > 0

	// Report the fastest verified node and its measured time so the interface
	// can say what "自动" is aiming at, rather than leaving it a black box.
	fastest := Proxy{}
	fastestMS := 0.0
	for _, p := range optimized {
		ms := p.MeasuredMS
		if ms <= 0 {
			ms = latencyFromName(p.Name)
		}
		if ms <= 0 {
			continue
		}
		if fastestMS == 0 || ms < fastestMS {
			fastest, fastestMS = p, ms
		}
	}

	// Two pools, optimised edges first. A subscription node that happens to
	// carry the same name as an optimised one is listed once.
	all := make([]Proxy, 0, len(optimized)+len(base))
	optimizedNames := make(map[string]bool, len(optimized))
	for _, p := range optimized {
		optimizedNames[p.Name] = true
		all = append(all, p)
	}
	for _, p := range base {
		if !optimizedNames[p.Name] {
			all = append(all, p)
		}
	}

	list := make([]map[string]interface{}, 0, len(all))
	for _, n := range all {
		delay := 0
		if p, ok := proxies[n.Name]; ok {
			delay = p.Delay
		}
		list = append(list, map[string]interface{}{
			"name":      n.Name,
			"server":    n.Server,
			"port":      n.Port,
			"type":      n.Type,
			"network":   n.Network,
			"delay":     delay,
			"active":    n.Name == current,
			"optimized": optimizedNames[n.Name],
		})
	}

	return map[string]interface{}{
		"ok":          true,
		"app":         AppName,
		"version":     AppVersion,
		"coreUp":      a.core.IsUp(),
		"corePid":     a.core.Pid(),
		"coreVersion": a.core.Version(),
		"coreUptime":  a.core.Uptime(),
		"mode":        st.Mode,
		"current":     current,
		// What PROXY is set to. It differs from current only when a group is selected,
		// and the interface uses it to say "AUTO (currently X)" instead of pretending
		// the user picked X.
		"currentPick": pick,
		"autoPick":    autoPick, // what the core's AUTO group currently chooses
		"autoPickOn":  !st.AutoPickOff,
		"fastestName": fastest.Name,
		"pickDebug":   a.lastPickDebug,
		"healthEvent": a.healthLastEv,
		// A copy, never the internal map. Handing the live map to the JSON
		// encoder meant every status request read it while healthLoop could be
		// writing it, which is a fatal runtime error rather than a wrong answer.
		"flakyNodes": a.flakyNodesCopy(),
		"fastestMS":  fastestMS,
		"nodes":      list,
		"nodeCount":  len(list),
		"optCount":   len(optimized),
		"baseCount":  len(base),
		// Whether the stored optimisation still describes the current subscription.
		// A stale list is a real condition after a subscription change, and the
		// interface can say so instead of silently showing nodes that are gone.
		"optimizedCurrent": a.store.OptimizedIsCurrent(),
		"storedCount":      len(snap.Optimized),
		"isOptimized":      isOptimized,
		"settings":         st,
		"systemProxy":      a.sysproxy.Status(),
		// The TUN state, in the same shape the interface reads.
		//
		// Added because the tray menu needed it and could not get it: the menu asked
		// for "tunMode" and "tunRun" and Status returned neither, so the item reported
		// "not enabled" whether the tunnel was up or not. A menu that lies about the
		// switch it is offering is worse than no menu item.
		"tunMode":      st.TunMode,
		"tunRun":       a.TunRunState(),
		"optimizing":   a.opt.Running(),
		"progress":     a.opt.Progress(),
		"optSummary":   a.opt.LastSummary(),
		"lastOptimize": snap.LastOptimize,
		"error":        a.lastErr,
		"ports": map[string]int{
			"mixed": st.MixedPort, "api": st.APIPort, "ui": st.UIPort, "control": st.ControlPort,
		},
		"traffic": a.traffic(),
	}
}

func (a *App) traffic() Connections {
	c := a.core.Connections()
	if c.DownloadTotal > 0 || c.UploadTotal > 0 {
		a.trafficSnap = c
		return c
	}
	return a.trafficSnap
}

// ---- node control ---------------------------------------------------------

// Switch pins a node in the PROXY group.
func (a *App) Switch(name string) error {
	return a.switchTo(name, true)
}

// switchTo applies a node choice.
//
// byUser matters: when the user clicks a node, auto-pick must not silently
// undo it two seconds later. That made the node list look broken - the row
// highlighted, then quietly reverted. A deliberate pick is therefore trusted
// for a while, and only the next optimisation (which produces fresh
// measurements) puts auto-pick back in charge.
func (a *App) switchTo(name string, byUser bool) error {
	if err := a.core.Select("PROXY", name); err != nil {
		return err
	}
	// drop live sockets so a bad route is not kept alive
	a.core.CloseConnections()
	if err := a.store.SetCurrent(name); err != nil {
		return err
	}
	if byUser {
		a.mu.Lock()
		a.userPicked = name
		a.userPickedAt = time.Now()
		a.mu.Unlock()
	}
	return nil
}

func (a *App) SetMode(mode string) error {
	switch mode {
	case "rule", "global", "direct":
	default:
		return fmt.Errorf("未知模式 %q", mode)
	}
	if err := a.core.SetMode(mode); err != nil {
		return err
	}
	_, err := a.store.UpdateSettings(map[string]interface{}{"mode": mode})
	if err == nil {
		Log("proxy mode -> %s", mode)
	}
	return err
}

// ---- optimisation ---------------------------------------------------------

func (a *App) StartOptimize() bool {
	if !a.opt.begin() {
		return false
	}
	go func() {
		defer a.opt.end()
		a.mu.Lock()
		a.optimizing = true
		a.mu.Unlock()
		defer func() {
			a.mu.Lock()
			a.optimizing = false
			a.mu.Unlock()
		}()

		snap := a.store.Snapshot()
		if len(snap.BaseNodes) == 0 {
			a.lastErr = "还没有节点：请先在「订阅」页添加一个订阅"
			Log("%s", a.lastErr, "WARN")
			return
		}
		st := snap.Settings
		// Scan a generous set, not exactly what the user asked to display: the
		// keepNodes setting is applied when listing nodes, so a larger pool is
		// what makes raising that number take effect instantly instead of
		// needing another ten minute scan.
		minWanted := st.KeepNodes
		if minWanted < 64 {
			minWanted = 64
		}
		// Record the generation the scan starts from. A scan takes minutes, and a
		// subscription change during that window would otherwise let results
		// describing the old nodes overwrite the new ones.
		startGen := a.store.SubscriptionGeneration()
		best, _, err := a.opt.ScanEdges(snap.BaseNodes, st, minWanted)
		if err != nil {
			a.lastErr = err.Error()
			Log("optimize failed: %v", err, "ERR")
			return
		}
		installed, err := a.store.SetOptimizedIfCurrent(startGen, best)
		if err != nil {
			Log("could not save optimized nodes: %v", err, "ERR")
		}
		if !installed {
			Log("optimisation finished after the subscription changed; discarding its "+
				"results rather than installing nodes that may no longer exist", "WARN")
			a.lastErr = "优选完成时订阅已改变，本次结果已丢弃（节点可能已不存在）。请重新优选"
			return
		}
		// Keep the user's pick when it still exists somewhere, otherwise fall
		// back to the fastest optimised node. A subscription node the user had
		// selected must NOT be replaced just because it is absent from the
		// optimised list.
		cur := a.store.Snapshot().Current
		if !a.nodeExists(cur) {
			cur = best[0].Name
			_ = a.store.SetCurrent(cur)
		}
		if err := a.applyConfig(); err != nil {
			Log("hot reload after optimize failed: %v", err, "WARN")
		}
		_ = a.switchTo(cur, false)
		// fresh measurements exist now, so auto-pick is in charge again
		a.mu.Lock()
		a.userPicked = ""
		a.userPickedAt = time.Time{}
		a.mu.Unlock()
		_ = a.store.SetLastOptimize(time.Now())
		a.lastErr = ""
		Log("optimize done: stored %d optimised nodes, showing %d, current=%s",
			len(best), len(a.mergedNodes()), cur)
	}()
	return true
}

// nodeExists reports whether a name is present in either node pool.
func (a *App) nodeExists(name string) bool {
	if name == "" {
		return false
	}
	snap := a.store.Snapshot()
	for _, p := range snap.Optimized {
		if p.Name == name {
			return true
		}
	}
	for _, p := range snap.BaseNodes {
		if p.Name == name {
			return true
		}
	}
	return false
}

// ---- subscriptions --------------------------------------------------------

func (a *App) AddSubscription(rawURL, name string) (*Subscription, error) {
	text, info, err := FetchSubscription(rawURL, "", a.store.Settings().AllowInsecureSubscription)
	if err != nil {
		return nil, err
	}
	nodes := ParseSubscription(text)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("订阅内容里没有解析到任何节点")
	}
	sub := Subscription{
		ID:         shortID(rawURL + fmt.Sprint(time.Now().UnixNano())),
		Name:       strings.TrimSpace(name),
		URL:        strings.TrimSpace(rawURL),
		Enabled:    true,
		LastFetch:  nowStamp(),
		NodeCount:  len(nodes),
		AutoUpdate: true,
	}
	if info != nil {
		sub.Upload = info.Upload
		sub.Download = info.Download
		sub.Total = info.Total
		sub.Expire = info.Expire
	}
	if sub.Name == "" {
		host := rawURL
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.IndexAny(host, "/:"); i >= 0 {
			host = host[:i]
		}
		sub.Name = host
	}
	snap := a.store.Snapshot()
	subs := append(snap.Subscriptions, sub)
	if err := a.store.SetSubscriptions(subs); err != nil {
		return nil, err
	}
	// A first subscription becomes the active one, otherwise the scheduled
	// refresh has nothing to refresh until the user clicks it.
	if len(snap.Subscriptions) == 0 {
		_ = a.store.SetActiveSubscription(sub.ID)
	}
	if err := a.store.SetNodes(nodes, nil); err != nil {
		return nil, err
	}
	_, _ = a.store.UpdateSettings(map[string]interface{}{"lastProfile": sub.ID})
	if err := a.applyConfig(); err != nil {
		Log("config apply after subscribe failed: %v", err, "WARN")
	}
	Log("subscription added: %s (%d nodes)", sub.Name, len(nodes))
	return &sub, nil
}

func (a *App) UpdateSubscription(id string) (int, error) {
	snap := a.store.Snapshot()
	var target *Subscription
	for i := range snap.Subscriptions {
		if snap.Subscriptions[i].ID == id {
			target = &snap.Subscriptions[i]
			break
		}
	}
	if target == nil {
		return 0, fmt.Errorf("找不到该订阅")
	}
	text, info, err := FetchSubscription(target.URL, target.UserAgent, a.store.Settings().AllowInsecureSubscription)
	if err != nil {
		target.LastError = err.Error()
		_ = a.store.SetSubscriptions(snap.Subscriptions)
		return 0, err
	}
	nodes := ParseSubscription(text)
	if len(nodes) == 0 {
		target.LastError = "订阅内容里没有解析到任何节点"
		_ = a.store.SetSubscriptions(snap.Subscriptions)
		return 0, fmt.Errorf("%s", target.LastError)
	}
	target.LastError = ""
	target.LastFetch = nowStamp()
	target.NodeCount = len(nodes)
	if info != nil {
		target.Upload = info.Upload
		target.Download = info.Download
		target.Total = info.Total
		target.Expire = info.Expire
	}
	if err := a.store.SetSubscriptions(snap.Subscriptions); err != nil {
		return 0, err
	}
	if err := a.store.SetNodes(nodes, nil); err != nil {
		return 0, err
	}
	if err := a.applyConfig(); err != nil {
		Log("config apply after subscription update failed: %v", err, "WARN")
	}
	Log("subscription refreshed: %s (%d nodes)", target.Name, len(nodes))
	return len(nodes), nil
}

func (a *App) RemoveSubscription(id string) error {
	snap := a.store.Snapshot()
	subs := make([]Subscription, 0, len(snap.Subscriptions))
	for _, s := range snap.Subscriptions {
		if s.ID != id {
			subs = append(subs, s)
		}
	}
	if len(subs) == len(snap.Subscriptions) {
		return fmt.Errorf("找不到该订阅")
	}
	if err := a.store.SetSubscriptions(subs); err != nil {
		return err
	}
	if len(subs) == 0 {
		_ = a.store.SetNodes([]Proxy{}, []Proxy{})
		_ = a.applyConfig()
	}
	Log("subscription removed: %s", id)
	return nil
}

func (a *App) SelectSubscription(id string) (int, error) {
	n, err := a.UpdateSubscription(id)
	if err != nil {
		return 0, err
	}
	// One call sets both the Enabled flag and SelectedSub, so the scheduled
	// refresh has a target instead of an empty string.
	_ = a.store.SetActiveSubscription(id)
	_ = a.store.SetCurrent("")
	Log("subscription selected: %s", id)
	return n, nil
}

// ---- settings -------------------------------------------------------------

func (a *App) ApplySettings(patch map[string]interface{}) (Settings, error) {
	// The interface toggles "autoPick", but the stored field is the inverse
	// ("autoPickOff") so that older settings files default to ON.
	if v, ok := patch["autoPick"]; ok {
		if on, isBool := v.(bool); isBool {
			patch = copyPatch(patch)
			patch["autoPickOff"] = !on
			delete(patch, "autoPick")
		}
	}
	before := a.store.Settings()
	next, err := a.store.UpdateSettings(patch)
	if err != nil {
		return next, err
	}

	// mode may change through two different UI controls
	if m, ok := patch["mode"].(string); ok && m != before.Mode {
		if err := a.core.SetMode(m); err != nil {
			Log("could not switch mode: %v", err, "WARN")
		}
	}

	// anything that changes the generated config needs a rewrite + reload.
	// keepNodes is deliberately NOT in this list: it only caps how many
	// optimised nodes are shown, so changing it must not rewrite the config.
	//
	// The three TUN settings belong here. They were missing, and the consequence
	// was exact: enabling TUN stored the mode, restarted the core, and never wrote
	// a config containing a tun block - so the core started without TUN, no
	// adapter appeared, and the activation waited out its timeout and rolled back.
	// The core's own log had no TUN lines at all, which is what gave it away.
	needReload := false
	for _, k := range []string{
		"mixedPort", "apiPort", "directCNDomains", "blockAds", "customRules",
		"tunMode", "tunDevice", "tunStack",
	} {
		if _, ok := patch[k]; ok {
			needReload = true
			break
		}
	}
	if needReload {
		if err := a.applyConfig(); err != nil {
			Log("config apply after settings change failed: %v", err, "WARN")
		}
	}

	// the system proxy follows the mixed port
	if mp, ok := patch["mixedPort"].(int); ok && mp > 0 && mp != before.MixedPort {
		a.core = NewCore(a.core.exePath, a.core.dataDir, a.configPath, a.secret, next.ControlPort)
		// The new core is started through whoever owns it, so a port change cannot
		// produce a second core either.
		if err := a.StartCoreThroughOwner(nil, ""); err != nil {
			Log("restarting the core on the new port failed: %v", err, "WARN")
		}
	}
	// Switching auto-pick on should take effect at once, not on the next tick.
	if v, ok := patch["autoPickOff"]; ok {
		if off, isBool := v.(bool); isBool && !off {
			if picked, changed := a.enforceFastest(); changed {
				Log("auto-pick enabled: switched to %q (%.0fms)", picked.Name, picked.delay)
			}
		}
	}
	if sp, ok := patch["systemProxy"].(bool); ok {
		if sp {
			if _, err := a.sysproxy.Enable(next.MixedPort, next.ProxyBypass, false); err != nil {
				Log("could not enable system proxy: %v", err, "WARN")
			}
		} else {
			a.sysproxy.Disable()
		}
	}
	return next, nil
}

// ---- shutdown -------------------------------------------------------------

func (a *App) Shutdown() {
	a.mu.Lock()
	if a.quitting {
		a.mu.Unlock()
		return
	}
	a.quitting = true
	a.mu.Unlock()

	Log("shutting down")
	close(a.stopCh)
	// core first: the "is that port still alive" check in Restore must not be
	// answered by our own listener, or the proxy is left pointing at a dead port
	//
	// Unless the service owns it. A resident service holding the core across window
	// restarts is what it is for, so closing the window must not stop it - that would
	// make every restart re-run the activation and ask for authorisation again, which
	// is the thing the service exists to avoid. The service stops the core when the
	// service itself stops.
	if a.coreOwnerNow() == ownerService {
		Log("shutdown: the core belongs to the service and is left running")
	} else if err := a.StopCoreThroughOwner(); err != nil {
		Log("shutdown: stopping the core reported: %v", err, "WARN")
	}
	a.sysproxy.Restore()
	_ = a.store.Save()
	Log("Zenith stopped")
	if a.onQuit != nil {
		a.onQuit()
	}
	os.Exit(0)
}
