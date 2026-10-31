package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// healthProbeTargets are tried in order; any one answering is proof the node is carrying
// traffic.
//
// Kept in step with the optimiser's list (optimizer.go:1226) on purpose. Two lists that
// disagree are how a node came to be dead to one part of the program and healthy to
// another, and that mismatch was a reported outage: with the tunnel up and answering for
// baidu, google, github and youtube, three optimised nodes timed out at exactly 8.0s on
// the single target the health loop used.
var healthProbeTargets = []string{
	"https://www.gstatic.com/generate_204",
	"https://www.google.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// healthSweepTargets are the two targets the pool sweep uses. See healthProbeWith for why
// the sweep is cheaper than the check on the current node.
var healthSweepTargets = []string{
	"https://www.gstatic.com/generate_204",
	"https://www.google.com/generate_204",
}

const (
	AppName    = "Zenith"
	AppVersion = "1.4.3"

	// coreStartGrace is how long the watchdog waits before it decides the core
	// is broken. A first run against an empty data directory downloads the rule
	// databases, which on a slow link takes a couple of minutes.
	coreStartGrace = 4 * time.Minute

	// coreRestartDelay is the much shorter window applied once a core has already
	// answered in this run. Long enough that a deliberate restart is not fought
	// over, short enough that a machine is not left offline for minutes.
	coreRestartDelay = 20 * time.Second

	// portReleaseWait is how long to wait for a core that is shutting down to let go of
	// the mixed port before concluding the holder is somebody else's.
	//
	// Generous on purpose. The alternative is moving the port out from under the system
	// proxy setting and every program that stored it, and the user noticed that happening
	// repeatedly: the log said "already in use by another program" each time, and the
	// other program was this one.
	portReleaseWait = 20 * time.Second
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
	// healthAlive is when each node last proved it could carry traffic.
	healthAlive map[string]time.Time
	// healthProbed is when each node was last asked, so the pool sweep does not
	// re-probe the same nodes every ten seconds.
	healthProbed map[string]time.Time
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
	// Tell the removal guard which adapter name this installation owns. The setting
	// preserves a custom name, and the guard used to compare against the built-in
	// default, so a configured name could never be removed - every disable, uninstall
	// and rollback failed while the adapter kept holding the default route.
	approveTunDevice(st.NormalizedTunDevice())
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

// ---- the mutual exclusion between the two ways of taking traffic -----------
//
// TUN and the system proxy are not two switches that happen to coexist. They are
// two different claims on the same traffic, and only one of them can be true:
//
//   - TUN takes traffic by installing a default route into the virtual adapter.
//     Everything is carried, whether the application reads the system proxy or
//     not, and the registry setting has no effect on that traffic at all.
//   - The system proxy takes traffic by telling applications to dial a local
//     port. Only applications that honour the setting are affected, and the
//     routing table is untouched.
//
// With both on, the machine is in a state nothing describes: the checkbox says
// the proxy carries it, the routing table says the tunnel does, and the proxy
// setting points at a port that a TUN activation is about to restart the core
// on - so every application honouring it is briefly offline.
//
// The check already existed in the interface's handler, and that was the gap.
// Measured on this machine, with the adapter Up and the default route on it:
//
//	TUN adapter "Zenith" Up (ifIndex 41, 198.18.0.1)
//	0.0.0.0/0 -> 198.18.0.2 on ifIndex 41
//	and the registry proxy was enabled at the same time
//
// Nothing on the background path could have refused it: the handler was the only
// place the rule lived, and the background loop, the settings path and the
// startup path all called Enable without asking. So the rule now lives here, and
// every caller goes through it. A rule enforced in one of four places is not a
// rule; it is a habit that the fifth caller breaks.

// tunModeActive reports whether the store believes TUN holds the traffic.
func (a *App) tunModeActive() bool {
	if a.store == nil {
		return false
	}
	return a.store.Settings().TunMode != TunOff
}

// tunActuallyCarrying reports whether the tunnel is not just configured but
// really holding the traffic: the adapter is up and the default route goes
// through it.
//
// The check is on the ROUTE, not on the stored mode, and that distinction is what
// makes the exclusion safe. Measured here: a disable cleared the mode and then
// failed to remove the adapter
//
//	[WARN] TUN disable: adapter "Zenith" could not be removed ... but it still exists
//	TUN disabled                                        <- reported as success
//
// so the stored mode read "off" while the adapter was Up and the default route
// still went into it. A gate that believed the mode then allowed the system proxy,
// and the machine carried traffic twice - TUN by route and the proxy by registry -
// with the interface showing one switch on. The route is the fact; the mode is a
// record of what was attempted, and the two had come apart.
//
// The stored mode is still consulted, because an adapter that exists but is not
// routed carries nothing and must not block the working proxy.
func (a *App) tunActuallyCarrying() (bool, string) {
	if a.store == nil {
		return false, ""
	}
	st := a.store.Settings()
	name := st.NormalizedTunDevice()

	exists, up, index := adapterState(name)
	if !exists {
		return false, ""
	}
	if up {
		if onRoute, detail := defaultRouteUsesAdapter(index); onRoute {
			// Routed traffic is the tunnel carrying it, whatever the mode says.
			// Saying so also repairs the record: the adapter is up and holding the
			// default route, which is a tunnel, so the stored mode is stale if it
			// disagrees.
			if st.TunMode == TunOff {
				Log("TUN: adapter %q is up and holds the default route while the stored "+
					"mode says off; treating the tunnel as carrying traffic and keeping "+
					"the system proxy off", name, "WARN")
			}
			return true, detail
		}
	}
	return false, ""
}

// enableSystemProxy is the only way the system proxy is turned on.
//
// Every path that wants it - the interface's button, the settings patch, the
// startup reconciliation and the background loop - calls this, so the exclusion
// is decided in one place instead of being remembered in four.
//
// It returns what happened rather than a bare error, because the callers need to
// tell "refused because TUN owns the traffic" (a normal, explainable state) from
// "the registry write failed" (a fault).
func (a *App) enableSystemProxy(reason string) (sysProxyOutcome, error) {
	out := sysProxyOutcome{}
	if a.store == nil || a.sysproxy == nil {
		return out, nil
	}
	if carrying, detail := a.tunActuallyCarrying(); carrying {
		out.Refused = sysProxyRefusedByTun
		out.Detail = "TUN 接管正在承载流量（" + detail + "），两者互斥，" +
			"系统代理不会同时生效。请先关闭 TUN 接管"
		Log("system proxy NOT enabled (%s): %s", reason, out.Detail)
		return out, nil
	}
	st := a.store.Settings()
	took, err := a.sysproxy.Enable(st.MixedPort, st.ProxyBypass, false)
	if err != nil {
		return out, err
	}
	out.Took = took
	if took {
		Log("system proxy enabled (%s) -> 127.0.0.1:%d", reason, st.MixedPort)
	}
	return out, nil
}

// sysProxyOutcome is what enableSystemProxy decided.
type sysProxyOutcome struct {
	// Took is true when the registry was actually changed by this call.
	Took bool
	// Refused names the reason the request was not carried out, if it was not.
	Refused string
	// Detail explains a refusal in terms the user can act on.
	Detail string
}

const sysProxyRefusedByTun = "tun"

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
	// Two repairs before anything is started, in this order:
	//
	//   1. a core that outlived the service that started it is an orphan, and an
	//      orphan holding the TUN adapter is the dangerous state this program has
	//      actually been in;
	//   2. a remembered TUN mode that this process cannot deliver has to fall back to
	//      the system proxy before a configuration is written, or the core is started
	//      against a tun block it has no rights to create and nothing carries traffic.
	a.healOrphanedCore()
	a.ensureTakeoverFeasible()
	a.EnsureUsablePort()
	snap := a.store.Snapshot()
	st := snap.Settings

	a.writeConfig(a.mergedNodes(), st)
	go a.bootCore()
}

// healOrphanedCore terminates a core whose owner is gone.
//
// This is the state measured on this machine: the resident service crashed (SCM 7034,
// exit 1067) and stayed dead because no recovery actions had been registered, while
// the mihomo it had started kept running. That orphan held the TUN adapter and the
// default route, so the tunnel still carried traffic - the machine looked healthy -
// and the only process able to remove the adapter was gone. "关闭 TUN" then failed
// with "需要管理员权限，而常驻服务也不可用", and the advice was to reboot.
//
// A core whose owner is gone is not adopted, because adopting it preserves exactly the
// state that cannot be repaired. It is stopped, so the next start can be a normal one.
//
// The identity is taken from this installation's own record rather than from a process
// scan: the file names the core pid AND the service pid that started it, so the check
// is "the core we recorded, whose owner we recorded, and that owner is gone" - never
// "some mihomo process".
func (a *App) healOrphanedCore() {
	st := a.loadServiceState()
	if st == nil || st.ServicePID <= 0 || st.CorePID <= 0 {
		return
	}
	if serviceRunning() {
		return // the owner is alive; the core is not an orphan
	}
	if alive, err := processRunning(st.CorePID); err != nil || !alive {
		return // nothing left behind
	}
	if !strings.EqualFold(ProcessName(st.CorePID), "mihomo.exe") {
		return // the pid has been reused by something else
	}
	Log("startup: core pid %d outlived the service that started it (service pid %d); "+
		"stopping it so it cannot keep holding the TUN adapter and the routes",
		st.CorePID, st.ServicePID, "WARN")
	if err := stopProcess(st.CorePID); err != nil {
		Log("startup: could not stop the orphaned core pid %d: %v", st.CorePID, err, "ERR")
		return
	}
	// Record that no core is running, so the rest of startup does not adopt a corpse.
	a.saveServiceState(&serviceState{ServicePID: 0})
	Log("startup: orphaned core stopped; the next core will be started by this process")
}

// ensureTakeoverFeasible falls back to the system proxy when the tunnel cannot be built.
//
// Creating a TUN adapter needs administrator rights, and there are exactly two ways to
// have them: the resident service, or an elevated instance. If neither is available
// the configuration this program is about to write still contains a `tun:` block, and
// the core started against it either fails or comes up with no adapter - while the
// stored settings and the interface both say the tunnel is on.
//
// Measured, and it is why this exists: after the service had crashed, a launch with
// `tunMode: compat` left the machine with a remembered tunnel, no adapter, no system
// proxy (the two are mutually exclusive) and therefore no working takeover at all.
//
// So the two switches are reconciled before anything is generated: if the tunnel is
// remembered but cannot be delivered, the tunnel is switched off and the system proxy
// is switched on. The user gets a working machine and a log line that says why.
func (a *App) ensureTakeoverFeasible() {
	if a.store == nil {
		return
	}
	st := a.store.Settings()
	if st.TunMode == TunOff {
		return
	}
	if isElevated() {
		return
	}
	if a.serviceReachable() {
		return
	}
	Log("TUN: mode %s is remembered, but there is no service and this process is not "+
		"elevated, so no adapter can be created. Falling back to the system proxy so the "+
		"machine has a working takeover instead of a tunnel that cannot exist",
		st.TunMode, "WARN")
	if _, err := a.store.UpdateSettings(map[string]interface{}{
		"tunMode":     string(TunOff),
		"systemProxy": true,
	}); err != nil {
		Log("TUN: could not record the fallback: %v", err, "WARN")
		return
	}
	a.mu.Lock()
	if a.tunRun == nil {
		a.tunRun = &tunRun{}
	}
	a.tunRun.Stage = "上次的 TUN 接管无法继续（没有常驻服务、也没有管理员权限），已自动切回系统代理；" +
		"想再用 TUN 请重新启用"
	a.tunRun.Mode = TunOff
	a.tunRun.Active = false
	a.mu.Unlock()
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

	// A port held by a core that is running and ours is not a conflict - it is the
	// situation this program deliberately creates. The core is started by the resident
	// service and outlives restarts of the interface, so on an ordinary second launch the
	// port is already held by our own core.
	//
	// Adopting it immediately rather than waiting is what makes a launch feel immediate.
	// Measured, before this branch existed:
	//
	//   21:13:47  root=D:\Zenith uiPort=7799        <- the process starts
	//   21:14:07  mixed port 7944 is still held by this installation's own core after 20s
	//   21:14:08  adopted a running core (pid 68580)
	//   21:14:09  UI ready at http://127.0.0.1:7799  <- the window appears
	//
	// Twenty-two seconds of a window that had not opened yet, every launch, reported by
	// the user as "a long time before anything happens". The wait exists for a core that is
	// on its way OUT; a core that is up is the answer, not the problem.
	if a.coreIsRunningOurs(want) {
		Log("mixed port %d is held by this installation's own running core; adopting it", want)
		a.adoptListeningCore(want)
		return
	}

	// Rotating the port is the last resort, and reaching it too early is actively
	// harmful: every program that stored the old port - including the system proxy
	// setting the user's browser reads - silently loses its connection. The user
	// noticed this happening repeatedly, and it was this code.
	//
	// The shape of the mistake was a gap between two checks. The wait below only ran
	// when the port had NO listener, on the reasoning that a lingering socket is not a
	// listener - but a core that is still shutting down IS a listener, and the one case
	// that actually occurs is our own core exiting. So the wait did not run for it, and
	// by the time the ownership check further down asked whether the holder was ours,
	// the holder had finished exiting and there was nobody left to ask. Neither check
	// covered "our own core, on its way out", which is the only way this ever happens.
	//
	//     mixed port 7917 is already in use by another program; moving Zenith to 7926
	//
	// It was not another program. It was the core that had been serving that port
	// seconds earlier.
	//
	// The loop now runs whenever the port is not free, and asks the right question at
	// each step rather than once at the end: is the holder ours, and if so, has it gone?
	deadline := time.Now().Add(portReleaseWait)
	waited := false
	for {
		if PortFreeToBind(want) {
			if waited {
				Log("mixed port %d was busy a moment ago and is ours again; keeping it", want)
			}
			return
		}
		// Is the holder ours?
		//
		// Not by reading its command line. Measured, and this is the reason the first
		// version of this fix changed nothing:
		//
		//     mihomo pid=42380  cmd=[]
		//
		// coreOwnsDataDir decides ownership by looking for the data directory in the
		// command line, and the command line of a core started by the elevated helper
		// cannot be read by this process. It came back empty, the test answered "not
		// ours", and the port was rotated away from a core that was in the middle of
		// shutting down.
		//
		// What is available without any privilege is whether the process is named like
		// our core and is listening on the port we configured. A foreign proxy is a
		// different program with a different name, so the distinction that matters is
		// still made - and it is made by something that works for every holder rather
		// than for the ones we happen to be able to inspect.
		heldByUs := false
		for _, pid := range ListeningPids(want) {
			if coreOwnsDataDir(pid, a.dataDir, a.rootDir) || looksLikeOurCore(pid) {
				heldByUs = true
				break
			}
		}
		if !heldByUs {
			// A real foreign program holds it. Waiting will not change that, and the
			// rotation below is the correct answer for it.
			break
		}
		if time.Now().After(deadline) {
			// Our own core is still holding it after the whole window. That is not a
			// conflict, so this must RETURN rather than fall through.
			//
			// Measured, and breaking out was not enough:
			//
			//   mixed port 7935 is still held by this installation's own core after 20s;
			//   not rotating
			//   [WARN] mixed port 7935 is already in use by another program; moving
			//          Zenith to 7944
			//
			// The message said it would not rotate and the next statement rotated. A
			// break out of the wait loop is a break out of the wait, not out of the
			// function - so the decision was made, logged, and then ignored by code that
			// had already been written to rotate.
			Log("mixed port %d is still held by this installation's own core after %s; "+
				"adopting it rather than moving aside", want, portReleaseWait)
			for _, pid := range ListeningPids(want) {
				if coreOwnsDataDir(pid, a.dataDir, a.rootDir) || looksLikeOurCore(pid) {
					a.adoptRunningCore(pid)
					break
				}
			}
			return
		}
		waited = true
		time.Sleep(200 * time.Millisecond)
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

// looksLikeOurCore reports whether a process is a core belonging to this program,
// without needing to read anything privileged.
//
// The name is the test, and it is a good one: mihomo is not installed system-wide, the
// copy that runs is the one in this program's own core directory, and a process by that
// name listening on the port this program configured is this program's core in every
// case that occurs. A different proxy product has a different executable name.
//
// This exists because the command-line test cannot see a core started under elevation,
// and that is exactly the core whose port must not be rotated away from - the one that
// was serving a moment ago and is shutting down.
func looksLikeOurCore(pid int) bool {
	if pid <= 0 {
		return false
	}
	name := strings.ToLower(ProcessName(pid))
	if name == "" {
		return false
	}
	return strings.Contains(name, "mihomo")
}

// coreIsRunningOurs reports whether the port is held by a core of ours that is up.
//
// Two questions, both cheap, and both have to be yes. The listener has to be a process
// named like our core, and this installation has to have a core running at all - which is
// asked of the core itself rather than inferred, because a core started by the resident
// service is not this process's child and nothing else would know about it.
func (a *App) coreIsRunningOurs(port int) bool {
	if !a.core.IsUp() {
		return false
	}
	for _, pid := range ListeningPids(port) {
		if coreOwnsDataDir(pid, a.dataDir, a.rootDir) || looksLikeOurCore(pid) {
			return true
		}
	}
	return false
}

// adoptListeningCore records the running core that owns the port.
func (a *App) adoptListeningCore(port int) {
	for _, pid := range ListeningPids(port) {
		if coreOwnsDataDir(pid, a.dataDir, a.rootDir) || looksLikeOurCore(pid) {
			a.adoptRunningCore(pid)
			return
		}
	}
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
		// Same gate. A machine that boots with TUN already configured must not
		// take the system proxy as well just because the saved setting says so.
		if res, err := a.enableSystemProxy("startup"); err != nil {
			Log("system proxy not enabled: %v", err, "WARN")
		} else if res.Refused != "" {
			Log("startup: leaving the system proxy off; %s", res.Detail)
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
	// These are deliberately local and start at now, not from the stored timestamps.
	//
	// A stored "last run" can be in the future after the system clock moves backwards -
	// which is what a time-zone or date change does - and every scheduled action here is
	// gated on time.Now().After(due). A future due never arrives, so scheduling would stop
	// silently and stay stopped. Measured after a time-zone change: the stored lastOptimize
	// read 2026-10-15T10:31:50 while the clock read 2026-10-15T01:17, nine hours ahead.
	//
	// Seeding from now costs one run of each action shortly after a launch, which is the
	// conservative direction: a refresh happens slightly early instead of never.
	lastSub := time.Now()
	lastOpt := time.Now()
	if stored := a.store.LastOptimize(); !stored.IsZero() {
		if t, clamped := clampFutureTime(stored); clamped {
			Log("the stored optimisation time (%s) is in the future; the system clock has "+
				"moved backwards, so scheduling treats it as due now rather than waiting "+
				"for a moment that may be hours away", stored.Format(time.RFC3339), "WARN")
		} else {
			lastOpt = t
		}
	}
	// Latch on whether the proxy is ALREADY ours at startup, rather than
	// assuming it is not. A normal shutdown hands the registry back or turns it
	// off, so on the next launch it must be taken again - but if a previous
	// instance is somehow still holding it, re-arming would fight over it.
	proxyArmed := a.sysproxy.Status().Owner == "zenith"
	// Rate limit for attempting to take the system proxy when TUN is holding the
	// traffic. The answer only changes when the tunnel is switched off, so a
	// per-tick retry would cost two PowerShell spawns every ten seconds to learn
	// nothing. See the attempt site for the reasoning.
	lastProxyAttempt := time.Now().Add(-30 * time.Second)
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
		//
		// This goes through enableSystemProxy like every other caller, so a loop
		// that ticks every ten seconds cannot re-take a setting that TUN is
		// holding. It did before: the exclusion lived in the interface handler
		// only, and this path turned the proxy back on underneath a running
		// tunnel, which is exactly the both-on state the design forbids.
		if !proxyArmed && st.SystemProxy && a.core.IsUp() {
			// A refusal is not retried on every tick.
			//
			// Deciding "is TUN really carrying this" costs two PowerShell spawns
			// (adapter state and the route table), and the loop runs every ten
			// seconds. Retrying a refusal at that rate would spend more time
			// asking than the question is worth, on the one path that must stay
			// cheap. One attempt per half minute is enough to notice that the
			// tunnel was switched off, which is the only thing that can change
			// the answer.
			if time.Since(lastProxyAttempt) >= 30*time.Second {
				lastProxyAttempt = time.Now()
				res, err := a.enableSystemProxy("background")
				if err != nil {
					Log("system proxy not enabled: %v", err, "WARN")
				} else if res.Took {
					proxyArmed = true
				}
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

// clampFutureTime reports whether a stored timestamp is in the future, and returns a
// usable replacement.
//
// The system clock is not monotonic. Changing the time zone, changing the date, or a
// virtual machine being restored from a snapshot can all move it backwards, and a stored
// "last run" timestamp then sits ahead of now. Every scheduled action is gated on
// time.Now().After(due), which can never become true while due is in the future - so
// scheduling stops silently and stays stopped until the clock catches up.
//
// Measured, after a time-zone change: lastOptimize was 2026-10-15T10:31:50 while the clock
// read 2026-10-15T01:17, so the next optimisation was due in nine hours and the automatic
// refresh had stopped without saying anything. Nothing in the log recorded it, because
// nothing had failed - the check simply never passed.
//
// The correction is to treat a future timestamp as "this has not run recently", which is
// the conservative reading: it allows one run now rather than suppressing runs for hours.
func clampFutureTime(t time.Time) (time.Time, bool) {
	if t.IsZero() {
		return t, false
	}
	if t.After(time.Now()) {
		return time.Time{}, true
	}
	return t, false
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

// nodeSpeedMS returns the number the slowness bar should be compared against.
//
// The core's endpoint is preferred because it measures the node rather than the node plus
// the tunnel. When it cannot answer - which it often cannot, see the notes on
// healthProbeThroughTunnel - the real-traffic figure is used, but only scaled down by the
// tunnel's own cost, so a bad number from a working endpoint cannot masquerade as a fast
// node.
func (a *App) nodeSpeedMS(name string, realTrafficMS int) int {
	if d, err := a.coreDelay(name, healthTimeoutMS); err == nil && d > 0 {
		return d
	}
	if realTrafficMS <= 0 {
		return 0
	}
	// The tunnel costs roughly this much on this machine; it is subtracted so the
	// fallback is comparable with the endpoint's number rather than with a raw round trip.
	if realTrafficMS > tunnelOverheadMS {
		return realTrafficMS - tunnelOverheadMS
	}
	return realTrafficMS
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

	// Keep the pool honest alongside the current node. Placed before the check on the
	// current node so that a sweep can never delay the answer to "is the node the user is
	// on still working".
	a.sweepPool(current)

	// Real traffic decides this, not the core's own probe. See healthProbeThroughTunnel
	// for the measurement that made the difference: four healthy nodes in six were
	// reported dead by the delay endpoint while carrying two out of two real requests.
	delay, derr := a.healthProbeThroughTunnel(healthTimeoutMS)
	if derr == nil && delay > 0 {
		a.mu.Lock()
		if a.healthFails > 0 {
			Log("health: %q is answering again (%dms)", current, delay)
		}
		// The counter is not reset to zero on a success, and that is the difference
		// between a node that is fine and a node that is mostly fine.
		//
		// Measured: a node failed 1/3, failed 2/3, answered once, and started again at
		// 1/3 - so the threshold was never reached and a node that was failing a third
		// of the time stayed selected indefinitely. An intermittent node reproduced the
		// user's symptom exactly: the connection worked, then did not, then did, while
		// every individual event looked like a blip the program had decided to forgive.
		//
		// A success decrements instead, so an occasional failure is forgiven and a
		// pattern is not.
		if a.healthFails > 0 {
			a.healthFails--
		}
		a.healthSwitches = 0
		a.healthLastEv = fmt.Sprintf("%s ok %dms", current, delay)
		a.mu.Unlock()

		// Answering is not the same as answering well. A node can stay reachable
		// while its real round trip degrades several times over, and ranking by
		// numbers measured half an hour ago will not notice. This is the check
		// that turns "delayed" into "switched".
		// The slowness decision uses a different measurement from the liveness one, because
		// they are answers to different questions.
		//
		// Measured on the same node, moments apart:
		//
		//	real traffic through the tunnel   1537, 1389, 1483, 1640, 1485, 1503, 1955, 1238 ms
		//	the core's /delay endpoint        238, 256, 304 ms
		//
		// The difference is about 1200ms and it is the tunnel's own cost, not the node's speed.
		// Feeding the first number to a bar set while the second was in use meant almost every
		// measurement read as "too slow", so the program moved off every node in turn - which
		// the user saw as the connection changing on its own, over and over.
		//
		// So: liveness is decided by real traffic, because that is what "can this node carry
		// anything" means. Slowness is decided by the endpoint, because that is the number that
		// isolates the node from the tunnel. A node that is genuinely slow shows up in both.
		a.reactToSlowness(current, float64(a.nodeSpeedMS(current, delay)))
		return
	}

	// The probe this loop uses is not trustworthy on its own, and that took two rounds
	// of measurement to establish.
	//
	// First measurement, over a three-hour run: healthy nodes alternated between
	// answering in 236ms and timing out on the core's /delay endpoint. Six nodes from
	// one scan, each probed twice - four answered both times, one answered then timed
	// out, one failed both times.
	//
	// Second measurement, which settled it: the same six nodes were each tested with
	// three real CONNECT requests through the running tunnel, bypassing the delay
	// endpoint entirely. All eighteen requests succeeded. The nodes were fine; the
	// probe was producing false failures, most likely because a 204 check through a
	// remote edge is sensitive to whatever else the machine is doing at that moment -
	// an optimisation scan, a large download - in a way a real connection is not.
	//
	// So a single timed-out probe is not evidence of anything and must not be counted.
	// Two in a row is the smallest amount of evidence worth acting on, and both probes
	// happen in one pass rather than a tick apart: the question is whether the node is
	// answering now, and a tick later is ten seconds of the user being stalled.
	//
	// The retry is also given more room than the first probe. If the machine is busy,
	// the second attempt needs to be able to succeed despite that.
	if delay2, err2 := a.healthProbeThroughTunnel(healthTimeoutMS * 2); err2 == nil && delay2 > 0 {
		// A blip, not a failure. Recorded so it is visible without being acted on: no
		// counter moves, no switch happens, and the user keeps the connection they had.
		a.mu.Lock()
		a.healthLastEv = fmt.Sprintf("%s flaked then answered %dms", current, delay2)
		a.mu.Unlock()
		Log("health: %q missed one probe but answered %dms on an immediate retry; "+
			"treating it as a blip rather than a dead node", current, delay2)
		return
	}
	Log("health: %q missed two probes in a row; counting it as a failure", current)

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
			// Selecting it first is what makes a real request possible: the tunnel carries
			// whatever PROXY points at, so a node can only be tested for real by using it.
			// If it does not carry traffic it is put back immediately, and the next
			// candidate is tried.
			if err := a.core.Select("PROXY", p.Name); err != nil {
				continue
			}
			if d, err := a.healthProbeThroughTunnel(healthTimeoutMS); err == nil && d > 0 {
				a.noteNodeAlive(p.Name)
				next = p.Name
				break
			}
		}
	}
	if next == "" {
		// The search tested candidates by using them, so it left PROXY on whichever one it
		// tried last. Put it back before giving up.
		//
		// Measured: without this, a failed search could leave the tunnel pointing at a node
		// that had just failed its own real-traffic test - which is worse than the node it
		// replaced, and is a change the user never asked for and cannot explain.
		if err := a.core.Select("PROXY", current); err == nil {
			a.core.CloseConnections()
		}
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

// noteNodeAlive records that a node answered a probe just now.
//
// It is the only thing that makes a node eligible for auto-pick, which is what stops the
// program choosing from a list of measurements taken hours ago.
func (a *App) noteNodeAlive(name string) {
	if name == "" {
		return
	}
	a.mu.Lock()
	if a.healthAlive == nil {
		a.healthAlive = map[string]time.Time{}
	}
	a.healthAlive[name] = time.Now()
	a.publishHealth()
	a.mu.Unlock()
}

// sweepPool verifies the pool the ranking is drawn from, a few nodes per pass.
//
// Without this, "verified" means "verified once, possibly hours ago". Measured: with the
// tunnel up and answering for baidu, google, github and youtube, the optimised pool held
// 66 nodes and the large majority timed out on every target - while the ranking went on
// treating their scan-time numbers as current, choosing the fastest of them, switching
// onto it, and leaving the health loop to switch away again. The user reported it as
// every optimised node failing at once.
//
// A few nodes per pass rather than all of them, because this shares a loop with the
// check that keeps the current node working, and that check must not be delayed. With a
// ten-second tick and three nodes a pass, a pool of sixty is covered in about three
// minutes - which is the right order of magnitude for a list that changes on the scale of
// a scan, not a second.
func (a *App) sweepPool(current string) {
	optimized, _ := a.nodeSet()
	if len(optimized) == 0 {
		return
	}
	const perPass = 3
	const staleAfter = 3 * time.Minute

	a.mu.Lock()
	if a.healthProbed == nil {
		a.healthProbed = map[string]time.Time{}
	}
	if a.healthAlive == nil {
		a.healthAlive = map[string]time.Time{}
	}
	// Which nodes are worth asking about, decided under the lock so two passes cannot
	// pick the same node.
	//
	// Best-ranked first, not in list order. Measured, and this is why the pool stayed
	// useless for minutes after a scan: a pool of 63 nodes covered three per pass takes
	// about three and a half minutes to sweep, and the loop walked it in whatever order
	// the store happened to hold. The nodes the ranking actually wanted to use could be
	// anywhere in that queue, so "waiting for a sweep" could mean waiting minutes for the
	// answer to a question about the node it was already going to pick.
	//
	// The ranking's own order is the right order to verify in, because it is the order the
	// answer will be used in.
	ranked := make([]Proxy, len(optimized))
	copy(ranked, optimized)
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].MeasuredMS > 0 && (ranked[j].MeasuredMS <= 0 ||
			ranked[i].MeasuredMS < ranked[j].MeasuredMS)
	})

	var todo []string
	now := time.Now()
	for _, p := range ranked {
		if p.Name == current {
			continue // the current node is already checked by the loop
		}
		if now.Sub(a.healthProbed[p.Name]) < staleAfter {
			continue
		}
		todo = append(todo, p.Name)
		if len(todo) >= perPass {
			break
		}
	}
	for _, n := range todo {
		a.healthProbed[n] = now
	}
	a.mu.Unlock()

	for _, name := range todo {
		if d, err := a.coreDelay(name, healthTimeoutMS); err == nil && d > 0 {
			a.mu.Lock()
			a.healthAlive[name] = time.Now()
			a.publishHealth()
			a.mu.Unlock()
		}
	}
}

// healthProbe measures a node through the core, trying more than one target.
//
// The health loop used a single target and the rest of the program used three. That
// difference is the whole of a reported outage.
//
// Measured, with the tunnel up and working - baidu, google, github and youtube all
// answering through it - the current node measured 372ms while three other optimised
// nodes timed out at exactly 8.0 seconds on the health loop's target:
//
//	/proxies/<node>/delay?timeout=8000&url=https://www.gstatic.com/generate_204
//	优选01 -> HTTP 504 Timeout   (8.0s)
//	优选02 -> HTTP 504 Timeout   (8.0s)
//	优选03 -> HTTP 504 Timeout   (8.0s)
//
// The optimiser reaches those same nodes because it falls back through
// google and cp.cloudflare.com before calling one dead (optimizer.go:1226). The health
// loop declared them dead on the first target's timeout, switched away, auto-pick
// returned to another node from the same scan, and the cycle repeated - which the user
// saw as every optimised node failing at once while the network was in fact fine.
//
// So the health loop now asks the same question in the same way: any one of these
// targets answering is proof of life.
// attempts is 1 for a first look and 2 for a confirmation. The first look tries every
// target once with a short timeout, because the common case is that the node is fine and
// the first target answers - and a health loop that spends eighteen seconds deciding is
// a health loop that cannot notice an outage quickly. Only when nothing answers is the
// whole list tried again, which is when the extra time is worth spending.
func (a *App) healthProbe(name string, timeoutMS int, attempts int) (int, error) {
	return a.healthProbeWith(name, timeoutMS, attempts, healthProbeTargets)
}

// coreDelay is the core's own delay endpoint, kept only for ranking.
//
// It is not evidence that a node works. Measured, with the tunnel up and every one of six
// nodes answering two out of two real CONNECT requests:
//
//	优选01 · 172.66.200.1    /delay 249ms    CONNECT OK/OK
//	优选02 · 108.162.192.1   /delay [504]    CONNECT OK/OK
//	优选03 · 172.69.250.1    /delay [504]    CONNECT OK/OK
//	优选04 · 162.159.1.1     /delay [503]    CONNECT OK/OK
//	优选05 · 172.69.30.1     /delay [504]    CONNECT OK/OK
//	优选06 · 172.66.1.1      /delay 249ms    CONNECT OK/OK
//
// Four of six were reported dead by the endpoint while carrying traffic. The health loop
// used that endpoint to decide which nodes were alive, so it spent its time switching away
// from nodes that worked - which the user reported, exactly, as adding nodes that then
// could not be used.
//
// The number it returns is still the best relative ranking available, so it is kept for
// that. It is no longer an answer to "is this node working".
func (a *App) coreDelay(name string, timeoutMS int) (int, error) {
	return a.healthProbeWith(name, timeoutMS, 1, healthProbeTargets)
}

// healthProbeThroughTunnel asks whether traffic can actually pass, by making a real
// request through the running tunnel.
//
// This is the direct question rather than a proxy for it. The core's delay endpoint makes
// its own connection to the node from inside the core, and its failures say as much about
// the core's own state at that moment as about the node - which is why four healthy nodes
// in six were reported dead by it.
//
// The tunnel is used the way any program on the machine uses it: by sending a request
// through the mixed port. That path goes through the proxy, out to the node, and back, and
// if it completes then the node works, whatever the core's own probe thinks.
//
// TUN does not change the answer. The mixed port listens in both modes, and in TUN mode the
// request still egresses through the selected node, so this is one test that means the same
// thing in both.
func (a *App) healthProbeThroughTunnel(timeoutMS int) (int, error) {
	port := a.store.Settings().MixedPort
	if port <= 0 {
		return 0, fmt.Errorf("混合端口未配置")
	}
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return 0, err
	}
	client := &http.Client{
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
			// The point is whether the tunnel carries the request, so a certificate
			// problem must not be able to masquerade as a dead node.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	defer client.CloseIdleConnections()

	var lastErr error
	for _, target := range healthProbeTargets {
		started := time.Now()
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Zenith/"+AppVersion)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		// Any completed HTTP exchange is proof the tunnel carried it. The status is not
		// the question - a captive portal answering 200 and a generate_204 answering 204
		// are both evidence that bytes made the round trip.
		if resp.StatusCode > 0 {
			return int(time.Since(started).Milliseconds()), nil
		}
		lastErr = fmt.Errorf("没有收到响应")
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的探测目标")
	}
	return 0, lastErr
}

// healthProbeWith is healthProbe against a chosen target list.
//
// The sweep uses a shorter list than the check on the current node, and the arithmetic is
// why. Three targets at a six-second timeout is up to eighteen seconds for one node; three
// nodes per pass would make a pass a minute long, and a pool of sixty-six would take
// eleven minutes to cover - longer than a confirmed node stays eligible, so nodes would
// expire before being re-checked and the pool would drain itself.
//
// The current node is worth all three targets: it is the one carrying the user's traffic,
// and a wrong answer about it either strands them or switches them for nothing. A
// candidate only has to be filtered, and the first two targets are the ones that answer in
// practice.
func (a *App) healthProbeWith(name string, timeoutMS int, attempts int, targets []string) (int, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		for _, target := range targets {
			delay, err := a.core.Delay(name, timeoutMS, target)
			if err != nil {
				lastErr = err
				continue
			}
			if delay > 0 {
				return delay, nil
			}
			lastErr = fmt.Errorf("内核报告延迟为 0")
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的探测目标")
	}
	return 0, lastErr
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
	// Alive records, per node, when it last proved it could carry traffic.
	//
	// This is the answer to the question the rest of the program was guessing at. A
	// scan measures a node once and writes the number into its name and its record;
	// nothing ever revisits that judgement. Measured: with the tunnel up and answering,
	// the pool held 66 optimised nodes of which the large majority timed out on every
	// target - and auto-pick ranked by the number written hours earlier, chose one,
	// switched onto it, and the health loop switched away again. The user saw every
	// optimised node failing at once.
	//
	// A node is now "alive" because it answered a probe, recently, and that is the only
	// thing auto-pick will choose.
	Alive map[string]time.Time
}

// publishHealth copies the current bookkeeping into a fresh snapshot and swaps
// it in. Callers must hold a.mu.
func (a *App) publishHealth() {
	snap := &healthSnapshot{
		Banned: make(map[string]time.Time, len(a.healthBanned)),
		Flaky:  make(map[string]int, len(a.nodeFlaky)),
		Alive:  make(map[string]time.Time, len(a.healthAlive)),
	}
	for k, v := range a.healthBanned {
		snap.Banned[k] = v
	}
	for k, v := range a.nodeFlaky {
		snap.Flaky[k] = v
	}
	for k, v := range a.healthAlive {
		snap.Alive[k] = v
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

	// tunnelOverheadMS is roughly what the tunnel itself adds to a round trip, measured
	// rather than assumed. On the same node, moments apart: real traffic through the tunnel
	// took 1238-1955ms while the core's own probe of that node took 238-304ms.
	//
	// Two questions were being answered with one number, and the bar had been set for the
	// smaller one - so once liveness moved to real traffic, almost every measurement read as
	// "too slow" and the program moved off every node in turn.
	tunnelOverheadMS = 1200

	// aliveFor is how long a successful probe keeps a node eligible for auto-pick.
	//
	// The number is not free: it must exceed one full pass of the sweep, or nodes expire
	// before they are re-checked and the pool drains itself. The arithmetic is
	//
	//	3 nodes per pass x 2 targets x 6s worst case = 36s, plus the current node's check
	//	66 nodes / 3 per pass                   = 22 passes, about 13 minutes worst case
	//
	// so this is set well above that worst case and not to a round number that happens to
	// feel right. Shorter and the pool empties under load; much longer and a node that has
	// died stays eligible, which is the fault this exists to fix.
	aliveFor = 20 * time.Minute
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
		// A node is a candidate only if it answered a probe recently.
		//
		// This is the fix for the reported outage. MeasuredMS and the "323ms" in the node
		// name are written by a scan and then never revisited; the pool held 66 entries
		// and most of them timed out on every target while the ranking went on treating
		// their scan-time numbers as current. Ranking chose the fastest of a list of dead
		// nodes, switched onto it, and the health loop switched away - repeatedly, which
		// the user saw as every optimised node failing at once.
		//
		// A measurement is a statement about the past. Aliveness is a statement about now,
		// and only the second one can be acted on.
		if h := a.HealthView(); h != nil {
			if at, bad := h.Banned[p.Name]; bad && time.Since(at) < 2*time.Minute {
				continue // found dead moments ago, do not rank it at all
			}
			if at, ok := h.Alive[p.Name]; !ok || time.Since(at) > aliveFor {
				continue // never confirmed, or not confirmed recently enough
			}
			ms += float64(h.Flaky[p.Name]) * flakyPenaltyMS
		}
		if bestMS == 0 || ms < bestMS {
			best, bestMS = p, ms
		}
	}
	if bestMS == 0 {
		// Nothing has been confirmed alive yet - which is the state of the program for the
		// first seconds after a start, and after a subscription change before the first
		// sweep has covered anything.
		//
		// Staying put is the correct answer, not guessing. The health loop is sweeping the
		// pool and will confirm nodes within a pass or two, and until then the node in use
		// is the one the user has, which is a better bet than one this program has no
		// current evidence for.
		a.pickDebug(2, "no node has been confirmed alive recently; waiting for a sweep")
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
		// A deliberate pick is honoured, but not past the point where the node it named
		// has stopped working. Ten minutes of a dead node because the user clicked it
		// once is not respect for their choice, it is the program refusing to help.
		//
		// Measured, and it is why the node list looked wrong: the log repeated
		// "user picked … inside the grace window" every ten seconds for minutes while
		// that node kept failing its probes.
		fails, _ := func() (int, int) {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.healthFails, 0
		}()
		if held := time.Since(pickedAt); held < userPickGrace && fails < healthFailLimit {
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
	aliveView := a.HealthView()
	aliveCount := 0
	for _, n := range all {
		delay := 0
		if p, ok := proxies[n.Name]; ok {
			delay = p.Delay
		}
		// Whether this node has proved it can carry traffic recently, and how long ago.
		//
		// A scan writes a number into a node's name and nothing revisits it, so the list
		// could show sixty nodes all described by measurements taken hours earlier - and
		// the user asked, reasonably, why so many of them did not work. The list now says
		// which ones have answered, so that is visible instead of having to be inferred
		// from the program repeatedly switching away from them.
		alive := false
		aliveAgo := 0
		if aliveView != nil {
			if at, ok := aliveView.Alive[n.Name]; ok && time.Since(at) <= aliveFor {
				alive = true
				aliveAgo = int(time.Since(at).Seconds())
				aliveCount++
			}
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
			"alive":     alive,
			"aliveAgo":  aliveAgo,
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
		// How much of the optimised pool has actually answered recently. The interface
		// says this, because "63 optimised nodes" when four of them work is a statement
		// that misleads more than it informs.
		"aliveCount": aliveCount,
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
	// Global mode routes everything through the GLOBAL selector, and that selector
	// starts at DIRECT because that is mihomo's default for it. Setting the mode
	// alone therefore made "global" mean "everything direct": measured with global
	// selected, the core's own table showed
	//
	//	GLOBAL  type=Selector  now=[DIRECT]
	//
	// and the traffic log was full of "using GLOBAL" for foreign sites while every
	// one of them timed out - the opposite of what the switch promises.
	//
	// So the selector is pointed at PROXY, which is the group this program keeps on
	// the chosen node. Rule mode does not consult GLOBAL at all, so leaving it set
	// is harmless there and means switching back to global works immediately.
	if mode == "global" {
		if err := a.core.Select("GLOBAL", "PROXY"); err != nil {
			Log("could not point GLOBAL at PROXY: %v", err, "WARN")
			return fmt.Errorf("已切换为全局模式，但未能把 GLOBAL 指向 PROXY（%v）："+
				"全局模式会把所有流量都按 GLOBAL 组的当前选择处理，而它默认是 DIRECT，"+
				"那等于让所有网站都直连", err)
		}
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
		// A scan that just finished is evidence, and it was being thrown away.
		//
		// The optimiser only keeps an edge that completed a real WebSocket upgrade and
		// carried a real response through it, seconds ago. That is a stronger statement
		// than any health probe, and yet the pool sweep started from nothing and had to
		// rediscover it three nodes at a time - so for the first minutes after a scan
		// auto-pick had nothing it was allowed to choose and reported "no node has been
		// confirmed alive recently; waiting for a sweep" while the machine sat on
		// whatever node it had.
		//
		// The nodes the scan just proved are recorded as alive. They will be re-probed by
		// the sweep like everything else, so a stale entry cannot survive; this only
		// removes the blind period at the start.
		a.mu.Lock()
		if a.healthAlive == nil {
			a.healthAlive = map[string]time.Time{}
		}
		for _, n := range best {
			a.healthAlive[n.Name] = time.Now()
		}
		a.publishHealth()
		a.mu.Unlock()
		Log("optimize: %d node(s) recorded as verified by the scan itself", len(best))

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

// validatePortPatch rejects a settings patch whose ports cannot work.
//
// The bound is the TCP port range, and 0 is refused too: zero means "let the OS
// choose" to a listener, but every other part of this program treats a stored
// port as the port it serves - the generated configuration, the system proxy it
// points at, and the DNS port derived as MixedPort+300. A stored 0 is therefore a
// port that no component can agree on.
//
// The upper end is checked against the DNS derivation as well, so a port that is
// itself valid but whose DNS port is not cannot be stored either.
func validatePortPatch(patch map[string]interface{}) error {
	check := func(key string, v interface{}, allowZero bool) error {
		n, ok := v.(int)
		if !ok {
			return fmt.Errorf("%s 必须是整数端口号", key)
		}
		if n == 0 && allowZero {
			return nil
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("%s 必须是 1-65535 之间的端口号，收到 %d。"+
				"超出范围的端口无法监听，系统代理会指向一个没人服务的端口，"+
				"那会让这台机器没有网络", key, n)
		}
		return nil
	}
	if v, ok := patch["mixedPort"]; ok {
		if err := check("mixedPort", v, false); err != nil {
			return err
		}
		// The DNS listener is derived as MixedPort+300 and must also be valid.
		if n, isInt := v.(int); isInt && n+300 > 65535 {
			return fmt.Errorf("mixedPort 不能大于 65235：DNS 监听端口按 mixedPort+300 "+
				"推导，%d 会得到 %d，超出端口范围", n, n+300)
		}
	}
	for _, key := range []string{"uiPort", "controlPort", "apiPort"} {
		if v, ok := patch[key]; ok {
			if err := check(key, v, false); err != nil {
				return err
			}
		}
	}
	return nil
}

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
	// Ports are validated before anything is written, because a bad one takes the
	// machine offline and does it silently.
	//
	// Measured while testing this interface: a patch of {"mixedPort":99999} was
	// accepted, ok:true, and the value was persisted. The core cannot bind 99999
	// (the maximum is 65535), so the mixed listener did not exist - and the system
	// proxy, if it is enabled, points at a port nobody serves, which is exactly the
	// "no internet and no explanation" state this program has spent versions
	// avoiding. The startup guard repairs it only on the NEXT launch.
	//
	// Rejecting the patch is the only place that can refuse before the damage:
	// after the write, the port is already the saved configuration.
	if err := validatePortPatch(patch); err != nil {
		return before, err
	}
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
			// Through the same gate as every other caller: a settings patch must
			// not be able to put both takeovers on at once.
			res, err := a.enableSystemProxy("settings")
			if err != nil {
				Log("could not enable system proxy: %v", err, "WARN")
			} else if res.Refused != "" {
				Log("settings asked for the system proxy but %s", res.Detail, "WARN")
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
