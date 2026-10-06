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
	"time"
)

const (
	AppName    = "Zenith"
	AppVersion = "1.0.0"

	// coreStartGrace is how long the watchdog waits before it decides the core
	// is broken. A first run against an empty data directory downloads the rule
	// databases, which on a slow link takes a couple of minutes.
	coreStartGrace = 4 * time.Minute
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

	mu          sync.Mutex
	optimizing  bool
	lastErr     string
	// pending auto-pick: a marginal win has to persist before it is acted on
	pickCandidate string
	pickSince     time.Time
	pickWatching  bool
	// the user's most recent deliberate node choice, respected for a while
	userPicked   string
	userPickedAt time.Time
	quitting    bool
	stopCh      chan struct{}
	onQuit      func()
	trafficSnap Connections
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

	app := &App{
		store:      store,
		dataDir:    dataDir,
		rootDir:    rootDir,
		logDir:     logDir,
		configPath: filepath.Join(dataDir, "config.yaml"),
		secret:     "zenith-" + fmt.Sprint(time.Now().UnixNano()%1_000_000),
		dnsPort:    st.MixedPort + 300,
		stopCh:     make(chan struct{}),
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
	st := store.Settings()
	a.dnsPort = st.MixedPort + 300
	// the core always lives next to the executable, never inside the data dir
	a.core = NewCore(filepath.Join(a.rootDir, "core", "mihomo.exe"),
		dataDir, a.configPath, a.secret, st.ControlPort)
	a.opt = NewOptimizer(dataDir)
	a.sysproxy = NewSystemProxy(dataDir)
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
	a.lastErr = fmt.Sprintf("端口 %d 已被其他程序占用，已自动改用 %d", want, free)
}

func (a *App) bootCore() {
	st := a.store.Settings()
	if err := a.core.Start(); err != nil {
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

		if !a.core.IsUp() {
			// Give the core room to finish its first start. A brand new data
			// directory has no rule databases yet, so mihomo downloads them and
			// that takes far longer than the health check interval. Restarting
			// it mid-download looped forever, because every restart began the
			// same download again and the core never got to answer.
			if time.Since(started) < coreStartGrace {
				continue
			}
			if a.core.Ensure() {
				a.lastErr = ""
			}
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

		// Keep the fastest verified node in use. The core's own url-test only
		// knows whether a node answers a 204 probe; Zenith knows the real
		// WebSocket handshake time it measured. This reuses that measurement so
		// "自动" means the fastest node Zenith actually proved, not the fastest
		// one that happens to answer a ping.
		if !st.AutoPickOff && a.core.IsUp() && !a.opt.Running() {
			if picked, changed := a.enforceFastest(); changed {
				Log("auto-pick: switched to the fastest verified node %q (%.0fms)", picked.Name, picked.delay)
			}
		}

		if st.SubscriptionAutoUpdate {
			due := lastSub.Add(time.Duration(st.SubscriptionIntervalHours) * time.Hour)
			if time.Now().After(due) {
				lastSub = time.Now()
				if id := a.store.Snapshot().SelectedSub; id != "" {
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
		if bestMS == 0 || ms < bestMS {
			best, bestMS = p, ms
		}
	}
	if bestMS == 0 {
		return pickResult{}, false
	}

	proxies, err := a.core.Proxies()
	if err != nil {
		return pickResult{}, false
	}
	current := ""
	if g, ok := proxies["PROXY"]; ok {
		current = g.Now
	}
	if current == best.Name {
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
			return pickResult{}, false
		}
	}

	// Nothing to fix when the current node is already effectively the fastest,
	// or when the difference is inside the noise band.
	if curMS > 0 {
		delta := curMS - bestMS
		if delta < pickNoiseFloorMS {
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
				return pickResult{}, false
			}
		}
	}

	if err := a.core.Select("PROXY", best.Name); err != nil {
		return pickResult{}, false
	}
	a.core.CloseConnections()
	_ = a.store.SetCurrent(best.Name)
	a.resetPickWatch()
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
		optimized = optimized[:n]
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
	for _, p := range optimized {
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
	return out
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
}

// applyConfig rewrites the config and hot reloads it. No process restart.
func (a *App) applyConfig() error {
	a.writeConfig(a.mergedNodes(), a.store.Settings())
	if !a.core.IsUp() {
		return a.core.Start()
	}
	return a.core.Reload()
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
	current := snap.Current
	if group != nil && group.Now != "" {
		current = group.Now
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
		"ok":           true,
		"app":          AppName,
		"version":      AppVersion,
		"coreUp":       a.core.IsUp(),
		"corePid":      a.core.Pid(),
		"coreVersion":  a.core.Version(),
		"coreUptime":   a.core.Uptime(),
		"mode":         st.Mode,
		"current":      current,
		"autoPick":     autoPick, // what the core's AUTO group currently chooses
		"autoPickOn":   !st.AutoPickOff,
		"fastestName":  fastest.Name,
		"fastestMS":    fastestMS,
		"nodes":        list,
		"nodeCount":    len(list),
		"optCount":     len(optimized),
		"baseCount":    len(base),
		"storedCount":  len(snap.Optimized),
		"isOptimized":  isOptimized,
		"settings":     st,
		"systemProxy":  a.sysproxy.Status(),
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
		best, _, err := a.opt.ScanEdges(snap.BaseNodes, st, minWanted)
		if err != nil {
			a.lastErr = err.Error()
			Log("optimize failed: %v", err, "ERR")
			return
		}
		if err := a.store.SetNodes(nil, best); err != nil {
			Log("could not save optimized nodes: %v", err, "ERR")
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
	text, info, err := FetchSubscription(rawURL, "")
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
	text, info, err := FetchSubscription(target.URL, target.UserAgent)
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
	snap := a.store.Snapshot()
	subs := snap.Subscriptions
	for i := range subs {
		subs[i].Enabled = subs[i].ID == id
	}
	_ = a.store.SetSubscriptions(subs)
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
	needReload := false
	for _, k := range []string{"mixedPort", "apiPort", "directCNDomains", "blockAds", "customRules"} {
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
		_ = a.core.Start()
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
	a.core.Stop()
	a.sysproxy.Restore()
	_ = a.store.Save()
	Log("Zenith stopped")
	if a.onQuit != nil {
		a.onQuit()
	}
	os.Exit(0)
}

