package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	AppName    = "Zenith"
	AppVersion = "1.0.0"
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
	configPath string
	secret     string
	dnsPort    int

	mu          sync.Mutex
	optimizing  bool
	lastErr     string
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

// ---- startup --------------------------------------------------------------

// Boot prepares the config and starts the core in the BACKGROUND.
//
// It deliberately does not block on the core: a fresh install has to unpack the
// geodata files on first run and that can take up to a minute. The window must
// appear immediately so the user sees progress instead of a frozen app.
func (a *App) Boot() {
	snap := a.store.Snapshot()
	st := snap.Settings

	nodes := snap.Optimized
	if len(nodes) == 0 {
		nodes = snap.BaseNodes
	}
	a.writeConfig(nodes, st)
	go a.bootCore()
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
	lastSub := time.Now()
	lastOpt := time.Now()
	proxyArmed := false
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
	cfg := BuildConfig(nodes, st, a.secret, a.store.Snapshot().Current, a.dnsPort)
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
		"autoPick":     autoPick,
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

func (a *App) Switch(name string) error {
	if err := a.core.Select("PROXY", name); err != nil {
		return err
	}
	// drop live sockets so a bad route is not kept alive
	a.core.CloseConnections()
	return a.store.SetCurrent(name)
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
		_ = a.core.Select("PROXY", cur)
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

