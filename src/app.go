package main

import (
	"encoding/json"
	"fmt"
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

// ---- config ---------------------------------------------------------------

func (a *App) writeConfig(nodes []Proxy, st Settings) {
	cfg := BuildConfig(nodes, st, a.secret, a.store.Snapshot().Current, a.dnsPort)
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o644); err != nil {
		Log("could not write config: %v", err, "ERR")
	}
}

// applyConfig rewrites the config and hot reloads it. No process restart.
func (a *App) applyConfig() error {
	snap := a.store.Snapshot()
	nodes := snap.Optimized
	if len(nodes) == 0 {
		nodes = snap.BaseNodes
	}
	a.writeConfig(nodes, snap.Settings)
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

	nodes := snap.Optimized
	isOptimized := true
	if len(nodes) == 0 {
		nodes = snap.BaseNodes
		isOptimized = false
	}
	list := make([]map[string]interface{}, 0, len(nodes))
	for _, n := range nodes {
		delay := 0
		if p, ok := proxies[n.Name]; ok {
			delay = p.Delay
		}
		list = append(list, map[string]interface{}{
			"name":   n.Name,
			"server": n.Server,
			"port":   n.Port,
			"type":   n.Type,
			"delay":  delay,
			"active": n.Name == current,
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
		"isOptimized":  isOptimized,
		"settings":     st,
		"systemProxy":  a.sysproxy.Status(),
		"optimizing":   a.opt.Running(),
		"progress":     a.opt.Progress(),
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
		nodes := snap.BaseNodes
		if len(nodes) == 0 {
			nodes = snap.Optimized
		}
		if len(nodes) == 0 {
			a.lastErr = "还没有节点：请先在「订阅」页添加一个订阅"
			Log("%s", a.lastErr, "WARN")
			return
		}
		st := snap.Settings
		best, _, err := a.opt.ScanEdges(nodes, st)
		if err != nil {
			a.lastErr = err.Error()
			Log("optimize failed: %v", err, "ERR")
			return
		}
		if err := a.store.SetNodes(nil, best); err != nil {
			Log("could not save optimized nodes: %v", err, "ERR")
		}
		// keep the user's pick when it survived, otherwise take the new winner
		cur := a.store.Snapshot().Current
		names := make([]string, 0, len(best))
		for _, n := range best {
			names = append(names, n.Name)
		}
		if !contains(names, cur) {
			cur = best[0].Name
			_ = a.store.SetCurrent(cur)
		}
		if err := a.applyConfig(); err != nil {
			Log("hot reload after optimize failed: %v", err, "WARN")
		}
		_ = a.core.Select("PROXY", cur)
		_ = a.store.SetLastOptimize(time.Now())
		a.lastErr = ""
		Log("optimize done: %d nodes, current=%s", len(best), cur)
	}()
	return true
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

	// anything that changes the generated config needs a rewrite + reload
	needReload := false
	for _, k := range []string{"mixedPort", "apiPort", "directCNDomains", "blockAds", "customRules", "keepNodes"} {
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

// ensure json round trip helpers are used
var _ = json.Marshal
