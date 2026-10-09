package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Zenith - a small, self contained Clash client.
//
// Nothing has to be installed: the executable, the proxy core and the UI all
// live in the repository, so a fresh clone runs by double clicking.
// ---------------------------------------------------------------------------

func main() {
	// Detached recovery path, and it has to be handled BEFORE flag.Parse.
	//
	// flag.Parse exits the process with status 2 on an unknown flag, so a
	// watchdog that is dispatched after it can never run at all. That is exactly
	// what happened: the helper was spawned, the child died on its own argument,
	// and the crash protection the user was told about did not exist. The check
	// therefore happens first and does not rely on the flag package.
	if isSelfTestInvocation() {
		// Reports what the pre-parse dispatch decided, and exits.
		//
		// It prints the decision for the argument list it was given as well as the
		// one it is running under, so a build can prove both shapes are classified
		// correctly without executing either of them - running the real watchdog
		// would clear a system proxy pointing at a dead port, and a build check
		// must not be able to change the machine it runs on.
		// The sample is a full argument vector including the program name, which is
		// the same shape os.Args has: watchdogShapeOf reads index 1 onward.
		sample := []string{"zenith.exe", "-watchdog", `C:\data`, "7899"}
		fmt.Printf("selftest ok args=%d watchdog=%v sample=%v\n",
			len(os.Args),
			isWatchdogInvocation(),
			watchdogShapeOf(sample))
		return
	}
	if isWatchdogInvocation() {
		runWatchdogFromArgs()
		return
	}

	var (
		headless = flag.Bool("headless", false, "run the backend only, without a window")
		browser  = flag.Bool("browser", false, "open the UI in the default browser")
		stop     = flag.Bool("stop", false, "stop a running Zenith and exit")
		noProxy  = flag.Bool("no-proxy", false, "run without touching the system proxy")
		version  = flag.Bool("version", false, "print the version and exit")
		portFlag = flag.Int("port", 0, "UI port (default 7799)")
		dataFlag = flag.String("datadir", "", "use a different data directory")
		// Passed by the instance that requests elevation, so the elevated helper
		// reads exactly the same tree. Inferring it is not reliable: the helper can
		// be started with a different working directory.
		rootFlag = flag.String("root", "", "internal: the program directory to use")
		// Raised by the elevation request. The elevated instance runs the same
		// product; it only differs in having the rights the adapter and the routes
		// need, and it is the one that performs the activation transaction.
		tunElevated = flag.Bool("tun-elevated", false, "internal: continue a TUN enable with administrator rights")
		tunModeFlag = flag.String("tun-mode", "", "internal: the TUN mode the elevated instance should activate")
	)
	flag.Parse()

	// A GUI-subsystem binary has no console, so an unhandled panic would vanish
	// without a trace. Catch it and put it in the log instead.
	defer func() {
		if r := recover(); r != nil {
			Log("PANIC: %v\n%s", r, debug.Stack(), "ERR")
			Info(AppName, fmt.Sprintf("Zenith 遇到内部错误并已停止：\n%v\n\n详情见 logs/zenith.log", r))
			os.Exit(1)
		}
	}()

	if *version {
		fmt.Printf("%s %s (%s)\n", AppName, AppVersion, goVersion())
		return
	}

	var rootDir string
	if *rootFlag != "" {
		// An explicit root wins, so an elevated helper operates on the same tree as
		// the instance that asked for it.
		rootDir = *rootFlag
		if abs, err := filepath.Abs(rootDir); err == nil {
			rootDir = abs
		}
	} else {
		var err error
		rootDir, err = resolveRoot()
		if err != nil {
			fatal("cannot locate the program directory: %v", err)
		}
	}

	if *stop {
		stopRunning(rootDir)
		return
	}

	app, err := NewApp(rootDir)
	if err != nil {
		fatal("initialisation failed: %v", err)
	}
	if *dataFlag != "" {
		// Isolated run: used for testing so the real data directory, ports and
		// system proxy are untouched.
		abs, aerr := filepath.Abs(*dataFlag)
		if aerr != nil {
			fatal("bad -datadir: %v", aerr)
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			fatal("cannot create -datadir: %v", err)
		}
		// An isolated run must not destroy what is already there.
		//
		// This used to write an empty state.json whenever free.flag was absent,
		// without checking whether the directory already held a real one. Pointing
		// -datadir at a directory in use therefore wiped the user's subscriptions,
		// nodes and settings - silently, and with nothing to restore from. That
		// happened, to a real data directory, and it is the worst failure this
		// program can have.
		//
		// The rule now: never overwrite an existing state.json. A directory is only
		// initialised when it has none.
		free := filepath.Join(abs, "free.flag")
		stateFile := filepath.Join(abs, "state.json")
		if _, err := os.Stat(free); err != nil || !fileExists(stateFile) {
			if _, err := os.Stat(stateFile); err == nil {
				// A real state file is present. Adopt it rather than replacing it,
				// and say so, because the operator asked for isolation and is not
				// getting it.
				Log("isolated run: %s already holds a state file; using it as-is rather "+
					"than initialising an empty one", abs, "WARN")
				_ = os.WriteFile(free, []byte("1"), 0o644)
			} else {
				_ = os.WriteFile(free, []byte("1"), 0o644)
				_ = os.WriteFile(stateFile,
					[]byte(`{"settings":{"systemProxy":false}}`), 0o644)
			}
		}
		app.rebindDirs(abs)
		// Make the promise real. Announcing "the system proxy will not be touched"
		// in the log was not enough: this run's own dead-port guard then disabled
		// the proxy that the real instance was serving, because the guard cannot
		// tell a broken proxy from one belonging to an instance it must not
		// disturb. Every mutating path now returns early.
		app.sysproxy.SetReadOnly(true)
		Log("isolated run: data dir=%s, system proxy is read-only", abs, "WARN")
	}
	st := app.store.Settings()
	uiPort := st.UIPort
	if *portFlag > 0 {
		uiPort = *portFlag
	}
	// An explicit "leave my network alone" switch. Two Zenith instances on
	// different UI ports would otherwise both try to own the system proxy, and
	// whichever started last would silently steal it.
	if *noProxy {
		app.sysproxy.SetReadOnly(true)
		if st.SystemProxy {
			if _, err := app.store.UpdateSettings(map[string]interface{}{"systemProxy": false}); err == nil {
				st.SystemProxy = false
			}
		}
		Log("running with -no-proxy: the system proxy will not be touched")
	}

	Log("root=%s uiPort=%d headless=%v", rootDir, uiPort, *headless)

	// The elevated instance is dispatched here, before the single-instance check.
	//
	// It has to be: the ordinary instance already holds the UI port, so a check
	// for "is something already listening" matches, the process decides it is a
	// second launch, opens a window and exits - and the activation it was elevated
	// to perform never runs. That is exactly what happened: approving the prompt
	// produced a second window and no tunnel.
	//
	// This instance owns no interface and shows no window. It activates, reports
	// through the transaction record, and exits.
	if *tunElevated {
		mode := TunMode(*tunModeFlag)
		if !mode.Valid() || mode == TunOff {
			mode = TunCompat
		}
		// The elevated helper manages the tunnel, not the system proxy. Claiming the
		// proxy would make two processes own one setting.
		app.sysproxy.SetReadOnly(true)
		Log("elevated instance: activating TUN in %s mode", mode)
		// No window, no tray, no second UI server: this process exists only for
		// the activation, which needs rights the ordinary instance does not have.
		if err := app.RunElevatedActivation(mode); err != nil {
			Log("elevated instance: %v", err, "ERR")
		} else {
			Log("elevated instance: activation finished")
		}
		return
	}

	// One instance per data directory: a second launch just shows the window.
	if IsPortListening(uiPort) {
		Log("port %d already answers -> attaching to the running instance", uiPort)
		if *headless {
			fmt.Println("Zenith is already running")
			return
		}
		if _, err := openWindow(uiPort, st, *browser, app.dataDir); err != nil {
			fmt.Printf("Zenith is already running: http://127.0.0.1:%d/\n", uiPort)
		}
		return
	}

	// The core starts in the background on purpose: the window must appear at
	// once, even on a first run where the geodata files still need unpacking.
	// background() is an endless loop, so it MUST run in its own goroutine.
	app.Boot()
	// Reconcile the remembered TUN state with what the machine actually has. A
	// reboot or another VPN can make the stored switch wrong, and believing it
	// would mean reporting protection that is not there.
	app.RecoverTun()
	// A configuration activation that never finished may have left a candidate on
	// disk that failed verification. The transaction record is what distinguishes
	// that from a deliberate state.
	app.RecoverConfigTransaction()
	go app.background()
	// Liveness runs on its own timer, separate from the housekeeping tick so
	// unrelated work can never delay noticing a dead node.
	go app.healthLoop()
	// Insurance against this process being killed outright: a detached child
	// waits for the proxy port to come up and, if it never does, clears the
	// registry entry so the machine is not left with no internet.
	startWatchdog(app.dataDir, app.store.Settings().MixedPort)

	srv := NewServer(app, filepath.Join(rootDir, "web"), uiPort)
	if err := srv.Listen(); err != nil {
		fatal("%v", err)
	}

	if *headless {
		fmt.Printf("Zenith is running: http://127.0.0.1:%d/\n", uiPort)
		select {}
	}

	// The tray icon is the application's home now. Closing the window hides it
	// instead of quitting, so the proxy keeps running and the user gets it back
	// from the tray - which is also the only place that really quits.
	tray := NewTray()
	wireTray(tray, app, srv, uiPort)
	iconPath := filepath.Join(rootDir, "data", "zenith.ico")
	go func() {
		if err := tray.Run(iconPath, AppName); err != nil {
			Log("tray icon unavailable: %v", err, "WARN")
			return
		}
		Log("tray icon ready")
	}()
	select {
	case <-tray.Ready():
	case <-time.After(5 * time.Second):
		Log("tray icon did not come up in time; the window still works", "WARN")
	}

	if wp, werr := openWindow(uiPort, st, *browser, app.dataDir); werr != nil {
		Log("could not open a window: %v (the tray can still open it)", werr, "WARN")
	} else {
		windowProc.Store(wp)
	}

	// Update the hover text with the live node and latency, so the tray is
	// useful without opening anything.
	go func() {
		for {
			time.Sleep(10 * time.Second)
			st := app.Status()
			cur, _ := st["current"].(string)
			if cur == "" {
				cur = "未选择节点"
			}
			delay := 0
			if nodes, ok := st["nodes"].([]map[string]interface{}); ok {
				for _, n := range nodes {
					if act, _ := n["active"].(bool); act {
						if d, ok := n["delay"].(int); ok {
							delay = d
						}
						break
					}
				}
			}
			tip := fmt.Sprintf("%s · %s", AppName, cur)
			if delay > 0 {
				tip = fmt.Sprintf("%s · %s · %dms", AppName, cur, delay)
			}
			tray.SetTip(tip)
		}
	}()

	// Keep the backend alive for as long as the process runs. The window may be
	// closed and reopened many times; only the tray's 退出 does a real shutdown.
	select {}
}

// startWatchdog launches a detached copy of this executable in -watchdog mode.
//
// It is the answer to "the app died and left my network broken": the child keeps
// running after the parent is gone, waits for the proxy port to come up and,
// when it never does, puts the registry back. It stays silent while a live
// instance owns the port, so a normal restart is unaffected.
func startWatchdog(dataDir string, port int) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "-watchdog", dataDir, fmt.Sprint(port))
	cmd.Dir = filepath.Dir(exe)
	// detached: no console, no shared stdio, and it must outlive us
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000008, // CREATE_NO_WINDOW | DETACHED_PROCESS
	}
	if err := cmd.Start(); err != nil {
		Log("could not start the proxy watchdog: %v", err, "WARN")
		return
	}
	// Reap it so no zombie entry lingers; the child keeps running regardless.
	go func() { _ = cmd.Wait() }()
	Log("proxy watchdog armed (port %d)", port)
}

// ---- tray menu ------------------------------------------------------------

// Menu ids. Small positive numbers; the tray dispatches on wParam.
const (
	idShowWindow = 1 + iota
	idOpenBrowser
	idModeRule
	idModeGlobal
	idModeDirect
	idSysProxy
	idOptimize
	idQuit
)

// apiPost talks to our own local server, so a tray action behaves exactly like
// the same click in the interface - including the validation and the errors.
func apiPost(port int, path string, body interface{}) map[string]interface{} {
	raw, err := json.Marshal(body)
	if err != nil {
		return map[string]interface{}{"ok": false, "error": err.Error()}
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, path), bytes.NewReader(raw))
	if err != nil {
		return map[string]interface{}{"ok": false, "error": err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{"ok": false, "error": err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]interface{}{"ok": false, "error": strings.TrimSpace(string(data))}
	}
	return out
}

// windowProc tracks the browser process that is currently showing the UI.
//
// Counting windows through the shell is not reliable enough to decide whether a
// window already exists: the query can fail or lag, and the result was a second
// window stacked on top of the first. The process handle is authoritative, and
// Chromium's own single-instance behaviour covers the case where the handle is
// stale because the browser handed the URL to an existing process.
var windowProc atomic.Pointer[os.Process]

func wireTray(tray *Tray, app *App, srv *Server, uiPort int) {
	// Opening the window is idempotent: a live window process means the UI is up.
	bringUp := func() {
		if p := windowProc.Load(); p != nil && processAlive(p) {
			Log("window is already open (pid %d)", p.Pid)
			return
		}
		st := app.store.Settings()
		p, err := openWindow(uiPort, st, false, app.dataDir)
		if err != nil {
			Log("could not open the window: %v", err, "WARN")
			Info(AppName, fmt.Sprintf("无法打开窗口：%v\n\n界面地址：http://127.0.0.1:%d/", err, uiPort))
			return
		}
		windowProc.Store(p)
	}

	tray.On(idShowWindow, bringUp)
	tray.On(idOpenBrowser, func() {
		st := app.store.Settings()
		if _, err := openWindow(uiPort, st, true, app.dataDir); err != nil {
			Log("could not open the browser: %v", err, "WARN")
		}
	})
	tray.On(idModeRule, func() { trayMode(app, "rule") })
	tray.On(idModeGlobal, func() { trayMode(app, "global") })
	tray.On(idModeDirect, func() { trayMode(app, "direct") })
	tray.On(idSysProxy, func() {
		cur := app.store.Settings().SystemProxy
		if r := apiPost(uiPort, "/api/system-proxy", map[string]interface{}{"enabled": !cur}); r["ok"] != true {
			Info(AppName, fmt.Sprintf("切换系统代理失败：%v", r["error"]))
		}
	})
	tray.On(idOptimize, func() {
		if r := apiPost(uiPort, "/api/optimize", nil); r["ok"] != true {
			Info(AppName, fmt.Sprintf("无法开始优选：%v", r["error"]))
			return
		}
		Info(AppName, "已开始优选边缘节点。\n过程中可以正常上网，完成后会自动切换。")
	})
	tray.On(idQuit, func() {
		if !Confirm(AppName, "退出 Zenith？\n\n会同时停止代理并还原系统代理设置。") {
			return
		}
		// tear the tray down first so no ghost icon is left in the notification area
		tray.Stop()
		select {
		case <-tray.closed:
		case <-time.After(2 * time.Second):
		}
		app.Shutdown()
	})

	// The menu is rebuilt every time it opens, so the ticks and the labels can
	// never be stale.
	tray.SetMenu(func() []menuItem {
		st := app.Status()
		mode, _ := st["mode"].(string)
		optimizing, _ := st["optimizing"].(bool)
		proxyOn := false
		if ps, ok := st["systemProxy"].(ProxyState); ok {
			proxyOn = ps.Enabled && ps.Owner == "zenith"
		}

		items := []menuItem{
			{id: idShowWindow, label: "打开 Zenith 窗口"},
			{id: idOpenBrowser, label: "在浏览器中打开"},
			{separate: true},
			{id: idModeRule, label: "规则模式", checked: mode == "rule"},
			{id: idModeGlobal, label: "全局模式", checked: mode == "global"},
			{id: idModeDirect, label: "直连模式", checked: mode == "direct"},
			{separate: true},
			{id: idSysProxy, label: "系统代理", checked: proxyOn},
		}
		if optimizing {
			items = append(items, menuItem{id: idOptimize, label: "正在优选…", disabled: true})
		} else {
			items = append(items, menuItem{id: idOptimize, label: "立即优选节点"})
		}
		// Subscription management and settings live in the window itself; the
		// menu deliberately does not duplicate them, because a tray item that
		// can only point at a tab is worse than no item at all.
		items = append(items,
			menuItem{separate: true},
			menuItem{id: idQuit, label: "退出 Zenith"},
		)
		return items
	})
}

func trayMode(app *App, mode string) {
	if err := app.SetMode(mode); err != nil {
		Info(AppName, fmt.Sprintf("切换模式失败：%v", err))
	}
}

// resolveRoot finds the folder holding core/, web/ and data/. It works both when
// running from the repository and from a copied executable.
// fileExists reports whether a path is an existing regular file.
func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func resolveRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "web", "index.html")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	wd, err := os.Getwd()
	if err == nil {
		if _, err := os.Stat(filepath.Join(wd, "web", "index.html")); err == nil {
			return wd, nil
		}
	}
	return filepath.Dir(exe), nil
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Log("%s", msg, "ERR")
	fmt.Fprintln(os.Stderr, "Zenith:", msg)
	os.Exit(1)
}

// trace prints a startup landmark straight to stderr so a launch that dies
// early can be diagnosed without guessing.
func trace(what string) {
	fmt.Fprintf(os.Stderr, "[zenith] %s\n", what)
}

// stopRunning asks a running instance to quit cleanly; that also hands the
// system proxy back.
func stopRunning(rootDir string) {
	port := 7799
	if store, err := NewStore(filepath.Join(rootDir, "data")); err == nil {
		port = store.Settings().UIPort
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/quit", port)
	script := fmt.Sprintf(
		`try { Invoke-RestMethod -Uri '%s' -Method Post -TimeoutSec 5 | Out-Null } catch { }`, url)
	_ = hiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Run()
	time.Sleep(1500 * time.Millisecond)
	fmt.Println("Zenith has been asked to stop.")
}

// ---- window ---------------------------------------------------------------

// openWindow launches the UI in a chromeless app window. A private profile is
// used so it never merges with the user's normal browser session, and so the
// window size and position flags are honoured on every launch.
func openWindow(port int, st Settings, forceBrowser bool, dataDir string) (*os.Process, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if forceBrowser {
		return nil, exec.Command("cmd", "/c", "start", "", url).Start()
	}
	exe := findBrowser()
	if exe == "" {
		return nil, fmt.Errorf("no Edge or Chrome found")
	}
	profileDir := filepath.Join(dataDir, "ui-profile")
	_ = os.MkdirAll(profileDir, 0o755)

	w, h := st.WindowWidth, st.WindowHeight
	if w <= 0 {
		w = 1200
	}
	if h <= 0 {
		h = 780
	}

	// Reuse an existing window when one is already open: without a stable
	// profile lock Chromium would just stack another window on every call.
	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profileDir,
		fmt.Sprintf("--window-size=%d,%d", w, h),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-features=Translate,msEdgeIdentityFeatures",
	}
	if st.WindowX != 0 || st.WindowY != 0 {
		args = append(args, fmt.Sprintf("--window-position=%d,%d", st.WindowX, st.WindowY))
	}
	// Opt-in diagnostics: dropping a file called ui-debug.flag into the data
	// directory exposes the window's DevTools endpoint so the interface can be
	// inspected and its console read. Off unless the file exists.
	if _, err := os.Stat(filepath.Join(dataDir, "ui-debug.flag")); err == nil {
		args = append(args, "--remote-debugging-port=9222",
			"--remote-allow-origins=http://127.0.0.1:9222")
		Log("UI diagnostics enabled on 127.0.0.1:9222", "WARN")
	}

	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	Log("window opened (pid %d)", cmd.Process.Pid)
	return cmd.Process, nil
}

func findBrowser() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
	}
	for _, c := range candidates {
		if c == "" || strings.HasPrefix(c, string(os.PathSeparator)) {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// processAlive reports whether a tracked process is still running.
//
// Go caches the exit code of a Process it has already reaped, so both Signal(0)
// and a fresh FindProcess can keep answering "alive" long after the process is
// gone. That made the tray refuse to reopen a closed window. The Win32 wait
// primitive answers the real question.
func processAlive(p *os.Process) bool {
	if p == nil || p.Pid <= 0 {
		return false
	}
	const (
		processQueryLimitedInformation = 0x1000
		synchronize                    = 0x00100000
		waitTimeout                    = 0x00000102
	)
	k := syscall.NewLazyDLL("kernel32.dll")
	h, _, _ := k.NewProc("OpenProcess").Call(
		processQueryLimitedInformation|synchronize, 0, uintptr(p.Pid))
	if h == 0 {
		return false // cannot open it, so it is gone
	}
	defer k.NewProc("CloseHandle").Call(h)
	ret, _, _ := k.NewProc("WaitForSingleObject").Call(h, 0)
	return uint32(ret) == waitTimeout
}

// countWindows reports how many Zenith UI windows exist. It returns -1 when the
// answer cannot be determined; callers must treat that as unknown and never
// shut down because of it.
func countWindows(port int) int {
	needle := fmt.Sprintf("--app=http://127.0.0.1:%d", port)
	script := `Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | ` +
		`Where-Object { $_.CommandLine -like '*` + needle + `*' } | ` +
		`Measure-Object | Select-Object -ExpandProperty Count`
	out, err := hiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return -1
	}
	txt := strings.TrimSpace(string(out))
	if txt == "" {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(txt, "%d", &n); err != nil {
		return -1
	}
	return n
}

func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}
