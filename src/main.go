package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	var (
		headless = flag.Bool("headless", false, "run the backend only, without a window")
		browser  = flag.Bool("browser", false, "open the UI in the default browser")
		stop     = flag.Bool("stop", false, "stop a running Zenith and exit")
		noProxy  = flag.Bool("no-proxy", false, "run without touching the system proxy")
		version  = flag.Bool("version", false, "print the version and exit")
		portFlag = flag.Int("port", 0, "UI port (default 7799)")
	)
	flag.Parse()

	if *version {
		fmt.Printf("%s %s (%s)\n", AppName, AppVersion, goVersion())
		return
	}

	rootDir, err := resolveRoot()
	if err != nil {
		fatal("cannot locate the program directory: %v", err)
	}

	if *stop {
		stopRunning(rootDir)
		return
	}

	app, err := NewApp(rootDir)
	if err != nil {
		fatal("initialisation failed: %v", err)
	}
	st := app.store.Settings()
	uiPort := st.UIPort
	if *portFlag > 0 {
		uiPort = *portFlag
	}
	// An explicit "leave my network alone" switch. Two Zenith instances on
	// different UI ports would otherwise both try to own the system proxy, and
	// whichever started last would silently steal it.
	if *noProxy && st.SystemProxy {
		if _, err := app.store.UpdateSettings(map[string]interface{}{"systemProxy": false}); err == nil {
			st.SystemProxy = false
			Log("running with -no-proxy: the system proxy will not be touched")
		}
	}

	Log("root=%s uiPort=%d headless=%v", rootDir, uiPort, *headless)

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
	go app.background()

	srv := NewServer(app, filepath.Join(rootDir, "web"), uiPort)
	if err := srv.Listen(); err != nil {
		fatal("%v", err)
	}

	if *headless {
		fmt.Printf("Zenith is running: http://127.0.0.1:%d/\n", uiPort)
		select {}
	}

	proc, err := openWindow(uiPort, st, *browser, app.dataDir)
	if err != nil {
		fmt.Printf("could not open a window: %v\nUI: http://127.0.0.1:%d/\n", err, uiPort)
		select {}
	}

	// watchWindow calls Shutdown when the UI window really goes away. It can
	// also return early: Chromium may hand the URL to an already running
	// process, and the window count can fail to resolve. In those cases the
	// backend MUST stay alive - letting the main goroutine fall through here
	// used to end the process while the window was still on screen.
	watchWindow(proc, uiPort, func() { app.Shutdown() })
	Log("window watcher finished; Zenith keeps serving the open window")

	// Fallback: also stop when no Zenith window remains, checked slowly so a
	// transient query failure can never kill a live session.
	for {
		time.Sleep(20 * time.Second)
		if n := countWindows(uiPort); n == 0 {
			Log("no Zenith window left; shutting down")
			app.Shutdown()
		}
	}
}

// resolveRoot finds the folder holding core/, web/ and data/. It works both when
// running from the repository and from a copied executable.
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
// used so it never merges with the user's normal browser session.
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
	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profileDir,
		fmt.Sprintf("--window-size=%d,%d", w, h),
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-features=Translate,msEdgeIdentityFeatures",
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

// watchWindow stops the app when the window really goes away. A spawned browser
// process dying is not proof the window closed: Chromium hands the URL to an
// existing instance and our process exits at once.
func watchWindow(proc *os.Process, port int, onClose func()) {
	if proc == nil {
		return
	}
	started := time.Now()
	gone := 0
	for {
		time.Sleep(3 * time.Second)
		if processAlive(proc) {
			continue
		}
		n := countWindows(port)
		if n < 0 {
			Log("could not determine the window count, keeping Zenith running", "WARN")
			continue
		}
		if n > 0 {
			Log("window process handed off; %d window(s) still open", n)
			return
		}
		if time.Since(started) < 20*time.Second {
			Log("window process exited during the settle period, keeping Zenith running", "WARN")
			return
		}
		gone++
		if gone >= 2 {
			Log("window closed -> shutting down")
			onClose()
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func processAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}
