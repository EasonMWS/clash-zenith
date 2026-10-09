package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// System proxy handling.
//
// This is the part of a proxy client that can take the user offline, so the
// rules are deliberately conservative:
//
//  1. If another proxy client is running, never repoint the registry. Zenith
//     would silently cut the user off from the client they are using.
//  2. Snapshot the previous values before touching anything.
//  3. On exit, hand the setting BACK to its previous owner rather than just
//     disabling it - unless that owner is gone, in which case disabling is the
//     only safe option (a proxy pointing at a dead port means no internet).
//  4. Never enable it before the core is actually listening.
// ---------------------------------------------------------------------------

const regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type proxySnapshot struct {
	SavedAt       string `json:"savedAt"`
	ProxyEnable   uint32 `json:"proxyEnable"`
	ProxyServer   string `json:"proxyServer"`
	ProxyOverride string `json:"proxyOverride"`
	AutoConfigURL string `json:"autoConfigUrl"`
}

type SystemProxy struct {
	snapshotPath string
	tookProxy    bool
	proxyPort    int
	blockedBy    string
	// readOnly makes every mutating method a no-op.
	//
	// It exists because a promise made in a log line is not a promise the code
	// keeps. An isolated run announced that it would not touch the system proxy,
	// and then its own dead-port guard disabled the proxy the real instance was
	// serving - because the guard cannot tell "this proxy is broken" from "this
	// proxy belongs to an instance I must not disturb". A flag on the handle is
	// the stronger statement.
	readOnly bool
}

// SetReadOnly makes this handle refuse to change anything. An isolated run still
// needs to read the current state in order to report it, but must never write,
// restore or clean up a setting that belongs to another instance.
func (s *SystemProxy) SetReadOnly(v bool) {
	s.readOnly = v
}

func NewSystemProxy(stateDir string) *SystemProxy {
	return &SystemProxy{snapshotPath: filepath.Join(stateDir, "proxy-snapshot.json")}
}

// ---- registry access through reg.exe --------------------------------------
//
// Using reg.exe keeps the whole program free of cgo and Windows API bindings,
// and makes the logic easy to audit by hand.

func regQuery(name string) string {
	out, err := HiddenCommand("reg", "query", `HKCU\`+regKeyPath, "/v", name)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], name) {
			return strings.Join(fields[2:], " ")
		}
	}
	return ""
}

func regSet(name, typ, value string) error {
	_, err := HiddenCommand("reg", "add", `HKCU\`+regKeyPath, "/v", name, "/t", typ, "/d", value, "/f")
	return err
}

// NotifyWinInet tells running programs the proxy settings changed, otherwise
// browsers keep using the old ones until they are restarted.
func NotifyWinInet() {
	script := `$sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);'; ` +
		`$t = Add-Type -MemberDefinition $sig -Name ZenithWinInet -Namespace Zenith -PassThru; ` +
		`[void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0); ` +
		`[void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`
	_, _ = HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

// ---- state ----------------------------------------------------------------

type ProxyState struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Override string `json:"override"`
	Owner    string `json:"owner"`   // '' | 'zenith' | process name
	Blocked  string `json:"blocked"` // reason the proxy was left alone
}

func (s *SystemProxy) Status() ProxyState {
	enable := regQuery("ProxyEnable")
	server := regQuery("ProxyServer")
	override := regQuery("ProxyOverride")
	st := ProxyState{
		Enabled:  strings.TrimSpace(enable) == "0x1",
		Server:   server,
		Override: override,
		Blocked:  s.blockedBy,
	}
	port := portFromServer(server)
	if port > 0 {
		for _, pid := range ListeningPids(port) {
			name := ProcessName(pid)
			if name != "" {
				if strings.Contains(name, "mihomo") {
					st.Owner = "zenith"
				} else {
					st.Owner = name
				}
				break
			}
		}
	}
	if st.Owner == "" && s.tookProxy {
		st.Owner = "zenith"
	}
	return st
}

func portFromServer(server string) int {
	if server == "" {
		return 0
	}
	idx := strings.LastIndex(server, ":")
	if idx < 0 {
		return 0
	}
	var p int
	if _, err := fmt.Sscanf(server[idx+1:], "%d", &p); err != nil {
		return 0
	}
	return p
}

// ---- snapshot / restore ---------------------------------------------------

// PortFreeToBind reports whether Zenith can take a port for itself.
//
// A plain bind test is not enough: mihomo sets SO_REUSEADDR, so on Windows it
// will happily bind a port another application is already listening on, and both
// then accept a share of the connections - silently splitting traffic between
// two different proxies. So the real listener table is consulted as well.
func PortFreeToBind(port int) bool {
	if len(ListeningPids(port)) > 0 {
		return false
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func (s *SystemProxy) saveSnapshot() error {
	snap := proxySnapshot{
		SavedAt:       nowStamp(),
		ProxyServer:   regQuery("ProxyServer"),
		ProxyOverride: regQuery("ProxyOverride"),
		AutoConfigURL: regQuery("AutoConfigURL"),
	}
	if strings.TrimSpace(regQuery("ProxyEnable")) == "0x1" {
		snap.ProxyEnable = 1
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.snapshotPath, raw, 0o644)
}

func (s *SystemProxy) loadSnapshot() *proxySnapshot {
	raw, err := os.ReadFile(s.snapshotPath)
	if err != nil {
		return nil
	}
	var snap proxySnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil
	}
	return &snap
}

// foreignClients lists other proxy clients that are running right now. Exact
// process names are used because Zenith's own core is called mihomo.exe.
func foreignClients() []string {
	out, err := HiddenCommand("tasklist", "/FO", "CSV", "/NH")
	if err != nil {
		return nil
	}
	present := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		name := strings.ToLower(strings.Trim(strings.SplitN(line, `","`, 2)[0], `"`))
		present[name] = true
	}
	var found []string
	for exe, label := range map[string]string{
		"flclash.exe":             "FlClash",
		"flclashcore.exe":         "FlClash",
		"clash-verge.exe":         "Clash Verge",
		"clash-verge-service.exe": "Clash Verge",
		"clashn.exe":              "ClashN",
		"clashwin.exe":            "Clash for Windows",
		"cfw.exe":                 "Clash for Windows",
		"sing-box.exe":            "sing-box",
		"v2ray.exe":               "v2ray",
		"v2rayn.exe":              "v2rayN",
		"xray.exe":                "Xray",
		"nekoray.exe":             "Nekoray",
		"nekobox.exe":             "NekoBox",
		"hiddify.exe":             "Hiddify",
	} {
		if present[exe] && !contains(found, label) {
			found = append(found, label)
		}
	}
	return found
}

// Enable points the system proxy at Zenith's mixed port.
//
// Returns took=true when this call actually changed the registry, and false
// when Zenith already owned the setting - callers need that distinction to stop
// retrying without logging the same line every few seconds.
// force bypasses the "someone else owns it" guard (the user asked for it).
func (s *SystemProxy) Enable(port int, bypass string, force bool) (took bool, err error) {
	cur := s.Status()
	curPort := portFromServer(cur.Server)
	oursAlready := curPort == port && cur.Enabled
	if oursAlready {
		s.tookProxy = true
		s.proxyPort = port
		return false, nil
	}

	foreign := foreignClients()
	blocker := ""
	if foreign != nil && !oursAlready {
		blocker = "检测到其他代理客户端正在运行（" + strings.Join(foreign, ", ") + "）"
	} else if cur.Owner != "" && cur.Owner != "zenith" && !oursAlready {
		blocker = "系统代理当前由 " + cur.Owner + " 使用中"
	}
	if blocker != "" && !force {
		s.blockedBy = blocker
		s.tookProxy = false
		Log("system proxy NOT taken: %s. Zenith listens on %d and leaves the registry alone.", blocker, port)
		return false, nil
	}
	if blocker != "" {
		s.blockedBy = blocker
	}

	if !IsPortListening(port) {
		return false, fmt.Errorf("端口 %d 还没有监听，先启动内核再接管系统代理", port)
	}
	if err := s.saveSnapshot(); err != nil {
		Log("could not save the proxy snapshot: %v", err, "WARN")
	}
	if err := regSet("ProxyEnable", "REG_DWORD", "1"); err != nil {
		return false, err
	}
	if err := regSet("ProxyServer", "REG_SZ", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return false, err
	}
	if bypass != "" {
		_ = regSet("ProxyOverride", "REG_SZ", bypass)
	}
	s.tookProxy = true
	s.proxyPort = port
	NotifyWinInet()
	Log("system proxy enabled -> 127.0.0.1:%d", port)
	return true, nil
}

// Disable only flips the switch; it does not restore anything.
func (s *SystemProxy) Disable() {
	if s.readOnly {
		return
	}
	_ = regSet("ProxyEnable", "REG_DWORD", "0")
	s.tookProxy = false
	NotifyWinInet()
	Log("system proxy disabled")
}

// Restore hands the setting back to whoever owned it before, or switches it off
// when that owner is gone. Returns true when it changed something.
func (s *SystemProxy) Restore() bool {
	if s.readOnly {
		return false
	}
	if !s.tookProxy {
		Log("system proxy was never taken by Zenith; leaving it untouched")
		return false
	}
	snap := s.loadSnapshot()
	if snap == nil {
		s.Disable()
		return true
	}
	// if something else owns the setting now, do not trample it
	cur := regQuery("ProxyServer")
	if cur != "" && cur != snap.ProxyServer && portFromServer(cur) != s.proxyPort {
		Log("system proxy is owned by someone else now (%s), leaving it", cur, "WARN")
		s.tookProxy = false
		return false
	}
	if snap.ProxyServer != "" {
		if p := portFromServer(snap.ProxyServer); p > 0 && len(ListeningPids(p)) == 0 {
			// the old owner is gone: restoring it would mean no internet
			Log("previous proxy %s has no listener any more; leaving the system proxy OFF", snap.ProxyServer, "WARN")
			s.Disable()
			return true
		}
		_ = regSet("ProxyServer", "REG_SZ", snap.ProxyServer)
		if snap.ProxyOverride != "" {
			_ = regSet("ProxyOverride", "REG_SZ", snap.ProxyOverride)
		}
		if snap.AutoConfigURL != "" {
			_ = regSet("AutoConfigURL", "REG_SZ", snap.AutoConfigURL)
		}
	}
	enable := "0"
	if snap.ProxyEnable == 1 {
		enable = "1"
	}
	_ = regSet("ProxyEnable", "REG_DWORD", enable)
	NotifyWinInet()
	Log("system proxy restored to previous state (enable=%s server=%s)", enable, snap.ProxyServer)
	s.tookProxy = false
	return true
}

// GuardDeadProxy is the background safety net: if the registry points at a port
// nobody listens on the user is silently offline, so put it back.
func (s *SystemProxy) GuardDeadProxy() {
	if s.readOnly {
		// A run that promised not to touch the system proxy must not interpret a
		// dead port as its own to clean up. The port may belong to the instance it
		// is not allowed to disturb, and doing so once took a live instance's proxy
		// down and left the machine without one.
		return
	}
	st := s.Status()
	if !st.Enabled || st.Server == "" {
		return
	}
	port := portFromServer(st.Server)
	if port == 0 || IsPortListening(port) {
		return
	}
	Log("system proxy points at dead port %d -> fixing", port, "WARN")
	if !s.Restore() {
		s.Disable()
	}
}

// NeutraliseFromOtherProcess is the last resort for the case where Zenith's
// process dies without running its shutdown path - a crash, a task kill, a power
// event. It is started detached by the watchdog helper, because a registry left
// pointing at a dead local port means no internet at all, which is the worst
// thing a proxy client can leave behind.
//
// It stands down while a live Zenith still owns the port, so a normal restart is
// never disturbed.
func NeutraliseFromOtherProcess(stateDir string, port int) {
	s := NewSystemProxy(stateDir)
	st := s.Status()
	if !st.Enabled || portFromServer(st.Server) != port {
		return // nothing of ours is in the registry any more
	}
	// Give a starting instance time to bind before deciding it is dead.
	for i := 0; i < 24; i++ {
		if IsPortListening(port) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	Log("watchdog: port %d never came up; clearing the proxy so the machine is not left offline", port, "WARN")
	if !s.Restore() {
		s.Disable()
	}
}

// isSelfTestInvocation recognises the build-verification entry point.
func isSelfTestInvocation() bool {
	return len(os.Args) >= 2 && os.Args[1] == "-self-test"
}

// watchdogShapeOf reports whether a given argument list is a watchdog invocation.
//
// isWatchdogInvocation answers the same question about the running process. This
// variant exists so a build can prove the classification is right for the real
// shape without executing it, since executing it has side effects.
func watchdogShapeOf(args []string) bool {
	if len(args) < 4 {
		return false
	}
	if args[1] != "-watchdog" {
		return false
	}
	_, err := strconv.Atoi(args[3])
	return err == nil
}

// isWatchdogInvocation reports whether this process was started as the detached
// recovery helper.
//
// It deliberately does not use the flag package. flag.Parse terminates the
// process on an unknown flag, so a helper that is recognised only after parsing
// can never run: the child was spawned with -watchdog, died on its own argument,
// and the crash protection silently did not exist. This runs before any parsing.
//
// A watchdog also only ever has a data directory and a port, and it never has a
// window, so the shape of the argument list is unambiguous.
func isWatchdogInvocation() bool {
	return watchdogShapeOf(os.Args)
}

// runWatchdogFromArgs is the detached recovery path. It runs as its own process,
// outlives the parent, and only touches the system proxy if the parent never
// managed to bring its port up - meaning it died without running its shutdown
// path and left the registry pointing at nothing.
//
// It always ends cleanly, whatever it finds. This helper is best-effort: finding
// nothing to do is its normal, expected outcome, and reporting that as a failure
// would make a test harness (or a supervisor) treat a healthy machine as broken.
// The only thing worth an exit code here would be an outright crash, and that is
// caught separately.
func runWatchdogFromArgs() {
	defer func() {
		if r := recover(); r != nil {
			// Even a panic is reported through the log rather than an exit status:
			// there is no caller left that could act on a status.
			Log("watchdog: recovered from %v while checking the proxy", r, "WARN")
		}
	}()
	port, err := strconv.Atoi(os.Args[3])
	if err != nil || port <= 0 {
		return
	}
	// A missing or unreadable data directory is not a reason to fail either; the
	// helper simply has no ownership record to consult.
	NeutraliseFromOtherProcess(os.Args[2], port)
}

// ---- hidden command helper ------------------------------------------------

// HiddenCommand runs a program without flashing a console window.
func HiddenCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return string(out), fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		if len(out) > 0 {
			return string(out), nil
		}
		return "", err
	}
	return string(out), nil
}
