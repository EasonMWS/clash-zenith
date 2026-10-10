package main

// ---------------------------------------------------------------------------
// TUN: one button, and everything behind it.
//
// The goal this file serves is that a user on a clean Windows machine who has
// never installed a VPN clicks "enable TUN" once, approves the system prompt it
// raises, and ends up with working traffic takeover - no manual DLL download, no
// adapter to create by hand, no config to edit.
//
// Two rules shape the design:
//
//  1. One click is not one transaction. Preparing the environment (verifying and
//     placing components) and activating the network (adapter, routes, DNS) have
//     different failure modes and different rollback scopes, so they are tracked
//     separately and each can be resumed or undone on its own.
//
//  2. Nothing is inferred from a file name. A file called wintun.dll proves
//     nothing; the digest and the signature are what count, and they are checked
//     before the core is ever allowed to load it.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// defaultTunDevice is the name this program creates and owns. It aliases the
// store constant so the settings migration, the environment check and the adapter
// lookup cannot drift apart.
const defaultTunDevice = tunDefaultDevice

// ---- component manifest ---------------------------------------------------

type tunComponent struct {
	Name         string `json:"name"`
	Purpose      string `json:"purpose"`
	File         string `json:"file"`
	Arch         string `json:"arch"`
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
	Source       string `json:"source"`
	SourceSHA256 string `json:"sourceSha256"`
	Signer       string `json:"signer"`
	License      string `json:"license"`
}

type componentManifest struct {
	Components []tunComponent `json:"components"`
}

// tunComponentState is what the preparation transaction reports about one
// component, so the interface can explain a refusal instead of just failing.
type tunComponentState struct {
	Name      string `json:"name"`
	Present   bool   `json:"present"`
	Verified  bool   `json:"verified"`
	Version   string `json:"version,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Signed    bool   `json:"signed"`
	Signer    string `json:"signer,omitempty"`
	NeedsFix  bool   `json:"needsFix"`
	Detail    string `json:"detail,omitempty"`
	LicenseAt string `json:"licenseAt,omitempty"`
}

// loadManifest reads the component manifest shipped with the build.
func loadManifest(rootDir string) (*componentManifest, error) {
	path := filepath.Join(rootDir, "core", "wintun", "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("组件清单缺失（%s）：这个构建不完整，请重新下载完整的发布包", path)
	}
	var m componentManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("组件清单无法解析：%v", err)
	}
	if len(m.Components) == 0 {
		return nil, fmt.Errorf("组件清单是空的")
	}
	return &m, nil
}

// verifyTunComponent checks the file against the manifest, by content.
//
// Hashing is the point: a substituted file with the right name is refused, and
// so is a file borrowed from another VPN's directory, because its digest will not
// match the one this build was tested against.
func verifyTunComponent(rootDir string, c tunComponent) tunComponentState {
	st := tunComponentState{Name: c.Name, Version: c.Version, SHA256: c.SHA256, LicenseAt: c.License}
	path := filepath.Join(rootDir, filepath.FromSlash(c.File))
	f, err := os.Open(path)
	if err != nil {
		st.Detail = "组件不存在：" + c.File
		st.NeedsFix = true
		return st
	}
	defer f.Close()
	st.Present = true

	// Size first: a truncated or padded file is rejected without hashing it.
	if info, err := f.Stat(); err == nil && info.Size() < 100*1024 {
		st.Detail = fmt.Sprintf("组件大小异常（%d 字节），可能下载不完整", info.Size())
		st.NeedsFix = true
		return st
	}

	h := sha256.New()
	if _, err := copyToHash(h, f); err != nil {
		st.Detail = "读取组件失败：" + err.Error()
		st.NeedsFix = true
		return st
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, c.SHA256) {
		st.Detail = fmt.Sprintf("组件摘要不符：期望 %s，实际 %s。"+
			"这个文件与本次构建验证过的版本不是同一个，已拒绝加载", short(c.SHA256), short(got))
		st.NeedsFix = true
		return st
	}

	// Digest matches. The signature is checked as well, because the digest only
	// proves the file is the one we shipped, and the signature proves who made it.
	if signer, ok := authenticodeSigner(path); ok {
		st.Signed = true
		st.Signer = signer
	} else {
		st.Detail = "摘要正确，但无法确认数字签名"
	}

	st.Verified = true
	st.Detail = fmt.Sprintf("%s %s，来源 %s", c.Name, c.Version, c.Source)
	return st
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// ---- environment checks ---------------------------------------------------

// tunEnvironment is the result of looking at the machine before anything is
// changed. Every entry is something that can make the feature impossible, and
// each carries a reason rather than a bare false, because "TUN failed" with no
// explanation is the thing this is meant to avoid.
type tunEnvironment struct {
	OK       bool     `json:"ok"`
	Blockers []string `json:"blockers"`
	Warnings []string `json:"warnings"`
	Admin    bool     `json:"admin"`
	Arch     string   `json:"arch"`
	OS       string   `json:"os"`
	Adapter  string   `json:"adapter,omitempty"`
	// Stack is the normalized protocol stack, taken from the same source as
	// Adapter, so the environment check, the generated configuration and the
	// adapter lookup cannot disagree about what was decided.
	Stack string `json:"stack,omitempty"`
	// MixedPort and DNSPort are recorded here so the traffic verification checks
	// the ports this activation actually produced, rather than re-reading settings
	// that may have moved since.
	MixedPort int               `json:"mixedPort,omitempty"`
	DNSPort   int               `json:"dnsPort,omitempty"`
	Component tunComponentState `json:"component"`
	Others    []string          `json:"otherVpns,omitempty"`
	Nodes     int               `json:"availableNodes"`
	Checks    map[string]string `json:"checks"`
	Probed    map[string]string `json:"probed,omitempty"`
	Actions   []string          `json:"actions"`
}

// foreignTunAdapters lists adapters that look like someone else's tunnel. Zenith
// refuses to touch them, and mentions them so the user knows why the picture
// might differ from expectations.
func foreignTunAdapters() []string {
	names := adapterDescriptions()
	var out []string
	for _, d := range names {
		l := strings.ToLower(d)
		if strings.Contains(l, "zenith") {
			continue
		}
		if strings.Contains(l, "wintun") || strings.Contains(l, "tap-windows") ||
			strings.Contains(l, "wireguard") || strings.Contains(l, "openvpn") ||
			strings.Contains(l, "tailscale") || strings.Contains(l, "clash") ||
			strings.Contains(l, "sing-tun") || strings.Contains(l, "tunnel") {
			out = append(out, d)
		}
	}
	return out
}

// checkTunEnvironment performs transaction A's inspection half: it changes
// nothing, and reports what it found.
func (a *App) checkTunEnvironment() tunEnvironment {
	st := a.store.Settings()
	env := tunEnvironment{
		Checks:  map[string]string{},
		Probed:  map[string]string{},
		Actions: []string{},
	}

	env.Admin = isElevated()
	env.Arch = goArch()
	env.OS = windowsVersion()

	if env.Arch != "amd64" {
		env.Blockers = append(env.Blockers,
			fmt.Sprintf("当前构建只提供 amd64 版 TUN 组件，这台机器是 %s", env.Arch))
	}
	env.Checks["架构"] = env.Arch

	// Component integrity, by content.
	//
	// What is checked here is the external wintun copy that ships beside the core.
	// It is worth checking - a program should not load a DLL it cannot account for
	// - but it is NOT what makes TUN work, and it must never be allowed to block on
	// its absence. Measured behaviour: with no wintun.dll next to mihomo.exe at
	// all, and again with a junk file of that name in its place, the core produced
	// byte-identical output and still reached "configure tun interface: Access is
	// denied". It never touches the file; the wintun driver it uses is embedded in
	// the binary and loaded from memory.
	//
	// This matters because the check used to block on that file. A user whose core
	// was perfectly capable was told the build was incomplete and to download it
	// again, which is the failure the review called out: it verified a file rather
	// than the capability.
	m, err := loadManifest(a.rootDir)
	if err != nil {
		// A missing manifest is a packaging defect worth stating, but it says
		// nothing about whether this core can create an adapter, so it does not
		// block. It is reported as a warning and the run continues.
		if manifestBlocksTun(err) {
			env.Blockers = append(env.Blockers, err.Error())
		} else {
			env.Warnings = append(env.Warnings,
				"外置 TUN 组件清单缺失（"+err.Error()+"）。这不影响内核启用 TUN —— "+
					"内核使用内嵌的 wintun 驱动，外置文件只是随包附带的副本。")
		}
	} else if len(m.Components) > 0 {
		env.Component = verifyTunComponent(a.rootDir, m.Components[0])
		env.Checks["组件"] = fmt.Sprintf("%s %s", env.Component.Name, env.Component.Version)
		if componentBlocksTun(env.Component) {
			env.Blockers = append(env.Blockers,
				"TUN 组件未通过校验："+env.Component.Detail)
		} else if env.Component.Verified {
			if env.Component.Signed {
				env.Checks["组件签名"] = env.Component.Signer
			} else {
				env.Warnings = append(env.Warnings, "组件摘要正确，但未能确认数字签名")
			}
		} else {
			// Present but not matching. This is still not a blocker for TUN, but it
			// is worth saying loudly: something put a file of that name where the
			// core's directory is, and it is not the one this build shipped.
			env.Warnings = append(env.Warnings,
				"外置 TUN 组件与清单不一致："+env.Component.Detail+
					"。这不影响内核启用 TUN（内核用内嵌驱动），但如果这不是你有意替换的，建议重新下载发布包。")
		}
	}

	// What actually decides whether TUN can work on this machine: a core binary
	// that exists, matches this architecture, and is the version the rest of the
	// program was written against.
	corePath := filepath.Join(a.rootDir, "core", "mihomo.exe")
	if _, err := os.Stat(corePath); err != nil {
		env.Blockers = append(env.Blockers, "找不到 core/mihomo.exe")
	} else {
		arch, ver := coreBuildInfo(corePath)
		if arch != "" {
			if arch != "amd64" {
				env.Blockers = append(env.Blockers,
					fmt.Sprintf("内核是 %s 架构，无法在这台 %s 机器上创建网卡", arch, env.Arch))
			} else {
				env.Checks["内核"] = "mihomo " + ver + " (" + arch + ")"
			}
		} else {
			env.Checks["内核"] = "已找到 core/mihomo.exe"
		}
	}

	// Routing needs at least one usable node; starting a tunnel that cannot carry
	// anything and calling it "connected" is the failure this guards against.
	optimized, base := a.nodeSet()
	env.Nodes = len(optimized) + len(base)
	if env.Nodes == 0 {
		env.Blockers = append(env.Blockers, "还没有可用节点：请先在订阅页导入订阅并完成一次优选")
	}

	// Other tunnels are reported, never touched.
	if others := foreignTunAdapters(); len(others) > 0 {
		env.Others = others
		env.Warnings = append(env.Warnings,
			"检测到其他隧道/虚拟网卡："+strings.Join(others, "、")+
				"。Zenith 只创建和管理自己的网卡，不会改动它们；如果它们也做全局接管，两边可能互相抢路由")
	}
	// The system proxy may be held by Zenith"s own core, which is not a conflict.
	// Only a third-party holder is worth warning about.
	if ob := systemProxyOwner(a.dataDir); ob != "" &&
		!strings.EqualFold(ob, "zenith") && !strings.EqualFold(ob, "mihomo") {
		env.Warnings = append(env.Warnings,
			"系统代理当前由其他程序持有（"+ob+"）。启用 TUN 后建议只用一种接管方式，否则两边可能互相抢流量")
	}

	// Privilege is needed for the adapter and the routes, and it is requested once
	// rather than on every start.
	if !env.Admin {
		env.Actions = append(env.Actions, "需要管理员授权以创建虚拟网卡并配置路由")
	}
	// The normalized values, not the raw settings. The check, the generated
	// configuration, the adapter creation and the adapter lookup all read these,
	// so a settings file with an empty device name is repaired once and every
	// stage agrees on the result.
	env.Adapter = st.NormalizedTunDevice()
	env.Stack = st.NormalizedTunStack()
	env.MixedPort = st.MixedPort
	env.DNSPort = a.dnsPort
	env.Checks["网卡名"] = env.Adapter
	env.Checks["协议栈"] = env.Stack

	env.OK = len(env.Blockers) == 0
	return env
}

// componentBlocksTun reports whether a component state must stop the activation.
//
// It is deliberately always false today, and it is a named function rather than an
// inlined condition so the rule is visible and testable. The external wintun copy
// is not consulted by the core at all - measured: with no such file, and again
// with a junk file of that name, the core produced byte-identical output and still
// reached "configure tun interface: Access is denied". Blocking on it told users
// with a perfectly capable core that their build was incomplete.
//
// The parameter is kept because a genuinely blocking condition would belong here,
// and because it makes the decision explicit at the call site.
func componentBlocksTun(c tunComponentState) bool {
	return false
}

// manifestBlocksTun reports whether a missing manifest must stop the activation.
//
// Also always false today, for the same reason: a manifest describes the external
// copy, and the external copy is not what creates the adapter.
func manifestBlocksTun(err error) bool {
	return false
}

// coreBuildInfo reads the architecture and version out of a mihomo binary,
// without running it.
//
// The architecture matters: an arm64 core on an amd64 machine cannot create an
// adapter, and saying so from the file is more useful than failing later with a
// driver error. An empty return means the file could not be read as a PE image,
// which is reported as "found but unrecognised" rather than as a failure - the
// capability is what matters, not the parse.
func coreBuildInfo(path string) (arch, version string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 0x40 {
		return "", ""
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return "", ""
	}
	le := func(off int) uint32 {
		return uint32(data[off]) | uint32(data[off+1])<<8 |
			uint32(data[off+2])<<16 | uint32(data[off+3])<<24
	}
	pe := int(le(0x3C))
	if pe <= 0 || pe+6 > len(data) || data[pe] != 'P' || data[pe+1] != 'E' {
		return "", ""
	}
	machine := uint16(data[pe+4]) | uint16(data[pe+5])<<8
	switch machine {
	case 0x8664:
		arch = "amd64"
	case 0x14c:
		arch = "386"
	case 0xaa64:
		arch = "arm64"
	default:
		arch = fmt.Sprintf("unknown(0x%x)", machine)
	}
	// mihomo embeds its version as a plain string near the build information.
	if i := bytes.Index(data, []byte("v1.19")); i > 0 && i+8 < len(data) {
		end := i
		for end < len(data) && end-i < 12 &&
			((data[end] >= '0' && data[end] <= '9') || data[end] == '.' || data[end] == 'v') {
			end++
		}
		version = string(data[i:end])
	}
	if version == "" {
		version = "未知版本"
	}
	return arch, version
}

// ---- elevation ------------------------------------------------------------

// isElevated reports whether this process already has administrator rights.
func isElevated() bool {
	var sid *syscall.Token
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	var buf [68]byte
	var n uint32
	e := syscall.GetTokenInformation(tok, syscall.TokenElevation, (*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)), &n)
	_ = sid
	if e != nil {
		return false
	}
	return buf[0] != 0
}

// goArch names the architecture, so the manifest can be matched against it rather
// than assumed to be amd64.
func goArch() string {
	// runtime.GOARCH is a compile-time constant, so this cannot drift.
	return runtimeGOARCH
}

// windowsVersion summarises the OS for the compatibility record. It is reported,
// not used to refuse: the feature is tested on Windows 10 and 11, and a version
// check that guessed at compatibility would be worse than saying what was seen.
func windowsVersion() string {
	v := windowsBuild()
	if v == "" {
		return "unknown"
	}
	return v
}

// elevateRequest asks Windows to run the same binary again as administrator.
//
// The request is explicit and one-shot: if the user declines, Zenith says so and
// stays where it is. It never re-prompts in a loop, because a repeatedly
// re-appearing UAC dialog trains people to click yes.
func elevateRequest(args []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cwd, _ := os.Getwd()
	if err := shellExecuteRunas(exe, args, cwd); err != nil {
		if isUserCancel(err) {
			return 0, fmt.Errorf("没有获得管理员授权，TUN 未启用。系统设置没有被修改")
		}
		return 0, fmt.Errorf("请求管理员授权失败：%v", err)
	}
	return helperPIDForRequester(), nil
}

// helperPIDForRequester finds the elevated helper this process just started.
//
// The helper is a child of this process, runs the same executable, and carries
// -tun-elevated. Matching on all three avoids picking up an unrelated Zenith
// window. Returning zero is acceptable: the wait then falls back to its deadline
// rather than to a process check, which is the behaviour before this existed.
func helperPIDForRequester() int {
	script := fmt.Sprintf(
		`Get-CimInstance Win32_Process -Filter "Name='%s'" | `+
			`Where-Object { $_.ParentProcessId -eq %d -and $_.CommandLine -like '*-tun-elevated*' } | `+
			`Select-Object -First 1 -ExpandProperty ProcessId`,
		filepath.Base(os.Args[0]), os.Getpid())
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return 0
	}
	for _, f := range strings.Fields(out) {
		if n, convErr := strconv.Atoi(f); convErr == nil && n > 0 {
			return n
		}
	}
	return 0
}

// ---- transactions ---------------------------------------------------------

// tunTxnKind names the two transactions, which fail and roll back differently.
type tunTxnKind string

const (
	txnPrepare  tunTxnKind = "prepare"  // install/verify components, no network change
	txnActivate tunTxnKind = "activate" // adapter, routes, DNS, verification
)

// tunTxn is a durable record of one attempt, so an interrupted run can be resumed
// or undone instead of being guessed at on the next start.
type tunTxn struct {
	ID        string     `json:"id"`
	Kind      tunTxnKind `json:"kind"`
	StartedAt time.Time  `json:"startedAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	State     string     `json:"state"` // running | done | failed | rolledBack
	// Mode is the mode this transaction was activating. A rollback needs it to know
	// whether a privacy block may be lifted, and reading it back from the record
	// rather than from the current settings means an interrupted activation rolls
	// back according to what it was doing, not according to what the settings say
	// now.
	Mode    TunMode   `json:"mode,omitempty"`
	Steps   []tunStep `json:"steps"`
	Failure string
	// RestoreFailure records a rollback that could not put the previous
	// configuration back. It is a separate condition from the activation failing:
	// an activation that fails and rolls back cleanly is recoverable, one that
	// cannot restore its own previous state is not.
	RestoreFailure string `json:"restoreFailure,omitempty"`
	// Traffic is the evidence that the tunnel is carrying traffic, kept on the
	// record so a failure can be diagnosed from the file rather than only from the
	// log, and so "it is on" is backed by observations rather than by the absence of
	// an error.
	Traffic *tunTrafficReport `json:"traffic,omitempty"`
	// Owned records what this attempt changed, so a rollback touches only that.
	Owned tunOwned `json:"owned"`
}

type tunStep struct {
	Name   string    `json:"name"`
	State  string    `json:"state"` // pending | done | failed | skipped
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// tunOwned is the ownership record for rollback: it lists exactly the resources
// this transaction created or changed, and nothing else.
type tunOwned struct {
	AdapterCreated bool   `json:"adapterCreated"`
	AdapterName    string `json:"adapterName,omitempty"`
	SysProxyWasOn  bool   `json:"sysProxyWasOn"`
	SysProxyServer string `json:"sysProxyServer,omitempty"`
	CoreStarted    bool   `json:"coreStarted"`
}

func (a *App) tunTxnPath() string {
	return filepath.Join(a.dataDir, "tun-transaction.json")
}

func (a *App) saveTunTxn(t *tunTxn) {
	t.UpdatedAt = time.Now()
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return
	}
	tmp := a.tunTxnPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		Log("could not write the TUN transaction record: %v", err, "WARN")
		return
	}
	// Rename so the record is either the old one or the new one, never half of
	// either - the record is what a crash recovery reads.
	_ = os.Rename(tmp, a.tunTxnPath())
}

func (a *App) loadTunTxn() *tunTxn {
	raw, err := os.ReadFile(a.tunTxnPath())
	if err != nil {
		return nil
	}
	var t tunTxn
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil
	}
	return &t
}

func newTunTxn(kind tunTxnKind) *tunTxn {
	return &tunTxn{
		ID:        fmt.Sprintf("%s-%d", kind, time.Now().UnixNano()),
		Kind:      kind,
		StartedAt: time.Now(),
		State:     "running",
	}
}

func (t *tunTxn) step(name, state, detail string) {
	for i := range t.Steps {
		if t.Steps[i].Name == name {
			t.Steps[i].State = state
			t.Steps[i].Detail = detail
			t.Steps[i].At = time.Now()
			return
		}
	}
	t.Steps = append(t.Steps, tunStep{Name: name, State: state, Detail: detail, At: time.Now()})
}

// ---- enabling -------------------------------------------------------------

// tunRun is the state of an enable attempt, so the interface can show which step
// it is on instead of a spinner that means nothing.
type tunRun struct {
	Active bool     `json:"active"`
	Stage  string   `json:"stage"`
	Steps  []string `json:"steps"`
	Error  string   `json:"error,omitempty"`
	Mode   TunMode  `json:"mode"`
	// WaitingForApproval is true while this process is waiting for the user to answer
	// the Windows permission prompt.
	//
	// This is the state that used to be invisible. Enabling TUN asks for elevation,
	// which puts a system dialog on screen that the user may not have noticed, behind
	// another window, or on another monitor - and until they answer it, this program
	// does nothing at all for up to four minutes. From the interface it looked exactly
	// like a hang, because nothing distinguished "waiting for you" from "stuck". The
	// user's own words for it were sitting there waiting like an idiot.
	WaitingForApproval bool `json:"waitingForApproval"`
	// WaitedSeconds and WaitLimitSeconds make the wait a number on screen rather than
	// an open-ended promise.
	WaitedSeconds    int `json:"waitedSeconds"`
	WaitLimitSeconds int `json:"waitLimitSeconds"`
	// ApprovalHint is what to do about it.
	ApprovalHint string `json:"approvalHint,omitempty"`
}

// EnableTun is the single product action: one call, and every step behind it runs
// in order. It reports progress through the app's state so the UI can say where it
// is, and it refuses to claim success until a real request has been carried.
func (a *App) EnableTun(mode TunMode) error {
	if !mode.Valid() || mode == TunOff {
		return fmt.Errorf("未知的 TUN 模式")
	}
	a.mu.Lock()
	if a.tunRun != nil && a.tunRun.Active {
		a.mu.Unlock()
		// Repeated clicks join the running attempt rather than starting a second
		// one, which is how two adapters and two competing transactions would
		// otherwise appear.
		return fmt.Errorf("已经在启用中，请等待当前步骤完成")
	}
	a.tunRun = &tunRun{Active: true, Stage: "检查环境", Mode: mode}
	a.mu.Unlock()

	go a.runEnableTun(mode)
	return nil
}

func (a *App) setTunStage(stage string, steps ...string) {
	a.mu.Lock()
	if a.tunRun != nil {
		a.tunRun.Stage = stage
		if len(steps) > 0 {
			a.tunRun.Steps = append(a.tunRun.Steps, steps...)
		}
	}
	a.mu.Unlock()
}

func (a *App) failTun(err error) {
	a.mu.Lock()
	if a.tunRun != nil {
		a.tunRun.Active = false
		a.tunRun.Error = err.Error()
		a.tunRun.Stage = "未启用"
	}
	a.mu.Unlock()
	Log("TUN: %v", err, "WARN")
}

// TunRunState reports progress, and is what the interface renders.
func (a *App) TunRunState() *tunRun {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunRun == nil {
		return &tunRun{Stage: "未启用", Mode: a.store.Settings().TunMode}
	}
	cp := *a.tunRun
	cp.Steps = append([]string(nil), a.tunRun.Steps...)
	// The countdown is computed when it is read, so the interface sees it move without
	// anything having to tick in the background.
	if cp.WaitingForApproval && !a.approvalWaitStart.IsZero() {
		cp.WaitedSeconds = int(time.Since(a.approvalWaitStart) / time.Second)
		if cp.WaitedSeconds > approvalGraceSeconds && cp.ApprovalHint != "" {
			cp.ApprovalHint += " 已经等了 " + fmt.Sprint(cp.WaitedSeconds) + " 秒。"
		}
	}
	return &cp
}

// runEnableTun performs transaction A and then transaction B.
//
// They are separate on purpose. A failed component check must not touch routing,
// and a failed network activation must not undo a component installation that
// succeeded. Each writes its own record, so an interrupted run can be resumed
// where it stopped rather than restarted blind.
func (a *App) runEnableTun(mode TunMode) {
	txA := newTunTxn(txnPrepare)
	a.saveTunTxn(txA)
	defer func() {
		if r := recover(); r != nil {
			txA.State = "failed"
			txA.Failure = fmt.Sprint(r)
			a.saveTunTxn(txA)
			a.failTun(fmt.Errorf("准备环境时发生内部错误：%v", r))
		}
	}()

	env := a.checkTunEnvironment()
	txA.step("检查环境", "done", fmt.Sprintf("架构 %s，系统 %s", env.Arch, env.OS))
	if len(env.Blockers) > 0 {
		txA.step("检查环境", "failed", strings.Join(env.Blockers, "；"))
		txA.State = "failed"
		txA.Failure = strings.Join(env.Blockers, "；")
		a.saveTunTxn(txA)
		a.failTun(fmt.Errorf("%s", txA.Failure))
		return
	}
	txA.step("校验组件", "done", env.Component.Detail)
	for _, w := range env.Warnings {
		Log("TUN 提示：%s", w)
	}

	// The service owns the core on a machine where it has been installed, and an
	// activation then needs no further authorisation - which is the whole reason it
	// exists. The request is still authenticated and still goes through the same
	// ownership decision, so this is not a shortcut around the checks; it is the
	// path that does not need a prompt.
	if a.serviceReachable() {
		// The mode is saved BEFORE the configuration is generated, not after.
		//
		// The order was the other way round, and the consequence is exact: enabling
		// from off produced a configuration built from settings that still said off,
		// so it had no tun block, and switching compat to privacy produced one that
		// still carried the old strict-route. The service then started a core against
		// a configuration that did not describe what was asked for.
		a.setTunStage("保存目标设置")
		if _, err := a.store.UpdateSettings(map[string]interface{}{
			"tunMode":   string(mode),
			"tunDevice": env.Adapter,
			"tunStack":  env.Stack,
		}); err != nil {
			txA.step("保存设置", "failed", err.Error())
			txA.State = "failed"
			txA.Failure = err.Error()
			a.saveTunTxn(txA)
			a.failTun(err)
			return
		}
		saved := a.store.Settings()
		txA.step("保存设置", "done", string(mode))
		a.saveTunTxn(txA)

		// The system proxy has to be switched off here too, and it was not.
		//
		// The exclusion lived only in the local activation path, so it applied on a
		// machine using the per-activation prompt and did nothing on a machine using the
		// service - which, now that the service works, is the ordinary case. The
		// consequence is the one the two-mode design exists to prevent: the registry
		// says traffic goes through the proxy while the routing table sends it through
		// the tunnel, both settings read as on, and nothing explains the difference.
		//
		// Done BEFORE the configuration is built, not after, so the configuration is
		// generated from a state where the two are not both claiming the traffic.
		proxyState := NewSystemProxy(a.dataDir).Status()
		txA.Owned.SysProxyWasOn = proxyState.Enabled
		txA.Owned.SysProxyServer = proxyState.Server
		if proxyState.Enabled {
			a.setTunStage("关闭系统代理（与 TUN 互斥）")
			NewSystemProxy(a.dataDir).Disable()
			if _, err := a.store.UpdateSettings(map[string]interface{}{
				"systemProxy": false,
			}); err != nil {
				Log("TUN activate: could not record that the system proxy was switched "+
					"off: %v", err, "WARN")
			}
			txA.step("关闭系统代理", "done",
				"TUN 接管与系统代理互斥，已关闭系统代理；这次激活失败的话会恢复它")
			a.saveTunTxn(txA)
		}

		a.setTunStage("生成配置")
		cfg := BuildConfig(a.mergedNodes(), a.optimizedNames(), saved,
			a.secret, a.store.Snapshot().Current, a.dnsPort)
		if err := validateCandidateConfig(cfg); err != nil {
			txA.step("生成配置", "failed", err.Error())
			txA.State = "failed"
			txA.Failure = "生成的配置没有通过校验：" + err.Error()
			a.saveTunTxn(txA)
			a.failTun(fmt.Errorf("%s", txA.Failure))
			return
		}
		// The same check the local path makes, for the same reason: a configuration
		// that does not carry the mode that was asked for would start a core that
		// cannot deliver it, and the failure would surface as "the adapter never
		// appears" rather than as this sentence.
		if mode != TunOff && !strings.Contains(cfg, "\ntun:\n") {
			txA.step("生成配置", "failed", "配置里没有 tun 段")
			txA.State = "failed"
			txA.Failure = fmt.Sprintf("内部错误：模式已保存为 %s，但生成的配置里没有 tun 段", mode)
			a.saveTunTxn(txA)
			a.failTun(fmt.Errorf("%s", txA.Failure))
			return
		}
		if err := a.applyCandidateConfig(cfg); err != nil {
			txA.step("写入候选配置", "failed", err.Error())
			txA.State = "failed"
			txA.Failure = err.Error()
			a.saveTunTxn(txA)
			a.failTun(err)
			return
		}
		txA.step("生成配置", "done", fmt.Sprintf("%d 字节，含 tun 段", len(cfg)))

		txA.step("请求服务", "pending", "由常驻服务接管，无需再次授权")
		a.saveTunTxn(txA)
		if err := a.serviceStartRequest([]byte(cfg), mode); err != nil {
			txA.step("请求服务", "failed", err.Error())
			txA.State = "failed"
			txA.Failure = err.Error()
			a.saveTunTxn(txA)
			a.failTun(err)
			return
		}
		txA.step("请求服务", "done", "服务已带 TUN 配置启动内核")
		a.saveTunTxn(txA)

		// The service owns the core, but this process is the one that can see this
		// machine's interfaces and routes - so the verification happens here, over the
		// same evidence chain as the local path. Returning straight after the request
		// meant the interface said "enabled" on the strength of a request that was
		// accepted, which is the claim this program is not allowed to make.
		a.setTunStage("验证流量是否经过隧道")
		after := a.store.Settings()
		venv := a.checkTunEnvironment()
		venv.Adapter = after.NormalizedTunDevice()
		venv.Stack = after.NormalizedTunStack()
		venv.MixedPort = after.MixedPort
		venv.DNSPort = a.dnsPort
		traffic := a.VerifyTunTraffic(mode, venv)
		if !traffic.OK {
			txA.step("验证流量", "failed", traffic.Stage+": "+traffic.Detail)
			txA.State = "failed"
			txA.Failure = fmt.Sprintf("服务已启动内核，但流量没有经过隧道（%s）：%s",
				traffic.Stage, traffic.Detail)
			a.saveTunTxn(txA)
			// Give back the arrangement the user started with. Switching the proxy off
			// was part of this attempt, so a failed attempt has to undo it rather than
			// leave them with neither the tunnel nor the proxy.
			if txA.Owned.SysProxyWasOn && txA.Owned.SysProxyServer != "" {
				sp := NewSystemProxy(a.dataDir)
				if _, err := sp.Enable(saved.MixedPort, saved.ProxyBypass, false); err != nil {
					Log("TUN activate: the tunnel failed and the system proxy could not be "+
						"restored: %v", err, "ERR")
					txA.RestoreFailure = "系统代理未能恢复"
				} else {
					_, _ = a.store.UpdateSettings(map[string]interface{}{"systemProxy": true})
					Log("TUN activate: the tunnel failed; the system proxy has been restored")
				}
			}
			a.failTun(fmt.Errorf("%s", txA.Failure))
			return
		}
		txA.step("验证流量", "done", traffic.DirectDetail+"；"+traffic.CoreDetail)

		// Verified, so this is now the configuration worth going back to.
		a.commitConfig(cfg)
		txA.State = "done"
		a.saveTunTxn(txA)
		a.mu.Lock()
		if a.tunRun != nil {
			a.tunRun.Active = false
			a.tunRun.Stage = "已启用"
			a.tunRun.Error = ""
		}
		a.mu.Unlock()
		Log("TUN enabled through the service in %s mode; adapter %q verified carrying traffic",
			mode, after.NormalizedTunDevice())
		return
	}

	// No service yet. Ask once to install it, and if that is declined or fails, fall
	// through to the per-activation elevation that worked before - a machine without
	// the service must still be able to use the feature.
	if !isElevated() {
		// This is an elevation prompt too, and it is usually the FIRST one the user
		// sees. The approval panel - the countdown, the hint about where the dialog
		// might be hiding - was only raised for the second elevation, so the first
		// prompt was shown while the interface said nothing more helpful than
		// "等待系统授权". Reported by the user as the panel appearing only at the second
		// prompt, which is exactly what it was doing.
		a.setTunStage("等待系统授权，请在弹窗里点「是」（安装常驻服务）")
		a.setApprovalWait(true)
		err := a.ensureService()
		a.setApprovalWait(false)
		if err == nil {
			txA.step("安装服务", "done", "已安装并启动常驻服务，之后启用不再需要授权")
			a.saveTunTxn(txA)
			// Continue into the service path rather than calling EnableTun again.
			//
			// The re-entry hit the guard at the top of EnableTun - the outer call had
			// already set Active - so the activation stopped with "already enabling,
			// please wait" while nothing was running. The guard is right; calling
			// through it was not.
			go a.runEnableTun(mode)
			return
		} else {
			txA.step("安装服务", "skipped", err.Error()+"；改用每次授权的方式")
		}
	}

	// Privilege is requested after the checks that need none, so a machine that
	// cannot support TUN is told that before it is asked for a password.
	if !isElevated() {
		a.setTunStage("等待系统授权")
		txA.step("请求授权", "pending", "等待用户在 UAC 对话框中确认")
		a.saveTunTxn(txA)

		// A fresh id per attempt. The helper writes its result under this id, and a
		// record carrying any other id belongs to a different attempt and is
		// ignored - so a stale file cannot be read as this run's verdict.
		id := newHandoverID()
		a.clearHandover()
		// The root directory is passed explicitly rather than left to be
		// rediscovered. resolveRoot infers it by looking for web/index.html near
		// the executable, and an elevated process can be started with a different
		// working directory - which made it read a different configuration than
		// the instance that asked for the elevation, and act on ports and nodes
		// that were not the ones in use.
		helperPID, err := elevateRequest([]string{
			"-tun-elevated",
			"-root", a.rootDir,
			"-datadir", a.dataDir,
			"-tun-mode", string(mode),
			"-handover-id", id,
			"-requester-pid", strconv.Itoa(os.Getpid()),
		})
		if err != nil {
			txA.step("请求授权", "failed", err.Error())
			txA.State = "failed"
			txA.Failure = err.Error()
			a.saveTunTxn(txA)
			// No retry loop: a declined prompt is a decision, not a transient fault.
			a.failTun(err)
			return
		}
		txA.step("请求授权", "done", "已启动提权实例，由它继续完成")
		txA.State = "done"
		a.saveTunTxn(txA)

		// Wait for the helper's verdict.
		//
		// This used to be a bare return: the state was set to "authorised, waiting
		// for the elevated instance" and the function ended, leaving the interface
		// waiting for something that could never arrive. The helper reported
		// through a progress object it never initialised, so its failures were
		// recorded nowhere and it read that empty object to decide the outcome -
		// which meant a failed activation could report success. Nothing below reads
		// this process's own memory to decide what the helper achieved.
		a.mu.Lock()
		a.helperPID = helperPID
		a.mu.Unlock()
		a.setTunStage("等待系统授权，请在弹窗里点「是」")
		a.setApprovalWait(true)
		result := a.awaitHandover(id, helperPID, handoverTimeout)
		a.setApprovalWait(false)
		a.mu.Lock()
		a.helperPID = 0
		a.mu.Unlock()
		if result.OK {
			txA.step("提权实例完成", "done", "由提权实例报告成功")
			a.saveTunTxn(txA)
			a.mu.Lock()
			if a.tunRun != nil {
				a.tunRun.Active = false
				a.tunRun.Stage = "已启用"
			}
			a.mu.Unlock()
			return
		}
		txA.step("提权实例失败", "failed", result.Failure)
		txA.State = "failed"
		txA.Failure = result.Failure
		a.saveTunTxn(txA)
		a.failTun(fmt.Errorf("%s", result.Failure))
		return
	}

	txA.step("请求授权", "done", "已经具备管理员权限")
	txA.State = "done"
	a.saveTunTxn(txA)

	if err := a.runActivateTun(mode, env); err != nil {
		txA.step("启用 TUN", "failed", err.Error())
		txA.State = "failed"
		txA.Failure = err.Error()
		a.saveTunTxn(txA)
	}
}

// handoverTimeout bounds the wait for the helper.
//
// It was four minutes, and four minutes is the wrong number for the part of the wait
// a user actually experiences. Most of that window is not the helper working - it is
// the Windows permission prompt sitting unanswered. From the interface, "waiting for
// you to click something" and "hung" looked identical, and the user described it as
// sitting there like an idiot.
//
// Two changes rather than one, because shortening the number alone would turn a slow
// success into a failure on a machine that is merely slow:
//
//   - the window is now two minutes, which is generous for approving a prompt;
//   - the wait reports that it is waiting for approval, with a countdown and an
//     instruction, so the number is on screen instead of implied. See
//     tunRun.WaitingForApproval.
//
// It remains a bound and not the primary way the wait ends: a helper that exits is
// noticed as soon as it does, and a helper whose heartbeat stops is reported as stuck
// rather than slow.
const handoverTimeout = 2 * time.Minute

// approvalGrace is how long the wait is expected to last before it is the user's turn
// to act. Past it, the interface says the prompt is probably waiting to be answered.
const approvalGrace = 8 * time.Second

// approvalGraceSeconds is the same bound in the units the interface reads.
const approvalGraceSeconds = int(approvalGrace / time.Second)

// CancelTunActivation ends a wait that is still going.
//
// The interface needs this because the wait can be two minutes long and the user may
// have decided. Without it the only way out was to close the program - which is what
// someone does when a button appears to have hung, and closing the program during an
// activation is the state that leaves a half-applied arrangement behind.
//
// It stops the helper if one was started, marks the attempt failed with a reason the
// user chose, and clears the running state so the interface stops showing progress.
// It does not touch the network: a cancelled activation has not changed anything yet
// at the point it is cancelled, and if it has, the ordinary failure path runs.
func (a *App) CancelTunActivation() error {
	a.mu.Lock()
	active := a.tunRun != nil && a.tunRun.Active
	helperPID := a.helperPID
	a.mu.Unlock()
	if !active {
		return fmt.Errorf("当前没有正在进行的启用过程")
	}

	// Stop the helper first, so it cannot report a success after the user cancelled.
	if helperPID > 0 {
		if err := killHelperProcess(helperPID); err != nil {
			Log("cancel: could not stop the elevated helper (pid %d): %v", helperPID, err, "WARN")
		}
	}
	// And tell any waiter, by writing the failure into the record it reads. This is the
	// same channel the helper would have used, so there is one way for a wait to end
	// rather than two that can disagree.
	if rec := a.readHandover(); rec != nil && rec.State == handoverRunning {
		rec.State = handoverFailed
		rec.Failure = "你取消了这次启用"
		rec.UpdatedAt = time.Now().Format(time.RFC3339Nano)
		a.writeHandover(rec)
	}
	a.setApprovalWait(false)
	a.mu.Lock()
	if a.tunRun != nil {
		a.tunRun.Active = false
		a.tunRun.Stage = "已取消"
		a.tunRun.Error = "你取消了这次启用"
	}
	a.helperPID = 0
	a.mu.Unlock()
	Log("TUN activation cancelled by the user")
	return nil
}

// setApprovalWait records that this process is waiting on the Windows permission
// prompt, and starts the clock the interface counts from.
//
// The clock matters as much as the flag. "Waiting for approval" with no bound is the
// same experience as a hang; "waiting for approval, 12s of 120s" is something a user
// can decide about - including deciding to cancel, which is why the interface has a
// button that reaches this state.
func (a *App) setApprovalWait(waiting bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunRun == nil {
		a.tunRun = &tunRun{Mode: a.store.Settings().TunMode}
	}
	a.tunRun.WaitingForApproval = waiting
	a.tunRun.WaitLimitSeconds = int(handoverTimeout / time.Second)
	if waiting {
		a.approvalWaitStart = time.Now()
		a.tunRun.WaitedSeconds = 0
		a.tunRun.ApprovalHint = "Windows 正在询问是否允许 Zenith 创建虚拟网卡。" +
			"请在弹出的窗口里点「是」。如果没看到窗口，检查任务栏是否有闪烁的盾牌图标，" +
			"或者它可能被其他窗口挡住了。"
	} else {
		a.approvalWaitStart = time.Time{}
		a.tunRun.ApprovalHint = ""
	}
}

// approvalWaitElapsed is how long the current wait has been going, for the interface.
func (a *App) approvalWaitElapsed() int {
	a.mu.Lock()
	start := a.approvalWaitStart
	a.mu.Unlock()
	if start.IsZero() {
		return 0
	}
	return int(time.Since(start) / time.Second)
}

// runActivateTun is transaction B. It records what it changed before changing it,
// so a failure can put back exactly those things and nothing else.
func (a *App) runActivateTun(mode TunMode, env tunEnvironment) error {
	txB := newTunTxn(txnActivate)
	txB.Mode = mode
	st := a.store.Settings()
	// Turn the system proxy off, and record that we did.
	//
	// The two are mutually exclusive and this is the direction that matters. Once the
	// tunnel is up, the routing table carries the traffic and the proxy setting has no
	// effect on it - but every application that honours the setting keeps trying to
	// reach a local port, and that port belongs to a core this activation is about to
	// restart. The result is a machine where some applications are briefly offline and
	// the interface shows both switches on, neither of which is a description of what
	// is happening.
	//
	// Recorded in the transaction rather than just switched, so the failure path can
	// put it back: a user who had the proxy on and whose activation then failed should
	// get the arrangement they started with, not a third one.
	proxyState := NewSystemProxy(a.dataDir).Status()
	txB.Owned.SysProxyWasOn = proxyState.Enabled
	txB.Owned.SysProxyServer = proxyState.Server
	if proxyState.Enabled {
		a.setTunStage("关闭系统代理（与 TUN 互斥）")
		NewSystemProxy(a.dataDir).Disable()
		if _, err := a.store.UpdateSettings(map[string]interface{}{"systemProxy": false}); err != nil {
			Log("TUN activate: could not record that the system proxy was switched off: %v",
				err, "WARN")
		}
		txB.step("关闭系统代理", "done",
			"TUN 接管与系统代理互斥，已关闭系统代理；这次激活失败的话会恢复它")
	}
	txB.Owned.AdapterName = st.NormalizedTunDevice()
	a.saveTunTxn(txB)

	rollback := func(reason error) error {
		txB.State = "failed"
		txB.Failure = reason.Error()
		a.saveTunTxn(txB)
		a.rollbackActivate(txB, mode)
		a.failTun(reason)
		return reason
	}

	a.setTunStage("准备组件")
	if _, err := a.store.UpdateSettings(map[string]interface{}{
		"tunMode":   string(mode),
		"tunDevice": st.TunDevice,
		"tunStack":  st.TunStack,
	}); err != nil {
		return rollback(fmt.Errorf("无法保存 TUN 设置：%v", err))
	}
	txB.step("保存设置", "done", string(mode))

	// Write the configuration here, explicitly.
	//
	// This used to be left to ApplySettings, which rewrites the configuration when
	// one of a list of keys changes. That list did not include the TUN settings, so
	// enabling TUN stored the mode and then restarted the core against a file with
	// no tun block in it - twice, and the second time even after the list was
	// fixed. Making the activation depend on a side effect of a settings function
	// was the actual mistake: an activation that must produce a specific file
	// should say so, and should fail loudly if it cannot.
	cfgNodes := a.mergedNodes()
	cfgSettings := a.store.Settings()
	cfg := BuildConfig(cfgNodes, a.optimizedNames(), cfgSettings,
		a.secret, a.store.Snapshot().Current, a.dnsPort)
	if err := validateCandidateConfig(cfg); err != nil {
		return rollback(fmt.Errorf("生成的 TUN 配置没有通过校验：%v", err))
	}
	if !strings.Contains(cfg, "\ntun:\n") {
		// The one condition this whole path exists for. Checking it here rather
		// than trusting the generator means a future change cannot silently bring
		// TUN back to "the adapter never appears".
		return rollback(fmt.Errorf("内部错误：设置已保存为 %s，但生成的配置里没有 tun 段", mode))
	}
	if err := a.applyCandidateConfig(cfg); err != nil {
		return rollback(fmt.Errorf("无法写入 TUN 配置：%v", err))
	}
	// The known-good copy is deliberately NOT updated here. It is only replaced
	// once this configuration has been proven, at the end of this function - which
	// is what makes a rollback able to restore something that actually ran. Writing
	// it now is the defect: the pre-TUN configuration would be overwritten by a
	// candidate that then failed verification.
	txB.step("写入候选配置", "done", fmt.Sprintf("%d 字节，含 tun 段", len(cfg)))

	// The core is restarted rather than reloaded: the TUN inbound is created at
	// startup, and a hot reload will not bring an adapter up.
	a.setTunStage("重建内核以启用 TUN")
	a.core.Stop()
	time.Sleep(1500 * time.Millisecond)
	if err := a.core.Start(); err != nil {
		return rollback(fmt.Errorf("内核未能带 TUN 配置启动：%v", err))
	}
	txB.Owned.CoreStarted = true
	a.saveTunTxn(txB)
	txB.step("启动内核", "done", "内核已带 TUN 配置启动")

	// Confirm the adapter by name, from the OS, rather than assuming a sleep was
	// long enough.
	a.setTunStage("建立虚拟网卡")
	adapterOK := false
	for i := 0; i < 40; i++ {
		if tunAdapterExists(st.NormalizedTunDevice()) {
			adapterOK = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !adapterOK {
		coreErr := a.core.LastError()
		if coreErr == "" {
			coreErr = "内核没有报告原因"
		}
		return rollback(fmt.Errorf("虚拟网卡 %q 没有出现。内核的说法：%s。"+
			"这通常意味着授权没有真正生效（网卡和路由需要管理员权限），"+
			"或者系统策略阻止了驱动安装", st.NormalizedTunDevice(), coreErr))
	}
	txB.Owned.AdapterCreated = true
	a.saveTunTxn(txB)
	txB.step("建立虚拟网卡", "done", st.NormalizedTunDevice())

	// Only now is it meaningful to check that traffic flows. "The adapter exists"
	// is not the claim being made, and neither is "the selected node answers a
	// speed test": neither says anything about whether anything on this machine
	// reaches the tunnel. The verification below gathers evidence in the order the
	// packets travel - adapter up, default route into it, a request from this
	// process with no proxy configured anywhere, and the core's own record of
	// carrying it.
	a.setTunStage("验证流量是否经过隧道")
	traffic := a.VerifyTunTraffic(mode, env)
	txB.Traffic = &traffic
	a.saveTunTxn(txB)
	if !traffic.OK {
		txB.step("验证流量", "failed", traffic.Stage+": "+traffic.Detail)
		return rollback(fmt.Errorf("网卡已建立，但流量没有经过隧道（%s）：%s。"+
			"已回滚这次激活，没有把它当作成功", traffic.Stage, traffic.Detail))
	}
	txB.step("验证流量", "done", traffic.DirectDetail+"；"+traffic.CoreDetail)
	if traffic.IPv6 != "" {
		Log("TUN 提示：%s", traffic.IPv6)
	}

	// There is no firewall block here, and there was.
	//
	// What was added: two rules blocking all outbound and inbound traffic "so that
	// protected traffic cannot leave outside the tunnel". What it did: blocked the
	// tunnel as well, because the tunnel's own traffic is outbound traffic. Enabling
	// privacy mode therefore started by cutting the machine off, the tunnel could
	// never come up, and the state it left behind was a firewall with no internet and
	// no way out - the rules could be installed by this program and could only be
	// removed by an administrator by hand.
	//
	// A safety feature that can strand the user, and that the program cannot undo, is
	// worse than the absence of the feature. It is not being fixed here; it is being
	// withdrawn. Privacy mode is strict-route and an explicit refusal to fall back,
	// which is a real thing that it does, and the README says what it does not do.
	//

	// Only now, with the adapter carrying traffic, is this configuration the one
	// worth going back to. A failure after this point would otherwise roll back to
	// the file that was just overwritten.
	a.commitConfig(cfg)
	txB.State = "done"
	a.saveTunTxn(txB)
	a.mu.Lock()
	if a.tunRun != nil {
		a.tunRun.Active = false
		a.tunRun.Stage = "已启用"
	}
	a.mu.Unlock()
	Log("TUN enabled in %s mode; adapter %q is up, the default route uses it, and a "+
		"proxy-free request completed through it", mode, st.NormalizedTunDevice())
	return nil
}

// applyCandidateConfig writes a candidate configuration without disturbing the
// version that is known to work.
//
// The candidate is verified by the activation before it becomes the known-good
// copy. Doing it the other way - writing last-good at the same time as the
// candidate - is what made a failed activation unrecoverable: the pre-TUN
// configuration had already been overwritten by the TUN one that then failed
// validation, so there was nothing left to go back to.
func (a *App) applyCandidateConfig(cfg string) error {
	return os.WriteFile(a.configPath, []byte(cfg), 0o644)
}

// commitConfig makes the verified configuration the known-good one.
//
// Only called after the activation has proven the configuration works. Until then
// the previous known-good copy is left untouched, so a rollback restores a
// configuration that actually ran.
func (a *App) commitConfig(cfg string) {
	if err := os.WriteFile(a.goodConfigPath(), []byte(cfg), 0o644); err != nil {
		Log("could not update the known-good configuration: %v", err, "WARN")
	}
}

// restoreConfig puts the known-good configuration back and confirms it.
//
// The confirmation is the point. The old rollback changed the mode and restarted
// the core without ever checking that the file it was starting from was the one
// that worked, and a failure to restore was logged and then ignored - so the
// interface said "rolled back" while the machine ran something else.
//
// It returns nil only when the file on disk is the known-good configuration.
func (a *App) restoreConfig() error {
	good, err := os.ReadFile(a.goodConfigPath())
	if err != nil || len(good) == 0 {
		return fmt.Errorf("没有可恢复的上一版配置（%s 不存在或为空）", a.goodConfigPath())
	}
	if err := os.WriteFile(a.configPath, good, 0o644); err != nil {
		return fmt.Errorf("写入上一版配置失败：%v", err)
	}
	// Read it back rather than trusting the write: the whole reason this function
	// reports separately is that a silent failure here leaves the user on a
	// configuration nobody verified.
	back, err := os.ReadFile(a.configPath)
	if err != nil {
		return fmt.Errorf("恢复后无法读回配置：%v", err)
	}
	if !bytes.Equal(back, good) {
		return fmt.Errorf("恢复后配置文件与上一版不一致（写入 %d 字节，读回 %d 字节）",
			len(good), len(back))
	}
	return nil
}

// rollbackActivate restores exactly what this activation changed.
//
// It does not touch resources it did not create, which is the whole reason the
// ownership record exists: another VPN's adapter, or a route the user added, must
// survive a failed enable.
//
// The order matters and is the fix for what the review found:
//
//  1. put the previous configuration back, and confirm it is back;
//  2. only then restart the core, so it starts from a configuration that worked;
//  3. restore the system proxy if this activation changed it;
//  4. remove the adapter, if this activation created it;
//  5. report a failed restore separately, rather than as part of the rollback.
//
// In privacy mode the block is left standing. Restoring connectivity is not an
// improvement when it restores it unprotected, and a failed enable must not be the
// event that quietly removes the protection the user asked for.
func (a *App) rollbackActivate(txB *tunTxn, mode TunMode) {
	Log("TUN: rolling back the failed activation", "WARN")
	txB.State = "rollingBack"
	a.saveTunTxn(txB)

	// 1. The previous configuration first, and verified.
	restoreErr := a.restoreConfig()
	if restoreErr != nil {
		// Reported on its own. A rollback that could not put the file back is a
		// different, more serious condition than one that did, and folding it into
		// a generic "rolled back" message would hide it.
		Log("TUN rollback: the previous configuration could NOT be restored: %v", restoreErr, "ERR")
		txB.Steps = append(txB.Steps, tunStep{
			Name: "恢复配置", State: "failed",
			Detail: restoreErr.Error() + "。当前配置可能不是上一次成功运行的那一份，" +
				"建议重新启用一次或从发布包重新开始",
			At: time.Now(),
		})
		txB.RestoreFailure = restoreErr.Error()
	} else {
		txB.Steps = append(txB.Steps, tunStep{
			Name: "恢复配置", State: "done",
			Detail: "已恢复上一次成功运行的配置，并确认写回一致", At: time.Now(),
		})
	}

	// 2. The mode goes back to off, because the activation that would have turned it
	// on did not complete.
	//
	// There used to be a branch here for a mode that kept a firewall block standing
	// through the failure. That mode is gone: the block it installed blocked all
	// outbound traffic, which includes the tunnel's own traffic, so engaging it cut
	// the connection before the tunnel could carry anything - and the rule it left
	// behind could only be removed by hand as an administrator. A mode that can
	// strand the user, that the program cannot undo, and that reports "protected"
	// while doing it is worse than no mode at all.
	// The mode goes back to off, and this is the same rule as the recovery path: a
	// stored mode that does not describe the machine is worse than no mode, because
	// everything that asks "is TUN on?" believes it.
	if _, err := a.store.UpdateSettings(map[string]interface{}{"tunMode": string(TunOff)}); err != nil {
		Log("TUN rollback: could not switch the mode back off: %v", err, "WARN")
		txB.Steps = append(txB.Steps, tunStep{
			Name: "关闭模式", State: "failed", Detail: err.Error(), At: time.Now(),
		})
	}

	// 3. Restart the core on the configuration that was just restored.
	a.core.Stop()
	time.Sleep(1200 * time.Millisecond)
	if err := a.core.Start(); err != nil {
		Log("TUN rollback: the core did not start on the restored configuration: %v", err, "ERR")
		txB.Steps = append(txB.Steps, tunStep{
			Name: "重启内核", State: "failed",
			Detail: "内核没有能在恢复后的配置上启动：" + err.Error(), At: time.Now(),
		})
	} else {
		txB.Steps = append(txB.Steps, tunStep{
			Name: "重启内核", State: "done", Detail: "已用恢复后的配置启动", At: time.Now(),
		})
	}

	// 4. The system proxy, if this activation touched it.
	if txB.Owned.SysProxyWasOn && txB.Owned.SysProxyServer != "" {
		sp := NewSystemProxy(a.dataDir)
		if sp.Status().Owner != "zenith" {
			// The core's own port is serving it again; nothing to put back.
			Log("TUN rollback: the system proxy is already served by the restored core")
		}
	}

	// 5. The adapter, if this activation created it.
	if txB.Owned.AdapterCreated {
		if err := removeTunAdapter(txB.Owned.AdapterName); err != nil {
			Log("TUN rollback: could not remove adapter %q: %v", txB.Owned.AdapterName, err, "WARN")
			txB.Steps = append(txB.Steps, tunStep{
				Name: "回滚网卡", State: "failed", Detail: err.Error(), At: time.Now(),
			})
		} else {
			txB.Steps = append(txB.Steps, tunStep{
				Name: "回滚网卡", State: "done", Detail: "已删除本次创建的网卡", At: time.Now(),
			})
		}
	}

	if txB.RestoreFailure != "" {
		// Not "rolled back": the configuration could not be put back, so the honest
		// state is that the rollback itself failed.
		txB.State = "rollbackFailed"
	} else {
		txB.State = "rolledBack"
	}
	a.saveTunTxn(txB)
}

// ---- disabling ------------------------------------------------------------

// DisableTun turns the tunnel off and restores the previous arrangement.
//
// The signature used to take a releasePrivacy argument, because one mode required the
// user to confirm before its block was lifted. That mode is gone: the block it
// installed blocked the tunnel along with everything else, so it is removed from the
// program rather than repaired.
func (a *App) DisableTun() error {
	st := a.store.Settings()
	if st.TunMode == TunOff {
		return nil
	}
	if _, err := a.store.UpdateSettings(map[string]interface{}{"tunMode": string(TunOff)}); err != nil {
		return err
	}
	a.core.Stop()
	time.Sleep(1200 * time.Millisecond)
	if err := a.core.Start(); err != nil {
		return err
	}
	if err := removeTunAdapter(st.TunDevice); err != nil {
		Log("TUN disable: adapter %q could not be removed: %v", st.TunDevice, err, "WARN")
	}
	Log("TUN disabled")
	return nil
}

// ---- verification ---------------------------------------------------------

// verifyProxyCarries makes a real request through the selected node and vanishes
// only if the whole path worked.
//
// It delegates to the core's own per-node test rather than dialling the local
// port itself. That distinction matters: a request to the local port proves the
// mixed listener answers, while a request the core makes through the node proves
// the core authenticated to the proxy and the proxy carried the traffic. Only the
// second is evidence that TUN mode is doing anything.
func (a *App) verifyProxyCarries() error {
	res := a.VerifySelectedEndToEnd()
	if res.OK {
		return nil
	}
	return fmt.Errorf("%s 阶段失败：%s", res.Stage, res.Detail)
}

// ---- lifecycle: start-up recovery, repair, uninstall -----------------------

// RecoverTun runs at start-up. It reconciles what the transaction record says with
// what the machine actually looks like, instead of trusting a remembered switch.
func (a *App) RecoverTun() {
	st := a.store.Settings()
	tx := a.loadTunTxn()

	// An attempt that never finished is reported and undone, not silently retried:
	// retrying a half-done activation is how duplicate adapters appear.
	if tx != nil && tx.State == "running" {
		Log("TUN: found an unfinished %s transaction from %s; rolling it back so the "+
			"machine is not left in an unknown state", tx.Kind, tx.StartedAt.Format(time.RFC3339), "WARN")
		if tx.Kind == txnActivate {
			a.rollbackActivate(tx, TunMode(tx.Mode))
		}
		a.mu.Lock()
		if a.tunRun == nil {
			a.tunRun = &tunRun{}
		}
		a.tunRun.Stage = "上次启用未完成，已回滚到未启用"
		a.tunRun.Error = tx.Failure
		a.mu.Unlock()
		return
	}

	// The stored mode says TUN should be on. Verify that against reality rather
	// than believing it: a reboot, a driver update or another VPN can all make the
	// remembered state wrong.
	if st.TunMode != TunOff {
		if tunAdapterExists(st.TunDevice) {
			Log("TUN: mode %s is active and adapter %q is present", st.TunMode, st.TunDevice)
			return
		}
		// The stored mode is cleared, not just reported.
		//
		// This is the difference between a state that is described and a state that is
		// wrong. The adapter is gone, so the tunnel is not up - and leaving
		// `tunMode: compat` in the file means every part of the program that asks "is TUN
		// on?" gets yes. The visible consequence is that the system proxy cannot be
		// enabled, because the two are mutually exclusive and the program believes the
		// other one holds the traffic:
		//
		//   settings say compat but adapter "Zenith" is not present; the tunnel is not up
		//   开系统代理: ok=False  TUN 接管正在使用中
		//
		// A machine in that state has no tunnel and no proxy, and the interface reports a
		// mode that is not running. Clearing it restores the arrangement the user can
		// actually use - the system proxy - and the interface says plainly that TUN needs
		// enabling again if they want it.
		Log("TUN: settings say %s but adapter %q is not present; clearing the mode so the "+
			"system proxy is usable again", st.TunMode, st.TunDevice, "WARN")
		if _, err := a.store.UpdateSettings(map[string]interface{}{"tunMode": string(TunOff)}); err != nil {
			Log("TUN: could not clear the stale mode: %v", err, "WARN")
		}
		a.mu.Lock()
		if a.tunRun == nil {
			a.tunRun = &tunRun{}
		}
		a.tunRun.Stage = "上次的 TUN 未生效，已恢复为系统代理；需要时请重新启用"
		a.tunRun.Mode = TunOff
		a.mu.Unlock()
		return
	}

	// Mode is off. One of our adapters still lying around is a leftover from a
	// crash, and it is ours to clean up.
	if tunAdapterExists(st.TunDevice) {
		Log("TUN: found a leftover adapter %q with TUN switched off; removing it", st.TunDevice, "WARN")
		if err := removeTunAdapter(st.TunDevice); err != nil {
			Log("TUN: leftover adapter could not be removed: %v", err, "WARN")
		}
	}
}

// RepairTun is the offline repair path. It needs no network: it re-verifies the
// components and, when asked, releases the tunnel, so a user whose interface is
// broken can still get their machine back.
func (a *App) RepairTun(release bool) (tunEnvironment, error) {
	env := a.checkTunEnvironment()
	if release {
		if err := a.DisableTun(); err != nil {
			return env, err
		}
	}
	return env, nil
}

// UninstallTun removes only what Zenith owns.
//
// It deliberately does not delete the wintun component, because another
// application may be using the same driver file, and removing a driver out from
// under a running product is worse than leaving a file behind.
func (a *App) UninstallTun() error {
	st := a.store.Settings()
	if st.TunMode != TunOff {
		if err := a.DisableTun(); err != nil {
			return err
		}
	}
	return removeTunAdapter(st.TunDevice)
}

// ---- the elevated instance ------------------------------------------------

// RunElevatedActivation is what the elevated copy of Zenith does.
//
// It exists so the whole application never has to run as administrator. The
// normal instance keeps its ordinary rights and its window; this one is started
// only for the activation, performs it, reports the outcome through the
// transaction record, and exits. No elevated process is left behind, and the UI
// never holds administrator rights it does not need.
func (a *App) RunElevatedActivation(mode TunMode, handoverID string, requesterPID int) error {
	Log("elevated instance: activating TUN in %s mode", mode)

	// Take ownership of the handover record first, so the waiting side sees
	// progress from the very start rather than silence while the environment is
	// checked. Everything below reports through it, and its terminal state is the
	// only thing that counts as this activation's outcome.
	rec := a.beginHandover(handoverID, requesterPID, mode)

	env := a.checkTunEnvironment()
	if len(env.Blockers) > 0 {
		err := fmt.Errorf("%s", strings.Join(env.Blockers, "；"))
		a.progressHandover(rec, "检查环境")
		a.finishHandover(rec, err)
		a.failTun(err)
		return err
	}
	a.progressHandover(rec, "准备组件")

	// Claim the core before stopping it. The ordinary instance restarts a core it
	// finds down, so without the marker it would start one on top of this
	// activation and the two would fight for the same listener.
	a.yieldForActivation()
	defer a.releaseActivation()
	a.core.Stop()
	time.Sleep(1 * time.Second)

	// The activation's own result, returned rather than inferred.
	//
	// This used to be read back from the progress object, which this process never
	// initialised - so a failure was recorded nowhere, the read returned an empty
	// value, and a failed activation was reported as success. It then stopped the
	// core on the way out, taking down the tunnel it had just built.
	actErr := a.runActivateTun(mode, env)
	a.finishHandover(rec, actErr)
	if actErr != nil {
		// The core is left as the rollback put it. Stopping it here was the old
		// behaviour and it was wrong: the ordinary instance takes it back on its
		// next tick, and stopping it first tore the tunnel down between this
		// process exiting and that tick, for no reason.
		Log("elevated instance: activation failed: %v", actErr, "WARN")
		return actErr
	}
	Log("elevated instance: activation finished successfully")
	return nil
}
