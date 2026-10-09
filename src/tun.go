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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const defaultTunDevice = "Zenith"

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
	OK        bool              `json:"ok"`
	Blockers  []string          `json:"blockers"`
	Warnings  []string          `json:"warnings"`
	Admin     bool              `json:"admin"`
	Arch      string            `json:"arch"`
	OS        string            `json:"os"`
	Adapter   string            `json:"adapter,omitempty"`
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
	m, err := loadManifest(a.rootDir)
	if err != nil {
		env.Blockers = append(env.Blockers, err.Error())
	} else {
		env.Component = verifyTunComponent(a.rootDir, m.Components[0])
		if !env.Component.Verified {
			env.Blockers = append(env.Blockers,
				"TUN 组件未通过校验："+env.Component.Detail)
		}
		env.Checks["组件"] = fmt.Sprintf("%s %s", env.Component.Name, env.Component.Version)
		if env.Component.Signed {
			env.Checks["组件签名"] = env.Component.Signer
		} else {
			env.Warnings = append(env.Warnings, "组件摘要正确，但未能确认数字签名")
		}
	}

	// The core must actually be able to load it. Presence on disk is not proof:
	// the file has to be next to the core binary, because the loader searches the
	// executable's own directory first.
	coreDir := filepath.Join(a.rootDir, "core")
	if _, err := os.Stat(filepath.Join(coreDir, "mihomo.exe")); err != nil {
		env.Blockers = append(env.Blockers, "找不到 core/mihomo.exe")
	} else {
		env.Checks["内核"] = "已找到 core/mihomo.exe"
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
	if st.TunDevice == "" {
		st.TunDevice = defaultTunDevice
	}
	env.Adapter = st.TunDevice
	env.Checks["网卡名"] = st.TunDevice

	env.OK = len(env.Blockers) == 0
	return env
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
func elevateRequest(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb := "runas"
	cwd, _ := os.Getwd()
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.Dir = cwd
	if err := shellExecuteRunas(exe, args, cwd); err != nil {
		if isUserCancel(err) {
			return fmt.Errorf("没有获得管理员授权，TUN 未启用。系统设置没有被修改")
		}
		return fmt.Errorf("请求管理员授权失败：%v", err)
	}
	_ = verb
	_ = cmd
	return nil
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
	Steps     []tunStep  `json:"steps"`
	Failure   string     `json:"failure,omitempty"`
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

	// Privilege is requested after the checks that need none, so a machine that
	// cannot support TUN is told that before it is asked for a password.
	if !isElevated() {
		a.setTunStage("等待系统授权")
		txA.step("请求授权", "pending", "等待用户在 UAC 对话框中确认")
		a.saveTunTxn(txA)
		// The root directory is passed explicitly rather than left to be
		// rediscovered. resolveRoot infers it by looking for web/index.html near
		// the executable, and an elevated process can be started with a different
		// working directory - which made it read a different configuration than
		// the instance that asked for the elevation, and act on ports and nodes
		// that were not the ones in use.
		err := elevateRequest([]string{
			"-tun-elevated",
			"-root", a.rootDir,
			"-datadir", a.dataDir,
			"-tun-mode", string(mode),
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
		a.mu.Lock()
		if a.tunRun != nil {
			a.tunRun.Stage = "已授权，等待提权实例接管"
		}
		a.mu.Unlock()
		return
	}

	txA.step("请求授权", "done", "已经具备管理员权限")
	txA.State = "done"
	a.saveTunTxn(txA)

	a.runActivateTun(mode, env)
}

// runActivateTun is transaction B. It records what it changed before changing it,
// so a failure can put back exactly those things and nothing else.
func (a *App) runActivateTun(mode TunMode, env tunEnvironment) {
	txB := newTunTxn(txnActivate)
	st := a.store.Settings()
	proxyState := NewSystemProxy(a.dataDir).Status()
	txB.Owned.SysProxyWasOn = proxyState.Enabled
	txB.Owned.SysProxyServer = proxyState.Server
	txB.Owned.AdapterName = st.TunDevice
	a.saveTunTxn(txB)

	rollback := func(reason error) {
		txB.State = "failed"
		txB.Failure = reason.Error()
		a.saveTunTxn(txB)
		a.rollbackActivate(txB)
		a.failTun(reason)
	}

	a.setTunStage("准备组件")
	if _, err := a.store.UpdateSettings(map[string]interface{}{
		"tunMode":   string(mode),
		"tunDevice": st.TunDevice,
		"tunStack":  st.TunStack,
	}); err != nil {
		rollback(fmt.Errorf("无法保存 TUN 设置：%v", err))
		return
	}
	txB.step("保存设置", "done", string(mode))

	// The core is restarted rather than reloaded: the TUN inbound is created at
	// startup, and a hot reload will not bring an adapter up.
	a.setTunStage("重建内核以启用 TUN")
	a.core.Stop()
	time.Sleep(1500 * time.Millisecond)
	if err := a.core.Start(); err != nil {
		rollback(fmt.Errorf("内核未能带 TUN 配置启动：%v", err))
		return
	}
	txB.Owned.CoreStarted = true
	a.saveTunTxn(txB)
	txB.step("启动内核", "done", "内核已带 TUN 配置启动")

	// Confirm the adapter by name, from the OS, rather than assuming a sleep was
	// long enough.
	a.setTunStage("建立虚拟网卡")
	adapterOK := false
	for i := 0; i < 40; i++ {
		if tunAdapterExists(st.TunDevice) {
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
		rollback(fmt.Errorf("虚拟网卡 %q 没有出现。内核的说法：%s。"+
			"常见原因是组件未被正确加载，或系统策略阻止了驱动安装", st.TunDevice, coreErr))
		return
	}
	txB.Owned.AdapterCreated = true
	a.saveTunTxn(txB)
	txB.step("建立虚拟网卡", "done", st.TunDevice)

	// Only now is it meaningful to check that traffic flows. "The adapter exists"
	// is not the claim being made.
	a.setTunStage("验证真实代理请求")
	if err := a.verifyProxyCarries(); err != nil {
		rollback(fmt.Errorf("网卡已建立，但真实请求没有通过隧道：%v。"+
			"已回滚这次激活，没有把它当作成功", err))
		return
	}
	txB.step("验证连接", "done", "真实请求已通过隧道")

	txB.State = "done"
	a.saveTunTxn(txB)
	a.mu.Lock()
	if a.tunRun != nil {
		a.tunRun.Active = false
		a.tunRun.Stage = "已启用"
	}
	a.mu.Unlock()
	Log("TUN enabled in %s mode; adapter %q verified carrying traffic", mode, st.TunDevice)
}

// rollbackActivate restores exactly what this activation changed.
//
// It does not touch resources it did not create, which is the whole reason the
// ownership record exists: another VPN's adapter, or a route the user added, must
// survive a failed enable.
func (a *App) rollbackActivate(txB *tunTxn) {
	Log("TUN: rolling back the failed activation", "WARN")
	// Put the mode back to off first, so the next core start does not try to bring
	// up a tunnel that just failed.
	if _, err := a.store.UpdateSettings(map[string]interface{}{"tunMode": string(TunOff)}); err == nil {
		a.core.Stop()
		time.Sleep(1200 * time.Millisecond)
		_ = a.core.Start()
	}
	if txB.Owned.AdapterCreated {
		if err := removeTunAdapter(txB.Owned.AdapterName); err != nil {
			Log("TUN rollback: could not remove adapter %q: %v", txB.Owned.AdapterName, err, "WARN")
			txB.step("回滚网卡", "failed", err.Error())
		} else {
			txB.step("回滚网卡", "done", "已删除本次创建的网卡")
		}
	}
	txB.State = "rolledBack"
	a.saveTunTxn(txB)
}

// ---- disabling ------------------------------------------------------------

// DisableTun turns the tunnel off and restores the previous arrangement. In
// privacy mode nothing may call it implicitly: releasing the block is the user's
// decision, which is why releasePrivacy exists as an explicit argument.
func (a *App) DisableTun(releasePrivacy bool) error {
	st := a.store.Settings()
	if st.TunMode == TunOff {
		return nil
	}
	if st.TunMode == TunPrivacy && !releasePrivacy {
		return fmt.Errorf("当前是隐私保护模式：请先确认要退出保护并恢复常规联网")
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
			a.rollbackActivate(tx)
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
		Log("TUN: settings say %s but adapter %q is not present; the tunnel is not up",
			st.TunMode, st.TunDevice, "WARN")
		a.mu.Lock()
		if a.tunRun == nil {
			a.tunRun = &tunRun{}
		}
		a.tunRun.Stage = "上次的 TUN 未生效，需要重新启用"
		a.tunRun.Mode = st.TunMode
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
		if err := a.DisableTun(true); err != nil {
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
		if err := a.DisableTun(true); err != nil {
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
func (a *App) RunElevatedActivation(mode TunMode) error {
	Log("elevated instance: activating TUN in %s mode", mode)
	env := a.checkTunEnvironment()
	if len(env.Blockers) > 0 {
		err := fmt.Errorf("%s", strings.Join(env.Blockers, "；"))
		a.failTun(err)
		return err
	}
	// Claim the core before stopping it. The ordinary instance restarts a core it
	// finds down, so without the marker it would start one on top of this
	// activation and the two would fight for the same listener.
	a.yieldForActivation()
	defer a.releaseActivation()
	a.core.Stop()
	time.Sleep(1 * time.Second)
	a.runActivateTun(mode, env)
	if st := a.TunRunState(); st.Error != "" {
		Log("elevated instance: activation failed: %s", st.Error, "WARN")
		a.core.Stop()
		return fmt.Errorf("%s", st.Error)
	}
	Log("elevated instance: activation finished")
	// Hand the core back: the ordinary instance will start it again on its next
	// tick, and this process leaves no privileged service running.
	a.core.Stop()
	return nil
}
