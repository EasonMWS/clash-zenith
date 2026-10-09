package main

// ---------------------------------------------------------------------------
// Who owns the core.
//
// The core was owned by whichever process happened to be running. That worked
// until elevation, when it became two processes: the ordinary instance started a
// core, an elevated helper stopped it to take the ports, started its own, then
// stopped that one on the way out and expected the first instance to notice and
// start another. Both generated their own control secret, both cached their own
// settings, and both wrote the same configuration file. The review found three
// consequences and all three were real:
//
//   - a tunnel that had just been brought up was stopped by the helper leaving;
//   - the ordinary instance had no rights to take over what the helper had built;
//   - the secrets did not match, so a core that was plainly running was reported
//     as unavailable because authentication failed.
//
// The fix is not another coordination scheme between two owners. It is one owner.
// A small resident service holds the core; the window asks it to start and stop
// things. The window never starts a core itself when the service is present, and
// the service never assumes the window is watching.
//
// The service is what makes "authorise once, then it just works" true: it is
// installed once, under elevation, and from then on starting the tunnel needs no
// prompt.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serviceName is the name Windows knows the service by, and the name the UI uses
// in its requests.
const serviceName = "ZenithService"

// servicePort is fixed rather than dynamic: the service is a system component with
// one job, and a stable port is what lets the window find it without a discovery
// step that could itself fail. It is bound to loopback only.
const servicePort = 7795

// serviceBaseURL is where the service listens.
func serviceBaseURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", servicePort)
}

// serviceState is what the service's state file records about the core it owns.
//
// It is a file rather than only in-memory state so that a window which starts
// after the service can still report what is running, and so a diagnostic can see
// who owns the core without asking anyone.
type serviceState struct {
	// CorePID is the core the service is running, or zero.
	CorePID int `json:"corePid"`
	// CoreStartedAt is when the service started it.
	CoreStartedAt string `json:"coreStartedAt,omitempty"`
	// ConfigDigest is the configuration the service last wrote, so a window can
	// tell whether the running core matches what it believes.
	ConfigDigest string `json:"configDigest,omitempty"`
	// Mode is the TUN mode the running core was started with.
	Mode string `json:"mode,omitempty"`
	// ServicePID is the service process itself, so a stale file is recognisable.
	ServicePID int `json:"servicePid"`
	// UpdatedAt is when this was written.
	UpdatedAt string `json:"updatedAt"`
}

func serviceStatePath(dataDir string) string {
	return filepath.Join(dataDir, "service-state.json")
}

func (a *App) loadServiceState() *serviceState {
	raw, err := os.ReadFile(serviceStatePath(a.dataDir))
	if err != nil {
		return nil
	}
	var s serviceState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

func (a *App) saveServiceState(s *serviceState) {
	s.UpdatedAt = time.Now().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	tmp := serviceStatePath(a.dataDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, serviceStatePath(a.dataDir))
}

// ---- the window's side -----------------------------------------------------

// serviceReachable reports whether the service is installed and answering.
//
// It is a real request rather than a file check: a state file can outlive the
// process that wrote it, and acting on one would mean the window and the service
// both start a core.
func serviceReachable() bool {
	c := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := c.Get(serviceBaseURL() + "/alive")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// serviceInstalled reports whether the service is registered with Windows.
//
// This is deliberately separate from reachability: an installed service that is
// stopped is a different situation from one that was never installed, and they
// need different messages. The first needs starting, the second needs the one
// authorisation the design is built around.
func serviceInstalled() bool {
	out, err := HiddenCommand("sc", "query", serviceName)
	if err != nil {
		return false
	}
	// "does not exist" arrives as a non-zero exit with that text; an existing
	// service prints its state.
	return strings.Contains(out, "SERVICE_NAME") || strings.Contains(out, "STATE")
}

// serviceStart requests the service to start the core with a configuration.
//
// The request carries the control secret. That is the authenticated local channel
// the review asked for: the secret is already required to talk to the core, so
// reusing it means the channel adds no new credential to lose, and a process that
// cannot read the secret cannot make the service act.
func (a *App) serviceStartRequest(cfg []byte, mode TunMode) error {
	body, err := json.Marshal(map[string]interface{}{
		"config": string(cfg),
		"mode":   string(mode),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, serviceBaseURL()+"/core/start", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zenith-Secret", a.secret)
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("无法连接 Zenith 服务：%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("Zenith 服务拒绝了请求：控制密码不一致。"+
			"这通常意味着服务是用另一份 data 目录安装的（%s）", serviceStatePath(a.dataDir))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Zenith 服务返回 %d：%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		OK    bool   `json:"ok"`
		PID   int    `json:"pid"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("Zenith 服务的回应无法解析：%v", err)
	}
	if !out.OK {
		if out.Error == "" {
			out.Error = "服务没有说明原因"
		}
		return fmt.Errorf("%s", out.Error)
	}
	return nil
}

// serviceStopRequest asks the service to stop the core it owns.
func (a *App) serviceStopRequest() error {
	req, err := http.NewRequest(http.MethodPost, serviceBaseURL()+"/core/stop", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Zenith-Secret", a.secret)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// serviceCorePID reports the core the service says it is running.
func (a *App) serviceCorePID() int {
	c := &http.Client{Timeout: 2500 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, serviceBaseURL()+"/core/state", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("X-Zenith-Secret", a.secret)
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var st serviceState
	if err := json.Unmarshal(raw, &st); err != nil {
		return 0
	}
	return st.CorePID
}

// ---- core ownership --------------------------------------------------------

// coreOwner names who is responsible for the core right now.
type coreOwner string

const (
	ownerService coreOwner = "service" // the resident service holds it
	ownerSelf    coreOwner = "self"    // this process holds it
	ownerNone    coreOwner = "none"    // nobody does
)

// coreOwnerNow decides who owns the core, by asking rather than assuming.
func (a *App) coreOwnerNow() coreOwner {
	if serviceReachable() {
		return ownerService
	}
	if a.core != nil && a.core.IsUp() {
		return ownerSelf
	}
	return ownerNone
}

// StartCoreThroughOwner starts the core, whichever way is correct for this machine.
//
// This is the single entry point the rest of the program uses. Callers do not
// choose between the service and a local process; they ask for a core, and this
// decides. That is what stops two owners existing again: there is one place that
// knows, and it asks the service when the service is there.
func (a *App) StartCoreThroughOwner(cfg []byte, mode TunMode) error {
	switch a.coreOwnerNow() {
	case ownerService:
		return a.serviceStartRequest(cfg, mode)
	case ownerSelf:
		if a.core.IsUp() {
			return nil
		}
		if err := a.core.Start(); err != nil {
			return fmt.Errorf("内核未能启动：%v", err)
		}
		return nil
	default:
		if err := a.core.Start(); err != nil {
			return fmt.Errorf("内核未能启动：%v", err)
		}
		return nil
	}
}

// StopCoreThroughOwner stops the core, whichever way is correct.
func (a *App) StopCoreThroughOwner() error {
	if a.coreOwnerNow() == ownerService {
		return a.serviceStopRequest()
	}
	if a.core != nil {
		a.core.Stop()
	}
	return nil
}

// ---- the service's side ----------------------------------------------------

// serviceHandler is the service's HTTP surface.
//
// It is small on purpose. The service does one thing - hold the core - and the
// fewer things it can be asked to do, the less there is to get wrong in the one
// process that runs with rights the rest of the program does not have.
type serviceHandler struct {
	app    *App
	secret string
}

func (h *serviceHandler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		// Deliberately unauthenticated and trivial: it answers "is anything there",
		// which is the question the window needs answered before it decides who owns
		// the core. It reveals nothing and changes nothing.
		writeJSON(w, 200, map[string]interface{}{"ok": true, "service": serviceName})
	})
	mux.HandleFunc("/core/start", h.auth(h.handleStart))
	mux.HandleFunc("/core/stop", h.auth(h.handleStop))
	mux.HandleFunc("/core/state", h.auth(h.handleState))
	return mux
}

// auth enforces the control secret and refuses anything that is not loopback.
//
// Two checks because they stop different things: the loopback check stops another
// machine, and the secret stops another account on this one. A request without the
// secret is refused before it reaches a handler, so no handler has to remember to
// check.
func (h *serviceHandler) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || (host != "127.0.0.1" && host != "::1") {
			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"ok": false, "error": "只接受本机请求",
			})
			return
		}
		got := r.Header.Get("X-Zenith-Secret")
		if got == "" {
			got = r.URL.Query().Get("secret")
		}
		if !secretEqual(got, h.secret) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"ok": false, "error": "控制密码不正确",
			})
			return
		}
		next(w, r)
	}
}

func (h *serviceHandler) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "需要 POST"})
		return
	}
	var in struct {
		Config string `json:"config"`
		Mode   string `json:"mode"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "无法读取请求：" + err.Error()})
		return
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请求格式不正确"})
		return
	}
	if err := validateCandidateConfig(in.Config); err != nil {
		// The service validates before it acts. A window that sends a broken
		// configuration gets it refused here rather than a core that fails to start
		// with no explanation.
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": "配置没有通过校验：" + err.Error()})
		return
	}
	if err := h.app.serviceStartCore([]byte(in.Config), TunMode(in.Mode)); err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "pid": h.app.core.Pid()})
}

func (h *serviceHandler) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "需要 POST"})
		return
	}
	h.app.core.Stop()
	h.app.saveServiceState(&serviceState{ServicePID: os.Getpid()})
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (h *serviceHandler) handleState(w http.ResponseWriter, r *http.Request) {
	st := h.app.loadServiceState()
	if st == nil {
		st = &serviceState{ServicePID: os.Getpid()}
	}
	// Report the live pid rather than the recorded one: the record can be stale,
	// and the question being asked is what is running now.
	st.CorePID = h.app.core.Pid()
	writeJSON(w, 200, st)
}

// serviceStartCore writes the configuration and starts the core, as the owner.
//
// Writing and starting happen together and in one place because they have to agree:
// a core started against a configuration the service did not write is the state
// that produced "the adapter never appears" with no stated reason.
func (a *App) serviceStartCore(cfg []byte, mode TunMode) error {
	if err := os.WriteFile(a.configPath, cfg, 0o644); err != nil {
		return fmt.Errorf("无法写入配置：%v", err)
	}
	a.core.Stop()
	time.Sleep(500 * time.Millisecond)
	if err := a.core.Start(); err != nil {
		return fmt.Errorf("内核未能启动：%v", err)
	}
	a.saveServiceState(&serviceState{
		CorePID:       a.core.Pid(),
		CoreStartedAt: time.Now().Format(time.RFC3339Nano),
		ConfigDigest:  digestOf(cfg),
		Mode:          string(mode),
		ServicePID:    os.Getpid(),
	})
	return nil
}

// RunService is the service process's main loop.
//
// It serves the authenticated channel and holds the core. It does not open a
// window, show a tray icon or serve the interface: it exists to own one thing, and
// everything else would be surface area on the process with the most rights.
func RunService(rootDir, dataDir, secret string) error {
	app, err := NewApp(rootDir)
	if err != nil {
		return err
	}
	if dataDir != "" {
		app.rebindDirs(dataDir)
	}
	if secret == "" {
		secret = app.secret
	}
	app.sysproxy.SetReadOnly(true)
	app.core.SetNoOrphanCleanup(true)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", servicePort))
	if err != nil {
		return fmt.Errorf("服务端口 %d 无法监听：%v", servicePort, err)
	}
	h := &serviceHandler{app: app, secret: secret}
	srv := &http.Server{
		Handler:           h.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Announce the state before serving, so a window that starts at the same moment
	// does not see a listening port with no state behind it.
	if st := app.loadServiceState(); st == nil {
		app.saveServiceState(&serviceState{ServicePID: os.Getpid()})
	}
	Log("service: listening on %s (pid %d, data %s)", serviceBaseURL(), os.Getpid(), app.dataDir)
	return srv.Serve(ln)
}

// secretEqual compares two secrets in constant time.
//
// A timing side channel on a loopback service is a small risk, but the comparison
// costs nothing extra and the alternative - a plain string compare that returns on
// the first differing byte - is the kind of detail that is hard to justify leaving
// in a file whose whole subject is authentication.
func secretEqual(got, want string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// serviceControl runs an sc command and returns its combined output.
func serviceControl(args ...string) (string, error) {
	return HiddenCommand("sc", args...)
}

// ---- installing the service ------------------------------------------------

// installService registers the service with Windows. It needs elevation, and it is
// the one authorisation the design depends on.
//
// The requirement it satisfies is "authorise once, then it just works": after this
// succeeds, starting the tunnel is a request to a running service rather than a
// new elevation.
func (a *App) installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法确定程序路径：%v", err)
	}
	binPath := fmt.Sprintf(`"%s" -service -root "%s" -datadir "%s"`,
		exe, a.rootDir, a.dataDir)

	// auto start means the tunnel survives a reboot without the user having to
	// remember anything, which is the point of a resident service.
	if out, err := serviceControl("create", serviceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "Zenith 网络服务"); err != nil {
		return fmt.Errorf("注册服务失败：%v（%s）", err, strings.TrimSpace(out))
	}
	if out, err := serviceControl("description", serviceName,
		"持有并管理 Zenith 的代理内核，使启用 TUN 只需要一次授权"); err != nil {
		// Not fatal: a missing description does not stop the service working.
		Log("could not set the service description: %v (%s)", err, strings.TrimSpace(out), "WARN")
	}
	// If it fails to start, say why rather than reporting a successful install of
	// something that is not running.
	if out, err := serviceControl("start", serviceName); err != nil {
		return fmt.Errorf("服务已注册但未能启动：%v（%s）", err, strings.TrimSpace(out))
	}
	// Starting is asynchronous. Waiting for the endpoint is what makes the next
	// step's decision - service or local core - correct rather than a race.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if serviceReachable() {
			Log("service installed and answering on %s", serviceBaseURL())
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("服务已注册并启动，但 %s 没有回应。请查看 logs 目录下的日志", serviceBaseURL())
}

// uninstallService removes the service. Used by the offline repair path, so a user
// whose machine is in a bad state can still get it back.
func (a *App) uninstallService() error {
	if serviceReachable() {
		_ = a.serviceStopRequest()
	}
	if _, err := serviceControl("stop", serviceName); err != nil {
		Log("service stop reported: %v", err)
	}
	if out, err := serviceControl("delete", serviceName); err != nil {
		return fmt.Errorf("删除服务失败：%v（%s）", err, strings.TrimSpace(out))
	}
	return nil
}

// ---- elevation for the service ---------------------------------------------

// ensureService makes the service exist and answer, requesting the one
// authorisation if it is not there yet.
//
// The order is deliberate: check whether it is already running before asking for
// anything. An installed service that is simply stopped needs no prompt, and
// prompting for something that does not need it is how users learn to click yes
// without reading.
func (a *App) ensureService() error {
	if serviceReachable() {
		return nil
	}
	if serviceInstalled() {
		// Registered but not answering. Try to start it without elevation first;
		// Windows will refuse if the caller lacks the right, and only then do we ask.
		if _, err := serviceControl("start", serviceName); err == nil {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				if serviceReachable() {
					return nil
				}
				time.Sleep(300 * time.Millisecond)
			}
		}
	}

	// Not installed, or installed and unwilling. The elevated helper installs it.
	Log("service: not available; requesting the one authorisation to install it")
	pid, err := elevateRequest([]string{
		"-install-service",
		"-root", a.rootDir,
		"-datadir", a.dataDir,
		"-handover-id", newHandoverID(),
		"-requester-pid", fmt.Sprint(os.Getpid()),
	})
	if err != nil {
		return err
	}
	_ = pid
	// Wait for the service to answer, reporting the helper's own verdict if it
	// exits first - the same rule as the activation handover: never infer success
	// from our own memory of what we asked for.
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if serviceReachable() {
			return nil
		}
		if pid > 0 && !helperStillRunning(pid) {
			// Give a moment for the endpoint to come up after the helper exits.
			time.Sleep(1200 * time.Millisecond)
			if serviceReachable() {
				return nil
			}
			return fmt.Errorf("安装服务的授权进程已经退出，但服务没有回应（%s）。"+
				"这通常意味着注册被拒绝（需要管理员权限），或该端口已被占用。"+
				"可以查看 logs 目录下的日志了解原因", serviceBaseURL())
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("等待服务启动超过 45 秒仍没有回应（%s）", serviceBaseURL())
}
