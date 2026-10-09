package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Core: owns the mihomo process and talks to its REST API.
//
// Everything the user does in the UI goes through the API so the process never
// has to be restarted. Reloading the config file is also in place (PUT /configs).
// ---------------------------------------------------------------------------

type Core struct {
	mu         sync.Mutex
	exePath    string
	dataDir    string
	configPath string
	secret     string
	apiPort    int
	proc       *exec.Cmd
	startedAt  time.Time
	logFile    *os.File
	// lastErr records why the most recent start failed, so a refused TUN enable
	// can report the core's own words instead of guessing.
	lastErr string
}

func NewCore(exePath, dataDir, configPath, secret string, apiPort int) *Core {
	return &Core{
		exePath:    exePath,
		dataDir:    dataDir,
		configPath: configPath,
		secret:     secret,
		apiPort:    apiPort,
	}
}

// ---- REST helpers ---------------------------------------------------------

func (c *Core) api(method, path string, body interface{}, timeout time.Duration) (map[string]interface{}, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", c.apiPort, path), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if len(data) == 0 {
		return map[string]interface{}{}, nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]interface{}{"raw": string(data)}, nil
	}
	return out, nil
}

// LastError returns the most recent core startup failure, so a failed enable can
// say what the core objected to instead of just "the adapter did not appear".
func (c *Core) LastError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

func (c *Core) IsUp() bool {
	_, err := c.api(http.MethodGet, "/version", nil, 1500*time.Millisecond)
	return err == nil
}

func (c *Core) Version() string {
	v, err := c.api(http.MethodGet, "/version", nil, 2*time.Second)
	if err != nil {
		return ""
	}
	if s, ok := v["version"].(string); ok {
		return s
	}
	return ""
}

// ---- process lifecycle ----------------------------------------------------

// Start launches the core if it is not already answering.
func (c *Core) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.IsUp() {
		return nil
	}
	if _, err := os.Stat(c.exePath); err != nil {
		return fmt.Errorf("找不到内核文件 %s", c.exePath)
	}
	// a previous run killed mid-flight can leave a core holding our ports
	c.killOrphansLocked()

	if c.logFile == nil {
		execLog := filepath.Join(c.dataDir, "..", "logs", "engine.log")
		// Rotate before handing the file to the child. The core writes straight to
		// this descriptor, so there is no write hook to rotate on, and the core's
		// log is the one that actually grows: at info level it writes a line per
		// connection. Rotating here means the cap holds across restarts, which the
		// watchdog makes regular.
		rotateIfNeeded(execLog)
		f, err := os.OpenFile(execLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			c.logFile = f
		}
	}

	cmd := exec.Command(c.exePath, "-d", c.dataDir, "-f", c.configPath)
	cmd.Dir = c.dataDir
	if c.logFile != nil {
		cmd.Stdout = c.logFile
		cmd.Stderr = c.logFile
	}
	// no console window on Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		return err
	}
	c.proc = cmd
	c.startedAt = time.Now()

	// The first run of a fresh install has to unpack geodata (tens of MB), which
	// can take a minute on a slow link, so the deadline is generous.
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if c.IsUp() {
			Log("core is up (pid %d, %s)", cmd.Process.Pid, c.Version())
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("内核启动后立即退出，请查看 logs/engine.log")
		}
	}
	return fmt.Errorf("内核未在预期时间内响应，请查看 logs/engine.log")
}

func (c *Core) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

func (c *Core) stopLocked() {
	if c.proc != nil && c.proc.Process != nil {
		Log("stopping core pid %d", c.proc.Process.Pid)
		_ = c.proc.Process.Kill()
		_, _ = c.proc.Process.Wait()
	}
	c.proc = nil
	if n := c.killOrphansLocked(); n > 0 {
		Log("cleaned up %d lingering core process(es)", n)
	}
}

// Ensure restarts the core if it stopped answering.
func (c *Core) Ensure() bool {
	if c.IsUp() {
		return true
	}
	Log("core is not responding, restarting", "WARN")
	c.Stop()
	return c.Start() == nil
}

func (c *Core) Pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc != nil && c.proc.Process != nil {
		return c.proc.Process.Pid
	}
	return 0
}

func (c *Core) Uptime() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.startedAt.IsZero() {
		return 0
	}
	return int(time.Since(c.startedAt).Seconds())
}

// Reload asks mihomo to re-read config.yaml. This is the whole reason Zenith
// never has to restart anything when nodes change.
func (c *Core) Reload() error {
	body := map[string]interface{}{"path": filepath.ToSlash(c.configPath), "force": true}
	if _, err := c.api(http.MethodPut, "/configs?force=true", body, 20*time.Second); err != nil {
		if _, err2 := c.api(http.MethodPut, "/configs", map[string]interface{}{
			"path": filepath.ToSlash(c.configPath),
		}, 20*time.Second); err2 != nil {
			return err
		}
	}
	Log("config reloaded in place (no restart)")
	return nil
}

// LiveConfig asks the core what it is actually running.
//
// It exists because a successful reload call is not proof that the core took the
// new configuration. This reads the running state, so activation can be verified
// rather than assumed - which is the difference between "we asked it to reload"
// and "it is running what we intended".
func (c *Core) LiveConfig() (map[string]interface{}, error) {
	return c.api(http.MethodGet, "/configs", nil, 8*time.Second)
}

// SetMode switches rule/global/direct at runtime.
func (c *Core) SetMode(mode string) error {
	_, err := c.api(http.MethodPatch, "/configs", map[string]interface{}{"mode": mode}, 8*time.Second)
	return err
}

// ---- proxies --------------------------------------------------------------

type ProxyStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Now     string `json:"now"`
	Delay   int    `json:"delay"`
	History []struct {
		Time  string `json:"time"`
		Delay int    `json:"delay"`
	} `json:"history"`
	Alive bool `json:"alive"`
}

func (c *Core) Proxies() (map[string]*ProxyStatus, error) {
	data, err := c.api(http.MethodGet, "/proxies", nil, 10*time.Second)
	if err != nil {
		return nil, err
	}
	raw, ok := data["proxies"].(map[string]interface{})
	if !ok {
		return map[string]*ProxyStatus{}, nil
	}
	out := make(map[string]*ProxyStatus, len(raw))
	for name, v := range raw {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		ps := &ProxyStatus{
			Name: name,
			Type: asString(m["type"]),
			Now:  asString(m["now"]),
		}
		if hist, ok := m["history"].([]interface{}); ok && len(hist) > 0 {
			for _, h := range hist {
				hm, ok := h.(map[string]interface{})
				if !ok {
					continue
				}
				var e struct {
					Time  string `json:"time"`
					Delay int    `json:"delay"`
				}
				e.Time = asString(hm["time"])
				e.Delay = asInt(hm["delay"])
				ps.History = append(ps.History, e)
			}
			ps.Delay = ps.History[len(ps.History)-1].Delay
			ps.Alive = ps.Delay > 0
		}
		out[name] = ps
	}
	return out, nil
}

// Select pins a node in a group. Instant, no restart.
func (c *Core) Select(group, name string) error {
	_, err := c.api(http.MethodPut, "/proxies/"+urlPathEscape(group),
		map[string]interface{}{"name": name}, 8*time.Second)
	if err == nil {
		Log("switched %s -> %s", group, name)
	}
	return err
}

// Delay measures one node through the core.
func (c *Core) Delay(name string, timeoutMS int, testURL string) (int, error) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	path := fmt.Sprintf("/proxies/%s/delay?timeout=%d&url=%s",
		urlPathEscape(name), timeoutMS, urlQueryEscape(testURL))
	data, err := c.api(http.MethodGet, path, nil, time.Duration(timeoutMS)*time.Millisecond+6*time.Second)
	if err != nil {
		return 0, err
	}
	return asInt(data["delay"]), nil
}

type Connections struct {
	DownloadTotal int64 `json:"downloadTotal"`
	UploadTotal   int64 `json:"uploadTotal"`
	Count         int   `json:"count"`
}

func (c *Core) Connections() Connections {
	data, err := c.api(http.MethodGet, "/connections", nil, 6*time.Second)
	if err != nil {
		return Connections{}
	}
	conns, _ := data["connections"].([]interface{})
	return Connections{
		DownloadTotal: int64(asInt(data["downloadTotal"])),
		UploadTotal:   int64(asInt(data["uploadTotal"])),
		Count:         len(conns),
	}
}

// CloseConnections drops all live connections, used after switching nodes so a
// bad route is not kept alive by an existing socket.
func (c *Core) CloseConnections() {
	_, _ = c.api(http.MethodDelete, "/connections", nil, 6*time.Second)
}

// ---- orphan cleanup -------------------------------------------------------

// killOrphansLocked terminates mihomo processes that belong to us but are not
// the one we are tracking. Uses PowerShell's CIM query because wmic no longer
// ships with current Windows builds.
func (c *Core) killOrphansLocked() int {
	keep := 0
	if c.proc != nil && c.proc.Process != nil {
		keep = c.proc.Process.Pid
	}
	script := `Get-CimInstance Win32_Process -Filter "Name='mihomo.exe'" | ` +
		`Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress`
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return 0
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return 0
	}
	var items []struct {
		ProcessId   int
		CommandLine string
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		var one struct {
			ProcessId   int
			CommandLine string
		}
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return 0
		}
		items = []struct {
			ProcessId   int
			CommandLine string
		}{one}
	}
	killed := 0
	for _, it := range items {
		if it.ProcessId == 0 || it.ProcessId == keep {
			continue
		}
		cmd := strings.ToLower(it.CommandLine)
		if !strings.Contains(cmd, "zenith") && !strings.Contains(cmd, strings.ToLower(filepath.ToSlash(c.dataDir))) {
			continue
		}
		_ = exec.Command("taskkill", "/PID", fmt.Sprint(it.ProcessId), "/F").Run()
		killed++
	}
	return killed
}

// ---- port helpers ---------------------------------------------------------

// IsPortListening reports whether something already LISTENING on a port.
//
// Ownership decisions use the real listener table, not a connect probe: a
// socket in TIME_WAIT still accepts connections, which used to make the chosen
// port number drift upwards on every run (7899 -> 7922 -> 7942 ...).
// This is a plain bind test: a failed bind means somebody holds the port.
func IsPortListening(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func ListeningPids(port int) []int {
	out, err := HiddenCommand("netstat", "-ano", "-p", "TCP")
	if err != nil {
		return nil
	}
	var pids []int
	suffix := fmt.Sprintf(":%d", port)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		if !strings.HasSuffix(fields[1], suffix) || !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		var pid int
		fmt.Sscanf(fields[4], "%d", &pid)
		if pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

func ProcessName(pid int) string {
	out, err := HiddenCommand("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if strings.HasPrefix(line, `"`) {
		parts := strings.SplitN(line, `","`, 2)
		return strings.ToLower(strings.Trim(parts[0], `"`))
	}
	return ""
}

func urlPathEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "?", "%3F"), "#", "%23")
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, ":", "%3A"), "/", "%2F"), "?", "%3F")
}
