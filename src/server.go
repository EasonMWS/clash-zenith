package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Local HTTP server: serves the UI and the JSON API the UI talks to.
// Bound to 127.0.0.1 only, so nothing is exposed to the network.
// ---------------------------------------------------------------------------

type Server struct {
	app     *App
	uiPort  int
	mux     *http.ServeMux
	webRoot string
	// token is a per-launch secret required by every API route.
	//
	// The API binds to loopback, but loopback is not an authentication boundary:
	// any other process running as this user, and any web page the browser is
	// persuaded to load, can reach it. Without a token those callers could read
	// the subscription URL and the generated config - which contains the core
	// secret, node UUIDs and WebSocket paths - or switch nodes and shut the app
	// down. The token is generated per launch, never written to disk, and handed
	// to the UI by rewriting the page it is served.
	token string
}

func NewServer(app *App, webRoot string, uiPort int) *Server {
	s := &Server{
		app:     app,
		uiPort:  uiPort,
		mux:     http.NewServeMux(),
		webRoot: webRoot,
		token:   randomToken(),
	}
	s.routes()
	return s
}

// randomToken returns a 256-bit URL-safe secret. The previous core secret was
// derived from a timestamp, which is guessable and has a tiny space; this does
// not repeat that mistake.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A token we cannot generate is worse than no token at all, because it
		// would be predictable. Fall back to something still unguessable enough
		// to stop a local process, and say so.
		Log("could not read cryptographic randomness for the API token: %v", err, "ERR")
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/status", s.wrap(s.handleStatus))
	s.mux.HandleFunc("/api/nodes", s.wrap(s.handleNodes))
	s.mux.HandleFunc("/api/switch", s.wrap(s.handleSwitch))
	s.mux.HandleFunc("/api/mode", s.wrap(s.handleMode))
	s.mux.HandleFunc("/api/optimize", s.wrap(s.handleOptimize))
	s.mux.HandleFunc("/api/optimize/cancel", s.wrap(s.handleOptimizeCancel))
	s.mux.HandleFunc("/api/test-delay", s.wrap(s.handleTestDelay))
	s.mux.HandleFunc("/api/subscriptions", s.wrap(s.handleSubscriptions))
	s.mux.HandleFunc("/api/subscriptions/add", s.wrap(s.handleSubscriptionAdd))
	s.mux.HandleFunc("/api/subscriptions/update", s.wrap(s.handleSubscriptionUpdate))
	s.mux.HandleFunc("/api/subscriptions/remove", s.wrap(s.handleSubscriptionRemove))
	s.mux.HandleFunc("/api/subscriptions/select", s.wrap(s.handleSubscriptionSelect))
	s.mux.HandleFunc("/api/settings", s.wrap(s.handleSettings))
	s.mux.HandleFunc("/api/system-proxy", s.wrap(s.handleSystemProxy))
	s.mux.HandleFunc("/api/rules", s.wrap(s.handleRules))
	s.mux.HandleFunc("/api/logs", s.wrap(s.handleLogs))
	s.mux.HandleFunc("/api/core/restart", s.wrap(s.handleCoreRestart))
	s.mux.HandleFunc("/api/about", s.wrap(s.handleAbout))
	// TUN lifecycle. One route for the product action, plus the read-only checks
	// the interface needs to explain itself.
	s.mux.HandleFunc("/api/tun/check", s.wrap(s.handleTunCheck))
	s.mux.HandleFunc("/api/tun/enable", s.wrap(s.handleTunEnable))
	s.mux.HandleFunc("/api/tun/disable", s.wrap(s.handleTunDisable))
	s.mux.HandleFunc("/api/tun/repair", s.wrap(s.handleTunRepair))
	s.mux.HandleFunc("/api/tun/uninstall", s.wrap(s.handleTunUninstall))
	s.mux.HandleFunc("/api/quit", s.wrap(s.handleQuit))
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) wrap(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				Log("panic in %s: %v", r.URL.Path, rec, "ERR")
				writeJSON(w, 500, map[string]interface{}{"ok": false, "error": fmt.Sprint(rec)})
			}
		}()
		w.Header().Set("Cache-Control", "no-store")

		// The Host header must be a loopback literal. A page on the internet can
		// point a name it controls at 127.0.0.1, so a request that arrives with a
		// foreign Host is either a DNS-rebinding attempt or a mistake.
		if !isLoopbackHost(r.Host) {
			writeJSON(w, 403, map[string]interface{}{
				"ok": false, "error": "只接受来自本机的请求（Host 检查未通过）",
			})
			return
		}
		// A browser sends Origin on cross-origin writes. Anything that is not our
		// own page is refused outright, so a malicious site cannot drive the API
		// even with the token somehow known.
		if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(o) {
			writeJSON(w, 403, map[string]interface{}{
				"ok": false, "error": "跨源请求已被拒绝",
			})
			return
		}
		// Every route is authenticated, reads included: the read endpoints are
		// where the subscription URL and the config preview come from.
		if !s.tokenOK(r) {
			writeJSON(w, 401, map[string]interface{}{
				"ok": false, "error": "缺少或错误的访问令牌；请通过 Zenith 打开的界面操作",
			})
			return
		}

		// Writes must actually look like writes. Without this a form or an image
		// tag is enough to trigger a state change, because those cannot set a
		// JSON content type.
		if r.Method == http.MethodPost && !strings.HasPrefix(
			strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			writeJSON(w, 415, map[string]interface{}{
				"ok": false, "error": "写接口只接受 application/json",
			})
			return
		}
		h(w, r)
	}
}

// tokenOK accepts the token from the header the UI sends, or from the query
// string, which is how the page learns it in the first place.
func (s *Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-Zenith-Token")
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	if got == "" || len(got) != len(s.token) {
		return false
	}
	// constant time, so a local attacker cannot recover the token byte by byte
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *Server) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return isLoopbackHost(u.Host)
}

// isLoopbackHost reports whether a Host or host:port value refers to this
// machine. Only literal loopback addresses are accepted, never a name that could
// be pointed at 127.0.0.1 from outside.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ---- TUN ------------------------------------------------------------------

// handleTunCheck reports what the machine looks like without changing anything, so
// the interface can explain a refusal before the user is asked for a password.
func (s *Server) handleTunCheck(w http.ResponseWriter, r *http.Request) {
	env := s.app.checkTunEnvironment()
	writeJSON(w, 200, map[string]interface{}{
		"ok":     true,
		"env":    env,
		"run":    s.app.TunRunState(),
		"mode":   s.app.store.Settings().TunMode,
		"labels": tunModeLabels(),
	})
}

func tunModeLabels() map[string]string {
	return map[string]string{
		string(TunCompat):  TunCompat.Label(),
		string(TunPrivacy): TunPrivacy.Label(),
	}
}

// handleTunEnable is the single product action. Everything behind it - checking,
// authorisation, component placement, adapter, routes, verification - runs from
// this one call.
func (s *Server) handleTunEnable(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	mode := TunMode(asString(body["mode"]))
	if mode == "" {
		mode = TunCompat
	}
	if !mode.Valid() || mode == TunOff {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "未知的 TUN 模式"})
		return
	}
	if err := s.app.EnableTun(mode); err != nil {
		writeJSON(w, 409, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "started": true, "run": s.app.TunRunState(),
	})
}

func (s *Server) handleTunDisable(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	// Releasing privacy protection is a decision, so it has to be stated.
	release := body["releasePrivacy"] == true
	if err := s.app.DisableTun(release); err != nil {
		writeJSON(w, 409, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (s *Server) handleTunRepair(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	env, err := s.app.RepairTun(body["release"] == true)
	if err != nil {
		writeJSON(w, 409, map[string]interface{}{"ok": false, "error": err.Error(), "env": env})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "env": env})
}

func (s *Server) handleTunUninstall(w http.ResponseWriter, r *http.Request) {
	if err := s.app.UninstallTun(); err != nil {
		writeJSON(w, 409, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

// ---- end TUN --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request) map[string]interface{} {
	out := map[string]interface{}{}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/")
	if rel == "" {
		rel = "index.html"
	}
	clean := strings.ReplaceAll(rel, "..", "")
	full := s.webRoot + string(os.PathSeparator) + strings.ReplaceAll(clean, "/", string(os.PathSeparator))
	data, err := os.ReadFile(full)
	if err != nil {
		// SPA fallback: unknown paths render the app shell
		data, err = os.ReadFile(s.webRoot + string(os.PathSeparator) + "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		clean = "index.html"
	}
	ctype := "text/plain; charset=utf-8"
	switch {
	case strings.HasSuffix(clean, ".html"):
		ctype = "text/html; charset=utf-8"
	case strings.HasSuffix(clean, ".css"):
		ctype = "text/css; charset=utf-8"
	case strings.HasSuffix(clean, ".js"):
		ctype = "application/javascript; charset=utf-8"
	case strings.HasSuffix(clean, ".svg"):
		ctype = "image/svg+xml"
	case strings.HasSuffix(clean, ".png"):
		ctype = "image/png"
	case strings.HasSuffix(clean, ".ico"):
		ctype = "image/x-icon"
	case strings.HasSuffix(clean, ".json"):
		ctype = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	// Hand the API token to our own page. It is inserted only into the HTML shell
	// served from loopback, so a script on any other origin has no way to read it;
	// together with the Host and Origin checks that is what keeps the API ours.
	// A strict CSP goes with it: the UI needs no remote origins at all.
	if strings.HasSuffix(clean, ".html") {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		data = injectToken(data, s.token)
	}
	_, _ = w.Write(data)
}

// injectToken puts the API token into the page as a meta tag, replacing the
// placeholder the checked-in HTML carries. Doing it at serve time means the
// token is never stored in the repository and changes on every launch.
func injectToken(page []byte, token string) []byte {
	const marker = `<meta name="zenith-token" content="">`
	if !bytes.Contains(page, []byte(marker)) {
		return page
	}
	repl := []byte(`<meta name="zenith-token" content="` + token + `">`)
	return bytes.Replace(page, []byte(marker), repl, 1)
}

// ---- status ---------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Status())
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	st := s.app.Status()
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "nodes": st["nodes"], "current": st["current"],
		"autoPick": st["autoPick"], "isOptimized": st["isOptimized"],
	})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	name, _ := body["name"].(string)
	if name == "" {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少节点名"})
		return
	}
	if err := s.app.Switch(name); err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "current": s.app.store.Snapshot().Current})
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	mode, _ := body["mode"].(string)
	if mode == "" {
		if auto, ok := body["autoOptimize"].(bool); ok {
			_, _ = s.app.store.UpdateSettings(map[string]interface{}{"autoOptimize": auto})
			writeJSON(w, 200, map[string]interface{}{"ok": true, "autoOptimize": auto})
			return
		}
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少 mode"})
		return
	}
	if err := s.app.SetMode(mode); err != nil {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "mode": mode})
}

func (s *Server) handleOptimize(w http.ResponseWriter, r *http.Request) {
	started := s.app.StartOptimize()
	writeJSON(w, 200, map[string]interface{}{"ok": true, "started": started})
}

func (s *Server) handleOptimizeCancel(w http.ResponseWriter, r *http.Request) {
	s.app.opt.Cancel()
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (s *Server) handleTestDelay(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	name, _ := body["name"].(string)
	if name == "" {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少节点名"})
		return
	}
	d, err := s.app.core.Delay(name, 5000, "")
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "delay": 0, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "delay": d})
}

// ---- subscriptions --------------------------------------------------------

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	st := s.app.store.Snapshot()
	writeJSON(w, 200, map[string]interface{}{
		"ok":            true,
		"subscriptions": st.Subscriptions,
		"selected":      st.SelectedSub,
		"lastFetch":     st.Settings.LastProfile,
	})
}

func (s *Server) handleSubscriptionAdd(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	rawURL, _ := body["url"].(string)
	name, _ := body["name"].(string)
	if strings.TrimSpace(rawURL) == "" {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "请填写订阅地址"})
		return
	}
	sub, err := s.app.AddSubscription(rawURL, name)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "subscription": sub})
}

func (s *Server) handleSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	id, _ := body["id"].(string)
	n, err := s.app.UpdateSubscription(id)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "nodes": n})
}

func (s *Server) handleSubscriptionRemove(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	id, _ := body["id"].(string)
	if err := s.app.RemoveSubscription(id); err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (s *Server) handleSubscriptionSelect(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	id, _ := body["id"].(string)
	n, err := s.app.SelectSubscription(id)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "nodes": n})
}

// ---- settings / rules -----------------------------------------------------

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]interface{}{"ok": true, "settings": s.app.store.Settings()})
		return
	}
	body := readBody(r)
	next, err := s.app.ApplySettings(body)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "settings": next})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		st := s.app.store.Settings()
		writeJSON(w, 200, map[string]interface{}{
			"ok":       true,
			"rules":    st.CustomRules,
			"targets":  RuleTargets,
			"blockAds": st.BlockAds,
			"directCN": st.DirectCNDomains,
			// inverted on purpose: true means the game platforms go direct
			"gamePlatformDirectOff": st.GamePlatformDirectOff,
			"currentCfg":            s.app.CurrentConfigPreview(),
		})
		return
	}
	body := readBody(r)
	rulesRaw, ok := body["rules"].([]interface{})
	if !ok {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少 rules"})
		return
	}
	var rules []string
	for _, rv := range rulesRaw {
		line := strings.TrimSpace(fmt.Sprint(rv))
		if line == "" {
			continue
		}
		if err := ValidateRule(line); err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error() + " → " + line})
			return
		}
		rules = append(rules, line)
	}
	if _, err := s.app.ApplySettings(map[string]interface{}{"customRules": rules}); err != nil {
		writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "rules": rules})
}

// ---- misc -----------------------------------------------------------------

func (s *Server) handleSystemProxy(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	want, ok := body["enabled"].(bool)
	if !ok {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少 enabled"})
		return
	}
	st := s.app.store.Settings()
	if want {
		if _, err := s.app.sysproxy.Enable(st.MixedPort, st.ProxyBypass, false); err != nil {
			writeJSON(w, 200, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
	} else {
		s.app.sysproxy.Disable()
	}
	_, _ = s.app.store.UpdateSettings(map[string]interface{}{"systemProxy": want})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "state": s.app.sysproxy.Status()})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lines := 300
	if v, err := strconv.Atoi(q.Get("lines")); err == nil && v > 0 && v < 5000 {
		lines = v
	}
	which := q.Get("which")
	text := ""
	if which == "core" {
		raw, _ := os.ReadFile(s.app.logDir + string(os.PathSeparator) + "engine.log")
		text = tailString(string(raw), lines)
	} else {
		text = TailLog(lines)
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "which": which, "text": text})
}

func tailString(s string, lines int) string {
	parts := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func (s *Server) handleCoreRestart(w http.ResponseWriter, r *http.Request) {
	ok := s.app.core.Ensure()
	writeJSON(w, 200, map[string]interface{}{"ok": ok})
}

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"ok":      true,
		"name":    AppName,
		"version": AppVersion,
		"go":      goVersion(),
		"core":    s.app.core.Version(),
		"license": "GPL-3.0",
		"repo":    "https://github.com/EasonMWS/clash-zenith",
		"dataDir": s.app.dataDir,
		"ports": map[string]int{
			"mixed":   s.app.store.Settings().MixedPort,
			"api":     s.app.store.Settings().APIPort,
			"ui":      s.app.store.Settings().UIPort,
			"control": s.app.store.Settings().ControlPort,
		},
	})
}

func (s *Server) handleQuit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"ok": true})
	go func() {
		time.Sleep(300 * time.Millisecond)
		s.app.Shutdown()
	}()
}

// Listen starts the UI server and returns once it is bound.
func (s *Server) Listen() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.uiPort)
	Log("binding UI server on %s", addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		Log("could not bind %s: %v", addr, err, "ERR")
		return fmt.Errorf("界面端口 %d 被占用：%w", s.uiPort, err)
	}
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			Log("ui server stopped: %v", err, "WARN")
		}
	}()
	Log("UI ready at http://%s", addr)
	return nil
}

// sortedNames is a small helper used by the UI payloads.
func sortedNames(m map[string]*ProxyStatus) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
