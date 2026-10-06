package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
}

func NewServer(app *App, webRoot string, uiPort int) *Server {
	s := &Server{app: app, uiPort: uiPort, mux: http.NewServeMux(), webRoot: webRoot}
	s.routes()
	return s
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
		h(w, r)
	}
}

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
	_, _ = w.Write(data)
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
			"ok":         true,
			"rules":      st.CustomRules,
			"targets":    RuleTargets,
			"blockAds":   st.BlockAds,
			"directCN":   st.DirectCNDomains,
			"currentCfg": s.app.CurrentConfigPreview(),
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
		if err := s.app.sysproxy.Enable(st.MixedPort, st.ProxyBypass, false); err != nil {
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
		"repo":    "https://github.com/zenith-app/zenith",
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
