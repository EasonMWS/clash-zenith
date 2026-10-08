package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

var (
	logMu   sync.Mutex
	logPath string
)

func InitLog(dir string) {
	_ = os.MkdirAll(dir, 0o755)
	logPath = filepath.Join(dir, "zenith.log")
}

// Log writes a line to the log file and to stdout.
//
// If the last argument is one of INFO/WARN/ERR/OK it is used as the level and
// everything before it is the (optionally formatted) message. Everything else
// is passed straight to Sprintf, so both plain and formatted calls work.
func Log(format string, args ...interface{}) {
	level := ""
	if n := len(args); n > 0 {
		if s, ok := args[n-1].(string); ok && isLevel(s) {
			level = s
			args = args[:n-1]
		}
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	if level != "" {
		line = fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, msg)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			_, _ = f.WriteString(line)
			_ = f.Close()
		}
	}
	fmt.Print(line)
}

func isLevel(s string) bool {
	switch s {
	case "INFO", "WARN", "ERR", "OK":
		return true
	}
	return false
}

func TailLog(lines int) string {
	if logPath == "" {
		return ""
	}
	f, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	var all []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		all = append(all, sc.Text())
	}
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// ---------------------------------------------------------------------------
// Edge optimiser
//
// Cloudflare is anycast: the same edge IP can land in a different data centre
// from one hour to the next, and the provider's own domain resolves to whatever
// the local DNS hands out. So Zenith keeps a pool of candidate edge addresses,
// fires a REAL WebSocket upgrade at each one (only HTTP 101 proves the edge can
// actually tunnel the node's traffic), ranks them by median time, and rewrites
// the node list with the winners. The core then hot reloads - no restart.
// ---------------------------------------------------------------------------

type edgeResult struct {
	IP     string  `json:"ip"`
	Median float64 `json:"median"`
	Score  float64 `json:"score"`
	OK     int     `json:"ok"`
	Rounds int     `json:"rounds"`
}

type OptimizeProgress struct {
	Stage string `json:"stage"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Text  string `json:"text"`
}

// OptimizeSummary explains what the last scan actually did, so the UI can be
// honest about a subscription that mixes optimisable relays with direct nodes.
type OptimizeSummary struct {
	Templates     int      `json:"templates"`     // distinct WebSocket tunnels found
	Optimizable   int      `json:"optimizable"`   // nodes those tunnels can represent
	Unsupported   int      `json:"unsupported"`   // nodes优选 cannot touch (direct nodes)
	FailedTunnels []string `json:"failedTunnels"` // tunnels that yielded nothing
	Nodes         int      `json:"nodes"`         // optimised nodes produced
}

type Optimizer struct {
	dataDir     string
	mu          sync.Mutex
	running     bool
	prog        OptimizeProgress
	cancel      chan struct{}
	lastSummary OptimizeSummary
}

func (o *Optimizer) LastSummary() OptimizeSummary {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastSummary
}

func NewOptimizer(dataDir string) *Optimizer {
	return &Optimizer{dataDir: dataDir, prog: OptimizeProgress{Stage: "idle"}}
}

func (o *Optimizer) Progress() OptimizeProgress {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.prog
}

func (o *Optimizer) Running() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.running
}

func (o *Optimizer) setProgress(stage string, done, total int, text string) {
	o.mu.Lock()
	o.prog = OptimizeProgress{Stage: stage, Done: done, Total: total, Text: text}
	o.mu.Unlock()
}

// candidateFile returns the path of the candidate pool, seeding it on first run.
func (o *Optimizer) candidateFile() string {
	return filepath.Join(o.dataDir, "candidates.txt")
}

func (o *Optimizer) Candidates() []string {
	path := o.candidateFile()
	if _, err := os.Stat(path); err != nil {
		_ = os.WriteFile(path, []byte(seedCandidates), 0o644)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !looksLikeIPv4(line) || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func (o *Optimizer) learnCandidates(ips []string) int {
	known := map[string]bool{}
	for _, c := range o.Candidates() {
		known[c] = true
	}
	var fresh []string
	for _, ip := range ips {
		if !known[ip] {
			fresh = append(fresh, ip)
			known[ip] = true
		}
	}
	if len(fresh) == 0 {
		return 0
	}
	f, err := os.OpenFile(o.candidateFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0
	}
	defer f.Close()
	_, _ = f.WriteString("\n" + strings.Join(fresh, "\n") + "\n")
	return len(fresh)
}

// probeWS performs one WebSocket upgrade attempt against an edge IP and returns
// the time to the 101 response.
func probeWS(ip, sni, path, host string, timeout time.Duration) (time.Duration, bool) {
	return probeWSVerbose(ip, sni, path, host, timeout, nil)
}

// probeHTTPS fetches a URL through the tunnel, end to end.
//
// Verifying the WebSocket upgrade is not enough on its own. A Cloudflare edge
// has been observed completing the upgrade happily and then silently dropping
// ordinary HTTP requests through the same tunnel: the core's own latency test
// reported 239 ms while every real request through that node timed out. The
// upgrade only proves the edge accepts the request, not that it carries the
// response back, so a candidate must also return a real status line here.
func probeHTTPS(ip, sni, host, requestPath string, timeout time.Duration) (time.Duration, bool) {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.Dial("tcp", ip+":443")
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if requestPath == "" {
		requestPath = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Zenith-probe\r\n"+
		"Accept: */*\r\nConnection: close\r\n\r\n", requestPath, host)

	start := time.Now()
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, false
	}
	elapsed := time.Since(start)
	line := string(buf[:n])
	if idx := strings.Index(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}
	// Any real status line proves the edge carried the response back. The code
	// itself does not matter: 200, 301, 403 and 404 all mean the tunnel works.
	if !strings.HasPrefix(line, "HTTP/") {
		return 0, false
	}
	return elapsed, true
}

// randomWSKey produces a valid Sec-WebSocket-Key: base64 of 16 random bytes.
// An earlier version base64 encoded a zero-padded timestamp, which decodes to
// sixteen zero bytes - Cloudflare answers 400 Bad Request for that, and every
// candidate edge then looked dead.
func randomWSKey() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func probeWSVerbose(ip, sni, path, host string, timeout time.Duration, why *string) (time.Duration, bool) {
	fail := func(reason string) (time.Duration, bool) {
		if why != nil {
			*why = reason
		}
		return 0, false
	}
	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.Dial("tcp", ip+":443")
	if err != nil {
		return fail("tls dial: " + err.Error())
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	key := randomWSKey()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, key)

	start := time.Now()
	if _, err := conn.Write([]byte(req)); err != nil {
		return fail("write: " + err.Error())
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fail("read: " + err.Error())
	}
	elapsed := time.Since(start)
	line := string(buf[:n])
	if idx := strings.Index(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}
	if !strings.Contains(line, "101") {
		return fail("status: " + line)
	}
	return elapsed, true
}

// wsEndpoint is the routing identity of an optimisable node: the SNI, path and
// Host are what Cloudflare routes on, so only the edge address may change. Two
// nodes sharing these values will be reached through the same tunnel and must
// be optimised together.
type wsEndpoint struct {
	SNI  string
	Path string
	Host string
}

// templateGroup is one optimisable tunnel plus the node it is cloned from.
type templateGroup struct {
	index    int
	template Proxy
	ep       wsEndpoint
}

func endpointOf(p *Proxy) wsEndpoint {
	sni := p.Servername
	if sni == "" {
		sni = p.SNI
	}
	if sni == "" {
		sni = p.Server
	}
	path := "/"
	host := sni
	if p.WSOpts != nil {
		if v, ok := p.WSOpts["path"].(string); ok && v != "" {
			path = v
		}
		if hdrs, ok := p.WSOpts["headers"].(map[string]interface{}); ok {
			if h, ok := hdrs["Host"].(string); ok && h != "" {
				host = h
			}
		}
	}
	return wsEndpoint{SNI: sni, Path: path, Host: host}
}

// canOptimize reports whether a node can be re-pointed at a Cloudflare edge.
//
// Only WebSocket + TLS qualifies. A subscription that mixes a Cloudflare relay
// with direct nodes (Singapore / Japan / US) therefore yields both kinds, and
// the direct ones must be left completely alone - they are reachable at their
// own address and no edge swap can improve them.
func canOptimize(p *Proxy) bool {
	if p.Server == "" || p.Port == 0 {
		return false
	}
	if !strings.EqualFold(p.Network, "ws") {
		return false
	}
	// TLS is implied by servername/sni, or stated explicitly
	return p.TLS != nil && *p.TLS || p.Servername != "" || p.SNI != ""
}

// collectTemplates finds every distinct optimisable tunnel in the node list,
// preferring a vmess entry as the representative of each one.
func collectTemplates(nodes []Proxy) []templateGroup {
	type slot struct {
		group templateGroup
		vmess bool
	}
	order := make([]string, 0, 4)
	seen := make(map[string]*slot, 4)

	for i := range nodes {
		p := nodes[i]
		if !canOptimize(&p) {
			continue
		}
		ep := endpointOf(&p)
		key := strings.ToLower(fmt.Sprintf("%s|%s|%s|%d", ep.SNI, ep.Path, ep.Host, p.Port))

		isVmess := strings.EqualFold(p.Type, "vmess")
		if s, ok := seen[key]; ok {
			// a vmess node is the better template: it carries uuid/cipher/alterId
			if isVmess && !s.vmess {
				s.group.template = p
				s.group.ep = ep
				s.vmess = true
			}
			continue
		}
		seen[key] = &slot{group: templateGroup{template: p, ep: ep}, vmess: isVmess}
		order = append(order, key)
	}

	out := make([]templateGroup, 0, len(order))
	for _, k := range order {
		g := seen[k].group
		g.index = len(out) + 1
		out = append(out, g)
	}
	return out
}

// ScanEdges ranks the candidate pool and returns the winning proxies, built by
// re-pointing the template node's server field at each winning IP.
//
// min Wanted is a floor, not a cap: if fewer edges verify than the user wants,
// the scan runs a second pass over the next slice of the candidate pool instead
// of silently returning less than asked for.
func (o *Optimizer) ScanEdges(nodes []Proxy, st Settings, minWanted int) ([]Proxy, []edgeResult, error) {
	groups := collectTemplates(nodes)
	if len(groups) == 0 {
		return nil, nil, fmt.Errorf("订阅里没有可用于优选的节点：优选只能作用于 WebSocket + TLS 中转节点，" +
			"直连节点（trojan/ss/hysteria2 等）不需要也不能优选")
	}
	optimizable := 0
	for i := range nodes {
		if canOptimize(&nodes[i]) {
			optimizable++
		}
	}
	Log("optimiser: %d node(s), %d optimisable across %d distinct tunnel(s)",
		len(nodes), optimizable, len(groups))
	for _, g := range groups {
		Log("  tunnel %d: sni=%s host=%s path=%s (from %q)",
			g.index, g.ep.SNI, g.ep.Host, g.ep.Path, g.template.Name)
	}

	ips := o.Candidates()
	total := len(ips)
	if total == 0 {
		return nil, nil, fmt.Errorf("候选 IP 池是空的")
	}
	rounds := st.ProbeRounds
	if rounds <= 0 {
		rounds = 3
	}
	workers := st.ProbeWorkers
	if workers <= 0 {
		workers = 24
	}
	// Always verify more edges than the display cap so the user can raise
	// keepNodes without paying for another full scan.
	if minWanted < 64 {
		minWanted = 64
	}
	if minWanted > len(ips) {
		minWanted = len(ips)
	}
	// Split the budget over the tunnels. Each keeps a useful share, and the
	// candidate slice each one sweeps is proportionally smaller, so adding a
	// second relay does not double the wall clock time.
	perTemplate := (minWanted + len(groups) - 1) / len(groups)
	if perTemplate < 8 {
		perTemplate = 8
	}

	type groupOutcome struct {
		group   templateGroup
		results []edgeResult
		err     error
	}
	outcomes := make([]groupOutcome, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		select {
		case <-o.cancel:
			return nil, nil, fmt.Errorf("已取消")
		default:
		}
		wg.Add(1)
		go func(i int, g templateGroup) {
			defer wg.Done()
			wWorkers := workers / len(groups)
			if wWorkers < 6 {
				wWorkers = 6
			}
			usable, err := o.scanPass(ips, &g.template, g.ep.SNI, g.ep.Path, g.ep.Host,
				rounds, wWorkers, perTemplate)
			if err == nil && len(usable) < perTemplate {
				// first slice was not enough, sweep the rest of the pool
				if rest := ips[min(perTemplate, len(ips)):]; len(rest) > 0 {
					more, err2 := o.scanPass(rest, &g.template, g.ep.SNI, g.ep.Path, g.ep.Host,
						rounds, wWorkers, perTemplate-len(usable))
					if err2 == nil {
						usable = append(usable, more...)
						sort.Slice(usable, func(a, b int) bool { return usable[a].Score < usable[b].Score })
					}
				}
			}
			outcomes[i] = groupOutcome{group: g, results: usable, err: err}
		}(i, g)
	}
	wg.Wait()

	// Build the per-tunnel node lists, keeping the tunnels separate so a relay
	// that verifies well cannot crowd out one that verifies poorly.
	var out []Proxy
	var allUsable []edgeResult
	var failed []string
	for _, oc := range outcomes {
		if oc.err != nil {
			Log("tunnel %d failed: %v", oc.group.index, oc.err, "WARN")
			failed = append(failed, fmt.Sprintf("%s:%s", oc.group.ep.SNI, oc.group.ep.Path))
			continue
		}
		if len(oc.results) == 0 {
			failed = append(failed, fmt.Sprintf("%s:%s", oc.group.ep.SNI, oc.group.ep.Path))
			continue
		}
		allUsable = append(allUsable, oc.results...)
		Log("tunnel %d: %d usable edge(s), best %.0fms",
			oc.group.index, len(oc.results), oc.results[0].Median*1000)
		for i, r := range oc.results {
			if i >= perTemplate {
				break
			}
			p := oc.group.template
			p.Server = r.IP
			p.MeasuredMS = r.Median * 1000
			// The IP already identifies the winner; the tunnel suffix only has to
			// disambiguate when more than one relay is in play.
			if len(groups) > 1 {
				p.Name = fmt.Sprintf("优选T%d-%02d · %s · %.0fms", oc.group.index, i+1, r.IP, r.Median*1000)
			} else {
				p.Name = fmt.Sprintf("优选%02d · %s · %.0fms", i+1, r.IP, r.Median*1000)
			}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("没有一个边缘节点可用：可能是订阅已失效或网络本身有问题")
	}

	sort.Slice(allUsable, func(i, j int) bool { return allUsable[i].Score < allUsable[j].Score })
	{
		learned := o.learnCandidates(func() []string {
			seen := map[string]bool{}
			learned := make([]string, 0, len(allUsable))
			for _, r := range allUsable {
				if !seen[r.IP] {
					seen[r.IP] = true
					learned = append(learned, r.IP)
				}
			}
			return learned
		}())
		if learned > 0 {
			Log("candidate pool grew by %d verified IPs", learned)
		}
	}

	o.mu.Lock()
	o.lastSummary = OptimizeSummary{
		Templates:     len(groups),
		Optimizable:   optimizable,
		Unsupported:   len(nodes) - optimizable,
		FailedTunnels: failed,
		Nodes:         len(out),
	}
	o.mu.Unlock()

	Log("edge scan done: %d node(s) from %d tunnel(s), best %s (%.0fms)",
		len(out), len(groups)-len(failed), allUsable[0].IP, allUsable[0].Median*1000)
	o.setProgress("idle", 0, 0, "完成")
	return out, allUsable, nil
}

// scanPass probes one slice of candidate IPs and returns those that completed a
// real WebSocket upgrade, ranked by median time.
func (o *Optimizer) scanPass(ips []string, template *Proxy, sni, path, host string,
	rounds, workers, wanted int) ([]edgeResult, error) {

	if wanted > 0 && len(ips) > wanted*3 {
		// no point testing far more addresses than the caller needs
		ips = ips[:wanted*3]
	}
	total := len(ips)
	o.setProgress("scan", 0, total, fmt.Sprintf("正在测试 %d 个边缘节点…", total))

	var done int64
	sem := make(chan struct{}, workers)
	results := make([]edgeResult, 0, total)
	var resMu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-o.cancel:
			return nil, fmt.Errorf("已取消")
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			var times []float64
			ok := 0
			for i := 0; i < rounds; i++ {
				wsTime, good := probeWS(ip, sni, path, host, 6*time.Second)
				if !good {
					continue
				}
				// The upgrade alone is not proof. Some edges accept it and then
				// drop ordinary traffic, so every round must also fetch a real
				// response through the same tunnel. The cost recorded is the
				// round trip the user will actually experience.
				httpTime, carried := probeHTTPS(ip, sni, host, httpProbePath, 6*time.Second)
				if !carried {
					continue
				}
				if httpTime > wsTime {
					times = append(times, httpTime.Seconds())
				} else {
					times = append(times, wsTime.Seconds())
				}
				ok++
			}
			n := atomic.AddInt64(&done, 1)
			if n%10 == 0 {
				o.setProgress("scan", int(n), total,
					fmt.Sprintf("正在测试边缘节点 %d/%d", n, total))
			}
			if ok == 0 {
				return
			}
			sort.Float64s(times)
			median := times[len(times)/2]
			penalty := float64(rounds-ok) * 0.4
			resMu.Lock()
			results = append(results, edgeResult{
				IP: ip, Median: median, Score: median + penalty, OK: ok, Rounds: rounds,
			})
			resMu.Unlock()
		}(ip)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Score < results[j].Score })
	return results, nil
}

func (o *Optimizer) Cancel() {
	o.mu.Lock()
	if o.cancel != nil {
		close(o.cancel)
	}
	o.cancel = make(chan struct{})
	o.mu.Unlock()
}

func (o *Optimizer) begin() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.running {
		return false
	}
	o.running = true
	o.cancel = make(chan struct{})
	return true
}

func (o *Optimizer) end() {
	o.mu.Lock()
	o.running = false
	o.prog = OptimizeProgress{Stage: "idle", Text: "完成"}
	o.mu.Unlock()
}

// seedCandidates is the starting pool. Zenith appends every IP it verifies, so
// the list sharpens the more it runs.
const seedCandidates = `# Zenith 边缘 IP 候选池
# 每行一个 IP，以 # 开头的行为注释。
# 每次优选实测可用的 IP 会自动追加到文件末尾，池子越用越准。
103.21.244.1
103.21.244.30
103.21.244.60
103.21.244.100
103.21.244.130
103.21.244.160
103.21.244.200
103.21.244.250
103.31.4.1
103.31.4.30
103.31.4.60
103.31.4.100
103.31.4.130
103.31.4.160
103.31.4.200
103.31.4.250
188.114.96.1
188.114.96.30
188.114.96.60
188.114.96.100
188.114.96.130
188.114.96.160
188.114.96.200
188.114.96.250
188.114.97.1
188.114.97.30
188.114.97.60
188.114.97.100
188.114.97.130
188.114.97.160
188.114.97.200
188.114.97.250
188.114.98.1
188.114.98.30
188.114.98.60
188.114.98.100
188.114.98.130
188.114.98.160
188.114.98.200
188.114.98.250
188.114.99.1
188.114.99.30
188.114.99.60
188.114.99.100
188.114.99.130
188.114.99.160
188.114.99.200
188.114.99.250
172.67.1.1
172.67.30.1
172.67.60.1
172.67.100.1
172.67.130.1
172.67.152.1
172.67.200.1
172.67.250.1
104.16.1.1
104.16.30.1
104.16.60.1
104.16.100.1
104.16.130.1
104.16.160.1
104.16.200.1
104.16.250.1
104.17.1.1
104.17.30.1
104.17.60.1
104.17.100.1
104.17.130.1
104.17.160.1
104.17.200.1
104.17.250.1
104.18.1.1
104.18.30.1
104.18.60.1
104.18.100.1
104.18.130.1
104.18.160.1
104.18.200.1
104.18.250.1
104.19.1.1
104.19.30.1
104.19.60.1
104.19.100.1
104.19.130.1
104.19.160.1
104.19.200.1
104.19.250.1
104.20.1.1
104.20.30.1
104.20.60.1
104.20.100.1
104.20.130.1
104.20.160.1
104.20.200.1
104.20.250.1
104.21.1.1
104.21.30.1
104.21.60.1
104.21.100.1
104.21.130.1
104.21.160.1
104.21.200.1
104.21.250.1
104.24.1.1
104.24.30.1
104.24.60.1
104.24.100.1
104.24.130.1
104.24.160.1
104.24.200.1
104.24.250.1
104.25.1.1
104.25.30.1
104.25.60.1
104.25.100.1
104.25.130.1
104.25.160.1
104.25.200.1
104.25.250.1
104.26.1.1
104.26.30.1
104.26.60.1
104.26.100.1
104.26.130.1
104.26.160.1
104.26.200.1
104.26.250.1
104.27.1.1
104.27.30.1
104.27.60.1
104.27.100.1
104.27.130.1
104.27.160.1
104.27.200.1
104.27.250.1
172.64.1.1
172.64.30.1
172.64.60.1
172.64.100.1
172.64.130.1
172.64.160.1
172.64.200.1
172.64.250.1
172.65.1.1
172.65.30.1
172.65.60.1
172.65.100.1
172.65.130.1
172.65.160.1
172.65.200.1
172.65.250.1
172.66.1.1
172.66.30.1
172.66.60.1
172.66.100.1
172.66.130.1
172.66.160.1
172.66.200.1
172.66.250.1
172.68.1.1
172.68.30.1
172.68.60.1
172.68.100.1
172.68.130.1
172.68.160.1
172.68.200.1
172.68.250.1
172.69.1.1
172.69.30.1
172.69.60.1
172.69.100.1
172.69.130.1
172.69.160.1
172.69.200.1
172.69.250.1
162.159.1.1
162.159.30.1
162.159.60.1
162.159.100.1
162.159.128.1
162.159.160.1
162.159.200.1
162.159.250.1
108.162.192.1
108.162.192.30
108.162.192.60
108.162.192.100
108.162.192.130
108.162.192.160
108.162.192.200
108.162.192.250
108.162.193.1
108.162.193.30
108.162.193.60
108.162.193.100
108.162.193.130
108.162.193.160
108.162.193.200
108.162.193.250
141.101.64.1
141.101.64.30
141.101.64.60
141.101.64.100
141.101.64.130
141.101.64.160
141.101.64.200
141.101.64.250
141.101.65.1
141.101.65.30
141.101.65.60
141.101.65.100
141.101.65.130
141.101.65.160
141.101.65.200
141.101.65.250
173.245.48.1
173.245.48.30
173.245.48.60
173.245.48.100
173.245.48.130
173.245.48.160
173.245.48.200
173.245.48.250
190.93.240.1
190.93.240.30
190.93.240.60
190.93.240.100
190.93.240.130
190.93.240.160
190.93.240.200
190.93.240.250
197.234.240.1
197.234.240.30
197.234.240.60
197.234.240.100
197.234.240.130
197.234.240.160
197.234.240.200
197.234.240.250
103.22.200.1
103.22.200.30
103.22.200.60
103.22.200.100
103.22.200.130
103.22.200.160
103.22.200.200
103.22.200.250
131.0.72.1
131.0.72.30
131.0.72.60
131.0.72.100
131.0.72.130
131.0.72.160
131.0.72.200
131.0.72.250
`
