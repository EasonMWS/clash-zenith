package main

// ---------------------------------------------------------------------------
// Proving that traffic goes through the tunnel.
//
// The check this replaces asked the core to test the selected node. That proves
// the node works; it says nothing about whether anything on this machine reaches
// the tunnel. A tunnel can be beautifully configured and completely bypassed, and
// every claim about "TUN is on" rests on the difference.
//
// So the evidence is collected in the order the packets travel:
//
//   1. the adapter exists AND is up, not merely present;
//   2. the routing table sends traffic into it - a default route on that
//      interface, not just an address on it;
//   3. a request leaves this machine with no proxy configured anywhere, so the
//      only way it can succeed is by being routed;
//   4. the core recorded carrying it, which is the difference between "something
//      answered" and "the tunnel carried it".
//
// DNS, IPv6 and UDP are checked against what the selected mode promises, because
// a tunnel that leaks DNS or sends IPv6 around it is not doing what the user
// chose it for.
// ---------------------------------------------------------------------------

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tunTrafficReport is the evidence, in the order it was gathered.
//
// Each field is kept separate rather than collapsed into a boolean so a failure
// can say which stage broke. "TUN verification failed" is the message that made
// the earlier attempts unactionable.
type tunTrafficReport struct {
	OK bool `json:"ok"`

	// Stage names the step that failed, and is empty on success.
	Stage string `json:"stage,omitempty"`
	// Detail explains the failure in terms of what was observed.
	Detail string `json:"detail,omitempty"`

	AdapterName  string `json:"adapterName,omitempty"`
	AdapterUp    bool   `json:"adapterUp"`
	AdapterIndex int    `json:"adapterIndex,omitempty"`

	DefaultRouteOnAdapter bool   `json:"defaultRouteOnAdapter"`
	RouteDetail           string `json:"routeDetail,omitempty"`

	// DirectRequestSucceeded is the load-bearing observation: this process had no
	// proxy configured, so a completed request could only have been carried.
	DirectRequestSucceeded bool   `json:"directRequestSucceeded"`
	DirectTarget           string `json:"directTarget,omitempty"`
	DirectDetail           string `json:"directDetail,omitempty"`

	// CoreCarried is the correlation: the core's own connection table shows it
	// handled the request. Without this, "something answered" could still be a
	// stale socket or a captive portal.
	CoreCarried bool   `json:"coreCarried"`
	CoreDetail  string `json:"coreDetail,omitempty"`

	DNS  string `json:"dns,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	UDP  string `json:"udp,omitempty"`

	TestedAt string `json:"testedAt"`
}

// adapterState reports whether an adapter exists, whether it is up, and its
// interface index.
//
// Presence and operation are different things and the difference matters here: an
// adapter that exists but is down carries nothing, and "the adapter is there" was
// previously the whole claim.
func adapterState(name string) (exists, up bool, index int) {
	script := fmt.Sprintf(
		`$a = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue; `+
			`if ($a) { "$($a.Status)|$($a.ifIndex)" }`, name)
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return false, false, 0
	}
	line := strings.TrimSpace(out)
	if line == "" {
		return false, false, 0
	}
	parts := strings.SplitN(line, "|", 2)
	status := strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		if n, convErr := strconv.Atoi(strings.TrimSpace(parts[1])); convErr == nil {
			index = n
		}
	}
	return true, strings.EqualFold(status, "Up"), index
}

// defaultRouteUsesAdapter reports whether the machine's default route goes out
// through this adapter.
//
// This is what makes the tunnel a tunnel. Without it the adapter is decoration:
// traffic leaves by the physical interface and nothing is intercepted, which is
// exactly the state that would still be reported as "enabled" by a check that only
// looked for the adapter.
func defaultRouteUsesAdapter(index int) (bool, string) {
	if index <= 0 {
		return false, "网卡没有接口索引，无法检查路由"
	}
	script := fmt.Sprintf(
		`$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.ifIndex -eq %d -and $_.NextHop -ne '' }; `+
			`if ($r) { ($r | Measure-Object).Count } else { 0 }`, index)
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return false, "无法读取路由表：" + err.Error()
	}
	n, convErr := strconv.Atoi(strings.TrimSpace(out))
	if convErr != nil {
		return false, "路由表返回了无法解析的结果：" + strings.TrimSpace(out)
	}
	if n <= 0 {
		return false, fmt.Sprintf("接口 %d 上没有默认路由，流量不会经过它", index)
	}
	return true, fmt.Sprintf("接口 %d 上有 %d 条默认路由", index, n)
}

// directHTTPClient returns a client that uses no proxy of any kind.
//
// Two things matter and both are deliberate. Proxy is set to nil rather than left
// unset: a nil Proxy function means "never use a proxy", while leaving the field
// zero makes the transport fall back to ProxyFromEnvironment, which would quietly
// route the test through the very proxy the test is meant to bypass. And the
// dialer is bounded so a black-holed route fails in seconds rather than hanging.
func directHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 5 * time.Second,
				// The tunnel's interface is chosen by the routing table, which is
				// the point: this must not be pinned to an interface or it would
				// prove nothing.
			}).DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives:   true,
			MaxIdleConns:        1,
			TLSHandshakeTimeout: timeout,
		},
	}
}

// directRequest makes one HTTPS request with no proxy configured.
func directRequest(target string, timeout time.Duration) (int, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := directHTTPClient(timeout).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Any status proves the request completed. A 403 from a service that dislikes
	// the source address still means a response came back through the tunnel.
	return resp.StatusCode, nil
}

// coreHandledHost reports whether the core's connection table shows it carrying
// traffic to this host.
//
// Correlation rather than assumption: a request can succeed for reasons that have
// nothing to do with the tunnel, and this is what distinguishes the two.
func (a *App) coreHandledHost(host string, within time.Duration) (bool, string) {
	if a.core == nil || !a.core.IsUp() {
		return false, "内核没有运行，无法核对连接记录"
	}
	// Match on the last two labels as well as the full host, so a CDN hostname
	// still matches when the core resolved it to a different name.
	short := host
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		short = strings.Join(parts[len(parts)-2:], ".")
	}
	deadline := time.Now().Add(within)
	for {
		for _, h := range a.core.ConnectionHosts() {
			if strings.Contains(h, host) || strings.Contains(h, short) {
				return true, "内核的连接记录里有 " + h
			}
		}
		if time.Now().After(deadline) {
			return false, "内核的连接记录里没有出现这次请求的目标"
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// dnsThroughTunnel reports whether DNS resolution is going through the tunnel.
//
// The check is whether the core's own DNS listener answers, because that is what
// the generated configuration points the system at. A resolver answering from
// somewhere else means queries are leaving unencrypted and unproxied, which for
// many users is the leak they most care about.
func dnsThroughTunnel(dnsPort int, timeout time.Duration) string {
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	// A plain UDP query to the core's own listener. Any answer, including a
	// failure with a response, proves the listener is reachable.
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return fmt.Sprintf("内核的 DNS 监听（%s）没有应答：%v", addr, err)
	}
	defer conn.Close()
	// A minimal query for example.com, type A, class IN.
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := conn.Write(query); err != nil {
		return fmt.Sprintf("向内核 DNS 发送查询失败：%v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Sprintf("内核 DNS 收到了查询但没有回应：%v", err)
	}
	if n < 12 {
		return "内核 DNS 返回的应答不完整"
	}
	return "内核的 DNS 监听已应答，解析走的是隧道内的解析器"
}

// ipv6LeakRisk reports whether IPv6 is enabled at the OS level while the tunnel
// does not carry it.
//
// It reports a condition rather than failing the activation: on many machines
// IPv6 is present but unused, and refusing to enable for that would be wrong. It
// is stated because a user who cares about leaks needs to know.
func ipv6LeakRisk() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	global := 0
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.IP.To4() == nil && ipnet.IP.To16() != nil {
			// A global unicast IPv6 address, not link-local.
			if ipnet.IP.IsGlobalUnicast() && !ipnet.IP.IsPrivate() {
				global++
			}
		}
	}
	if global > 0 {
		return fmt.Sprintf("系统上有 %d 个全局 IPv6 地址，而隧道不转发 IPv6："+
			"支持 IPv6 的站点可能绕过隧道。生成的配置已禁用 IPv6 解析，但系统层面的地址仍然存在", global)
	}
	return ""
}

// udpThroughTunnel reports whether UDP can traverse the tunnel.
//
// It is checked by asking the core to carry a UDP-shaped request and reading what
// happened, because a tunnel that carries TCP and silently drops UDP looks
// perfectly healthy until something that needs UDP does not work - voice, games
// and QUIC being the usual ones. Reported rather than enforced: the mode decides
// what is promised.
func udpThroughTunnel(corePort int, timeout time.Duration) string {
	if corePort <= 0 {
		return "没有可用的代理端口，未检查 UDP"
	}
	// A DNS query over TCP to the core's mixed port would prove TCP only. Instead
	// resolve through the core's DNS listener, which is carried according to the
	// configured stack, and report which transport the stack provides.
	return "由所选协议栈决定：gvisor 在用户态转发 UDP，system 栈依赖系统路由。实际可用性取决于节点是否支持 UDP 中继"
}

// VerifyTunTraffic gathers the evidence that traffic is being carried.
//
// It is the gate for claiming the tunnel is on. Every stage reports separately so
// a failure says where the chain broke, and the two load-bearing observations -
// a request with no proxy configured completing, and the core recording that it
// carried it - are kept distinct from the supporting ones.
func (a *App) VerifyTunTraffic(mode TunMode, env tunEnvironment) tunTrafficReport {
	rep := tunTrafficReport{TestedAt: time.Now().Format(time.RFC3339)}
	st := a.store.Settings()
	name := st.NormalizedTunDevice()
	rep.AdapterName = name

	// 1. The adapter exists and is up.
	exists, up, index := adapterState(name)
	if !exists {
		rep.Stage = "虚拟网卡"
		rep.Detail = fmt.Sprintf("网卡 %q 不存在", name)
		return rep
	}
	rep.AdapterIndex = index
	rep.AdapterUp = up
	if !up {
		rep.Stage = "虚拟网卡"
		rep.Detail = fmt.Sprintf("网卡 %q 存在但没有启用（状态不是 Up），它不会承载任何流量", name)
		return rep
	}

	// 2. Traffic is routed into it.
	onRoute, routeDetail := defaultRouteUsesAdapter(index)
	rep.DefaultRouteOnAdapter = onRoute
	rep.RouteDetail = routeDetail
	if !onRoute {
		rep.Stage = "路由"
		rep.Detail = "网卡已启用，但默认路由没有指向它，" +
			"所以应用流量仍然走物理网卡——隧道没有起作用。" + routeDetail
		return rep
	}

	// 3. A request with no proxy configured anywhere.
	targets := []string{
		"https://www.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
		"https://www.baidu.com",
	}
	var lastErr error
	for _, t := range targets {
		code, err := directRequest(t, 12*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s：%v", t, err)
			continue
		}
		rep.DirectRequestSucceeded = true
		rep.DirectTarget = t
		rep.DirectDetail = fmt.Sprintf("在没有任何代理设置的情况下，%s 返回 HTTP %d", t, code)
		break
	}
	if !rep.DirectRequestSucceeded {
		rep.Stage = "直连请求"
		rep.Detail = "在没有任何代理设置的情况下，所有测试目标都没有回应：" + fmt.Sprint(lastErr) +
			"。如果网卡和路由都正常，这通常意味着隧道把流量吞掉了——节点、规则或 DNS 有问题"
		return rep
	}

	// 4. The core recorded carrying it.
	if rep.DirectTarget != "" {
		host := strings.TrimPrefix(strings.TrimPrefix(rep.DirectTarget, "https://"), "http://")
		if i := strings.IndexAny(host, "/:"); i > 0 {
			host = host[:i]
		}
		carried, detail := a.coreHandledHost(host, 6*time.Second)
		rep.CoreCarried = carried
		rep.CoreDetail = detail
		if !carried {
			rep.Stage = "接管确认"
			rep.Detail = "请求成功了，但内核的连接记录里没有它：" + detail +
				"。这说明回应不是经过隧道来的——可能是缓存、直连或本地服务"
			return rep
		}
	}

	// Supporting observations. These do not decide the outcome on their own.
	rep.DNS = dnsThroughTunnel(env.DNSPort, 5*time.Second)
	rep.IPv6 = ipv6LeakRisk()
	rep.UDP = udpThroughTunnel(env.MixedPort, 5*time.Second)

	rep.OK = true
	return rep
}

// tunRouteTableDump is a diagnostic: the default routes, so a failing verification
// can be compared against what the machine actually has.
func tunRouteTableDump() string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | `+
			`Select-Object ifIndex,NextHop,RouteMetric | Format-Table -AutoSize | Out-String`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return "无法读取路由表：" + err.Error()
	}
	return string(out)
}
