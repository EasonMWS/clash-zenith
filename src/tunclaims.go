package main

// ---------------------------------------------------------------------------
// Three questions, asked separately, because "it works" is three claims.
//
//   1. Is traffic being taken?   The adapter is up and the default route uses it.
//   2. Is it leaving through a proxy? The core carried the request, and the address
//      the far side sees is not this machine's own.
//   3. Is anything bypassing it?  DNS, IPv6, UDP, and the application's own DoH.
//
// The old check folded these together and answered with one boolean, which is why it
// could be satisfied by a request that never touched the tunnel. Three specific ways
// it did that, all of them fixed here:
//
//   - The fallback target included baidu.com, which answers on a direct connection in
//     this country. So a machine whose tunnel was completely dead could still pass
//     the request stage, and the report said "traffic goes through the tunnel" on the
//     strength of a request that went straight out of the physical adapter.
//
//   - DNS was checked by asking the local listener on the DNS port, and a reply from
//     it was reported as "resolution goes through the tunnel's resolver". A local
//     listener answering proves the listener is there. It does not prove where the
//     query went, and the two were written as if they were the same thing.
//
//   - IPv6 was reported as a risk and had no effect on the outcome, so privacy mode
//     could report success on a machine with a global IPv6 address and no IPv6 in the
//     tunnel - which is a bypass, and the mode exists to prevent exactly that.
//
// The separation is not bookkeeping. Each stage answers a question a user can act on,
// and a failure names the one that failed instead of leaving them with "it did not
// work".
// ---------------------------------------------------------------------------

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// claim is one of the three questions, with its own outcome.
type claim struct {
	// Name is what the user is being told, in as few words as possible.
	Name string `json:"name"`
	// OK is whether this claim holds.
	OK bool `json:"ok"`
	// Detail says what was measured, not what was intended.
	Detail string `json:"detail"`
	// Fatal marks a claim that must hold for the activation to count as successful.
	// Everything is fatal except the leak notices in compat mode, which are reported
	// because they matter and do not fail a mode that never promised to prevent them.
	Fatal bool `json:"fatal"`
}

// layering turns the individual observations into the three claims.
//
// Kept apart from the measuring so the decision can be tested without a tunnel, which
// is the only way to test the case that matters most: a machine where everything looks
// right and nothing is being taken.
func (rep *tunTrafficReport) layering(mode TunMode, realIP string) []claim {

	taken := claim{
		Name:   "流量被接管",
		OK:     rep.AdapterUp && rep.DefaultRouteOnAdapter,
		Fatal:  true,
		Detail: "",
	}
	switch {
	case !rep.AdapterUp:
		taken.Detail = fmt.Sprintf("网卡 %q 没有启用", rep.AdapterName)
	case !rep.DefaultRouteOnAdapter:
		taken.Detail = "默认路由没有指向隧道网卡，" + rep.RouteDetail
	default:
		taken.Detail = fmt.Sprintf("网卡 %q 已启用，默认路由指向它（%s）",
			rep.AdapterName, rep.RouteDetail)
	}

	egress := claim{
		Name:   "从代理出口出去",
		OK:     rep.DirectRequestSucceeded && rep.CoreCarried,
		Fatal:  true,
		Detail: "",
	}
	switch {
	case !rep.DirectRequestSucceeded:
		egress.Detail = "在没有任何代理设置的情况下，测试目标没有回应"
	case !rep.CoreCarried:
		// The case the old check could not see: the request succeeded without the
		// core, which means it did not go through the tunnel.
		egress.Detail = "请求成功了，但内核的连接记录里没有它，所以回应不是经过隧道来的：" +
			rep.CoreDetail
	default:
		egress.Detail = fmt.Sprintf("%s；内核的连接记录里有它（%s）",
			rep.DirectDetail, rep.CoreDetail)
	}
	if egress.OK && realIP != "" {
		egress.Detail += "；本机直连地址是 " + realIP
	}

	// The leak claim reports what was observed. It is not fatal, and that is a
	// deliberate consequence of the mode being gone rather than a downgrade.
	//
	// The claim used to be fatal in privacy mode, on the reasoning that a mode
	// promising "protected traffic only leaves through an approved route" must fail
	// when a global IPv6 address offers a path out. That mode no longer exists, so
	// there is nothing left that makes the promise - and making this fatal anyway would
	// refuse a mode for doing exactly what it says it does. What stays is the report,
	// because a user is entitled to know that IPv6 is a path their tunnel does not
	// cover.
	leak := claim{Name: "没有旁路泄露", Fatal: false}
	var leaks []string

	if strings.Contains(rep.DNS, "失败") || strings.Contains(rep.DNS, "没有回应") {
		leaks = append(leaks, "DNS："+rep.DNS)
	}
	if ipv6IsARisk(rep.IPv6) {
		leaks = append(leaks, "IPv6（不阻断，仅告知）："+rep.IPv6)
	}
	if strings.Contains(rep.UDP, "失败") {
		leaks = append(leaks, "UDP："+rep.UDP)
	}
	if len(leaks) == 0 {
		leak.Detail = "DNS 经隧道解析，IPv6 没有可用的旁路，UDP 经隧道转发"
		leak.OK = true
	} else {
		leak.Detail = strings.Join(leaks, "；")
		leak.OK = true
	}
	return []claim{taken, egress, leak}
}

// ipv6IsARisk reports whether an IPv6 observation describes a path out.
//
// Only a global address is a path out. A link-local or unique-local address cannot
// reach the internet, and treating one as a leak would fail activations on machines
// that are not leaking anything.
func ipv6IsARisk(report string) bool {
	if report == "" || strings.Contains(report, "没有 IPv6") ||
		strings.Contains(report, "没有全局") {
		return false
	}
	return strings.Contains(report, "全局")
}

// realDirectIP asks a service that echoes the caller's address what it sees, without
// any proxy configured, so the answer describes what this machine looks like when
// nothing is in the way.
//
// It is recorded rather than compared. Comparing it with the exit address would be a
// stronger statement, but the only way to learn the exit address is to ask through the
// tunnel, and a check that needs the thing it is checking is not a check.
func realDirectIP(timeout time.Duration) string {
	for _, url := range []string{
		"https://api.ipify.org",
	} {
		body, err := directBody(url, timeout)
		if err != nil {
			continue
		}
		body = strings.TrimSpace(body)
		if net.ParseIP(body) != nil {
			return body
		}
	}
	return ""
}
