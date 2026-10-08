package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Config generation
//
// Zenith never restarts the core to change something: it writes this file and
// asks mihomo to reload it. Everything the UI toggles at runtime (proxy mode,
// selected node) is applied through the REST API instead, so nothing flickers.
// ---------------------------------------------------------------------------

const configHeadTemplate = `mixed-port: %d
allow-lan: false
bind-address: 127.0.0.1
mode: %s
log-level: %s
ipv6: false
unified-delay: true
tcp-concurrent: true
find-process-mode: 'off'
external-controller: 127.0.0.1:%d
secret: "%s"
profile:
  store-selected: true
  store-fake-ip: false
geo-auto-update: false
geodata-mode: false
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:%d
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - 'localhost.ptlogin2.qq.com'
  default-nameserver: [223.5.5.5, 119.29.29.29]
  # Resolving the node domains is the one job that must never depend on the
  # proxy: a hostname-based subscription resolved through the tunnel would
  # deadlock, and resolved through a Chinese resolver it comes back clean only
  # because the node domains are themselves fronted by Cloudflare.
  proxy-server-nameserver: [223.5.5.5, 119.29.29.29]
  # Chinese domains go to a Chinese resolver, which is correct and fast for them.
  nameserver: [223.5.5.5, 119.29.29.29]
  # Everything else is resolved through the proxy. This is the only reliable
  # route: Chinese resolvers return poisoned answers for foreign domains, and
  # the public resolvers that would answer correctly are unreachable from here
  # (1.1.1.1 times out on port 53 entirely). The bootstrap below resolves the
  # DoH hostnames through the same clean Chinese resolvers, so the first query
  # cannot deadlock.
  nameserver-policy:
    'geosite:cn,private': [223.5.5.5, 119.29.29.29]
    'geosite:geolocation-!cn': ['https://1.1.1.1/dns-query#PROXY', 'https://8.8.8.8/dns-query#PROXY']
  fallback: [223.5.5.5, 119.29.29.29]
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
`

// q always quotes a scalar; provider supplied names contain characters that
// would otherwise break the yaml.
func q(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func yamlScalar(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, yamlScalar(x))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case string:
		if t == "" {
			return `""`
		}
		return q(t)
	}
	return q(fmt.Sprint(v))
}

func proxyToYAML(p Proxy) string {
	var b strings.Builder
	write := func(k string, v interface{}) {
		fmt.Fprintf(&b, "  %s: %s\n", k, yamlScalar(v))
	}
	write("name", p.Name)
	write("type", p.Type)
	write("server", p.Server)
	write("port", p.Port)
	if p.UUID != "" {
		write("uuid", p.UUID)
	}
	if p.Password != "" {
		write("password", p.Password)
	}
	if p.Cipher != "" {
		write("cipher", p.Cipher)
	}
	// alterId must always be present for vmess, even when it is zero: mihomo
	// refuses the node with "has unset fields: alterId" otherwise.
	if p.Type == "vmess" {
		write("alterId", p.AlterID)
	} else if p.AlterID != 0 {
		write("alterId", p.AlterID)
	}
	if p.Flow != "" {
		write("flow", p.Flow)
	}
	if p.TLS != nil {
		write("tls", *p.TLS)
	}
	if p.Servername != "" {
		write("servername", p.Servername)
	}
	if p.SNI != "" {
		write("sni", p.SNI)
	}
	if p.SkipCertVerify != nil {
		write("skip-cert-verify", *p.SkipCertVerify)
	}
	if p.ClientFingerprint != "" {
		write("client-fingerprint", p.ClientFingerprint)
	}
	if p.Network != "" {
		write("network", p.Network)
	}
	if p.UDP != nil {
		write("udp", *p.UDP)
	}
	for _, key := range []string{"ws-opts", "grpc-opts", "h2-opts"} {
		var m map[string]interface{}
		switch key {
		case "ws-opts":
			m = p.WSOpts
		case "grpc-opts":
			m = p.GrpcOpts
		case "h2-opts":
			m = p.H2Opts
		}
		if len(m) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s:\n", key)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := m[k]
			if sub, ok := v.(map[string]interface{}); ok {
				fmt.Fprintf(&b, "    %s:\n", k)
				subKeys := make([]string, 0, len(sub))
				for sk := range sub {
					subKeys = append(subKeys, sk)
				}
				sort.Strings(subKeys)
				for _, sk := range subKeys {
					fmt.Fprintf(&b, "      %s: %s\n", sk, yamlScalar(sub[sk]))
				}
				continue
			}
			fmt.Fprintf(&b, "    %s: %s\n", k, yamlScalar(v))
		}
	}
	// keep unknown provider keys so nothing is silently lost
	if len(p.Extra) > 0 {
		keys := make([]string, 0, len(p.Extra))
		for k := range p.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "alpn" {
				fmt.Fprintf(&b, "  alpn: %s\n", yamlScalar(p.Extra[k]))
				continue
			}
			fmt.Fprintf(&b, "  %s: %s\n", k, yamlScalar(p.Extra[k]))
		}
	}
	return b.String()
}

// dedupeNames makes every node name unique, which mihomo requires.
func dedupeNames(in []Proxy) []Proxy {
	seen := map[string]int{}
	out := make([]Proxy, 0, len(in))
	for _, p := range in {
		base := p.Name
		if base == "" {
			base = p.Server
		}
		if n, dup := seen[base]; dup {
			seen[base] = n + 1
			p.Name = fmt.Sprintf("%s (%d)", base, n+1)
		} else {
			seen[base] = 1
			p.Name = base
		}
		out = append(out, p)
	}
	return out
}

// BuildConfig renders mihomo's config.yaml.
//
// optimised names the nodes that came from the edge scan; they are the ones the
// AUTO group is allowed to choose between, because they are the only ones Zenith
// has actually verified. The subscription's own nodes are still listed in PROXY
// so they can be picked by hand.
func BuildConfig(nodes []Proxy, optimised []string, st Settings, secret string, current string, dnsPort int) string {
	nodes = dedupeNames(nodes)
	var b strings.Builder

	logLevel := "info"
	mode := st.Mode
	switch mode {
	case "global", "direct", "rule":
	default:
		mode = "rule"
	}
	fmt.Fprintf(&b, configHeadTemplate, st.MixedPort, mode, logLevel, st.ControlPort, secret, dnsPort)

	b.WriteString("\nproxies:\n")
	if len(nodes) == 0 {
		// mihomo rejects an empty proxies list, so emit a harmless placeholder
		b.WriteString("  - {name: \"__none__\", type: socks5, server: 127.0.0.1, port: 1}\n")
	}
	names := make([]string, 0, len(nodes))
	for _, p := range nodes {
		// The reference layout mihomo accepts is:
		//
		//   proxies:
		//   - name: "x"          <- first key inlined after "- "
		//     type: "vmess"      <- two spaces
		//     ws-opts:
		//       headers:         <- four spaces
		//
		// proxyToYAML already emits that relative indentation, so the block is
		// written verbatim with only the first line reshaped. Adding an extra
		// offset (or trimming the indent) breaks nested keys - both were tried
		// and mihomo answered "did not find expected key".
		body := proxyToYAML(p)
		lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
		if len(lines) == 0 {
			continue
		}
		b.WriteString("- " + strings.TrimSpace(lines[0]) + "\n")
		for _, ln := range lines[1:] {
			b.WriteString(ln + "\n")
		}
		names = append(names, p.Name)
	}

	b.WriteString("\nproxy-groups:\n")
	// AUTO is a url-test group, but it only ever contains nodes the optimiser
	// verified. Mixing the subscription's own nodes in used to make the core
	// wander onto a node Zenith had not measured, which is the opposite of what
	// "use the fastest verified node" means.
	//
	// The group is still useful even though Zenith also enforces the choice
	// itself: it gives the core an immediate answer, and it is what the PROXY
	// group follows when the user has not pinned anything.
	autoMembers := make([]string, 0, len(optimised))
	seenAuto := make(map[string]bool, len(optimised))
	for _, n := range optimised {
		if contains(names, n) && !seenAuto[n] {
			seenAuto[n] = true
			autoMembers = append(autoMembers, n)
		}
	}
	if len(autoMembers) == 0 {
		// nothing verified yet: fall back to everything so the proxy still works
		autoMembers = append(autoMembers, names...)
	}

	b.WriteString("  - name: \"AUTO\"\n")
	b.WriteString("    type: url-test\n")
	b.WriteString("    url: \"https://www.gstatic.com/generate_204\"\n")
	b.WriteString("    interval: 180\n")
	b.WriteString("    tolerance: 120\n")
	b.WriteString("    lazy: false\n")
	if len(autoMembers) > 0 {
		b.WriteString("    proxies:\n")
		for _, n := range autoMembers {
			fmt.Fprintf(&b, "      - %s\n", q(n))
		}
	} else {
		b.WriteString("    proxies: [\"DIRECT\"]\n")
	}

	b.WriteString("  - name: \"PROXY\"\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	// Anything the user explicitly pinned goes first so it is the default.
	if current != "" && contains(names, current) {
		fmt.Fprintf(&b, "      - %s\n", q(current))
	}
	b.WriteString("      - \"AUTO\"\n")
	for _, n := range names {
		if n == current {
			continue
		}
		fmt.Fprintf(&b, "      - %s\n", q(n))
	}
	// DIRECT must never live inside a url-test group (mihomo reports a fixed
	// near-zero delay for it and it would always win), but a select group is
	// exactly where it belongs.
	b.WriteString("      - \"DIRECT\"\n")

	b.WriteString("\nrules:\n")
	if st.BlockAds {
		b.WriteString("  - \"GEOSITE,category-ads-all,REJECT\"\n")
	}
	for _, r := range st.CustomRules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, _, ok := splitRule(r); !ok {
			continue
		}
		fmt.Fprintf(&b, "  - %s\n", q(r))
	}
	if !st.GamePlatformDirectOff {
		// Game launchers and stores, placed before the CN rules on purpose.
		//
		// The problem this solves: a launcher opens, the login and store requests
		// go out, and the pages hang or the sign-in fails, because those endpoints
		// are blocked while the launcher itself never consults the system proxy
		// for them. Naming the platforms explicitly is what fixes it.
		//
		// Only the store/community/login side is listed. The download CDNs are
		// absent from these categories, which is exactly what we want: they are
		// usually reachable directly and pulling game data through a proxy would
		// be far slower.
		for _, site := range gamePlatformSites {
			fmt.Fprintf(&b, "  - %s\n", q("GEOSITE,"+site+",PROXY"))
		}
	}
	if st.DirectCNDomains {
		// geosite:cn is the reliable way to catch Chinese sites: DOMAIN-SUFFIX,cn
		// alone misses the many .com ones (baidu.com, bilibili.com, taobao.com).
		b.WriteString("  - \"GEOSITE,cn,DIRECT\"\n")
		b.WriteString("  - \"GEOIP,CN,DIRECT\"\n")
	}
	b.WriteString("  - \"DOMAIN-SUFFIX,cn,DIRECT\"\n")
	b.WriteString("  - \"MATCH,PROXY\"\n")
	return b.String()
}

// gamePlatformSites are the GeoSite categories covering the international game
// launchers, stores and their login endpoints. Every name here was checked
// against the bundled GeoSite.dat; a category that does not exist in the data
// file makes the core refuse to start, so this list must not be guessed at.
//
// Deliberately absent: steamcn and similar China-specific entries, and any
// category that only contains download CDN hostnames.
var gamePlatformSites = []string{
	"steam",       // store, community, login (NOT the download CDN)
	"epicgames",   // Epic Games Store and launcher
	"ea",          // EA app and Origin
	"origin",      // older Origin endpoints still in use
	"ubisoft",     // Ubisoft Connect
	"blizzard",    // Battle.net and Blizzard login
	"riot",        // Riot Client and League of Legends
	"rockstar",    // Rockstar Games Launcher
	"gog",         // GOG Galaxy
	"nintendo",    // Nintendo eShop and account
	"playstation", // PlayStation Network
	"xbox",        // Xbox app and account
	"discord",     // voice and chat, commonly used alongside games
	"twitch",      // streaming, same audience
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// splitRule validates "TYPE,ARG,TARGET" style rules so a typo in the advanced
// editor cannot break the whole config.
func splitRule(rule string) (string, string, bool) {
	parts := strings.Split(rule, ",")
	if len(parts) < 2 {
		return "", "", false
	}
	kind := strings.ToUpper(strings.TrimSpace(parts[0]))
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
		"GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR",
		"SRC-PORT", "DST-PORT", "PROCESS-NAME", "PROCESS-PATH",
		"RULE-SET", "MATCH", "NETWORK", "IN-TYPE":
		return kind, strings.Join(parts[1:], ","), true
	}
	return "", "", false
}

// RuleTargets are the choices the advanced editor offers for a rule's target.
var RuleTargets = []string{"PROXY", "AUTO", "DIRECT", "REJECT"}

// ValidateRule is used by the API to give the user a clear message.
func ValidateRule(rule string) error {
	kind, rest, ok := splitRule(rule)
	if !ok {
		return fmt.Errorf("规则必须以受支持的类型开头，例如 DOMAIN-SUFFIX,google.com,PROXY")
	}
	if kind == "MATCH" {
		return nil
	}
	if strings.TrimSpace(rest) == "" {
		return fmt.Errorf("规则缺少参数：需要写成 类型,匹配内容,出口")
	}
	return nil
}
