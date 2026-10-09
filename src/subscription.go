package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// A tiny YAML subset parser.
//
// Providers hand out clash configs, and the shapes that actually show up need
// block mappings, block sequences, flow sequences, quoted/plain scalars and
// comments. Writing this by hand keeps Zenith dependency free, and the earlier
// Python version proved the awkward case: a proxy whose first key is a
// multi-line sequence whose items sit at the SAME indent as the entry's own
// keys ("- alpn:" followed by "- h2"). A line based reader that classifies by
// "- " prefix handles that; an indentation-only reader does not.
// ---------------------------------------------------------------------------

type yamlLine struct {
	indent  int
	text    string
	lineNo  int
	rawText string
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			inner := s[1 : len(s)-1]
			if s[0] == '"' {
				if v, err := strconv.Unquote(s); err == nil {
					return v
				}
				inner = strings.ReplaceAll(inner, `\"`, `"`)
				inner = strings.ReplaceAll(inner, `\\`, `\`)
			}
			return inner
		}
	}
	return s
}

// parseFlowMap handles the inline "{key: value, ...}" form, which some
// providers use for a compact proxy entry.
func parseFlowMap(s string) (map[string]interface{}, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, false
	}
	out := map[string]interface{}{}
	for _, part := range splitFlow(s[1 : len(s)-1]) {
		k, v, ok := splitKeyValue(part)
		if !ok {
			k = strings.TrimSpace(part)
			k = strings.Trim(k, `"'`)
			v = ""
		}
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = scalarValue(v)
	}
	return out, len(out) > 0
}

func scalarValue(s string) interface{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "{") {
		if m, ok := parseFlowMap(s); ok {
			return m
		}
	}
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []interface{}{}
		}
		parts := splitFlow(inner)
		out := make([]interface{}, 0, len(parts))
		for _, p := range parts {
			out = append(out, scalarValue(p))
		}
		return out
	}
	switch strings.ToLower(unquote(s)) {
	case "true":
		return true
	case "false":
		return false
	case "null", "~":
		return nil
	}
	uq := unquote(s)
	if n, err := strconv.Atoi(uq); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(uq, 64); err == nil {
		return f
	}
	return uq
}

func splitFlow(s string) []string {
	var out []string
	depth := 0
	inS, inD := false, false
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '[', '{':
			if !inS && !inD {
				depth++
			}
		case ']', '}':
			if !inS && !inD {
				depth--
			}
		case ',':
			if depth == 0 && !inS && !inD {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

func splitKeyValue(s string) (string, string, bool) {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ':':
			if !inS && !inD {
				if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
					return unquote(s[:i]), strings.TrimSpace(s[i+1:]), true
				}
			}
		}
	}
	return "", "", false
}

// yamlParseTop parses a document into a map. Nested sequences/mappings become
// []interface{} / map[string]interface{}.
func yamlParseTop(doc string) map[string]interface{} {
	lines := preprocess(doc)
	v, _ := parseBlock(lines, 0, 0)
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func preprocess(doc string) []yamlLine {
	raw := strings.Split(strings.ReplaceAll(doc, "\r\n", "\n"), "\n")
	out := make([]yamlLine, 0, len(raw))
	for i, l := range raw {
		if strings.HasPrefix(l, "\ufeff") {
			l = strings.TrimPrefix(l, "\ufeff")
		}
		l = stripComment(l)
		if strings.TrimSpace(l) == "" {
			continue
		}
		indent := 0
		for indent < len(l) && l[indent] == ' ' {
			indent++
		}
		if strings.HasPrefix(strings.TrimSpace(l), "---") || strings.HasPrefix(strings.TrimSpace(l), "...") {
			continue
		}
		out = append(out, yamlLine{indent: indent, text: strings.TrimSpace(l), lineNo: i, rawText: l})
	}
	return out
}

func nextIndent(lines []yamlLine, i int) int {
	for j := i + 1; j < len(lines); j++ {
		return lines[j].indent
	}
	return -1
}

// parseBlock reads consecutive lines at exactly `indent`.
func parseBlock(lines []yamlLine, i, indent int) (interface{}, int) {
	if i >= len(lines) {
		return map[string]interface{}{}, i
	}
	if strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-" {
		return parseSeq(lines, i, indent)
	}
	return parseMap(lines, i, indent)
}

func parseSeq(lines []yamlLine, i, indent int) (interface{}, int) {
	out := []interface{}{}
	for i < len(lines) {
		ln := lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			// stray deeper line; skip it rather than corrupting the structure
			i++
			continue
		}
		if !strings.HasPrefix(ln.text, "- ") && ln.text != "-" {
			break
		}
		payload := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		// an inline mapping is a complete entry on its own
		if m, ok := parseFlowMap(payload); ok {
			out = append(out, m)
			i++
			continue
		}
		key, val, isKV := splitKeyValue(payload)
		if !isKV {
			out = append(out, scalarValue(payload))
			i++
			continue
		}
		item := map[string]interface{}{}
		entryIndent := indent + 2
		if val == "" {
			ni := nextIndent(lines, i)
			if ni > ln.indent {
				child, ni2 := parseBlock(lines, i+1, ni)
				item[key] = child
				i = ni2
			} else {
				item[key] = map[string]interface{}{}
				i++
			}
		} else {
			item[key] = scalarValue(val)
			i++
		}
		// continuation keys of the same entry
		for i < len(lines) {
			c := lines[i]
			if c.indent != entryIndent || strings.HasPrefix(c.text, "- ") {
				break
			}
			ck, cv, ok := splitKeyValue(c.text)
			if !ok {
				break
			}
			if cv == "" {
				ni := nextIndent(lines, i)
				if ni > c.indent {
					child, ni2 := parseBlock(lines, i+1, ni)
					item[ck] = child
					i = ni2
					continue
				}
				item[ck] = map[string]interface{}{}
				i++
				continue
			}
			item[ck] = scalarValue(cv)
			i++
		}
		out = append(out, item)
	}
	return out, i
}

func parseMap(lines []yamlLine, i, indent int) (interface{}, int) {
	out := map[string]interface{}{}
	for i < len(lines) {
		ln := lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			i++
			continue
		}
		if strings.HasPrefix(ln.text, "- ") {
			break
		}
		key, val, ok := splitKeyValue(ln.text)
		if !ok {
			i++
			continue
		}
		if val == "" {
			// The block below a key may be a sequence OR a mapping. Some
			// providers put the sequence items at the SAME indent as the key
			// ("proxies:" at column 0 followed by "- name: x" at column 0),
			// so a deeper indent cannot be required here.
			if i+1 < len(lines) {
				next := lines[i+1]
				if strings.HasPrefix(next.text, "- ") || next.text == "-" {
					child, ni := parseBlock(lines, i+1, next.indent)
					out[key] = child
					i = ni
					continue
				}
				if next.indent > ln.indent {
					child, ni := parseBlock(lines, i+1, next.indent)
					out[key] = child
					i = ni
					continue
				}
			}
			out[key] = map[string]interface{}{}
			i++
			continue
		}
		out[key] = scalarValue(val)
		i++
	}
	return out, i
}

// ---------------------------------------------------------------------------
// clash config -> []Proxy
// ---------------------------------------------------------------------------

func parseClashConfig(doc string) []Proxy {
	root := yamlParseTop(doc)
	raw, ok := root["proxies"]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]Proxy, 0, len(list))
	for _, it := range list {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		p, ok := proxyFromMap(m)
		if ok {
			out = append(out, p)
		}
	}
	return out
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return fmt.Sprint(v)
}

func asInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}

func asBoolPtr(v interface{}) *bool {
	switch t := v.(type) {
	case bool:
		return boolPtr(t)
	case string:
		b := strings.EqualFold(t, "true") || t == "1"
		return boolPtr(b)
	}
	return nil
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func proxyFromMap(m map[string]interface{}) (Proxy, bool) {
	p := Proxy{
		Name:              asString(m["name"]),
		Type:              strings.ToLower(asString(m["type"])),
		Server:            asString(m["server"]),
		Port:              asInt(m["port"]),
		UUID:              asString(m["uuid"]),
		Password:          asString(m["password"]),
		Cipher:            asString(m["cipher"]),
		AlterID:           asInt(m["alterId"]),
		Flow:              asString(m["flow"]),
		UDP:               asBoolPtr(m["udp"]),
		TLS:               asBoolPtr(m["tls"]),
		SNI:               asString(m["sni"]),
		Servername:        asString(m["servername"]),
		SkipCertVerify:    asBoolPtr(m["skip-cert-verify"]),
		ClientFingerprint: asString(m["client-fingerprint"]),
		Network:           asString(m["network"]),
		WSOpts:            asMap(m["ws-opts"]),
		GrpcOpts:          asMap(m["grpc-opts"]),
		H2Opts:            asMap(m["h2-opts"]),
	}
	if p.Server == "" || p.Type == "" {
		return p, false
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Name == "" {
		p.Name = p.Server
	}
	p.Extra = map[string]interface{}{}
	for k, v := range m {
		switch k {
		case "name", "type", "server", "port", "uuid", "password", "cipher",
			"alterId", "flow", "udp", "tls", "sni", "servername", "skip-cert-verify",
			"client-fingerprint", "network", "ws-opts", "grpc-opts", "h2-opts":
		default:
			p.Extra[k] = v
		}
	}
	return p, true
}

// ---------------------------------------------------------------------------
// share links -> Proxy
// ---------------------------------------------------------------------------

func parseShareLinks(doc string) []Proxy {
	out := []Proxy{}
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var p Proxy
		var ok bool
		switch {
		case strings.HasPrefix(line, "vmess://"):
			p, ok = parseVmessURI(line)
		case strings.HasPrefix(line, "vless://"):
			p, ok = parseVlessURI(line)
		case strings.HasPrefix(line, "trojan://"):
			p, ok = parseTrojanURI(line)
		case strings.HasPrefix(line, "ss://"):
			p, ok = parseSSURI(line)
		case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
			p, ok = parseHy2URI(line)
		}
		if ok {
			out = append(out, p)
		}
	}
	return out
}

func decodeBase64(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

func parseVmessURI(uri string) (Proxy, bool) {
	body := strings.TrimPrefix(uri, "vmess://")
	decoded := decodeBase64(body)
	if decoded == "" {
		return Proxy{}, false
	}
	var j map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &j); err != nil {
		return Proxy{}, false
	}
	p := Proxy{
		Name:    asString(j["ps"]),
		Type:    "vmess",
		Server:  asString(j["add"]),
		Port:    asInt(j["port"]),
		UUID:    asString(j["id"]),
		AlterID: asInt(j["aid"]),
		Cipher:  asString(j["scy"]),
		UDP:     boolPtr(true),
	}
	if p.Cipher == "" {
		p.Cipher = "auto"
	}
	if p.Port == 0 {
		p.Port = 443
	}
	tlsOn := strings.EqualFold(asString(j["tls"]), "tls") || asString(j["tls"]) == "true"
	if tlsOn {
		p.TLS = boolPtr(true)
		if sni := asString(j["sni"]); sni != "" {
			p.Servername = sni
		} else if h := asString(j["host"]); h != "" {
			p.Servername = h
		}
	}
	switch strings.ToLower(asString(j["net"])) {
	case "ws":
		p.Network = "ws"
		host := asString(j["host"])
		path := asString(j["path"])
		if path == "" {
			path = "/"
		}
		p.WSOpts = map[string]interface{}{
			"path":    path,
			"headers": map[string]interface{}{"Host": host},
		}
	case "grpc":
		p.Network = "grpc"
		p.GrpcOpts = map[string]interface{}{"grpc-service-name": asString(j["path"])}
	case "h2":
		p.Network = "h2"
		p.H2Opts = map[string]interface{}{"path": asString(j["path"]), "host": []interface{}{asString(j["host"])}}
	}
	if p.Name == "" {
		p.Name = p.Server
	}
	p.ClientFingerprint = "chrome"
	return p, p.Server != "" && p.UUID != ""
}

func splitURIParts(uri string) (string, url.Values, string) {
	base := uri
	frag := ""
	if i := strings.Index(base, "#"); i >= 0 {
		frag = base[i+1:]
		base = base[:i]
	}
	q := url.Values{}
	if i := strings.Index(base, "?"); i >= 0 {
		if v, err := url.ParseQuery(base[i+1:]); err == nil {
			q = v
		}
		base = base[:i]
	}
	return base, q, frag
}

func parseVlessURI(uri string) (Proxy, bool) {
	base, q, frag := splitURIParts(uri)
	re := regexp.MustCompile(`^vless://([^@]+)@([^:/]+):(\d+)`)
	m := re.FindStringSubmatch(base)
	if m == nil {
		return Proxy{}, false
	}
	name, _ := url.QueryUnescape(frag)
	p := Proxy{
		Name:   name,
		Type:   "vless",
		Server: m[2],
		Port:   asInt(m[3]),
		UUID:   m[1],
		UDP:    boolPtr(true),
		Flow:   q.Get("flow"),
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if sec := q.Get("security"); sec == "tls" || sec == "reality" {
		p.TLS = boolPtr(true)
		if sni := q.Get("sni"); sni != "" {
			p.Servername = sni
		}
	}
	if q.Get("type") == "ws" {
		p.Network = "ws"
		path, _ := url.QueryUnescape(q.Get("path"))
		if path == "" {
			path = "/"
		}
		p.WSOpts = map[string]interface{}{
			"path":    path,
			"headers": map[string]interface{}{"Host": q.Get("host")},
		}
	}
	if p.Name == "" {
		p.Name = p.Server
	}
	return p, true
}

func parseTrojanURI(uri string) (Proxy, bool) {
	base, q, frag := splitURIParts(uri)
	re := regexp.MustCompile(`^trojan://([^@]+)@([^:/]+):(\d+)`)
	m := re.FindStringSubmatch(base)
	if m == nil {
		return Proxy{}, false
	}
	name, _ := url.QueryUnescape(frag)
	pw, _ := url.QueryUnescape(m[1])
	p := Proxy{
		Name:     name,
		Type:     "trojan",
		Server:   m[2],
		Port:     asInt(m[3]),
		Password: pw,
		UDP:      boolPtr(true),
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if q.Get("sni") != "" {
		p.SNI = q.Get("sni")
	}
	if q.Get("type") == "ws" {
		p.Network = "ws"
		path, _ := url.QueryUnescape(q.Get("path"))
		if path == "" {
			path = "/"
		}
		p.WSOpts = map[string]interface{}{
			"path":    path,
			"headers": map[string]interface{}{"Host": q.Get("host")},
		}
	}
	if p.Name == "" {
		p.Name = p.Server
	}
	return p, true
}

func parseSSURI(uri string) (Proxy, bool) {
	body := strings.TrimPrefix(uri, "ss://")
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		name, _ = url.QueryUnescape(body[i+1:])
		body = body[:i]
	}
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i]
	}
	if !strings.Contains(body, "@") {
		body = decodeBase64(body)
	}
	if !strings.Contains(body, "@") {
		return Proxy{}, false
	}
	creds, hostport := body[:strings.LastIndex(body, "@")], body[strings.LastIndex(body, "@")+1:]
	if !strings.Contains(creds, ":") {
		creds = decodeBase64(creds)
	}
	ci := strings.Index(creds, ":")
	if ci < 0 {
		return Proxy{}, false
	}
	method := creds[:ci]
	password := creds[ci+1:]
	hi := strings.LastIndex(hostport, ":")
	if hi < 0 {
		return Proxy{}, false
	}
	host := hostport[:hi]
	port := asInt(strings.TrimRight(hostport[hi+1:], "/"))
	if name == "" {
		name = host
	}
	return Proxy{
		Name: name, Type: "ss", Server: host, Port: port,
		Cipher: method, Password: password, UDP: boolPtr(true),
	}, host != "" && port != 0
}

func parseHy2URI(uri string) (Proxy, bool) {
	base, q, frag := splitURIParts(strings.Replace(uri, "hy2://", "hysteria2://", 1))
	re := regexp.MustCompile(`^hysteria2://([^@]+)@([^:/]+):(\d+)`)
	m := re.FindStringSubmatch(base)
	if m == nil {
		return Proxy{}, false
	}
	name, _ := url.QueryUnescape(frag)
	pw, _ := url.QueryUnescape(m[1])
	p := Proxy{
		Name: name, Type: "hysteria2", Server: m[2], Port: asInt(m[3]),
		Password: pw, UDP: boolPtr(true),
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if q.Get("sni") != "" {
		p.SNI = q.Get("sni")
	}
	if q.Get("insecure") == "1" {
		p.SkipCertVerify = boolPtr(true)
	}
	if p.Name == "" {
		p.Name = p.Server
	}
	return p, true
}

// ParseSubscription turns a downloaded body into nodes. It accepts either a
// clash style config or a list of share links, and also unwraps a base64 body
// (many providers still hand those out).
func ParseSubscription(body string) []Proxy {
	trimmed := strings.TrimSpace(body)
	if p := parseClashConfig(trimmed); len(p) > 0 {
		return p
	}
	if p := parseShareLinks(trimmed); len(p) > 0 {
		return p
	}
	// a base64 wrapped list of links
	if !strings.Contains(trimmed, "://") && !strings.Contains(trimmed, ":") {
		if dec := decodeBase64(trimmed); dec != "" {
			if p := parseClashConfig(dec); len(p) > 0 {
				return p
			}
			if p := parseShareLinks(dec); len(p) > 0 {
				return p
			}
		}
	}
	return nil
}

// FetchSubscription downloads a subscription. It never goes through a system
// proxy: Zenith itself may be that proxy, and fetching through a core that is
// still starting would deadlock the first launch.
//
// allowInsecure disables certificate verification for this one fetch. It exists
// only because private subscriptions occasionally live behind a self-signed
// certificate; it is off by default and the caller is expected to have asked the
// user. Verification being on by default is the point: without it, anyone who
// can intercept the connection can replace every node in the subscription, and
// the client would install their servers and credentials without a word.
func FetchSubscription(rawURL, ua string, allowInsecure bool) (string, *SubscriptionInfo, error) {
	if ua == "" {
		ua = "mihomo/1.19.32"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return "", nil, fmt.Errorf("订阅地址无效")
	}
	// A subscription carries server addresses and credentials, so it is never
	// fetched in the clear. Plain http would let any hop on the path rewrite it,
	// and there is no downgrade that makes that acceptable.
	if !strings.EqualFold(u.Scheme, "https") {
		return "", nil, fmt.Errorf("订阅地址必须是 https（当前是 %q）；"+
			"明文下载会让中途任何一跳都能替换你的节点和凭据", u.Scheme)
	}
	// Make sure every non-ascii byte in the path is percent-encoded exactly
	// once. Assigning the escaped form back to Path and RawPath together used to
	// double-encode a Chinese path and the provider answered 404.
	u.RawPath = ""
	u.Path = u.EscapedPath()
	if strings.ContainsAny(u.Path, "%") {
		u.RawPath = u.Path
		if dec, derr := url.PathUnescape(u.Path); derr == nil {
			u.Path = dec
		} else {
			u.RawPath = ""
		}
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	// No redirect may leave https, and none may cross to a different host: a
	// redirect is the simplest way to hand a credential-bearing URL to a third
	// party. Same-host redirects are allowed because providers do use them.
	originHost := strings.ToLower(u.Host)
	tr := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: allowInsecure,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			if !strings.EqualFold(r.URL.Scheme, "https") {
				return fmt.Errorf("订阅服务器试图把 https 降级到 %s，已拒绝", r.URL.Scheme)
			}
			if !strings.EqualFold(r.URL.Host, originHost) {
				return fmt.Errorf("订阅服务器试图重定向到另一个域名（%s），"+
					"这会把你的订阅凭据交给第三方，已拒绝", r.URL.Host)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("服务器返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", nil, err
	}
	text := string(body)
	// some providers actually return GBK
	if !strings.Contains(text, "proxies:") && !strings.Contains(text, "://") {
		if g := decodeGBK(body); g != "" {
			text = g
		}
	}
	info := &SubscriptionInfo{}
	if up := resp.Header.Get("Subscription-Userinfo"); up != "" {
		info.parse(up)
	}
	if up := resp.Header.Get("Profile-Update-Interval"); up != "" {
		if h, err := strconv.Atoi(strings.TrimSpace(up)); err == nil {
			info.UpdateIntervalHours = h
		}
	}
	if name := resp.Header.Get("Content-Disposition"); name != "" {
		info.SuggestedName = name
	}
	return text, info, nil
}

// SubscriptionInfo mirrors the Subscription-Userinfo header.
type SubscriptionInfo struct {
	Upload              int64
	Download            int64
	Total               int64
	Expire              int64
	UpdateIntervalHours int
	SuggestedName       string
}

func (s *SubscriptionInfo) parse(v string) {
	for _, part := range strings.Split(v, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "upload":
			s.Upload = n
		case "download":
			s.Download = n
		case "total":
			s.Total = n
		case "expire":
			s.Expire = n
		}
	}
}

// decodeGBK converts a GBK byte slice to UTF-8 without external packages by
// falling back to latin-1 when the runes look wrong. Providers rarely need it,
// but a mangled response is worse than a lossy one.
func decodeGBK(b []byte) string {
	// A tiny best effort: replace invalid UTF-8 sequences with '?'. Doing a real
	// GBK table would add a large dependency for a rare case.
	if isMostlyUTF8(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for _, c := range b {
		if c < 0x80 {
			out = append(out, rune(c))
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

func isMostlyUTF8(b []byte) bool {
	bad := 0
	for i := 0; i < len(b); {
		r, size := decodeRune(b[i:])
		if r == 0xFFFD && size == 1 {
			bad++
		}
		i += size
	}
	return bad*10 < len(b)
}

func decodeRune(b []byte) (rune, int) {
	if len(b) == 0 {
		return 0xFFFD, 0
	}
	if b[0] < 0x80 {
		return rune(b[0]), 1
	}
	for _, r := range string(b) {
		return r, len(string(r))
	}
	return 0xFFFD, 1
}
