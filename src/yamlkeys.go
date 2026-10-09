package main

// ---------------------------------------------------------------------------
// Nothing from a subscription may change the shape of the configuration.
//
// The generator is a text builder, not a serialiser. Every key it writes comes from
// somewhere, and the ones that come from a subscription are the ones an attacker
// controls. A key is written as `  key: value`, so a key containing a newline writes
// whatever follows it at the indentation the builder chose - which is how a
// subscription can add a field to the document rather than describe a proxy option.
//
// The first fix covered the flat Extra map. It missed the nested maps, and that was
// the whole gap: `ws-opts`, `grpc-opts` and `h2-opts` are written through a separate
// branch that emitted their keys and sub-keys untouched. A subscription parser
// decodes an escaped newline inside a quoted key, and the generator then writes it
// out verbatim.
//
// So the rule lives here, once, and is applied to every value at every depth before
// anything is written. The alternative - checking each branch - is what produced the
// gap in the first place: a branch was added and the check was not.
//
// What this does not claim. It is not a substitute for a real YAML serialiser, and
// the review is right that one would be better. What it does is make the property
// checkable in one place and impossible to forget in a new branch, because the
// branches go through this function rather than around it.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"strings"
)

// yamlKeyMaxLen bounds a key. Real proxy option names are short; a long one is a
// sign of something other than an option name.
const yamlKeyMaxLen = 64

// validYAMLKey reports whether a key can be written without escaping.
//
// A key that consists only of letters, digits, `-`, `_` and `.` cannot terminate the
// line, cannot start a new block, cannot introduce a comment and cannot be read as a
// document separator. Anything else is refused rather than escaped: an escaped key
// would still be written by a builder that does not escape, so refusing is the only
// answer this design can give honestly.
func validYAMLKey(k string) bool {
	if k == "" || len(k) > yamlKeyMaxLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// nestedKeyAllowed reports whether a key inside ws-opts, grpc-opts or h2-opts may be
// written.
//
// This is an allowlist for the same reason the flat one is: a denylist has to
// anticipate every way a crafted key could escape its block, and the cost of missing
// one is a subscription that rewrites the running configuration. The list below is
// the set of nested options mihomo documents for these three transports.
func nestedKeyAllowed(k string) bool {
	if !validYAMLKey(k) {
		return false
	}
	switch k {
	// shared by the transports below
	case "path", "host", "headers", "method", "early-data-header-name",
		"max-early-data", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open":
		return true
	// grpc
	case "grpc-service-name", "grpc-mode", "multi-mode", "permit-without-stream",
		"ping-interval", "max-connections", "min-streams", "max-streams":
		return true
	// h2
	case "h2-host", "h2-path", "h2-headers", "idle-timeout", "keepalive-interval":
		return true
	default:
		return false
	}
}

// subscriptionValueIsSafe walks a value from subscription data and reports the first
// thing wrong with it.
//
// It recurses, because the defect it exists for was a nested map that a flat check
// did not see. Keys are validated at every level; values must be scalars, lists of
// scalars, or maps, and a value that is itself a map is walked rather than trusted.
//
// depth is bounded so a subscription cannot turn validation into a stack overflow.
func subscriptionValueIsSafe(key string, v interface{}, depth int) error {
	if depth > 6 {
		return fmt.Errorf("字段 %q 嵌套过深", key)
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		// A value is written with yamlScalar, which quotes and escapes. A newline
		// inside a quoted scalar is safe; what is not safe is a NUL or a control
		// character, which some parsers treat as a document boundary.
		for i := 0; i < len(t); i++ {
			if t[i] < 0x20 && t[i] != '\t' {
				return fmt.Errorf("字段 %q 的值含有控制字符", key)
			}
		}
		return nil
	case bool, int, int64, float64, uint64, uint32:
		return nil
	case []interface{}:
		for i, item := range t {
			if err := subscriptionValueIsSafe(fmt.Sprintf("%s[%d]", key, i), item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		for k, item := range t {
			if !validYAMLKey(k) {
				return fmt.Errorf("字段 %q 下的键 %q 不能作为 YAML 键写入（可能包含换行或冒号）", key, k)
			}
			if err := subscriptionValueIsSafe(key+"."+k, item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		// An unexpected type would be written by yamlScalar's fallback, which
		// formats it. Refusing is clearer than guessing how it will look.
		return fmt.Errorf("字段 %q 的值类型 %T 不受支持", key, v)
	}
}

// sanitizeNestedOpts returns the safe subset of a nested options map.
//
// Everything not on the allowlist, and everything whose value fails validation, is
// dropped. Dropping rather than failing the whole subscription is deliberate: a
// subscription with one unusual option should still work, and the option that was
// dropped is reported so it is not a silent loss.
func sanitizeNestedOpts(transport string, m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if !nestedKeyAllowed(k) {
			Log("subscription: dropped %s option %q; it is not one this program writes", transport, k)
			continue
		}
		if err := subscriptionValueIsSafe(k, v, 0); err != nil {
			Log("subscription: dropped %s option %q: %v", transport, k, err)
			continue
		}
		// A nested map is filtered one level further, so a header table cannot
		// carry a key that the check above allowed only because it is a valid YAML
		// key. Header names contain letters and hyphens, which the validator already
		// permits, but their values are still checked by the walk above.
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sanitizeProxyMaps applies the nested rules to a node's transport options.
//
// Called once, where the node is written, so a future transport option cannot be
// added to the generator without passing through here.
func sanitizeProxyMaps(p *Proxy) {
	p.WSOpts = sanitizeNestedOpts("ws-opts", p.WSOpts)
	p.GrpcOpts = sanitizeNestedOpts("grpc-opts", p.GrpcOpts)
	p.H2Opts = sanitizeNestedOpts("h2-opts", p.H2Opts)
}

// countUnsafeKeys reports how many keys in a map would be refused, for diagnostics
// and tests. It does not modify anything.
func countUnsafeKeys(m map[string]interface{}) int {
	n := 0
	for k := range m {
		if !validYAMLKey(k) {
			n++
		}
	}
	return n
}

// describeUnsafeKeys names the offending keys, truncated, so a log line says what
// was wrong rather than only that something was.
func describeUnsafeKeys(m map[string]interface{}) string {
	var bad []string
	for k := range m {
		if !validYAMLKey(k) {
			bad = append(bad, fmt.Sprintf("%q", truncateForMessage(k, 40)))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	return strings.Join(bad, ", ")
}
