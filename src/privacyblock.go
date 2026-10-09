package main

// ---------------------------------------------------------------------------
// A block that does not depend on the core staying alive.
//
// Privacy mode used to be expressed as `strict-route: true` in the generated
// configuration, plus a setting called TunBlockOnFailure that nothing ever read.
// The claim it made - "a dropped connection keeps refusing rather than falling
// back to direct" - therefore rested on a core option whose documented meaning is
// narrower than the claim: it suppresses multihomed DNS leakage, it is not a kill
// switch, and it does nothing at all once the core process is gone.
//
// Worse, the rollback path could restore a configuration from before TUN existed
// and restart the core on it, leaving the machine online and unprotected while the
// transaction record said "privacy block unchanged".
//
// What a block has to be, to mean anything:
//
//   - it survives the core exiting, being killed, or failing to start;
//   - it survives this program exiting entirely;
//   - it is a system policy, not a process watching a port;
//   - its actual state can be read back and verified, so the interface reports
//     what is enforced rather than what was requested.
//
// Windows Firewall rules are all four. They are keyed to the program, so they
// outlive every process involved, and `netsh` can report whether they exist.
//
// The direction of failure is deliberate. Lifting the block requires an explicit
// call with an explicit reason; nothing about restoring connectivity, rolling back
// an activation, or losing the core reaches the release path. A block that is in
// place and should not be is a nuisance the user can clear; a block that is absent
// when the user believes it is on is the failure this file exists to prevent.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"strings"
	"time"
)

// blockRulePrefix names every rule this program creates, so it can find exactly
// its own and nothing else. Another product's firewall rules are not ours to
// touch, the same way another product's adapter is not ours to remove.
const blockRulePrefix = "Zenith Privacy Block"

// blockRuleNames are the rules a block consists of.
//
// Two directions rather than one. An outbound block alone still leaves an inbound
// connection that was established before the block in place, and a tunnel that
// carries replies to something the user did not intend to allow is not a block.
func blockRuleNames() []string {
	return []string{
		blockRulePrefix + " (out)",
		blockRulePrefix + " (in)",
	}
}

// privacyBlockState is what is actually enforced, read back from the system.
type privacyBlockState struct {
	// Requested is what the settings asked for.
	Requested bool `json:"requested"`
	// Enforced is what the firewall reports. The interface uses this one.
	Enforced bool `json:"enforced"`
	// Detail explains a disagreement between the two, or why the state could not
	// be read.
	Detail string `json:"detail,omitempty"`
	// Rules lists the rule names found.
	Rules []string `json:"rules,omitempty"`
	// CheckedAt is when this was read.
	CheckedAt string `json:"checkedAt"`
}

// RedactConfigForDisplay masks the credentials in a generated configuration while
// leaving its structure intact.
//
// The rules editor shows the live configuration so a user can see what their rules
// produce. That preview contained everything: the core's control secret, every node
// UUID and password, and the WebSocket paths. It is behind the token, but the token
// is not an account boundary - so what the interface hands out should not be a
// credential even to a legitimate caller.
//
// Redaction rather than omission: the shape is the useful part. Replacing values
// with a fixed marker keeps the preview editable and honest, and it means a
// screenshot or a pasted log line no longer carries the ability to use the nodes.
func RedactConfigForDisplay(cfg string) string {
	if cfg == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(cfg))
	for _, line := range strings.Split(cfg, "\n") {
		b.WriteString(redactConfigLine(line))
		b.WriteByte('\n')
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// redactConfigLine masks one line if it carries a credential.
//
// The list is explicit rather than heuristic. A heuristic that redacted anything
// that looked secret would eventually redact a rule or a node name and make the
// preview useless for the thing it exists for.
func redactConfigLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return line
	}
	// Find the key, preserving the original indentation.
	indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	body := strings.TrimLeft(line, " \t")
	colon := strings.Index(body, ":")
	if colon <= 0 {
		return line
	}
	key := strings.TrimSpace(body[:colon])
	// A nested key arrives as "  something: value" inside a headers block; the key
	// alone is what matters.
	rest := body[colon+1:]

	switch key {
	case "secret", "uuid", "password":
		return indent + key + ": \"<hidden>\""
	case "path", "ws-path", "h2-path":
		// Only inside a transport block, but a bare `path:` at top level does not
		// exist in a generated configuration, so the key alone is a safe signal.
		return indent + key + ": \"<hidden>\""
	case "private-key", "public-key", "short-id", "psk":
		return indent + key + ": \"<hidden>\""
	case "Host", "host":
		// A subscription's WebSocket Host header names the provider's front domain.
		// The value is left alone: it is what the rule engine matches on, and hiding
		// it would make the preview less useful than the leak it prevents is
		// harmful. Recorded here so the decision is visible rather than accidental.
		return line
	}
	// A bare scalar that looks like a UUID and is not behind a known key - for
	// example a share link written into a rule. Masked, because a UUID is the one
	// credential shape that survives being quoted into another field.
	if uuidLike(rest) {
		return indent + key + ": \"<hidden>\""
	}
	return line
}

// uuidLike reports whether a value reads as a UUID, with or without quotes.
func uuidLike(v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if len(v) != 36 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// The check reads netsh's output for the rule's own name rather than relying on
// its exit code or on a localised "no rules match" sentence. Both of those were
// tried and both are wrong here:
//
//   - netsh exits 1 when a rule is absent, but it writes "No rules match the
//     specified criteria." to stdout and nothing to stderr. HiddenCommand treats a
//     non-zero exit with empty stderr and non-empty output as success, so the exit
//     code never reaches this function.
//   - the sentence is translated. On a Chinese Windows it reads
//     "没有与指定条件相匹配的规则。", so matching on the English text reports a rule
//     as present when it is absent - which for a block is the dangerous direction:
//     the interface would say "protected" because the query failed to understand
//     the answer.
//
// A rule that exists is echoed back with its name. That line is the same in every
// locale, so it is the thing to look for.
func blockRuleExists(name string) (bool, error) {
	out, err := HiddenCommand("netsh", "advfirewall", "firewall", "show", "rule",
		"name="+name)
	if err != nil {
		return false, fmt.Errorf("无法查询防火墙规则 %q：%v（%s）", name, err, strings.TrimSpace(out))
	}
	if out == "" {
		return false, fmt.Errorf("查询防火墙规则 %q 没有得到任何输出，无法判断它是否存在", name)
	}
	// The rule name appears in the output when a rule was found. Matching on the
	// name itself is what makes this independent of the message language.
	return strings.Contains(out, name), nil
}

// PrivacyBlockEnforced reports whether the block is actually in place.
//
// Both rules must be present. A half-applied block is reported as not enforced,
// because the state the user cares about is "nothing gets out", and one rule does
// not deliver that.
func PrivacyBlockEnforced() (bool, []string, error) {
	var present []string
	for _, name := range blockRuleNames() {
		ok, err := blockRuleExists(name)
		if err != nil {
			return false, present, err
		}
		if ok {
			present = append(present, name)
		}
	}
	return len(present) == len(blockRuleNames()), present, nil
}

// ApplyPrivacyBlock installs the block.
//
// It needs elevation, which is why it runs inside the elevated activation rather
// than from the window: the block is a system policy and creating one is an
// administrative act.
//
// Idempotent: applying a block that is already there is not an error, because the
// activation may be retried and a user may press the button twice.
func ApplyPrivacyBlock(reason string) error {
	if enforced, _, err := PrivacyBlockEnforced(); err == nil && enforced {
		Log("privacy block is already in place (%s)", reason)
		return nil
	}
	for _, name := range blockRuleNames() {
		dir := "out"
		if strings.HasSuffix(name, "(in)") {
			dir = "in"
		}
		action := "block"
		// One rule per direction, each blocking that direction outright. No
		// program, port or address exemptions: the point of the mode is that
		// protected traffic leaves only through an approved route, and enumerating
		// what to allow is how a bypass gets introduced later by someone who does
		// not know why a rule was there.
		if out, err := HiddenCommand("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name,
			"dir="+dir,
			"action="+action,
			"enable=yes",
			"profile=any",
			"description=Zenith privacy mode: protected traffic must not leave outside the tunnel. "+
				"Removing this rule turns the protection off.",
		); err != nil {
			return fmt.Errorf("无法建立防火墙规则 %q：%v（%s）", name, err, strings.TrimSpace(out))
		}
	}
	// Read back rather than trust the command. A block that was asked for and not
	// applied is the failure this whole file is about.
	ok, present, err := PrivacyBlockEnforced()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("防火墙规则已下发但没有生效，实际存在 %d/%d 条",
			len(present), len(blockRuleNames()))
	}
	Log("privacy block applied and verified: %s", reason)
	return nil
}

// ReleasePrivacyBlock removes the block.
//
// This is the only path that removes it, and it takes a reason so the log says who
// decided. Every other code path - rolling back a failed activation, restoring a
// previous configuration, the core dying, the program exiting - leaves it in place
// on purpose.
func ReleasePrivacyBlock(reason string) error {
	removed := 0
	var firstErr error
	for _, name := range blockRuleNames() {
		ok, err := blockRuleExists(name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !ok {
			continue
		}
		if out, err := HiddenCommand("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+name); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("无法删除防火墙规则 %q：%v（%s）", name, err, strings.TrimSpace(out))
			}
			continue
		}
		removed++
	}
	ok, _, err := PrivacyBlockEnforced()
	if err != nil && firstErr == nil {
		firstErr = err
	}
	if ok {
		return fmt.Errorf("阻断规则仍然生效，释放没有成功；请手动检查防火墙规则 %q",
			blockRulePrefix)
	}
	Log("privacy block released (%s): %d rule(s) removed", reason, removed)
	return firstErr
}

// PrivacyBlockStatus reads what is enforced and compares it with what was asked.
//
// The reported state is the enforced one. If they disagree the detail says so,
// because "the setting says on and the system says off" is the exact condition a
// user must not have to guess about.
func (a *App) PrivacyBlockStatus() privacyBlockState {
	st := a.store.Settings()
	out := privacyBlockState{
		Requested: st.TunMode == TunPrivacy && st.TunBlockOnFailure,
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	enforced, rules, err := PrivacyBlockEnforced()
	out.Enforced = enforced
	out.Rules = rules
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	switch {
	case out.Requested && !enforced:
		out.Detail = fmt.Sprintf("隐私模式要求阻断，但系统上找不到防火墙规则（%s）。"+
			"这通常意味着激活没有拿到管理员权限，或者规则被其他程序删除了。"+
			"在这个状态下流量不受阻断保护", blockRulePrefix)
	case !out.Requested && enforced:
		out.Detail = fmt.Sprintf("阻断规则仍然生效（%s），但设置里没有要求。"+
			"这通常是上一次隐私模式退出时释放失败。网络会被全部阻断，直到释放它",
			blockRulePrefix)
	default:
		out.Detail = "阻断状态与设置一致"
	}
	return out
}
