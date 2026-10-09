package main

// ---------------------------------------------------------------------------
// Masking credentials in the configuration preview.
//
// The rules editor shows the generated configuration so a user can see what their
// rules produce. That preview contained everything: the core's control secret, every
// node UUID and password, and the WebSocket paths. It is behind the token, but the
// token is not an account boundary - so what the interface hands out should not be a
// credential even to a legitimate caller.
//
// Redaction rather than omission: the shape is the useful part. Replacing values with
// a fixed marker keeps the preview editable and honest, and it means a screenshot or a
// pasted log line no longer carries the ability to use the nodes.
//
// This used to live in a file about privacy mode, which is gone. It was never about
// privacy mode; it is about the preview not carrying credentials.
// ---------------------------------------------------------------------------

import (
	"strings"
)

// RedactConfigForDisplay masks the credentials in a generated configuration while
// leaving its structure intact.
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
// The list is explicit rather than heuristic. A heuristic that redacted anything that
// looked secret would eventually redact a rule or a node name and make the preview
// useless for the thing it exists for.
func redactConfigLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return line
	}
	indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	body := strings.TrimLeft(line, " \t")
	colon := strings.Index(body, ":")
	if colon <= 0 {
		return line
	}
	key := strings.TrimSpace(body[:colon])
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
		// it would make the preview less useful than the leak it prevents is harmful.
		// Recorded here so the decision is visible rather than accidental.
		return line
	}
	// A bare scalar that looks like a UUID and is not behind a known key - for example
	// a share link written into a rule. Masked, because a UUID is the one credential
	// shape that survives being quoted into another field.
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
