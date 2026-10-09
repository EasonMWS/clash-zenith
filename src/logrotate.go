package main

// ---------------------------------------------------------------------------
// Log rotation.
//
// Both logs grow forever otherwise, and this client is meant to run for weeks.
// The core's log is the worse of the two: at info level it writes a line per
// connection, which on a busy machine is megabytes a day, and a disk that fills
// up takes down far more than the log.
//
// The scheme is deliberately simple and self-contained: a size cap and a small
// number of rotated files. One rotation check per write, and no separate
// goroutine, because a log that can block the thing it is logging is worse than
// a log that grows.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	// A megabyte per file with five kept is a bounded few megabytes, comfortable
	// for a diagnostic record and irrelevant to disk usage.
	logMaxBytes  = 2 << 20 // 2 MB
	logKeepFiles = 4       // zenith.log.1 .. .4
)

var (
	rotateMu sync.Mutex
	logSizes = map[string]int64{}
)

// rotateIfNeeded checks the size of a log and rotates it when it has grown past
// the cap.
//
// It is called before every append rather than on a timer, so a burst of output
// cannot outrun it. The size is tracked in memory and re-read from disk on the
// first write after start-up, so a log inherited from a previous run is not
// allowed to grow unbounded just because this process did not see it fill up.
func rotateIfNeeded(path string) {
	if path == "" {
		return
	}
	rotateMu.Lock()
	defer rotateMu.Unlock()

	size, known := logSizes[path]
	if !known {
		if st, err := os.Stat(path); err == nil {
			size = st.Size()
		}
	}
	if size < logMaxBytes {
		logSizes[path] = size
		return
	}

	// Shift zenith.log.(n-1) -> zenith.log.n, oldest dropped, then the live file
	// becomes .1 and a fresh one is started.
	for i := logKeepFiles - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", path, i)
		to := fmt.Sprintf("%s.%d", path, i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	_ = os.Rename(path, path+".1")
	logSizes[path] = 0
}

// accountLogWrite keeps the in-memory size in step with what was written.
func accountLogWrite(path string, n int) {
	if path == "" || n <= 0 {
		return
	}
	rotateMu.Lock()
	logSizes[path] += int64(n)
	rotateMu.Unlock()
}

// logRotatedFiles lists the rotated companions of a log, newest first. Used by
// the diagnostics view so a user can see the history without the app having to
// concatenate it in memory.
func logRotatedFiles(path string) []string {
	var out []string
	for i := 1; i <= logKeepFiles; i++ {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		// .1 is the most recent rotation, so sort numerically ascending.
		return strings.TrimPrefix(out[i], path+".") < strings.TrimPrefix(out[j], path+".")
	})
	return out
}

// logDirUsage reports how much the log directory occupies, which is the number a
// user actually cares about.
func logDirUsage(dir string) int64 {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}

// ---- redaction ------------------------------------------------------------

// Redaction exists because the two things most likely to end up in a log by
// accident are the subscription URL - which is a bearer credential, not an
// address - and node identifiers. Both are the user's secrets, and a log is the
// easiest file to hand to somebody while asking for help.
//
// The rule is deliberately conservative: it rewrites anything that looks like a
// credential-bearing URL, and leaves ordinary text alone so the log stays
// readable.
var redactHosts = []string{
	// host substrings that mark a line as carrying subscription material
}

// redactLine removes credentials from a log line before it is written or shown.
func redactLine(line string) string {
	return redactURLs(line)
}

// redactURLs shortens any http(s) URL that carries a path, keeping the host so
// the line is still useful for diagnosis.
//
// A subscription URL looks like https://host/token where the token is the whole
// secret. Replacing the path with a marker keeps "which provider" while dropping
// "which credential".
func redactURLs(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		j := strings.Index(s[i:], "http")
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		// Only treat it as a URL if it is followed by ://, so "http_proxy" and
		// ordinary prose survive.
		if !strings.HasPrefix(s[j:], "http://") && !strings.HasPrefix(s[j:], "https://") {
			b.WriteString(s[i : j+4])
			i = j + 4
			continue
		}
		b.WriteString(s[i:j])
		end := j
		for end < len(s) && !isURLTerminator(s[end]) {
			end++
		}
		b.WriteString(shortenURL(s[j:end]))
		i = end
	}
	return b.String()
}

func isURLTerminator(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"' || c == '\'' ||
		c == ')' || c == ']' || c == '}' || c == ',' || c == '<' || c == '>' || c == '|'
}

// shortenURL keeps the scheme and host, and replaces a non-trivial path with a
// length marker. A URL with no path is left alone; there is no secret in it.
func shortenURL(u string) string {
	schemeEnd := strings.Index(u, "://")
	if schemeEnd < 0 {
		return u
	}
	rest := u[schemeEnd+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return u // no path, nothing to hide
	}
	host := rest[:slash]
	path := rest[slash:]
	if path == "/" || path == "" {
		return u
	}
	return u[:schemeEnd+3] + host + "/<redacted:" + fmt.Sprint(len(path)) + ">"
}

// redactForDisplay applies redaction to a block of text, used by the log viewer
// and by any future diagnostic export.
func redactForDisplay(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = redactLine(l)
	}
	return strings.Join(lines, "\n")
}

// logDirForUsage is a tiny helper so callers do not have to remember the layout.
func logDirForUsage(dataDir string) string {
	return filepath.Join(filepath.Dir(dataDir), "logs")
}
