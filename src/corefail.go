package main

// ---------------------------------------------------------------------------
// Saying why the core would not start.
//
// The startup wait had two defects and they compounded. The obvious one: it
// checked cmd.ProcessState to notice the child dying, but that field stays nil
// until Wait is called, so the branch never fired and every failure waited out the
// full deadline. The one behind it: whatever the reason, the message was the same
// sentence pointing at a log file.
//
// The review's ask was to tell port conflicts, authentication failures,
// configuration errors and driver failures apart rather than reporting a timeout
// for all of them - so this reads what the core actually said, maps it to a
// condition, and each condition carries the next thing to do.
//
// The classification is by evidence, not by guessing: it looks for the specific
// strings mihomo emits for each case and admits when it does not recognise the
// output rather than picking the closest match.
// ---------------------------------------------------------------------------

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// coreFailure names what went wrong, in terms a user can act on.
type coreFailure int

const (
	coreFailureUnknown coreFailure = iota
	coreFailurePortInUse
	coreFailureAuth
	coreFailureConfig
	coreFailureDriver
	coreFailureGeodata
	coreFailureMissingBinary
)

// Label is the short form used in the interface.
func (f coreFailure) Label() string {
	switch f {
	case coreFailurePortInUse:
		return "端口冲突"
	case coreFailureAuth:
		return "认证失败"
	case coreFailureConfig:
		return "配置错误"
	case coreFailureDriver:
		return "驱动失败"
	case coreFailureGeodata:
		return "规则库缺失"
	case coreFailureMissingBinary:
		return "缺少内核"
	default:
		return "未知原因"
	}
}

// Advice is what the user should do about it. A failure without a next step is a
// failure the user cannot act on.
func (f coreFailure) Advice() string {
	switch f {
	case coreFailurePortInUse:
		return "另一个程序占用了配置里的监听端口。关闭占用它的程序，或在设置里换一个端口"
	case coreFailureAuth:
		return "控制密码与内核不一致。删除 data/control.secret 后重新启动 Zenith 会让两边重新生成一致的密码"
	case coreFailureConfig:
		return "生成的配置被内核拒绝。这通常是节点或规则的问题，界面上的错误信息里有内核的原话"
	case coreFailureDriver:
		return "创建虚拟网卡失败。最常见的原因是授权没有真正生效——网卡和路由需要管理员权限"
	case coreFailureGeodata:
		return "规则数据库缺失或被截断。重新下载完整的发布包可以修复"
	case coreFailureMissingBinary:
		return "core/mihomo.exe 不存在。请从发布包中完整解压，不要只复制主程序"
	default:
		return "请查看 logs/engine.log 里内核自己写下的原因"
	}
}

// classifyCoreLog reads the tail of the core's log and maps it to a condition.
//
// Reading the child's own words is the only way to tell these apart: from outside,
// a core that exits because its port is taken and one that exits because its
// configuration is invalid look identical - a process that is gone.
func classifyCoreLog(logPath string) (coreFailure, string) {
	raw, err := os.ReadFile(logPath)
	if err != nil || len(raw) == 0 {
		return coreFailureUnknown, ""
	}
	// Only the tail matters; a long-lived log's earlier lines describe earlier
	// runs.
	const tail = 16 << 10
	if len(raw) > tail {
		raw = raw[len(raw)-tail:]
	}
	text := string(raw)
	low := strings.ToLower(text)

	// The last non-empty line is the most useful single thing to show.
	lastLine := ""
	for _, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			lastLine = s
		}
	}

	switch {
	case strings.Contains(low, "address already in use") ||
		strings.Contains(low, "only one usage of each socket address") ||
		strings.Contains(low, "bind:") && strings.Contains(low, "in use"):
		return coreFailurePortInUse, lastLine

	case strings.Contains(low, "authentication") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "secret") && strings.Contains(low, "mismatch"):
		return coreFailureAuth, lastLine

	case strings.Contains(low, "configure tun interface") ||
		strings.Contains(low, "access is denied") ||
		strings.Contains(low, "wintun"):
		// Driver and privilege failures arrive as the identical message, because
		// from the core's side they are the same thing: it could not configure the
		// interface. The advice below names both possibilities rather than guessing
		// between them.
		return coreFailureDriver, lastLine

	case strings.Contains(low, "geosite") || strings.Contains(low, "geoip") ||
		strings.Contains(low, "rule-set") || strings.Contains(low, "geodata"):
		return coreFailureGeodata, lastLine

	case strings.Contains(low, "parse config") ||
		strings.Contains(low, "unmarshal") ||
		strings.Contains(low, "yaml:") ||
		strings.Contains(low, "initial configuration") && strings.Contains(low, "error") ||
		strings.Contains(low, "proxy 0:") ||
		strings.Contains(low, "has unset fields"):
		return coreFailureConfig, lastLine

	case strings.Contains(low, "fatal") || strings.Contains(low, "level=error"):
		// Something was reported but it is not one of the shapes above. Saying so
		// is more useful than choosing the closest category.
		return coreFailureUnknown, lastLine
	}
	return coreFailureUnknown, lastLine
}

// coreStartFailure builds the error for a core that did not come up.
//
// It combines the classification with the core's own last line, so the message
// carries both what kind of problem it is and the evidence for it.
func coreStartFailure(logPath string, exited bool, pid int) error {
	kind, lastLine := classifyCoreLog(logPath)
	what := "内核没有在预期时间内响应"
	if exited {
		what = "内核启动后立即退出"
	}
	msg := what + "（" + kind.Label() + "）。" + kind.Advice()
	if lastLine != "" {
		msg += "\n内核最后写道：" + truncateForMessage(lastLine, 300)
	}
	if pid > 0 {
		msg += "\n进程号：" + itoa(pid)
	}
	return &coreStartError{kind: kind, detail: msg, lastLine: lastLine, pid: pid}
}

// coreStartError carries the classification alongside the message, so a caller can
// branch on the kind rather than parsing the text back out.
type coreStartError struct {
	kind     coreFailure
	detail   string
	lastLine string
	pid      int
}

func (e *coreStartError) Error() string { return e.detail }

// Kind reports what kind of failure this was.
func (e *coreStartError) Kind() coreFailure { return e.kind }

// truncateForMessage shortens a line for display without cutting it mid-rune.
func truncateForMessage(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// itoa avoids pulling strconv into this file for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// engineLogPath is where the core's output goes, resolved from the data directory
// the same way the start path resolves it.
func engineLogPath(dataDir string) string {
	return filepath.Join(dataDir, "..", "logs", "engine.log")
}

// waitForCoreUp waits for the core to answer, watching for the child exiting.
//
// exitCh is closed by the goroutine that waits on the process. That is the point:
// cmd.ProcessState stays nil until Wait is called, so the previous check of that
// field never fired and a core that died in the first second still cost the full
// deadline before anything was reported.
func waitForCoreUp(isUp func() bool, exitCh <-chan struct{}, deadline time.Duration) (bool, bool) {
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if isUp() {
			return true, false
		}
		select {
		case <-exitCh:
			// One more check: the core may have answered and then been replaced by
			// this exit in a race.
			if isUp() {
				return true, true
			}
			return false, true
		default:
		}
		time.Sleep(400 * time.Millisecond)
	}
	return isUp(), false
}
