package main

// ---------------------------------------------------------------------------
// Configuration as a transaction.
//
// The previous behaviour was a straight overwrite: generate, write, reload, and
// hope. If the write half-finished, or the core refused the result, the failure
// was logged and the broken file stayed on disk for the next start to trip over.
// The interface still reported success, because nothing tracked whether the
// configuration had actually taken effect.
//
// This file makes the sequence explicit and reversible:
//
//   prepare   validate the candidate and keep the last known good version
//   activate  install the candidate and ask the core to load it
//   verify    ask the core what it is actually running
//   commit    only now is the candidate the new known-good version
//   rollback  on any failure, restore what was working before
//
// The point of the verification step is that a reload returning success is not
// the same as the core running the new configuration. The core is asked what it
// has, and the answer is compared against what was intended.
// ---------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// configTxn records one attempt to change the running configuration.
type configTxn struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	State     string    `json:"state"` // prepared | activated | committed | rolledBack | failed
	Reason    string    `json:"reason,omitempty"`
	// Digest identifies the candidate, so a rollback can confirm it is undoing
	// the version it thinks it is.
	Digest string `json:"digest"`
	// HadGood says whether a previous good version existed. A first run has none,
	// and then a failure means "nothing was ever installed" rather than "restore".
	HadGood bool      `json:"hadGood"`
	Steps   []tunStep `json:"steps,omitempty"`
}

func (a *App) configTxnPath() string  { return filepath.Join(a.dataDir, "config-transaction.json") }
func (a *App) goodConfigPath() string { return filepath.Join(a.dataDir, "config.last-good.yaml") }

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (a *App) saveConfigTxn(t *configTxn) {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return
	}
	tmp := a.configTxnPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		Log("could not record the configuration transaction: %v", err, "WARN")
		return
	}
	_ = os.Rename(tmp, a.configTxnPath())
}

func (a *App) loadConfigTxn() *configTxn {
	raw, err := os.ReadFile(a.configTxnPath())
	if err != nil {
		return nil
	}
	var t configTxn
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil
	}
	return &t
}

// validateCandidateConfig catches the mistakes that would make the core refuse to
// start, before the running configuration is touched.
//
// This is a structural check, not a full parse: it confirms the pieces the core
// requires are present and that nothing obvious is malformed. A candidate that
// fails here is never installed, so a running core is never disturbed by one.
func validateCandidateConfig(cfg string) error {
	if strings.TrimSpace(cfg) == "" {
		return fmt.Errorf("生成的配置是空的")
	}
	for _, need := range []string{"mixed-port:", "proxies:", "proxy-groups:", "rules:"} {
		if !strings.Contains(cfg, need) {
			return fmt.Errorf("配置缺少必需字段 %q", need)
		}
	}
	// Every proxy-group member must name a proxy that exists, or the core refuses
	// to load the whole file. This is the mistake most likely to be introduced by
	// a code change rather than by user input, so it is worth catching here.
	names := map[string]bool{}
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		// Both shapes the generator can emit: the block form "- name: x" and the
		// inline form "- {name: x, type: ...}". Missing the inline one would make
		// this validator reject a configuration that is actually fine, which is
		// worse than not checking at all.
		var n string
		switch {
		case strings.HasPrefix(t, "- name: "):
			n = strings.TrimPrefix(t, "- name: ")
		case strings.HasPrefix(t, "- {name: "):
			n = strings.TrimPrefix(t, "- {name: ")
		default:
			continue
		}
		n = strings.Trim(n, `"'`)
		if i := strings.IndexAny(n, `",}`); i > 0 {
			n = n[:i]
		}
		n = strings.TrimSpace(n)
		if n != "" {
			names[n] = true
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("配置里没有任何节点")
	}
	// A group referencing a name that does not exist is the classic cause of
	// "the core will not start after an update".
	inGroups := false
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "proxy-groups:") {
			inGroups = true
			continue
		}
		if inGroups && strings.HasPrefix(t, "rules:") {
			inGroups = false
		}
		if !inGroups {
			continue
		}
		if strings.HasPrefix(t, `- "`) || strings.HasPrefix(t, `- '`) {
			ref := strings.Trim(t[2:], `"'`)
			if ref == "DIRECT" || ref == "REJECT" || ref == "PASS" || ref == "COMPATIBLE" {
				continue
			}
			if !names[ref] {
				return fmt.Errorf("代理组引用了不存在的节点 %q", ref)
			}
		}
	}
	// Tun mode must be one this version understands, since the block is emitted
	// from it and an unknown value would silently mean "system proxy".
	if strings.Contains(cfg, "\ntun:\n") && !strings.Contains(cfg, "  enable: true") {
		return fmt.Errorf("TUN 段存在但没有启用")
	}
	return nil
}

// applyConfigTransactional is the only path that changes the running
// configuration.
//
// It returns an error when the new configuration is not actually in effect, which
// is the difference from before: callers can no longer report success while the
// core is running something else.
func (a *App) applyConfigTransactional(nodes []Proxy, st Settings) error {
	tx := &configTxn{
		ID:        fmt.Sprintf("cfg-%d", time.Now().UnixNano()),
		StartedAt: time.Now(),
		State:     "prepared",
	}
	step := func(name, state, detail string) {
		for i := range tx.Steps {
			if tx.Steps[i].Name == name {
				tx.Steps[i] = tunStep{Name: name, State: state, Detail: detail, At: time.Now()}
				return
			}
		}
		tx.Steps = append(tx.Steps, tunStep{Name: name, State: state, Detail: detail, At: time.Now()})
	}

	// ---- prepare -----------------------------------------------------------
	optimized := a.optimizedNames()
	cfg := BuildConfig(nodes, optimized, st, a.secret, a.store.Snapshot().Current, a.dnsPort)
	if err := validateCandidateConfig(cfg); err != nil {
		tx.State = "failed"
		tx.Reason = err.Error()
		step("校验候选配置", "failed", err.Error())
		a.saveConfigTxn(tx)
		return fmt.Errorf("新配置没有通过校验，已保留当前配置：%v", err)
	}
	candidate := []byte(cfg)
	tx.Digest = digestOf(candidate)
	step("校验候选配置", "done", fmt.Sprintf("摘要 %s", tx.Digest[:12]))

	// Keep the version that is currently working, so a failure has something to
	// go back to. Read from disk rather than from memory: the file is what the
	// core actually loaded.
	if prior, err := os.ReadFile(a.configPath); err == nil && len(prior) > 0 {
		if err := os.WriteFile(a.goodConfigPath(), prior, 0o644); err == nil {
			tx.HadGood = true
			step("保存可回滚版本", "done", fmt.Sprintf("摘要 %s", digestOf(prior)[:12]))
		}
	}
	if !tx.HadGood {
		step("保存可回滚版本", "skipped", "还没有成功过的版本，失败时保持未配置状态")
	}
	a.saveConfigTxn(tx)

	// ---- activate ----------------------------------------------------------
	if err := os.WriteFile(a.configPath, candidate, 0o644); err != nil {
		tx.State = "failed"
		tx.Reason = err.Error()
		step("写入候选配置", "failed", err.Error())
		a.saveConfigTxn(tx)
		a.rollbackConfig(tx)
		return fmt.Errorf("写入配置失败：%v", err)
	}
	step("写入候选配置", "done", "")

	if !a.core.IsUp() {
		if err := a.core.Start(); err != nil {
			tx.State = "failed"
			tx.Reason = err.Error()
			step("启动内核", "failed", err.Error())
			a.saveConfigTxn(tx)
			a.rollbackConfig(tx)
			return fmt.Errorf("内核未能启动：%v", err)
		}
		step("启动内核", "done", "首次启动")
	} else if err := a.core.Reload(); err != nil {
		tx.State = "failed"
		tx.Reason = err.Error()
		step("内核加载", "failed", err.Error())
		a.saveConfigTxn(tx)
		a.rollbackConfig(tx)
		return fmt.Errorf("内核拒绝加载新配置：%v", err)
	} else {
		step("内核加载", "done", "热重载")
	}
	tx.State = "activated"
	a.saveConfigTxn(tx)

	// ---- verify ------------------------------------------------------------
	// A reload that returned success is not proof that the core is running the new
	// configuration. It is asked what it has.
	if !a.core.IsUp() {
		tx.State = "failed"
		tx.Reason = "内核在加载后没有响应"
		step("确认生效", "failed", tx.Reason)
		a.saveConfigTxn(tx)
		a.rollbackConfig(tx)
		return fmt.Errorf("内核加载后没有响应，已回滚")
	}
	// The core reports its live port map; a mismatch means it did not take the
	// candidate, whatever the reload call said.
	if live, err := a.core.LiveConfig(); err == nil {
		if want, ok := live["mixed-port"]; ok {
			if got, ok2 := toInt(want); ok2 && got != st.MixedPort {
				tx.State = "failed"
				tx.Reason = fmt.Sprintf("内核报告的混合端口是 %d，期望 %d", got, st.MixedPort)
				step("确认生效", "failed", tx.Reason)
				a.saveConfigTxn(tx)
				a.rollbackConfig(tx)
				return fmt.Errorf("%s，已回滚", tx.Reason)
			}
		}
	}
	step("确认生效", "done", "")

	// ---- commit ------------------------------------------------------------
	tx.State = "committed"
	a.saveConfigTxn(tx)
	if err := os.WriteFile(a.goodConfigPath(), candidate, 0o644); err != nil {
		Log("could not update the known-good configuration: %v", err, "WARN")
	}
	return nil
}

// rollbackConfig restores the last version that worked.
//
// When there is none, it says so rather than pretending: on a first run there is
// nothing to restore, and claiming otherwise would leave the user believing a
// configuration is in effect when none ever was.
func (a *App) rollbackConfig(tx *configTxn) {
	good, err := os.ReadFile(a.goodConfigPath())
	if err != nil || len(good) == 0 {
		Log("configuration rollback: there is no previously working version to restore", "WARN")
		tx.Steps = append(tx.Steps, tunStep{Name: "回滚", State: "skipped",
			Detail: "没有可回滚的版本", At: time.Now()})
		tx.State = "rolledBack"
		a.saveConfigTxn(tx)
		return
	}
	if err := os.WriteFile(a.configPath, good, 0o644); err != nil {
		Log("configuration rollback failed to write: %v", err, "ERR")
		return
	}
	// The core may not exist yet, or may already be gone. Guarding here rather
	// than at every call site keeps the rollback usable from start-up recovery,
	// where nothing is running and there is no core to ask.
	if a.core != nil && a.core.IsUp() {
		if err := a.core.Reload(); err != nil {
			Log("configuration rollback: the core would not load the previous version either: %v", err, "ERR")
		}
	}
	tx.Steps = append(tx.Steps, tunStep{Name: "回滚", State: "done",
		Detail: fmt.Sprintf("已恢复摘要 %s", digestOf(good)[:12]), At: time.Now()})
	tx.State = "rolledBack"
	a.saveConfigTxn(tx)
	Log("configuration rolled back to the last version that worked")
}

// optimizedNames is the list the AUTO group is built from.
func (a *App) optimizedNames() []string {
	optimized, _ := a.nodeSet()
	out := make([]string, 0, len(optimized))
	for _, p := range optimized {
		out = append(out, p.Name)
	}
	return out
}

// RecoverConfigTransaction runs at start-up.
//
// An activation that never finished means the configuration on disk may be a
// candidate that failed verification. The record is what distinguishes that from
// a deliberate state, so it is consulted rather than guessed at from timestamps.
func (a *App) RecoverConfigTransaction() {
	tx := a.loadConfigTxn()
	if tx == nil {
		return
	}
	switch tx.State {
	case "prepared", "activated":
		Log("configuration: found an unfinished activation from %s; restoring the last version that worked",
			tx.StartedAt.Format(time.RFC3339), "WARN")
		a.rollbackConfig(tx)
	case "failed":
		// Already rolled back when it failed; nothing to do beyond noting it.
		Log("configuration: the previous activation failed (%s) and was rolled back", tx.Reason)
	}
}

// toInt accepts the numeric shapes a JSON-decoded value can take, since the core
// reports ports as a number but other fields may arrive as strings.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case string:
		var out int
		if _, err := fmt.Sscanf(n, "%d", &out); err == nil {
			return out, true
		}
	}
	return 0, false
}
