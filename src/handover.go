package main

// ---------------------------------------------------------------------------
// The activation handover.
//
// An activation that needs elevation is two processes: the one with the window,
// which cannot touch the adapter, and the elevated helper, which can. The
// previous version handed over and then simply returned, leaving the interface
// saying "authorised, waiting for the elevated instance" with nothing that could
// ever end that wait. The helper had no way back: it reported through a progress
// object it never initialised, so a failure was recorded nowhere, and it then
// decided the outcome by reading that empty object - which meant a failed
// activation reported success and then stopped the core on its way out.
//
// This file is the channel that replaces that. It is deliberately a file rather
// than anything in memory, because the two processes share only the data
// directory, and because a durable record is what lets the next start-up tell an
// interrupted activation from a completed one.
//
// The rules:
//
//   - Every activation has a unique id. A record whose id does not match is from
//     a different attempt and is ignored.
//   - Only the helper writes a terminal state. The waiting side never infers
//     success from its own memory of what it asked for.
//   - A helper that exits without writing one is a failure, and says so as its
//     own case rather than being reported as a timeout.
//   - The wait always ends. Timeout and helper-exit both end it.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Handover states. Terminal states are succeeded and failed; everything else
// means the helper is still working.
const (
	handoverRunning   = "running"
	handoverSucceeded = "succeeded"
	handoverFailed    = "failed"
)

// handoverHeartbeatTimeout is how long a stage may go without progress before the
// helper is considered stuck rather than slow.
//
// The longest legitimate step is the adapter appearing, which the activation polls
// for up to twenty seconds, plus a core restart. Ninety seconds is comfortably past
// that and far short of the overall deadline, so a genuine stall is reported while
// the user is still watching rather than minutes later.
const handoverHeartbeatTimeout = 90 * time.Second

// handoverRecord is the helper's report, written where the waiting side can read
// it.
type handoverRecord struct {
	// ID identifies this activation. The waiting side passes it to the helper and
	// ignores any record carrying a different one, so a stale file from an earlier
	// attempt cannot be mistaken for this attempt's result.
	ID string `json:"id"`
	// HelperPID identifies the process that wrote it, so a record can be
	// attributed when more than one helper has ever run.
	HelperPID int `json:"helperPid"`
	// RequesterPID is the instance that asked for elevation. A record addressed to
	// a different process is not ours to act on.
	RequesterPID int `json:"requesterPid"`

	State     string `json:"state"`
	Stage     string `json:"stage,omitempty"`
	Failure   string `json:"failure,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Adapter   string `json:"adapter,omitempty"`
	StartedAt string `json:"startedAt"`
	UpdatedAt string `json:"updatedAt"`
	// ExitedAt is set when the helper is about to leave. It is the difference
	// between "still working" and "gone without finishing".
	ExitedAt string `json:"exitedAt,omitempty"`
	// Heartbeat is refreshed every time the helper reports progress. It is the
	// difference between "slow" and "stopped": UpdatedAt moves on every write,
	// including writes from the waiting side, so it cannot answer that question on
	// its own.
	Heartbeat string `json:"heartbeat,omitempty"`
}

func (a *App) handoverPath() string {
	return filepath.Join(a.dataDir, "activation-handover.json")
}

// newHandoverID makes an id unique to one activation attempt.
func newHandoverID() string {
	return fmt.Sprintf("act-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// writeHandover saves the record. A failure to write is logged and otherwise
// ignored: the record is how the other process learns what happened, but losing it
// must not stop this process from doing its work.
func (a *App) writeHandover(rec *handoverRecord) {
	rec.UpdatedAt = time.Now().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	tmp := a.handoverPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		Log("could not record the activation handover: %v", err, "WARN")
		return
	}
	_ = os.Rename(tmp, a.handoverPath())
}

// readHandover loads the record, if there is one.
func (a *App) readHandover() *handoverRecord {
	raw, err := os.ReadFile(a.handoverPath())
	if err != nil {
		return nil
	}
	var rec handoverRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil
	}
	return &rec
}

// clearHandover removes the record, so the next activation cannot read this one's
// result.
func (a *App) clearHandover() {
	_ = os.Remove(a.handoverPath())
}

// handoverResult is what the waiting side learns.
type handoverResult struct {
	Done    bool
	OK      bool
	Stage   string
	Failure string
}

// awaitHandover waits for the helper to report, and always returns.
//
// Three things end the wait, and they are distinguished because they mean
// different things to the user:
//
//   - the helper writes a terminal state: its own verdict, which is the only
//     thing that counts as success;
//   - the helper process exits without writing one: a crash or a kill, reported
//     as such rather than as a timeout, because a timeout would send the user
//     looking for a slow operation instead of a dead process;
//   - the deadline passes: the operation is genuinely stuck.
//
// Progress is copied into the app's own state as it arrives, so the interface can
// show the helper's stage rather than a static "waiting".
func (a *App) awaitHandover(id string, helperPID int, timeout time.Duration) handoverResult {
	deadline := time.Now().Add(timeout)
	lastStage := ""
	lastState := ""
	for {
		rec := a.readHandover()
		if rec != nil && rec.ID == id {
			if rec.Stage != "" && rec.Stage != lastStage {
				lastStage = rec.Stage
				a.setTunStage(rec.Stage)
			}
			lastState = rec.State
			switch rec.State {
			case handoverSucceeded:
				return handoverResult{Done: true, OK: true, Stage: rec.Stage}
			case handoverFailed:
				reason := rec.Failure
				if reason == "" {
					reason = "提权实例报告失败，但没有给出原因"
				}
				return handoverResult{Done: true, OK: false, Stage: rec.Stage, Failure: reason}
			}
		}

		// A helper that is gone and never reported is a failure with its own name.
		if helperPID > 0 && !helperStillRunning(helperPID) {
			// One last read: a record may have been written between the check above
			// and the process exiting.
			time.Sleep(300 * time.Millisecond)
			if rec := a.readHandover(); rec != nil && rec.ID == id {
				switch rec.State {
				case handoverSucceeded:
					return handoverResult{Done: true, OK: true, Stage: rec.Stage}
				case handoverFailed:
					reason := rec.Failure
					if reason == "" {
						reason = "提权实例报告失败，但没有给出原因"
					}
					return handoverResult{Done: true, OK: false, Stage: rec.Stage, Failure: reason}
				}
			}
			return handoverResult{
				Done:  true,
				OK:    false,
				Stage: lastStage,
				Failure: "提权实例已经退出，但没有报告结果。这通常意味着它在创建网卡时被系统终止，" +
					"或者它的进程被结束掉了。激活没有完成，也没有留下半配置状态。" +
					describeHandoverState(lastState),
			}
		}

		// A helper whose heartbeat has stopped is not slow, it is stuck. Saying so
		// as soon as the heartbeat goes quiet is the difference between a user
		// waiting for something that will finish and a user waiting for something
		// that will not.
		if rec != nil && rec.ID == id && rec.State == handoverRunning && rec.Heartbeat != "" {
			if hb, err := time.Parse(time.RFC3339Nano, rec.Heartbeat); err == nil {
				if time.Since(hb) > handoverHeartbeatTimeout {
					return handoverResult{
						Done:  true,
						OK:    false,
						Stage: lastStage,
						Failure: fmt.Sprintf("提权实例停在「%s」已经超过 %s，没有任何进展，"+
							"判定为卡住并停止等待。这通常意味着它在这一步被系统阻止了"+
							"（例如授权没有生效，或系统策略不允许创建网卡）",
							lastStage, handoverHeartbeatTimeout),
					}
				}
			}
		}

		if time.Now().After(deadline) {
			return handoverResult{
				Done:  true,
				OK:    false,
				Stage: lastStage,
				Failure: fmt.Sprintf("等待提权实例超过 %s 仍没有结果，已停止等待。"+
					"最后记录的阶段是「%s」。这通常意味着提权实例卡在了某一步，"+
					"可以查看日志了解它停在哪里。", timeout.Round(time.Second), lastStage),
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// describeHandoverState adds the helper's last reported state to a failure, when
// there was one, so "no result" is not the whole story.
func describeHandoverState(state string) string {
	switch state {
	case "":
		return " 提权实例没有写下任何进度，说明它在开始工作前就结束了。"
	case handoverRunning:
		return " 它最后记录的状态是「进行中」。"
	default:
		return " 它最后记录的状态是「" + state + "」。"
	}
}

// beginHandover is called by the helper when it takes over. It claims the record
// so the waiting side sees progress rather than silence.
func (a *App) beginHandover(id string, requesterPID int, mode TunMode) *handoverRecord {
	// The adapter name is recorded so the waiting side and the helper agree on what
	// is being created. Guarded rather than assumed: the record must be writable
	// even when the store is not available, because losing it means losing the only
	// channel the waiting side has.
	adapter := tunDefaultDevice
	if a.store != nil {
		adapter = a.store.Settings().NormalizedTunDevice()
	}
	rec := &handoverRecord{
		ID:           id,
		HelperPID:    os.Getpid(),
		RequesterPID: requesterPID,
		State:        handoverRunning,
		Stage:        "提权实例已启动，准备环境",
		Mode:         string(mode),
		Adapter:      adapter,
		StartedAt:    time.Now().Format(time.RFC3339Nano),
		// A heartbeat from the first moment, so the waiting side can tell "has not
		// started reporting yet" from "stopped reporting" without waiting for the
		// overall deadline to answer the wrong question.
		Heartbeat: time.Now().Format(time.RFC3339Nano),
	}
	a.writeHandover(rec)
	return rec
}

// finishHandover records the helper's verdict. The waiting side never decides
// success for itself; this is the only place success is written.
func (a *App) finishHandover(rec *handoverRecord, err error) {
	if err != nil {
		rec.State = handoverFailed
		rec.Failure = err.Error()
	} else {
		rec.State = handoverSucceeded
	}
	rec.ExitedAt = time.Now().Format(time.RFC3339Nano)
	a.writeHandover(rec)
}

// progressHandover updates the stage the waiting side displays.
func (a *App) progressHandover(rec *handoverRecord, stage string) {
	if rec == nil {
		return
	}
	rec.Stage = stage
	rec.Heartbeat = time.Now().Format(time.RFC3339Nano)
	a.writeHandover(rec)
}

// helperStillRunning reports whether a process id still refers to a running process.
//
// It is deliberately permissive about permissions: an elevated process cannot be
// opened by a non-elevated one, and reporting that as "gone" would end the wait
// early and wrongly. A refusal to open is therefore treated as alive.
func helperStillRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	alive, err := processRunning(pid)
	if err != nil {
		return true
	}
	return alive
}
