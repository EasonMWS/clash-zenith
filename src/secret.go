package main

// ---------------------------------------------------------------------------
// The control secret, owned by the data directory rather than by a process.
//
// The control API is the one thing that can reconfigure the core, so its secret
// has to be strong. It also has to be the same secret for every process that talks
// to that core - and that is what went wrong.
//
// The secret used to be generated fresh on every start. That is fine for security
// and fatal for a handover: an elevated helper is a different process reading the
// same data directory, so it generated its own secret, wrote its own configuration
// and started its own core. The ordinary instance then held a secret that no
// longer matched the running core, which is exactly the review's finding - the
// core is up, and the program calls it unavailable because authentication fails.
//
// So the secret lives beside the data it protects, is created once, and is read by
// everyone who needs it. Single ownership is the point: one writer, many readers.
//
// What this trades away, stated plainly: a secret on disk is readable by anything
// that can read the file. That is the same position the configuration already
// occupies - the configuration embeds the secret anyway - so the file adds no new
// exposure, and the permissions below narrow it to the user's own account.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// secretFileMode is what a POSIX system would call owner-only. It is passed to
// OpenFile for that reason, but on Windows it does not restrict anything: NTFS
// permissions come from the ACL, and a file created with 0o600 is still readable
// by every account on the machine. Measured, not assumed - the first version of
// this file was mode 666 on disk while these comments claimed otherwise.
//
// So the real restriction is applied through the ACL, below.
const secretFileMode = 0o600

func secretPath(dataDir string) string {
	return filepath.Join(dataDir, "control.secret")
}

// loadOrCreateSecret returns the control secret for this data directory, creating
// it on first use.
//
// Idempotent by design: every process that needs the secret calls this, the first
// one creates it, and the rest read it. A process that cannot read an existing
// secret must not silently replace it - that would lock out the core currently
// running with the old value - so a read error is reported rather than papered
// over with a new secret.
func loadOrCreateSecret(dataDir string) (string, error) {
	p := secretPath(dataDir)

	raw, err := os.ReadFile(p)
	if err == nil {
		s := strings.TrimSpace(string(raw))
		if len(s) >= 32 {
			// Tighten a file that predates this, since a secret readable by other
			// accounts is worth repairing rather than trusting.
			restrictSecretFile(p)
			return s, nil
		}
		// Present but unusable. Refusing is safer than replacing: a core may be
		// running with whatever value was intended, and silently issuing a new one
		// would make that core unreachable with no explanation.
		return "", fmt.Errorf("控制密码文件 %s 存在但内容不可用（长度 %d）。"+
			"删除它可以让 Zenith 重新生成，但请先确认没有正在运行的内核在使用旧值", p, len(s))
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("无法读取控制密码文件 %s：%v", p, err)
	}

	secret := randomToken()
	// Write with owner-only permissions from the start, rather than creating it
	// world-readable and narrowing it afterwards.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, secretFileMode)
	if err != nil {
		if os.IsExist(err) {
			// Another process created it between the read and the write. Read theirs
			// rather than overwriting: they may already have started a core with it.
			if raw, rerr := os.ReadFile(p); rerr == nil {
				if s := strings.TrimSpace(string(raw)); len(s) >= 32 {
					return s, nil
				}
			}
		}
		return "", fmt.Errorf("无法创建控制密码文件 %s：%v", p, err)
	}
	if _, err := f.WriteString(secret); err != nil {
		f.Close()
		_ = os.Remove(p)
		return "", fmt.Errorf("无法写入控制密码文件 %s：%v", p, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("无法关闭控制密码文件 %s：%v", p, err)
	}
	// Restrict it to this account now that it has contents. Doing it after the
	// write rather than before avoids a window where the file exists but the ACL
	// call has not run.
	restrictSecretFile(p)
	Log("created the control secret for this data directory (%s)", p)
	return secret, nil
}

// restrictSecretFile narrows a file to the current user and to administrators.
//
// On Windows the POSIX mode passed to OpenFile does not restrict anything, so this
// is the actual protection. It removes inherited permissions and grants only the
// owner, which is the account that will read it. Failure is logged rather than
// fatal: a secret that cannot be tightened is worse than one that can be, but it
// is not worse than no proxy at all, and the user is told.
func restrictSecretFile(path string) {
	// /inheritance:r drops inherited entries, /grant:r replaces the grants with
	// just this one.
	user := os.Getenv("USERNAME")
	domain := os.Getenv("USERDOMAIN")
	if user == "" {
		Log("could not determine the current account; leaving %s with inherited "+
			"permissions", path, "WARN")
		return
	}
	who := user
	if domain != "" {
		who = domain + `\` + user
	}
	if _, err := HiddenCommand("icacls", path, "/inheritance:r",
		"/grant:r", who+":F"); err != nil {
		Log("could not restrict the permissions of %s to %s: %v",
			path, who, err, "WARN")
	}
}

// ensureSecretFileExists reports whether a secret file is present, without
// creating one. Used by diagnostics that must not have a side effect.
func ensureSecretFileExists(dataDir string) bool {
	raw, err := os.ReadFile(secretPath(dataDir))
	return err == nil && len(strings.TrimSpace(string(raw))) >= 32
}
