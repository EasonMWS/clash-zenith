package main

// ---------------------------------------------------------------------------
// The rule that must be true before anything else happens: do not be offline.
//
// A system proxy pointing at a port with no listener takes the machine off the
// internet. Measured, not assumed: with `ProxyEnable=1` and `ProxyServer=127.0.0.1:7899`
// and nothing on 7899, baidu and bilibili both fail to connect. Windows does not treat
// a loopback proxy as optional, and it does not diagnose it - the browser says the site
// is unreachable, and the site is fine.
//
// So a crash of this program, or a kill of its core, leaves the user offline with no
// indication of why. That is the worst thing a proxy client can do, and it is the thing
// this program kept doing.
//
// The detached watchdog was the answer to it, and it does not hold: measured, a
// watchdog started with the real flags is gone within seconds while the one run by hand
// lives long enough to do its job. A safety net that only works when it is not needed
// is not a safety net.
//
// This is the replacement, and it is built on the one thing that is certain: the next
// start happens. Whatever the previous run left behind, a starting program can see it
// and undo it before it does anything else. So the rule is inverted - instead of hoping
// to clean up on the way out, every start cleans up on the way in:
//
//  1. Read the registry. If the proxy is not ours, leave it alone: another program's
//     configuration is not ours to change.
//  2. If it is ours and the port it names has no listener, it is a leftover from a run
//     that died. Clear it, and say so in the log.
//  3. Only then start anything else.
//
// The cost is that a leftover stays until the next start rather than being cleared
// within seconds. That is the honest trade: a guarantee that holds every time beats a
// timer that holds most of the time, and the user's own action - opening the program
// again - is the trigger.
//
// The watchdog stays as a second line, because when it does survive it clears the
// leftover sooner. It is no longer the line being relied on.
// ---------------------------------------------------------------------------

import (
	"time"
)

// claimProxyForStartup clears a leftover of ours before anything else runs.
//
// It returns whether it changed the setting, so the caller can say so rather than
// leaving a silent change to the machine's configuration.
//
// The guards are the whole point, and there are three:
//
//   - the setting must be enabled;
//   - it must name exactly the port this program is configured to use, so another
//     program's proxy is never touched;
//   - that port must have no listener, so a live instance - this one duplicating, or
//     another copy the user started - is never disconnected.
func (a *App) claimProxyForStartup() bool {
	sp := NewSystemProxy(a.dataDir)
	st := sp.Status()
	if !st.Enabled || st.Server == "" {
		return false
	}
	port := portFromServer(st.Server)
	want := a.store.Settings().MixedPort
	if port == 0 || port != want {
		return false // somebody else's setting, or a port we do not serve
	}
	if portHasListener(port) {
		return false
	}
	// No listener is not the same as no core, and treating them as the same was a
	// mistake made once already in this function's first version.
	//
	// Measured: it cleared a perfectly good proxy because it ran a moment before the
	// core had bound its port, so a working arrangement was taken away by the check
	// meant to protect it. The question is not "is the port bound right now" but "is
	// there a core that is going to serve it", and this program knows the answer to
	// the second one without guessing.
	if a.core != nil && a.core.IsUp() {
		// A core this process started and that is answering. The port will be bound;
		// clearing the proxy here would disconnect a working setup.
		return false
	}
	if a.serviceReachable() {
		// The resident service owns the core and is answering. Same reasoning.
		return false
	}
	if a.recentCoreStart() {
		// A core was started as part of this very startup and has not had time to
		// bind. Waiting is correct; clearing is not.
		Log("startup: the system proxy points at %s and a core was just started; "+
			"leaving the setting alone while it comes up", st.Server)
		return false
	}
	Log("startup: the system proxy points at %s, which this program serves and "+
		"nothing is listening on. That is a leftover from a run that did not shut down "+
		"cleanly, and it would leave the machine with no internet. Clearing it now",
		st.Server, "WARN")
	sp.Disable()
	if _, err := a.store.UpdateSettings(map[string]interface{}{"systemProxy": false}); err != nil {
		Log("startup: could not record that the proxy was cleared: %v", err, "WARN")
	}
	a.proxyClearedAtStartup = true
	return true
}

// recentCoreStart reports whether this process has started a core very recently, so a
// port that is not bound yet is expected rather than evidence of a dead run.
func (a *App) recentCoreStart() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.coreStartedAt.IsZero() {
		return false
	}
	return time.Since(a.coreStartedAt) < coreStartGrace
}

// waitForCoreThenClaimProxy is the same rule applied once more, a little later.
//
// The startup path has a window of its own: the proxy is read from the saved settings,
// the core is started, and if the core never manages to bind, the machine is offline
// for as long as the program is running. This waits a bounded time for the core and
// then applies the same three guards.
//
// It runs in the background so it cannot delay the window opening.
func (a *App) waitForCoreThenClaimProxy(deadline time.Duration) {
	start := time.Now()
	for time.Since(start) < deadline {
		if a.quitting {
			return
		}
		if a.core != nil && a.core.IsUp() {
			return // the port is being served; nothing to clear
		}
		if a.serviceReachable() {
			return // the service holds the core and is answering
		}
		time.Sleep(500 * time.Millisecond)
	}
	if a.quitting {
		return
	}
	a.ensureNotOfflineBecauseOfUs()
}
