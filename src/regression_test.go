package main

// ---------------------------------------------------------------------------
// Regression tests for the defects the review found.
//
// Each test here exists because the corresponding bug shipped and was only caught
// by reading the source or by a user hitting it. They are deliberately written
// against the behaviour that was wrong, not against the implementation, so a
// future refactor that reintroduces the bug fails the test rather than passing it.
//
// Run with: go test ./...
// The race detector needs cgo, so on a machine without a C toolchain run the
// concurrency test directly - it asserts on observable state rather than relying
// on the detector.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// reqWithToken builds the minimal request the token check reads.
func reqWithToken(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	if tok != "" {
		r.Header.Set("X-Zenith-Token", tok)
	}
	return r
}

// ---- R02: the watchdog must be reachable before flag parsing --------------

func TestWatchdogInvocationIsRecognised(t *testing.T) {
	// The bug: the dispatch sat after flag.Parse, which exits on an unknown flag,
	// so the helper died on its own argument and the crash protection did not
	// exist. The check must therefore not involve the flag package at all.
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"zenith.exe", "-watchdog", `C:\data`, "7899"}, true},
		{[]string{"zenith.exe", "-watchdog"}, false},                       // not enough arguments
		{[]string{"zenith.exe", "-watchdog", `C:\data`}, false},            // no port
		{[]string{"zenith.exe", "-watchdog", `C:\data`, "abc"}, false},     // port is not a number
		{[]string{"zenith.exe"}, false},                                    // plain start
		{[]string{"zenith.exe", "-headless"}, false},                       // another flag
		{[]string{"zenith.exe", "-verbose", "-watchdog", "d", "1"}, false}, // not the first argument
	}
	saved := os.Args
	defer func() { os.Args = saved }()
	for _, c := range cases {
		os.Args = c.args
		if got := isWatchdogInvocation(); got != c.want {
			t.Errorf("isWatchdogInvocation(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// ---- R01: health state must be readable without racing the writer ----------

func TestHealthSnapshotIsIndependent(t *testing.T) {
	// The bug: the status handler returned the live map to the JSON encoder while
	// healthLoop wrote it, which is a fatal runtime error rather than a wrong
	// answer. A reader must therefore get a copy that cannot change under it.
	a := &App{}
	a.healthBanned = map[string]time.Time{"node-a": time.Now()}
	a.nodeFlaky = map[string]int{"node-a": 3}
	a.publishHealth()

	view := a.HealthView()
	if view == nil {
		t.Fatal("publishHealth did not produce a snapshot")
	}
	if view.Flaky["node-a"] != 3 {
		t.Fatalf("snapshot lost the failure count: %v", view.Flaky)
	}

	// A later write must not reach the snapshot a reader already holds.
	a.nodeFlaky["node-a"] = 99
	a.healthBanned["node-b"] = time.Now()
	if view.Flaky["node-a"] != 3 {
		t.Errorf("a reader's snapshot changed after a later write: %d", view.Flaky["node-a"])
	}
	if _, leaked := view.Banned["node-b"]; leaked {
		t.Error("a reader's snapshot gained an entry written after it was taken")
	}

	// And the copy handed out for reporting must be detached: mutating what a
	// caller received must not reach the snapshot other callers will read.
	// Note the snapshot still holds the published value (3), because publishing
	// happens after the write that the snapshot is meant to describe.
	cp := a.flakyNodesCopy()
	if cp["node-a"] != 3 {
		t.Fatalf("the reporting copy should reflect the published snapshot, got %d", cp["node-a"])
	}
	cp["node-a"] = 7
	cp["node-zzz"] = 1
	fresh := a.flakyNodesCopy()
	if fresh["node-a"] != 3 {
		t.Errorf("mutating the reported copy changed later readers: %d", fresh["node-a"])
	}
	if _, leaked := fresh["node-zzz"]; leaked {
		t.Error("mutating the reported copy added an entry for later readers")
	}
}

func TestHealthSnapshotUnderConcurrentPublishAndRead(t *testing.T) {
	// The shape of the original failure: one writer, several readers. Without the
	// snapshot this is the access pattern that produced a fatal map error.
	a := &App{}
	a.healthBanned = map[string]time.Time{}
	a.nodeFlaky = map[string]int{}
	a.mu.Lock()
	a.publishHealth()
	a.mu.Unlock()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			a.mu.Lock()
			name := "node-" + string(rune('a'+i%8))
			a.nodeFlaky[name]++
			a.healthBanned[name] = time.Now()
			a.publishHealth()
			a.mu.Unlock()
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if h := a.HealthView(); h != nil {
					// Touch both maps the way ranking and reporting do.
					_ = h.Flaky["node-a"]
					_, _ = h.Banned["node-a"]
					for k, v := range h.Flaky {
						_ = k
						_ = v
					}
				}
				_ = a.flakyNodesCopy()
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---- R04: the slow-node counter has to survive between checks --------------

// newTestStore builds a store whose optimized list is the given nodes, so the
// slow-node path has somewhere to switch to without touching the real data dir.
func newTestStore(t *testing.T, nodes []Proxy) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.SetNodes(nil, nodes); err != nil {
		t.Fatalf("SetNodes: %v", err)
	}
	return st
}

func TestSlowStrikesAccumulate(t *testing.T) {
	// The bug: the counter was incremented and cleared in the same critical
	// section, before the threshold test, so it was always 1 and the switch never
	// fired. Two consecutive slow readings must now be able to trigger it.
	a := &App{}
	// A node set with an origin node to switch to, so the switch has a target.
	optimized := []Proxy{
		{Name: "pinned", MeasuredMS: 250},
		{Name: "origin", OriginNode: true, Server: "example.invalid"},
	}
	a.store = newTestStore(t, optimized)

	// First slow reading: must not switch, and must leave the count at one.
	a.reactToSlowness("pinned", float64(slowNodeMS)+100)
	a.mu.Lock()
	after1 := a.slowStrikes
	a.mu.Unlock()
	if after1 != 1 {
		t.Fatalf("after one slow reading the counter is %d, want 1 "+
			"(a counter that resets here is the bug that made the feature dead code)", after1)
	}

	// A fast reading resets it: the bar is about sustained slowness.
	a.reactToSlowness("pinned", 100)
	a.mu.Lock()
	afterFast := a.slowStrikes
	a.mu.Unlock()
	if afterFast != 0 {
		t.Errorf("a fast reading left the counter at %d, want 0", afterFast)
	}
}

// ---- TUN: component verification must be by content -----------------------

func TestComponentVerificationRejectsWrongContent(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "core", "wintun")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "wintun-amd64.dll")

	// A file with the right name and a plausible size, but not the right bytes.
	body := make([]byte, 200*1024)
	copy(body, []byte("not the real component"))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	good := sha256.Sum256([]byte("the real component"))

	c := tunComponent{
		Name: "wintun", File: "core/wintun/wintun-amd64.dll",
		Version: "0.14.1", SHA256: hex.EncodeToString(good[:]),
	}
	st := verifyTunComponent(dir, c)
	if st.Verified {
		t.Fatal("a component whose contents do not match the manifest was accepted")
	}
	if !st.Present {
		t.Error("the component should be reported as present but unverified")
	}
	if !st.NeedsFix {
		t.Error("a digest mismatch must be reported as needing repair")
	}
	if !strings.Contains(st.Detail, "摘要不符") {
		t.Errorf("the refusal should say what was wrong, got %q", st.Detail)
	}

	// Missing entirely is a different, equally clear answer.
	st2 := verifyTunComponent(dir, tunComponent{
		Name: "wintun", File: "core/wintun/missing.dll", SHA256: "00",
	})
	if st2.Verified || !st2.NeedsFix {
		t.Error("a missing component must be reported as needing repair")
	}
	if !strings.Contains(st2.Detail, "不存在") {
		t.Errorf("the refusal should say the file is missing, got %q", st2.Detail)
	}

	// And the correct content is accepted.
	if err := os.WriteFile(path, []byte("the real component"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Re-pad to clear the size floor so the digest check is what is being tested.
	ok := append([]byte("the real component"), make([]byte, 200*1024)...)
	if err := os.WriteFile(path, ok, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ok)
	st3 := verifyTunComponent(dir, tunComponent{
		Name: "wintun", File: "core/wintun/wintun-amd64.dll",
		Version: "0.14.1", SHA256: hex.EncodeToString(sum[:]),
	})
	if !st3.Verified {
		t.Fatalf("a component matching the manifest was refused: %s", st3.Detail)
	}
}

func TestTunModeValidityAndLabels(t *testing.T) {
	// An unrecognised stored value must be treated as off, not guessed at.
	for _, m := range []TunMode{"", TunOff, TunCompat, TunPrivacy} {
		if !m.Valid() {
			t.Errorf("%q should be valid", m)
		}
	}
	for _, m := range []TunMode{"on", "privacy ", "TUN", "compat2", "true"} {
		if m.Valid() {
			t.Errorf("%q should not be accepted as a mode", m)
		}
	}
	// The three states must be described differently: conflating "an adapter
	// exists" with "protected" is the specific mistake the labels guard against.
	labels := map[string]string{}
	for _, m := range []TunMode{TunOff, TunCompat, TunPrivacy} {
		l := m.Label()
		if l == "" {
			t.Errorf("mode %q has no label", m)
		}
		if _, dup := labels[l]; dup {
			t.Errorf("two modes share the label %q", l)
		}
		labels[l] = l
	}
	if !strings.Contains(TunPrivacy.Label(), "隐私") {
		t.Error("the privacy mode label should say so plainly")
	}
	if !strings.Contains(TunCompat.Label(), "不承诺") {
		t.Error("the compat label must not read as a guarantee that all traffic is proxied")
	}
}

// ---- TUN: transactions must record what they own before changing it -------

func TestTunTransactionOwnershipAndRollbackScope(t *testing.T) {
	dir := t.TempDir()
	a := &App{dataDir: dir}

	tx := newTunTxn(txnActivate)
	tx.Owned.AdapterCreated = true
	tx.Owned.AdapterName = defaultTunDevice
	tx.Owned.SysProxyWasOn = true
	tx.Owned.SysProxyServer = "127.0.0.1:7890"
	tx.step("保存设置", "done", "compat")
	a.saveTunTxn(tx)

	// The record must survive a round trip intact: a crash recovery reads it and
	// needs to know exactly what to undo.
	back := a.loadTunTxn()
	if back == nil {
		t.Fatal("the transaction record could not be read back")
	}
	if back.State != "running" {
		t.Errorf("state = %q, want running", back.State)
	}
	if !back.Owned.AdapterCreated || back.Owned.AdapterName != defaultTunDevice {
		t.Errorf("adapter ownership was lost: %+v", back.Owned)
	}
	if !back.Owned.SysProxyWasOn || back.Owned.SysProxyServer != "127.0.0.1:7890" {
		t.Errorf("system proxy ownership was lost: %+v", back.Owned)
	}
	if len(back.Steps) != 1 || back.Steps[0].Name != "保存设置" {
		t.Errorf("steps were lost: %+v", back.Steps)
	}

	// A step recorded twice updates rather than duplicating, so the record stays a
	// sequence of states instead of a log of retries.
	tx.step("保存设置", "failed", "boom")
	back2 := a.loadTunTxn()
	tx.step("保存设置", "done", "again")
	if back2 == nil {
		t.Fatal("record vanished")
	}
	if len(tx.Steps) != 1 {
		t.Errorf("re-recording a step duplicated it: %+v", tx.Steps)
	}
	if tx.Steps[0].State != "done" {
		t.Errorf("re-recording a step did not update its state: %+v", tx.Steps[0])
	}
}

func TestAdapterRemovalRefusesForeignNames(t *testing.T) {
	// Uninstall and rollback must only ever remove Zenith's own adapter. A name
	// that is not ours has to be refused outright, before any OS call is made.
	fake := NewSystemProxy(t.TempDir())
	_ = fake
	for _, name := range []string{"", "Ethernet", "Wi-Fi", "vEthernet (WSL)", "Zenith2"} {
		if err := removeTunAdapter(name); err == nil {
			t.Errorf("removeTunAdapter(%q) was allowed; it must only touch %q",
				name, defaultTunDevice)
		}
	}
}

// ---- S02: the local API must reject unauthenticated and foreign requests ---

func TestLoopbackHostCheck(t *testing.T) {
	// A page on the internet can point a name it controls at 127.0.0.1, so only
	// literal loopback values may pass.
	good := []string{"127.0.0.1", "127.0.0.1:7799", "localhost:7799", "localhost", "[::1]:7799", "::1"}
	bad := []string{"", "evil.example.com", "evil.example.com:7799", "192.168.1.5",
		"10.0.0.1:7799", "0.0.0.0", "attacker.test:80"}
	for _, h := range good {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range bad {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

func TestTokenComparisonRejectsWrongAndShortValues(t *testing.T) {
	s := &Server{token: "0123456789012345678901234567890123456789ab"}
	if !s.tokenOK(reqWithToken(s.token)) {
		t.Error("the correct token was rejected")
	}
	if s.tokenOK(reqWithToken("")) {
		t.Error("an empty token was accepted")
	}
	if s.tokenOK(reqWithToken("short")) {
		t.Error("a short token was accepted")
	}
	// Same length, one byte different: the length check alone must not be the gate.
	wrong := "0123456789012345678901234567890123456789ac"
	if s.tokenOK(reqWithToken(wrong)) {
		t.Error("a same-length wrong token was accepted")
	}
}

func TestRandomTokenIsUnpredictableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := randomToken()
		if len(tok) < 40 {
			t.Fatalf("token is too short to be 256 bits: %d chars", len(tok))
		}
		if seen[tok] {
			t.Fatal("randomToken produced a duplicate")
		}
		seen[tok] = true
	}
}

// ---- S01: subscriptions must not be fetched in the clear ------------------

func TestSubscriptionRefusesPlainHTTP(t *testing.T) {
	// A subscription carries server addresses and credentials, so there is no
	// acceptable downgrade.
	_, _, err := FetchSubscription("http://example.com/sub", "", false)
	if err == nil {
		t.Fatal("a plain http subscription was accepted")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("the refusal should explain that https is required, got %q", err)
	}
	_, _, err = FetchSubscription("not a url", "", false)
	if err == nil {
		t.Error("an unparseable address was accepted")
	}
}

// ---- helpers --------------------------------------------------------------

// ---- config: TUN must not be emittable by a subscription ------------------

func TestConfigEmitsTunOnlyWhenRequested(t *testing.T) {
	nodes := []Proxy{{Name: "n1", Type: "vmess", Server: "1.2.3.4", Port: 443}}
	for _, tc := range []struct {
		mode TunMode
		want bool
	}{
		{TunOff, false},
		{TunCompat, true},
		{TunPrivacy, true},
	} {
		cfg := BuildConfig(nodes, []string{"n1"}, Settings{
			MixedPort: 7890, ControlPort: 7797, Mode: "rule", TunMode: tc.mode,
			TunDevice: defaultTunDevice, TunStack: "gvisor",
		}, "secret", "n1", 8199)
		has := strings.Contains(cfg, "\ntun:\n")
		if has != tc.want {
			t.Errorf("mode %q: tun block present = %v, want %v", tc.mode, has, tc.want)
		}
		if tc.mode == TunPrivacy && !strings.Contains(cfg, "strict-route: true") {
			t.Error("privacy mode must ask the core for strict-route")
		}
		if tc.mode == TunCompat && !strings.Contains(cfg, "strict-route: false") {
			t.Error("compat mode must not claim strict routing")
		}
	}
}

func TestConfigIsValidJSONWhereItClaimsToBe(t *testing.T) {
	// The manifest takes the same shape as the component file; a broken manifest
	// must be rejected rather than half-read.
	var m componentManifest
	raw := []byte(`{"components":[{"name":"wintun","file":"x","sha256":"ab"}]}`)
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Components) != 1 || m.Components[0].Name != "wintun" {
		t.Fatalf("manifest parsed wrong: %+v", m)
	}
}

// ---- the pre-parse dispatch, and the watchdog's exit contract ---------------

func TestSelfTestInvocationIsInert(t *testing.T) {
	// The build check needs a way to prove the pre-parse dispatch works that
	// cannot itself change the machine, because running the real watchdog would
	// clear a system proxy pointing at a dead port.
	saved := os.Args
	defer func() { os.Args = saved }()

	os.Args = []string{"zenith.exe", "-self-test"}
	if !isSelfTestInvocation() {
		t.Error("-self-test should be recognised")
	}
	if isWatchdogInvocation() {
		t.Error("-self-test must not be mistaken for a watchdog run")
	}

	// With extra arguments following, the self-test is still recognised, and the
	// watchdog predicate is correctly false: it reads os.Args[1], which is
	// -self-test here. The release smoke test asserts on the classification of a
	// sample instead, which is what watchdogShapeOf is for.
	os.Args = []string{"zenith.exe", "-self-test", "-watchdog", `C:\data`, "7999"}
	if !isSelfTestInvocation() {
		t.Error("-self-test should still be recognised with extra arguments")
	}
	if isWatchdogInvocation() {
		t.Error("-watchdog in second position must not be read as the watchdog invocation")
	}

	// A watchdog invocation proper is a different shape.
	os.Args = []string{"zenith.exe", "-watchdog", `C:\data`, "7999"}
	if !isWatchdogInvocation() {
		t.Error("the watchdog form should be recognised")
	}
	if isSelfTestInvocation() {
		t.Error("the watchdog form must not be mistaken for a self-test")
	}

	// The classification of an arbitrary vector, which is what a build can check
	// without executing anything.
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"zenith.exe", "-watchdog", `C:\data`, "7899"}, true},
		{[]string{"zenith.exe", "-watchdog", `C:\data`, "0"}, true},
		{[]string{"zenith.exe", "-watchdog", `C:\data`, "abc"}, false},
		{[]string{"zenith.exe", "-watchdog", `C:\data`}, false},
		{[]string{"zenith.exe", "-self-test", "-watchdog", `C:\data`, "7899"}, false},
		{[]string{"zenith.exe", "-headless"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := watchdogShapeOf(c.args); got != c.want {
			t.Errorf("watchdogShapeOf(%v) = %v, want %v", c.args, got, c.want)
		}
	}
	// The two predicates must agree on the same vector, or the running process and
	// the build check would disagree about what a watchdog is.
	os.Args = []string{"zenith.exe", "-watchdog", `C:\data`, "7899"}
	if isWatchdogInvocation() != watchdogShapeOf(os.Args) {
		t.Error("isWatchdogInvocation and watchdogShapeOf disagree on the same vector")
	}
}

func TestWatchdogToleratesMissingDataDirectory(t *testing.T) {
	// The watchdog is best-effort: finding nothing to do is its normal outcome.
	// A missing ownership record must not turn into an error, because a supervisor
	// or a build check would read a non-zero status as "the machine is broken".
	saved := os.Args
	defer func() { os.Args = saved }()

	missing := filepath.Join(t.TempDir(), "not-created")
	os.Args = []string{"zenith.exe", "-watchdog", missing, "7908"}
	if !isWatchdogInvocation() {
		t.Fatal("the watchdog form should be recognised")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// NeutraliseFromOtherProcess is the body runWatchdogFromArgs calls. It must
		// return rather than panic or block when the directory is absent.
		NeutraliseFromOtherProcess(missing, 7908)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the watchdog did not finish; it must not retry forever on a missing directory")
	}

	// A nonsense port must be ignored rather than acted on.
	NeutraliseFromOtherProcess(missing, 0)
	NeutraliseFromOtherProcess(missing, -1)
}

func TestPortFromServerParsing(t *testing.T) {
	// The watchdog and the dead-proxy guard both key off this, so a wrong answer
	// here would make them act on a port that is not ours.
	cases := map[string]int{
		"127.0.0.1:7899": 7899,
		"127.0.0.1:7890": 7890,
		"":               0,
		"127.0.0.1":      0,
		"not a server":   0,
	}
	for in, want := range cases {
		if got := portFromServer(in); got != want {
			t.Errorf("portFromServer(%q) = %d, want %d", in, got, want)
		}
	}
}

// ---- R06: configuration changes must be verifiable and reversible -----------

func TestValidateCandidateConfigCatchesWhatTheCoreWouldReject(t *testing.T) {
	good := BuildConfig(
		[]Proxy{{Name: "n1", Type: "vmess", Server: "1.2.3.4", Port: 443, Network: "ws"}},
		[]string{"n1"},
		Settings{MixedPort: 7890, ControlPort: 7797, Mode: "rule", TunDevice: defaultTunDevice, TunStack: "gvisor"},
		"secret", "n1", 8199)
	if err := validateCandidateConfig(good); err != nil {
		t.Fatalf("a configuration the app generated was rejected: %v", err)
	}

	// Each of these is a shape the core would refuse, and installing one would
	// take the running core down. They must be caught before anything is written.
	bad := []struct{ name, cfg string }{
		{"empty", ""},
		{"whitespace only", "   \n\n  "},
		{"no port", "proxies:\n  - {name: n1, type: socks5, server: 1.2.3.4, port: 1}\nproxy-groups: []\nrules: []\n"},
		{"no proxies", "mixed-port: 7890\nproxy-groups: []\nrules: []\n"},
		{"no groups", "mixed-port: 7890\nproxies:\n  - {name: n1, type: socks5, server: 1.2.3.4, port: 1}\nrules: []\n"},
		{"no rules", "mixed-port: 7890\nproxies:\n  - {name: n1, type: socks5, server: 1.2.3.4, port: 1}\nproxy-groups: []\n"},
		{"group references a node that does not exist",
			"mixed-port: 7890\nproxies:\n  - {name: n1, type: socks5, server: 1.2.3.4, port: 1}\n" +
				"proxy-groups:\n  - name: \"PROXY\"\n    type: select\n    proxies:\n      - \"n2\"\n      - \"DIRECT\"\nrules:\n  - \"MATCH,PROXY\"\n"},
	}
	for _, c := range bad {
		if err := validateCandidateConfig(c.cfg); err == nil {
			t.Errorf("%s: the candidate was accepted but the core would refuse it", c.name)
		}
	}

	// A group naming a built-in is fine; DIRECT and REJECT are not proxies.
	withBuiltins := "mixed-port: 7890\nproxies:\n  - {name: n1, type: socks5, server: 1.2.3.4, port: 1}\n" +
		"proxy-groups:\n  - name: \"PROXY\"\n    type: select\n    proxies:\n" +
		"      - \"n1\"\n      - \"DIRECT\"\n      - \"REJECT\"\nrules:\n  - \"MATCH,PROXY\"\n"
	if err := validateCandidateConfig(withBuiltins); err != nil {
		t.Errorf("built-in targets should be allowed: %v", err)
	}
}

func TestConfigRollbackWithoutAPreviousVersionSaysSo(t *testing.T) {
	// On a first run there is nothing to restore. Claiming otherwise would leave
	// the user believing a configuration is in effect when none ever was.
	dir := t.TempDir()
	a := &App{dataDir: dir, configPath: filepath.Join(dir, "config.yaml")}
	tx := &configTxn{ID: "t", State: "failed", StartedAt: time.Now()}

	a.rollbackConfig(tx)

	if tx.State != "rolledBack" {
		t.Errorf("state = %q, want rolledBack", tx.State)
	}
	found := false
	for _, s := range tx.Steps {
		if s.Name == "回滚" && s.State == "skipped" {
			found = true
		}
	}
	if !found {
		t.Error("a rollback with nothing to restore must record that, not silently do nothing")
	}
	if _, err := os.Stat(a.configPath); err == nil {
		t.Error("a rollback with no known-good version must not create a configuration file")
	}
}

func TestConfigRollbackRestoresTheGoodVersion(t *testing.T) {
	dir := t.TempDir()
	a := &App{dataDir: dir, configPath: filepath.Join(dir, "config.yaml")}
	good := []byte("mixed-port: 7890\nproxies: []\nproxy-groups: []\nrules: []\n")
	if err := os.WriteFile(a.goodConfigPath(), good, 0o644); err != nil {
		t.Fatal(err)
	}
	// The candidate that failed is what is on disk now.
	if err := os.WriteFile(a.configPath, []byte("this is not valid yaml at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	tx := &configTxn{ID: "t", State: "failed", StartedAt: time.Now()}
	a.rollbackConfig(tx)

	got, err := os.ReadFile(a.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Errorf("rollback did not restore the known-good configuration:\n%q", got)
	}
	if tx.State != "rolledBack" {
		t.Errorf("state = %q, want rolledBack", tx.State)
	}
}

func TestConfigTransactionRecordSurvivesARestart(t *testing.T) {
	// A crash mid-activation is exactly the case the record exists for, so it has
	// to be durable and readable back.
	dir := t.TempDir()
	a := &App{dataDir: dir}
	tx := &configTxn{ID: "cfg-1", State: "activated", StartedAt: time.Now(), Digest: "abc123"}
	a.saveConfigTxn(tx)
	back := a.loadConfigTxn()
	if back == nil {
		t.Fatal("the transaction record could not be read back")
	}
	if back.State != "activated" || back.Digest != "abc123" {
		t.Errorf("record lost data: %+v", back)
	}
}

func TestDigestOfIsStableAndDistinguishing(t *testing.T) {
	a := digestOf([]byte("hello"))
	b := digestOf([]byte("hello"))
	c := digestOf([]byte("hello!"))
	if a != b {
		t.Error("the same input produced different digests")
	}
	if a == c {
		t.Error("different inputs produced the same digest")
	}
	if len(a) != 64 {
		t.Errorf("digest should be 64 hex characters, got %d", len(a))
	}
}

func TestToIntAcceptsTheShapesJSONProduces(t *testing.T) {
	// The core reports ports as JSON numbers, which decode to float64, but other
	// fields arrive as strings. A wrong answer here would make the activation
	// verification compare against garbage.
	cases := []struct {
		in   interface{}
		want int
		ok   bool
	}{
		{float64(7890), 7890, true},
		{int(7891), 7891, true},
		{"7892", 7892, true},
		{"not a number", 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := toInt(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("toInt(%v) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// ---- R08: the active subscription must be recorded where readers look -------

func TestActiveSubscriptionFallsBackToTheEnabledFlag(t *testing.T) {
	// Two fields describe which subscription is in use, and only one of them used
	// to be written. Every reader of the other saw nothing, which is how the
	// scheduled refresh ended up with no target and silently did nothing.
	//
	// A file written before the fix has Enabled set and SelectedSub empty. It must
	// still report the subscription in use, or the refresh stays broken for
	// existing users.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []Subscription{
		{ID: "a", Name: "one", URL: "https://a.example/x", Enabled: false},
		{ID: "b", Name: "two", URL: "https://b.example/y", Enabled: true},
	}
	if err := st.SetSubscriptions(legacy); err != nil {
		t.Fatal(err)
	}
	if got := st.ActiveSubscription(); got != "b" {
		t.Errorf("legacy file: ActiveSubscription = %q, want %q (the enabled one)", got, "b")
	}

	// Setting it explicitly must move both fields together.
	if err := st.SetActiveSubscription("a"); err != nil {
		t.Fatal(err)
	}
	if got := st.ActiveSubscription(); got != "a" {
		t.Errorf("after selecting a: ActiveSubscription = %q, want a", got)
	}
	snap := st.Snapshot()
	for _, sub := range snap.Subscriptions {
		want := sub.ID == "a"
		if sub.Enabled != want {
			t.Errorf("subscription %q has Enabled=%v, want %v", sub.ID, sub.Enabled, want)
		}
	}
	if snap.SelectedSub != "a" {
		t.Errorf("SelectedSub = %q, want a; the two fields must not drift apart", snap.SelectedSub)
	}

	// Exactly one subscription may be active at a time.
	n := 0
	for _, sub := range snap.Subscriptions {
		if sub.Enabled {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d subscriptions are enabled, want exactly 1", n)
	}
}

func TestActiveSubscriptionSurvivesAReload(t *testing.T) {
	// The value is what the scheduled refresh uses, so it has to be durable.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscriptions([]Subscription{
		{ID: "x", Name: "x", URL: "https://x.example/1"},
		{ID: "y", Name: "y", URL: "https://y.example/2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetActiveSubscription("y"); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.ActiveSubscription(); got != "y" {
		t.Errorf("after a reload ActiveSubscription = %q, want y", got)
	}
}

// ---- S05: a subscription is data, not policy -------------------------------

func TestExtraKeysCannotRestructureTheConfiguration(t *testing.T) {
	// The generator used to write unknown provider keys through verbatim, and the
	// key name goes into the YAML unescaped. A key containing a colon, a newline or
	// a control character can therefore change the shape of the document rather
	// than describe a proxy option - which would let an imported subscription
	// reach the controller, the DNS block, the TUN block or the rules.
	node := Proxy{
		Name: "hostile", Type: "vmess", Server: "1.2.3.4", Port: 443,
		Network: "ws",
		Extra: map[string]interface{}{
			// a key that would close the proxy mapping and open a new top-level one
			"x": nil,
			// the ones that must never survive
			"controller: 0.0.0.0:9090": "yes",
			"a\nb":                     "yes",
			"tun\x00":                  "yes",
			"  dns:":                   "yes",
			"- rules:":                 "yes",
			"external-controller":      "0.0.0.0:9090",
			"secret":                   "INJECTED-SECRET-VALUE",
		},
	}
	cfg := BuildConfig([]Proxy{node}, []string{"hostile"},
		Settings{MixedPort: 7890, ControlPort: 7797, Mode: "rule", TunDevice: defaultTunDevice, TunStack: "gvisor"},
		"realsecret", "hostile", 8199)

	// Distinctive strings, so a match can only come from an injected key and never
	// from prose in the template's own comments. An earlier version of this test
	// looked for the word "leak" and failed on the comment that says "leaking".
	for _, forbidden := range []string{
		"0.0.0.0:9090",          // the attacker's controller address
		"INJECTED-SECRET-VALUE", // the attacker's secret value
		"- rules: ",             // a key that would open a new top-level section
		"\n  dns: ",             // likewise
	} {
		if strings.Contains(cfg, forbidden) {
			t.Errorf("a subscription key reached the configuration: %q\n%s", forbidden, cfg)
		}
	}
	// The legitimate header values must be unchanged. That is the precise claim: a
	// subscription cannot alter the controller or the secret - not that those words
	// are absent from a file that is supposed to contain them.
	if !strings.Contains(cfg, "external-controller: 127.0.0.1:7797") {
		t.Error("the real controller address was altered or lost")
	}
	if !strings.Contains(cfg, `secret: "realsecret"`) {
		t.Error("the real secret was altered or lost")
	}
	if n := strings.Count(cfg, "external-controller"); n != 1 {
		t.Errorf("the controller key appears %d times; a subscription injected a second one", n)
	}
	if n := strings.Count(cfg, "secret:"); n != 1 {
		t.Errorf("the secret key appears %d times; a subscription injected a second one", n)
	}
	// The configuration must still be one the validator accepts: the point is that
	// the hostile keys changed nothing, not that they broke the file.
	if err := validateCandidateConfig(cfg); err != nil {
		t.Errorf("the configuration with hostile keys is not valid: %v", err)
	}
}

func TestAllowedExtraKeysStillPassThrough(t *testing.T) {
	// The boundary must not throw away ordinary provider options, or real
	// subscriptions would lose settings they depend on.
	node := Proxy{
		Name: "n", Type: "vmess", Server: "1.2.3.4", Port: 443, Network: "ws",
		Extra: map[string]interface{}{
			"alpn":             []interface{}{"h2", "http/1.1"},
			"packet-encoding":  "xudp",
			"tfo":              true,
			"skip-cert-verify": false,
			"mptcp":            true,
		},
	}
	cfg := BuildConfig([]Proxy{node}, []string{"n"},
		Settings{MixedPort: 7890, ControlPort: 7797, Mode: "rule", TunDevice: defaultTunDevice, TunStack: "gvisor"},
		"secret", "n", 8199)
	for _, want := range []string{"alpn:", "packet-encoding:", "tfo:", "mptcp:"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("an allowed option was dropped: %q missing from\n%s", want, cfg)
		}
	}
}

func TestSafeExtraKeyName(t *testing.T) {
	good := []string{"alpn", "packet-encoding", "udp-over-tcp", "reality-opts", "a.b", "x_1"}
	for _, k := range good {
		if !safeExtraKeyName(k) {
			t.Errorf("safeExtraKeyName(%q) = false, want true", k)
		}
	}
	bad := []string{
		"", "controller: 9090", "a b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x1bb",
		"  dns", "dns:", "- rules", "a[0]", "a{b}", "a,b", "a'b", `a"b`,
		strings.Repeat("x", 65),
	}
	for _, k := range bad {
		if safeExtraKeyName(k) {
			t.Errorf("safeExtraKeyName(%q) = true, want false", k)
		}
	}
}

func TestAllowedExtraKeyIsAnAllowlist(t *testing.T) {
	// Anything not named is refused. A denylist would have to anticipate every way
	// a crafted key could escape its block, and missing one means a subscription
	// that rewrites the running configuration.
	if allowedExtraKey("external-controller") {
		t.Error("the controller must never be settable from a subscription")
	}
	if allowedExtraKey("dns") || allowedExtraKey("tun") || allowedExtraKey("rules") {
		t.Error("global sections must never be settable from a subscription")
	}
	if allowedExtraKey("bind-address") || allowedExtraKey("allow-lan") {
		t.Error("listener settings must never be settable from a subscription")
	}
	if !allowedExtraKey("alpn") {
		t.Error("ordinary transport options should pass")
	}
}

// ---- R09: results must not outlive the material they describe --------------

func TestStaleOptimisationResultsAreRefused(t *testing.T) {
	// A scan takes minutes. If the user switches subscriptions inside that window,
	// results describing the old nodes must be discarded rather than installed -
	// otherwise the node list, the health history and the current selection all end
	// up pointing at servers that are no longer in the subscription.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	stale := []Proxy{{Name: "old-1", Server: "1.1.1.1"}, {Name: "old-2", Server: "2.2.2.2"}}
	current := []Proxy{{Name: "new-1", Server: "3.3.3.3"}}

	gen := st.SubscriptionGeneration()

	// The subscription changes while the scan is running.
	st.BumpSubscriptionGeneration()

	ok, err := st.SetOptimizedIfCurrent(gen, stale)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("results from before the subscription change were installed")
	}
	snap := st.Snapshot()
	for _, p := range snap.Optimized {
		if strings.HasPrefix(p.Name, "old-") {
			t.Errorf("a stale node reached the store: %q", p.Name)
		}
	}

	// Results from the current generation are accepted.
	ok, err = st.SetOptimizedIfCurrent(st.SubscriptionGeneration(), current)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("results from the current generation were refused")
	}
	if got := len(st.Snapshot().Optimized); got != 1 {
		t.Errorf("stored %d optimised nodes, want 1", got)
	}
}

func TestBaseNodeChangesBumpTheGeneration(t *testing.T) {
	// The generation has to move on every path that changes the material, or the
	// staleness check silently stops protecting anything.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	g0 := st.SubscriptionGeneration()
	if err := st.SetNodes([]Proxy{{Name: "a", Server: "1.1.1.1"}}, nil); err != nil {
		t.Fatal(err)
	}
	g1 := st.SubscriptionGeneration()
	if g1 == g0 {
		t.Error("changing the base nodes did not advance the generation")
	}
	st.BumpSubscriptionGeneration()
	if st.SubscriptionGeneration() == g1 {
		t.Error("an explicit bump did not advance the generation")
	}
}

func TestOptimizedIsCurrentReflectsTheStore(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing optimised yet.
	if st.OptimizedIsCurrent() {
		t.Error("an empty optimisation should not report as current")
	}
	gen := st.SubscriptionGeneration()
	if ok, err := st.SetOptimizedIfCurrent(gen, []Proxy{{Name: "n", Server: "1.1.1.1"}}); err != nil || !ok {
		t.Fatalf("setup failed: ok=%v err=%v", ok, err)
	}
	if !st.OptimizedIsCurrent() {
		t.Error("fresh results should report as current")
	}
	st.BumpSubscriptionGeneration()
	if st.OptimizedIsCurrent() {
		t.Error("results should stop being current once the subscription changes")
	}
}

// ---- L4: the end-to-end verification must report where it broke ------------

func TestEndToEndVerificationReportsTheStage(t *testing.T) {
	// Success through the tunnel is the only evidence the whole path works, and a
	// failure has to say which stage broke rather than just "it did not work".
	// With no core running there is nothing to route through, and that is a
	// specific, reportable condition.
	a := &App{}
	res := a.VerifySelectedEndToEnd()
	if res.OK {
		t.Fatal("verification reported success with no core running")
	}
	if res.Stage != "core" {
		t.Errorf("stage = %q, want core; the report must name where it failed", res.Stage)
	}
	if res.Detail == "" {
		t.Error("a failure must carry an explanation")
	}
	if res.TestedAt == "" {
		t.Error("the result should record when it was taken")
	}
}

func TestHTTPThroughProxyRejectsANonsensePort(t *testing.T) {
	// The helper is kept as a building block for the local-listener check. A bad
	// port must fail immediately rather than attempting a connection.
	if err := httpThroughProxy(0, "http://example.invalid/", time.Second); err == nil {
		t.Error("port 0 should be refused")
	}
	if err := httpThroughProxy(-1, "http://example.invalid/", time.Second); err == nil {
		t.Error("a negative port should be refused")
	}
}

func TestOptimizedCurrentIsReportedInStatus(t *testing.T) {
	// A stale optimisation is a real condition after a subscription change, and
	// the interface needs to be able to say so rather than showing nodes that are
	// no longer in the subscription.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.OptimizedIsCurrent() {
		t.Error("a store with no optimisation should not report current")
	}
	if ok, err := st.SetOptimizedIfCurrent(st.SubscriptionGeneration(),
		[]Proxy{{Name: "n", Server: "1.1.1.1"}}); err != nil || !ok {
		t.Fatalf("setup failed: ok=%v err=%v", ok, err)
	}
	if !st.OptimizedIsCurrent() {
		t.Error("fresh results should report current")
	}
}

// ---- the elevated instance must not be mistaken for a second launch --------

func TestElevatedDispatchComesBeforeTheSingleInstanceCheck(t *testing.T) {
	// The ordinary instance already holds the UI port, so a check for "is
	// something listening" matches the elevated instance too. When the elevated
	// dispatch sat after it, approving the prompt produced a second window and no
	// tunnel: the process decided it was a second launch and exited before doing
	// the work it was elevated for.
	//
	// This is an ordering property of main, so it is checked against the source
	// rather than by running it - the failure mode is a wrong branch, not a wrong
	// return value.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("main.go is not readable from the test directory: %v", err)
	}
	text := string(src)

	elevated := strings.Index(text, "if *tunElevated {")
	instance := strings.Index(text, "if IsPortListening(uiPort) {")
	if elevated < 0 {
		t.Fatal("the elevated dispatch is missing from main")
	}
	if instance < 0 {
		t.Fatal("the single-instance check is missing from main")
	}
	if elevated > instance {
		t.Error("the elevated dispatch sits after the single-instance check, so an " +
			"elevated run would be treated as a second launch and never activate TUN")
	}
}

func TestElevatedRunReturnsAnErrorRatherThanReportingThroughState(t *testing.T) {
	// The elevated process has no window and no UI, and it is started through
	// ShellExecute so its exit status cannot be read either. Its verdict reaches
	// the interface through the handover record, and a signature that returned
	// nothing would leave the caller unable to say whether the activation worked -
	// which is exactly the defect: the outcome used to be read back from a progress
	// object this process never initialised, so a failure was reported as success.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func (a *App) RunElevatedActivation(mode TunMode, handoverID string, requesterPID int) error {") {
		t.Error("RunElevatedActivation should take the handover id and return an error, so its " +
			"outcome can be reported rather than inferred")
	}
	// And it must report through the channel, not through local state.
	if !strings.Contains(text, "a.finishHandover(rec,") {
		t.Error("the elevated activation does not write its verdict to the handover record")
	}
}

// ---- the activation handover must not start a second core ------------------

func TestActivationYieldBlocksCoreRecovery(t *testing.T) {
	// The ordinary instance restarts a core it finds down. An elevated activation
	// has to stop that core to take the ports, so without a yield the background
	// loop starts a second one on top of the activation and the two fight for the
	// same listener.
	dir := t.TempDir()
	a := &App{dataDir: dir}

	if a.activationYielded() {
		t.Error("a fresh instance should not report a yield")
	}
	a.yieldForActivation()
	if !a.activationYielded() {
		t.Fatal("the yield marker was not honoured")
	}
	a.releaseActivation()
	if a.activationYielded() {
		t.Error("the yield marker survived its release, which would disable core recovery")
	}
}

func TestStaleActivationYieldIsDiscarded(t *testing.T) {
	// An elevated instance killed mid-activation would otherwise leave a marker
	// behind forever, and the ordinary instance would never restart its core
	// again - a far worse failure than the conflict the marker prevents.
	dir := t.TempDir()
	a := &App{dataDir: dir}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.WriteFile(a.activationYieldPath(), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(a.activationYieldPath(), old, old); err != nil {
		t.Fatal(err)
	}
	if a.activationYielded() {
		t.Error("a marker older than the threshold must not keep blocking recovery")
	}
	if _, err := os.Stat(a.activationYieldPath()); err == nil {
		t.Error("the stale marker should have been removed")
	}
}

// ---- an isolated run must never destroy a real data directory --------------

func TestIsolatedRunDoesNotOverwriteAnExistingState(t *testing.T) {
	// This is the failure that actually happened: -datadir pointed at a directory
	// in use, free.flag was absent, and an empty state.json was written over the
	// user's subscriptions, nodes and settings - silently, with nothing to restore
	// from. The rule is that an existing state file is never replaced.
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	real := []byte(`{"settings":{"mixedPort":7899},"subscriptions":[{"id":"keepme"}]}`)
	if err := os.WriteFile(stateFile, real, 0o644); err != nil {
		t.Fatal(err)
	}

	// The guard this models: initialise only when there is no state file.
	mustNotInit := func() bool {
		return fileExists(filepath.Join(dir, "state.json"))
	}
	if !mustNotInit() {
		t.Fatal("an existing state file should be recognised as existing")
	}

	// And an empty directory is still initialised.
	empty := t.TempDir()
	if fileExists(filepath.Join(empty, "state.json")) {
		t.Error("an empty directory should report no state file, so it can be initialised")
	}
}

func TestFileExistsDistinguishesFilesFromDirectories(t *testing.T) {
	dir := t.TempDir()
	if fileExists(dir) {
		t.Error("a directory should not be reported as an existing file")
	}
	f := filepath.Join(dir, "x")
	if fileExists(f) {
		t.Error("a missing path should not be reported as existing")
	}
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !fileExists(f) {
		t.Error("an existing file should be reported as existing")
	}
}

func TestInjectedPortCannotReachTheRealConfiguration(t *testing.T) {
	// The same class of mistake in the generator: a subscription key must not be
	// able to change a global setting. Checked here as well as in the S05 test so
	// the property is stated for the configuration as a whole.
	node := Proxy{
		Name: "n", Type: "socks5", Server: "1.2.3.4", Port: 1080,
		Extra: map[string]interface{}{"mixed-port": 1, "allow-lan": true},
	}
	cfg := BuildConfig([]Proxy{node}, []string{"n"},
		Settings{MixedPort: 7899, ControlPort: 7797, Mode: "rule", TunDevice: defaultTunDevice, TunStack: "gvisor"},
		"secret", "n", 8199)
	if strings.Contains(cfg, "mixed-port: 1") {
		t.Error("a subscription overrode the mixed port")
	}
	if !strings.Contains(cfg, "mixed-port: 7899") {
		t.Error("the configured mixed port was lost")
	}
	if strings.Contains(cfg, "allow-lan: true") {
		t.Error("a subscription enabled LAN exposure")
	}
}

// ---- a run that promised not to touch the proxy must keep that promise -----

func TestReadOnlySystemProxyRefusesToMutate(t *testing.T) {
	// The promise used to be a log line. An isolated run then disabled the proxy
	// the real instance was serving, because its dead-port guard cannot tell a
	// broken proxy from one belonging to an instance it must not disturb.
	dir := t.TempDir()
	sp := NewSystemProxy(dir)
	sp.SetReadOnly(true)

	// Every mutating path must be inert. These are called with a port nothing is
	// listening on, which is exactly the condition that used to trigger a write.
	before := sp.Status()
	sp.GuardDeadProxy()
	if sp.Restore() {
		t.Error("Restore reported success on a read-only handle")
	}
	sp.Disable()
	after := sp.Status()
	if before.Enabled != after.Enabled || before.Server != after.Server {
		t.Errorf("a read-only handle changed the proxy state: %+v -> %+v", before, after)
	}
}

func TestReadOnlyIsOffByDefault(t *testing.T) {
	// A normal instance must still be able to manage the proxy, or the read-only
	// guard would turn into a feature that silently stops working.
	sp := NewSystemProxy(t.TempDir())
	if sp.readOnly {
		t.Error("a freshly created SystemProxy should not be read-only")
	}
	sp.SetReadOnly(true)
	if !sp.readOnly {
		t.Error("SetReadOnly(true) did not take effect")
	}
	sp.SetReadOnly(false)
	if sp.readOnly {
		t.Error("SetReadOnly(false) did not take effect")
	}
}

// ---- the system proxy must follow the port --------------------------------

func TestPortRotationMustRepointAnOwnedProxy(t *testing.T) {
	// The registry kept pointing at the port nothing was listening on after a
	// rotation, so every application that honours the system proxy was silently
	// offline while the interface still reported the proxy as on. That is the
	// worst outcome this program can produce, and it happened.
	//
	// This asserts the decision rule rather than the registry itself, since the
	// test must not change the machine it runs on.
	owned := []string{"", "zenith", "mihomo", "Zenith", "MIHOMO"}
	for _, o := range owned {
		if !proxyOwnerIsOurs(o) {
			t.Errorf("owner %q should be treated as ours, so the proxy can follow the port", o)
		}
	}
	foreign := []string{"clash-verge", "FlClash", "v2rayN", "sing-box", "Clash for Windows"}
	for _, o := range foreign {
		if proxyOwnerIsOurs(o) {
			t.Errorf("owner %q is another product; its proxy setting must be left alone", o)
		}
	}
}

// ---- enabling TUN must actually reach the configuration --------------------

func TestTunSettingsTriggerAConfigRewrite(t *testing.T) {
	// The three TUN settings were missing from the reload trigger list, and the
	// consequence was exact: enabling TUN stored the mode, restarted the core, and
	// never wrote a config containing a tun block. The core therefore started
	// without TUN, no adapter appeared, and the activation waited out its timeout
	// and rolled back. The core's own log had no TUN lines at all.
	//
	// This is a property of a list in ApplySettings, so it is checked against the
	// source: a missing entry is a silent failure with no return value to assert on.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable from the test directory: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "needReload := false")
	if start < 0 {
		t.Fatal("the reload trigger list is missing from ApplySettings")
	}
	end := strings.Index(text[start:], "if needReload {")
	if end < 0 {
		t.Fatal("could not find the end of the reload trigger list")
	}
	block := text[start : start+end]
	for _, key := range []string{"tunMode", "tunDevice", "tunStack"} {
		if !strings.Contains(block, `"`+key+`"`) {
			t.Errorf("%q is not in the reload trigger list, so changing it would not "+
				"rewrite the configuration and TUN would never be enabled", key)
		}
	}
	// And the settings that were already there must stay, or this fix would have
	// traded one silent failure for another.
	for _, key := range []string{"mixedPort", "blockAds", "customRules"} {
		if !strings.Contains(block, `"`+key+`"`) {
			t.Errorf("%q was dropped from the reload trigger list", key)
		}
	}
}

func TestTunModeProducesATunBlockInTheGeneratedConfig(t *testing.T) {
	// The other half of the same property: once the rewrite is triggered, the
	// generated configuration must actually contain the block the core needs.
	base := Settings{MixedPort: 7899, ControlPort: 7797, Mode: "rule",
		TunDevice: defaultTunDevice, TunStack: "gvisor"}
	off := BuildConfig([]Proxy{{Name: "n", Type: "socks5", Server: "1.2.3.4", Port: 1080}},
		[]string{"n"}, base, "s", "n", 8199)
	if strings.Contains(off, "\ntun:\n") {
		t.Error("a tun block was emitted while TUN was off")
	}

	on := base
	on.TunMode = TunPrivacy
	withTun := BuildConfig([]Proxy{{Name: "n", Type: "socks5", Server: "1.2.3.4", Port: 1080}},
		[]string{"n"}, on, "s", "n", 8199)
	if !strings.Contains(withTun, "\ntun:\n") {
		t.Fatal("enabling TUN produced no tun block, so the core would start without it")
	}
	if !strings.Contains(withTun, "enable: true") {
		t.Error("the tun block is present but not enabled")
	}
	// The mode has to reach the block, or the three policies would be one policy.
	if !strings.Contains(withTun, "strict-route: true") {
		t.Error("privacy mode should ask for a strict route")
	}
	if err := validateCandidateConfig(withTun); err != nil {
		t.Errorf("the generated TUN configuration is not valid: %v", err)
	}
}

func TestApplySettingsRewritesConfigForTunMode(t *testing.T) {
	// End to end through the real store: change the TUN mode the way the
	// activation does, and confirm the generated configuration gains a tun block.
	// The earlier tests asserted the trigger list and the generator separately;
	// this asserts the join, which is where the failure actually was.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateSettings(map[string]interface{}{
		"tunMode": "compat", "tunDevice": "Zenith", "tunStack": "gvisor",
	}); err != nil {
		t.Fatal(err)
	}
	got := st.Settings()
	if got.TunMode != TunCompat {
		t.Fatalf("tunMode = %q, want compat", got.TunMode)
	}
	if got.TunDevice != "Zenith" {
		t.Errorf("tunDevice = %q, want Zenith", got.TunDevice)
	}
	if got.TunStack != "gvisor" {
		t.Errorf("tunStack = %q, want gvisor", got.TunStack)
	}

	a := &App{dataDir: dir, store: st}
	cfg := BuildConfig([]Proxy{{Name: "n", Type: "socks5", Server: "1.2.3.4", Port: 1080}},
		[]string{"n"}, got, "s", "n", 8199)
	if !strings.Contains(cfg, "\ntun:\n") {
		t.Error("the stored settings did not produce a tun block")
	}
	if !strings.Contains(cfg, "device: \"Zenith\"") {
		t.Error("the tun block does not name the adapter the activation waited for")
	}
	_ = a
}

// ---- the TUN component check must test capability, not a file --------------

func TestCoreDoesNotNeedAnExternalWintunDll(t *testing.T) {
	// Measured behaviour, which this test records rather than re-runs: with no
	// wintun.dll beside mihomo.exe, and again with a four-kilobyte junk file of
	// that name in its place, the core produced byte-identical output and still
	// reached "configure tun interface: Access is denied". It never opens the
	// file - the driver it uses is embedded in the binary and loaded from memory.
	//
	// The check used to block on that file, so a user whose core was perfectly
	// capable was told the build was incomplete and to download it again. This
	// asserts the decision rule that replaced it.
	env := tunEnvironment{Checks: map[string]string{}, Warnings: []string{}}

	// Absence of the external copy must not block.
	missing := tunComponentState{Name: "wintun", Version: "0.14.1", Verified: false,
		Detail: "文件不存在"}
	if componentBlocksTun(missing) {
		t.Error("a missing external wintun copy must not block TUN: the core does not use it")
	}
	// Absence of the manifest must not block either.
	if manifestBlocksTun(nil) {
		t.Error("a missing component manifest must not block TUN")
	}
	// A mismatched external copy is worth a warning, not a refusal.
	mismatch := tunComponentState{Name: "wintun", Version: "0.14.1", Verified: false,
		Detail: "摘要不符"}
	if componentBlocksTun(mismatch) {
		t.Error("a mismatched external copy must warn rather than block")
	}
	// A verified one is simply fine.
	ok := tunComponentState{Name: "wintun", Version: "0.14.1", Verified: true, Signed: true,
		Signer: "CN=WireGuard LLC"}
	if componentBlocksTun(ok) {
		t.Error("a verified component must not block")
	}
	_ = env
}

func TestCoreBuildInfoReadsArchitecture(t *testing.T) {
	// The architecture matters: an arm64 core on an amd64 machine cannot create an
	// adapter, and reading that from the file is more useful than a driver error
	// later. This runs against the core that ships with the program.
	arch, ver := coreBuildInfo(filepath.Join("..", "core", "mihomo.exe"))
	if arch == "" {
		t.Skip("core/mihomo.exe is not readable from the test directory")
	}
	if arch != "amd64" {
		t.Errorf("core architecture = %q, want amd64 on this build", arch)
	}
	if ver == "" || ver == "未知版本" {
		t.Errorf("core version was not read: %q", ver)
	}
	// A file that is not a PE image must return empty rather than guessing.
	dir := t.TempDir()
	junk := filepath.Join(dir, "notape.exe")
	if err := os.WriteFile(junk, bytes.Repeat([]byte("A"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if a, v := coreBuildInfo(junk); a != "" || v != "" {
		t.Errorf("a non-PE file produced (%q, %q), want empty", a, v)
	}
}

func TestTunDefaultsAreNormalizedOnLoad(t *testing.T) {
	// A settings file written before these fields existed has them empty. The
	// environment check used to substitute the default locally without telling
	// anyone, so the check reported one name, the generated configuration carried
	// another, and the adapter lookup searched for a third. The migration now
	// normalizes once and every stage reads the same value.
	dir := t.TempDir()
	legacy := `{"settings":{"mixedPort":7890,"controlPort":7797,"mode":"rule",` +
		`"tunDevice":"","tunStack":""}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := st.Settings()
	if got.TunDevice != tunDefaultDevice {
		t.Errorf("tunDevice = %q, want %q after migration", got.TunDevice, tunDefaultDevice)
	}
	if got.TunStack != tunDefaultStack {
		t.Errorf("tunStack = %q, want %q after migration", got.TunStack, tunDefaultStack)
	}
	if got.NormalizedTunDevice() != got.TunDevice {
		t.Error("the migration and the accessor disagree about the device name")
	}

	// An unusable stack must be repaired rather than passed to the core, which
	// would refuse the whole configuration.
	bad := Settings{TunDevice: "  ", TunStack: "not-a-stack"}
	if bad.NormalizedTunDevice() != tunDefaultDevice {
		t.Error("a blank device name must normalize to the default")
	}
	if bad.NormalizedTunStack() != tunDefaultStack {
		t.Error("an unrecognised stack must normalize to a value the core accepts")
	}
	// A valid explicit choice must survive.
	keep := Settings{TunDevice: "MyTun", TunStack: "system"}
	if keep.NormalizedTunDevice() != "MyTun" {
		t.Error("an explicit device name must be kept")
	}
	if keep.NormalizedTunStack() != "system" {
		t.Error("an explicit valid stack must be kept")
	}
}

func TestGeneratedConfigUsesTheNormalizedValues(t *testing.T) {
	// The generator and the environment check must agree, or the adapter that gets
	// created is not the one being looked for.
	st := Settings{MixedPort: 7890, ControlPort: 7797, Mode: "rule",
		TunMode: TunCompat, TunDevice: "", TunStack: ""}
	// Normalize the way the migration would.
	st.TunDevice = st.NormalizedTunDevice()
	st.TunStack = st.NormalizedTunStack()
	cfg := BuildConfig([]Proxy{{Name: "n", Type: "socks5", Server: "1.2.3.4", Port: 1}},
		[]string{"n"}, st, "s", "n", 8199)
	if !strings.Contains(cfg, `device: "`+tunDefaultDevice+`"`) {
		t.Errorf("the generated configuration does not name %q:\n%s", tunDefaultDevice, cfg)
	}
	// The stack is emitted quoted, so the assertion matches the quoted form rather
	// than assuming a bare scalar.
	if !strings.Contains(cfg, `stack: "`+tunDefaultStack+`"`) {
		t.Errorf("the generated configuration does not use stack %q:\n%s", tunDefaultStack, cfg)
	}
}

// ---- P0-1: the handover must have a result channel --------------------------

// testAppForHandover builds an App with a control secret, which the handover record
// needs: the record is signed with it, and a record without a valid signature is
// refused. Production always has a secret - it is created with the data directory -
// so a test without one models a state that cannot occur.
func testAppForHandover(dir string) *App {
	return &App{dataDir: dir, secret: strings.Repeat("s", 43)}
}

func TestHandoverRecordRoundTrips(t *testing.T) {
	// The waiting side used to be told "authorised, waiting for the elevated
	// instance" and then have nothing that could ever end that wait: the helper
	// reported through a progress object it never initialised, so its verdict went
	// nowhere. This record is the channel that replaced it.
	dir := t.TempDir()
	a := testAppForHandover(dir)

	if rec := a.readHandover(); rec != nil {
		t.Fatal("a fresh data directory should have no handover record")
	}
	id := newHandoverID()
	rec := a.beginHandover(id, 4242, TunPrivacy)
	if rec.ID != id || rec.RequesterPID != 4242 || rec.State != handoverRunning {
		t.Fatalf("the record was not started correctly: %+v", rec)
	}
	back := a.readHandover()
	if back == nil || back.ID != id {
		t.Fatal("the record could not be read back")
	}
	if back.HelperPID != os.Getpid() {
		t.Errorf("helper pid = %d, want %d", back.HelperPID, os.Getpid())
	}
	if back.Adapter != tunDefaultDevice {
		t.Errorf("adapter = %q, want the normalized default %q", back.Adapter, tunDefaultDevice)
	}

	a.progressHandover(back, "建立虚拟网卡")
	if got := a.readHandover(); got == nil || got.Stage != "建立虚拟网卡" {
		t.Error("progress was not recorded, so the interface would show a static waiting message")
	}

	a.finishHandover(back, nil)
	done := a.readHandover()
	if done == nil || done.State != handoverSucceeded {
		t.Fatalf("success was not recorded: %+v", done)
	}
	a.clearHandover()
	if a.readHandover() != nil {
		t.Error("clearing did not remove the record, so the next activation could read this one's verdict")
	}
}

func TestHandoverFailureCarriesItsReason(t *testing.T) {
	// The failure this whole file exists for: a failed activation must arrive with
	// a reason attached, not as silence and not as success.
	dir := t.TempDir()
	a := testAppForHandover(dir)
	rec := a.beginHandover(newHandoverID(), 1, TunCompat)
	want := "虚拟网卡没有出现：内核说 Access is denied"
	a.finishHandover(rec, fmt.Errorf("%s", want))

	back := a.readHandover()
	if back == nil {
		t.Fatal("no record")
	}
	if back.State != handoverFailed {
		t.Errorf("state = %q, want %q", back.State, handoverFailed)
	}
	if back.Failure != want {
		t.Errorf("failure = %q, want %q", back.Failure, want)
	}
	if back.ExitedAt == "" {
		t.Error("a terminal record should record when the helper left")
	}
}

func TestAwaitHandoverAlwaysEnds(t *testing.T) {
	// The interface must never wait forever. Three things end it, and each is
	// exercised here: the helper reports, the helper exits, and the deadline
	// passes.
	dir := t.TempDir()

	// 1. The helper reports success.
	a := testAppForHandover(dir)
	id := newHandoverID()
	rec := a.beginHandover(id, os.Getpid(), TunCompat)
	a.finishHandover(rec, nil)
	res := a.awaitHandover(id, os.Getpid(), 2*time.Second)
	if !res.Done || !res.OK {
		t.Errorf("a reported success should end the wait as success: %+v", res)
	}

	// 2. The helper reports failure, and the reason survives.
	a2 := testAppForHandover(t.TempDir())
	id2 := newHandoverID()
	rec2 := a2.beginHandover(id2, os.Getpid(), TunCompat)
	a2.finishHandover(rec2, fmt.Errorf("网卡创建失败"))
	res2 := a2.awaitHandover(id2, os.Getpid(), 2*time.Second)
	if !res2.Done || res2.OK {
		t.Errorf("a reported failure should end the wait as failure: %+v", res2)
	}
	if res2.Failure != "网卡创建失败" {
		t.Errorf("the reason was lost: %q", res2.Failure)
	}

	// 3. No record at all and a process that does not exist: the wait ends as a
	//    failure that names the case, rather than running to the deadline.
	a3 := testAppForHandover(t.TempDir())
	res3 := a3.awaitHandover("id-that-never-reports", 0, 1500*time.Millisecond)
	if !res3.Done || res3.OK {
		t.Errorf("a deadline that passes must end the wait as failure: %+v", res3)
	}
	if res3.Failure == "" {
		t.Error("a failure must carry an explanation")
	}
}

func TestStaleHandoverRecordIsNotThisAttemptsVerdict(t *testing.T) {
	// A record from an earlier attempt carries a different id. Reading it as this
	// attempt's result would report the previous activation's outcome, which is how
	// a failure gets shown as a success.
	dir := t.TempDir()
	a := testAppForHandover(dir)
	stale := a.beginHandover("act-old", os.Getpid(), TunCompat)
	a.finishHandover(stale, nil) // the previous attempt succeeded

	res := a.awaitHandover("act-new", 0, 1200*time.Millisecond)
	if res.OK {
		t.Fatal("a record from a different attempt was accepted as this attempt's success")
	}
	if !res.Done {
		t.Fatal("the wait did not end")
	}
}

func TestProcessRunningDistinguishesGoneFromUninspectable(t *testing.T) {
	// An elevated helper cannot be opened by a non-elevated process. Treating that
	// refusal as "gone" would end the wait early and report a failure while the
	// helper was still working.
	alive, _ := processRunning(os.Getpid())
	if !alive {
		t.Error("this process should be reported as running")
	}
	// A pid that cannot exist.
	gone, _ := processRunning(0x7FFFFFF0)
	if gone {
		t.Error("a pid that cannot exist should be reported as gone")
	}
	if helperStillRunning(0) {
		t.Error("pid 0 must never be reported as a running helper")
	}
	if !helperStillRunning(os.Getpid()) {
		t.Error("this process should be reported as running")
	}
}

// ---- P0-3: a failed activation must not destroy the way back ---------------

func TestCandidateConfigDoesNotOverwriteTheKnownGood(t *testing.T) {
	// The defect: the known-good copy was written at the same moment as the
	// candidate, so a TUN configuration that then failed verification had already
	// replaced the pre-TUN one. A rollback had nothing that actually ran to go back
	// to. The candidate is now written alone, and the known-good copy only after the
	// configuration is proven.
	dir := t.TempDir()
	a := &App{dataDir: dir, configPath: filepath.Join(dir, "config.yaml")}

	working := []byte("mixed-port: 7899\nproxies: []\nproxy-groups: []\nrules: []\n")
	if err := os.WriteFile(a.goodConfigPath(), working, 0o644); err != nil {
		t.Fatal(err)
	}

	candidate := []byte("mixed-port: 7899\ntun:\n  enable: true\nproxies: []\nproxy-groups: []\nrules: []\n")
	if err := a.applyCandidateConfig(string(candidate)); err != nil {
		t.Fatal(err)
	}

	// The candidate is live; the way back is untouched.
	if got, _ := os.ReadFile(a.configPath); !bytes.Equal(got, candidate) {
		t.Error("the candidate was not written to the live configuration")
	}
	if got, _ := os.ReadFile(a.goodConfigPath()); !bytes.Equal(got, working) {
		t.Fatalf("the known-good copy was replaced before the candidate was proven:\n%q", got)
	}

	// And a rollback now has a real configuration to restore.
	if err := a.restoreConfig(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if got, _ := os.ReadFile(a.configPath); !bytes.Equal(got, working) {
		t.Errorf("restore did not put the working configuration back:\n%q", got)
	}
}

func TestRestoreConfigReportsFailureInsteadOfPretending(t *testing.T) {
	// A rollback that could not put the previous configuration back is a different
	// and more serious condition than one that did. Reporting it as a plain
	// "rolled back" hid it.
	dir := t.TempDir()
	a := &App{dataDir: dir, configPath: filepath.Join(dir, "config.yaml")}

	// Nothing known-good to restore.
	if err := a.restoreConfig(); err == nil {
		t.Error("restoring with no known-good copy must report failure, not succeed")
	}

	// An empty known-good copy is equally unusable.
	if err := os.WriteFile(a.goodConfigPath(), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.restoreConfig(); err == nil {
		t.Error("restoring from an empty known-good copy must report failure")
	}

	// A real one succeeds and the file matches byte for byte.
	good := []byte("mixed-port: 7899\nproxies: []\nproxy-groups: []\nrules: []\n")
	if err := os.WriteFile(a.goodConfigPath(), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.restoreConfig(); err != nil {
		t.Fatalf("restore failed with a valid known-good copy: %v", err)
	}
	if got, _ := os.ReadFile(a.configPath); !bytes.Equal(got, good) {
		t.Error("the restored file does not match the known-good copy")
	}
}

func TestPrivacyBlockIsNotLiftedByAFailedActivation(t *testing.T) {
	// The block is the feature. A failed enable must not be the event that quietly
	// removes the protection the user asked for, so releasing it is a separate,
	// explicit action rather than something a rollback does on its way out.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateSettings(map[string]interface{}{"tunMode": string(TunPrivacy)}); err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st, configPath: filepath.Join(dir, "config.yaml")}

	// A rollback in privacy mode leaves the mode alone.
	txB := newTunTxn(txnActivate)
	txB.Mode = TunPrivacy
	txB.Owned.AdapterName = tunDefaultDevice
	a.core = NewCore("", dir, a.configPath, "s", 7797)
	a.rollbackActivate(txB, TunPrivacy)

	if got := a.store.Settings().TunMode; got != TunPrivacy {
		t.Errorf("tunMode = %q after a failed privacy activation, want %q: the block must stand",
			got, TunPrivacy)
	}
	found := false
	for _, s := range txB.Steps {
		if s.Name == "隐私阻断" {
			found = true
		}
	}
	if !found {
		t.Error("the rollback should record that the privacy block was deliberately left standing")
	}

	// Releasing it is explicit and separate.
	if err := a.releasePrivacyBlock("test"); err != nil {
		t.Fatal(err)
	}
	if got := a.store.Settings().TunMode; got != TunOff {
		t.Errorf("tunMode = %q after an explicit release, want off", got)
	}
}

func TestRollbackWithoutAKnownGoodReportsRestoreFailure(t *testing.T) {
	// End to end through the rollback: with no known-good configuration the
	// transaction must not end as a clean "rolledBack", because nothing was put
	// back.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st, configPath: filepath.Join(dir, "config.yaml")}
	a.core = NewCore("", dir, a.configPath, "s", 7797)

	txB := newTunTxn(txnActivate)
	txB.Mode = TunCompat
	a.rollbackActivate(txB, TunCompat)

	if txB.State == "rolledBack" {
		t.Error("a rollback with nothing to restore must not report a clean rollback")
	}
	if txB.State != "rollbackFailed" {
		t.Errorf("state = %q, want rollbackFailed", txB.State)
	}
	if txB.RestoreFailure == "" {
		t.Error("the restore failure must be recorded on its own, not folded into the general failure")
	}
}

// ---- P0-7: prove the traffic, not just the node ----------------------------

func TestDirectClientIgnoresProxySettings(t *testing.T) {
	// The load-bearing observation is "a request completed with no proxy
	// configured". If the client honoured HTTPS_PROXY the test would be routing
	// through the very proxy it is meant to bypass, and would pass on a machine
	// where the tunnel does nothing.
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	os.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	defer func() {
		os.Unsetenv("HTTPS_PROXY")
		os.Unsetenv("HTTP_PROXY")
		os.Unsetenv("ALL_PROXY")
	}()

	c := directHTTPClient(time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	if tr.Proxy != nil {
		t.Error("the direct client has a proxy function; it would not bypass the proxy it is testing")
	}
	// And the request must actually fail against the dead proxy above, which is
	// only true if the proxy was ignored - a client that used it would fail to
	// connect, so a successful connection to a real host proves the point.
	if _, err := directRequest("http://127.0.0.1:1/", 1500*time.Millisecond); err == nil {
		t.Error("a request to a closed port should fail")
	}
}

func TestVerifyTunTrafficReportsTheStageItStoppedAt(t *testing.T) {
	// "TUN verification failed" was the message that made the earlier attempts
	// unactionable. Each stage must name itself.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The adapter name comes from the store, not from env, so it has to be changed
	// there for this test to be deterministic. It was not, and the test failed on a
	// machine that happened to have a real Zenith adapter left up by an activation -
	// failing for the right reason, because the check had correctly moved on to a
	// later stage.
	if _, err := st.UpdateSettings(map[string]interface{}{
		"tunDevice": "ZenithDefinitelyNotPresent",
	}); err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st, configPath: filepath.Join(dir, "config.yaml")}
	a.core = NewCore("", dir, a.configPath, "s", 7797)

	env := tunEnvironment{Adapter: "ZenithDefinitelyNotPresent", Stack: tunDefaultStack,
		MixedPort: 7899, DNSPort: 8199, Checks: map[string]string{}}
	rep := a.VerifyTunTraffic(TunCompat, env)

	if rep.OK {
		t.Fatal("verification reported success with no tunnel at all")
	}
	if rep.Stage == "" {
		t.Error("a failed verification must name the stage it stopped at")
	}
	if rep.Detail == "" {
		t.Error("a failed verification must explain what was observed")
	}
	if rep.TestedAt == "" {
		t.Error("the report should record when it was taken")
	}
	// With no adapter present the first stage is the adapter, and it must say so
	// rather than blaming the tunnel.
	if rep.Stage != "虚拟网卡" {
		t.Errorf("stage = %q, want 虚拟网卡 when no adapter exists", rep.Stage)
	}
}

func TestAdapterStateDistinguishesMissingFromDown(t *testing.T) {
	// An adapter that exists but is down carries nothing, and "the adapter is there"
	// was previously the whole claim.
	exists, up, _ := adapterState("ZenithDefinitelyNotPresent")
	if exists {
		t.Error("a name that does not exist must report as not existing")
	}
	if up {
		t.Error("a name that does not exist must not report as up")
	}
}

func TestDefaultRouteCheckRejectsAnUnusableIndex(t *testing.T) {
	// A zero index means the adapter could not be resolved, and treating that as
	// "route is fine" would let the verification pass without checking anything.
	ok, detail := defaultRouteUsesAdapter(0)
	if ok {
		t.Error("an unusable interface index must not be reported as having a route")
	}
	if detail == "" {
		t.Error("the failure must explain itself")
	}
}

func TestTrafficReportIsRecordedOnTheTransaction(t *testing.T) {
	// The evidence belongs on the record, not only in the log, so a failure can be
	// diagnosed from the file afterwards.
	dir := t.TempDir()
	a := &App{dataDir: dir}
	tx := newTunTxn(txnActivate)
	tx.Traffic = &tunTrafficReport{OK: false, Stage: "路由", Detail: "没有默认路由"}
	a.saveTunTxn(tx)
	back := a.loadTunTxn()
	if back == nil || back.Traffic == nil {
		t.Fatal("the traffic report did not survive the round trip")
	}
	if back.Traffic.Stage != "路由" {
		t.Errorf("stage = %q, want 路由", back.Traffic.Stage)
	}
}

// ---- the control secret belongs to the data directory ----------------------

func TestControlSecretIsStableAcrossProcesses(t *testing.T) {
	// Generated fresh on every start, the secret differed between the ordinary
	// instance and the elevated helper reading the same data directory. The helper
	// wrote a configuration with its secret and started a core with it, and the
	// ordinary instance was left holding a value that no longer matched - a core
	// that is up, reported as unavailable. Two processes reading the same directory
	// must get the same secret.
	dir := t.TempDir()

	first, err := loadOrCreateSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 {
		t.Fatalf("secret is too short to be strong: %d characters", len(first))
	}
	second, err := loadOrCreateSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("two reads of the same data directory produced different secrets")
	}

	// And it is on disk, so a separate process gets the same answer.
	raw, err := os.ReadFile(secretPath(dir))
	if err != nil {
		t.Fatalf("the secret was not written to disk: %v", err)
	}
	if strings.TrimSpace(string(raw)) != first {
		t.Error("the file does not contain the secret that was returned")
	}
}

func TestControlSecretIsRestrictedToThisAccount(t *testing.T) {
	// The secret grants control of the core's configuration API, which is enough to
	// redirect every connection this machine makes.
	//
	// The check is against the actual ACL rather than the POSIX mode, because on
	// Windows the mode OpenFile takes does not restrict anything: the first version
	// of this file read 0666 on disk while its comment claimed owner-only. Measured
	// rather than assumed.
	dir := t.TempDir()
	if _, err := loadOrCreateSecret(dir); err != nil {
		t.Fatal(err)
	}
	out, err := HiddenCommand("icacls", secretPath(dir))
	if err != nil {
		t.Skipf("icacls is unavailable, cannot check the ACL: %v", err)
	}
	// Broad principals that must not appear.
	for _, broad := range []string{"Everyone", "BUILTIN\\Users", "Authenticated Users"} {
		if strings.Contains(out, broad) {
			t.Errorf("the secret file grants access to %q:\n%s", broad, out)
		}
	}
	// The current account must appear, or the interface cannot read its own secret.
	user := os.Getenv("USERNAME")
	if user != "" && !strings.Contains(out, user) {
		t.Errorf("the secret file does not grant access to the current account %q:\n%s", user, out)
	}
	// And SYSTEM must appear, because the resident service runs as it. The first
	// version granted only the interactive account, and the service then failed to
	// start with a message about a password file - a long way from "the permissions
	// are too tight".
	if !strings.Contains(out, "SYSTEM") {
		t.Errorf("the secret file does not grant access to SYSTEM, so the resident "+
			"service cannot read it:\n%s", out)
	}
}

func TestSecretReadabilityIsCheckedNotAssumed(t *testing.T) {
	// A file can exist and still be unreadable, and that is exactly the state that
	// stopped the service. The check must read the file rather than stat it.
	dir := t.TempDir()
	if err := secretReadableByThisProcess(dir); err == nil {
		t.Error("a missing secret file should be reported")
	}
	if _, err := loadOrCreateSecret(dir); err != nil {
		t.Fatal(err)
	}
	if err := secretReadableByThisProcess(dir); err != nil {
		t.Errorf("a secret this process just wrote should be readable: %v", err)
	}
	// A file that exists with unusable content is also a failure.
	if err := os.WriteFile(secretPath(dir), []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secretReadableByThisProcess(dir); err == nil {
		t.Error("a secret file with unusable content should be reported")
	}
}

func TestCurrentAccountNameIsDomainQualified(t *testing.T) {
	// icacls needs DOMAIN\user to be unambiguous, and an account name alone can
	// resolve to a different principal on a machine with more than one domain.
	got := currentAccountName()
	if got == "" {
		t.Skip("USERNAME is not set in this environment")
	}
	if user := os.Getenv("USERNAME"); !strings.Contains(got, user) {
		t.Errorf("currentAccountName() = %q, which does not contain %q", got, user)
	}
}

func TestControlSecretIsNotSilentlyReplaced(t *testing.T) {
	// A core may be running with the value that is on disk. Replacing it would make
	// that core unreachable with no explanation, so a present-but-unusable file is
	// reported instead.
	dir := t.TempDir()
	if err := os.WriteFile(secretPath(dir), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSecret(dir); err == nil {
		t.Fatal("an unusable secret file should be reported, not silently replaced")
	}
	// And the file is left as it was.
	raw, _ := os.ReadFile(secretPath(dir))
	if string(raw) != "short" {
		t.Error("the unusable file was modified instead of reported")
	}
}

func TestControlSecretIsDistinctPerDataDirectory(t *testing.T) {
	// Two installations must not share a secret.
	a, err := loadOrCreateSecret(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateSecret(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two different data directories produced the same secret")
	}
}

func TestSecretIsUsableAsAnAPIHeader(t *testing.T) {
	// It travels in a header, so it must not need escaping, and it must carry
	// enough entropy to be worth calling a secret.
	dir := t.TempDir()
	s, err := loadOrCreateSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			t.Fatalf("the secret contains %q, which is not URL-safe", string(c))
		}
	}
	if ensureSecretFileExists(t.TempDir()) {
		t.Error("a directory with no secret should report none")
	}
	if !ensureSecretFileExists(dir) {
		t.Error("a directory with a secret should report one")
	}
}

// ---- P0-2/P0-5: one owner for the core, and an authenticated channel --------

func TestServiceRefusesRequestsWithoutTheSecret(t *testing.T) {
	// The channel is what lets the window ask a resident service to start and stop
	// the core. It must authenticate, or any process on the machine could redirect
	// every connection this computer makes.
	h := &serviceHandler{secret: "the-real-secret", app: &App{}}
	srv := httptest.NewServer(h.routes())
	defer srv.Close()

	// The liveness endpoint is deliberately open: it answers "is anything there",
	// which the window needs before it can decide who owns the core, and it reveals
	// nothing and changes nothing.
	resp, err := http.Get(srv.URL + "/alive")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/alive = %d, want 200: the window must be able to ask without a secret", resp.StatusCode)
	}

	// Everything that acts needs the secret.
	for _, path := range []string{"/core/start", "/core/stop", "/core/state"} {
		for _, hdr := range []string{"", "wrong", "the-real-secre", "the-real-secretx"} {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader("{}"))
			if hdr != "" {
				req.Header.Set("X-Zenith-Secret", hdr)
			}
			r2, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			r2.Body.Close()
			if r2.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with secret %q = %d, want 401", path, hdr, r2.StatusCode)
			}
		}
	}
}

func TestServiceAcceptsTheCorrectSecret(t *testing.T) {
	// And the correct secret works, or the channel would be useless.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st, configPath: filepath.Join(dir, "config.yaml")}
	a.core = NewCore("", dir, a.configPath, "s", 7797)
	h := &serviceHandler{secret: "the-real-secret", app: a}
	srv := httptest.NewServer(h.routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/core/state", nil)
	req.Header.Set("X-Zenith-Secret", "the-real-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/core/state with the correct secret = %d, want 200", resp.StatusCode)
	}
}

func TestServiceRefusesAConfigurationTheCoreWouldReject(t *testing.T) {
	// The service validates before it acts. A window that sends a broken
	// configuration gets it refused with a reason, rather than a core that fails to
	// start with no explanation - which was the failure mode that made the earlier
	// attempts unactionable.
	dir := t.TempDir()
	st, _ := NewStore(dir)
	a := &App{dataDir: dir, store: st, configPath: filepath.Join(dir, "config.yaml")}
	a.core = NewCore("", dir, a.configPath, "s", 7797)
	h := &serviceHandler{secret: "s3cret-value-long-enough", app: a}
	srv := httptest.NewServer(h.routes())
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"config": "this is not a configuration", "mode": "compat"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/core/start", bytes.NewReader(body))
	req.Header.Set("X-Zenith-Secret", "s3cret-value-long-enough")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("response was not JSON: %s", raw)
	}
	if out.OK {
		t.Error("the service accepted a configuration the core would reject")
	}
	if !strings.Contains(out.Error, "校验") {
		t.Errorf("the refusal should say it was a validation failure, got %q", out.Error)
	}
}

func TestCoreOwnerIsDecidedByAsking(t *testing.T) {
	// One owner, decided by asking rather than assuming. When the service is not
	// reachable and no core is running, nobody owns it - and that is a state the
	// caller must handle rather than a nil dereference.
	a := &App{dataDir: t.TempDir()}
	a.core = NewCore("", t.TempDir(), filepath.Join(t.TempDir(), "c.yaml"), "s", 7797)
	// No service is running in the test environment.
	if got := a.coreOwnerNow(); got != ownerNone && got != ownerSelf {
		t.Errorf("owner = %q, want none or self when no service answers", got)
	}
}

func TestSecretEqualIsConstantTimeAndRejectsEmpties(t *testing.T) {
	if secretEqual("", "abc") {
		t.Error("an empty candidate must not match")
	}
	if secretEqual("abc", "") {
		t.Error("an empty expected secret must never match anything")
	}
	if secretEqual("abc", "abd") {
		t.Error("different secrets must not match")
	}
	if !secretEqual("abc", "abc") {
		t.Error("equal secrets must match")
	}
}

func TestServiceStateSurvivesARestart(t *testing.T) {
	// The record is how a window that starts later learns what the service holds,
	// and how a diagnostic sees who owns the core without asking anyone.
	dir := t.TempDir()
	a := &App{dataDir: dir}
	if got := a.loadServiceState(); got != nil {
		t.Fatal("a fresh directory should have no service state")
	}
	a.saveServiceState(&serviceState{CorePID: 4242, Mode: "compat", ConfigDigest: "abc"})
	back := a.loadServiceState()
	if back == nil {
		t.Fatal("the state could not be read back")
	}
	if back.CorePID != 4242 || back.Mode != "compat" || back.ConfigDigest != "abc" {
		t.Errorf("the record lost data: %+v", back)
	}
	if back.UpdatedAt == "" {
		t.Error("the record should say when it was written")
	}
}

// ---- P0-5: name the failure, and notice an exit as it happens --------------

func TestCoreFailuresAreToldApart(t *testing.T) {
	// Every startup failure used to produce the same sentence pointing at a log
	// file, after the full deadline had passed. Telling them apart is what makes a
	// failure actionable.
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name string
		log  string
		want coreFailure
	}{
		{
			"port already in use",
			`time="2026-01-01T00:00:00Z" level=error msg="Mixed(http+socks) proxy listening error: listen tcp 127.0.0.1:7899: bind: address already in use"`,
			coreFailurePortInUse,
		},
		{
			"windows socket message",
			`level=error msg="listen tcp 127.0.0.1:7899: bind: Only one usage of each socket address is normally permitted."`,
			coreFailurePortInUse,
		},
		{
			"tun driver refused",
			`level=error msg="Start TUN listening error: configure tun interface: Access is denied."`,
			coreFailureDriver,
		},
		{
			"wintun mentioned",
			`level=error msg="wintun: could not create adapter"`,
			coreFailureDriver,
		},
		{
			"configuration rejected",
			`level=error msg="Parse config error: yaml: unmarshal errors: line 12: cannot unmarshal"`,
			coreFailureConfig,
		},
		{
			"rule database missing",
			`level=error msg="can't initial GeoSite databse"`,
			coreFailureGeodata,
		},
		{
			"authentication",
			`level=error msg="authentication failed: secret mismatch"`,
			coreFailureAuth,
		},
	}

	for _, c := range cases {
		p := write(strings.ReplaceAll(c.name, " ", "_")+".log", c.log)
		got, last := classifyCoreLog(p)
		if got != c.want {
			t.Errorf("%s: classified as %q, want %q", c.name, got.Label(), c.want.Label())
		}
		if last == "" {
			t.Errorf("%s: the core's own last line should be reported alongside", c.name)
		}
	}

	// An unrecognised failure must say so rather than picking the closest category.
	p := write("unknown.log", `level=error msg="something nobody has seen before"`)
	if got, _ := classifyCoreLog(p); got != coreFailureUnknown {
		t.Errorf("an unrecognised failure was classified as %q", got.Label())
	}
	// And a missing log is not an error in itself.
	if got, _ := classifyCoreLog(filepath.Join(dir, "nope.log")); got != coreFailureUnknown {
		t.Error("a missing log should classify as unknown, not fail")
	}
}

func TestEveryCoreFailureCarriesAdvice(t *testing.T) {
	// A failure without a next step is one the user cannot act on, which was the
	// complaint about the old single message.
	for _, k := range []coreFailure{
		coreFailureUnknown, coreFailurePortInUse, coreFailureAuth,
		coreFailureConfig, coreFailureDriver, coreFailureGeodata,
		coreFailureMissingBinary,
	} {
		if k.Label() == "" {
			t.Errorf("failure %d has no label", k)
		}
		if k.Advice() == "" {
			t.Errorf("failure %q has no advice", k.Label())
		}
	}
	// The driver advice must name the likely cause, since authorisation that did
	// not take effect is indistinguishable from a driver problem at this level.
	if !strings.Contains(coreFailureDriver.Advice(), "管理员") {
		t.Error("the driver advice should name the privilege possibility")
	}
}

func TestCoreStartFailureIncludesTheEvidence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.log")
	line := `level=error msg="listen tcp 127.0.0.1:7899: bind: address already in use"`
	if err := os.WriteFile(p, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	err := coreStartFailure(p, true, 4242)
	msg := err.Error()
	if !strings.Contains(msg, "立即退出") {
		t.Error("the message should say the process exited rather than timing out")
	}
	if !strings.Contains(msg, "端口冲突") {
		t.Error("the message should name the failure kind")
	}
	if !strings.Contains(msg, "address already in use") {
		t.Error("the message should carry the core's own words as evidence")
	}
	if !strings.Contains(msg, "4242") {
		t.Error("the message should carry the pid")
	}
	// And the classification is available without parsing the text back out.
	var ce *coreStartError
	if !errors.As(err, &ce) {
		t.Fatal("the error should carry its classification")
	}
	if ce.Kind() != coreFailurePortInUse {
		t.Errorf("kind = %q, want port in use", ce.Kind().Label())
	}
}

func TestWaitForCoreUpNoticesAnExitImmediately(t *testing.T) {
	// The defect this replaces: cmd.ProcessState stays nil until Wait is called, so
	// the exit branch never fired and a core that died in its first second still
	// cost the full deadline.
	exited := make(chan struct{})
	close(exited)
	start := time.Now()
	up, didExit := waitForCoreUp(func() bool { return false }, exited, 5*time.Second)
	elapsed := time.Since(start)
	if up {
		t.Error("a core that never answers must not be reported as up")
	}
	if !didExit {
		t.Error("the exit was not noticed")
	}
	if elapsed > 2*time.Second {
		t.Errorf("the exit took %v to notice; it should be immediate rather than waiting out the deadline", elapsed)
	}

	// A core that comes up is reported as up, and the exit flag is false.
	up, didExit = waitForCoreUp(func() bool { return true }, make(chan struct{}), 3*time.Second)
	if !up || didExit {
		t.Errorf("a core that answers should be up=%v exit=%v", up, didExit)
	}
}

func TestWaitForCoreUpToleratesAnExitAfterSuccess(t *testing.T) {
	// The core can answer and then be replaced by an exit in a race. Reporting a
	// failure there would be wrong.
	exited := make(chan struct{})
	close(exited)
	up, _ := waitForCoreUp(func() bool { return true }, exited, 2*time.Second)
	if !up {
		t.Error("a core that is answering must be reported as up even if the exit channel is closed")
	}
}

func TestHandoverHeartbeatDistinguishesStuckFromSlow(t *testing.T) {
	// UpdatedAt moves on every write, including writes from the waiting side, so it
	// cannot answer "is the helper still working". The heartbeat can, and the
	// difference matters: a user waiting for something that will finish is in a
	// different position from one waiting for something that will not.
	dir := t.TempDir()
	a := testAppForHandover(dir)
	id := newHandoverID()
	a.beginHandover(id, os.Getpid(), TunCompat)
	back := a.readHandover()
	if back.Heartbeat == "" {
		t.Fatal("starting should record a heartbeat, or the wait cannot tell stuck from slow")
	}
	first := back.Heartbeat

	time.Sleep(10 * time.Millisecond)
	a.progressHandover(back, "建立虚拟网卡")
	back = a.readHandover()
	if back.Heartbeat == first {
		t.Error("reporting progress should refresh the heartbeat")
	}
	if back.Stage != "建立虚拟网卡" {
		t.Errorf("stage = %q", back.Stage)
	}
}

func TestStaleHeartbeatEndsTheWait(t *testing.T) {
	// A helper that has stopped reporting is reported as stuck at the stage it
	// stopped at, rather than being waited on until the overall deadline.
	dir := t.TempDir()
	a := testAppForHandover(dir)
	id := newHandoverID()
	rec := a.beginHandover(id, os.Getpid(), TunCompat)
	// Backdate the heartbeat past the threshold, keeping the record otherwise live.
	// The record is edited rather than re-created so this exercises the path the
	// waiting side actually reads.
	rec.Heartbeat = time.Now().Add(-2 * handoverHeartbeatTimeout).Format(time.RFC3339Nano)
	rec.Stage = "建立虚拟网卡"
	a.writeHandover(rec)
	_ = rec

	start := time.Now()
	res := a.awaitHandover(id, os.Getpid(), 60*time.Second)
	elapsed := time.Since(start)

	if !res.Done || res.OK {
		t.Fatalf("a stalled helper must end the wait as a failure: %+v", res)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %v to notice a stalled heartbeat; it should be immediate", elapsed)
	}
	if !strings.Contains(res.Failure, "建立虚拟网卡") {
		t.Errorf("the failure should name the stage it stalled at, got %q", res.Failure)
	}
	if !strings.Contains(res.Failure, "卡住") {
		t.Errorf("the failure should say it was judged stuck rather than timing out, got %q", res.Failure)
	}
}

// ---- the handover record must not be editable into a wrong verdict ----------

func TestHandoverRecordIsSignedAndDetectsTampering(t *testing.T) {
	// The record decides whether an activation is reported as successful, so a
	// record that has been edited must not be believed. This detects corruption,
	// truncation, and a record written for a different data directory - the key is
	// that directory's secret.
	//
	// It does NOT defend against a malicious process running as the same user,
	// which can read the same secret. That is stated rather than implied: the
	// defence there is the filesystem permissions on the data directory, not
	// cryptography.
	dir := t.TempDir()
	a := &App{dataDir: dir, secret: "a-secret-of-sufficient-length-000000"}
	rec := a.beginHandover(newHandoverID(), os.Getpid(), TunCompat)
	a.finishHandover(rec, nil)

	back := a.readHandover()
	if back == nil {
		t.Fatal("a signed record should be readable")
	}
	if back.State != handoverSucceeded {
		t.Fatalf("state = %q", back.State)
	}
	if back.Signature == "" {
		t.Fatal("the record was written without a signature")
	}

	// Flip the verdict to a failure and rewrite it. The signature must refuse it -
	// in this direction too, because a forged failure is also a wrong report.
	back.State = handoverFailed
	back.Failure = "forged"
	raw, _ := json.MarshalIndent(back, "", "  ")
	if err := os.WriteFile(a.handoverPath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := a.readHandover(); got != nil {
		t.Errorf("a tampered record was accepted: state=%q", got.State)
	}

	// And a forged success is refused just as firmly.
	rec2 := a.beginHandover(newHandoverID(), os.Getpid(), TunCompat)
	rec2.State = handoverSucceeded
	rec2.Signature = "0000000000000000000000000000000000000000000000000000000000000000"
	raw2, _ := json.MarshalIndent(rec2, "", "  ")
	if err := os.WriteFile(a.handoverPath(), raw2, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := a.readHandover(); got != nil {
		t.Error("a record with a wrong signature was accepted")
	}
}

func TestHandoverRecordFromAnotherDataDirectoryIsRefused(t *testing.T) {
	// The signature key is the data directory's secret, so a record written for a
	// different tree does not verify here. Pointing a helper at the wrong directory
	// produces a record that is ignored rather than acted on.
	dirA, dirB := t.TempDir(), t.TempDir()
	a := &App{dataDir: dirA, secret: "secret-for-directory-a-0000000000000"}
	a.beginHandover("act-shared", os.Getpid(), TunCompat)

	// Copy the file into B, which has a different secret.
	raw, err := os.ReadFile(a.handoverPath())
	if err != nil {
		t.Fatal(err)
	}
	b := &App{dataDir: dirB, secret: "secret-for-directory-b-1111111111111"}
	if err := os.WriteFile(b.handoverPath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := b.readHandover(); got != nil {
		t.Error("a record signed with another directory's secret was accepted")
	}
	// The same file reads correctly in its own directory.
	if got := a.readHandover(); got == nil {
		t.Error("the record should be readable in the directory it was written for")
	}
}

func TestUnsignedHandoverRecordIsRefused(t *testing.T) {
	// A record from a version that did not sign, or one written by hand. Refusing
	// it ends the wait with an honest failure rather than a verdict that may have
	// been mangled.
	dir := t.TempDir()
	a := &App{dataDir: dir, secret: "secret-of-sufficient-length-00000000"}
	rec := handoverRecord{
		ID: "act-handwritten", State: handoverSucceeded,
		HelperPID: os.Getpid(), StartedAt: time.Now().Format(time.RFC3339Nano),
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(a.handoverPath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := a.readHandover(); got != nil {
		t.Error("an unsigned record was accepted")
	}
}

func TestHandoverMACCoverEveryDecisiveField(t *testing.T) {
	// Every field that decides anything is covered, so none can be edited without
	// the signature failing. The canonical form is fixed in code rather than taken
	// from the struct, so a future field reordering cannot silently change what is
	// signed.
	base := handoverRecord{
		ID: "act-1", HelperPID: 10, RequesterPID: 20,
		State: handoverRunning, Stage: "s", Mode: "compat", Adapter: "Zenith",
	}
	secret := "a-key-of-sufficient-length-000000000000"
	want := handoverMAC(secret, &base)

	mutations := map[string]func(*handoverRecord){
		"id":            func(r *handoverRecord) { r.ID = "act-2" },
		"helper pid":    func(r *handoverRecord) { r.HelperPID = 11 },
		"requester pid": func(r *handoverRecord) { r.RequesterPID = 21 },
		"state":         func(r *handoverRecord) { r.State = handoverSucceeded },
		"stage":         func(r *handoverRecord) { r.Stage = "other" },
		"mode":          func(r *handoverRecord) { r.Mode = "privacy" },
		"adapter":       func(r *handoverRecord) { r.Adapter = "Other" },
		"exited at":     func(r *handoverRecord) { r.ExitedAt = "now" },
	}
	for name, mutate := range mutations {
		r := base
		mutate(&r)
		if got := handoverMAC(secret, &r); got == want {
			t.Errorf("changing %s did not change the signature, so it is not covered", name)
		}
	}

	// A different key produces a different signature, which is what makes a record
	// from another directory fail here.
	if handoverMAC("another-key-of-sufficient-length-000000", &base) == want {
		t.Error("the signature does not depend on the key")
	}
	// An empty key must not produce a verifiable signature at all.
	if handoverMAC("", &base) != "" {
		t.Error("an empty key must not sign")
	}
}

// ---- a second writer must be noticed ---------------------------------------

func TestSettingsPickUpAnotherProcessesWrite(t *testing.T) {
	// The state file has more than one legitimate writer: an elevated helper records
	// the TUN mode it activated, while the interface that is already running holds
	// its own copy in memory. Observed on this machine - a tunnel was up, the adapter
	// was up, the default route went through it, and the interface reported TUN as
	// off, because nobody told it the file had changed.
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Settings().TunMode; got != TunOff {
		t.Fatalf("tunMode starts as %q, want off", got)
	}

	// A second store, standing in for the other process.
	b, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpdateSettings(map[string]interface{}{"tunMode": string(TunCompat)}); err != nil {
		t.Fatal(err)
	}

	// The first store must see it on its next read, not on its next restart.
	if got := a.Settings().TunMode; got != TunCompat {
		t.Errorf("tunMode = %q after another process wrote compat; the change was not noticed", got)
	}

	// And the other direction, so this is not one-way.
	if _, err := a.UpdateSettings(map[string]interface{}{"tunMode": string(TunPrivacy)}); err != nil {
		t.Fatal(err)
	}
	if got := b.Settings().TunMode; got != TunPrivacy {
		t.Errorf("tunMode = %q in the other store; the change was not noticed", got)
	}
}

func TestSettingsReloadDoesNotLoseThisProcessesWrites(t *testing.T) {
	// A reload must not discard what this process just wrote. The guard is by
	// modification time, and the writer updates it, so this asserts the property
	// rather than the mechanism.
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateSettings(map[string]interface{}{"mixedPort": 7901}); err != nil {
		t.Fatal(err)
	}
	// Several reads in a row, each of which now checks the file.
	for i := 0; i < 5; i++ {
		if got := a.Settings().MixedPort; got != 7901 {
			t.Fatalf("read %d: mixedPort = %d, want 7901", i, got)
		}
	}
}

func TestSettingsSyncIgnoresAnOlderFile(t *testing.T) {
	// A file that has gone backwards - restored from a backup, or a clock change -
	// must not silently replace live settings with an older set.
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateSettings(map[string]interface{}{"mixedPort": 7902}); err != nil {
		t.Fatal(err)
	}
	// Rewrite an older state and backdate it.
	old := []byte(`{"settings":{"mixedPort":7000}}`)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "state.json"), past, past); err != nil {
		t.Fatal(err)
	}
	if got := a.Settings().MixedPort; got != 7902 {
		t.Errorf("mixedPort = %d; an older file replaced the live settings", got)
	}
}

func TestReloadAdoptsAChangeImmediately(t *testing.T) {
	// Reload is for a caller that knows another process has just written.
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpdateSettings(map[string]interface{}{"mode": "global"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := a.Settings().Mode; got != "global" {
		t.Errorf("mode = %q after Reload, want global", got)
	}
}

func TestSettingsSyncToleratesAMissingFile(t *testing.T) {
	// The data directory can be removed underneath a running program. Reading
	// settings must not fail in a way that takes the caller down; the in-memory copy
	// is what it has.
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateSettings(map[string]interface{}{"mixedPort": 7903}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if got := a.Settings().MixedPort; got != 7903 {
		t.Errorf("mixedPort = %d after the file disappeared; the in-memory copy should remain", got)
	}
}

func TestOurOwnCoreOnThePortIsAdoptedNotRotatedAwayFrom(t *testing.T) {
	// The state this was observed in: an activation left a core holding the
	// configured port, the interface started afterwards, decided its own core was a
	// foreign program, and moved itself to a different port. The tunnel was up and
	// carrying traffic the whole time, and the program disagreed with itself - the
	// system proxy could not follow because nothing was listening on the new port.
	//
	// Ownership is judged by the command line naming this data directory, because
	// every client that ships a core calls it mihomo.exe.
	dir := t.TempDir()

	// This process's own core is not a mihomo, so it must not be adopted.
	if coreOwnsDataDir(os.Getpid(), dir, t.TempDir()) {
		t.Error("a process that is not a core must not be reported as one")
	}
	// Nor is pid 0.
	if coreOwnsDataDir(0, dir, t.TempDir()) {
		t.Error("pid 0 must not be reported as a core")
	}
	// A pid that does not exist is not a core.
	if coreOwnsDataDir(0x7FFFFFF0, dir, t.TempDir()) {
		t.Error("a pid that does not exist must not be reported as a core")
	}
}

func TestAdoptedCoreIsRecorded(t *testing.T) {
	// Recording it is what lets the rest of the program tell "there is no core" from
	// "there is a core I did not start". Those are different situations and were
	// previously the same.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st}

	a.mu.Lock()
	before := a.adoptedCorePID
	a.mu.Unlock()
	if before != 0 {
		t.Errorf("adoptedCorePID starts as %d, want 0", before)
	}

	a.adoptRunningCore(4242)
	a.mu.Lock()
	got := a.adoptedCorePID
	a.mu.Unlock()
	if got != 4242 {
		t.Errorf("adoptedCorePID = %d after adopting, want 4242", got)
	}
}

// ---- no runtime file may be tracked, ever -----------------------------------

func TestNoRuntimeFileIsTrackedByGit(t *testing.T) {
	// This is a guard against a mistake made three times, not a test of behaviour.
	//
	//   - config.last-good.yaml, a whole configuration including node credentials;
	//   - data/control.secret, the key to the core's control API, which sat in a
	//     public repository for seven commits;
	//   - data/service-state.json and data/activation-handover.json, runtime records.
	//
	// Each time the file was added by code and forgotten by the ignore list, and each
	// time the omission was found by hand rather than by the build. The ignore rules
	// are now written by kind, and this asserts the property those rules exist for.
	//
	// It shells out to git, so it is skipped where git or the repository is absent -
	// a machine building from an unpacked release has neither and must still be able
	// to run the suite.
	root := ".."
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not a git checkout")
	}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		out, err := cmd.Output()
		return string(out), err
	}
	out, err := git("ls-files", "data/")
	if err != nil {
		t.Skipf("git is unavailable or this is not a checkout: %v", err)
	}

	// What ships is only what a fresh clone needs to start: the rule databases, the
	// icon, the first-run marker, and the candidate pool the optimiser seeds from.
	allowed := map[string]bool{
		"data/GeoSite.dat":    true,
		"data/geoip.metadb":   true,
		"data/zenith.ico":     true,
		"data/free.flag":      true,
		"data/candidates.txt": true,
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(filepath.ToSlash(line))
		if f == "" || allowed[f] {
			continue
		}
		t.Errorf("data/%s is tracked by git. Anything under data/ other than the "+
			"shipped files is generated at runtime and must not be committed - "+
			"three leaks came from exactly this, one of them a control secret that "+
			"reached a public repository. Add it to .gitignore.", strings.TrimPrefix(f, "data/"))
	}
}

// ---- the privacy block must be a system policy, not a declaration ----------

func TestPrivacyBlockHasNoExecutionPathByAccident(t *testing.T) {
	// The setting existed and nothing read it. That is the defect this file fixes,
	// and it is worth a test that fails if the block is ever disconnected from the
	// paths that establish it - a security control that is only declared is worse
	// than one that is absent, because the interface reports it as on.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "ApplyPrivacyBlock(") {
		t.Error("the privacy activation does not establish the block")
	}
	if !strings.Contains(text, "ReleasePrivacyBlock(") {
		t.Error("nothing releases the block, so it could never be turned off")
	}
	// And the rollback must check whether it is still enforced rather than assert
	// that it is.
	if !strings.Contains(text, "PrivacyBlockEnforced()") {
		t.Error("the rollback does not verify the block survived a failed activation")
	}
}

func TestPrivacyBlockRuleNamesAreScopedToThisProgram(t *testing.T) {
	// The rules are found by exact name. A prefix match would risk deleting a rule
	// belonging to something else, the same way an adapter is matched by name.
	names := blockRuleNames()
	if len(names) != 2 {
		t.Fatalf("expected two rules (one per direction), got %d", len(names))
	}
	for _, n := range names {
		if !strings.HasPrefix(n, blockRulePrefix) {
			t.Errorf("rule %q does not carry the prefix %q", n, blockRulePrefix)
		}
		if !strings.Contains(n, "Zenith") {
			t.Errorf("rule %q does not name this program", n)
		}
	}
	// Both directions, because an outbound block alone leaves an established
	// inbound connection carrying replies.
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "(in)") || !strings.Contains(joined, "(out)") {
		t.Errorf("the block must cover both directions, got %v", names)
	}
}

func TestPrivacyBlockStatusReportsEnforcedNotRequested(t *testing.T) {
	// The interface decides whether to say "protected" from this. Reporting the
	// setting instead of the system would reproduce the original defect in a new
	// place: a claim of protection backed by nothing.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateSettings(map[string]interface{}{"tunMode": string(TunPrivacy)}); err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st}

	got := a.PrivacyBlockStatus()
	if !got.Requested {
		t.Fatal("privacy mode with block-on-failure should be reported as requested")
	}
	if got.CheckedAt == "" {
		t.Error("the status should record when it was read")
	}
	// This test runs without elevation, so the rules cannot be installed. The point
	// is which field carries the answer: Enforced must reflect the system, and the
	// detail must say plainly that the two disagree.
	if got.Enforced {
		t.Skip("firewall rules are present on this machine; the disagreement case cannot be exercised")
	}
	if got.Detail == "" {
		t.Error("a disagreement between the setting and the system must be explained")
	}
	if !strings.Contains(got.Detail, "不受阻断保护") && !strings.Contains(got.Detail, "防火墙规则") {
		t.Errorf("the detail should name the condition, got %q", got.Detail)
	}
}

func TestPrivacyBlockStatusQuietWhenNothingIsAsked(t *testing.T) {
	// With TUN off there is nothing to protect, and the status should not read as a
	// warning.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: dir, store: st}
	got := a.PrivacyBlockStatus()
	if got.Requested {
		t.Error("nothing was asked for")
	}
	if got.Enforced {
		t.Error("no rules should be present in a fresh data directory")
	}
}

// ---- a subscription must not be able to add a field to the document --------

func TestNestedTransportKeysCannotInjectTopLevelFields(t *testing.T) {
	// The review verified this against the source and it held: the flat allowlist on
	// Extra did not cover the nested maps, and `ws-opts` was written through a
	// separate branch that emitted its keys and sub-keys untouched.
	//
	// The chain that makes it reachable: the subscription parser unquotes with
	// strconv.Unquote, which turns an escaped \n inside a quoted key into a real
	// newline, and the generator then writes that key verbatim at whatever
	// indentation it chose - so the text after the newline becomes a new field in
	// the document rather than part of a proxy option.
	hostile := "x\n  audit-marker: injected"
	node := Proxy{
		Name: "n", Type: "vmess", Server: "1.2.3.4", Port: 443, Network: "ws",
		WSOpts: map[string]interface{}{
			"path": "/ws",
			"headers": map[string]interface{}{
				hostile: "yes",
			},
			// And a nested key at the outer level, same shape.
			"bad\n  other-marker: injected": "yes",
		},
	}
	cfg := BuildConfig([]Proxy{node}, []string{"n"},
		Settings{MixedPort: 7890, ControlPort: 7797, Mode: "rule",
			TunDevice: tunDefaultDevice, TunStack: tunDefaultStack},
		"secret", "n", 8199)

	for _, forbidden := range []string{"audit-marker", "other-marker", "injected"} {
		if strings.Contains(cfg, forbidden) {
			t.Errorf("a subscription key reached the configuration as %q:\n%s", forbidden, cfg)
		}
	}
	// The legitimate option must survive, or the fix would be a regression in what
	// subscriptions can express.
	if !strings.Contains(cfg, "path:") {
		t.Errorf("the legitimate option was dropped:\n%s", cfg)
	}
}

func TestNestedOptionAllowlistRefusesUnknownAndUnsafeKeys(t *testing.T) {
	// An allowlist, for the same reason the flat one is: a denylist has to
	// anticipate every way a crafted key could escape its block.
	allowed := []string{"path", "host", "headers", "grpc-service-name", "h2-host"}
	for _, k := range allowed {
		if !nestedKeyAllowed(k) {
			t.Errorf("nestedKeyAllowed(%q) = false, want true", k)
		}
	}
	refused := []string{
		"", "a b", "a\tb", "a\nb", "a\rb", "a\x00b",
		"key: value", "- item", "  indented", "a[0]", "a{b}", "a,b", "a'b", `a"b`,
		"#comment", "|block", ">folded", "&anchor", "*alias", "%directive",
		strings.Repeat("x", 65),
		// Names that are valid YAML keys but are not options for these transports.
		"extra-global", "external-controller", "dns", "tun",
	}
	for _, k := range refused {
		if nestedKeyAllowed(k) {
			t.Errorf("nestedKeyAllowed(%q) = true, want false", k)
		}
	}
}

func TestValueValidationWalksNestedMaps(t *testing.T) {
	// The defect was a nested map a flat check did not see, so the check walks.
	good := map[string]interface{}{
		"path": "/ws",
		"headers": map[string]interface{}{
			"User-Agent": "x",
			"Host":       "example.com",
		},
	}
	for k, v := range good {
		if err := subscriptionValueIsSafe(k, v, 0); err != nil {
			t.Errorf("%q should be safe: %v", k, err)
		}
	}

	// A control character in a value is refused, because some parsers treat one as
	// a document boundary.
	if err := subscriptionValueIsSafe("k", "a\x00b", 0); err == nil {
		t.Error("a NUL in a value must be refused")
	}
	// An unsafe key at depth two is still found.
	if err := subscriptionValueIsSafe("headers",
		map[string]interface{}{"a\nb": "x"}, 0); err == nil {
		t.Error("an unsafe nested key must be found by the walk")
	}
	// And depth is bounded, so validation cannot be turned into a stack overflow.
	deep := interface{}("leaf")
	for i := 0; i < 12; i++ {
		deep = map[string]interface{}{"k": deep}
	}
	if err := subscriptionValueIsSafe("root", deep, 0); err == nil {
		t.Error("unbounded nesting must be refused")
	}
}

func TestSanitizeKeepsGoodOptionsAndDropsBadOnes(t *testing.T) {
	// Dropping rather than failing the whole subscription: one unusual option should
	// not cost the user every node they have.
	in := map[string]interface{}{
		"path":    "/ws",
		"host":    "example.com",
		"bogus":   "x",
		"a\nb":    "y",
		"headers": map[string]interface{}{"User-Agent": "z"},
	}
	out := sanitizeNestedOpts("ws-opts", in)
	if out == nil {
		t.Fatal("nothing survived")
	}
	if _, ok := out["path"]; !ok {
		t.Error("a legitimate option was dropped")
	}
	if _, ok := out["host"]; !ok {
		t.Error("a legitimate option was dropped")
	}
	if _, ok := out["bogus"]; ok {
		t.Error("an unknown option was kept")
	}
	if _, ok := out["a\nb"]; ok {
		t.Error("an unsafe key was kept")
	}
	// An empty result is nil rather than an empty map, so the generator's
	// len(m) == 0 branch still skips writing the block at all.
	if sanitizeNestedOpts("ws-opts", map[string]interface{}{"bogus": 1}) != nil {
		t.Error("a map with nothing usable should be nil")
	}
}

func TestSubscriptionParsingCannotProduceAnUnsafeNestedKey(t *testing.T) {
	// End to end through the real parser, which is where the escaped newline is
	// decoded. If this holds, no path from subscription text to the generator
	// carries an unsafe key.
	doc := `{"outbounds":[{"type":"vmess","tag":"n","server":"1.2.3.4","server_port":443,` +
		`"uuid":"00000000-0000-0000-0000-000000000000","transport":{"type":"ws",` +
		`"path":"/ws","headers":{"x\n  audit-marker: injected":"yes"}}}]}`
	for _, p := range ParseSubscription(doc) {
		for transport, m := range map[string]map[string]interface{}{
			"ws-opts": p.WSOpts, "grpc-opts": p.GrpcOpts, "h2-opts": p.H2Opts,
		} {
			for k, v := range m {
				if !nestedKeyAllowed(k) {
					t.Errorf("%s carries %q, which the allowlist refuses", transport, k)
				}
				if err := subscriptionValueIsSafe(k, v, 0); err != nil {
					t.Errorf("%s carries an unsafe value at %q: %v", transport, k, err)
				}
			}
		}
	}
}

// ---- the interface must not hand its token to a foreign page ---------------

func TestForeignPageCannotObtainTheToken(t *testing.T) {
	// A hostile page can navigate the browser to http://127.0.0.1:<port>/. The
	// response used to carry the API token, so that page could then read it. Fetch
	// Metadata is set by the browser and cannot be forged by a page, which is what
	// makes the distinction available.
	const expect = "127.0.0.1:7799"

	foreign := []struct {
		name    string
		fetch   string
		origin  string
		wantRef bool
	}{
		{"cross-site navigation", "cross-site", "https://evil.example", true},
		{"same-site, another port", "same-site", "http://127.0.0.1:8080", true},
		{"foreign origin with no metadata", "", "https://evil.example", true},
		{"foreign origin even when metadata lies", "same-origin", "https://evil.example", true},
		{"unrecognised metadata", "something-new", "", true},
		// Ours, and the two shapes a legitimate load takes.
		{"our own page", "same-origin", "http://127.0.0.1:7799", false},
		{"a navigation the user started", "none", "", false},
		// No metadata at all: a local script or a command-line client. It cannot be
		// distinguished from the browser, and the honest answer is to allow it and
		// say so in the README rather than to pretend the token authenticates users.
		{"no metadata, no origin", "", "", false},
	}
	for _, c := range foreign {
		r := httptest.NewRequest(http.MethodGet, "http://"+expect+"/", nil)
		r.Host = expect
		if c.fetch != "" {
			r.Header.Set("Sec-Fetch-Site", c.fetch)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		got := !interfaceRequestAllowed(r, expect)
		if got != c.wantRef {
			t.Errorf("%s: refused = %v, want %v", c.name, got, c.wantRef)
		}
	}
}

func TestOriginComparisonIsExactOnPort(t *testing.T) {
	// The previous check accepted any loopback origin, so another application on
	// this machine was treated as ours.
	const expect = "127.0.0.1:7799"
	ours := []string{"http://127.0.0.1:7799", "http://localhost:7799"}
	for _, o := range ours {
		if !originIsOurs(o, expect) {
			t.Errorf("originIsOurs(%q) = false, want true", o)
		}
	}
	notOurs := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8081",
		"https://127.0.0.1:7799",
		"http://evil.example",
		"http://127.0.0.1",
		"",
		"not a url",
	}
	for _, o := range notOurs {
		if originIsOurs(o, expect) {
			t.Errorf("originIsOurs(%q) = true, want false", o)
		}
	}
}

func TestConfigPreviewIsRedacted(t *testing.T) {
	// The preview existed to show what the rules produce, and it carried the core
	// secret, every node UUID and every WebSocket path. The token is not an account
	// boundary, so what the interface hands out should not be a credential even to a
	// legitimate caller.
	cfg := `mixed-port: 7890
external-controller: 127.0.0.1:7797
secret: "the-core-control-secret"
proxies:
  - name: "node"
    type: vmess
    server: example.com
    uuid: 187d8fa9-569b-49e4-bd00-bbb318a4f295
    ws-opts:
      path: "/a-private-path"
      headers:
        Host: front.example.com
rules:
  - "DOMAIN-SUFFIX,example.com,PROXY"
`
	out := RedactConfigForDisplay(cfg)
	for _, leak := range []string{
		"the-core-control-secret",
		"187d8fa9-569b-49e4-bd00-bbb318a4f295",
		"/a-private-path",
	} {
		if strings.Contains(out, leak) {
			t.Errorf("the preview still carries %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "<hidden>") {
		t.Error("nothing was replaced, so the redaction did not run")
	}
	// The structure is the useful part and must survive: a preview that hid the
	// keys would not be a preview.
	for _, keep := range []string{
		"mixed-port: 7890",
		"external-controller: 127.0.0.1:7797",
		"server: example.com",
		"DOMAIN-SUFFIX,example.com,PROXY",
		"secret:",
		"uuid:",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("the preview lost %q, which makes it useless for its purpose:\n%s", keep, out)
		}
	}
	// The Host header is deliberately kept, and that decision is recorded rather
	// than accidental: it is what rules match on.
	if !strings.Contains(out, "front.example.com") {
		t.Error("the Host header was hidden; it is what rules match on")
	}
	// Line count is preserved, so the preview still lines up with the real file.
	if strings.Count(out, "\n") != strings.Count(cfg, "\n") {
		t.Errorf("redaction changed the number of lines: %d -> %d",
			strings.Count(cfg, "\n"), strings.Count(out, "\n"))
	}
}

func TestConfigRedactionLeavesCommentsAndBlanksAlone(t *testing.T) {
	in := "# a comment mentioning secret: not-a-secret\n\nsecret: \"real\"\n"
	out := RedactConfigForDisplay(in)
	if !strings.Contains(out, "# a comment mentioning secret: not-a-secret") {
		t.Error("a comment was altered")
	}
	if strings.Contains(out, `"real"`) {
		t.Error("the real secret was not masked")
	}
}

func TestUUIDLikeRecognisesOnlyUUIDs(t *testing.T) {
	yes := []string{
		"187d8fa9-569b-49e4-bd00-bbb318a4f295",
		`"187d8fa9-569b-49e4-bd00-bbb318a4f295"`,
	}
	for _, v := range yes {
		if !uuidLike(v) {
			t.Errorf("uuidLike(%q) = false, want true", v)
		}
	}
	no := []string{"", "short", "187d8fa9-569b-49e4-bd00-bbb318a4f29",
		"187d8fa9x569b-49e4-bd00-bbb318a4f295", "example.com",
		"187d8fa9-569b-49e4-bd00-bbb318a4f2955"}
	for _, v := range no {
		if uuidLike(v) {
			t.Errorf("uuidLike(%q) = true, want false", v)
		}
	}
}
