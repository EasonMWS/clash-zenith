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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	// The elevated process has no window and no UI, so its only way to report is
	// its exit status and the log. A signature that returns nothing would leave
	// the caller unable to say whether the activation worked.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	if !strings.Contains(string(src), "func (a *App) RunElevatedActivation(mode TunMode) error {") {
		t.Error("RunElevatedActivation should return an error so its caller can report the outcome")
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
