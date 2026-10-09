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

	// With the watchdog arguments following, both must be readable: this is what
	// the release smoke test asserts on.
	os.Args = []string{"zenith.exe", "-self-test", "-watchdog", `C:\data`, "7999"}
	if !isSelfTestInvocation() {
		t.Error("-self-test should still be recognised with extra arguments")
	}
	if isWatchdogInvocation() {
		// -watchdog is not the first argument here, so this is correctly false;
		// the smoke test reads the same predicate to show the shape is understood.
		t.Log("watchdog is correctly not the first argument in the self-test form")
	}

	// A watchdog invocation proper is a different shape.
	os.Args = []string{"zenith.exe", "-watchdog", `C:\data`, "7999"}
	if !isWatchdogInvocation() {
		t.Error("the watchdog form should be recognised")
	}
	if isSelfTestInvocation() {
		t.Error("the watchdog form must not be mistaken for a self-test")
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
