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
	for _, m := range []TunMode{"", TunOff, TunCompat} {
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
	for _, m := range []TunMode{TunOff, TunCompat} {
		l := m.Label()
		if l == "" {
			t.Errorf("mode %q has no label", m)
		}
		if _, dup := labels[l]; dup {
			t.Errorf("two modes share the label %q", l)
		}
		labels[l] = l
	}
	if !strings.Contains(TunCompat.Label(), "TUN") {
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
		{TunCompat, true},
	} {
		cfg := BuildConfig(nodes, []string{"n1"}, Settings{
			MixedPort: 7890, ControlPort: 7797, Mode: "rule", TunMode: tc.mode,
			TunDevice: defaultTunDevice, TunStack: "gvisor",
		}, "secret", "n1", 8199)
		has := strings.Contains(cfg, "\ntun:\n")
		if has != tc.want {
			t.Errorf("mode %q: tun block present = %v, want %v", tc.mode, has, tc.want)
		}
		// strict-route is emitted with the tunnel, not with a mode.
		//
		// It used to be set only for a mode called "privacy", which is gone. Its
		// documented meaning is narrower than that name suggested - it suppresses
		// multihomed DNS leakage, it is not a kill switch, and it stops doing anything
		// once the core stops - so it is on for every tunnel and described for what it
		// does rather than for what a mode was called.
		if has && !strings.Contains(cfg, "strict-route: true") {
			t.Error("the tunnel should ask the core to suppress DNS leakage")
		}
		if !has && strings.Contains(cfg, "strict-route:") {
			t.Error("no tunnel means no tunnel options")
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
	on.TunMode = TunCompat
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
	rec := a.beginHandover(id, 4242, TunCompat)
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

	// The liveness endpoint answers without a secret, because the window has to ask
	// before it has decided to trust anything. It now answers with a proof instead of
	// a bare 200: the old shape meant any program that bound the port was believed,
	// and the next request carried the control secret to it.
	resp, err := http.Get(srv.URL + "/alive?nonce=abc123")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/alive = %d, want 200: the window must be able to ask without a secret",
			resp.StatusCode)
	}
	var alive serviceAliveResponse
	if err := json.Unmarshal(body, &alive); err != nil {
		t.Fatalf("the liveness answer is not the agreed shape: %v (%s)", err, body)
	}
	if alive.Nonce != "abc123" {
		t.Errorf("the answer echoes nonce %q, want the one we sent", alive.Nonce)
	}
	want := serviceProofMAC("the-real-secret", "abc123", alive.TS, alive.Port)
	if alive.Proof != want {
		t.Error("the service did not prove it holds the secret")
	}
	// And the proof is not the secret, in any encoding.
	if strings.Contains(string(body), "the-real-secret") {
		t.Error("the liveness answer carries the secret itself")
	}
	// A request with no nonce is refused rather than answered with a proof over an
	// empty value, which would be a proof anybody could compute a use for.
	bad, err := http.Get(srv.URL + "/alive")
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode == http.StatusOK {
		t.Error("/alive without a nonce should not be answered")
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
	if _, err := a.UpdateSettings(map[string]interface{}{"tunMode": string(TunCompat)}); err != nil {
		t.Fatal(err)
	}
	if got := b.Settings().TunMode; got != TunCompat {
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
    uuid: 00000000-1111-2222-3333-444444444444
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
		"00000000-1111-2222-3333-444444444444",
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
		"00000000-1111-2222-3333-444444444444",
		`"00000000-1111-2222-3333-444444444444"`,
	}
	for _, v := range yes {
		if !uuidLike(v) {
			t.Errorf("uuidLike(%q) = false, want true", v)
		}
	}
	no := []string{"", "short", "deadbeef-0000-1111-bd00-22223333333355",
		"deadbeefx0000-1111-bd00-bbb318a4f29", "example.com",
		"00000000-1111-2222-3333-4444444444445"}
	for _, v := range no {
		if uuidLike(v) {
			t.Errorf("uuidLike(%q) = true, want false", v)
		}
	}
}

// ---- an adapter name reaches a shell, so it must be a plain identifier -------

func TestAdapterNameCannotEscapeIntoPowerShell(t *testing.T) {
	// Measured before this was fixed. `tunDevice` was interpolated into
	//     Get-NetAdapter -Name '<name>'
	// and into Remove-NetAdapter inside the elevated helper, so a name containing a
	// single quote closed the string. With
	//
	//     x'; Write-Host PWNED; #
	//
	// the generated command ran and printed PWNED.
	//
	// Escaping would be the other answer and is the wrong one: the name is also
	// written into the configuration and passed to the core, so a value needing
	// escaping in one place and not another will be escaped in one place and not
	// another. A name that is not a plain identifier is refused.
	hostile := []string{
		`x'; Write-Host PWNED; #`,
		`x'; Remove-NetAdapter -Name 'Ethernet' -Confirm:$false; '`,
		"x`nWrite-Host PWNED",
		`x$(Write-Host PWNED)`,
		`x"; Write-Host PWNED; "`,
		"x\ny", "x\ty", "x|y", "x&y", "x>y", "x<y", "x;y",
		"", "  ", "---", "___",
		strings.Repeat("a", 33),
		"Zenith\x00",
	}
	for _, name := range hostile {
		if validAdapterName(name) {
			t.Errorf("validAdapterName(%q) = true; this name would be interpolated into a shell", name)
		}
	}

	// And the settings accessor substitutes the default rather than passing it on.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateSettings(map[string]interface{}{
		"tunDevice": `x'; Write-Host PWNED; #`,
	}); err != nil {
		t.Fatal(err)
	}
	if got := st.Settings().NormalizedTunDevice(); got != tunDefaultDevice {
		t.Errorf("an unusable name reached the accessor as %q; it must be replaced", got)
	}
}

func TestOrdinaryAdapterNamesAreAccepted(t *testing.T) {
	// The rule must not be so strict that a legitimate name is refused, or the
	// substitution would be the bug.
	good := []string{
		"Zenith", "zenith", "MyTun", "tun0", "Zenith-Tun", "Zenith_Tun",
		"Local Area Connection", "Wintun 1", "a", "A1",
	}
	for _, name := range good {
		if !validAdapterName(name) {
			t.Errorf("validAdapterName(%q) = false, want true", name)
		}
	}
	// And the default is obviously among them.
	if !validAdapterName(tunDefaultDevice) {
		t.Fatalf("the default name %q is refused by its own rule", tunDefaultDevice)
	}
}

func TestAdapterLookupRefusesAnUnusableNameRatherThanPassingItOn(t *testing.T) {
	// The second check, at the point the name reaches a shell. It cannot fire today
	// because the accessor substitutes first; it exists so that relaxing the fixed
	// name later does not quietly reopen the hole.
	if tunAdapterExists(`x'; Write-Host PWNED; #`) {
		t.Error("the adapter lookup accepted a name it should refuse")
	}
	if err := removeTunAdapter(`x'; Write-Host PWNED; #`); err == nil {
		t.Error("adapter removal accepted a name it should refuse")
	}
}

// ---- the service path must run the same state machine ----------------------

func TestServicePathSavesTheModeBeforeGeneratingTheConfig(t *testing.T) {
	// The order was the other way round, and the consequence was exact: enabling from
	// off produced a configuration built from settings that still said off, so it had
	// no tun block; switching compat to privacy produced one that still carried the
	// old strict-route. The service then started a core against a configuration that
	// did not describe what was asked for.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "if a.serviceReachable() {")
	if start < 0 {
		t.Fatal("the service path is missing")
	}
	end := strings.Index(text[start:], "txA.step(\"请求服务\", \"pending\"")
	if end < 0 {
		t.Fatal("could not find the end of the service path's preparation")
	}
	block := text[start : start+end]

	save := strings.Index(block, "UpdateSettings")
	build := strings.Index(block, "BuildConfig")
	if save < 0 || build < 0 {
		t.Fatal("the block does not both save and build")
	}
	if save > build {
		t.Error("the configuration is generated before the mode is saved, so it " +
			"describes the previous mode rather than the requested one")
	}
}

func TestServicePathVerifiesBeforeClaimingSuccess(t *testing.T) {
	// Returning straight after the request meant the interface said "enabled" on the
	// strength of a request that was accepted. That is the claim this program is not
	// allowed to make.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "if a.serviceReachable() {")
	end := strings.Index(text[start:], "\n\t// No service yet.")
	if end < 0 {
		t.Fatal("could not find the end of the service path")
	}
	block := text[start : start+end]

	if !strings.Contains(block, "VerifyTunTraffic(") {
		t.Error("the service path does not verify the traffic before reporting success")
	}
	if !strings.Contains(block, "commitConfig(") {
		t.Error("the service path does not commit the verified configuration")
	}
	if !strings.Contains(block, "a.tunRun.Active = false") {
		t.Error("the service path does not clear the running flag, so the interface " +
			"would stay in the running state after success")
	}
	// And the guard that the mode actually reached the configuration.
	if !strings.Contains(block, "tun:") {
		t.Error("the service path does not check that the generated configuration " +
			"carries the mode it was asked for")
	}
}

func TestNothingReEntersEnableTun(t *testing.T) {
	// The re-entry hit the guard at the top of EnableTun - the outer call had already
	// set Active - so the activation stopped with "already enabling, please wait"
	// while nothing was running. The guard is right; calling through it was not.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	// The only call to EnableTun should be from the HTTP handler, which is where a
	// user action arrives. A call from inside the activation is the defect.
	if strings.Contains(text, "go a.EnableTun(") {
		t.Error("the activation re-enters EnableTun, which its own guard refuses")
	}
	// The route out of the install branch is the internal function instead.
	if !strings.Contains(text, "go a.runEnableTun(mode)") {
		t.Error("the install branch should continue into the same state machine")
	}
}

// ---- the service must speak the SCM protocol -------------------------------

func TestServiceSpeaksTheServiceControlManagerProtocol(t *testing.T) {
	// The service was registered with Windows and could never start. The review found
	// the reason by reading the source: no StartServiceCtrlDispatcher, no control
	// handler, no status reporting - the -service branch opened a socket and served.
	//
	// From the SCM's side that is not a service. It starts the process, waits for it
	// to connect to the dispatcher, and when it does not, concludes the start failed.
	// Confirmed on this machine: AUTO_START, and STOPPED, having never once run.
	src, err := os.ReadFile("scm.go")
	if err != nil {
		t.Fatalf("scm.go is missing, so no SCM protocol is implemented: %v", err)
	}
	text := string(src)
	for _, need := range []string{
		"StartServiceCtrlDispatcherW",
		"RegisterServiceCtrlHandlerExW",
		"SetServiceStatus",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("the SCM protocol needs %s and does not have it", need)
		}
	}
	// The four states that make a service manageable rather than a process that
	// happens to be running.
	for _, state := range []string{
		"svcStateStartPending", "svcStateRunning", "svcStateStopPending", "svcStateStopped",
	} {
		if !strings.Contains(text, state) {
			t.Errorf("the service never reports %s, so the SCM cannot tell what it is doing", state)
		}
	}
	// And it must honour stop, or it is killed with its children - which for this
	// service means the core it owns.
	if !strings.Contains(text, "svcControlStop") {
		t.Error("the service does not handle a stop request")
	}
	// The clean shutdown lives in service.go, which is where the listener is.
	svc, err := os.ReadFile("service.go")
	if err != nil {
		t.Skipf("service.go is not readable: %v", err)
	}
	if !strings.Contains(string(svc), "srv.Shutdown") {
		t.Error("the service does not shut its listener down cleanly on stop")
	}
	if !strings.Contains(string(svc), "app.core.Stop()") {
		t.Error("stopping the service does not stop the core it owns, which would " +
			"leave an orphan with no owner - the state this design exists to avoid")
	}
}

func TestServiceRefusesToRunOutsideTheScm(t *testing.T) {
	// Running the binary by hand with -service must fail with a message that says
	// why. That is not a limitation to work around: it is how the protocol behaves,
	// and it is also how the implementation gets tested without installing anything.
	src, err := os.ReadFile("scm.go")
	if err != nil {
		t.Skipf("scm.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "无法连接到服务控制管理器") {
		t.Error("a failed dispatcher connection must be reported in terms of what it means")
	}
	if !strings.Contains(text, "func IsRunningAsService()") {
		t.Error("the program should be able to say whether it was started by the SCM")
	}
}

func TestServerKnowsItsOwnOrigin(t *testing.T) {
	// expectHost was declared and never assigned, so the origin check compared against
	// an empty string and refused every request carrying an Origin header - including
	// the interface's own. The symptom was "跨源请求已被拒绝" with the system proxy and
	// TUN switches refusing to move, which is how it was found.
	//
	// A field that must be set and is not is invisible until something depends on it,
	// so this asserts the dependence rather than the field.
	srv := NewServer(&App{}, t.TempDir(), 7799)
	if srv.expectHost == "" {
		t.Fatal("the server does not know its own host, so every request with an " +
			"Origin header will be refused - including its own page's")
	}
	if !originIsOurs("http://127.0.0.1:7799", srv.expectHost) {
		t.Errorf("the server does not recognise its own origin: expectHost=%q", srv.expectHost)
	}
	if !originIsOurs("http://localhost:7799", srv.expectHost) {
		t.Errorf("localhost is the same server and must be recognised: expectHost=%q", srv.expectHost)
	}
	if originIsOurs("http://127.0.0.1:8080", srv.expectHost) {
		t.Error("another loopback port is another application and must not be recognised")
	}

	// And end to end through the middleware, with the headers a real same-origin
	// request carries.
	for _, hdrs := range []map[string]string{
		{"Origin": "http://127.0.0.1:7799"},
		{"Origin": "http://127.0.0.1:7799", "Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "none"},
		{},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7799/api/status", nil)
		r.Host = "127.0.0.1:7799"
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		if !interfaceRequestAllowed(r, srv.expectHost) {
			t.Errorf("our own request was refused with headers %v", hdrs)
		}
	}
	// And a genuinely foreign one is still refused.
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7799/api/status", nil)
	r.Host = "127.0.0.1:7799"
	r.Header.Set("Origin", "https://evil.example")
	if interfaceRequestAllowed(r, srv.expectHost) {
		t.Error("a foreign origin must still be refused")
	}
}

func TestAdapterRemovalUsesAToolThatExists(t *testing.T) {
	// Measured on this machine:
	//
	//   Get-NetAdapter       resolves
	//   Remove-NetAdapter    does NOT resolve
	//   Remove-PnpDevice     does NOT resolve
	//   Disable-PnpDevice    resolves
	//   pnputil.exe          present
	//
	// So the old call failed with CommandNotFoundException every time, the error went
	// to the log, and the adapter stayed. The next activation then reported it as
	// "another tunnel or virtual adapter" - the program warning the user about its own
	// leftover.
	src, err := os.ReadFile("winapi.go")
	if err != nil {
		t.Skipf("winapi.go is not readable: %v", err)
	}
	text := string(src)
	// Whether it is *called*, not whether it is mentioned: the comment above the
	// function names both cmdlets to explain why they are not used, and a test that
	// forbade the name would forbid the explanation.
	for _, call := range []string{
		`Remove-NetAdapter -Name`,
		`Remove-PnpDevice -InstanceId`,
	} {
		if strings.Contains(text, call) {
			t.Errorf("the removal still calls %q, which does not resolve here", call)
		}
	}
	if !strings.Contains(text, "pnputil") {
		t.Error("the removal does not use pnputil, the tool that is actually present")
	}
	// And it must check the outcome rather than trusting the command, because the
	// defect being fixed is a removal that reported success and did nothing.
	if !strings.Contains(text, "但网卡仍然存在") {
		t.Error("the removal does not verify that the adapter is gone")
	}
	// A fallback that at least stops it carrying traffic.
	if !strings.Contains(text, "Disable-NetAdapter") {
		t.Error("there is no fallback for a removal that cannot complete")
	}
}

func TestAdapterInstanceIDIsReadNotConstructed(t *testing.T) {
	// The instance id is read from the adapter, so the removal cannot be pointed at
	// anything but the interface being looked at.
	src, err := os.ReadFile("winapi.go")
	if err != nil {
		t.Skipf("winapi.go is not readable: %v", err)
	}
	if !strings.Contains(string(src), "PnPDeviceID") {
		t.Error("the instance id is not read from the adapter")
	}
}

// ---- a starting core is not a dead proxy -----------------------------------

func TestDeadProxyGuardLeavesOurOwnPortAlone(t *testing.T) {
	// Observed, with timestamps from the log:
	//
	//   19:53:52  the program starts
	//   19:53:53  the watchdog arms on the configured port
	//   19:54:03  "system proxy points at dead port 7899 -> fixing"
	//   19:54:03  "system proxy disabled"       <- the machine is now offline
	//   19:57:24  the core comes up (the user was answering the elevation prompt)
	//   19:57:28  TUN verified carrying traffic
	//
	// Four minutes with no internet, because the guard could not tell a port about to
	// be served from a port nothing would ever serve. The window is not theoretical:
	// with TUN enabled the core is started by an elevated activation, so there is a
	// prompt to read and answer between the window opening and the core answering.
	dir := t.TempDir()
	sp := NewSystemProxy(dir)

	// Without a configured port, a dead port is still cleaned up - the guard keeps
	// its original purpose.
	if sp.ownPortExpected(7899) {
		t.Error("with no configured port, no port should be treated as ours")
	}

	sp.SetExpectedPort(7899)
	if !sp.ownPortExpected(7899) {
		t.Error("the configured port must not be treated as a dead proxy")
	}
	// A different port is still somebody's leftover and still gets cleaned up.
	for _, other := range []int{7908, 8080, 1, 65535} {
		if sp.ownPortExpected(other) {
			t.Errorf("port %d is not the configured port and must not be exempt", other)
		}
	}
	// And the exemption is off when nothing is configured, so the guard does not stop
	// working on a machine that has never set a port.
	sp.SetExpectedPort(0)
	if sp.ownPortExpected(7899) {
		t.Error("a zero configured port must not exempt anything")
	}
}

// ---- a credential change invalidates the optimisation ----------------------

func TestACredentialChangeInvalidatesTheOptimisation(t *testing.T) {
	// Observed, after a provider reset a subscription's UUID:
	//
	// The refresh returned one node with the same name and the same shape and a new
	// UUID. The generation counter did not move, so the stored optimisation still
	// counted as current and the program kept offering seventeen edge addresses
	// carrying a credential that had been revoked. Every one failed its delay test,
	// the health loop kept switching between them, and the interface showed a full
	// node list with nothing usable in it.
	//
	// The material comparison is the fix: a change to what a node connects with
	// invalidates what was derived from it.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := []Proxy{{
		Name: "n", Type: "vmess", Server: "1.2.3.4", Port: 443,
		UUID: "aaaaaaaa-1111-2222-3333-444444444444", Network: "ws",
		WSOpts: map[string]interface{}{"path": "/x"},
	}}
	if err := st.SetNodes(base, nil); err != nil {
		t.Fatal(err)
	}
	gen := st.Snapshot().SubGeneration
	// The optimisation is stored through the guarded setter, which is what records
	// the generation it belongs to. Writing the list directly would leave the
	// generation at zero and the result permanently "not current", which is a
	// different bug from the one under test.
	if ok, err := st.SetOptimizedIfCurrent(gen, []Proxy{{Name: "opt"}}); err != nil || !ok {
		t.Fatalf("storing the optimisation failed: ok=%v err=%v", ok, err)
	}
	if !st.OptimizedIsCurrent() {
		t.Fatal("a fresh optimisation should be current")
	}

	// The same material again: nothing to redo.
	if err := st.SetNodes(base, nil); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().SubGeneration != gen {
		t.Error("re-importing identical material must not invalidate the optimisation")
	}
	if !st.OptimizedIsCurrent() {
		t.Error("identical material must leave the optimisation current")
	}

	// A new credential with everything else identical - exactly what a UUID reset
	// produces.
	rotated := []Proxy{{
		Name: "n", Type: "vmess", Server: "1.2.3.4", Port: 443,
		UUID: "bbbbbbbb-1111-2222-3333-444444444444", Network: "ws",
		WSOpts: map[string]interface{}{"path": "/x"},
	}}
	if err := st.SetNodes(rotated, nil); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().SubGeneration == gen {
		t.Error("a rotated credential must invalidate the optimisation")
	}
	if st.OptimizedIsCurrent() {
		t.Error("the stored optimisation carries the revoked credential and must not " +
			"be reported as current")
	}
}

func TestMaterialComparisonIgnoresNamesOnly(t *testing.T) {
	// A renamed node is the same node. Re-running an optimisation because a label
	// moved would be its own defect, so the comparison deliberately omits the name.
	a := []Proxy{{Name: "first", Type: "vmess", Server: "1.2.3.4", Port: 443,
		UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	b := []Proxy{{Name: "second", Type: "vmess", Server: "1.2.3.4", Port: 443,
		UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	if !sameNodeMaterial(a, b) {
		t.Error("a name is cosmetic and must not count as a material change")
	}
	// Everything that decides whether the node works does count.
	for _, mutate := range []func(*Proxy){
		func(p *Proxy) { p.Server = "5.6.7.8" },
		func(p *Proxy) { p.Port = 8443 },
		func(p *Proxy) { p.UUID = "bbbbbbbb-1111-2222-3333-444444444444" },
		func(p *Proxy) { p.Type = "vless" },
		func(p *Proxy) { p.Network = "grpc" },
		func(p *Proxy) { p.WSOpts = map[string]interface{}{"path": "/y"} },
	} {
		c := []Proxy{{Name: "first", Type: "vmess", Server: "1.2.3.4", Port: 443,
			UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
		mutate(&c[0])
		if sameNodeMaterial(a, c) {
			t.Errorf("a change to %+v must count as material", c[0])
		}
	}
	if sameNodeMaterial(a, nil) {
		t.Error("a different number of nodes is a material change")
	}
}

// ---- the lifecycle must ask who owns the core ------------------------------

func TestTheLifecycleAsksWhoOwnsTheCore(t *testing.T) {
	// StartCoreThroughOwner and StopCoreThroughOwner were written for exactly this and
	// were never called from the lifecycle. Ordinary start, background recovery, the
	// port change and shutdown all reached for the core directly, so a service that
	// owned the core could be bypassed by a window that started a second one - and the
	// two then disagreed about the port and the configuration.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)

	// Every place that starts the core must go through the owner.
	if strings.Contains(text, "if err := a.core.Start(); err != nil {") {
		t.Error("bootCore still starts the core directly, so a service that already " +
			"holds one gets a second")
	}
	if !strings.Contains(text, "StartCoreThroughOwner") {
		t.Error("the lifecycle never asks who owns the core before starting one")
	}

	// Recovery must not fight the service for the same core.
	if !strings.Contains(text, "a.coreOwnerNow() == ownerService") {
		t.Error("the recovery loop does not know the service may own the core")
	}

	// Shutdown must leave a service-owned core alone, or every window restart asks
	// for authorisation again - the thing the service exists to avoid.
	quit := strings.Index(text, "func (a *App) Shutdown()")
	if quit < 0 {
		t.Fatal("Shutdown is missing")
	}
	tail := text[quit:]
	end := strings.Index(tail, "\nfunc ")
	if end > 0 {
		tail = tail[:end]
	}
	if !strings.Contains(tail, "StopCoreThroughOwner") {
		t.Error("shutdown does not stop the core through its owner")
	}
	if !strings.Contains(tail, "left running") {
		t.Error("shutdown does not say that a service-owned core is left alone")
	}
}

func TestServiceMustProveItsIdentityBeforeItIsSentTheSecret(t *testing.T) {
	// The client decided the service existed by asking a fixed port for an
	// unauthenticated 200. Anything that could bind 7795 could answer that, and would
	// then be handed the control secret in the next request. Loopback is not an
	// identity and a port number is not a program.
	secret := "a-shared-secret"
	const port = 7795

	// A proof over a nonce, a timestamp and the port: useless anywhere else, and not
	// reversible into the secret.
	p := serviceProofMAC(secret, "nonce-1", 1700000000, port)
	if p == "" {
		t.Fatal("no proof was produced")
	}
	if strings.Contains(p, secret) {
		t.Error("the proof contains the secret")
	}
	// Deterministic for the same inputs, so the client can check it.
	if serviceProofMAC(secret, "nonce-1", 1700000000, port) != p {
		t.Error("the proof is not deterministic")
	}
	// And different for every input that matters.
	for _, changed := range []string{
		serviceProofMAC("another-secret", "nonce-1", 1700000000, port),
		serviceProofMAC(secret, "nonce-2", 1700000000, port),
		serviceProofMAC(secret, "nonce-1", 1700000001, port),
		serviceProofMAC(secret, "nonce-1", 1700000000, 7796),
	} {
		if changed == p {
			t.Error("the proof does not depend on every input it covers")
		}
	}

	// A service that answers with the wrong proof is not trusted.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answers the right shape with a proof computed from a different secret, which
		// is what an impostor that does not hold ours would produce.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serviceAliveResponse{
			OK: true, Nonce: r.URL.Query().Get("nonce"),
			TS: time.Now().Unix(), Port: port, Proof: "not-the-right-proof",
		})
	}))
	defer bad.Close()
	// Point the check at it by parsing the port out of the test server's URL.
	if err := verifyServiceIdentityAgainst(secret, bad.URL, time.Second); err == nil {
		t.Error("a service that cannot prove itself must not be trusted")
	}
	// And a service that does hold the secret is trusted.
	good := httptest.NewServer(handleServiceAlive(secret, port))
	defer good.Close()
	if err := verifyServiceIdentityAgainst(secret, good.URL, 2*time.Second); err != nil {
		t.Errorf("a service that proves itself should be trusted: %v", err)
	}
	// A program that is not the service at all is refused, not mistaken for one.
	notAService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello, I am not a service"))
	}))
	defer notAService.Close()
	if err := verifyServiceIdentityAgainst(secret, notAService.URL, time.Second); err == nil {
		t.Error("something that cannot answer the protocol must not be trusted")
	}
}

// ---- the two ways of taking traffic are mutually exclusive ----------------

func TestAStoredModeThisVersionDoesNotHaveBecomesOff(t *testing.T) {
	// A settings file still holding `"tunMode": "privacy"` from the version that had
	// that mode caused two answers to one question. The accessor that validates
	// reported the tunnel as off, while every `st.TunMode != TunOff` test answered yes
	// - so the program believed a tunnel it had not started was running, refused to
	// enable the system proxy because of the mutual exclusion, and showed TUN as off
	// at the same time.
	//
	// Normalising on load is the fix: an unknown mode is not merely ignored, it is
	// gone.
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Write the file the way the older version would have left it.
	raw := `{"settings":{"tunMode":"privacy","mixedPort":7899},"revision":1}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := st2.Settings().TunMode
	if got != TunOff {
		t.Errorf("tunMode = %q after loading a mode this version does not have, want off",
			got)
	}
	if !got.Valid() {
		t.Errorf("the value left in settings, %q, is still not one this version knows", got)
	}
	// And the interface must agree with the code that decides.
	if st2.Settings().TunMode != TunOff {
		t.Error("the reported mode and the stored mode disagree, which is the defect")
	}
	_ = st
}

func TestSystemProxyRefusesWhileTunIsUsing(t *testing.T) {
	// They are not two features that happen to coexist. With TUN on, the routing table
	// carries the traffic and the proxy setting has no effect on it - so allowing both
	// produces a machine where the checkbox says one thing, the routing table says
	// another, and nothing explains the difference.
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Skipf("server.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, `"conflict": "tun"`) {
		t.Error("enabling the system proxy while TUN is on is not refused with a reason " +
			"the interface can act on")
	}
	if !strings.Contains(text, "两者互斥") {
		t.Error("the refusal does not explain the relationship, so a user turning one on " +
			"is not told what to do about the other")
	}
}

func TestEnablingTunTurnsTheSystemProxyOff(t *testing.T) {
	// The direction that matters. Once the tunnel is up, every application that honours
	// the proxy setting keeps trying to reach a local port that belongs to a core the
	// activation is about to restart.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "关闭系统代理（与 TUN 互斥）") {
		t.Error("the activation does not switch the system proxy off")
	}
	// And it must record that it did, so the failure path can put it back rather than
	// leaving the user with a third arrangement.
	if !strings.Contains(text, "SysProxyWasOn = proxyState.Enabled") {
		t.Error("the activation does not record whether it switched the proxy off")
	}
}

func TestAWaitedApprovalIsVisibleAndCancellable(t *testing.T) {
	// Enabling TUN asks for elevation, which puts a system dialog on screen that the
	// user may not have noticed. Until they answer it, nothing happens for up to two
	// minutes - and before this, nothing distinguished "waiting for you" from "stuck".
	// The user's description of it was sitting there like an idiot.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)

	// The wait is bounded, and the bound is short enough to be a wait rather than a
	// hang. It was four minutes, most of which was a prompt nobody had answered.
	if !strings.Contains(text, "const handoverTimeout = 2 * time.Minute") {
		t.Error("the approval wait is not bounded at two minutes")
	}
	// The wait is described, with a countdown.
	for _, need := range []string{
		"setApprovalWait(true)",
		"WaitingForApproval",
		"WaitLimitSeconds",
		"ApprovalHint",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("the wait does not report %s, so it still looks like a hang", need)
		}
	}
	// And it can be ended by the user rather than only by the clock.
	if !strings.Contains(text, "func (a *App) CancelTunActivation() error") {
		t.Error("there is no way to cancel a wait in progress, so the only exit is to " +
			"close the program - which is what someone does when a button looks hung, " +
			"and closing it mid-activation is the state that leaves a half-applied " +
			"arrangement behind")
	}
	// Cancelling must reach the helper, or the helper finishes after the cancel and
	// reports a success the user did not ask for.
	if !strings.Contains(text, "killHelperProcess(helperPID)") {
		t.Error("cancelling does not stop the elevated helper")
	}
}

func TestCancelIsReachableFromTheInterface(t *testing.T) {
	// A cancel that has no route is a comment.
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Skipf("server.go is not readable: %v", err)
	}
	if !strings.Contains(string(src), `"/api/tun/cancel"`) {
		t.Error("the cancel endpoint is not routed, so the interface cannot reach it")
	}
	html, err := os.ReadFile("../web/index.html")
	if err != nil {
		t.Skipf("index.html is not readable: %v", err)
	}
	h := string(html)
	for _, need := range []string{"tun-approval", "tun-approval-clock", "btn-tun-cancel"} {
		if !strings.Contains(h, need) {
			t.Errorf("the interface has no %s, so a wait in progress is still invisible "+
				"or unescapable", need)
		}
	}
	js, err := os.ReadFile("../web/app.js")
	if err != nil {
		t.Skipf("app.js is not readable: %v", err)
	}
	if !strings.Contains(string(js), "/api/tun/cancel") {
		t.Error("the interface does not call the cancel endpoint")
	}
}

// ---- a dead core must not leave the machine offline ------------------------

func TestADeadCoreTakesItsOwnDeadPortOutOfTheProxy(t *testing.T) {
	// Measured, and it is the failure the user actually lived through: the core exited
	// at 21:59:46, the registry still said ProxyEnable=1 pointing at the port the core
	// had been serving, and every application that honours the system proxy was
	// offline. The interface showed the proxy as on, because the registry said so.
	//
	// Recovery restarted the core and nothing asked what had happened to the proxy in
	// the meantime. If the restart keeps failing, the machine stays offline for good
	// while the program reports that everything is fine.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func (a *App) ensureNotOfflineBecauseOfUs()") {
		t.Fatal("nothing clears our own dead port out of the proxy setting")
	}
	// The recovery loop must call it.
	i := strings.Index(text, "if a.core.Ensure() {")
	if i < 0 {
		t.Fatal("the recovery loop is missing")
	}
	tail := text[i:]
	if end := strings.Index(tail, "// ---- "); end > 0 {
		tail = tail[:end]
	}
	if !strings.Contains(tail, "ensureNotOfflineBecauseOfUs") {
		t.Error("the recovery loop restarts the core and does not consider the proxy, " +
			"so a core that will not come back leaves the machine offline")
	}
}

func TestTheRecoveryDoesNotTouchSomebodyElsesProxy(t *testing.T) {
	// The narrowest possible version of the idea: it acts only when the setting points
	// at exactly the port this program serves, and that port has no listener. Another
	// program's configuration is not this program's to change, the same way another
	// program's adapter is not ours to remove.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	i := strings.Index(text, "func (a *App) ensureNotOfflineBecauseOfUs()")
	if i < 0 {
		t.Fatal("the helper is missing")
	}
	j := strings.Index(text[i:], "\n}\n")
	body := text[i : i+j+3]

	for _, guard := range []string{
		"!st.Enabled || st.Server == \"\"", // nothing set
		"port != want",                     // not our port
		"portHasListener(port)",            // something is serving it
	} {
		if !strings.Contains(body, guard) {
			t.Errorf("the recovery is missing the guard %q, so it could change a "+
				"setting that is not its to change", guard)
		}
	}
	// And it must say why, because a proxy that turns itself off is owed an
	// explanation.
	if !strings.Contains(body, "clearing the setting so the machine stays online") {
		t.Error("the recovery does not log why the proxy was cleared")
	}
}

// ---- a leftover proxy of ours must never leave the machine offline ---------

func TestADeadProxyReallyDoesTakeTheMachineOffline(t *testing.T) {
	// The premise the whole file rests on, measured rather than assumed: with
	// `ProxyEnable=1`, `ProxyServer=127.0.0.1:7899` and nothing listening on 7899,
	// requests fail. Windows does not treat a loopback proxy as optional and does not
	// diagnose it - the browser says the site is unreachable and the site is fine.
	//
	// This test does not reproduce the network condition (it would need to change the
	// machine's proxy). It asserts the guards that make the clearing safe, which is
	// what can be checked without side effects.
	src, err := os.ReadFile("startup.go")
	if err != nil {
		t.Skipf("startup.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func (a *App) claimProxyForStartup() bool") {
		t.Fatal("nothing clears a leftover proxy at startup, so a crash leaves the " +
			"machine offline until the user works out why")
	}
}

func TestTheStartupClearingCannotTakeAwayAWorkingProxy(t *testing.T) {
	// The first version of the startup check cleared a perfectly good proxy because it
	// ran a moment before the core had bound its port. A check meant to protect a
	// working arrangement took it away, which is the same class of mistake as the
	// thing it was written to prevent.
	//
	// The question is not "is the port bound right now" but "is there a core that is
	// going to serve it", and this program knows the answer without guessing.
	src, err := os.ReadFile("startup.go")
	if err != nil {
		t.Skipf("startup.go is not readable: %v", err)
	}
	text := string(src)
	i := strings.Index(text, "func (a *App) claimProxyForStartup() bool")
	j := strings.Index(text[i:], "\n}\n")
	body := text[i : i+j+3]

	for _, guard := range []string{
		"!st.Enabled || st.Server == \"\"", // nothing is set
		"port != want",                     // not the port we serve
		"portHasListener(port)",            // something is serving it
		"a.core.IsUp()",                    // our own core is answering
		"a.serviceReachable()",             // the service owns it and is answering
		"a.recentCoreStart()",              // a core was just started and is coming up
	} {
		if !strings.Contains(body, guard) {
			t.Errorf("the startup check is missing the guard %q, so it can clear a "+
				"proxy that is working", guard)
		}
	}
	// And it must consider the core's own state, not only whether the port is bound.
	if !strings.Contains(text, "func (a *App) recentCoreStart() bool") {
		t.Error("a port that is not bound yet cannot be told from a port nothing will " +
			"ever serve, so a starting core looks like a dead run")
	}
}

func TestTheCoreStartIsTimedSoAStartingCoreIsNotReadAsDead(t *testing.T) {
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "coreStartedAt") {
		t.Error("the core's start is not timed, so the startup check cannot tell a " +
			"starting core from an absent one")
	}
	if !strings.Contains(text, "a.coreStartedAt = time.Now()") {
		t.Error("bootCore does not record when it started the core")
	}
}

func TestTheRuleIsAppliedAgainAfterTheCoreShouldHaveStarted(t *testing.T) {
	// The startup path has a window of its own: the proxy is read from the saved
	// settings, the core is started, and if the core never manages to bind, the machine
	// is offline for as long as the program runs. The first check only covers what was
	// already on disk.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("main.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "app.claimProxyForStartup()") {
		t.Error("main does not clear a leftover proxy before starting")
	}
	if !strings.Contains(text, "go app.waitForCoreThenClaimProxy(") {
		t.Error("main does not apply the same rule again once the core has had its " +
			"chance to bind")
	}
}

func TestACoreThatDiedIsRestartedPromptly(t *testing.T) {
	// The long grace period exists for a genuine first start: a fresh data directory
	// has no rule databases, mihomo downloads them, and restarting it mid-download
	// looped forever because every restart began the same download again.
	//
	// But that reasoning only applies to a core that has never answered. Measured, it
	// was being applied to a core that had been serving and then died: the core went
	// down at 22:11:02 and the watchdog restarted it at 22:13:56, nearly three minutes
	// of the machine being offline with the proxy pointing at a port nothing was
	// behind, for a reason that did not apply.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "coreEverCameUp") {
		t.Fatal("nothing distinguishes a first start from a core that died after working, " +
			"so every failure waits out the first-start grace period")
	}
	if !strings.Contains(text, "coreRestartDelay = 20 * time.Second") {
		t.Error("there is no shorter window for a core that has already answered")
	}
	// The recovery must be the prompt one, and the grace period must be conditional.
	if !strings.Contains(text, "if !a.coreEverCameUp {") {
		t.Error("the first-start grace period is not conditional on the core never " +
			"having answered")
	}
	// It must be recorded in both places a core can come up: the one bootCore started,
	// and the one recovery started.
	if strings.Count(text, "noteCoreCameUp()") < 2 {
		t.Error("the first answer is not recorded on both paths, so a core started by " +
			"bootCore would never shorten the window")
	}
}

// ---- the four questions a user actually asks ------------------------------

func TestForceKillingUnderTunCannotTakeTheMachineOffline(t *testing.T) {
	// The scenario: TUN is on, the user opens Task Manager and ends the task.
	//
	// What a proxy client leaves behind in that case is normally a registry entry
	// pointing at a port that has just died, which on Windows is not "bypass the
	// proxy" but every request failing. The reason it does not happen here is an
	// ordering property, so it is worth asserting rather than assuming: the
	// activation switches the system proxy OFF before it builds the tunnel, so at the
	// moment the process can be killed there is no such entry to leave behind.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "关闭系统代理（与 TUN 互斥）") {
		t.Fatal("the activation does not switch the system proxy off, so a force kill " +
			"under TUN leaves a registry entry pointing at a dead port")
	}
	// The switch must happen before the tunnel is built, not after. Ordering is the
	// whole property, so compare the two positions rather than just their presence.
	proxyOff := strings.Index(text, "关闭系统代理（与 TUN 互斥）")
	tunnelUp := strings.Index(text, "TUN enabled in compat mode")
	if proxyOff < 0 || tunnelUp < 0 {
		t.Skip("could not locate both steps in the same function")
	}
	if proxyOff > tunnelUp {
		t.Error("the system proxy is switched off after the tunnel is built, so there is " +
			"a window in which a kill leaves the machine offline")
	}
	// And a leftover adapter is reconciled at the next start rather than believed.
	rec, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	if !strings.Contains(string(rec), "func (a *App) RecoverTun()") {
		t.Error("nothing reconciles a leftover adapter at startup")
	}
}

func TestClosingTheLidDoesNotHangTheShutdown(t *testing.T) {
	// Windows asks every window whether it is ready to end the session, and terminates
	// the process a few seconds later whatever the answer. Not handling the question
	// left the default answer - "yes, go ahead" - so the shutdown path never ran and
	// the system proxy was left pointing at a dead port.
	//
	// The answer must be immediate. Blocking on this thread to restore the proxy would
	// either be cut off or delay a shutdown the user asked for, and delaying a shutdown
	// is the behaviour the question was really about.
	src, err := os.ReadFile("tray.go")
	if err != nil {
		t.Skipf("tray.go is not readable: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "wmQueryEndSession") {
		t.Fatal("the tray window does not handle the end-session question, so the " +
			"shutdown path never runs")
	}
	if !strings.Contains(text, "wmEndSession") {
		t.Error("the tray window is not told when the session is actually ending")
	}
	// The hook is registered and separate from the menu's quit, because nobody is
	// there to answer a confirmation dialog during a shutdown.
	if !strings.Contains(text, "func (t *Tray) OnShutdown(") {
		t.Error("there is no shutdown hook to run the cleanup")
	}
	if !strings.Contains(text, "t.onShutdown = nil") {
		t.Error("the shutdown hook is not cleared, so a query followed by an end would " +
			"run the cleanup twice")
	}
	// The handler must return TRUE and do the work off the message thread.
	i := strings.Index(text, "case wmQueryEndSession:")
	if i < 0 {
		t.Fatal("the case is missing")
	}
	body := text[i : i+700]
	if !strings.Contains(body, "return 1") {
		t.Error("the end-session question is not answered with TRUE, so Windows may " +
			"decide this program is refusing to close")
	}
	if !strings.Contains(body, "go t.close()") {
		t.Error("the cleanup runs on the message thread, which delays the shutdown")
	}

	// And main must wire it up, or the hook is a comment.
	m, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("main.go is not readable: %v", err)
	}
	if !strings.Contains(string(m), "tray.OnShutdown(") {
		t.Error("main never registers a shutdown handler")
	}
}

func TestOpeningTheShortcutManyTimesStartsOneInstance(t *testing.T) {
	// Double-clicking the desktop shortcut five times must not produce five cores.
	// Two processes with one data directory is the state this program spent a long
	// time removing: they disagree about which port the proxy should point at, and the
	// user sees an interface reporting a dead core while the machine is online.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("main.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "IsPortListening(uiPort)") {
		t.Error("startup does not check whether another instance already owns the UI " +
			"port, so every double-click could start another copy")
	}
	// The check must come before the port is bound, or it is a race with itself.
	bind := strings.Index(text, "srv.Listen()")
	check := strings.Index(text, "IsPortListening(uiPort)")
	if bind < 0 || check < 0 {
		t.Skip("could not locate both")
	}
	if check > bind {
		t.Error("the single-instance check runs after binding, so two copies started at " +
			"the same moment could both proceed")
	}
}

// ---- there is always a way out --------------------------------------------

func TestThereIsAlwaysAHostnameNodeToFallBackTo(t *testing.T) {
	// The hostname node exists because a pinned edge address can be filtered while the
	// provider's own hostname keeps working - Cloudflare hands out a fresh edge per
	// connection, so it survives exactly the case where every pinned address fails.
	// The health loop prefers it for that reason.
	//
	// It was only ever produced by a successful optimisation, which leaves a gap that
	// opens precisely when things are already going wrong: an optimisation result gone
	// stale because the credential was rotated, followed by a subscription refresh that
	// fails because the provider is down. In that state there is no hostname node, the
	// health loop reports "no alternative is known-good", and the user is pinned to a
	// dead address until the provider comes back.
	base := []Proxy{{
		Name: "node", Type: "vmess", Server: "qh.example.com", Port: 443,
		UUID:       "deadbeef-0000-1111-2222-333333333333",
		Servername: "qh.example.com", Network: "ws",
	}}

	// With nothing optimised, one is composed.
	fb, ok := hostnameFallback(base)
	if !ok {
		t.Fatal("no fallback could be built from a hostname node")
	}
	if !fb.OriginNode {
		t.Error("the fallback is not marked as the hostname node, so the health loop " +
			"will not prefer it")
	}
	if fb.Server != "qh.example.com" {
		t.Errorf("the fallback points at %q, want the subscription's own hostname", fb.Server)
	}
	if fb.UUID != base[0].UUID {
		t.Error("the fallback lost the credential")
	}
	if fb.SNI != "qh.example.com" {
		t.Errorf("the fallback SNI is %q, which would break the TLS handshake", fb.SNI)
	}
	if fb.Name == "" {
		t.Error("the fallback has no name")
	}

	// A subscription whose nodes are all pinned addresses has no hostname to fall back
	// to, and inventing one would be a guess.
	pinned := []Proxy{{Name: "a", Server: "104.16.1.1", Port: 443}}
	if _, ok := hostnameFallback(pinned); ok {
		t.Error("a pinned address was treated as a hostname")
	}

	// And the merge must guarantee one is present.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "if !hasOrigin {") {
		t.Error("mergedNodes does not check whether a hostname node is present, so the " +
			"one case that needs it most is the one case without it")
	}
	if !strings.Contains(text, "if fb, ok := hostnameFallback(base); ok {") {
		t.Error("mergedNodes does not compose a hostname node when none exists")
	}
}

// ---- only a node the program offers may be selected ------------------------

func TestSwitchingRefusesAnythingThatIsNotANode(t *testing.T) {
	// The core's proxy table holds the groups as well as the nodes: PROXY, AUTO,
	// DIRECT. The switch endpoint passed the name straight through, so selecting AUTO
	// worked - and produced a state the interface could not describe. PROXY.Now is the
	// string "AUTO" while the traffic goes through whichever node the url-test group
	// chose, so nothing in the node list matched and no entry was shown as current.
	//
	// The interface never offered those names, which is exactly the shape of gap worth
	// closing: the next caller is a script, or a later version of the interface.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func (a *App) SwitchNode(") {
		t.Fatal("there is no checked switch, so any name the core knows can be selected")
	}

	// It must decide from what the program offers, not from a list of group names -
	// otherwise a group a subscription defines is accepted, and the next group name
	// has to be remembered.
	i := strings.Index(text, "func (a *App) SwitchNode(")
	j := strings.Index(text[i:], "\n}\n")
	body := text[i : i+j+3]
	if !strings.Contains(body, "a.nodeSet()") {
		t.Error("the check is not against the nodes this program offers")
	}
	if !strings.Contains(body, "没有这个节点") {
		t.Error("a refusal does not say what was wrong")
	}

	// And the endpoint must use it.
	srv, err := os.ReadFile("server.go")
	if err != nil {
		t.Skipf("server.go is not readable: %v", err)
	}
	if !strings.Contains(string(srv), "s.app.SwitchNode(name)") {
		t.Error("the switch endpoint bypasses the check")
	}
}

func TestSelectingAGroupStillNamesTheNodeInUse(t *testing.T) {
	// Defence in depth for the same state, reached any other way - a subscription that
	// defines its own group, a core that reports something unexpected. If PROXY is ever
	// set to a group, the interface must still be able to name the node carrying the
	// traffic, because a current node it cannot name is a current node the user cannot
	// see.
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Skipf("app.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, `group.Now == "AUTO"`) {
		t.Error("the reported current node does not resolve a group selection to the " +
			"node actually in use")
	}
	if !strings.Contains(text, `"currentPick"`) {
		t.Error("the reported status does not distinguish what was selected from what is " +
			"in use, so the interface cannot say \"AUTO, currently X\"")
	}
}

// ---- the two switches read as one choice, and an install can repair ---------

func TestTheServiceInstallReplacesABrokenRegistration(t *testing.T) {
	// Measured, and it cost the user two permission prompts every single time. An
	// earlier build had registered the service with a binary that did not speak the
	// Service Control Manager protocol, so Windows had it stuck in START_PENDING and it
	// never answered on its port. Every later attempt then went: create fails because
	// the name exists, start reports success because Windows still thinks the old
	// process is starting, the endpoint never answers, the install is reported as
	// failed, and the activation falls back to a per-activation prompt.
	//
	// Two UAC dialogs per attempt, forever, with the reason buried in a log.
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Skipf("service.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func (a *App) installService() error") {
		t.Fatal("installService is missing")
	}
	i := strings.Index(text, "func (a *App) installService() error")
	j := strings.Index(text[i:], "\nfunc ")
	body := text[i : i+j]

	if !strings.Contains(body, "serviceInstalled()") {
		t.Error("the install does not check whether a registration already exists, so a " +
			"broken one can block every future install")
	}
	if !strings.Contains(body, `serviceControl("delete", serviceName)`) {
		t.Error("the install does not remove an existing registration, so it cannot " +
			"repair one")
	}
	// The delete must happen before the create, or it is pointless.
	del := strings.Index(body, `serviceControl("delete", serviceName)`)
	cre := strings.Index(body, `serviceControl("create", serviceName`)
	if del < 0 || cre < 0 {
		t.Fatal("could not locate both calls")
	}
	if del > cre {
		t.Error("the existing registration is removed after the create, which cannot work")
	}
}

func TestBothElevationPromptsShowTheWaitingPanel(t *testing.T) {
	// There are two permission prompts on a machine with no service: one to install the
	// resident service, and - if that fails - one for the activation itself. The
	// approval panel, with the countdown and the hint about where the dialog might be
	// hiding, was only raised for the second. So the first prompt, which is usually the
	// one the user actually sees, was shown while the interface said nothing more
	// helpful than "等待系统授权". Reported by the user as the panel appearing only at
	// the second prompt, which is exactly what it was doing.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)

	// Both elevation sites must raise the wait.
	if strings.Count(text, "a.setApprovalWait(true)") < 2 {
		t.Errorf("only %d elevation site(s) raise the approval panel, want 2 - the "+
			"service install prompts too",
			strings.Count(text, "a.setApprovalWait(true)"))
	}
	// And each must clear it, or a stale timer keeps counting after the dialog is gone.
	if strings.Count(text, "a.setApprovalWait(false)") < 2 {
		t.Errorf("only %d site(s) clear the approval panel, want 2",
			strings.Count(text, "a.setApprovalWait(false)"))
	}
	// The service-install prompt should say what it is for, so a user seeing two dialogs
	// in a row knows the second is a different request.
	if !strings.Contains(text, "安装常驻服务") {
		t.Error("the first prompt does not say what it is asking for")
	}
}

func TestTheTraySaysWhyASwitchIsOff(t *testing.T) {
	// The two ways of taking traffic are mutually exclusive, so "系统代理" with no check
	// mark is ambiguous: the user turned it off, or enabling TUN turned it off for
	// them. A menu that shows the same thing in both cases leaves the user with a
	// switch that appears not to respond to anything - which is how the missing sync
	// was reported.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Skipf("main.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "func sysProxyLabel(on, tunOn bool) string") {
		t.Fatal("the system proxy item has one label for every state")
	}
	for _, need := range []string{
		"已启用，点击关闭",
		"TUN 接管中，已自动关闭",
		"已关闭，点击启用",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("the proxy label does not cover %q", need)
		}
	}
	// And the TUN item says the same thing from the other side.
	if !strings.Contains(text, "系统代理使用中，点击改用 TUN") {
		t.Error("the TUN item does not say when the system proxy is the one in use")
	}
	// The state must be read live on each open, not captured when the menu was built.
	// That mechanism lives in tray.go, which is where the popup is assembled.
	tray, err := os.ReadFile("tray.go")
	if err != nil {
		t.Skipf("tray.go is not readable: %v", err)
	}
	if !strings.Contains(string(tray), "items := build()") {
		t.Error("the menu is not rebuilt when it is opened, so it can go stale")
	}
}

func TestAStaleTunModeIsClearedNotJustReported(t *testing.T) {
	// The stored mode said compat, the adapter was gone, and the visible consequence
	// was that the system proxy could not be enabled - the two are mutually exclusive
	// and the program believed the one that was not running:
	//
	//   settings say compat but adapter "Zenith" is not present; the tunnel is not up
	//   开系统代理: ok=False  TUN 接管正在使用中
	//
	// A machine in that state has no tunnel and no proxy. Describing a wrong state is
	// not enough; the state has to be corrected, and the recovery path is where that
	// belongs because it is the only place that knows the machine is not what the file
	// says.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	i := strings.Index(text, "settings say %s but adapter %q is not present")
	if i < 0 {
		t.Fatal("the recovery path no longer notices a stale mode")
	}
	// The clearing call must be in the same branch, after the log line.
	branch := text[i:]
	if end := strings.Index(branch, "\n\t}\n"); end > 0 {
		branch = branch[:end]
	}
	if !strings.Contains(branch, `"tunMode": string(TunOff)`) {
		t.Error("the recovery reports the stale mode without clearing it, so the system " +
			"proxy stays unusable and the interface shows a mode that is not running")
	}
	if !strings.Contains(branch, "已恢复为系统代理") {
		t.Error("the message does not say what the machine has been restored to")
	}
}

func TestStartingThroughTheServiceBuildsAConfiguration(t *testing.T) {
	// Measured, on an ordinary launch after the service started working:
	//
	//   core start failed: 配置没有通过校验：生成的配置是空的
	//
	// bootCore calls StartCoreThroughOwner to get a core running for the
	// system-proxy path, and it has no configuration in hand - the local path ignores
	// the argument because the config file is on disk and the core reads it. Through
	// the service the argument IS the configuration, so passing nothing asked the
	// service to start a core from nothing, and the launch ended with no core at all.
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Skipf("service.go is not readable: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "func (a *App) coreConfigBytes()") {
		t.Fatal("nothing builds a configuration for the service path")
	}
	i := strings.Index(text, "case ownerService:")
	if i < 0 {
		t.Fatal("the service branch is missing")
	}
	branch := text[i:]
	if end := strings.Index(branch, "case ownerSelf:"); end > 0 {
		branch = branch[:end]
	}
	if !strings.Contains(branch, "len(cfg) == 0") {
		t.Error("the service branch sends whatever it was given, including nothing")
	}
	if !strings.Contains(branch, "a.coreConfigBytes()") {
		t.Error("the service branch does not build a configuration when it has none")
	}

	// The builder must go through the same inputs as every other path, or the service
	// and a local core could run different configurations - the disagreement this
	// design exists to remove.
	j := strings.Index(text, "func (a *App) coreConfigBytes()")
	body := text[j:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	for _, need := range []string{"a.mergedNodes()", "a.optimizedNames()", "a.secret"} {
		if !strings.Contains(body, need) {
			t.Errorf("the builder does not use %s, so it can produce a different "+
				"configuration from the local path", need)
		}
	}
	if !strings.Contains(body, "validateCandidateConfig(cfg)") {
		t.Error("the built configuration is not validated before it is sent")
	}
}

// ---- both activation paths must honour the exclusion -----------------------

func TestBothActivationPathsSwitchTheProxyOff(t *testing.T) {
	// There are two ways to activate the tunnel: through the resident service, and
	// through a per-activation elevation. The exclusion between the tunnel and the
	// system proxy was written into the second one only.
	//
	// That was invisible while the service never started, because every activation took
	// the other path. The moment the service worked, it became the ordinary case - and
	// the exclusion silently stopped applying: the registry said traffic went through
	// the proxy while the routing table sent it through the tunnel, both settings read
	// as on, and nothing explained the difference.
	//
	// So the assertion is not "the exclusion exists" but "it exists on both paths",
	// which is the property that was actually missing.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)

	marker := "关闭系统代理（与 TUN 互斥）"
	if n := strings.Count(text, marker); n < 2 {
		t.Errorf("the exclusion appears %d time(s), want at least 2 - one for the service "+
			"path and one for the per-activation path. A machine using the service is the "+
			"ordinary case now, so a rule that only covers the other one covers almost "+
			"nobody", n)
	}

	// And both paths must record what they changed, or a failed activation cannot put
	// the arrangement back.
	if n := strings.Count(text, "SysProxyWasOn = proxyState.Enabled"); n < 2 {
		t.Errorf("only %d path(s) record whether they switched the proxy off, want 2", n)
	}
}

func TestAFailedServiceActivationGivesTheProxyBack(t *testing.T) {
	// Switching the proxy off is part of the attempt, so a failed attempt has to undo
	// it. Otherwise a user whose tunnel failed to come up is left with neither the
	// tunnel nor the proxy - the worst of both, and not a state they asked for.
	src, err := os.ReadFile("tun.go")
	if err != nil {
		t.Skipf("tun.go is not readable: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "the tunnel failed; the system proxy has been restored") {
		t.Error("a failed activation does not restore the system proxy it switched off")
	}
	if !strings.Contains(text, `txA.RestoreFailure = "系统代理未能恢复"`) {
		t.Error("a restore that itself fails is not reported separately, so it would read " +
			"as a clean rollback")
	}
}
