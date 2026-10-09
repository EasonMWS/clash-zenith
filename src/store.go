package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// Proxy is one node in any of the shapes mihomo accepts. Only the fields we
// actually generate are typed; anything else survives in Extra so an unknown
// provider key is never silently dropped.
type Proxy struct {
	Name              string                 `json:"name"`
	Type              string                 `json:"type"`
	Server            string                 `json:"server"`
	Port              int                    `json:"port"`
	UUID              string                 `json:"uuid,omitempty"`
	Password          string                 `json:"password,omitempty"`
	Cipher            string                 `json:"cipher,omitempty"`
	AlterID           int                    `json:"alterId,omitempty"`
	Flow              string                 `json:"flow,omitempty"`
	UDP               *bool                  `json:"udp,omitempty"`
	TLS               *bool                  `json:"tls,omitempty"`
	SNI               string                 `json:"sni,omitempty"`
	Servername        string                 `json:"servername,omitempty"`
	SkipCertVerify    *bool                  `json:"skip-cert-verify,omitempty"`
	ClientFingerprint string                 `json:"client-fingerprint,omitempty"`
	Network           string                 `json:"network,omitempty"`
	WSOpts            map[string]interface{} `json:"ws-opts,omitempty"`
	GrpcOpts          map[string]interface{} `json:"grpc-opts,omitempty"`
	H2Opts            map[string]interface{} `json:"h2-opts,omitempty"`
	// MeasuredMS is the WebSocket handshake time the optimiser measured for this
	// edge, in milliseconds. It is what auto-pick ranks by, so the choice is
	// based on the real tunnel rather than on a ping.
	MeasuredMS float64 `json:"measuredMs,omitempty"`
	// OriginNode marks the hostname variant of a tunnel. It is not pinned to any
	// one Cloudflare edge, so it cannot be killed by a single address being
	// filtered; the health checker treats it as the safe option.
	OriginNode bool `json:"originNode,omitempty"`
	// OriginHost is the real server hostname behind the tunnel. When a node is
	// pinned to an edge IP this is where the SNI and Host header values come
	// from, so keeping it on the struct means they survive a scan instead of
	// being re-derived by hand at every use.
	OriginHost string                 `json:"originHost,omitempty"`
	Extra      map[string]interface{} `json:"-"`
}

// TunMode is how far Zenith goes in taking over traffic.
//
// The three values are deliberately distinct in the interface as well as in the
// code. Reporting "protected" because an adapter exists is the mistake this type
// exists to prevent: taking over traffic and forbidding direct connections are
// separate promises, and only the third one makes the second.
type TunMode string

const (
	// TunOff means applications reach the proxy through the system proxy setting,
	// and anything that ignores it goes direct.
	TunOff TunMode = ""
	// TunCompat routes the traffic it can reach through the user's rules, with
	// direct still allowed. This is "TUN is on", not "nothing can leak".
	TunCompat TunMode = "compat"
	// TunPrivacy additionally requires that protected traffic can only leave
	// through an approved route, and keeps refusing when the core is down.
	TunPrivacy TunMode = "privacy"
)

// Valid reports whether a stored value is one this version understands. An
// unrecognised value is treated as off rather than guessed at.
func (m TunMode) Valid() bool {
	return m == TunOff || m == TunCompat || m == TunPrivacy
}

// Label is the honest description of what the mode does, for the interface.
func (m TunMode) Label() string {
	switch m {
	case TunCompat:
		return "TUN 接管已启用（仍按规则允许直连，不承诺全部流量经代理）"
	case TunPrivacy:
		return "隐私保护已生效（受保护流量只走批准线路，断线保持阻断）"
	default:
		return "系统代理兼容模式（仅对遵循系统代理的应用生效）"
	}
}

// Subscription is one user added source of nodes.
type Subscription struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	LastFetch  string `json:"lastFetch"`
	LastError  string `json:"lastError"`
	NodeCount  int    `json:"nodeCount"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
	Total      int64  `json:"total"`
	Expire     int64  `json:"expire"`
	UserAgent  string `json:"userAgent"`
	AutoUpdate bool   `json:"autoUpdate"`
}

// Settings holds everything the UI can change.
type Settings struct {
	Mode           string `json:"mode"`           // rule | global | direct
	MixedPort      int    `json:"mixedPort"`      //
	APIPort        int    `json:"apiPort"`        //
	UIPort         int    `json:"uiPort"`         //
	ControlPort    int    `json:"controlPort"`    // mihomo external controller
	SystemProxy    bool   `json:"systemProxy"`    //
	AutoStart      bool   `json:"autoStart"`      //
	StartMinimized bool   `json:"startMinimized"` //
	Language       string `json:"language"`       // zh-CN | en-US

	// optimisation
	AutoOptimize        bool `json:"autoOptimize"`        // false => the user is in control
	AutoPickOff         bool `json:"autoPickOff"`         // stored inverted so the default is ON for older settings files
	OptimizeIntervalMin int  `json:"optimizeIntervalMin"` //
	OptimizeOnStart     bool `json:"optimizeOnStart"`     //
	KeepNodes           int  `json:"keepNodes"`           // how many winners to keep
	ProbeRounds         int  `json:"probeRounds"`         // ws rounds per candidate
	ProbeWorkers        int  `json:"probeWorkers"`        // concurrency

	// subscription
	SubscriptionAutoUpdate    bool `json:"subscriptionAutoUpdate"`
	SubscriptionIntervalHours int  `json:"subscriptionIntervalHours"`

	// rules
	CustomRules     []string `json:"customRules"`     // inserted before MATCH
	ProxyBypass     string   `json:"proxyBypass"`     // system proxy bypass list
	DirectCNDomains bool     `json:"directCNDomains"` // geosite:cn -> DIRECT
	BlockAds        bool     `json:"blockAds"`        // geosite:category-ads-all -> REJECT
	// GamePlatformThroughProxy routes the store, community and login endpoints of
	// the international game platforms through the proxy. Their download CDNs are
	// deliberately left out: those are mostly reachable directly and much faster
	// that way. Stored inverted so an older settings file without the field
	// defaults to on.
	GamePlatformDirectOff bool `json:"gamePlatformDirectOff"`
	// AllowInsecureSubscription disables certificate verification when
	// downloading subscriptions. Off by default and deliberately not inverted:
	// this is a security downgrade, so it has to be something the user turns on
	// knowingly rather than something inherited from an older settings file.
	// Only needed when the subscription sits behind a self-signed certificate.
	AllowInsecureSubscription bool `json:"allowInsecureSubscription"`

	// ---- TUN ----------------------------------------------------------------
	//
	// TunMode separates "take over traffic" from "forbid direct connections".
	// They are different promises and the UI must not conflate them: a virtual
	// adapter existing is not the same as being protected.
	TunMode   TunMode `json:"tunMode"`
	TunDevice string  `json:"tunDevice"` // adapter name Zenith creates and owns
	TunStack  string  `json:"tunStack"`  // gvisor | system | mixed
	// TunBlockOnFailure keeps the tunnel's refusal in place when the core dies.
	// Only meaningful in privacy mode, where recovering connectivity by falling
	// back to a direct connection would be the opposite of the intent.
	TunBlockOnFailure bool `json:"tunBlockOnFailure"`

	// meta
	WindowWidth  int    `json:"windowWidth"`
	WindowHeight int    `json:"windowHeight"`
	WindowX      int    `json:"windowX"` // remembered window position, 0 = let Windows choose
	WindowY      int    `json:"windowY"`
	LastProfile  string `json:"lastProfile"` // selected proxy group member
}

func defaultSettings() Settings {
	return Settings{
		Mode:                      "rule",
		MixedPort:                 7890,
		APIPort:                   7798,
		UIPort:                    7799,
		ControlPort:               7797,
		SystemProxy:               true,
		StartMinimized:            false,
		Language:                  "zh-CN",
		AutoOptimize:              true,
		AutoPickOff:               false, // auto-pick is on by default
		OptimizeIntervalMin:       30,
		OptimizeOnStart:           false,
		KeepNodes:                 16,
		ProbeRounds:               3,
		ProbeWorkers:              24,
		SubscriptionAutoUpdate:    true,
		SubscriptionIntervalHours: 6,
		DirectCNDomains:           true,
		BlockAds:                  false,
		TunMode:                   TunOff,
		TunDevice:                 defaultTunDevice,
		TunStack:                  "gvisor",
		TunBlockOnFailure:         true,
		WindowWidth:               1200,
		WindowHeight:              780,
		ProxyBypass: "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;" +
			"172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;" +
			"172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>",
	}
}

// State is everything persisted to disk.
type State struct {
	Settings      Settings       `json:"settings"`
	Subscriptions []Subscription `json:"subscriptions"`
	Optimized     []Proxy        `json:"optimized"`
	BaseNodes     []Proxy        `json:"baseNodes"`
	Current       string         `json:"current"`
	LastOptimize  string         `json:"lastOptimize"`
	SelectedSub   string         `json:"selectedSub"`
	// SubGeneration increments every time the subscription material changes. An
	// optimisation records the generation it started from, so a scan that finished
	// after the user switched subscriptions can be recognised as belonging to the
	// old one and discarded rather than installed.
	SubGeneration int64 `json:"subGeneration"`
	// OptimizedGeneration is the generation the stored results came from.
	OptimizedGeneration int64 `json:"optimizedGeneration"`
}

// ---------------------------------------------------------------------------
// Store: JSON backed persistence with atomic writes
// ---------------------------------------------------------------------------

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	s.state.Settings = defaultSettings()
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.saveLocked()
		}
		return err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		// keep a copy of the broken file instead of losing the user's setup
		_ = os.WriteFile(s.path+".bad", raw, 0o644)
		return err
	}
	// fill in any field the file predates
	def := defaultSettings()
	mergeDefaults(&st.Settings, def)
	s.state = st
	return nil
}

// TUN defaults, named once so the migration, the environment check, the
// generated configuration and the adapter lookup cannot disagree.
const (
	tunDefaultDevice = "Zenith"
	tunDefaultStack  = "gvisor"
)

// NormalizedTunDevice returns the adapter name to use, filling in the default.
//
// A settings file written before these fields existed has them empty, and the
// environment check used to substitute the default locally without telling anyone
// - so the check reported one name, the generated configuration carried another,
// and the adapter lookup searched for a third. Every path goes through here now.
func (s Settings) NormalizedTunDevice() string {
	if strings.TrimSpace(s.TunDevice) == "" {
		return tunDefaultDevice
	}
	return strings.TrimSpace(s.TunDevice)
}

// NormalizedTunStack returns the stack to use, filling in the default.
//
// Only stacks the core accepts are returned. An unrecognised value would make the
// core refuse the whole configuration, which is worse than choosing the documented
// default and saying so.
func (s Settings) NormalizedTunStack() string {
	switch strings.TrimSpace(s.TunStack) {
	case "gvisor", "system", "mixed":
		return strings.TrimSpace(s.TunStack)
	default:
		return tunDefaultStack
	}
}

// mergeDefaults copies zero values from def so a settings file written by an
// older version still yields a complete configuration.
func mergeDefaults(s *Settings, def Settings) {
	if s.Mode == "" {
		s.Mode = def.Mode
	}
	// The TUN fields are normalized rather than merely defaulted, so a file with
	// an empty or unusable value is repaired on load instead of asking the user to
	// edit JSON before the feature can work for the first time.
	s.TunDevice = s.NormalizedTunDevice()
	s.TunStack = s.NormalizedTunStack()
	if s.MixedPort == 0 {
		s.MixedPort = def.MixedPort
	}
	if s.APIPort == 0 {
		s.APIPort = def.APIPort
	}
	if s.UIPort == 0 {
		s.UIPort = def.UIPort
	}
	if s.ControlPort == 0 {
		s.ControlPort = def.ControlPort
	}
	if s.Language == "" {
		s.Language = def.Language
	}
	if s.KeepNodes == 0 {
		s.KeepNodes = def.KeepNodes
	}
	if s.ProbeRounds == 0 {
		s.ProbeRounds = def.ProbeRounds
	}
	if s.ProbeWorkers == 0 {
		s.ProbeWorkers = def.ProbeWorkers
	}
	if s.OptimizeIntervalMin == 0 {
		s.OptimizeIntervalMin = def.OptimizeIntervalMin
	}
	if s.SubscriptionIntervalHours == 0 {
		s.SubscriptionIntervalHours = def.SubscriptionIntervalHours
	}
	if s.WindowWidth == 0 {
		s.WindowWidth = def.WindowWidth
	}
	if s.WindowHeight == 0 {
		s.WindowHeight = def.WindowHeight
	}
	if s.ProxyBypass == "" {
		s.ProxyBypass = def.ProxyBypass
	}
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.state
	out.Subscriptions = append([]Subscription(nil), s.state.Subscriptions...)
	out.Optimized = append([]Proxy(nil), s.state.Optimized...)
	out.BaseNodes = append([]Proxy(nil), s.state.BaseNodes...)
	return out
}

func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Settings
}

// UpdateSettings applies a patch and persists it.
func (s *Store) UpdateSettings(patch map[string]interface{}) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(s.state.Settings)
	if err != nil {
		return s.state.Settings, err
	}
	var cur map[string]interface{}
	if err := json.Unmarshal(raw, &cur); err != nil {
		return s.state.Settings, err
	}
	for k, v := range patch {
		if _, known := cur[k]; known {
			cur[k] = v
		}
	}
	merged, err := json.Marshal(cur)
	if err != nil {
		return s.state.Settings, err
	}
	if err := json.Unmarshal(merged, &s.state.Settings); err != nil {
		return s.state.Settings, err
	}
	return s.state.Settings, s.saveLocked()
}

// SetActiveSubscription records which subscription is in use.
//
// Two fields describe this: Enabled marks the one subscription the user is on,
// and SelectedSub names it. They existed independently and only one of them was
// ever written, so every reader of the other saw nothing - which is how the
// scheduled refresh ended up with no target and silently did nothing.
//
// This sets both together. They are kept as separate fields because the file
// format predates this fix and older builds read Enabled.
func (s *Store) SetActiveSubscription(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Subscriptions {
		s.state.Subscriptions[i].Enabled = s.state.Subscriptions[i].ID == id
	}
	s.state.SelectedSub = id
	// saveLocked, not Save: the mutex is already held, and Save would take it a
	// second time. A recursive lock here deadlocks rather than failing loudly,
	// which is how it was found - the test suite simply stopped mid-run.
	return s.saveLocked()
}

// ActiveSubscription returns the id of the subscription in use, falling back to
// whichever one is enabled. The fallback matters for a file written before the
// two fields were kept in step: those have Enabled set and SelectedSub empty, and
// reporting "no subscription" for them would disable the refresh again.
func (s *Store) ActiveSubscription() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.SelectedSub != "" {
		return s.state.SelectedSub
	}
	for i := range s.state.Subscriptions {
		if s.state.Subscriptions[i].Enabled {
			return s.state.Subscriptions[i].ID
		}
	}
	return ""
}
func (s *Store) SetSubscriptions(subs []Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Subscriptions = subs
	return s.saveLocked()
}

func (s *Store) SetNodes(base, optimized []Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A change to the base nodes means the material optimisation works from has
	// changed, so anything derived from the previous material is now stale.
	if base != nil {
		s.state.SubGeneration++
	}
	if base != nil {
		s.state.BaseNodes = base
	}
	if optimized != nil {
		s.state.Optimized = optimized
	}
	return s.saveLocked()
}

func (s *Store) SetCurrent(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Current = name
	return s.saveLocked()
}

// SubscriptionGeneration reports the current generation of subscription material.
func (s *Store) SubscriptionGeneration() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.SubGeneration
}

// BumpSubscriptionGeneration records that the subscription material changed.
//
// Anything derived from the old material - optimised edge lists in particular -
// is now describing nodes that may no longer exist, so the generation is what a
// late result is compared against before it is allowed to take effect.
func (s *Store) BumpSubscriptionGeneration() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SubGeneration++
	_ = s.saveLocked()
	return s.state.SubGeneration
}

// SetOptimizedIfCurrent stores optimisation results only when they still describe
// the subscription they were computed from.
//
// It returns false when the results are stale, which the caller reports rather
// than installing: a scan takes minutes, and a subscription change during that
// window is exactly when stale results would otherwise overwrite good ones.
func (s *Store) SetOptimizedIfCurrent(generation int64, optimized []Proxy) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.state.SubGeneration {
		return false, nil
	}
	s.state.Optimized = optimized
	s.state.OptimizedGeneration = generation
	return true, s.saveLocked()
}

// OptimizedIsCurrent reports whether the stored optimisation still matches the
// subscription it came from.
func (s *Store) OptimizedIsCurrent() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.state.Optimized) == 0 {
		return false
	}
	return s.state.OptimizedGeneration == s.state.SubGeneration
}
func (s *Store) SetLastOptimize(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.LastOptimize = t.Format(time.RFC3339)
	return s.saveLocked()
}

// ---------------------------------------------------------------------------
// small helpers shared by the rest of the program
// ---------------------------------------------------------------------------

func boolPtr(v bool) *bool { return &v }

func nowStamp() string { return time.Now().Format(time.RFC3339) }

func shortID(seed string) string {
	var b strings.Builder
	for _, r := range seed {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			b.WriteRune(r + 32)
		}
		if b.Len() >= 12 {
			break
		}
	}
	if b.Len() == 0 {
		return fmt.Sprintf("sub%d", time.Now().UnixNano()%1000000)
	}
	return b.String()
}
