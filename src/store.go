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
	Extra             map[string]interface{} `json:"-"`
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
		OptimizeIntervalMin:       30,
		OptimizeOnStart:           false,
		KeepNodes:                 16,
		ProbeRounds:               3,
		ProbeWorkers:              24,
		SubscriptionAutoUpdate:    true,
		SubscriptionIntervalHours: 6,
		DirectCNDomains:           true,
		BlockAds:                  false,
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

// mergeDefaults copies zero values from def so a settings file written by an
// older version still yields a complete configuration.
func mergeDefaults(s *Settings, def Settings) {
	if s.Mode == "" {
		s.Mode = def.Mode
	}
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

func (s *Store) SetSubscriptions(subs []Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Subscriptions = subs
	return s.saveLocked()
}

func (s *Store) SetNodes(base, optimized []Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
