package model

import KC "github.com/MimoProxy/reka/internal/compat/kcptun"
import RD "github.com/MimoProxy/reka/internal/dns"
import "github.com/MimoProxy/reka/internal/platform"

// SchemaVersion is the only document version this build reads and writes.
const SchemaVersion = 1

// Profile is the user's main configuration document.
type Profile struct {
	MITM           *MITM           `yaml:"mitm"`
	HTTPRewrites   []HTTPRewrite   `yaml:"http-rewrites"`
	HeaderRewrites []HeaderRewrite `yaml:"header-rewrites"`
	BodyRewrites   []BodyRewrite   `yaml:"body-rewrites"`
	MapLocal       []MapLocal      `yaml:"map-local"`
	Scripts        []Script        `yaml:"scripts"`
	Geodata        []GeoDatabase   `yaml:"geodata"`
	Process        *Process        `yaml:"process"`
	Routing        *Routing        `yaml:"routing"`
	Sniff          *Sniff          `yaml:"sniff"`
	DNS            *RD.Config      `yaml:"dns"`
	SchemaVersion  int             `yaml:"schema-version"`
	Imports        []Import        `yaml:"imports"`
	Modules        []Module        `yaml:"modules"`
	Outbounds      []Outbound      `yaml:"outbounds"`
	Groups         []Group         `yaml:"groups"`
	Rules          []Rule          `yaml:"rules"`
	RuleSets       []RuleSet       `yaml:"rule-sets"`
	SubRules       []SubRules      `yaml:"sub-rules"`
	// Listeners and Log may also be set in the profile; local settings
	// override them on each machine.
	Listeners []Listener `yaml:"listeners"`
	Log       *Log       `yaml:"log"`
}

// LocalSettings are per-machine settings kept apart from the profile, so
// switching profiles never changes ports or the control endpoint.
type LocalSettings struct {
	MITM           *LocalMITM        `yaml:"mitm"`
	NetworkScenes  []NetworkScene    `yaml:"network-scenes"`
	TrafficBudgets []TrafficBudget   `yaml:"traffic-budgets"`
	Process        *Process          `yaml:"process"`
	Routing        *Routing          `yaml:"routing"`
	Sniff          *Sniff            `yaml:"sniff"`
	Network        *platform.Network `yaml:"network"`
	SchemaVersion  int               `yaml:"schema-version"`
	Listeners      []Listener        `yaml:"listeners"`
	Log            *Log              `yaml:"log"`
	Control        *Control          `yaml:"control"`
}

// Outbound types.
const (
	OutboundDirect      = "direct"
	OutboundReject      = "reject"
	OutboundHTTP        = "http"
	OutboundSOCKS       = "socks"
	OutboundShadowsocks = "shadowsocks"
	OutboundVLESS       = "vless"
	OutboundWireGuard   = "wireguard"
)

// Outbound is one proxy node or built-in action. Which fields apply depends
// on Type; a field that does not apply is an error, not ignored.
type Outbound struct {
	Plugin            *SSPlugin            `yaml:"plugin"`
	Encryption        string               `yaml:"encryption"`
	UDPOverTCP        bool                 `yaml:"udp-over-tcp"`
	UDPOverTCPVersion int                  `yaml:"udp-over-tcp-version"`
	Headers           []SubscriptionHeader `yaml:"headers"`
	Dialer            *Dialer              `yaml:"dialer"`
	Protocol          *Protocol            `yaml:"protocol"`
	Transport         *Transport           `yaml:"transport"`
	Multiplex         *Multiplex           `yaml:"multiplex"`
	ID                string               `yaml:"id"`
	Name              string               `yaml:"name"`
	Type              string               `yaml:"type"`

	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	// UDP enables UDP relay where the protocol supports it. Default true.
	UDP *bool `yaml:"udp"`

	Username string `yaml:"username"` // http, socks
	Password string `yaml:"password"` // http, socks, shadowsocks
	Method   string `yaml:"method"`   // shadowsocks

	UUID string `yaml:"uuid"` // vless
	// Flow is "" or "xtls-rprx-vision".
	Flow string `yaml:"flow"`
	// PacketEncoding is xudp (default), packetaddr, or none for raw VLESS UDP.
	PacketEncoding string `yaml:"packet-encoding"`

	TLS *TLS `yaml:"tls"` // http, vless
}

// TLS is client TLS for an outbound.
type TLSCarrier struct {
	Type        string `yaml:"type"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Version     int    `yaml:"version"`
	VersionHint string `yaml:"version-hint"`
	Script      string `yaml:"script"`
}
type TLS struct {
	Carrier *TLSCarrier `yaml:"carrier"`

	ECH            *ECH   `yaml:"ech"`
	CertificatePin string `yaml:"certificate-sha256"`
	VerifyName     string `yaml:"verify-name"`
	Certificate    string `yaml:"certificate"`
	PrivateKey     string `yaml:"private-key"`
	ServerName     string `yaml:"server-name"`
	Insecure       bool   `yaml:"insecure"`
	// Fingerprint selects a uTLS ClientHello, for example "chrome".
	Fingerprint string   `yaml:"fingerprint"`
	ALPN        []string `yaml:"alpn"`
	Reality     *Reality `yaml:"reality"`
}

type ECH struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Config          string `yaml:"config" json:"config,omitempty"`
	QueryServerName string `yaml:"query-server-name" json:"query-server-name,omitempty"`
}

// Reality is the client side of REALITY.
type Reality struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
	// X25519MLKEM768 keeps the hybrid post-quantum key share in the
	// ClientHello. Newer Xray servers may require it.
	X25519MLKEM768 bool `yaml:"x25519mlkem768"`
}

// Group types.
const GroupSelect = "select"

// Group is a policy group.
type Group struct {
	ExpectedStatus string `yaml:"expected-status"`
	URL            string `yaml:"url"`
	Interval       int    `yaml:"interval"`
	Timeout        int    `yaml:"timeout"`
	Tolerance      int    `yaml:"tolerance"`
	Lazy           *bool  `yaml:"lazy"`
	Strategy       string `yaml:"strategy"`
	IncludeAll     bool   `yaml:"include-all"`
	Filter         string `yaml:"filter"`
	ExcludeFilter  string `yaml:"exclude-filter"`
	DisableUDP     bool   `yaml:"disable-udp"`

	Icon    string   `yaml:"icon"`
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Members []string `yaml:"members"`
	// Selected is the user's choice; it is configuration, not runtime
	// state, so it survives restarts and shows in history.
	Selected string `yaml:"selected"`
}

// Rule routes connections that match to Outbound, which names an outbound
// or a group.
type Rule struct {
	ID string `yaml:"id"`
	// Syntax is the original rule line retained by the importer for diagnostics.
	Syntax string `yaml:"syntax"`
	// Source expands that source's rules here instead of matching a flow.
	Source   string `yaml:"source"`
	Module   string `yaml:"module"`
	Match    Match  `yaml:"match"`
	Outbound string `yaml:"outbound"`
	Call     string `yaml:"call"`
}

// Import selects which resources from a source are visible to the profile.
type Import struct {
	Rewrites  bool   `yaml:"rewrites"`
	RuleSets  bool   `yaml:"rule-sets"`
	SubRules  bool   `yaml:"sub-rules"`
	Source    string `yaml:"source"`
	Outbounds bool   `yaml:"outbounds"`
	Groups    bool   `yaml:"groups"`
}

// Sources contains normalized, immutable source snapshots. Downloading and
// importing external formats happens before submitting these documents.
type Sources struct {
	SchemaVersion int      `yaml:"schema-version"`
	Sources       []Source `yaml:"sources"`
}

type Subscription struct {
	CertificateFiles  []CertificateFile    `yaml:"certificate-files" json:"certificate_files,omitempty"`
	ProviderDirectory string               `yaml:"provider-directory" json:"provider_directory,omitempty"`
	Geodata           []GeoAsset           `yaml:"geodata" json:"geodata,omitempty"`
	URL               string               `yaml:"url" json:"url"`
	Format            string               `yaml:"format" json:"format,omitempty"`
	Interval          int                  `yaml:"interval" json:"interval,omitempty"`
	NodesOnly         bool                 `yaml:"nodes-only" json:"nodes_only,omitempty"`
	AllowPartial      bool                 `yaml:"allow-partial" json:"allow_partial,omitempty"`
	Paused            bool                 `yaml:"paused" json:"paused,omitempty"`
	Headers           []SubscriptionHeader `yaml:"headers" json:"headers,omitempty"`
}

// CertificateFile attaches local TLS identity material to a foreign path name.
// Value is inline PEM or a secret reference, never a path to open remotely.
type CertificateFile struct {
	Path  string `yaml:"path" json:"path"`
	Value string `yaml:"value" json:"value"`
}
type SubscriptionHeader struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}
type SourceLock struct {
	Root      string         `yaml:"root" json:"root"`
	Resources []ResourceLock `yaml:"resources" json:"resources"`
}
type ResourceLock struct {
	Format   string `yaml:"format" json:"format,omitempty"`
	Behavior string `yaml:"behavior" json:"behavior,omitempty"`
	ID       string `yaml:"id" json:"id"`
	Kind     string `yaml:"kind" json:"kind"`
	Name     string `yaml:"name" json:"name,omitempty"`
	Hash     string `yaml:"hash" json:"hash"`
	Request  string `yaml:"request" json:"request"`
}
type Source struct {
	MITM           *MITM           `yaml:"mitm"`
	HTTPRewrites   []HTTPRewrite   `yaml:"http-rewrites"`
	HeaderRewrites []HeaderRewrite `yaml:"header-rewrites"`
	BodyRewrites   []BodyRewrite   `yaml:"body-rewrites"`
	MapLocal       []MapLocal      `yaml:"map-local"`
	Scripts        []Script        `yaml:"scripts"`
	DNS            *RD.Config      `yaml:"dns"`
	Subscription   *Subscription   `yaml:"subscription"`
	Module         *ModuleSnapshot `yaml:"module"`
	Lock           *SourceLock     `yaml:"lock"`
	ID             string          `yaml:"id"`
	Outbounds      []Outbound      `yaml:"outbounds"`
	Groups         []Group         `yaml:"groups"`
	Rules          []Rule          `yaml:"rules"`
	RuleSets       []RuleSet       `yaml:"rule-sets"`
	SubRules       []SubRules      `yaml:"sub-rules"`
}

// Overlay contains explicit edits against the composed source/profile view.
type Overlay struct {
	SchemaVersion int  `yaml:"schema-version"`
	Patches       []Op `yaml:"patches"`
}

// Match is a rule condition: exactly one condition key, with one value or
// a list of values (any of them matches), plus modifiers.
type Match struct {
	// Kind is the condition key, for example "domain-suffix" or "all".
	Kind      string
	Values    []string
	NoResolve bool
	Children  []Match
}

// Listener types.
const (
	ListenerMixed = "mixed"
	ListenerSOCKS = "socks"
	ListenerHTTP  = "http"
)

// Listener is a local proxy endpoint.
type Listener struct {
	Users  []ListenerUser `yaml:"users"`
	ID     string         `yaml:"id"`
	Type   string         `yaml:"type"`
	Listen string         `yaml:"listen"`
	// UDP enables SOCKS5 UDP ASSOCIATE on mixed and socks listeners.
	// Default true.
	UDP *bool `yaml:"udp"`
}

// ListenerUser authenticates one local proxy client. Both fields may reference
// SecretStore values and are masked when documents are read through the API.
type ListenerUser struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// Log settings.
type Log struct {
	Level string `yaml:"level"`
}

// Control is where the control API listens. It is read at startup.
type Control struct {
	Listen string `yaml:"listen"`
}

// RuleSet pins external bytes or carries explicit inline condition entries.
type RuleSet struct {
	Download *ResourceDownload `yaml:"download"`
	ID       string            `yaml:"id"`
	// Name is shown to the user in place of the ID. It does not affect routing.
	Name       string          `yaml:"name"`
	Behavior   string          `yaml:"behavior"`
	Format     string          `yaml:"format"`
	Hash       string          `yaml:"hash"`
	Code       string          `yaml:"code"`
	Entries    []Match         `yaml:"entries"`
	References []RuleReference `yaml:"references"`
}
type SubRules struct {
	ID    string `yaml:"id"`
	Rules []Rule `yaml:"rules"`
}

type GeoAsset struct {
	ID  string `yaml:"id" json:"id"`
	URL string `yaml:"url" json:"url"`
}

type RuleReference struct {
	Name string `yaml:"name"`
	To   string `yaml:"to"`
}

type HysteriaRealm struct {
	Enabled     bool     `yaml:"enabled"`
	ServerURL   string   `yaml:"server-url"`
	Token       string   `yaml:"token"`
	RealmID     string   `yaml:"realm-id"`
	STUNServers []string `yaml:"stun-servers"`
	TLS         *TLS     `yaml:"tls"`
}

type Protocol struct {
	PrivateKey          string   `yaml:"private-key,omitempty" json:",omitempty"`
	PublicKey           string   `yaml:"public-key,omitempty" json:",omitempty"`
	PreSharedKey        string   `yaml:"pre-shared-key,omitempty" json:",omitempty"`
	Address             []string `yaml:"address,omitempty" json:",omitempty"`
	AllowedIPs          []string `yaml:"allowed-ips,omitempty" json:",omitempty"`
	PersistentKeepalive int      `yaml:"persistent-keepalive,omitempty" json:",omitempty"`
	Reserved            []uint8  `yaml:"reserved,omitempty" json:",omitempty"`
	MTU                 int      `yaml:"mtu,omitempty" json:",omitempty"`

	Realm          *HysteriaRealm `yaml:"realm"`
	UpBPS          *uint64        `yaml:"up-bps"`
	DownBPS        *uint64        `yaml:"down-bps"`
	ServerPorts    []string       `yaml:"server-ports"`
	HopInterval    int            `yaml:"hop-interval-seconds"`
	HopIntervalMax int            `yaml:"hop-interval-max-seconds"`
	Security       string         `yaml:"security"`
	AlterID        int            `yaml:"alter-id"`
	Version        int            `yaml:"version"`
	UserKey        string         `yaml:"user-key"`
	Mode           string         `yaml:"mode"`
	Reuse          bool           `yaml:"reuse"`
	UpMbps         int            `yaml:"up-mbps"`
	DownMbps       int            `yaml:"down-mbps"`
	Congestion     string         `yaml:"congestion-control"`
	UDPMode        string         `yaml:"udp-relay-mode"`
	ZeroRTT        bool           `yaml:"zero-rtt"`
	Heartbeat      int            `yaml:"heartbeat"`
	Obfs           *Obfs          `yaml:"obfs"`

	// AnyTLS uses the sing-anytls and mihomo 30-second defaults when these durations are zero.
	IdleSessionCheckIntervalSeconds int    `yaml:"idle-session-check-interval-seconds" json:",omitempty"`
	IdleSessionTimeoutSeconds       int    `yaml:"idle-session-timeout-seconds" json:",omitempty"`
	MinIdleSession                  int    `yaml:"min-idle-session" json:",omitempty"`
	ClientMetadata                  string `yaml:"client-metadata" json:",omitempty"`
}
type Obfs struct {
	MinPacketSize int    `yaml:"min-packet-size"`
	MaxPacketSize int    `yaml:"max-packet-size"`
	Type          string `yaml:"type"`
	Password      string `yaml:"password"`
	Host          string `yaml:"host"`
}
type Transport struct {
	XHTTP       *XHTTPOptions        `yaml:"xhttp"`
	Method      string               `yaml:"method"`
	Paths       []string             `yaml:"paths"`
	Hosts       []string             `yaml:"hosts"`
	Type        string               `yaml:"type"`
	Path        string               `yaml:"path"`
	Host        string               `yaml:"host"`
	Service     string               `yaml:"service-name"`
	Headers     []SubscriptionHeader `yaml:"headers"`
	EarlyData   int                  `yaml:"max-early-data"`
	EarlyHeader string               `yaml:"early-data-header"`
}
type Multiplex struct {
	OnlyTCP        bool    `yaml:"only-tcp"`
	Statistic      bool    `yaml:"statistic"`
	Brutal         *Brutal `yaml:"brutal"`
	Enabled        bool    `yaml:"enabled"`
	Protocol       string  `yaml:"protocol"`
	MaxConnections int     `yaml:"max-connections"`
	MinStreams     int     `yaml:"min-streams"`
	MaxStreams     int     `yaml:"max-streams"`
	Padding        bool    `yaml:"padding"`
}

type Brutal struct {
	Enabled bool   `yaml:"enabled"`
	UpBPS   uint64 `yaml:"up-bps"`
	DownBPS uint64 `yaml:"down-bps"`
}

// SSPlugin decorates the Shadowsocks stream carrier. kcptun requires UoT;
// for other plugins native UDP remains
// unchanged unless UDP-over-TCP is enabled.
type SSPlugin struct {
	Username          string     `yaml:"username"`
	ClientFingerprint string     `yaml:"client-fingerprint"`
	VersionHint       string     `yaml:"version-hint"`
	RestlsScript      string     `yaml:"restls-script"`
	ForceTLS12        bool       `yaml:"force-tls12"`
	ALPN              []string   `yaml:"alpn"`
	KCP               *KC.Config `yaml:"kcp"`

	Type        string               `yaml:"type"`
	Mode        string               `yaml:"mode"`
	Host        string               `yaml:"host"`
	Path        string               `yaml:"path"`
	TLS         *TLS                 `yaml:"tls"`
	Mux         *bool                `yaml:"mux"`
	Headers     []SubscriptionHeader `yaml:"headers"`
	HTTPUpgrade bool                 `yaml:"http-upgrade"`
	FastOpen    bool                 `yaml:"fast-open"`
	Version     int                  `yaml:"version"`
	Password    string               `yaml:"password"`
}

// ResourceDownload schedules updates of a pinned resource.
type ResourceDownload struct {
	URL       string `yaml:"url"`
	Interval  int    `yaml:"interval"`
	Automatic bool   `yaml:"automatic"`
}

// GeoDatabase pins a whole DAT/MMDB or an SRS selector identified by kind:code.
type GeoDatabase struct {
	ID       string            `yaml:"id"`
	Format   string            `yaml:"format"`
	Hash     string            `yaml:"hash"`
	Download *ResourceDownload `yaml:"download"`
}
