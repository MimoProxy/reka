package model

// SchemaVersion is the only document version this build reads and writes.
const SchemaVersion = 1

// Profile is the user's main configuration document.
type Profile struct {
	SchemaVersion int        `yaml:"schema-version"`
	Outbounds     []Outbound `yaml:"outbounds"`
	Groups        []Group    `yaml:"groups"`
	Rules         []Rule     `yaml:"rules"`
	// Listeners and Log may also be set in the profile; local settings
	// override them on each machine.
	Listeners []Listener `yaml:"listeners"`
	Log       *Log       `yaml:"log"`
}

// LocalSettings are per-machine settings kept apart from the profile, so
// switching profiles never changes ports or the control endpoint.
type LocalSettings struct {
	SchemaVersion int        `yaml:"schema-version"`
	Listeners     []Listener `yaml:"listeners"`
	Log           *Log       `yaml:"log"`
	Control       *Control   `yaml:"control"`
}

// Outbound types.
const (
	OutboundDirect      = "direct"
	OutboundReject      = "reject"
	OutboundHTTP        = "http"
	OutboundSOCKS       = "socks"
	OutboundShadowsocks = "shadowsocks"
	OutboundVLESS       = "vless"
)

// Outbound is one proxy node or built-in action. Which fields apply depends
// on Type; a field that does not apply is an error, not ignored.
type Outbound struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	Type string `yaml:"type"`

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
	// PacketEncoding is "xudp" (default) or "none" for vless UDP.
	PacketEncoding string `yaml:"packet-encoding"`

	TLS *TLS `yaml:"tls"` // http, vless
}

// TLS is client TLS for an outbound.
type TLS struct {
	ServerName string `yaml:"server-name"`
	Insecure   bool   `yaml:"insecure"`
	// Fingerprint selects a uTLS ClientHello, for example "chrome".
	Fingerprint string   `yaml:"fingerprint"`
	ALPN        []string `yaml:"alpn"`
	Reality     *Reality `yaml:"reality"`
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
	ID       string `yaml:"id"`
	Match    Match  `yaml:"match"`
	Outbound string `yaml:"outbound"`
}

// Match is a rule condition: exactly one condition key, with one value or
// a list of values (any of them matches), plus modifiers.
type Match struct {
	// Kind is the condition key, for example "domain-suffix" or "all".
	Kind      string
	Values    []string
	NoResolve bool
}

// Listener types.
const (
	ListenerMixed = "mixed"
	ListenerSOCKS = "socks"
	ListenerHTTP  = "http"
)

// Listener is a local proxy endpoint.
type Listener struct {
	ID     string `yaml:"id"`
	Type   string `yaml:"type"`
	Listen string `yaml:"listen"`
	// UDP enables SOCKS5 UDP ASSOCIATE on mixed and socks listeners.
	// Default true.
	UDP *bool `yaml:"udp"`
}

// Log settings.
type Log struct {
	Level string `yaml:"level"`
}

// Control is where the control API listens. It is read at startup.
type Control struct {
	Listen string `yaml:"listen"`
}
