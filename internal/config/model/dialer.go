package model

// Dialer applies to the connection from a node to its server (or to the
// destination for direct outbounds). Socket options remain OS capabilities.
type Dialer struct {
	Proxy       string `yaml:"proxy" json:"proxy,omitempty"`
	Interface   string `yaml:"interface-name" json:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark" json:"routing-mark,omitempty"`
	IPVersion   string `yaml:"ip-version" json:"ip-version,omitempty"`
	TFO         bool   `yaml:"tfo" json:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp" json:"mptcp,omitempty"`
	// NetworkStrategy chooses among the networks the platform reports:
	// "fallback" also tries the other networks when the preferred one has
	// not connected within NetworkFallbackDelay milliseconds, "hybrid"
	// races every network at once. Empty or "default" uses the system's
	// choice only.
	NetworkStrategy      string `yaml:"network-strategy" json:"network-strategy,omitempty"`
	NetworkFallbackDelay int    `yaml:"network-fallback-delay" json:"network-fallback-delay,omitempty"`
}
