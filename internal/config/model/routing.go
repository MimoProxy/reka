package model

// Routing selects traffic policy independently of OS network takeover.
// Global names an explicit native outbound/group ID used in global mode.
type Routing struct {
	Mode   string `yaml:"mode" json:"mode"`
	Global string `yaml:"global" json:"global,omitempty"`
	// BlockQUIC is off, per-policy, proxy or all. Per-policy blocks QUIC
	// only on outbounds that set block-quic.
	BlockQUIC string `yaml:"block-quic" json:"block-quic,omitempty"`
	// UDPFallback decides UDP that reaches an outbound without UDP relay:
	// reject (the default) or direct.
	UDPFallback string `yaml:"udp-fallback" json:"udp-fallback,omitempty"`
	// DNSFailure decides a connection when the lookup an IP rule needs
	// fails: continue (the default) skips IP rules and keeps matching, final
	// uses the final target, and reject fails the connection.
	DNSFailure string `yaml:"dns-failure" json:"dns-failure,omitempty"`
}
