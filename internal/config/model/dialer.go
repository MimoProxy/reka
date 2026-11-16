package model

// Dialer applies to the connection from a node to its server (or to the
// destination for direct outbounds). Socket options remain OS capabilities.
type Dialer struct {
	Interface   string `yaml:"interface-name" json:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark" json:"routing-mark,omitempty"`
	IPVersion   string `yaml:"ip-version" json:"ip-version,omitempty"`
	TFO         bool   `yaml:"tfo" json:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp" json:"mptcp,omitempty"`
}
