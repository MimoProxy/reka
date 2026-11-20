package model

// Sniff controls bounded protocol inspection before a flow is routed. It does
// not change the actual destination unless OverrideDestination is explicit.
type Sniff struct {
	Enabled             bool        `yaml:"enabled" json:"enabled"`
	Protocols           []string    `yaml:"protocols" json:"protocols,omitempty"`
	TimeoutMS           int         `yaml:"timeout-ms" json:"timeout-ms,omitempty"`
	MaxBytes            int         `yaml:"max-bytes" json:"max-bytes,omitempty"`
	MaxPackets          int         `yaml:"max-packets" json:"max-packets,omitempty"`
	OverrideDestination bool        `yaml:"override-destination" json:"override-destination,omitempty"`
	Rules               []SniffRule `yaml:"rules" json:"rules,omitempty"`
	SkipDomains         []string    `yaml:"skip-domains" json:"skip-domains,omitempty"`
}

// SniffRule selects inspection before any application bytes are read.
type SniffRule struct {
	Match               Match    `yaml:"match" json:"match"`
	Action              string   `yaml:"action" json:"action"`
	Protocols           []string `yaml:"protocols" json:"protocols,omitempty"`
	OverrideDestination *bool    `yaml:"override-destination" json:"override-destination,omitempty"`
}
