package model

// Sniff controls bounded protocol inspection before a flow is routed. It does
// not change the actual destination unless OverrideDestination is explicit.
type Sniff struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	Protocols           []string `yaml:"protocols" json:"protocols,omitempty"`
	TimeoutMS           int      `yaml:"timeout-ms" json:"timeout-ms,omitempty"`
	MaxBytes            int      `yaml:"max-bytes" json:"max-bytes,omitempty"`
	MaxPackets          int      `yaml:"max-packets" json:"max-packets,omitempty"`
	OverrideDestination bool     `yaml:"override-destination" json:"override-destination,omitempty"`
}
