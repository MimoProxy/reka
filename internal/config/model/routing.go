package model

// Routing selects traffic policy independently of OS network takeover.
// Global names an explicit native outbound/group ID used in global mode.
type Routing struct {
	Mode   string `yaml:"mode" json:"mode"`
	Global string `yaml:"global" json:"global,omitempty"`
}
