package model

// Process controls owner collection independently of routing conditions.
// Rule is lazy and backward-compatible; always resolves each admitted flow.
type Process struct {
	Mode string `yaml:"mode" json:"mode"`
}
