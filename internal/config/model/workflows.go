package model

// NetworkScene describes an automatic match on the current default interface.
// A scene without conditions is available for manual selection.
type NetworkScene struct {
	ID        string   `yaml:"id"`
	Interface string   `yaml:"interface"`
	IPCIDR    []string `yaml:"ip-cidr"`
}

type TrafficBudget struct {
	Source      string `yaml:"source"`
	Reserve     uint64 `yaml:"reserve-bytes"`
	ResetAt     string `yaml:"reset-at"`
	WarnPercent *int   `yaml:"warn-remaining-percent"`
}
