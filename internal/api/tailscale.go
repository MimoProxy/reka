package api

import "net/netip"

const (
	TailscaleStarting   = "starting"
	TailscaleNeedsLogin = "needs-login"
	TailscaleRunning    = "running"
	TailscaleStopped    = "stopped"
	TailscaleError      = "error"
)

// TailscaleStatus describes the outbound-only tailnet connection.
type TailscaleStatus struct {
	ID           string          `json:"id,omitempty"`
	State        string          `json:"state"`
	AuthURL      string          `json:"auth-url,omitempty"`
	TailscaleIPs []netip.Addr    `json:"tailscale-ips"`
	Peers        []TailscalePeer `json:"peers"`
	LastError    string          `json:"last-error,omitempty"`
}

type TailscalePeer struct {
	Hostname      string       `json:"hostname"`
	TailscaleIPs  []netip.Addr `json:"tailscale-ips"`
	Online        bool         `json:"online"`
	DirectAddress string       `json:"direct-address,omitempty"`
	DERPRegion    string       `json:"derp-region,omitempty"`
}
