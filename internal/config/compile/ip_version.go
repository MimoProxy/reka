package compile

import (
	"errors"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
)

// WithIPVersion returns a copy with the dialer IP policy and DNS IPv6 setting
// overridden. An empty policy keeps the compiled settings.
func (e *Effective) WithIPVersion(ipVersion string) (*Effective, error) {
	eff := *e
	eff.IPVersionOverride = ipVersion
	switch ipVersion {
	case "":
		return &eff, nil
	case "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer":
	default:
		return nil, errors.New("unknown IP version policy")
	}
	if e.DNS != nil {
		cfg := *e.DNS
		cfg.IPv6 = ipVersion != "ipv4"
		eff.DNS = &cfg
		if cfg.IPv6 != e.DNS.IPv6 {
			eff.DNSFingerprint = eff.dnsFingerprint()
		}
	}
	if ipVersion == "dual" {
		ipVersion = ""
	}
	eff.Outbounds = slices.Clone(e.Outbounds)
	changed := false
	for i := range eff.Outbounds {
		out := &eff.Outbounds[i]
		switch out.Type {
		case model.OutboundReject, "pass", "reject-drop":
			continue
		}
		var dialer model.Dialer
		if out.Dialer != nil {
			dialer = *out.Dialer
		}
		if dialer.Proxy != "" || dialer.IPVersion == ipVersion {
			continue
		}
		dialer.IPVersion = ipVersion
		out.Dialer = &dialer
		out.Fingerprint = outboundFingerprint(*out)
		changed = true
	}
	if changed {
		if problems := eff.fingerprintDetours(); len(problems) > 0 {
			return nil, errors.New(problems[0])
		}
	}
	return &eff, nil
}
