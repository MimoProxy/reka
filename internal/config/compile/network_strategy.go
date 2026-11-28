package compile

import (
	"errors"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
)

// Upper bound for network-fallback-delay. The default is 300ms, the same as
// sing-box's N.DefaultFallbackDelay.
const maxNetworkFallbackDelay = 10000

// WithNetworkStrategy returns a copy whose outbounds use the network strategy
// strategy, for a platform setting such as Wi-Fi assist. An empty strategy
// keeps the compiled settings. Outbounds that pin an interface, use TFO or
// dial through another outbound keep their own settings, since upstream does
// not combine those with a network strategy.
func (e *Effective) WithNetworkStrategy(strategy string) (*Effective, error) {
	eff := *e
	eff.NetworkStrategyOverride = strategy
	switch strategy {
	case "":
		return &eff, nil
	case "default", "fallback", "hybrid":
	default:
		return nil, errors.New("unknown network strategy")
	}
	eff.Outbounds = slices.Clone(e.Outbounds)
	changed := false
	for i := range eff.Outbounds {
		out := &eff.Outbounds[i]
		switch out.Type {
		case model.OutboundReject, model.OutboundTailscale, model.OutboundWireGuard, "pass", "reject-drop":
			continue
		}
		var dialer model.Dialer
		if out.Dialer != nil {
			dialer = *out.Dialer
		}
		if dialer.Proxy != "" || dialer.Interface != "" || dialer.TFO || dialer.NetworkStrategy == strategy {
			continue
		}
		dialer.NetworkStrategy = strategy
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
