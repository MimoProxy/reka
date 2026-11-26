package generation

import (
	"context"
	"net/netip"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func (e *Engine) preMatch(md sagernet.Metadata) sagernet.PreMatchVerdict {
	if md.InboundType != "tun" {
		return sagernet.PreMatchVerdict{}
	}
	s, g := e.current()
	if g.router == nil {
		return sagernet.PreMatchVerdict{}
	}
	state := e.routingState(g)
	inputAddress := md.Destination.Addr
	if inputAddress.IsValid() {
		if domain, ok := e.fake.Peek(inputAddress); ok {
			md.Destination.Domain = domain
			md.Destination.Addr = netip.Addr{}
		} else if e.isFakeIP(g, inputAddress) {
			if observe := e.opts.ObserveRoute; observe != nil {
				observe(RouteObservation{Address: inputAddress, Failure: fakeIPUnavailable})
			}
			dec := router.Decision{RuleIndex: -1, LookupRule: -1}
			return sagernet.PreMatchVerdict{
				Action: sagernet.PreMatchReject,
				Info:   g.flowInfo(s.Generation, md, dec, state.scene, fakeIPUnavailable),
				Scope:  g.historyScope,
			}
		}
	}

	packetMD := md
	if md.Destination.Domain == "" && inputAddress.IsValid() {
		md.Destination.Domain, md.Destination.DNSMapped = e.hostMapping.Lookup(inputAddress)
	}
	action := sagernet.PreMatchReject
	dec := router.Decision{RuleIndex: -1, LookupRule: -1, Outbound: model.OutboundReject}
	var rejectReason string
	routeMD := g.flowRouterMetadata(md, state.scene)
	if md.Network != "udp" || e.inboundAllowsUDP(g, md) {
		ctx := context.Background()
		opts := router.PreMatchOptions{Overrides: state.temporary, At: state.at}
		if packetMD.Destination.Domain == "" {
			sniff := flowSniffOptions(ctx, g.eff, packetMD, state.scene)
			if e.flowMaySniff(g, packetMD, state, sniff) {
				// Sniffing can supersede either a DNS mapping or an earlier hint.
				if routeMD.Domain != "" {
					return sagernet.PreMatchVerdict{}
				}
				opts.DomainPending = true
			}
		}
		if g.policies != nil {
			opts.Peek = g.peekPreMatchTarget
		}
		result := g.router.PreMatch(ctx, routeMD, opts)
		if e.mitmBlocksQUIC(g, md) {
			rejectReason = mitmQUIC
			if result.Decided {
				dec = result.Decision
			}
		} else if !result.Decided {
			// The rule is unknown, but the outcome may still be certain.
			if !quicAlwaysRejected(g, md, state) {
				return sagernet.PreMatchVerdict{}
			}
			rejectReason = blockQUIC
		} else if out, ok, reason := flowOutbound(g, s.Resources, md, result.Decision); !ok {
			dec, rejectReason = result.Decision, reason
		} else {
			dec, rejectReason = result.Decision, reason
			switch out.Type() {
			case "reject-drop":
				// A dropped TCP flow completes its handshake and then stalls;
				// dropping the SYN instead would change what the client sees.
				if md.Network != "udp" {
					return sagernet.PreMatchVerdict{}
				}
				action = sagernet.PreMatchDrop
			case model.OutboundReject:
			default:
				return sagernet.PreMatchVerdict{}
			}
		}
	}
	if observe := e.opts.ObserveRoute; observe != nil {
		observe(RouteObservation{Domain: routeMD.Domain, Address: inputAddress, Decision: dec})
	}
	return sagernet.PreMatchVerdict{
		Action: action,
		Info:   g.flowInfo(s.Generation, md, dec, state.scene, rejectReason),
		Scope:  g.historyScope,
	}
}

// quicAlwaysRejected reports whether block-quic rejects md whatever rule it
// matches. With block-quic set to all, a QUIC flow is rejected unless its
// route ends at a drop outbound, which is exempt and drops the flow instead.
// Proxy mode exempts direct routes, so it needs the matched rule.
func quicAlwaysRejected(g *generation, md sagernet.Metadata, state routingState) bool {
	if !isQUICFlow(md) || g.eff.Routing.BlockQUIC != "all" || g.rulesMayDrop {
		return false
	}
	isDrop := func(id string) bool { return g.dropOutbounds[id] }
	for _, rule := range state.temporary {
		if g.router.OverrideActive(rule, state.at) && g.router.Reaches(rule.Match.Rule(0).Target, isDrop) {
			return false
		}
	}
	return true
}

func (g *generation) peekPreMatchTarget(target string) (string, []string, bool) {
	if target == "" {
		return "", nil, true
	}
	out, chain, err := g.router.ResolveDynamic(target, func(group router.Group) string {
		if g.unfixedLoadBalance[group.ID] {
			// An empty choice stops resolution at this group.
			return ""
		}
		// Every choice that reaches Peek is independent of the flow key.
		return g.policies.Peek(group.ID, "", group.Selected)
	})
	return out, chain, err == nil
}
