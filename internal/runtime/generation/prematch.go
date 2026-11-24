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

	action := sagernet.PreMatchReject
	dec := router.Decision{RuleIndex: -1, LookupRule: -1, Outbound: model.OutboundReject}
	var rejectReason string
	routeMD := g.flowRouterMetadata(md, state.scene)
	if md.Network != "udp" || e.inboundAllowsUDP(g, md) {
		ctx := context.Background()
		opts := router.PreMatchOptions{Overrides: state.temporary, At: state.at}
		if md.Destination.Domain == "" {
			sniff := flowSniffOptions(ctx, g.eff, md, state.scene)
			if e.flowMaySniff(g, md, state, sniff) {
				// Sniffing can replace a hint already supplied by the caller.
				if md.SniffedDomain != "" {
					return sagernet.PreMatchVerdict{}
				}
				opts.DomainPending = true
			}
		}
		if g.policies != nil {
			opts.Peek = g.peekPreMatchTarget
		}
		result := g.router.PreMatch(ctx, routeMD, opts)
		if !result.Decided {
			return sagernet.PreMatchVerdict{}
		}
		dec = result.Decision
		out, ok, reason := flowOutbound(g, s.Resources, md, dec)
		rejectReason = reason
		if ok {
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
