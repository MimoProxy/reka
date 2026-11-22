package generation

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	D "github.com/miekg/dns"
)

const (
	ipCheckOK          = "ok"
	ipCheckFailed      = "failed"
	ipCheckUnavailable = "unavailable"
	ipCheckSkipped     = "skipped"
)

type IPCheck struct {
	Status  string `json:"status"`
	DelayMS *int64 `json:"delayMs,omitempty"`
	Error   string `json:"error,omitempty"`
}

type IPFamilyChecks struct {
	IPv4 IPCheck `json:"ipv4"`
	IPv6 IPCheck `json:"ipv6"`
}

type IPCheckNode struct {
	Member   string         `json:"member"`
	Resolved string         `json:"resolved"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Server   IPFamilyChecks `json:"server"`
	Exit     IPFamilyChecks `json:"exit"`
}

type IPCheckRecommendation struct {
	IPVersion string `json:"ipVersion"`
	Reason    string `json:"reason"`
}

type IPCheckResult struct {
	Local          IPFamilyChecks         `json:"local"`
	Node           *IPCheckNode           `json:"node,omitempty"`
	DNSMode        string                 `json:"dnsMode"`
	IPVersion      string                 `json:"ipVersion"`
	Recommendation *IPCheckRecommendation `json:"recommendation,omitempty"`
}

// RunIPCheck compares local connectivity and a single resolved leaf. The
// batch shares one probe slot, one deadline and one set of transport pins.
func (e *Engine) RunIPCheck(parent context.Context, member, url4, url6 string, timeoutMS int) (IPCheckResult, error) {
	if len(member) > 128 {
		return IPCheckResult{}, errors.New("ip check member is too long")
	}
	url4 = cmp.Or(url4, "https://1.1.1.1/cdn-cgi/trace")
	url6 = cmp.Or(url6, "https://[2606:4700:4700::1111]/cdn-cgi/trace")
	timeout, err := probeTimeout(url4, timeoutMS)
	if err != nil {
		return IPCheckResult{}, err
	}
	if _, err := probeTimeout(url6, timeoutMS); err != nil {
		return IPCheckResult{}, err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	release, err := e.takeProbeSlot(ctx)
	if err != nil {
		return IPCheckResult{}, err
	}
	defer release()
	var physicalDirect *sagernet.Outbound
	for ctx.Err() == nil {
		snapshot, g := e.current()
		direct := snapshot.Resources[model.OutboundDirect]
		if g.eff == nil || g.router == nil || direct == nil {
			return IPCheckResult{}, errors.New("ip check requires an active configuration")
		}
		if configured, _ := g.eff.Outbound(model.OutboundDirect); !configured.Builtin {
			// The profile may give its direct outbound a detour or other transport options.
			if physicalDirect == nil {
				physicalDirect, err = e.backend.NewOutbound(model.OutboundDirect, sagernet.DirectSpec{})
				if err != nil {
					return IPCheckResult{}, errors.New("could not prepare direct probe outbound")
				}
				defer physicalDirect.Close()
			}
			direct = physicalDirect
		}
		var resolved string
		if member != "" {
			resolved, _ = g.resolveProbe(member, url4)
		}
		out := snapshot.Resources[resolved]
		outbounds := []*sagernet.Outbound{direct}
		if out != nil {
			outbounds = append(outbounds, out)
		}
		pins, err := pinProbeOutbounds(g, snapshot, outbounds...)
		if err != nil {
			if e.rt.Current() != snapshot {
				continue
			}
			return IPCheckResult{}, errors.New("ip check runtime stopped")
		}
		defer closeSniffPins(pins)
		ctx = sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot)
		result := IPCheckResult{DNSMode: "normal", IPVersion: g.eff.IPVersionOverride}
		if g.eff.DNS != nil {
			result.DNSMode = cmp.Or(g.eff.DNS.Mode, result.DNSMode)
		}
		if result.DNSMode == "fake-ip" && e.packetFlowRealDNS.Load() {
			result.DNSMode = "normal"
		}
		var wg sync.WaitGroup
		wg.Go(func() { result.Local.IPv4 = ipCheckHTTP(ctx, g, direct, pins[direct], url4) })
		wg.Go(func() { result.Local.IPv6 = ipCheckHTTP(ctx, g, direct, pins[direct], url6) })
		if member != "" {
			target, _ := g.eff.Outbound(resolved)
			node := &IPCheckNode{Member: member, Resolved: resolved, Name: cmp.Or(target.Name, resolved), Type: target.Type}
			result.Node = node
			if out == nil {
				unavailable := IPCheck{Status: ipCheckUnavailable, Error: "outbound unavailable"}
				node.Server = IPFamilyChecks{IPv4: unavailable, IPv6: unavailable}
				node.Exit = node.Server
			} else {
				lookup := e.opts.Resolver.LookupNetIP
				if g.dns != nil {
					lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
						qtype := D.TypeA
						if network == "ip6" {
							qtype = D.TypeAAAA
						}
						return g.dns.LookupIPFamily(ctx, host, "direct", qtype)
					}
				}
				dial := pins[direct].Dial
				wg.Go(func() { node.Server.IPv4 = ipCheckServer(ctx, target, "ip4", lookup, dial) })
				wg.Go(func() { node.Server.IPv6 = ipCheckServer(ctx, target, "ip6", lookup, dial) })
				wg.Go(func() { node.Exit.IPv4 = ipCheckHTTP(ctx, g, out, pins[out], url4) })
				wg.Go(func() { node.Exit.IPv6 = ipCheckHTTP(ctx, g, out, pins[out], url6) })
			}
		}
		wg.Wait()
		if err := parent.Err(); err != nil {
			return IPCheckResult{}, err
		}
		result.Recommendation = recommendIPVersion(result.Local, result.Node, result.DNSMode)
		return result, nil
	}
	return IPCheckResult{}, ctx.Err()
}

func ipCheckHTTP(ctx context.Context, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, endpoint string) IPCheck {
	sample, err := probeHTTP(ctx, g, out, pin, endpoint, true)
	if sample.StatusCode != 0 {
		return IPCheck{Status: ipCheckOK, DelayMS: &sample.DelayMS}
	}
	return IPCheck{Status: ipCheckFailed, Error: ipCheckError(err, "connection failed")}
}

func ipCheckServer(ctx context.Context, target compile.Outbound, network string, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) IPCheck {
	if target.Dialer != nil && target.Dialer.Proxy != "" {
		return IPCheck{Status: ipCheckSkipped, Error: "dialer proxy"}
	}
	if target.Server == "" {
		return IPCheck{Status: ipCheckSkipped, Error: "no server"}
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(target.Server); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = lookup(ctx, network, target.Server)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return IPCheck{Status: ipCheckUnavailable, Error: "no address"}
			}
			return IPCheck{Status: ipCheckFailed, Error: ipCheckError(err, "dns")}
		}
	}
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.Is4() != (network == "ip4") {
			continue
		}
		if target.Type == "hysteria2" || target.Type == "tuic" || target.Plugin != nil && target.Plugin.Type == "kcptun" {
			return IPCheck{Status: ipCheckSkipped, Error: "udp transport"}
		}
		start := time.Now()
		conn, err := dial(ctx, "tcp", netip.AddrPortFrom(ip, target.Port).String())
		delayMS := max(1, time.Since(start).Milliseconds())
		if err != nil {
			return IPCheck{Status: ipCheckFailed, DelayMS: &delayMS, Error: ipCheckError(err, "connection failed")}
		}
		_ = conn.Close()
		return IPCheck{Status: ipCheckOK, DelayMS: &delayMS}
	}
	return IPCheck{Status: ipCheckUnavailable, Error: "no address"}
}

func ipCheckError(err error, fallback string) string {
	var networkError net.Error
	var certError *tls.CertificateVerificationError
	var recordError tls.RecordHeaderError
	var alertError tls.AlertError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EAFNOSUPPORT), errors.Is(err, syscall.EADDRNOTAVAIL):
		return "no route"
	case errors.Is(err, http.ErrSchemeMismatch), errors.As(err, &certError), errors.As(err, &recordError), errors.As(err, &alertError):
		return "tls"
	default:
		return fallback
	}
}

func recommendIPVersion(local IPFamilyChecks, node *IPCheckNode, dnsMode string) *IPCheckRecommendation {
	local4, local6 := local.IPv4.Status == ipCheckOK, local.IPv6.Status == ipCheckOK
	unreachable := func(check IPCheck) bool {
		return check.Status == ipCheckUnavailable || check.Status == ipCheckFailed
	}
	switch {
	case !local4 && !local6:
		return nil
	case local4 && unreachable(local.IPv6):
		return &IPCheckRecommendation{IPVersion: "ipv4", Reason: "local-ipv6-unavailable"}
	case local6 && unreachable(local.IPv4):
		return &IPCheckRecommendation{IPVersion: "ipv6", Reason: "local-ipv4-unavailable"}
	}
	if node != nil {
		server, exit := node.Server, node.Exit
		switch {
		case local6 && server.IPv4.Status == ipCheckOK && unreachable(server.IPv6):
			return &IPCheckRecommendation{IPVersion: "ipv4-prefer", Reason: "server-ipv4-only"}
		case server.IPv6.Status == ipCheckOK && unreachable(server.IPv4):
			return &IPCheckRecommendation{IPVersion: "ipv6-prefer", Reason: "server-ipv6-only"}
		case dnsMode != "fake-ip" && exit.IPv4.Status == ipCheckOK && unreachable(exit.IPv6):
			return &IPCheckRecommendation{IPVersion: "ipv4", Reason: "exit-ipv6-unavailable"}
		case local4 && local6 && exit.IPv4.Status == ipCheckOK && unreachable(exit.IPv6):
			// With fake IPs the node resolves domains itself, so a missing
			// IPv6 exit only affects connections to IPv6 literals.
			return &IPCheckRecommendation{IPVersion: "dual", Reason: "exit-ipv6-unavailable-fake-ip"}
		}
		if exit.IPv4.Status != ipCheckOK || exit.IPv6.Status != ipCheckOK {
			return nil
		}
	}
	if local4 && local6 {
		return &IPCheckRecommendation{IPVersion: "dual", Reason: "dual-ok"}
	}
	return nil
}
