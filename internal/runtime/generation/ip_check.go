package generation

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	D "github.com/miekg/dns"
	quic "github.com/sagernet/quic-go"
)

const (
	ipCheckOK          = "ok"
	ipCheckFailed      = "failed"
	ipCheckUnavailable = "unavailable"
	ipCheckSkipped     = "skipped"
)

type IPCheck struct {
	Status    string   `json:"status"`
	DelayMS   *int64   `json:"delayMs,omitempty"`
	Error     string   `json:"error,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Country   string   `json:"country,omitempty"`
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
	Host     string         `json:"host,omitempty"`
	Port     uint16         `json:"port,omitempty"`
	UDP      bool           `json:"udp"`
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
	QUIC           QUICCheck              `json:"quic"`
}

type QUICCheck struct {
	Local          IPCheck             `json:"local"`
	Node           *IPCheck            `json:"node,omitempty"`
	BlockQUIC      string              `json:"blockQuic"`
	Recommendation *QUICRecommendation `json:"recommendation,omitempty"`
}

type QUICRecommendation struct {
	BlockQUIC string `json:"blockQuic"`
	Reason    string `json:"reason"`
}

// IPCheckOptions selects what RunIPCheck measures. Empty fields use defaults.
type IPCheckOptions struct {
	// Member is the node or group to check. Empty checks the local network only.
	Member string
	// URL4 and URL6 are requested through the node to test its exit.
	URL4, URL6 string
	// Local4 and Local6 are IP:port TLS targets for the local check. A family
	// works when any one of them answers a TLS handshake.
	Local4, Local6 []string
	// LocalQUIC and NodeQUIC are IP:port QUIC targets of either address family.
	LocalQUIC, NodeQUIC []string
	TimeoutMS           int
}

// Public DNS-over-HTTPS resolvers run by several providers, so that one
// blocked provider does not make a working network look broken.
var (
	defaultLocal4    = []string{"223.5.5.5:443", "1.12.12.12:443", "1.1.1.1:443", "8.8.8.8:443"}
	defaultLocal6    = []string{"[2400:3200::1]:443", "[2400:3200:baba::1]:443", "[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}
	defaultLocalQUIC = []string{
		"223.5.5.5:443", "223.6.6.6:443", "1.1.1.1:443", "8.8.8.8:443",
		"[2400:3200::1]:443", "[2400:3200:baba::1]:443", "[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443",
	}
	defaultNodeQUIC = []string{"1.1.1.1:443", "8.8.8.8:443"}
)

const maxIPCheckTargets = 8

// Cap the diagnostic payload even when DNS returns a large answer set.
const maxIPCheckAddresses = 8

// RunIPCheck compares local connectivity and a single resolved leaf. The
// batch shares one probe slot, one deadline and one set of transport pins.
func (e *Engine) RunIPCheck(parent context.Context, opts IPCheckOptions) (IPCheckResult, error) {
	member := opts.Member
	if len(member) > 128 {
		return IPCheckResult{}, errors.New("ip check member is too long")
	}
	url4 := cmp.Or(opts.URL4, "https://1.1.1.1/cdn-cgi/trace")
	url6 := cmp.Or(opts.URL6, "https://[2606:4700:4700::1111]/cdn-cgi/trace")
	local4, err := localTargets(opts.Local4, defaultLocal4, true)
	if err != nil {
		return IPCheckResult{}, err
	}
	local6, err := localTargets(opts.Local6, defaultLocal6, false)
	if err != nil {
		return IPCheckResult{}, err
	}
	localQUIC, err := quicTargets(opts.LocalQUIC, defaultLocalQUIC)
	if err != nil {
		return IPCheckResult{}, err
	}
	nodeQUIC, err := quicTargets(opts.NodeQUIC, defaultNodeQUIC)
	if err != nil {
		return IPCheckResult{}, err
	}
	timeout, err := probeTimeout(url4, opts.TimeoutMS)
	if err != nil {
		return IPCheckResult{}, err
	}
	if _, err := probeTimeout(url6, opts.TimeoutMS); err != nil {
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
		result := IPCheckResult{
			DNSMode:   "normal",
			IPVersion: g.eff.IPVersionOverride,
			QUIC:      QUICCheck{BlockQUIC: cmp.Or(g.eff.Routing.BlockQUIC, "off")},
		}
		if g.eff.DNS != nil {
			result.DNSMode = cmp.Or(g.eff.DNS.Mode, result.DNSMode)
		}
		if result.DNSMode == "fake-ip" && e.packetFlowRealDNS.Load() {
			result.DNSMode = "normal"
		}
		var wg sync.WaitGroup
		wg.Go(func() { result.Local.IPv4 = ipCheckLocal(ctx, pins[direct].Dial, local4) })
		wg.Go(func() { result.Local.IPv6 = ipCheckLocal(ctx, pins[direct].Dial, local6) })
		wg.Go(func() { result.QUIC.Local = ipCheckQUIC(ctx, pins[direct].ListenPacket, localQUIC) })
		if member != "" {
			target, _ := g.eff.Outbound(resolved)
			node := &IPCheckNode{
				Member: member, Resolved: resolved, Name: cmp.Or(target.Name, resolved), Type: target.Type,
				Host: target.Server, Port: target.Port, UDP: target.UDP,
			}
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
				if node.Type != model.OutboundDirect {
					wg.Go(func() {
						check := ipCheckQUIC(g.probeLookupContext(ctx, out), pins[out].ListenPacket, nodeQUIC)
						result.QUIC.Node = &check
					})
				}
			}
		}
		wg.Wait()
		if err := parent.Err(); err != nil {
			return IPCheckResult{}, err
		}
		node := result.Node
		if node != nil && node.Type == model.OutboundDirect {
			// A group that currently resolves to direct has no node to judge.
			node = nil
		}
		result.Recommendation = recommendIPVersion(result.Local, node, result.DNSMode)
		nodeWorks := node != nil && (node.Exit.IPv4.Status == ipCheckOK || node.Exit.IPv6.Status == ipCheckOK)
		result.QUIC.Recommendation = recommendBlockQUIC(result.QUIC.Local, result.QUIC.Node, nodeWorks)
		return result, nil
	}
	return IPCheckResult{}, ctx.Err()
}

func localTargets(targets, defaults []string, ipv4 bool) ([]string, error) {
	if len(targets) == 0 {
		return defaults, nil
	}
	if len(targets) > maxIPCheckTargets {
		return nil, errors.New("too many local check targets")
	}
	for _, target := range targets {
		addr, err := netip.ParseAddrPort(target)
		if err != nil || addr.Port() == 0 || addr.Addr().Unmap().Is4() != ipv4 {
			return nil, errors.New("local check targets must be IP:port of one family")
		}
	}
	return targets, nil
}

func quicTargets(targets, defaults []string) ([]netip.AddrPort, error) {
	if len(targets) == 0 {
		targets = defaults
	}
	if len(targets) > maxIPCheckTargets {
		return nil, errors.New("too many QUIC check targets")
	}
	addresses := make([]netip.AddrPort, len(targets))
	for i, target := range targets {
		addr, err := netip.ParseAddrPort(target)
		if err != nil || addr.Port() == 0 {
			return nil, errors.New("QUIC check targets must be IP:port")
		}
		addresses[i] = addr
	}
	return addresses, nil
}

// ipCheckLocal connects to every target at once and reports the first
// success. A completed TCP connection is not enough: transparent proxies and
// other middleboxes accept connections they cannot deliver, so the target
// must answer a TLS handshake. When all fail, a missing route wins over other
// errors because it shows the family is absent rather than one target being
// blocked.
func ipCheckLocal(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), targets []string) IPCheck {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type attempt struct {
		delay int64
		err   error
	}
	results := make(chan attempt, len(targets))
	start := time.Now()
	for _, target := range targets {
		go func() {
			err := tlsReachable(ctx, dial, target)
			results <- attempt{max(1, time.Since(start).Milliseconds()), err}
		}()
	}
	var reason string
	for range targets {
		a := <-results
		if a.err == nil {
			return IPCheck{Status: ipCheckOK, DelayMS: &a.delay}
		}
		if category := ipCheckError(a.err, "connection failed"); reason == "" || category == "no route" {
			reason = category
		}
	}
	return IPCheck{Status: ipCheckFailed, Error: reason}
}

// tlsReachable reports whether a TLS server answers at target. A TLS alert
// also counts, since only a real server sends one. The certificate is not
// checked because nothing is exchanged after the handshake.
func tlsReachable(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), target string) error {
	conn, err := dial(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	err = client.HandshakeContext(ctx)
	var alert tls.AlertError
	if err == nil || errors.As(err, &alert) {
		return nil
	}
	return err
}

func ipCheckQUIC(ctx context.Context, listen func(context.Context, string) (net.PacketConn, error), targets []netip.AddrPort) IPCheck {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan IPCheck, len(targets))
	for _, target := range targets {
		go func() { results <- ipCheckQUICTarget(ctx, listen, target) }()
	}
	failure := IPCheck{Status: ipCheckFailed, Error: "udp unsupported"}
	for range targets {
		select {
		case check := <-results:
			if check.Status == ipCheckOK {
				return check
			}
			if failure.Error == "udp unsupported" || check.Error == "timeout" {
				failure = check
			}
		case <-ctx.Done():
			return IPCheck{Status: ipCheckFailed, Error: ipCheckError(ctx.Err(), "connection failed")}
		}
	}
	return failure
}

func ipCheckQUICTarget(ctx context.Context, listen func(context.Context, string) (net.PacketConn, error), target netip.AddrPort) IPCheck {
	start := time.Now()
	packet, err := listen(ctx, target.String())
	if err != nil {
		return IPCheck{Status: ipCheckFailed, Error: "udp unsupported"}
	}
	probe := quicProbePacketConn{PacketConn: packet, closeOnce: sync.OnceValue(packet.Close)}
	defer probe.Close()
	stop := context.AfterFunc(ctx, func() { _ = probe.Close() })
	defer stop()

	tlsConfig := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	conn, err := quic.Dial(ctx, probe, net.UDPAddrFromAddrPort(target), tlsConfig, &quic.Config{})
	delay := max(1, time.Since(start).Milliseconds())
	if err == nil {
		_ = conn.CloseWithError(0, "")
	} else if !quicResponded(err) {
		return IPCheck{Status: ipCheckFailed, Error: ipCheckError(cmp.Or(ctx.Err(), err), "connection failed")}
	}
	return IPCheck{Status: ipCheckOK, DelayMS: &delay}
}

func quicResponded(err error) bool {
	var transport *quic.TransportError
	var application *quic.ApplicationError
	var version *quic.VersionNegotiationError
	return errors.As(err, &transport) && transport.Remote ||
		errors.As(err, &application) && application.Remote ||
		errors.As(err, &version)
}

type quicProbePacketConn struct {
	net.PacketConn
	closeOnce func() error
}

func (c quicProbePacketConn) Close() error { return c.closeOnce() }

func (c quicProbePacketConn) SetReadDeadline(deadline time.Time) error {
	// Closing interrupts reads on teardown even if the proxy lacks deadline support.
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return c.Close()
	}
	return c.PacketConn.SetReadDeadline(deadline)
}

func ipCheckHTTP(ctx context.Context, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, endpoint string) IPCheck {
	check := IPCheck{Status: ipCheckOK}
	sample, err := probeHTTPResponse(ctx, g, out, pin, endpoint, func(response *http.Response) error {
		// Error responses still establish reachability and have no exit metadata.
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, maxProbeBodyBytes))
		if err != nil {
			return err
		}
		body := string(data)
		if len(body) == maxProbeBodyBytes && response.ContentLength != maxProbeBodyBytes {
			// A limit may cut a line in the middle of an IP or country code.
			body = body[:strings.LastIndexByte(body, '\n')+1]
		}
		addr, country := parseIPCheckBody(body)
		if addr.IsValid() {
			check.Addresses = []string{addr.String()}
		}
		check.Country = country
		return nil
	})
	if sample.StatusCode != 0 {
		check.DelayMS = &sample.DelayMS
		return check
	}
	return IPCheck{Status: ipCheckFailed, Error: ipCheckError(err, "connection failed")}
}

func parseIPCheckBody(body string) (netip.Addr, string) {
	if addr, err := netip.ParseAddr(strings.TrimSpace(body)); err == nil && addr.Zone() == "" {
		return addr.Unmap(), ""
	}
	var addr netip.Addr
	var country string
	for line := range strings.SplitSeq(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			addr, _ = netip.ParseAddr(value)
		case "loc":
			country = value
		}
	}
	if addr.Zone() != "" {
		addr = netip.Addr{}
	}
	if len(country) != 2 || country == "XX" || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		country = ""
	}
	return addr.Unmap(), country
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
	var check IPCheck
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.Is4() != (network == "ip4") {
			continue
		}
		address := ip.String()
		if slices.Contains(check.Addresses, address) {
			continue
		}
		check.Addresses = append(check.Addresses, address)
		if len(check.Addresses) == maxIPCheckAddresses {
			break
		}
	}
	if len(check.Addresses) == 0 {
		return IPCheck{Status: ipCheckUnavailable, Error: "no address"}
	}
	if target.Type == "hysteria2" || target.Type == "tuic" || target.Type == model.OutboundWireGuard || target.Plugin != nil && target.Plugin.Type == "kcptun" {
		check.Status, check.Error = ipCheckSkipped, "udp transport"
		return check
	}
	start := time.Now()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(check.Addresses[0], strconv.Itoa(int(target.Port))))
	delayMS := max(1, time.Since(start).Milliseconds())
	check.DelayMS = &delayMS
	if err != nil {
		check.Status, check.Error = ipCheckFailed, ipCheckError(err, "connection failed")
		return check
	}
	_ = conn.Close()
	check.Status = ipCheckOK
	return check
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

func recommendBlockQUIC(local IPCheck, node *IPCheck, nodeWorks bool) *QUICRecommendation {
	switch {
	case local.Status == ipCheckFailed:
		return &QUICRecommendation{BlockQUIC: "all", Reason: "local-quic-blocked"}
	case local.Status != ipCheckOK || node == nil:
		return nil
	case node.Status == ipCheckOK:
		return &QUICRecommendation{BlockQUIC: "off", Reason: "quic-ok"}
	case node.Status == ipCheckFailed && nodeWorks:
		return &QUICRecommendation{BlockQUIC: "proxy", Reason: "node-quic-unavailable"}
	default:
		return nil
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
