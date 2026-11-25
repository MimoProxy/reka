package generation

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
	"golang.org/x/net/publicsuffix"
)

type scriptHTTPClient struct {
	engine   *Engine
	snapshot *runtime.Snapshot[*sagernet.Outbound]
	state    routingState
	routing  scriptRouting
}

type scriptRouting interface {
	retain() bool
	release()
	outboundPins() map[*sagernet.Outbound]*sagernet.PinnedOutbound
}

var _ script.HTTPClient = scriptHTTPClient{}

func (c scriptHTTPClient) Do(ctx context.Context, input *script.HTTPRequest) (*script.HTTPResponse, error) {
	if input.PolicyDescriptor != "" {
		return nil, errors.New("HTTP client policy descriptor is unsupported")
	}
	if len(input.Body) > compile.ScriptDefaultMaxSize {
		return nil, errors.New("HTTP client request body exceeds size limit")
	}
	g := c.snapshot.Value.(*generation)
	if !c.routing.retain() {
		return nil, errors.New("HTTP client routing generation is unavailable")
	}
	defer c.routing.release()
	policy := ""
	if input.Policy != "" {
		var err error
		policy, err = scriptHTTPPolicy(g, input.Policy)
		if err != nil {
			return nil, err
		}
	}
	timeout := input.Timeout
	if timeout <= 0 {
		timeout = script.DefaultHTTPRequestTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, c.routing.outboundPins()), c.snapshot)
	req, err := http.NewRequestWithContext(ctx, input.Method, input.URL, bytes.NewReader(input.Body))
	if err != nil {
		return nil, err
	}
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || req.URL.Hostname() == "" {
		return nil, errors.New("HTTP client requires an HTTP or HTTPS URL")
	}
	for _, header := range input.Headers {
		if strings.EqualFold(header.Name, "Host") {
			req.Host = header.Value
		} else {
			req.Header.Add(header.Name, header.Value)
		}
	}
	transport := &http.Transport{
		// Dials are scoped to this request, including redirects. Keep the
		// deadline and retain the outbound pins even when net/http detaches
		// the dial context and returns before a dial has stopped.
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if !c.routing.retain() {
				return nil, errors.New("HTTP client routing generation is unavailable")
			}
			defer c.routing.release()
			return c.dial(ctx, g, policy, network, address)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: input.Insecure},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	if !input.AutoRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	if input.AutoCookie {
		client.Jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return nil, err
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, compile.ScriptDefaultMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > compile.ScriptDefaultMaxSize {
		return nil, errors.New("HTTP client response body exceeds size limit")
	}
	var headers []script.HeaderField
	for name, values := range res.Header {
		for _, value := range values {
			headers = append(headers, script.HeaderField{Name: name, Value: value})
		}
	}
	return &script.HTTPResponse{Status: res.StatusCode, Headers: headers, Body: body}, nil
}

func scriptHTTPPolicy(g *generation, name string) (string, error) {
	switch name {
	case "DIRECT":
		return model.OutboundDirect, nil
	case "REJECT":
		return model.OutboundReject, nil
	}
	if g.router.HasTarget(name) {
		return name, nil
	}
	var matches []string
	for _, out := range g.eff.Outbounds {
		if out.Name == name {
			matches = append(matches, out.ID)
		}
	}
	for _, group := range g.eff.Groups {
		if g.eff.GroupMetadata[group.ID].Name == name {
			matches = append(matches, group.ID)
		}
	}
	if len(matches) != 1 {
		return "", errors.New("HTTP client policy is unknown or ambiguous")
	}
	return matches[0], nil
}

func (c scriptHTTPClient) dial(ctx context.Context, g *generation, policy, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid HTTP client port")
	}
	destination := sagernet.Destination{Port: uint16(port)}
	if ip, err := netip.ParseAddr(host); err == nil {
		destination.Addr = ip.Unmap()
	} else {
		destination.Domain = host
	}
	localPort := c.engine.scriptListenerPort(g, destination.Port)
	if localPort && (localScriptAddress(destination.Addr) || localScriptHostname(destination.Domain)) {
		return nil, errScriptLocalListener
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Script fetches dial an outbound directly. They never enter an inbound
	// socket and consequently cannot enter MITM a second time here.
	md := sagernet.Metadata{Network: network, Destination: destination, SkipMITM: true}
	var out *sagernet.Outbound
	var lookup sagernet.LookupFunc
	if policy == "" {
		acquire := func(pick func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error) {
			out, ok := pick(c.snapshot)
			if !ok {
				return c.snapshot.Generation, nil, nil, false, nil
			}
			release, borrowed := c.routing.outboundPins()[out].Borrow()
			return c.snapshot.Generation, out, release, borrowed, nil
		}
		route := c.engine.routeWithAcquire(ctx, md, acquire, c.snapshot, c.state, false)
		if route.Release != nil {
			defer route.Release()
		}
		out, lookup = route.Outbound, route.Lookup
		if route.Destination != nil {
			destination = *route.Destination
		}
	} else {
		decision := router.Decision{Target: policy}
		if g.policies != nil {
			g.resolveObserved(&decision, routerMetadata(md), true)
			g.policies.MarkUsed(decision.Outbound)
		} else {
			decision.Outbound, _, err = g.router.ResolveDynamic(policy, func(group router.Group) string { return group.Selected })
			if err != nil {
				return nil, errors.New("HTTP client policy has no available outbound")
			}
		}
		out = c.snapshot.Resources[decision.Outbound]
	}
	if out == nil || out.Type() == model.OutboundReject || out.Type() == "reject-drop" {
		return nil, errors.New("HTTP client route rejected")
	}
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			if g.dns != nil {
				scope := "proxy"
				if out.Type() == model.OutboundDirect {
					scope = "direct"
				}
				return g.dns.Lookup(ctx, host, scope)
			}
			return c.engine.opts.Resolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if localPort {
		if localScriptAddress(destination.Addr) || localScriptHostname(destination.Domain) {
			return nil, errScriptLocalListener
		}
		if host := destination.Domain; host != "" {
			ips, err := lookup(ctx, host)
			if err != nil && out.Type() == model.OutboundDirect {
				return nil, err
			}
			if slices.ContainsFunc(ips, localScriptAddress) {
				return nil, errScriptLocalListener
			}
			if len(ips) > 0 {
				// Reuse the validated addresses if the outbound also resolves
				// this destination locally.
				base := lookup
				lookup = func(ctx context.Context, name string) ([]netip.Addr, error) {
					if router.NormalizeDomain(name) == router.NormalizeDomain(host) {
						return slices.Clone(ips), nil
					}
					return base(ctx, name)
				}
			}
		}
	}
	return out.Dial(sagernet.WithLookup(ctx, lookup), network, destination.String())
}

var errScriptLocalListener = errors.New("HTTP client destination is a local kernel listener")

func localScriptAddress(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	return ip.IsLoopback() || ip.IsUnspecified()
}

func localScriptHostname(host string) bool {
	host = router.NormalizeDomain(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// SetScriptClashAddress registers the actual address bound by the Clash API.
func (e *Engine) SetScriptClashAddress(address string) {
	a, _ := netip.ParseAddrPort(address)
	e.scriptClashPort.Store(uint32(a.Port()))
}

func (e *Engine) scriptListenerPort(g *generation, port uint16) bool {
	if port == 0 {
		return false
	}
	if slices.ContainsFunc(g.eff.Listeners, func(l compile.Listener) bool { return l.Listen.Port() == port }) {
		return true
	}
	if g.eff.DNS != nil {
		if a, err := netip.ParseAddrPort(g.eff.DNS.Listen); err == nil && a.Port() == port {
			return true
		}
	}
	if e.scriptClashPort.Load() == uint32(port) {
		return true
	}
	e.mu.Lock()
	found := e.dnsListener != nil && e.dnsListener.Addr().Port() == port
	for _, l := range e.listeners {
		if l.cfg.Listen.Port() == port {
			found = true
			break
		}
	}
	e.mu.Unlock()
	if found {
		return true
	}
	debug, _ := netip.ParseAddrPort(e.backend.HTTPSDebugStatus().Address)
	return debug.Port() == port
}

func (e *Engine) scriptServices(snap *runtime.Snapshot[*sagernet.Outbound], state routingState, routing scriptRouting, id, module string, log func(level, msg string)) script.Services {
	return script.Services{
		HTTP:   scriptHTTPClient{engine: e, snapshot: snap, state: state, routing: routing},
		Store:  e.scriptStore,
		Notify: scriptNotifier{notices: e.scriptNotifications, id: id, module: module},
		Log:    log,
	}
}
