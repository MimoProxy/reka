package generation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
	D "github.com/miekg/dns"
)

// A single 4 KiB page caps probe body reads and fits a typical exit trace.
const maxProbeBodyBytes = 4096

func (e *Engine) Traffic() api.Traffic {
	upload, download := e.backend.Traffic()
	return api.Traffic{UploadTotal: upload, DownloadTotal: download, SampledAt: time.Now().UTC()}
}

// ProbeOutbound measures an explicitly selected resource without changing
// routing state. It retains exactly that snapshot's transports during the
// bounded request, including lazy node DNS and dialer-proxy dependencies.
func (e *Engine) ProbeOutbound(ctx context.Context, request api.ProbeRequest) (api.ProbeResult, error) {
	result := api.ProbeResult{Outbound: request.Outbound}
	timeout, err := probeTimeout(request.URL, request.TimeoutMS)
	if err != nil {
		return result, err
	}
	if request.Outbound == "" {
		return result, errors.New("probe outbound is required")
	}
	// Waiting for a slot does not count against the probe's own timeout, so
	// a batch of probes started together measures each one fairly.
	release, err := e.takeProbeSlot(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for ctx.Err() == nil {
		snapshot, g := e.current()
		if g.eff == nil || g.router == nil {
			return result, errors.New("no active configuration")
		}
		id, err := g.resolveProbe(request.Outbound, request.URL)
		if err != nil || snapshot.Resources[id] == nil {
			return result, errors.New("probe outbound unavailable or rejected")
		}
		out := snapshot.Resources[id]
		pins, err := pinProbeOutbounds(g, snapshot, out)
		if err != nil {
			if e.rt.Current() == snapshot {
				return result, errors.New("probe runtime stopped")
			}
			continue
		}
		defer closeSniffPins(pins)
		ctx = sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot)
		var sample api.ArenaSample
		if request.Unified {
			sample, err = probeUnified(ctx, g, out, pins[out], request.URL)
		} else {
			sample, err = probeHTTP(ctx, g, out, pins[out], request.URL)
		}
		if sample.StatusCode != 0 {
			result.ResolvedOutbound, result.StatusCode, result.DelayMS = id, sample.StatusCode, sample.DelayMS
		}
		return result, err
	}
	return result, ctx.Err()
}

func (e *Engine) takeProbeSlot(ctx context.Context) (func(), error) {
	e.probeOnce.Do(func() {
		limit := 16
		if e.opts.HostPacketFlow {
			// Matches the batch size sing-box and mihomo use for latency tests.
			limit = 10
		}
		e.probeSlots = make(chan struct{}, limit)
	})
	select {
	case e.probeSlots <- struct{}{}:
		return func() { <-e.probeSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *generation) resolveProbe(outbound, url string) (string, error) {
	id, _, err := g.router.ResolveDynamic(outbound, func(group router.Group) string {
		if g.policies != nil {
			return g.policies.Peek(group.ID, "probe:"+url, group.Selected)
		}
		return group.Selected
	})
	return id, err
}

func pinProbeOutbounds(g *generation, snapshot *runtime.Snapshot[*sagernet.Outbound], outbounds ...*sagernet.Outbound) (map[*sagernet.Outbound]*sagernet.PinnedOutbound, error) {
	needed := sniffDNSDependencies(g, snapshot.Resources)
	for _, out := range outbounds {
		needed[out] = true
	}
	pins := make(map[*sagernet.Outbound]*sagernet.PinnedOutbound, len(needed))
	for out := range needed {
		pin, err := out.Pin()
		if err != nil {
			closeSniffPins(pins)
			return nil, err
		}
		pins[out] = pin
	}
	return pins, nil
}

func (g *generation) probeLookupContext(ctx context.Context, out *sagernet.Outbound) context.Context {
	if g.dns == nil {
		return ctx
	}
	return sagernet.WithLookup(ctx, func(ctx context.Context, name string) ([]netip.Addr, error) {
		return g.dns.Lookup(ctx, name, outboundLookupScope(out.Type(), "direct"))
	})
}

func probeHTTP(ctx context.Context, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, url string) (api.ArenaSample, error) {
	return probeHTTPResponse(ctx, g, out, pin, url, drainProbeResponse)
}

func probeHTTPResponse(ctx context.Context, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, url string, checkResponse func(*http.Response) error) (api.ArenaSample, error) {
	ctx = g.probeLookupContext(ctx, out)
	transport := &http.Transport{DisableKeepAlives: true, DialContext: pin.Dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return probeRequest(ctx, client, url, checkResponse)
}

// probeUnified sends the request twice over one kept-alive connection and
// reports the second round trip. If the second request fails, for example
// because the server closed the connection, the first result stands.
func probeUnified(ctx context.Context, g *generation, out *sagernet.Outbound, pin *sagernet.PinnedOutbound, url string) (api.ArenaSample, error) {
	ctx = g.probeLookupContext(ctx, out)
	transport := &http.Transport{DialContext: pin.Dial, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	first, err := probeRequest(ctx, client, url, drainProbeResponse)
	if err != nil {
		return first, err
	}
	if second, err := probeRequest(ctx, client, url, drainProbeResponse); err == nil {
		return second, nil
	}
	return first, nil
}

func probeRequest(ctx context.Context, client *http.Client, url string, checkResponse func(*http.Response) error) (api.ArenaSample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return api.ArenaSample{}, err
	}
	start := time.Now()
	response, err := client.Do(req)
	if err != nil {
		return api.ArenaSample{}, err
	}
	defer response.Body.Close()
	result := api.ArenaSample{DelayMS: max(1, time.Since(start).Milliseconds()), StatusCode: response.StatusCode}
	return result, checkResponse(response)
}

func drainProbeResponse(response *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProbeBodyBytes))
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("probe HTTP status %d", response.StatusCode)
	}
	return nil
}

func (e *Engine) QueryDNS(ctx context.Context, request api.DNSQueryRequest) (api.DNSQueryResult, error) {
	result := api.DNSQueryResult{Answer: []string{}, Authority: []string{}, Extra: []string{}}
	if request.Scope == "" {
		request.Scope = "normal"
	}
	if !slices.Contains([]string{"normal", "proxy", "direct", "bootstrap"}, request.Scope) {
		return result, errors.New("unknown DNS scope")
	}
	if request.Type == "" {
		request.Type = "A"
	}
	qtype, ok := D.StringToType[strings.ToUpper(request.Type)]
	if !ok {
		return result, errors.New("unknown DNS question type")
	}
	if len(request.Name) > 253 {
		return result, errors.New("DNS name is too long")
	}
	if _, ok := D.IsDomainName(request.Name); !ok || request.Name == "" {
		return result, errors.New("invalid DNS name")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx, release, resolver, err := e.retainCurrentDNS(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	q := new(D.Msg)
	q.SetQuestion(D.Fqdn(request.Name), qtype)
	response, err := resolver.Exchange(history.WithDNSOrigin(ctx, history.DNSOrigin{Kind: "control"}), q, request.Scope, request.Fake)
	if err != nil {
		return result, err
	}
	result.RCode = response.Rcode
	for _, rr := range response.Answer {
		result.Answer = append(result.Answer, rr.String())
	}
	for _, rr := range response.Ns {
		result.Authority = append(result.Authority, rr.String())
	}
	for _, rr := range response.Extra {
		result.Extra = append(result.Extra, rr.String())
	}
	return result, nil
}

func (e *Engine) FlushDNSCache() int {
	_, g := e.current()
	if g.dns == nil {
		return 0
	}
	return g.dns.FlushCache()
}

func (e *Engine) ResetNetwork() int {
	snapshot, g := e.current()
	e.retryTailscale()
	e.backend.NotifyEndpointNetworkChanged(context.Background())
	cleared := 0
	if g.dns != nil {
		cleared = g.dns.NetworkChanged()
	}
	for _, outbound := range snapshot.Resources {
		outbound.CloseIdleConnections()
	}
	return cleared
}

func (e *Engine) RulesPage(offset, limit int) api.RulesPage {
	snapshot, g := e.current()
	page := api.RulesPage{Generation: snapshot.Generation, Revision: g.revision, Rules: []api.RuleView{}}
	if g.router == nil {
		return page
	}
	page.Mode = g.eff.Routing.Mode
	rules := g.router.Rules()
	page.Total = rules.Len()
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	for i := offset; i < min(offset+limit, page.Total); i++ {
		rule := rules.Rule(i)
		kind := strings.ToUpper(rule.Kind.String())
		if rule.Kind == router.KindMatch {
			kind = "MATCH"
		}
		page.Rules = append(page.Rules, api.RuleView{
			Index: i, ID: rule.ID, Type: kind, Payload: strings.Join(rule.Values, ","), Outbound: rule.Target,
			Description: compile.DescribeRoutingRule(rule), Context: compile.LocalRuleSource(rule.ID),
		})
	}
	return page
}
