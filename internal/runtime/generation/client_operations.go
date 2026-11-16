package generation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/router"
	D "github.com/miekg/dns"
)

func (e *Engine) Traffic() api.Traffic {
	upload, download := e.backend.Traffic()
	return api.Traffic{UploadTotal: upload, DownloadTotal: download, SampledAt: time.Now().UTC()}
}

// ProbeOutbound measures an explicitly selected resource without changing
// routing state. It retains exactly that snapshot's transports during the
// bounded request, including lazy node DNS and dialer-proxy dependencies.
func (e *Engine) ProbeOutbound(ctx context.Context, request api.ProbeRequest) (api.ProbeResult, error) {
	result := api.ProbeResult{Outbound: request.Outbound}
	u, err := url.Parse(request.URL)
	if err != nil || len(request.URL) > 8192 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return result, errors.New("probe requires an HTTP(S) URL without userinfo")
	}
	if request.Outbound == "" {
		return result, errors.New("probe outbound is required")
	}
	if request.TimeoutMS == 0 {
		request.TimeoutMS = 5000
	}
	if request.TimeoutMS < 100 || request.TimeoutMS > 30000 {
		return result, errors.New("probe timeout must be 100..30000 ms")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutMS)*time.Millisecond)
	defer cancel()
	e.probeOnce.Do(func() { e.probeSlots = make(chan struct{}, 16) })
	select {
	case e.probeSlots <- struct{}{}:
		defer func() { <-e.probeSlots }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	for ctx.Err() == nil {
		snapshot, g := e.current()
		if g.eff == nil || g.router == nil {
			return result, errors.New("no active configuration")
		}
		id, _, err := g.router.ResolveDynamic(request.Outbound, func(group router.Group) string {
			if g.policies != nil {
				return g.policies.Peek(group.ID, "probe:"+request.URL, group.Selected)
			}
			return group.Selected
		})
		if err != nil || snapshot.Resources[id] == nil {
			return result, errors.New("probe outbound unavailable or rejected")
		}
		out := snapshot.Resources[id]
		pins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		needed := sniffDNSDependencies(g, snapshot.Resources)
		needed[out] = true
		valid := true
		for outbound := range needed {
			pin, err := outbound.Pin()
			if err != nil {
				valid = false
				break
			}
			pins[outbound] = pin
		}
		if !valid {
			closeSniffPins(pins)
			if e.rt.Current() == snapshot {
				return result, errors.New("probe runtime stopped")
			}
			continue
		}
		defer closeSniffPins(pins)
		ctx = sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot)
		if g.dns != nil {
			ctx = sagernet.WithLookup(ctx, func(ctx context.Context, name string) ([]netip.Addr, error) {
				scope := "proxy"
				if out.Type() == "direct" {
					scope = "direct"
				}
				return g.dns.Lookup(ctx, name, scope)
			})
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return pins[out].Dial(ctx, network, address)
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL, nil)
		if err != nil {
			return result, err
		}
		start := time.Now()
		response, err := client.Do(req)
		if err != nil {
			return result, err
		}
		defer response.Body.Close()
		result.ResolvedOutbound, result.StatusCode = id, response.StatusCode
		result.DelayMS = max(1, time.Since(start).Milliseconds())
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return result, fmt.Errorf("probe HTTP status %d", response.StatusCode)
		}
		return result, nil
	}
	return result, ctx.Err()
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
	response, err := resolver.Exchange(ctx, q, request.Scope, request.Fake)
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
		page.Rules = append(page.Rules, api.RuleView{Index: i, ID: rule.ID, Type: kind, Payload: strings.Join(rule.Values, ","), Outbound: rule.Target, Description: rule.String()})
	}
	return page
}
