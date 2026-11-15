package main

import (
	"context"
	"errors"
	"github.com/MimoProxy/reka/internal/policy"
	A "github.com/metacubex/mihomo/adapter"
	O "github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	P "github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	CP "github.com/metacubex/mihomo/constant/provider"
	"time"
)

type measured struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
}

func (p *measured) Name() string                { return p.name }
func (p *measured) AliveForTestUrl(string) bool { return p.alive }
func (p *measured) LastDelayForTestUrl(string) uint16 {
	if !p.alive {
		return 65535
	}
	return p.delay
}
func groupDiff() []map[string]any {
	proxies := []C.Proxy{&measured{A.NewProxy(O.NewDirect()), "dead", false, 65535}, &measured{A.NewProxy(O.NewDirect()), "slow", true, 30}, &measured{A.NewProxy(O.NewDirect()), "fast", true, 1}}
	hc := P.NewHealthCheck(proxies, "https://probe.test", 1000, 0, true, nil)
	provider, e := P.NewCompatibleProvider("test", proxies, hc)
	if e != nil {
		panic(e)
	}
	defer provider.Close()
	providers := []CP.ProxyProvider{provider}
	opts := G.GroupCommonOption{Name: "group", URL: "https://probe.test"}
	auto, e := G.NewURLTest(opts, G.URLTestOption{}, proxies[0], providers)
	if e != nil {
		panic(e)
	}
	fallback, e := G.NewFallback(opts, G.FallbackOption{}, proxies[0], providers)
	if e != nil {
		panic(e)
	}
	selector, e := G.NewSelector(opts, G.SelectorOption{}, proxies[0], providers)
	if e != nil {
		panic(e)
	}
	if e = selector.Set("slow"); e != nil {
		panic(e)
	}
	manager := policy.New([]policy.Group{{ID: "auto", Type: "url-test", Members: []string{"dead", "slow", "fast"}}, {ID: "fallback", Type: "fallback", Members: []string{"dead", "slow", "fast"}}, {ID: "manual", Type: "select", Members: []string{"slow", "fast"}, Selected: "slow"}}, func(ctx context.Context, member, _ string) error {
		if member == "dead" {
			return errors.New("down")
		}
		d := time.Millisecond
		if member == "slow" {
			d = 30 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	})
	manager.Start()
	defer manager.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, s := range manager.Statuses() {
			for _, r := range s.Results {
				ready = ready && !r.Checked.IsZero()
			}
		}
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	var out []map[string]any
	for _, tc := range []struct{ name, ref, id, base string }{{"url-test", auto.Now(), "auto", ""}, {"fallback", fallback.Now(), "fallback", ""}, {"manual-select", selector.Now(), "manual", "slow"}} {
		native := manager.Choose(tc.id, "example.test", tc.base)
		out = append(out, map[string]any{"name": tc.name, "native": native, "reference": tc.ref, "pass": native == tc.ref})
	}
	return out
}
