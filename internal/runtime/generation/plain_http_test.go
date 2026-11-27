package generation

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/script"
)

func activatePlainHTTPConfig(t *testing.T, engine *Engine, profile, local string, opts compile.Options, revision uint64) *compile.Effective {
	t.Helper()
	eff, diagnostics := compile.Compile([]byte(profile), []byte(local), opts)
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	prepared, err := engine.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Activate(prepared, revision); err != nil {
		t.Fatal(err)
	}
	return eff
}

func TestPlainHTTPAdmissionAndSniffing(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	md := sagernet.Metadata{
		Network: "tcp", Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.1"), Port: 80},
	}
	for i, tt := range []struct {
		name, pattern, domain, sniff string
		port                         uint16
		skip, unknown, prepare, take bool
	}{
		{name: "no rules"},
		{name: "HTTPS only", pattern: "^https://[^/]+/"},
		{name: "unknown host", pattern: "^http://example[.]com/", domain: "example.com", unknown: true, prepare: true, take: true},
		{name: "known host", pattern: "^http://example[.]com/", domain: "example.com", prepare: true, take: true},
		{name: "different host", pattern: "^http://example[.]com/", domain: "example.net"},
		{name: "different port", pattern: "^http://example[.]com:8080/", unknown: true},
		{name: "nondefault port", pattern: "^http://example[.]com:8080/", port: 8080, domain: "example.com", prepare: true, take: true},
		{name: "IP fallback", pattern: "^http://192[.]0[.]2[.]1/", prepare: true, take: true},
		{name: "host-less rule on port 80", pattern: `^http:\/\/[^?]+\/resolve`, domain: "example.com", prepare: true, take: true},
		{name: "host-less rule on another port", pattern: `^http:\/\/[^?]+\/resolve`, port: 443, domain: "example.com", take: true},
		{name: "host-less rule on another port without a domain", pattern: "^https?://", port: 8080, unknown: true, take: true},
		{name: "host and port rule on another port without a domain", pattern: "^http://example[.]com:8080/", port: 8080, domain: "example.com", unknown: true, prepare: true, take: true},
		{name: "skip parsed request", pattern: "^http://", skip: true},
		{name: "disabled sniffing", pattern: "^http://", sniff: "sniff: {enabled: false}"},
		{name: "excluded protocol", pattern: "^http://", sniff: "sniff: {protocols: [tls]}"},
		{name: "rule enables HTTP", pattern: "^http://", sniff: "sniff: {protocols: [tls], rules: [{match: {all: true}, action: sniff, protocols: [http]}]}", prepare: true, take: true},
		{name: "rule excludes HTTP", pattern: "^http://", sniff: "sniff: {rules: [{match: {all: true}, action: sniff, protocols: [tls]}]}", prepare: true},
		{name: "all flows skipped", pattern: "^http://", sniff: "sniff: {rules: [{match: {all: true}, action: skip}]}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			profile := "schema-version: 1\nmitm: {hostnames: [ignored.example.net], client-source-address: [192.0.2.99]}\n" + tt.sniff + "\n"
			if tt.pattern != "" {
				profile += fmt.Sprintf("map-local: [{id: local, match: '%s', data-type: text, data: sample}]\n", tt.pattern)
			}
			eff := activatePlainHTTPConfig(t, engine, profile, "", compile.Options{}, uint64(i+1))
			if tt.sniff == "" && !eff.SniffForRouting {
				t.Fatal("expected conditional sniffing")
			}
			metadata := md
			metadata.SkipMITM = tt.skip
			if tt.port != 0 {
				metadata.Destination.Port = tt.port
			}
			if !tt.unknown {
				metadata.Destination.Domain = tt.domain
			}
			prepared := engine.prepareFlow(t.Context(), metadata)
			if prepared.Release != nil {
				defer prepared.Release()
			}
			if prepared.Sniff.Enabled != tt.prepare {
				t.Fatalf("sniff enabled = %v, want %v", prepared.Sniff.Enabled, tt.prepare)
			}
			metadata.Protocol, metadata.SniffedDomain = "http", tt.domain
			route := prepared.Route(t.Context(), metadata)
			if route.Release != nil {
				defer route.Release()
			}
			if route.Outbound == nil || (route.MITM != nil) != tt.take {
				t.Fatalf("route = %+v", route)
			}
			if tt.take {
				host := tt.domain
				if host == "" {
					host = metadata.Destination.Addr.String()
				}
				if !route.MITM.PlainHTTP || route.MITM.Host != host || route.MITM.Issuer != nil || route.MITM.Reroute != nil {
					t.Fatalf("plain route = %+v", route.MITM)
				}
			}
			_, gen := engine.current()
			if gen.httpEngine != nil && len(gen.httpEngine.pins) != 0 {
				t.Fatal("rules with local responses retained unused outbounds")
			}
			if status := engine.MITMStatus(); status.CALoaded || status.CAError != "" || status.PlainHTTPConnections != 0 {
				t.Fatalf("unexpected status = %+v", status)
			}
		})
	}
}

func TestPlainHTTPRetainsSniffAndRerouteWithoutCA(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	profile := `schema-version: 1
outbounds: [{id: rewritten, type: direct}]
rules: [{match: {dst-port: 8080}, outbound: rewritten}]
http-rewrites:
  - {id: local-port, match: '^http://example[.]com/', action: header, target: 'http://example.com:8080/'}
`
	opts := compile.Options{Secrets: newMITMTestStore(t)}
	activatePlainHTTPConfig(t, engine, profile, "mitm: {enabled: true, ca: 'secret://mitm/ca'}", opts, 1)
	if status := engine.MITMStatus(); !status.Enabled || status.CALoaded || status.CAError != "no MITM CA installed" {
		t.Fatalf("missing CA status = %+v", status)
	}
	metadata := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "example.com", Port: 80}}
	prepared := engine.prepareFlow(t.Context(), metadata)
	if !prepared.Sniff.Enabled {
		t.Fatal("HTTP rule did not request sniffing")
	}
	defer prepared.Release()
	target := engine.OutboundInstance("rewritten")
	activatePlainHTTPConfig(t, engine, "schema-version: 1", "", compile.Options{}, 2)
	metadata.Protocol = "http"
	route := prepared.Route(t.Context(), metadata)
	if route.Release != nil {
		defer route.Release()
	}
	prepared.Release()
	if route.MITM == nil || !route.MITM.PlainHTTP || route.MITM.Issuer != nil || route.MITM.Reroute == nil {
		t.Fatalf("retired HTTP route = %+v", route)
	}
	metadata.Destination.Port = 8080
	rewritten := route.MITM.Reroute(t.Context(), metadata.Destination, nil)
	if rewritten.Release != nil {
		defer rewritten.Release()
	}
	if rewritten.Outbound != target || rewritten.Info.(*FlowInfo).Revision != 1 || rewritten.MITM != nil {
		t.Fatalf("reroute = %+v", rewritten)
	}
	rewritten.Release()
	route.Release()
	if target.Lease().Active() != 0 {
		t.Fatal("retired HTTP generation kept its outbound pin")
	}
}

func TestPlainHTTPScriptAdmission(t *testing.T) {
	for _, tt := range []struct {
		name, pattern string
		supported     bool
		kind          script.Kind
		want          bool
	}{
		{"request", "^http://example[.]com/", true, script.KindHTTPRequest, true},
		{"response", "^https?://", true, script.KindHTTPResponse, true},
		{"HTTPS script", "^https://", true, script.KindHTTPRequest, false},
		{"missing script engine", "^http://", false, script.KindHTTPRequest, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(EngineOptions{ScriptEngine: func() script.Engine {
				if tt.supported {
					return testScriptEngine{}
				}
				return nil
			}})
			t.Cleanup(engine.Close)
			activateScriptTestProfile(t, engine, 1, "example", false, compile.Script{ID: "hook", Type: string(tt.kind), Supported: true, Pattern: tt.pattern})
			md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "example.com", Port: 80}}
			prep := engine.prepareFlow(t.Context(), md)
			if prep.Release != nil {
				defer prep.Release()
			}
			if prep.Sniff.Enabled != tt.want {
				t.Fatalf("sniff enabled = %v", prep.Sniff.Enabled)
			}
			md.Protocol = "http"
			route := prep.Route(t.Context(), md)
			if route.Release != nil {
				defer route.Release()
			}
			if (route.MITM != nil) != tt.want {
				t.Fatalf("HTTP route = %+v", route.MITM)
			}
			if tt.want {
				matched := route.MITM.MatchScript(tt.kind, "http://example.com/script")
				if matched == nil || matched.Run == nil || (route.MITM.Reroute != nil) != (tt.kind == script.KindHTTPRequest) {
					t.Fatalf("script route = %+v", route.MITM)
				}
				_, gen := engine.current()
				if len(gen.httpEngine.pins) == 0 {
					t.Fatal("script HTTP client lost its routing pins")
				}
			}
		})
	}
}

func TestPlainHTTPUnmatchedRouteAllocations(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	profile := "schema-version: 1\nmap-local: [{id: local, match: '^http://example[.]com/', data-type: text, data: sample}]"
	activatePlainHTTPConfig(t, engine, profile, "", compile.Options{}, 1)
	snap, gen := engine.current()
	state := engine.routingState(gen)
	direct := snap.Resources["direct"]
	for _, dest := range []sagernet.Destination{
		{Domain: "example.net", Port: 80},
		{Domain: "ExAmPlE.NeT.", Port: 80},
		{Addr: netip.MustParseAddr("192.0.2.1"), Port: 80},
		{Addr: netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), Port: 80},
	} {
		md := sagernet.Metadata{Network: "tcp", Protocol: "http", Destination: dest}
		if got := testing.AllocsPerRun(100, func() {
			if route := engine.newMITMRoute(snap, state, md, direct, router.Decision{}); route != nil {
				t.Fatal("unmatched request selected the HTTP engine")
			}
		}); got != 0 {
			t.Fatalf("unmatched %v allocated %v times", dest, got)
		}
	}
}
