package router

import (
	"context"
	"net/netip"
	"testing"
)

func parseRules(t *testing.T, lines ...string) []RuleSpec {
	t.Helper()
	specs := make([]RuleSpec, 0, len(lines))
	for _, line := range lines {
		spec, _, err := ParseClashRule(line)
		if err != nil {
			t.Fatal(line, err)
		}
		specs = append(specs, spec)
	}
	return specs
}

func TestHTTPRequestRules(t *testing.T) {
	r := mustRouter(t, parseRules(t,
		`AND,((URL-REGEX,^http://192\.0\.2\.1/d\?),(USER-AGENT,Example*)),direct`,
		`URL-REGEX,^http://((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/d\?,reject`,
		`USER-AGENT,httpdns*,reject`,
		`DOMAIN-SUFFIX,example.org,proxy`,
		`IP-CIDR,192.0.2.0/24,proxy,no-resolve`,
	), nil)
	if !r.Rules().MatchesHTTP() {
		t.Fatal("rules do not report HTTP conditions")
	}
	addr := netip.MustParseAddr("192.0.2.1")
	connection := Metadata{Network: "tcp", Addr: addr, Port: 80}
	request := func(url, agent string) Metadata {
		md := connection
		md.HTTP = &HTTPRequest{URL: url, UserAgent: agent}
		return md
	}
	for _, tc := range []struct {
		name    string
		md      Metadata
		rule    int
		target  string
		pending bool
	}{
		// Without a request, URL and user agent conditions do not match and
		// routing falls through to later rules.
		{"connection", connection, 4, "proxy", true},
		{"exception", request("http://192.0.2.1/d?dn=example.org", "Example/1.0"), 0, "direct", false},
		{"other agent", request("http://192.0.2.1/d?dn=example.org", "Other/1.0"), 1, "reject", false},
		{"agent", request("http://192.0.2.1/v1/resolve", "httpdns/2.0"), 2, "reject", false},
		{"agent case", request("http://192.0.2.1/v1/resolve", "HttpDns/2.0"), 4, "proxy", false},
		{"other request", request("http://192.0.2.1/index.html", "Other/1.0"), 4, "proxy", false},
		{"udp", Metadata{Network: "udp", Addr: addr, Port: 80}, 4, "proxy", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := r.Route(context.Background(), tc.md, nil)
			if d.RuleIndex != tc.rule || d.Outbound != tc.target || d.HTTPPending != tc.pending {
				t.Fatalf("decision = rule %d %q pending %v", d.RuleIndex, d.Outbound, d.HTTPPending)
			}
		})
	}
	// A rule before the first HTTP condition decides without one.
	if d := r.Route(context.Background(), Metadata{Network: "tcp", Domain: "example.org"}, nil); d.RuleIndex != 3 || !d.HTTPPending {
		t.Fatalf("domain decision = %+v", d)
	}
	early := mustRouter(t, parseRules(t, `DOMAIN,example.org,proxy`, `URL-REGEX,^http://,reject`), nil)
	if d := early.Route(context.Background(), Metadata{Network: "tcp", Domain: "example.org"}, nil); d.RuleIndex != 0 || d.HTTPPending {
		t.Fatalf("early decision = %+v", d)
	}
}

func TestHTTPRequestNot(t *testing.T) {
	r := mustRouter(t, parseRules(t, `NOT,((USER-AGENT,Example*)),proxy`), nil)
	if d := r.Route(context.Background(), Metadata{Network: "tcp", Domain: "example.org"}, nil); d.Outbound != "proxy" || !d.HTTPPending {
		t.Fatalf("connection decision = %+v", d)
	}
	md := Metadata{Network: "tcp", Domain: "example.org", HTTP: &HTTPRequest{URL: "https://example.org/", UserAgent: "Example/1"}}
	if d := r.Route(context.Background(), md, nil); d.Outbound != "direct" || d.HTTPPending {
		t.Fatalf("request decision = %+v", d)
	}
}

func TestHTTPRequestRulesInConditionSet(t *testing.T) {
	var b ConditionSetBuilder
	for _, line := range []string{"DOMAIN,a.example", `URL-REGEX,^https://b\.example/ads`} {
		spec, err := ParseClashSetCondition(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(spec); err != nil {
			t.Fatal(err)
		}
	}
	set, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !set.MatchesHTTP() {
		t.Fatal("condition set does not report HTTP conditions")
	}
	r := mustRouter(t, []RuleSpec{{Kind: KindRuleSet, Values: []string{"ads"}, Set: set, Target: "reject"}}, nil)
	if !r.Rules().MatchesHTTP() {
		t.Fatal("referenced set does not report HTTP conditions")
	}
	md := Metadata{Network: "tcp", Domain: "b.example"}
	if d := r.Route(context.Background(), md, nil); d.Outbound != "direct" || !d.HTTPPending {
		t.Fatalf("connection decision = %+v", d)
	}
	md.HTTP = &HTTPRequest{URL: "https://b.example/ads/1"}
	if d := r.Route(context.Background(), md, nil); d.Outbound != "reject" {
		t.Fatalf("request decision = %+v", d)
	}
}

func TestPreMatchStopsAtHTTPRequestRules(t *testing.T) {
	r := mustRouter(t, parseRules(t, `URL-REGEX,^http://192\.0\.2\.1/,direct`, `IP-CIDR,192.0.2.0/24,reject,no-resolve`), nil)
	addr := netip.MustParseAddr("192.0.2.1")
	if got := r.PreMatch(context.Background(), Metadata{Network: "tcp", Addr: addr, Port: 80}, PreMatchOptions{}); got.Decided {
		t.Fatalf("TCP flow decided before its requests: %+v", got.Decision)
	}
	got := r.PreMatch(context.Background(), Metadata{Network: "udp", Addr: addr, Port: 80}, PreMatchOptions{})
	if !got.Decided || got.Decision.Outbound != "reject" {
		t.Fatalf("UDP flow = %+v", got)
	}
}

func TestHTTPRequestRuleValues(t *testing.T) {
	for _, line := range []string{`URL-REGEX,(?<=a)b,reject`, `USER-AGENT,,reject`} {
		if _, _, err := ParseClashRule(line); err == nil {
			t.Fatalf("%s parsed", line)
		}
	}
	spec, _, err := ParseClashRule(`URL-REGEX,^https?://a\.example/x{1,2},y,reject`)
	if err != nil || spec.Values[0] != `^https?://a\.example/x{1,2},y` || spec.Target != "reject" {
		t.Fatalf("spec = %+v, %v", spec, err)
	}
	for pattern, agents := range map[string][2][]string{
		"Example*":  {{"Example", "Example/1.0 (x)"}, {"example/1.0", "An Example"}},
		"*Mobile?x": {{"A Mobile1x", "Mobile/x"}, {"Mobile12x"}},
	} {
		for i, list := range agents {
			for _, agent := range list {
				if got := matchWildcard(pattern, agent); got != (i == 0) {
					t.Fatalf("%q against %q = %v", pattern, agent, got)
				}
			}
		}
	}
}
