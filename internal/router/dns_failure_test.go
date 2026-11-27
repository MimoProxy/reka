package router

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestDNSFailureBehavior(t *testing.T) {
	specs := []RuleSpec{
		{Kind: KindDomain, Values: []string{"early.test"}, Target: "reject"},
		{Kind: KindIPCIDR, Values: []string{"192.168.0.0/16"}, Target: "reject"},
		{Kind: KindDomainKeyword, Values: []string{"later"}, Target: "proxy"},
		{Kind: KindDomain, Values: []string{"indexed-later.test"}, Target: "proxy"},
	}
	env := func() *fakeEnv {
		return &fakeEnv{addrs: map[string][]netip.Addr{
			"ok.test":    {netip.MustParseAddr("192.168.1.1")},
			"empty.test": {},
		}}
	}
	cases := []struct {
		mode, domain string
		want         string
		failed       bool
	}{
		// continue keeps matching the rules after the failed lookup.
		{"", "later.test", "proxy", false},
		{DNSFailureContinue, "indexed-later.test", "proxy", false},
		{DNSFailureContinue, "none.test", "direct", false},
		// final skips the rules after the failed lookup.
		{DNSFailureFinal, "later.test", "direct", true},
		{DNSFailureFinal, "indexed-later.test", "direct", true},
		{DNSFailureFinal, "none.test", "direct", true},
		// An answer without addresses fails too.
		{DNSFailureFinal, "empty.test", "direct", true},
		// reject leaves the decision without an outbound.
		{DNSFailureReject, "later.test", "", true},
		// Rules before the lookup and successful lookups are unaffected.
		{DNSFailureReject, "early.test", "reject", false},
		{DNSFailureReject, "ok.test", "reject", false},
	}
	for _, tt := range cases {
		rs, err := CompileRules(specs)
		if err != nil {
			t.Fatal(err)
		}
		r, err := New(rs, Options{Outbounds: []string{"direct", "proxy", "reject"}, Final: "direct", DNSFailure: tt.mode})
		if err != nil {
			t.Fatal(err)
		}
		d := r.Route(context.Background(), Metadata{Network: "tcp", Domain: tt.domain, Port: 443}, env())
		if d.Outbound != tt.want || d.DNSFailure != tt.failed {
			t.Errorf("%s %s: got outbound %q, DNS failure %v; want %q, %v", tt.mode, tt.domain, d.Outbound, d.DNSFailure, tt.want, tt.failed)
		}
		if tt.failed && tt.mode == DNSFailureFinal && d.RuleIndex != -1 {
			t.Errorf("%s %s: rule index %d, want the final target", tt.mode, tt.domain, d.RuleIndex)
		}
	}
	if _, err := New(nil, Options{Outbounds: []string{"direct"}, Final: "direct", DNSFailure: "drop"}); err == nil {
		t.Fatal("unknown DNS failure behavior accepted")
	}
}

func TestDNSFailureKeepsTriggeringRuleMatch(t *testing.T) {
	// The rule that triggered the lookup can still match on its domain.
	or := RuleSpec{Kind: KindOr, Target: "proxy", Children: []RuleSpec{
		{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}},
		{Kind: KindDomain, Values: []string{"both.test"}},
	}}
	rs, err := CompileRules([]RuleSpec{or})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rs, Options{Outbounds: []string{"direct", "proxy"}, Final: "direct", DNSFailure: DNSFailureReject})
	if err != nil {
		t.Fatal(err)
	}
	d := r.Route(context.Background(), Metadata{Network: "tcp", Domain: "both.test"}, &fakeEnv{})
	if d.Outbound != "proxy" || d.DNSFailure {
		t.Fatalf("got %+v", d)
	}
}

func TestDNSFailureAfterTemporaryRuleLookup(t *testing.T) {
	temp, err := CompileRules([]RuleSpec{{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}, Target: "proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompileRules([]RuleSpec{{Kind: KindDomain, Values: []string{"saved.test"}, Target: "proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rs, Options{Outbounds: []string{"direct", "proxy"}, Final: "direct", DNSFailure: DNSFailureFinal})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	x := r.ExplainWithOverrides(context.Background(), Metadata{Network: "tcp", Domain: "saved.test"}, &fakeEnv{}, nil,
		[]TimedRule{{Match: temp, ExpiresAt: now.Add(time.Minute)}}, now)
	if x.Outbound != "direct" || !x.DNSFailure {
		t.Fatalf("got %+v", x.Decision)
	}
}
