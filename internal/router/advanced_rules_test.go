package router

import (
	"context"
	"net/netip"
	"testing"
)

type advancedEnv struct {
	info     ProcessInfo
	known    bool
	calls    int
	dnsCalls int
}

func (e *advancedEnv) Resolve(context.Context, string) ([]netip.Addr, error) {
	e.dnsCalls++
	return nil, ErrNoLookup
}
func (e *advancedEnv) Process(context.Context) (string, bool) {
	panic("ProcessInfo must be used once when available")
}
func (e *advancedEnv) ProcessInfo(context.Context) (ProcessInfo, bool) {
	e.calls++
	return e.info, e.known
}

func TestAdvancedMetadataAndOwnerRules(t *testing.T) {
	md := Metadata{Inbound: "local-auth", InboundType: "SOCKS5", InboundUser: "Alice", InboundPort: 17890, Network: "tcp"}
	for _, tc := range []struct {
		rule string
		hit  bool
	}{
		{`PROCESS-PATH,C:\Program Files\APP.exe,reject`, true},
		{`PROCESS-PATH,C:\Other\APP.exe,reject`, false},
		{`PROCESS-PATH-REGEX,(?<=Files\\)app(?=\.exe$),reject`, true},
		{`PROCESS-PATH-WILDCARD,c:\*\app.???,reject`, true},
		{`PROCESS-NAME-WILDCARD,APP.???,reject`, true},
		{`PROCESS-NAME-WILDCARD,app.??,reject`, false},
		{`IN-NAME,other/local-auth,reject`, true},
		{`IN-NAME,LOCAL-AUTH,reject`, false},
		{`IN-TYPE,socks/http,reject`, true},
		{`IN-TYPE,HTTP/HTTPS,reject`, false},
		{`IN-PORT,80/17900-17800,reject`, true},
		{`IN-USER,Bob/Alice,reject`, true},
		{`IN-USER,alice,reject`, false},
		{`UID,10000/11000-10001,reject`, true},
		{`UID,10000/20000-21000,reject`, false},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			spec, _, err := ParseClashRule(tc.rule)
			if err != nil {
				t.Fatal(err)
			}
			r := mustRouter(t, []RuleSpec{spec}, nil)
			env := &advancedEnv{known: true, info: ProcessInfo{Path: `C:\Program Files\App.exe`, UID: 10042, UIDKnown: true}}
			got := r.Route(context.Background(), md, env)
			if (got.Outbound == "reject") != tc.hit {
				t.Fatalf("unexpected decision: %+v", got)
			}
			if env.dnsCalls != 0 {
				t.Fatal("metadata condition performed DNS")
			}
		})
	}
}

func TestAdvancedUnknownMetadataNeverMatches(t *testing.T) {
	for _, line := range []string{`PROCESS-PATH-WILDCARD,*,reject`, `PROCESS-NAME-WILDCARD,*,reject`, `PROCESS-PATH-REGEX,.*,reject`, `UID,0-4294967295,reject`, `IN-NAME,auth,reject`, `IN-TYPE,TUN,reject`, `IN-PORT,0-65535,reject`, `IN-USER,user,reject`} {
		spec, _, err := ParseClashRule(line)
		if err != nil {
			t.Fatal(err)
		}
		r := mustRouter(t, []RuleSpec{spec}, nil)
		for _, env := range []*advancedEnv{{}, {known: true, info: ProcessInfo{UID: 10001}}, {known: true, info: ProcessInfo{UID: 0, UIDKnown: true}}} {
			if got := r.Route(context.Background(), Metadata{}, env); got.Outbound == "reject" {
				t.Fatal("unknown metadata matched", line, env, got)
			}
		}
	}
}

func TestAdvancedConditionsInLogicSetAndExplain(t *testing.T) {
	guard, _, err := ParseClashRule(`AND,((IN-USER,Alice),(PROCESS-PATH-REGEX,App\([a,b]{1,3}\)\.exe$),(UID,10001-10100)),reject`)
	if err != nil {
		t.Fatal(err)
	}
	set, err := CompileRules([]RuleSpec{guard})
	if err != nil {
		t.Fatal(err)
	}
	r := mustRouter(t, []RuleSpec{{Kind: KindRuleSet, Values: []string{"owners"}, Set: set, Target: "proxy", NoResolve: true}, {Kind: KindMatch, Target: "direct"}}, nil)
	if !r.Rules().NeedsProcess() {
		t.Fatal("nested owner dependency was lost")
	}
	env := &advancedEnv{known: true, info: ProcessInfo{Path: `/opt/App(ab).exe`, UID: 10042, UIDKnown: true}}
	exp := r.Explain(context.Background(), Metadata{InboundUser: "Alice", Domain: "unused.test"}, env)
	if exp.Undetermined || exp.Outbound != "proxy" || env.calls != 1 || env.dnsCalls != 0 {
		t.Fatal(exp, env)
	}
	env.calls = 0
	if got := r.Route(context.Background(), Metadata{InboundUser: "Bob"}, env); got.Outbound != "direct" || env.calls != 0 {
		t.Fatal("short-circuit owner lookup failed", got, env)
	}
}

func TestAdvancedInvalidRules(t *testing.T) {
	for _, line := range []string{`IN-TYPE,UNKNOWN,reject`, `IN-USER,Alice//Bob,reject`, `IN-PORT,65536,reject`, `UID,4294967296,reject`, `UID,-1,reject`, `UID,*,reject`, `PROCESS-PATH-REGEX,(?<,reject`, `IN-NAME,,reject`, `IN-PORT,80,reject,no-resolve`} {
		if _, _, err := ParseClashRule(line); err == nil {
			t.Fatal("invalid metadata condition accepted", line)
		}
	}
}
