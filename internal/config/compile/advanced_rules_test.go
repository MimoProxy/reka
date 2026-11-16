package compile

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func TestListenerAuthenticationSecretsAndFingerprint(t *testing.T) {
	s := store(t)
	_ = s.Set("listener/user", "Alice")
	_ = s.Set("listener/password", "first-password")
	local := []byte(`listeners: [{id: auth, type: mixed, listen: '127.0.0.1:17890', users: [{username: 'secret://listener/user', password: 'secret://listener/password'}]}]`)
	eff, ds := Compile([]byte("schema-version: 1"), local, Options{Secrets: s})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	l := eff.Listeners[0]
	if l.Users[0].Username != "Alice" || l.Users[0].Password != "first-password" {
		t.Fatal("authentication secrets unresolved")
	}
	raw, err := json.Marshal(l)
	if err != nil || strings.Contains(string(raw), "Alice") || strings.Contains(string(raw), "first-password") {
		t.Fatal("listener status leaked authentication identity", err)
	}
	_ = s.Set("listener/password", "second-password")
	updated, ds := Compile([]byte("schema-version: 1"), local, Options{Secrets: s})
	if ds.HasErrors() || updated.Listeners[0].Fingerprint == l.Fingerprint {
		t.Fatal("authentication rotation did not change listener fingerprint", ds)
	}
	_, ds = Compile([]byte("schema-version: 1"), local, Options{})
	for _, d := range ds {
		if strings.HasPrefix(d.Code, "secret.") && d.Document != model.DocLocal {
			t.Fatal("listener secret error attributed to shared profile", d)
		}
	}
	if !ds.HasErrors() {
		t.Fatal("missing authentication secret accepted")
	}
}

func TestListenerAuthenticationRejectsAmbiguousUsers(t *testing.T) {
	for _, users := range []string{`[{username: Alice, password: one}, {username: Alice, password: two}]`, `[{username: '', password: one}]`, `[{username: Alice, password: ''}]`, `[{username: 'Alice:Bob', password: one}]`} {
		local := `listeners: [{id: auth, type: mixed, listen: '127.0.0.1:17890', users: ` + users + `}]`
		if _, ds := Compile([]byte("schema-version: 1"), []byte(local), Options{}); !ds.HasErrors() {
			t.Fatal("invalid authentication users accepted")
		}
	}
}

type advancedCompileEnv struct{}

func (advancedCompileEnv) Resolve(context.Context, string) ([]netip.Addr, error) {
	return nil, router.ErrNoLookup
}
func (advancedCompileEnv) Process(context.Context) (string, bool) { return "/opt/App/app", true }
func (advancedCompileEnv) ProcessInfo(context.Context) (router.ProcessInfo, bool) {
	return router.ProcessInfo{Path: "/opt/App/app", UID: 10042, UIDKnown: true}, true
}

func TestAdvancedNativeSubRulesAndRuleSets(t *testing.T) {
	profile := `schema-version: 1
rule-sets:
 - id: owners
   entries:
    - {process-path-wildcard: /opt/*/app}
sub-rules:
 - id: trusted
   rules:
    - {match: {and: [{in-user: Alice}, {uid: 10000-10100}, {rule-set: owners, no-resolve: true}]}, outbound: reject}
rules:
 - {match: {in-type: HTTP/SOCKS}, call: trusted}
 - {match: {all: true}, outbound: direct}
`
	eff, ds := Compile([]byte(profile), nil, Options{ProcessLookup: true})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if !eff.Router.Rules().NeedsProcess() {
		t.Fatal("owner lookup lost through subrule or rule set")
	}
	got := eff.Router.Route(context.Background(), router.Metadata{InboundUser: "Alice", InboundType: "SOCKS5"}, advancedCompileEnv{})
	if got.Outbound != "reject" {
		t.Fatal(got)
	}
}
