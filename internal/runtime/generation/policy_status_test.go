package generation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestHealthExpectedStatusChangesObservedChoiceWithoutReplacingOutbound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) }))
	defer server.Close()
	e := NewEngine(EngineOptions{})
	defer e.Close()
	var previous *Prepared
	for i, rule := range []string{"204", "418/500-599", "*"} {
		input := fmt.Sprintf("schema-version: 1\noutbounds: [{id: local, type: direct}]\ngroups: [{id: health, type: url-test, members: [local], lazy: false, url: %q, expected-status: %q}]\nrules: [{id: all, match: {all: true}, outbound: health}]\n", server.URL, rule)
		eff, ds := compile.Compile([]byte(input), nil, compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Activate(p, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
		if previous != nil && previous.outbounds["local"] != p.outbounds["local"] {
			t.Fatal("health edit replaced existing transport")
		}
		previous = p
		deadline := time.Now().Add(3 * time.Second)
		checked := false
		for time.Now().Before(deadline) {
			states := e.GroupStatus()
			if len(states) > 0 && len(states[0].Results) > 0 && !states[0].Results[0].Checked.IsZero() {
				if states[0].Results[0].Alive != (rule != "204") {
					t.Fatal("wrong HTTP health classification", rule, states)
				}
				checked = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !checked {
			t.Fatal("health probe did not complete")
		}
	}
}

func TestRuntimeURLTestPinOverridesConfiguredMember(t *testing.T) {
	base, ds := compile.Compile([]byte(`schema-version: 1
outbounds: [{id: local, type: direct}, {id: alternate, type: direct}]
groups: [{id: health, type: url-test, members: [local, alternate], selected: local}]
rules: [{id: all, match: {all: true}, outbound: health}]
`), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	pinned := *base
	pinned.AutoGroups = slices.Clone(base.AutoGroups)
	pinned.AutoGroups[0].Selected = "alternate"

	e := NewEngine(EngineOptions{HostPacketFlow: true})
	defer e.Close()
	for i, tc := range []struct {
		eff  *compile.Effective
		want string
	}{
		{base, "local"},
		{&pinned, "alternate"},
		{base, "local"},
	} {
		p, err := e.Prepare(tc.eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Activate(p, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
		decision, err := e.Explain(t.Context(), ExplainRequest{Destination: "192.0.2.1:443"})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Outbound != tc.want {
			t.Fatalf("routed through %q, want %q", decision.Outbound, tc.want)
		}
	}
}
