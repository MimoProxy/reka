package generation

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/config/compile"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
