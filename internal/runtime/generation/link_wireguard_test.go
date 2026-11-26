package generation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestWireGuardLinkDiagnosticsAndReload(t *testing.T) {
	const profile = `schema-version: 1
outbounds:
  - id: home-wg
    type: wireguard
    server: home.example.com
    port: 51820
    protocol:
      private-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
      public-key: Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=
      address: [192.0.2.1/32]
`
	const local = `routing: {mode: global, global: direct}
link:
  wireguard:
    - outbound: home-wg
      routes: [%s]
`
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	t.Cleanup(func() { e.Close() })
	for i, tc := range []struct{ route, oldDestinationOutbound string }{
		{"10.0.0.0/24", "home-wg"},
		{"10.0.1.0/24", "direct"},
	} {
		eff, ds := compile.Compile([]byte(profile), []byte(fmt.Sprintf(local, tc.route)), compile.Options{OmitProvenance: true})
		if eff == nil || ds.HasErrors() {
			t.Fatal(ds)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if !p.Plan().RulesChanged {
			e.Abort(p)
			t.Fatal("route edit did not trigger a rules reload")
		}
		if _, err := e.Activate(p, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
		page := e.RulesPage(0, 10)
		const source = "local.yaml /link/wireguard/#0"
		if page.Mode != "global" || page.Total != 2 || len(page.Rules) != 2 || page.Rules[0].Outbound != "home-wg" ||
			page.Rules[0].Payload != tc.route || page.Rules[0].Context != source || !strings.Contains(page.Rules[0].Description, source) || page.Rules[1].Type != "MATCH" {
			t.Fatalf("unexpected global rules diagnostics: %+v", page)
		}
		explained, err := e.Explain(t.Context(), ExplainRequest{Destination: "10.0.0.10:443"})
		if err != nil || explained.Outbound != tc.oldDestinationOutbound {
			t.Fatalf("unexpected explanation after activation: %+v, %v", explained, err)
		}
		if i == 0 && (!explained.Matched || explained.RuleIndex != 0 || explained.RuleID != page.Rules[0].ID || !strings.Contains(explained.RuleSource, source)) {
			t.Fatalf("expected the local rule origin in the explanation: %+v", explained)
		}
	}
}
