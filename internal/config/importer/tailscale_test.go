package importer

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestClashTailscaleReferences(t *testing.T) {
	const input = `proxies:
  - name: Tailnet
    type: tailscale
    udp: true
    auth-key: discarded-test-key
    control-url: https://discarded.example
    state-dir: /discarded-state
    hostname: discarded-host
    ephemeral: false
    accept-routes: true
    exit-node: discarded-exit
    exit-node-allow-lan-access: true
  - {name: TCP, type: tailscale}
proxy-groups:
  - {name: Choose, type: select, proxies: [Tailnet, TCP]}
rules:
  - MATCH,Choose
`
	r := Import(request(input))
	if !r.Report.CanApply || r.Report.Partial || r.Report.Nodes.Imported != 2 || r.Report.Groups.Imported == 0 || r.Report.Rules.Imported != 1 {
		t.Fatal("Tailscale references or their dependents were dropped")
	}
	for _, key := range strings.Fields("auth-key control-url state-dir hostname ephemeral accept-routes exit-node exit-node-allow-lan-access") {
		path := "/proxies/#0/" + key
		if !slices.Contains(r.Report.Ignored, path) || !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
			return d.Path == path && d.Severity == model.SeverityWarning && strings.Contains(d.Message, "on this device")
		}) {
			t.Errorf("missing warning for %s", key)
		}
	}
	preview, err := json.Marshal(r.Preview(true))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Source), "discarded") || strings.Contains(string(preview), "discarded") {
		t.Fatal("import exposed a device setting in the source, preview, or report")
	}
	eff := compileImport(t, r)
	for _, item := range []struct {
		name string
		udp  bool
	}{{"Tailnet", true}, {"TCP", false}} {
		o, ok := eff.Outbound("airport/" + StableID("p", item.name))
		if !ok || o.Type != model.OutboundTailscale || o.UDP != item.udp || o.Tailscale != nil {
			t.Errorf("incorrect Tailscale reference for %s", item.name)
		}
	}
}
