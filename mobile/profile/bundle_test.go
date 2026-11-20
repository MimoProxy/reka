package profile

import (
	"context"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
)

func TestClashProfileControlsUseCompiledRules(t *testing.T) {
	raw := []byte(`
proxies:
  - {name: Node A, type: ss, server: a.example.test, port: 443, cipher: aes-128-gcm, password: example-a}
  - {name: Node B, type: ss, server: b.example.test, port: 443, cipher: aes-128-gcm, password: example-b}
proxy-groups:
  - {name: Main, type: select, proxies: [Node A, Node B]}
  - {name: Services, type: select, proxies: [Main, DIRECT]}
rules:
  - DOMAIN-SUFFIX,local.example.test,DIRECT
  - DOMAIN-SUFFIX,example.test,Services
  - MATCH,Main
`)
	ctx := context.Background()
	bundle, err := prepare(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	summary, ruleSet := bundle.Summary, eff.Router.Rules()
	mainGroup, services := summary.Groups[0], summary.Groups[1]
	updated, err := ApplyControls(eff, summary, Controls{Mode: "rule", Selections: map[string]string{"Main": "Node B"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Router.Rules() != ruleSet {
		t.Fatal("selection rebuilt the rule index")
	}
	decision := updated.RoutingRouter().Route(ctx, router.Metadata{Domain: "service.example.test", Network: "tcp"}, nil)
	if decision.Target != services.ID || decision.Outbound != mainGroup.Members[1] {
		t.Fatalf("selection not applied: %#v", decision)
	}
	decision = updated.RoutingRouter().Route(ctx, router.Metadata{Domain: "host.local.example.test", Network: "tcp"}, nil)
	if decision.Outbound != "direct" {
		t.Fatalf("first matching rule lost priority: %#v", decision)
	}
}
