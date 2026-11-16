package importer

import (
	"strings"
	"testing"
)

const providerInput = `proxy-providers:
 one: {type: http, url: 'https://provider.example/one', interval: 30}
 two: {type: inline, payload: [{name: Same, type: direct}]}
 unused: {type: http, url: 'https://must-not-fetch.example'}
proxy-groups:
 - {name: Choice, type: select, use: [one, two]}
rules: ["MATCH,Choice"]
`

func TestProviderExpansionNamespacesAndUnused(t *testing.T) {
	req := request(providerInput)
	providers, err := Providers(req)
	if err != nil || len(providers) != 2 {
		t.Fatal(providers, err)
	}
	payloads := map[string][]byte{}
	for _, p := range providers {
		payloads[p.ID] = p.Inline
		if p.Type == "http" {
			payloads[p.ID] = []byte("proxies: [{name: Same, type: direct}]")
		}
	}
	result := ImportProviders(req, payloads)
	if !result.Report.CanApply {
		t.Fatal(result.Report)
	}
	src := snapshot(t, result)
	if len(src.Outbounds) != 2 || src.Outbounds[0].ID == src.Outbounds[1].ID || src.Outbounds[0].Name != "Same" || src.Outbounds[1].Name != "Same" {
		t.Fatal("provider identities", src)
	}
	_ = compileImport(t, result)
	if result.Report.Bindings[0].Provider == "" {
		t.Fatal("provider identity missing in report")
	}
}
func TestProviderMissingNestedAndUnsupported(t *testing.T) {
	for _, data := range []string{
		strings.Replace(providerInput, "use: [one, two]", "use: [missing]", 1),
		strings.Replace(providerInput, "type: http", "type: file", 1),
		strings.Replace(providerInput, "interval: 30", "interval: 1", 1),
		strings.Replace(providerInput, "interval: 30", "override: {unknown: true}", 1),
	} {
		if _, err := Providers(request(data)); err == nil {
			t.Fatal("invalid provider accepted")
		}
	}
	providers, _ := Providers(request(providerInput))
	payloads := map[string][]byte{providers[0].ID: []byte("proxy-providers: {again: {type: http}}\nproxies: [{name: A, type: direct}]"), providers[1].ID: providers[1].Inline}
	if result := ImportProviders(request(providerInput), payloads); result.Report.CanApply {
		t.Fatal("nested provider accepted")
	}
}
func TestRuleProviderLockedExecution(t *testing.T) {
	data := "proxies: [{name: route, type: direct}]\nrule-providers: {rules: {type: http, url: https://rules.example/list, behavior: domain, format: text}}\nrules: ['RULE-SET,rules,route','MATCH,route']"
	req := request(data)
	providers, err := Providers(req)
	if err != nil || len(providers) != 1 {
		t.Fatal(err)
	}
	payloads := map[string][]byte{providers[0].ID: []byte("example.org\n")}
	result := ImportProviders(req, payloads)
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatal("locked rule set unavailable", result.Report)
	}
	src := snapshot(t, result)
	if len(src.RuleSets) != 1 || src.RuleSets[0].Hash == "" {
		t.Fatal("missing resource pin", src)
	}
}
