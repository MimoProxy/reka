package compile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

func TestModuleRemoteRuleSets(t *testing.T) {
	const rules = "https://example.test/ads.list"
	const domains = "https://example.test/ads.txt"
	const moduleText = "[Rule]\n" +
		"RULE-SET," + rules + ",REJECT,update-interval=43200\n" +
		"DOMAIN-SET," + domains + ",REJECT\n" +
		"AND,((RULE-SET," + rules + "),(DEST-PORT,443)),DIRECT\n"
	const ruleList = "# ads\nDOMAIN,ads.example.test\nDEST-PORT,8443\nSCRIPT,unknown\n"
	const domainList = ".tracker.example.test\nexact.example.test\n"
	moduleHash, ruleHash, domainHash := resource.Hash([]byte(moduleText)), resource.Hash([]byte(ruleList)), resource.Hash([]byte(domainList))
	ruleRequest, domainRequest := resource.Hash([]byte(rules)), resource.Hash([]byte(domains))
	sources := fmt.Sprintf(`sources:
  - id: filter
    module: {format: surge, request: %s}
    lock:
      root: %s
      resources:
        - {id: %s, kind: rule-set, request: %s, hash: %s}
        - {id: %s, kind: domain-set, request: %s, hash: %s}
`, (model.Module{URL: moduleLocation}).RequestHash(), moduleHash, ruleRequest[:24], ruleRequest, ruleHash, domainRequest[:24], domainRequest, domainHash)
	opts := Options{Sources: []byte(sources), ReadResource: func(hash string) ([]byte, error) {
		switch hash {
		case moduleHash:
			return []byte(moduleText), nil
		case ruleHash:
			return []byte(ruleList), nil
		case domainHash:
			return []byte(domainList), nil
		}
		return nil, resource.ErrCorrupt
	}}
	eff := compileModule(t, moduleProfile+"rules: [{id: final, match: {all: true}, outbound: direct}]\n", opts)
	if report := eff.Modules["filter"]; report.Rules != (module.Count{Total: 3, Imported: 2, Unavailable: 1}) {
		t.Fatalf("module rules = %+v, lines %+v", report.Rules, report.Lines)
	}
	for _, tc := range []struct {
		domain string
		port   uint16
		want   string
	}{
		{"ads.example.test", 80, "reject"},
		{"other.example.test", 8443, "reject"},
		{"tracker.example.test", 80, "reject"},
		{"a.tracker.example.test", 80, "reject"},
		{"exact.example.test", 80, "reject"},
		{"a.exact.example.test", 80, "direct"},
		{"other.example.test", 80, "direct"},
	} {
		if got := eff.Router.Route(t.Context(), router.Metadata{Domain: tc.domain, Port: tc.port}, nil); got.Outbound != tc.want {
			t.Errorf("%s:%d routes to %q, want %q", tc.domain, tc.port, got.Outbound, tc.want)
		}
	}
	for _, line := range eff.Modules["filter"].Lines {
		if line.Line == 4 && !strings.Contains(line.Message, "nested") {
			t.Errorf("nested remote rule set = %+v", line)
		}
	}

	// A module whose list is not downloaded yet keeps its other rules.
	missing := strings.Replace(sources, "kind: domain-set", "kind: map-local", 1)
	opts.Sources = []byte(missing)
	eff = compileModule(t, moduleProfile, opts)
	if report := eff.Modules["filter"]; !report.CanApply || report.Rules.Imported != 1 {
		t.Fatalf("module with a missing list = %+v", report)
	}
}
