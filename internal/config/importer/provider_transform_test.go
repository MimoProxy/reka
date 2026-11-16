package importer

import "testing"

func TestProviderFiltersOverridesAndPriority(t *testing.T) {
	req := request("proxy-providers:\n one:\n  type: inline\n  filter: 'US`HK'\n  exclude-filter: 'bad'\n  payload: [{name: HK-good, type: direct}, {name: US-good, type: direct}, {name: HK-bad, type: direct}]\n  override:\n   tfo: true\n   proxy-name: [{pattern: '-good$', target: '-ok'}]\n   additional-prefix: 'P-'\n   override-expr: ['.name |= upcase']\nproxy-groups: [{name: Choice, type: select, use: [one]}]\nrules: ['MATCH,Choice']")
	r := Import(req)
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	out := snapshot(t, r).Outbounds
	if len(out) != 2 || out[0].Name != "P-US-OK" || out[1].Name != "P-HK-OK" || out[0].Dialer == nil || !out[0].Dialer.TFO {
		t.Fatal(out)
	}
	compileImport(t, r)
}
func TestProviderHTTPFallbackAndFileAreExplicitBundles(t *testing.T) {
	for _, kind := range []string{"http", "file"} {
		req := request("proxy-providers: {one: {type: " + kind + ", path: nodes.yaml, url: https://nodes.test/list, payload: [{name: fallback, type: direct}]}}\nproxy-groups: [{name: Choice, type: select, use: [one]}]")
		ps, err := Providers(req)
		if err != nil || len(ps) != 1 || len(ps[0].Fallback) == 0 {
			t.Fatal(ps, err)
		}
		if Import(req).Report.CanApply {
			t.Fatal("network/file import ran without an explicit bundle")
		}
		r := ImportProviders(req, map[string][]byte{ps[0].ID: ps[0].Fallback})
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		compileImport(t, r)
	}
}
