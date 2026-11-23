package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const fixtureSRSPath = "/gh/MetaCubeX/meta-rules-dat@sing/geo/"

func srsFixture(t *testing.T, rule option.DefaultHeadlessRule) []byte {
	t.Helper()
	var data bytes.Buffer
	if err := srs.Write(&data, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestPrepareDefaultGeodataUsesPerCodeSRS(t *testing.T) {
	server, _ := newGeodataFixture(t)
	for path, rule := range map[string]option.DefaultHeadlessRule{
		"geosite/cn.srs":        {DomainSuffix: []string{"example.cn"}},
		"geosite/google@cn.srs": {Domain: []string{"region.google.test"}},
		"geoip/cn.srs":          {IPCIDR: []string{"192.0.2.0/24"}},
		"geoip/private.srs":     {IPCIDR: []string{"100.64.0.0/10"}},
	} {
		server.bodies[fixtureSRSPath+path] = srsFixture(t, rule)
	}
	const raw = `schema-version: 1
rules:
  - {match: {geosite: [CN, 'google@CN']}, outbound: reject}
  - {match: {rule-set: 'geoip:LAN'}, outbound: reject}
  - {match: {geoip: [PRIVATE, CN, LAN]}, outbound: reject}
`
	cache := t.TempDir()
	options := PrepareOptions{}
	bundle := mustPrepareGeodata(t, raw, cache, options, server)
	p, _, ds := model.ParseProfile(bundle.Profile)
	if ds.HasErrors() || bundle.Precompiled != nil || len(bundle.Resources) != 4 || len(bundle.Summary.Resources) != 2 {
		t.Fatalf("expected four raw SRS files grouped by kind, got resources %d, cache %v, diagnostics %v", len(bundle.Resources), bundle.Precompiled, ds)
	}
	if len(p.Geodata) != 5 {
		t.Fatalf("expected five locked selectors, got %+v", p.Geodata)
	}
	wantFiles := map[string]string{
		"geosite:cn": "geosite/cn.srs", "geosite:google@cn": "geosite/google@cn.srs", "geoip:cn": "geoip/cn.srs",
		"geoip:lan": "geoip/private.srs", "geoip:private": "geoip/private.srs",
	}
	for _, db := range p.Geodata {
		want := server.bodies[fixtureSRSPath+wantFiles[db.ID]]
		if db.Format != "srs" || db.Download != nil || len(want) == 0 || !bytes.Equal(want, bundle.Resources[db.Hash]) {
			t.Fatalf("unexpected locked selector %+v", db)
		}
	}
	for _, asset := range bundle.Summary.Resources {
		want := []string{"cn", "google@cn"}
		if asset.Name == "geoip" {
			want = []string{"cn", "lan", "private"}
		}
		if asset.ID != "geodata/"+asset.Name || !asset.Shared || !asset.Automatic || !slices.Equal(asset.Codes, want) ||
			asset.URL != geodataSRSURL+asset.Name+"/{code}.srs" || asset.Size == 0 || asset.NextMS <= asset.UpdatedMS {
			t.Fatalf("unexpected resource summary: %+v", asset)
		}
	}
	snapshot, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := CompileSnapshot(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"child.example.cn": "reject", "region.google.test": "reject", "other.google.test": "direct"} {
		if got := eff.Router.Route(t.Context(), router.Metadata{Domain: name}, nil).Outbound; got != want {
			t.Errorf("%s routed to %q, want %q", name, got, want)
		}
	}
	assertIPRoutes(t, bundle, map[string]string{"100.64.0.1": "reject", "192.0.2.1": "reject", "127.0.0.1": "reject", "203.0.113.1": "direct"})
	mustPrepareGeodata(t, raw, cache, options, server)
	if len(sharedState(t, cache)) != 4 || len(server.requests) != 4 {
		t.Fatalf("unexpected downloads or shared cache entries: %v", server.requests)
	}
	for path, count := range server.requests {
		if count != 1 {
			t.Errorf("expected to download %s once, got %d", path, count)
		}
	}
}

func TestPrepareSRSTemplateRefreshesEachCodeConditionally(t *testing.T) {
	server, options := newGeodataFixture(t)
	options.GeodataSources["geosite"] = geodataFixtureHost + "/sets/%7Bcode%7D.srs"
	a, b := "/sets/test.srs", "/sets/test@cn.srs"
	server.bodies[a] = srsFixture(t, option.DefaultHeadlessRule{Domain: []string{"one.test"}})
	server.bodies[b] = srsFixture(t, option.DefaultHeadlessRule{Domain: []string{"two.test"}})
	server.etags, server.checks = map[string]string{a: `"one"`, b: `"two"`}, map[string]int{}
	const raw = `schema-version: 1
rules: [{match: {geosite: [test, 'test@cn']}, outbound: reject}]
`
	cache := t.TempDir()
	mustPrepareGeodata(t, raw, cache, options, server)
	ageSharedState(t, cache, 2*geodataRefreshWindow)
	options.RefreshAsset = "geodata/geosite"
	bundle := mustPrepareGeodata(t, raw, cache, options, server)
	mustPrepareGeodata(t, raw, cache, options, server)
	if server.requests[a] != 2 || server.requests[b] != 2 || server.checks[a] != 1 || server.checks[b] != 1 {
		t.Fatalf("codes did not retain separate HTTP validators: %v, %v", server.requests, server.checks)
	}
	assertRoute(t, bundle, "one.test", "reject")
	assertRoute(t, bundle, "two.test", "reject")

	server.etags[b] = ""
	server.status = map[string]int{b: http.StatusNotFound}
	ageSharedState(t, cache, 2*geodataRefreshWindow)
	_, err := prepareGeodataFixture(t, raw, cache, options, server)
	var invalid *ValidationError
	if !errors.As(err, &invalid) || len(invalid.Diagnostics) != 1 || invalid.Diagnostics[0].Path != "geodata/geosite/test@cn" ||
		!strings.Contains(invalid.Diagnostics[0].Message, "geosite:test@cn SRS file not found (HTTP 404)") {
		t.Fatalf("expected a diagnostic naming the missing code, got %#v", err)
	}
}

func TestPrepareClashUsesSRSProviderAndGeodata(t *testing.T) {
	server, _ := newGeodataFixture(t)
	server.bodies[fixtureSRSPath+"geosite/google@cn.srs"] = srsFixture(t, option.DefaultHeadlessRule{DomainSuffix: []string{"google.test"}})
	server.bodies[fixtureSRSPath+"geoip/cn.srs"] = srsFixture(t, option.DefaultHeadlessRule{IPCIDR: []string{"192.0.2.0/24"}})
	server.bodies["/provider.srs"] = srsFixture(t, option.DefaultHeadlessRule{Domain: []string{"provider.test"}, Network: []string{"udp"}})
	raw := fmt.Sprintf(`rule-providers:
  example: {type: http, url: %s/provider.srs, format: srs, behavior: classical}
rules: ['GEOSITE,google@CN,REJECT', 'GEOIP,CN,REJECT,no-resolve', 'RULE-SET,example,REJECT']
`, geodataFixtureHost)
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), PrepareOptions{}, server)
	p, _, ds := model.ParseProfile(bundle.Profile)
	if ds.HasErrors() || len(p.RuleSets) != 3 || bundle.Precompiled != nil || len(bundle.Resources) != 3 {
		t.Fatalf("unexpected prepared subscription: %s, %v", bundle.Profile, ds)
	}
	for _, def := range p.RuleSets {
		if def.Format != "srs" || resource.Hash(bundle.Resources[def.Hash]) != def.Hash {
			t.Fatalf("unexpected imported rule set: %+v", def)
		}
	}
	assertRoute(t, bundle, "sub.google.test", "reject")
	assertIPRoutes(t, bundle, map[string]string{"192.0.2.1": "reject", "203.0.113.1": "direct"})
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	for net, want := range map[string]string{"tcp": "direct", "udp": "reject"} {
		if got := eff.Router.Route(t.Context(), router.Metadata{Domain: "provider.test", Network: net}, nil).Outbound; got != want {
			t.Errorf("%s routed to %q, want %q", net, got, want)
		}
	}
}
