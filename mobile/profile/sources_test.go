package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

const clashSourceFixture = `
proxies:
  - {name: First Node, type: direct}
  - {name: Second Node, type: socks5, server: second.example.test, port: 1080}
proxy-groups:
  - {name: Choice, type: select, proxies: [First Node, Second Node]}
rules: ["MATCH,Choice"]
`

const nodeSourceImport = `schema-version: 1
imports:
  - {source: s-test, outbounds: true}
`

func prepareSourceFixture(t *testing.T, raw string, options PrepareOptions) (*Bundle, string) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "snapshot.json")
	writeFixtureFile(t, input, []byte(raw))
	if err := PrepareFileWithOptions(t.Context(), input, output, dir, options); err != nil {
		var validation *ValidationError
		if errors.As(err, &validation) {
			t.Fatalf("%s: %v", validation, validation.Diagnostics)
		}
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, output
}

func TestPrepareImportsSubscriptionNodesAndGroups(t *testing.T) {
	first := importer.StableID("p", "First Node")
	second := importer.StableID("p", "Second Node")
	choice := importer.StableID("g", "Choice")
	source, sourcePath := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{Overlay: json.RawMessage(fmt.Sprintf(`{
		"schema-version":1,"patches":[{"op":"set","path":"/outbounds/%s/name","value":"Renamed"}]
	}`, first))})
	if source.Summary.Names[first] != "Renamed" {
		t.Fatal("the subscription fixture did not apply its overlay")
	}
	first, second, choice = "s-test/"+first, "s-test/"+second, "s-test/"+choice
	var options PrepareOptions
	if err := json.Unmarshal(fmt.Appendf(nil, `{
		"sources":{"s-test":%q},
		"overlay":{"schema-version":1,"patches":[
			{"op":"set","path":"/groups/missing/selected","value":"direct"},
			{"op":"set","path":%q,"value":%q}
		]}
	}`, sourcePath, model.JoinPath("/groups", choice, "selected"), second), &options); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`schema-version: 1
imports: [{source: s-test, outbounds: true, groups: true}]
groups:
  - {id: local, type: select, members: [%s, %s]}
rules:
  - {match: {all: true}, outbound: local}
`, first, choice)
	bundle, _ := prepareSourceFixture(t, raw, options)
	checkPatchStatuses(t, bundle.Summary.Patches, "overlay.path", "")
	sources, _, diagnostics := model.ParseSources(bundle.Sources)
	if diagnostics.HasErrors() || sources.SchemaVersion != model.SchemaVersion || len(sources.Sources) != 1 {
		t.Fatalf("missing source document: %s (%v)", bundle.Sources, diagnostics)
	}
	// Only the imported nodes and groups are packed; the subscription's rules stay out.
	if src := sources.Sources[0]; src.ID != "s-test" || src.DNS != nil || len(src.Rules) != 0 || len(src.Groups) != 1 {
		t.Fatalf("unexpected source snapshot: %+v", src)
	}

	base, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range []Summary{bundle.Summary, Describe(base)} {
		if len(summary.Outbounds) != 2 || summary.Names[first] != "First Node" || summary.Names[second] != "Second Node" {
			t.Fatalf("imported nodes lost their IDs or names: %+v", summary)
		}
		for _, id := range []string{first, second} {
			if !slices.ContainsFunc(summary.Outbounds, func(node Node) bool { return node.ID == id }) {
				t.Fatalf("missing outbound %q in %+v", id, summary.Outbounds)
			}
		}
		i := slices.IndexFunc(summary.Groups, func(group Group) bool { return group.ID == choice })
		if i < 0 || summary.Names[choice] != "Choice" || summary.Groups[i].Selected != second ||
			!slices.Equal(summary.Groups[i].Members, []string{first, second}) {
			t.Fatalf("imported group lost its ID, name or members: %+v", summary)
		}
	}
	controlled, err := ApplyControls(base, Describe(base), Controls{Mode: "rule", Selections: map[string]string{"local": choice}})
	if err != nil {
		t.Fatal(err)
	}
	if got := controlled.Router.Route(t.Context(), router.Metadata{Domain: "example.test"}, nil); got.Outbound != second {
		t.Fatalf("controlled route chose %q, want %q", got.Outbound, second)
	}
}

func TestPrepareReportsMissingSource(t *testing.T) {
	_, err := prepare(t.Context(), []byte(nodeSourceImport), nil)
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Diagnostics) != 1 {
		t.Fatalf("expected one compiler diagnostic, got %v", err)
	}
	d := validation.Diagnostics[0]
	if d.Code != "source.missing" || d.Document != model.DocProfile || d.Path != "/imports/#0/source" || d.Line != 3 || d.Column == 0 ||
		d.Message != "unknown source s-test" {
		t.Fatalf("unexpected diagnostic: %+v", d)
	}
}

func TestPrepareIgnoresUnusedSources(t *testing.T) {
	options := PrepareOptions{Sources: map[string]string{"s-test": filepath.Join(t.TempDir(), "missing.json")}}
	for _, raw := range []string{"schema-version: 1\n", clashSourceFixture + "imports: [{source: s-test, outbounds: true}]\n"} {
		bundle, _ := prepareSourceFixture(t, raw, options)
		if len(bundle.Sources) != 0 {
			t.Fatalf("unexpected source document: %s", bundle.Sources)
		}
	}
}

func TestPrepareImportsSubscriptionRuleResources(t *testing.T) {
	const subscription = `
proxies: [{name: Subscription Node, type: direct}]
rule-providers:
  blocked:
    type: inline
    behavior: classical
    payload: ["DOMAIN-SUFFIX,blocked.test", "GEOSITE,test"]
rules: ["RULE-SET,blocked,REJECT"]
`
	server, geodataOptions := newGeodataFixture(t)
	source := mustPrepareGeodata(t, subscription, t.TempDir(), geodataOptions, server)
	if source.Precompiled == nil || len(source.Precompiled.Sets) != 2 || len(source.Resources) != 4 {
		t.Fatalf("expected both source rule sets and their precompiled forms, got %d resources", len(source.Resources))
	}
	want := maps.Clone(source.Resources)
	for _, hash := range source.Precompiled.Sets {
		delete(want, hash)
	}
	unused := []byte("unused.test\n")
	source.Resources[resource.Hash(unused)] = unused
	options := PrepareOptions{Sources: map[string]string{"s-test": writeSourceBundle(t, source)}}

	nodes, _ := prepareSourceFixture(t, nodeSourceImport, options)
	if len(nodes.Resources) != 0 {
		t.Fatalf("node import retained %d rule resources", len(nodes.Resources))
	}
	raw := fmt.Sprintf(`schema-version: 1
imports: [{source: s-test, rule-sets: true}]
rules:
  - {match: {rule-set: s-test/%s}, outbound: reject}
  - {match: {all: true}, outbound: direct}
`, importer.StableID("rule", "blocked"))
	bundle, snapshot := prepareSourceFixture(t, raw, options)
	if bundle.Precompiled == nil || len(bundle.Precompiled.Sets) != 2 || len(bundle.Resources) != 4 {
		t.Fatalf("expected both imported rule sets and their precompiled forms, got %d resources", len(bundle.Resources))
	}
	for hash, data := range want {
		if !bytes.Equal(bundle.Resources[hash], data) {
			t.Fatal("an original imported resource is missing")
		}
	}
	assertRoute(t, bundle, "sub.blocked.test", "reject")
	assertRoute(t, bundle, "sub.suffix.test", "reject")
	assertRoute(t, bundle, "other.test", "direct")

	marked, _ := prepareSourceFixture(t, nodeSourceImport+"rules: [{source: s-test}]\n", options)
	assertRoute(t, marked, "sub.suffix.test", "reject")

	if err := os.Remove(options.Sources["s-test"]); err != nil {
		t.Fatal(err)
	}
	options.RebindSnapshot = snapshot
	rebound, _ := prepareSourceFixture(t, raw, options)
	if !bytes.Equal(rebound.Sources, bundle.Sources) || !maps.EqualFunc(rebound.Resources, bundle.Resources, bytes.Equal) {
		t.Fatal("the archive did not preserve the sources and rule resources")
	}
	assertRoute(t, rebound, "sub.suffix.test", "reject")

	server.bodies["/geosite.dat"] = bytes.ReplaceAll(server.bodies["/geosite.dat"], []byte("suffix.test"), []byte("second.test"))
	updated := mustPrepareGeodata(t, subscription, t.TempDir(), geodataOptions, server)
	options.Sources["s-test"] = writeSourceBundle(t, updated)
	options.RefreshSources = true
	refreshed, _ := prepareSourceFixture(t, raw, options)
	if refreshed.Precompiled == nil || len(refreshed.Precompiled.Sets) != 2 || len(refreshed.Resources) != 4 ||
		maps.Equal(refreshed.Precompiled.Sets, rebound.Precompiled.Sets) {
		t.Fatal("the imported provider was not recompiled")
	}
	assertRoute(t, refreshed, "sub.blocked.test", "reject")
	assertRoute(t, refreshed, "sub.second.test", "reject")
	assertRoute(t, refreshed, "sub.suffix.test", "direct")
	before, err := rebound.Compile()
	if err != nil {
		t.Fatal(err)
	}
	after, err := refreshed.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if before.RulesFingerprint == after.RulesFingerprint {
		t.Fatal("the cached provider fingerprint missed its updated dependency")
	}
}

func TestPrepareRejectsUnreadableSourceBundles(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	writeFixtureFile(t, corrupt, []byte("{broken"))
	oversized := filepath.Join(dir, "oversized.json")
	writeFixtureFile(t, oversized, nil)
	if err := os.Truncate(oversized, MaxBundleBytes+1); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing": filepath.Join(dir, "missing.json"), "corrupt": corrupt, "directory": dir, "oversized": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			p := &preparer{options: PrepareOptions{Sources: map[string]string{"s-test": path}}}
			if _, err := prepare(t.Context(), []byte(nodeSourceImport), p); err == nil || !strings.Contains(err.Error(), "cannot read source s-test") {
				t.Fatalf("expected an error identifying the source, got %v", err)
			}
		})
	}
}

func TestRebindKeepsOverlayPinnedSourceResource(t *testing.T) {
	const subscription = `rule-providers:
  blocked: {type: inline, behavior: domain, payload: [old.test]}
rules: ["RULE-SET,blocked,REJECT"]
`
	first, oldPath := prepareSourceFixture(t, subscription, PrepareOptions{})
	_, nextPath := prepareSourceFixture(t, strings.ReplaceAll(subscription, "old.test", "new.test"), PrepareOptions{})
	source, _, diagnostics := model.ParseProfile(first.Profile)
	if diagnostics.HasErrors() || len(source.RuleSets) != 1 {
		t.Fatal("expected one locked provider", diagnostics)
	}
	def := source.RuleSets[0]
	id := "s-test/" + def.ID
	overlay := json.RawMessage(fmt.Appendf(nil, `{"schema-version":1,"patches":[{"op":"set","path":%q,"value":%q}]}`,
		model.JoinPath("/rule-sets", id, "hash"), def.Hash))
	raw := fmt.Sprintf("schema-version: 1\nimports: [{source: s-test, rule-sets: true}]\nrules: [{match: {rule-set: %s}, outbound: reject}]\n", id)
	opts := PrepareOptions{Sources: map[string]string{"s-test": oldPath}, Overlay: overlay}
	_, archive := prepareSourceFixture(t, raw, opts)
	opts.Sources["s-test"] = nextPath
	opts.RebindSnapshot, opts.RefreshSources = archive, true
	refreshed, _ := prepareSourceFixture(t, raw, opts)
	if refreshed.Precompiled == nil || refreshed.Resources[def.Hash] == nil {
		t.Fatal("source refresh removed the pinned original")
	}
	refreshed.Precompiled = nil
	assertRoute(t, refreshed, "old.test", "reject")
	assertRoute(t, refreshed, "new.test", "direct")
}

func TestPrepareBoundsCombinedSourceResources(t *testing.T) {
	options := PrepareOptions{Sources: make(map[string]string)}
	for _, id := range []string{"s-first", "s-second"} {
		line := []byte("# " + id + " " + strings.Repeat("x", 60) + "\n")
		data := bytes.Repeat(line, MaxBundleBytes/2/len(line))
		data = append(data, "192.0.2.0/24\n"...)
		hash := resource.Hash(data)
		bundle := &Bundle{
			Version: bundleVersion, Resources: map[string][]byte{hash: data},
			Profile: json.RawMessage(fmt.Sprintf(`{"schema-version":1,"rule-sets":[{"id":"sites","behavior":"ipcidr","format":"text","hash":%q}]}`, hash)),
		}
		options.Sources[id] = writeSourceBundle(t, bundle)
	}
	raw := []byte(`schema-version: 1
imports:
  - {source: s-first, rule-sets: true}
  - {source: s-second, rule-sets: true}
`)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "prepared.json")
	writeFixtureFile(t, input, raw)
	if err := PrepareFileWithOptions(t.Context(), input, output, dir, options); !errors.Is(err, errBundleTooLarge) {
		t.Fatalf("expected a combined source size error, got %v", err)
	}
}

func writeSourceBundle(t *testing.T, bundle *Bundle) string {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source.json")
	writeFixtureFile(t, path, data)
	return path
}

func TestRebindRefreshesImportedSources(t *testing.T) {
	const updated = `
proxies: [{name: Renamed Node, type: direct}]
proxy-groups: [{name: Choice, type: select, proxies: [Renamed Node]}]
rules: ["MATCH,Choice"]
`
	first, _ := prepareSourceFixture(t, clashSourceFixture, PrepareOptions{})
	options := PrepareOptions{Sources: map[string]string{"s-test": writeSourceBundle(t, first)}}
	raw := `schema-version: 1
imports: [{source: s-test, outbounds: true, groups: true}]
rules: [{match: {all: true}, outbound: s-test/` + importer.StableID("g", "Choice") + `}]
`
	original, snapshot := prepareSourceFixture(t, raw, options)

	second, _ := prepareSourceFixture(t, updated, PrepareOptions{})
	options = PrepareOptions{Sources: map[string]string{"s-test": writeSourceBundle(t, second)},
		RebindSnapshot: snapshot, RefreshSources: true}
	rebound, _ := prepareSourceFixture(t, raw, options)
	names := slices.Collect(maps.Values(rebound.Summary.Names))
	if !slices.Contains(names, "Renamed Node") || slices.Contains(names, "First Node") {
		t.Fatalf("the rebind kept the old source: %v", names)
	}

	options.RefreshSources = false
	if err := os.Remove(options.Sources["s-test"]); err != nil {
		t.Fatal(err)
	}
	archived, _ := prepareSourceFixture(t, raw, options)
	if !bytes.Equal(archived.Sources, original.Sources) || bytes.Equal(original.Sources, rebound.Sources) {
		t.Fatal("a rebind without refresh changed the archived sources")
	}
}
