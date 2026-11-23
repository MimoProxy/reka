package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestCompileSnapshotUsesPrecompiledGeoSiteSelectors(t *testing.T) {
	server, options := newGeodataFixture(t)
	const raw = `schema-version: 1
outbounds: [{id: all-sites, type: direct}]
rules:
 - {match: {geosite: "test@cn"}, outbound: reject}
 - {match: {geosite: test}, outbound: all-sites}
`
	bundle := mustPrepareGeodata(t, raw, t.TempDir(), options, server)
	if bundle.Precompiled == nil || bundle.Precompiled.Version != 1 || len(bundle.Precompiled.Sets) != 2 {
		t.Fatal("expected both selectors in the version 1 precompiled manifest")
	}
	dat := lockedGeodata(t, bundle)["geosite"]
	digest := resource.Hash(dat)
	if !bytes.Equal(bundle.Resources[digest], dat) {
		t.Fatal("the original resource is missing")
	}
	original, _ := json.Marshal(dat)
	for _, mode := range []string{"current", "absent", "wrong-manifest-version", "wrong-resource-version", "missing-blob", "bad-digest"} {
		t.Run(mode, func(t *testing.T) {
			b := *bundle
			b.Resources = maps.Clone(b.Resources)
			b.Precompiled = &precompiledRuleSets{b.Precompiled.Version, maps.Clone(b.Precompiled.Sets)}
			switch mode {
			case "absent":
				b.Precompiled = nil
			case "wrong-manifest-version":
				b.Precompiled.Version++
			case "wrong-resource-version", "missing-blob", "bad-digest":
				for key, hash := range b.Precompiled.Sets {
					data := bytes.Clone(b.Resources[hash])
					delete(b.Resources, hash)
					if mode == "missing-blob" {
						continue
					}
					data[3]++
					if mode == "wrong-resource-version" {
						hash = resource.Hash(data)
						b.Precompiled.Sets[key] = hash
					}
					b.Resources[hash] = data
				}
			}
			snapshot, err := json.Marshal(&b)
			if err != nil {
				t.Fatal(err)
			}
			badSource := bytes.Replace(snapshot, original, []byte(`"!"`), 1)
			if bytes.Equal(badSource, snapshot) {
				t.Fatal("could not replace the source payload")
			}
			if mode == "current" {
				snapshot = badSource // This compiles only if no raw resource is read.
			} else if _, err := CompileSnapshot(badSource, nil); err == nil {
				t.Fatal("expected compilation to fall back to the invalid source")
			}
			eff, err := CompileSnapshot(snapshot, nil)
			if err != nil {
				t.Fatal(err)
			}
			clear(snapshot)
			for name, want := range map[string]string{"x.suffix.test": "reject", "exact.test": "all-sites", "regex123.test": "all-sites", "outside.test": "direct"} {
				if got := eff.Router.Route(t.Context(), router.Metadata{Domain: name}, nil).Outbound; got != want {
					t.Errorf("%s routed to %s, want %s", name, got, want)
				}
			}
		})
	}
}

func TestSnapshotBudgetKeepsOriginalResources(t *testing.T) {
	original := bytes.Repeat([]byte{'b'}, MaxBundleBytes*3/4-3072)
	large := bytes.Repeat([]byte{'l'}, 4096)
	small := []byte("small cache")
	originalHash, largeHash, smallHash := resource.Hash(original), resource.Hash(large), resource.Hash(small)
	largeKey, smallKey := resource.Hash([]byte("large")), resource.Hash([]byte("small"))
	b := &Bundle{
		Version: bundleVersion,
		Profile: json.RawMessage(`{"schema-version":1}`),
		Resources: map[string][]byte{
			originalHash: original, largeHash: large, smallHash: small,
		},
		Precompiled: &precompiledRuleSets{Version: 1, Sets: map[string]string{largeKey: largeHash, smallKey: smallHash}},
	}
	data, _, err := marshalPreparedBundle(b)
	if err != nil || len(data) > MaxBundleBytes {
		t.Fatal("snapshot does not fit", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Resources[originalHash], original) || got.Resources[largeHash] != nil ||
		!bytes.Equal(got.Resources[smallHash], small) || got.Precompiled == nil ||
		!maps.Equal(got.Precompiled.Sets, map[string]string{smallKey: smallHash}) {
		t.Fatal("trimming the derived cache changed the original resources")
	}
}

func TestSnapshotBudgetUsesSmallerArtifactsAndOriginals(t *testing.T) {
	large := bytes.Repeat([]byte{'a'}, MaxBundleBytes*3/4)
	small := []byte("small original")
	tinyCache := []byte("small cache")
	largeCache := bytes.Repeat([]byte{'b'}, len(large))
	largeHash, smallHash := resource.Hash(large), resource.Hash(small)
	tinyCacheHash, largeCacheHash := resource.Hash(tinyCache), resource.Hash(largeCache)
	largeKey, smallKey := resource.Hash([]byte("large")), resource.Hash([]byte("small"))
	b := &Bundle{
		Version: bundleVersion,
		Profile: json.RawMessage(`{"schema-version":1}`),
		Resources: map[string][]byte{
			largeHash: large, smallHash: small, tinyCacheHash: tinyCache, largeCacheHash: largeCache,
		},
		Precompiled: &precompiledRuleSets{Version: router.PrecompiledRuleSetVersion, Sets: map[string]string{
			largeKey: tinyCacheHash, smallKey: largeCacheHash,
		}},
		precompiledCoverage: map[string][]string{largeHash: {largeKey}, smallHash: {smallKey}},
	}
	data, omitted, err := marshalPreparedBundle(b)
	if err != nil || len(data) > MaxBundleBytes || !slices.Equal(omitted, []string{largeHash}) {
		t.Fatalf("expected to omit only the large original, got %v, %v", omitted, err)
	}
	fitted, err := Decode(data)
	if err != nil || !maps.EqualFunc(fitted.Resources, map[string][]byte{smallHash: small, tinyCacheHash: tinyCache}, bytes.Equal) {
		t.Fatal("snapshot did not keep the smaller original and required artifact", err)
	}
}

func largeGeoSite(t *testing.T, name, attrName string) []byte {
	t.Helper()
	field := func(data []byte, number protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(data, number, protowire.BytesType), value)
	}
	entry := func(name string) []byte {
		data := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 3) // Exact domain.
		return field(data, 2, []byte(name))
	}
	category := field(nil, 1, []byte("test"))
	category = field(category, 2, entry(name))
	category = field(category, 2, field(entry(attrName), 3, field(nil, 1, []byte("cn"))))
	// Padding in an unrecognized field makes the original exceed the snapshot budget.
	category = field(category, 100, make([]byte, MaxBundleBytes*3/4+1024))
	return field(nil, 1, category)
}

func TestOversizeSnapshotOmitsCoveredDATAndRebindRestoresIt(t *testing.T) {
	server, options := newGeodataFixture(t)
	server.bodies["/geosite.dat"] = largeGeoSite(t, "general.test", "attribute.test")
	cache := t.TempDir()
	const raw = `schema-version: 1
outbounds: [{id: broad, type: direct}]
rules:
 - {match: {geosite: 'test@cn'}, outbound: reject}
 - {match: {geosite: test}, outbound: broad}
`
	b := mustPrepareGeodata(t, raw, cache, options, server)
	if b.Precompiled == nil || len(b.Precompiled.Sets) != 2 || len(b.Resources) != 2 || len(b.OmittedResources) != 1 {
		t.Fatalf("expected only the two precompiled selectors, got %d resources and omissions %v", len(b.Resources), b.OmittedResources)
	}
	hash := b.OmittedResources[0]
	if data, err := resource.At(cache).Read(hash); err != nil || !bytes.Equal(data, server.bodies["/geosite.dat"]) {
		t.Fatal("original DAT was not saved in the main app cache", err)
	}
	snapshot, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	withDAT := *b
	withDAT.Resources = maps.Clone(b.Resources)
	withDAT.Resources[hash] = server.bodies["/geosite.dat"]
	withDAT.OmittedResources = nil
	full, err := json.Marshal(&withDAT)
	if err != nil || len(full) <= MaxBundleBytes {
		t.Fatal("fixture should exceed the budget before trimming", err)
	}
	t.Logf("snapshot with synthetic large DAT: %d to %d bytes", len(full), len(snapshot))
	compiled, err := CompileSnapshot(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	for domain, want := range map[string]string{"general.test": "broad", "attribute.test": "reject", "outside.test": "direct"} {
		if got := compiled.Router.Route(t.Context(), router.Metadata{Domain: domain}, nil).Outbound; got != want {
			t.Errorf("%s routed to %q, want %q", domain, got, want)
		}
	}

	for _, mode := range []string{"manifest version", "artifact version", "missing selector"} {
		t.Run(mode, func(t *testing.T) {
			old := *b
			old.Resources = maps.Clone(b.Resources)
			old.Precompiled = &precompiledRuleSets{Version: b.Precompiled.Version, Sets: maps.Clone(b.Precompiled.Sets)}
			if mode == "manifest version" {
				old.Precompiled.Version++
			} else {
				for key, digest := range old.Precompiled.Sets {
					artifact := bytes.Clone(old.Resources[digest])
					delete(old.Resources, digest)
					if mode == "artifact version" {
						artifact[3]++
						digest = resource.Hash(artifact)
						old.Precompiled.Sets[key] = digest
						old.Resources[digest] = artifact
					}
					break
				}
			}
			rawSnapshot, err := json.Marshal(&old)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CompileSnapshot(rawSnapshot, nil); !errors.Is(err, errSnapshotNeedsPreparation) {
				t.Fatalf("expected a message to prepare the profile again, got %v", err)
			}
			if _, err := old.Compile(); !errors.Is(err, errSnapshotNeedsPreparation) {
				t.Fatalf("expected the same message when loading a decoded snapshot, got %v", err)
			}
			options := PrepareOptions{RebindSnapshot: writeSourceBundle(t, &old)}
			updated := mustPrepareGeodata(t, raw, cache, options, server)
			if updated.Precompiled == nil || updated.Precompiled.Version != router.PrecompiledRuleSetVersion || !slices.Equal(updated.OmittedResources, []string{hash}) {
				t.Fatalf("rebind did not restore the DAT and regenerate its selectors: %+v", updated.Precompiled)
			}
			assertRoute(t, updated, "general.test", "broad")
			assertRoute(t, updated, "attribute.test", "reject")
		})
	}
	if server.requests["/geosite.dat"] != 1 {
		t.Fatalf("rebind downloaded the already locked DAT: %v", server.requests)
	}
}

func TestBudgetKeepsDATRequiredByUncoveredDatabase(t *testing.T) {
	dat := largeGeoSite(t, "general.test", "attribute.test")
	hash := resource.Hash(dat)
	b := &Bundle{
		Version: bundleVersion, Resources: map[string][]byte{hash: dat},
		Profile: json.RawMessage(fmt.Sprintf(`{
  "schema-version":1,
  "geodata":[{"id":"geosite","format":"dat","hash":%q}],
  "rule-sets":[{"id":"sites","behavior":"geosite","format":"dat","code":"test","hash":%q}],
  "rules":[{"match":{"rule-set":"sites"},"outbound":"reject"}]
}`, hash, hash)),
	}
	if _, ds := b.compileForPreparation(nil); ds.HasErrors() || b.Precompiled == nil || len(b.precompiledCoverage) > 0 {
		t.Fatalf("expected only the named rule set to be covered, got %v and %v", b.precompiledCoverage, ds)
	}
	if _, _, err := marshalPreparedBundle(b); !errors.Is(err, errBundleTooLarge) {
		t.Fatalf("the lock still needs its raw DAT, got %v", err)
	}
}

func TestSourceRefreshWithOmittedResourcesAndOverlay(t *testing.T) {
	server, options := newGeodataFixture(t)
	cache := t.TempDir()
	server.bodies["/geosite.dat"] = largeGeoSite(t, "old.test", "kept.test")
	source := mustPrepareGeodata(t, "rules: ['GEOSITE,test,REJECT']\n", cache, options, server)
	if len(source.OmittedResources) != 1 {
		t.Fatal("expected a source snapshot without the original DAT")
	}
	oldHash := source.OmittedResources[0]
	const raw = `schema-version: 1
imports: [{source: airport, rule-sets: true}]
rules:
  - {source: airport}
  - {match: {rule-set: pinned}, outbound: reject}
`
	options.Sources = map[string]string{"airport": writeSourceBundle(t, source)}
	options.Overlay = json.RawMessage(fmt.Sprintf(`{"schema-version":1,"patches":[
  {"op":"insert","path":"/rule-sets","value":{"id":"pinned","behavior":"geosite","format":"dat","code":"test@cn","hash":%q}}
]}`, oldHash))
	profile := mustPrepareGeodata(t, raw, cache, options, server)
	if len(profile.OmittedResources) != 1 || profile.OmittedResources[0] != oldHash || len(profile.Summary.Patches) != 1 || !profile.Summary.Patches[0].Applied {
		t.Fatalf("preparation did not restore the DAT for both selectors: %+v", profile.Summary.Patches)
	}
	assertRoute(t, profile, "old.test", "reject")

	server.bodies["/updated.dat"] = largeGeoSite(t, "new.test", "updated.test")
	options.GeodataSources["geosite"] = geodataFixtureHost + "/updated.dat"
	options.Overlay = nil
	updated := mustPrepareGeodata(t, "rules: ['GEOSITE,test,REJECT']\n", cache, options, server)
	if len(updated.OmittedResources) != 1 {
		t.Fatal("expected the updated source to omit its DAT")
	}
	options.Sources["airport"] = writeSourceBundle(t, updated)
	options.RebindSnapshot = writeSourceBundle(t, profile)
	options.RefreshSources = true
	refreshed := mustPrepareGeodata(t, raw, cache, options, server)
	if len(refreshed.OmittedResources) != 2 || !slices.Contains(refreshed.OmittedResources, oldHash) ||
		!slices.Contains(refreshed.OmittedResources, updated.OmittedResources[0]) {
		t.Fatalf("expected both locked originals to be omitted: %v", refreshed.OmittedResources)
	}
	assertRoute(t, refreshed, "new.test", "reject")
	assertRoute(t, refreshed, "kept.test", "reject")
	assertRoute(t, refreshed, "old.test", "direct")
}
