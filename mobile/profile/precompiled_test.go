package profile

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
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
	data, err := marshalPreparedBundle(b)
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
