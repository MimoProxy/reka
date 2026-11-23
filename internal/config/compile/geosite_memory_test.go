package compile

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"google.golang.org/protobuf/encoding/protowire"
)

func largeGeoSiteFixture() ([]byte, Options, string) {
	rng := rand.New(rand.NewPCG(17, 23))
	var first string
	category := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "large")
	var entry []byte
	for i := range 100_000 {
		host := fmt.Sprintf("%016x.example.test", rng.Uint64())
		if i == 0 {
			first = host
		}
		entry = protowire.AppendVarint(protowire.AppendTag(entry[:0], 1, protowire.VarintType), 2+uint64(i%2))
		entry = protowire.AppendString(protowire.AppendTag(entry, 2, protowire.BytesType), host)
		category = protowire.AppendBytes(protowire.AppendTag(category, 2, protowire.BytesType), entry)
	}
	data := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), category)
	hash := resource.Hash(data)
	profile := fmt.Sprintf(`schema-version: 1
geodata: [{id: geosite, format: dat, hash: %s}]
rules: [{id: match-large, match: {geosite: large}, outbound: reject}]
`, hash)
	return []byte(profile), Options{ReadResource: func(string) ([]byte, error) { return data, nil }}, first
}

func TestCompileLargeGeoSiteMemory(t *testing.T) {
	profile, options, host := largeGeoSiteFixture()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	eff, ds := Compile(profile, nil, options)
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(options) // The input DAT also lived across the baseline.
	if got := eff.Router.Route(t.Context(), router.Metadata{Domain: "sub." + host}, nil); got.Outbound != "reject" {
		t.Fatal("large category did not match its first suffix")
	}
	if set := eff.Rules[0].Set; set.Len() != 100_000 || set.Rule(0).Values[0] != host {
		t.Fatal("large category did not retain its inspectable entries")
	}
	const mib = 1 << 20
	retained := int64(after.HeapInuse) - int64(before.HeapInuse)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("retained HeapInuse delta %.2f MiB, TotalAlloc delta %.2f MiB", float64(retained)/mib, float64(allocated)/mib)
	// Leave room for allocator and GC differences across CI platforms.
	if retained > 18*mib || allocated > 80*mib {
		t.Fatal("large category exceeded its memory allowance")
	}
}

func BenchmarkCompileLargeGeoSite(b *testing.B) {
	profile, options, _ := largeGeoSiteFixture()
	b.ReportAllocs()
	for b.Loop() {
		eff, ds := Compile(profile, nil, options)
		if eff == nil || ds.HasErrors() {
			b.Fatal(ds)
		}
	}
}
