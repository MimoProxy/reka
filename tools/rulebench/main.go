// rulebench measures complete rule-only commits and large immutable rule indexes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

type metrics struct {
	Name    string  `json:"name"`
	Count   int     `json:"count"`
	Samples int     `json:"samples"`
	P50     float64 `json:"p50_ms"`
	P95     float64 `json:"p95_ms"`
	Heap    uint64  `json:"retained_heap_bytes,omitempty"`
	Build   float64 `json:"build_ms,omitempty"`
	Pass    bool    `json:"pass"`
}

func pct(v []float64, p float64) float64 {
	sort.Float64s(v)
	i := int(float64(len(v)-1) * p)
	return v[i]
}
func profile(n int, target string) string {
	var b strings.Builder
	b.WriteString("schema-version: 1\nrules:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, " - {id: r%d, match: {domain: '%06x.t'}, outbound: direct}\n", i, i)
	}
	fmt.Fprintf(&b, " - {id: final, match: {all: true}, outbound: %s}\n", target)
	return b.String()
}
func commits(n, samples int) metrics {
	root, e := os.MkdirTemp("", "reka-rulebench-")
	must(e)
	defer os.RemoveAll(root)
	eng := generation.NewEngine(generation.EngineOptions{})
	svc, e := service.Open(service.Options{StateRoot: root, Engine: eng, InitialProfile: []byte(profile(n, "direct"))})
	must(e)
	defer svc.Close()
	var values []float64
	for i := 0; i < samples+3; i++ {
		target := "reject"
		if i%2 != 0 {
			target = "direct"
		}
		text := profile(n, target)
		start := time.Now()
		result, e := svc.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: svc.ActiveRevision(), Profile: &text}, Source: "benchmark"})
		must(e)
		if result.State != "committed" {
			panic(fmt.Sprintf("commit failed: %+v", result))
		}
		if i >= 3 {
			values = append(values, float64(time.Since(start))/1e6)
		}
	}
	p95 := pct(values, .95)
	return metrics{"rule-only-commit", n, samples, pct(values, .5), p95, 0, 0, p95 < 500}
}
func queries(n, samples int) metrics {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%06x.t\n", i)
	}
	data := []byte(b.String())
	hash := resource.Hash(data)
	profile := fmt.Sprintf("schema-version: 1\nrule-sets: [{id: large, behavior: domain, format: text, hash: %s}]\nrules: [{id: resource, match: {rule-set: large}, outbound: reject},{id: final, match: {all: true}, outbound: direct}]", hash)
	runtime.GC()
	debug.FreeOSMemory()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{ReadResource: func(string) ([]byte, error) { return data, nil }})
	if ds.HasErrors() {
		panic(ds)
	}
	build := float64(time.Since(start)) / 1e6
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	values := make([]float64, 0, samples)
	for i := 0; i < samples; i++ {
		domain := fmt.Sprintf("%06x.t", (i*7919)%n)
		start := time.Now()
		d := eff.Router.Route(context.Background(), router.Metadata{Domain: domain}, nil)
		values = append(values, float64(time.Since(start))/1e6)
		if d.Outbound != "reject" {
			panic("index mismatch")
		}
	}
	runtime.KeepAlive(eff)
	return metrics{"rule-set-query", n, samples, pct(values, .5), pct(values, .95), after.HeapAlloc - before.HeapAlloc, build, true}
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	samples := flag.Int("samples", 20, "complete update samples")
	querySamples := flag.Int("queries", 100000, "queries per large set")
	flag.Parse()
	result := struct {
		Go, OS, Arch string
		At           time.Time
		Results      []metrics
	}{runtime.Version(), runtime.GOOS, runtime.GOARCH, time.Now().UTC(), []metrics{commits(10000, *samples), queries(100000, *querySamples), queries(1000000, *querySamples)}}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(result))
	if !result.Results[0].Pass {
		os.Exit(1)
	}
}
