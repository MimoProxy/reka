package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOnlyRootResponseCanDeclareSubscriptionAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3")
		w.Write([]byte("payload"))
	}))
	defer server.Close()
	f := fetcher(t)
	defer f.Client.CloseIdleConnections()
	b := f.Batch(nil, true)
	for _, item := range []struct{ id, kind string }{{"root", "subscription"}, {"provider", "proxy"}, {"geoip", "geodata"}} {
		if _, err := b.Fetch(context.Background(), item.id, item.kind, "", server.URL, nil, 30); err != nil {
			t.Fatal(err)
		}
	}
	if b.Entries["root"].Usage == nil || b.Entries["provider"].Usage != nil || b.Entries["geoip"].Usage != nil {
		t.Fatal("resource metadata confused with account declaration", b.Entries)
	}
}

func TestSubscriptionUserinfoParsing(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	full := responseUsage([]string{"Upload = 0; download=18446744073709551615; total=100; expire=1893456000; ignored=private"}, nil, false, now)
	if full.Upload == nil || *full.Upload != 0 || full.Download == nil || *full.Download != ^uint64(0) || full.Total == nil || *full.Total != 100 || full.ExpireUnix == nil || *full.ExpireUnix != 1893456000 || !full.ObservedAt.Equal(now) {
		t.Fatal("valid unsigned declaration was changed", full)
	}
	bad := responseUsage([]string{"upload=-1; download=18446744073709551616; total=12x; expire=253402300800"}, nil, false, now)
	if bad.Upload != nil || bad.Download != nil || bad.Total != nil || bad.ExpireUnix != nil || !reflect.DeepEqual(bad.InvalidFields, []string{"download", "expire", "total", "upload"}) {
		t.Fatal("invalid/overflow values must remain unknown", bad)
	}
	duplicate := responseUsage([]string{"upload=1; total=2", "upload=1; total=3; upload=4"}, nil, false, now)
	if duplicate.Upload != nil || duplicate.Total != nil || !reflect.DeepEqual(duplicate.InvalidFields, []string{"total", "upload"}) {
		t.Fatal("duplicate declarations accepted", duplicate)
	}
	zero := responseUsage([]string{"total=0; expire=0"}, nil, false, now)
	if zero.Upload != nil || zero.Download != nil || zero.Total == nil || *zero.Total != 0 || zero.ExpireUnix == nil || *zero.ExpireUnix != 0 {
		t.Fatal("zero and missing conflated", zero)
	}
	for _, header := range []string{"upload=+1", "upload=1.2", "upload", "upload=0x10", "upload="} {
		got := responseUsage([]string{header}, nil, false, now)
		if got.Upload != nil || len(got.InvalidFields) != 1 {
			t.Fatal("invalid syntax accepted", header, got)
		}
	}
	if responseUsage(nil, full, false, now) != nil {
		t.Fatal("fresh 200 without declaration retained old values")
	}
	if responseUsage(nil, full, true, now) != full {
		t.Fatal("304 without header lost prior usage")
	}
	if responseUsage([]string{"unrelated=1"}, full, true, now) != full {
		t.Fatal("304 omitted known fields lost prior usage")
	}
	next := responseUsage([]string{"download=4"}, full, true, now.Add(time.Second))
	if *next.Download != 4 || *next.Upload != 0 || *next.Total != 100 || *next.ExpireUnix != 1893456000 || *full.Download != ^uint64(0) {
		t.Fatal("304 partial merge mutated old usage", next, full)
	}
	tooLarge := responseUsage([]string{"upload=1;" + strings.Repeat("x", 8192)}, full, true, now)
	if tooLarge.Upload != nil || !reflect.DeepEqual(tooLarge.InvalidFields, []string{"header"}) {
		t.Fatal("unbounded metadata header accepted")
	}
}
