package service

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestTrafficBudgetExplicitResetAndReserve(t *testing.T) {
	eff, ds := compile.Compile([]byte(DefaultProfile), []byte("traffic-budgets: [{source: test, reserve-bytes: 100, reset-at: '2030-06-02T16:00:00Z'}]\n"), compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	upload, download, total := uint64(150), uint64(250), uint64(1000)
	expires := uint64(now.Add(7 * 24 * time.Hour).Unix())
	status := SubscriptionStatus{SourceID: "test", Usage: &api.SubscriptionUsage{Upload: &upload, Download: &download, Total: &total, ExpireUnix: &expires, ObservedAt: now}}
	budget := budgetFor(eff, "test")
	result := trafficBudget(status, budget, now)
	if result.State != "ok" || result.EndReason != "reset" || result.DaysRemaining == nil || *result.DaysRemaining != 2 ||
		result.DailyBytes == nil || *result.DailyBytes != 250 {
		t.Fatal(result)
	}
	status.Usage.Download = nil
	if result := trafficBudget(status, budget, now); result.State != "unknown" || result.DailyBytes != nil {
		t.Fatal("missing usage guessed a daily allowance", result)
	}
	download = math.MaxUint64
	status.Usage.Download = &download
	if result := trafficBudget(status, budget, now); result.State != "exhausted" || *result.RemainingBytes != 0 {
		t.Fatal("overflow created budget", result)
	}
}

func TestSubscriptionUsageRefreshPersists304AndLastGood(t *testing.T) {
	var stage atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch stage.Load() {
		case 1:
			w.WriteHeader(304)
			return
		case 2:
			w.Header().Set("Subscription-Userinfo", "download=9")
			w.WriteHeader(304)
			return
		case 3:
			w.Header().Set("Subscription-Userinfo", "download=-1; upload=2; upload=3")
			w.WriteHeader(304)
			return
		case 4:
			w.Header().Set("ETag", "two")
			w.Write([]byte(refreshRoot + "\n#new response\n"))
			return
		case 5:
			w.Header().Set("Subscription-Userinfo", "upload=4; total=0; expire=0")
		case 6:
			w.WriteHeader(503)
			return
		case 7:
			w.Header().Set("Subscription-Userinfo", "upload=999; download=999; total=999")
			w.Write([]byte("<invalid subscription>"))
			return
		default:
			w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=100; expire=1893456000")
		}
		w.Header().Set("ETag", "one")
		w.Write([]byte(refreshRoot))
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	configureRefresh(t, s, "account", server.URL+"?token=do-not-log")
	status := refreshNow(t, s, "account")
	if status.Usage == nil || *status.Usage.Upload != 1 || *status.Usage.Download != 2 || *status.Usage.Total != 100 {
		t.Fatal("root declaration absent", status)
	}
	if budgets, err := s.TrafficBudgets(); err != nil || len(budgets) != 1 || budgets[0].RemainingBytes == nil || *budgets[0].RemainingBytes != 97 {
		t.Fatal("budget did not use the provider declaration", budgets, err)
	}
	observed := status.Usage.ObservedAt
	stage.Store(1)
	status = refreshNow(t, s, "account")
	if *status.Usage.Download != 2 || !status.Usage.ObservedAt.Equal(observed) {
		t.Fatal("304 without header changed metadata")
	}
	stage.Store(2)
	status = refreshNow(t, s, "account")
	if *status.Usage.Upload != 1 || *status.Usage.Download != 9 || *status.Usage.Total != 100 || !status.Usage.ObservedAt.After(observed) {
		t.Fatal("304 partial declaration did not merge", status)
	}
	stage.Store(3)
	status = refreshNow(t, s, "account")
	if status.Usage.Upload != nil || status.Usage.Download != nil || *status.Usage.Total != 100 || !reflect.DeepEqual(status.Usage.InvalidFields, []string{"download", "upload"}) {
		t.Fatal("invalid metadata replaced valid fields incorrectly", status)
	}
	stage.Store(4)
	status = refreshNow(t, s, "account")
	if status.Usage != nil {
		t.Fatal("fresh declaration omission must be unknown", status)
	}
	stage.Store(5)
	status = refreshNow(t, s, "account")
	if status.Usage.Download != nil || *status.Usage.Upload != 4 || *status.Usage.Total != 0 || *status.Usage.ExpireUnix != 0 {
		t.Fatal("zero or missing declaration was conflated", status)
	}
	lastGood := status.Usage
	for _, step := range []int32{6, 7} {
		stage.Store(step)
		status = refreshNow(t, s, "account")
		if !status.Stale || !reflect.DeepEqual(status.Usage, lastGood) {
			t.Fatal("failed refresh replaced account metadata", status)
		}
		wire, _ := json.Marshal(status)
		if strings.Contains(string(wire), "do-not-log") || strings.Contains(string(wire), "http://") {
			t.Fatal("status exposed subscription URL")
		}
	}
	s.Close()
	s = e.open("", "")
	defer s.Close()
	statuses, err := s.ListSubscriptions()
	if err != nil || len(statuses) != 1 || !statuses[0].Stale || !reflect.DeepEqual(statuses[0].Usage, lastGood) {
		t.Fatal("restart lost last-good usage", statuses, err)
	}
}
