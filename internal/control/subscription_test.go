package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
)

func TestSubscriptionAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("proxies: [{name: Node, type: direct}]")) }))
	defer server.Close()
	addr, _ := startServer(t)
	client, err := Connect(addr, "subscription-api")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var committed service.Result
	if err := client.Call("ConfigureSubscription", map[string]any{"source_id": "sub", "base_revision": 1, "subscription": model.Subscription{URL: server.URL + "?token=private-token", Interval: 30}}, &committed); err != nil || committed.State != "committed" {
		t.Fatal(err, committed)
	}
	var cfg service.Configuration
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil || strings.Contains(cfg.Sources, "private-token") {
		t.Fatal("URL exposed", err)
	}
	var status service.SubscriptionStatus
	if err := client.Call("RefreshSubscription", map[string]any{"source_id": "sub", "wait": true}, &status); err != nil || status.State != "current" {
		t.Fatal(err, status)
	}
	var statuses []service.SubscriptionStatus
	if err := client.Call("ListSubscriptions", nil, &statuses); err != nil || len(statuses) != 1 || statuses[0].RootHash == "" {
		t.Fatal(err, statuses)
	}
}
