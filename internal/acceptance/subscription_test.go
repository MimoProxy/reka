package acceptance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
)

func TestSubscriptionRefreshKeepsLiveConnections(t *testing.T) {
	var changed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if changed.Load() {
			w.Write([]byte("proxies: [{name: b, type: direct}]\nproxy-groups: [{name: Choice, type: select, proxies: [b]}]\nrules: ['MATCH,Choice']"))
		} else {
			w.Write([]byte("proxies: [{name: a, type: direct}, {name: b, type: direct}]\nproxy-groups: [{name: Choice, type: select, proxies: [a,b]}]\nrules: ['MATCH,Choice']"))
		}
	}))
	defer server.Close()
	h := newHarness(t, baseProfile)
	configured, err := h.svc.ConfigureSubscription(context.Background(), h.svc.ActiveRevision(), "sub", &model.Subscription{URL: server.URL, Interval: 30})
	if err != nil || configured.State != "committed" {
		t.Fatal(err, configured)
	}
	if status, err := h.svc.RefreshSubscription(context.Background(), "sub"); err != nil || status.State != "current" {
		t.Fatal(err, status)
	}
	profile := "schema-version: 1\nimports: [{source: sub, outbounds: true, groups: true}]\nrules: [{source: sub}]\n"
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &profile}})
	oldID, newID := "sub/"+importer.StableID("p", "a"), "sub/"+importer.StableID("p", "b")
	oldInstance, newInstance := h.engine().OutboundInstance(oldID), h.engine().OutboundInstance(newID)
	listener := h.engine().ListenerInstance("mixed")
	echo := echoServer(t)
	old := openStream(t, h.proxy(), echo)
	waitFor(t, "old subscription stream", 2*time.Second, func() bool { return oldInstance.Active() == 1 })
	overlay := "patches: [{op: set, path: /groups/sub~1" + importer.StableID("g", "Choice") + "/selected, value: " + newID + "}]"
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Overlay: &overlay}})
	changed.Store(true)
	if status, err := h.svc.RefreshSubscription(context.Background(), "sub"); err != nil || status.State != "current" {
		t.Fatal(err, status)
	}
	fresh := openStream(t, h.proxy(), echo)
	waitFor(t, "new subscription stream", 2*time.Second, func() bool { return newInstance.Active() == 1 })
	if h.svc.GetConfiguration(true).Overlay != overlay || h.engine().ListenerInstance("mixed") != listener || h.engine().OutboundInstance(newID) != newInstance {
		t.Fatal("refresh replaced unchanged resources or user overlay")
	}
	time.Sleep(100 * time.Millisecond)
	if err := old.finish(); err != nil {
		t.Fatal("old stream interrupted", err)
	}
	if err := fresh.finish(); err != nil {
		t.Fatal("new stream", err)
	}
	waitFor(t, "old subscription instance drained", 2*time.Second, func() bool { return h.engine().Status().Draining == 0 })
}
