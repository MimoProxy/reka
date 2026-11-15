package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func TestS4RefreshResourceActivationFailureRestartRestore(t *testing.T) {
	var mode atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root":
			fmt.Fprintf(w, "rule-providers: {sites: {type: http, behavior: domain, format: text, url: '%s/sites'}}\nrules: ['AND,((RULE-SET,sites),(NETWORK,TCP)),REJECT','GEOIP,LAN,DIRECT,no-resolve','MATCH,DIRECT']", server.URL)
		case "/sites":
			switch mode.Load() {
			case 0:
				w.Write([]byte("+.first.test\n"))
			case 1:
				w.Write([]byte("+.second.test\n"))
			default:
				w.Write([]byte("invalid/entry\n"))
			}
		}
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	configureRefresh(t, s, "airport", server.URL+"/root")
	if status := refreshNow(t, s, "airport"); status.State != "current" {
		t.Fatal(status)
	}
	profile := "schema-version: 1\nrules: [{source: airport}]\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	check := func(domain, want string) {
		t.Helper()
		got := s.GetConfiguration(true).Effective.Router.Route(context.Background(), router.Metadata{Domain: domain, Network: "tcp"}, nil)
		if got.Outbound != want {
			t.Fatal(domain, got)
		}
	}
	check("x.first.test", "reject")
	check("x.second.test", "direct")
	first := s.ActiveRevision()
	firstHash := s.GetConfiguration(true).Effective.RulesFingerprint
	mode.Store(1)
	if status := refreshNow(t, s, "airport"); status.State != "current" {
		t.Fatal(status)
	}
	check("x.first.test", "direct")
	check("x.second.test", "reject")
	good := s.ActiveRevision()
	if s.GetConfiguration(true).Effective.RulesFingerprint == firstHash {
		t.Fatal("provider update did not rebuild rules")
	}
	mode.Store(2)
	status := refreshNow(t, s, "airport")
	if !status.Stale || status.ErrorCode != "rule_resource_invalid" || s.ActiveRevision() != good {
		t.Fatal("bad rule resource activated", status)
	}
	check("x.second.test", "reject")
	s.Close()
	s = e.open("", "")
	defer s.Close()
	check("x.second.test", "reject")
	server.Close()
	restored, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: first, BaseRevision: s.ActiveRevision()})
	if err != nil || restored.State != "committed" {
		t.Fatal(restored, err)
	}
	check("x.first.test", "reject")
	check("x.second.test", "direct")
}
func TestS4GeodataRefreshMaskAndMissingCode(t *testing.T) {
	geoip, err := os.ReadFile("../../../testdata/rules/geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	geosite, err := os.ReadFile("../../../testdata/rules/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	var bad atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root":
			code := "test@cn"
			if bad.Load() {
				code = "absent"
			}
			fmt.Fprintf(w, "rules: ['GEOSITE,%s,REJECT','GEOIP,CN,DIRECT,no-resolve','MATCH,DIRECT']", code)
		case "/geoip":
			if r.Header.Get("Authorization") != "" {
				t.Error("root credentials inherited")
			}
			w.Write(geoip)
		case "/geosite":
			w.Write(geosite)
		}
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	spec := &model.Subscription{URL: server.URL + "/root", Headers: []model.SubscriptionHeader{{Name: "Authorization", Value: "root-private"}}, Geodata: []model.GeoAsset{{ID: "geoip", URL: server.URL + "/geoip?token=geo-private"}, {ID: "geosite", URL: server.URL + "/geosite"}}}
	if result, err := s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", spec); err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
	if status := refreshNow(t, s, "airport"); status.State != "current" {
		t.Fatal(status)
	}
	profile := "schema-version: 1\nrules: [{source: airport}]\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	got := s.GetConfiguration(true).Effective.Router.Route(context.Background(), router.Metadata{Domain: "x.suffix.test"}, nil)
	if got.Outbound != "reject" {
		t.Fatal(got)
	}
	masked := s.GetConfiguration(false)
	if strings.Contains(masked.Sources, "geo-private") || strings.Contains(masked.Sources, "root-private") {
		t.Fatal("geodata credentials leaked")
	}
	// YAML masked round trip must keep URLs by resource identity, even when reordered.
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Sources: &masked.Sources})
	spec.URL = model.Mask
	spec.Headers[0].Value = model.Mask
	spec.Geodata = []model.GeoAsset{{ID: "geosite", URL: model.Mask}, {ID: "geoip", URL: model.Mask}}
	if result, err := s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "airport", spec); err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
	if !strings.Contains(s.GetConfiguration(true).Sources, "geo-private") {
		t.Fatal("geodata masked roundtrip lost URL")
	}
	before := s.ActiveRevision()
	bad.Store(true)
	if status := refreshNow(t, s, "airport"); !status.Stale || s.ActiveRevision() != before {
		t.Fatal("missing code activated", status)
	}
}
