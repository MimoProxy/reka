package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func fixtureManagedSRS(t *testing.T, rule option.DefaultHeadlessRule) []byte {
	t.Helper()
	var data bytes.Buffer
	if err := srs.Write(&data, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

type srsTransport func(*http.Request) (*http.Response, error)

func (f srsTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestManagedSRSDownloadAndRefresh(t *testing.T) {
	var body atomic.Value
	body.Store(fixtureManagedSRS(t, option.DefaultHeadlessRule{Domain: []string{"old.test"}}))
	client := &http.Client{Transport: srsTransport(func(*http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		_, _ = w.Write(body.Load().([]byte))
		return w.Result(), nil
	})}
	s := newEnv(t).open("schema-version: 1\n", "")
	defer s.Close()
	if err := s.StartSubscriptions(RefreshOptions{Client: client}); err != nil {
		t.Fatal(err)
	}
	install := api.InstallManagedResourceRequest{
		Kind: "rule-set", ID: "sites", Format: "srs", Behavior: "classical", URL: "https://rules.example/sites.srs",
		BaseRevision: s.ActiveRevision(),
	}
	if _, err := s.InstallManagedResource(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Patch: []model.Op{{
		Op: "insert", Path: "/rules", Value: json.RawMessage(`{"match":{"rule-set":"sites"},"outbound":"reject"}`),
	}}})
	route := func(domain string) string {
		return s.GetConfiguration(true).Effective.Router.Route(t.Context(), router.Metadata{Domain: domain}, nil).Outbound
	}
	if got := route("old.test"); got != "reject" {
		t.Fatalf("initial SRS download is not active: %s", got)
	}
	body.Store(fixtureManagedSRS(t, option.DefaultHeadlessRule{DomainSuffix: []string{"new.test"}}))
	refresh := api.RefreshManagedResourceRequest{Kind: "rule-set", ID: "sites", Wait: true}
	status, err := s.RefreshManagedResource(t.Context(), refresh)
	if err != nil || status.State != "ready" || route("old.test") != "direct" || route("sub.new.test") != "reject" {
		t.Fatalf("refresh did not activate new rules: %+v, %v", status, err)
	}
	body.Store(fixtureManagedSRS(t, option.DefaultHeadlessRule{QueryType: []option.DNSQueryType{1}}))
	revision := s.ActiveRevision()
	status, err = s.RefreshManagedResource(t.Context(), refresh)
	if err != nil || status.State != "stale" || status.ErrorCode != "unsupported_srs_condition_query_type" || s.ActiveRevision() != revision || route("sub.new.test") != "reject" {
		t.Fatalf("refresh should name the unsupported condition and keep the old rules: %+v, %v", status, err)
	}
}

func TestImportUsesPerCodeSRSResources(t *testing.T) {
	e := newEnv(t)
	store, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	req := importer.Request{
		SourceID: "airport", Data: "rules: ['GEOSITE,google@CN,REJECT', 'GEOIP,CN,DIRECT']\n",
		GeodataResources: make(map[string]string),
	}
	for id, rule := range map[string]option.DefaultHeadlessRule{
		"geosite:google@cn": {Domain: []string{"regional.test"}},
		"geoip:cn":          {IPCIDR: []string{"192.0.2.0/24"}},
	} {
		hash, err := store.Put(fixtureManagedSRS(t, rule))
		if err != nil {
			t.Fatal(err)
		}
		req.GeodataResources[id] = hash
	}
	s := e.open("schema-version: 1\n", "")
	defer s.Close()
	preview := s.PreviewImport(req, true)
	sources, _, ds := model.ParseSources([]byte(preview.Sources))
	if !preview.Report.CanApply || ds.HasErrors() || len(sources.Sources) != 1 || len(sources.Sources[0].RuleSets) != 2 {
		t.Fatalf("per-code SRS resources were not imported: %v", preview.Report.Diagnostics)
	}
	for _, def := range sources.Sources[0].RuleSets {
		if def.Format != "srs" || req.GeodataResources[def.Behavior+":"+def.Code] != def.Hash {
			t.Fatalf("unexpected imported selector: %+v", def)
		}
	}
	profile := "schema-version: 1\nimports: [{source: airport, rule-sets: true}]\nrules: [{source: airport}]\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Import: &req, Profile: &profile})
	decision := s.GetConfiguration(true).Effective.Router.Route(t.Context(), router.Metadata{Domain: "regional.test"}, nil)
	if decision.Outbound != "reject" {
		t.Fatalf("import did not bind the requested geosite code: %+v", decision)
	}
}
