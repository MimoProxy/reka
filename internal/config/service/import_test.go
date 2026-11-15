package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/store"
)

const importData = `proxies:
 - {name: route, type: direct}
 - {name: secure, type: socks5, server: 127.0.0.1, port: 1080, username: import-user, password: import-password}
proxy-groups:
 - {name: proxy, type: select, proxies: [route, secure], icon: 'https://icons.example/proxy.svg'}
rules: ["MATCH,proxy"]
`

func TestImportTransactionRefreshPlanAndRetry(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	request := importer.Request{SourceID: "sub", Data: importData}
	preview := s.PreviewImport(request, false)
	if !preview.Report.CanApply || strings.Contains(preview.Sources, "import-password") {
		t.Fatal("unsafe preview", preview.Report)
	}
	group := "sub/" + importer.StableID("g", "proxy")
	selection := "sub/" + importer.StableID("p", "route")
	profile := "schema-version: 1\nimports: [{source: sub, outbounds: true, groups: true}]\nrules: [{source: sub}]\n"
	overlay := "patches: [{op: set, path: /groups/" + strings.ReplaceAll(group, "/", "~1") + "/selected, value: " + selection + "}]\n"
	change := ChangeRequest{BaseRevision: 1, Import: &request, Profile: &profile, Overlay: &overlay}
	plan, err := s.Plan(change)
	if err != nil || !plan.Valid {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	commit := CommitRequest{ChangeRequest: change, OperationID: "import-retry", PlanHash: plan.PlanHash}
	first, err := s.Commit(context.Background(), commit)
	if err != nil || first.State != store.OpCommitted {
		t.Fatalf("commit %+v %v", first, err)
	}
	retry, err := s.Commit(context.Background(), commit)
	if err != nil || retry.Revision != first.Revision {
		t.Fatal("import retry", retry, err)
	}
	original := s.GetConfiguration(true)
	request.Data = strings.Replace(importData, "port: 1080", "port: 2080", 1)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: first.Revision, Import: &request})
	cfg := s.GetConfiguration(true)
	if cfg.Overlay != overlay || cfg.Profile != profile || cfg.Local != original.Local {
		t.Fatal("source import changed user documents")
	}
	out, _, err := cfg.Effective.Router.Resolve(group)
	if err != nil || out != selection {
		t.Fatalf("selection lost: %s %v", out, err)
	}
	// Replacing one source leaves other snapshots and their comments alone.
	another := importer.Request{SourceID: "other", Data: "proxies: [{name: other, type: direct}]"}
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: cfg.Revision, Import: &another})
	cfg = s.GetConfiguration(true)
	if len(cfg.Effective.SourceHashes) != 2 {
		t.Fatal("other source was overwritten")
	}
	bytes, _ := json.Marshal(s.GetConfiguration(false))
	if strings.Contains(string(bytes), "import-password") || strings.Contains(string(bytes), "import-user") {
		t.Fatal("import credential leaked through API")
	}
}
func TestImportIncompleteDoesNotModifyState(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	request := importer.Request{SourceID: "sub", Data: importData + "dns: {enable: true, enhanced-mode: fake-ip}\n"}
	change := ChangeRequest{BaseRevision: 1, Import: &request}
	valid, err := s.Validate(change)
	if err != nil || valid.Valid || !valid.Diagnostics.HasErrors() {
		t.Fatal("partial validate", valid, err)
	}
	plan, err := s.Plan(change)
	if err != nil || plan.Valid || !plan.Diagnostics.HasErrors() {
		t.Fatal("partial plan", plan, err)
	}
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: change})
	if err != nil || res.State != store.OpRejected || len(res.Diagnostics) == 0 || s.ActiveRevision() != 1 || s.GetConfiguration(true).Sources != "" {
		t.Fatal("partial import mutated state", res, err)
	}
	request.NodesOnly = true
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: 1, Import: &request})
}
