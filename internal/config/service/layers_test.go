package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
)

const sourceProfile = `schema-version: 1
imports: [{source: sub, outbounds: true, groups: true}]
rules:
 - {source: sub}
 - {id: final, match: {all: true}, outbound: sub/proxy}
`
const sourceSnapshot = `schema-version: 1
sources:
 - id: sub
   outbounds:
    - {id: a, type: direct}
    - {id: b, type: direct}
    - {id: unused, type: socks, server: 127.0.0.1, port: 1080, username: user, password: upstream-secret}
   groups: [{id: proxy, type: select, members: [a, b], selected: a}]
   rules: [{id: remote, match: {domain: source.test}, outbound: proxy}]
`
const sourceOverlay = `patches:
 - {op: set, path: /groups/sub~1proxy/selected, value: sub/b}
 - {op: set, path: /outbounds/sub~1unused/password, value: override-secret}
`

func layerRequest(base uint64) ChangeRequest {
	return ChangeRequest{BaseRevision: base, Profile: ptr(sourceProfile), Sources: ptr(sourceSnapshot), Overlay: ptr(sourceOverlay)}
}
func mustLayerCommit(t *testing.T, s *Service, req ChangeRequest) Result {
	t.Helper()
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: req})
	if err != nil || res.State != store.OpCommitted {
		t.Fatalf("commit: %+v %v", res, err)
	}
	return res
}
func assertLayers(t *testing.T, s *Service, rev uint64, snapshot string) {
	t.Helper()
	cfg := s.GetConfiguration(true)
	if cfg.Revision != rev || cfg.Sources != snapshot || cfg.Overlay != sourceOverlay || cfg.Profile != sourceProfile {
		t.Fatalf("documents differ: %+v", cfg)
	}
	out, _, err := cfg.Effective.Router.Resolve("sub/proxy")
	if err != nil || out != "sub/b" {
		t.Fatalf("selection: %s %v", out, err)
	}
}
func TestLayersCommitRefreshRestartRestore(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	first := mustLayerCommit(t, s, layerRequest(1))
	old := s.Engine().OutboundInstance("sub/b")
	updated := strings.Replace(sourceSnapshot, "port: 1080", "port: 2080", 1)
	second := mustLayerCommit(t, s, ChangeRequest{BaseRevision: first.Revision, Sources: &updated})
	assertLayers(t, s, second.Revision, updated)
	if old != s.Engine().OutboundInstance("sub/b") {
		t.Fatal("refresh rebuilt an unchanged instance")
	}
	s.Close()
	s = e.open("", "")
	defer s.Close()
	assertLayers(t, s, second.Revision, updated)
	restored, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: first.Revision, BaseRevision: second.Revision})
	if err != nil || restored.State != store.OpCommitted {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	assertLayers(t, s, restored.Revision, sourceSnapshot)
	// Restoring a revision from before sources and overlays also removes them.
	res, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: 1, BaseRevision: restored.Revision})
	if err != nil || res.State != store.OpCommitted {
		t.Fatalf("restore old-layout revision: %+v %v", res, err)
	}
	cfg := s.GetConfiguration(true)
	if cfg.Sources != "" || cfg.Overlay != "" {
		t.Fatal("restore retained future layers")
	}
}

func TestLayersPlanRetryConflictAndMask(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	req := layerRequest(1)
	plan, err := s.Plan(req)
	if err != nil || !plan.Valid {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	changed := req
	changed.Sources = ptr(sourceSnapshot + "# new content\n")
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: changed, PlanHash: plan.PlanHash})
	if err != nil || res.Error == nil || res.Error.Code != CodePlanChanged {
		t.Fatalf("unbound source plan: %+v %v", res, err)
	}
	request := CommitRequest{ChangeRequest: req, PlanHash: plan.PlanHash, OperationID: "layers-retry"}
	first, err := s.Commit(context.Background(), request)
	if err != nil || first.State != store.OpCommitted {
		t.Fatalf("commit: %+v %v", first, err)
	}
	retry, err := s.Commit(context.Background(), request)
	if err != nil || retry.Revision != first.Revision {
		t.Fatal("not idempotent", retry, err)
	}
	request.Overlay = ptr(sourceOverlay + "# changed\n")
	if _, err = s.Commit(context.Background(), request); err == nil {
		t.Fatal("operation ID reused for different overlay")
	}
	masked := s.GetConfiguration(false)
	serialized, _ := json.Marshal(masked)
	if strings.Contains(string(serialized), "upstream-secret") || strings.Contains(string(serialized), "override-secret") {
		t.Fatal("read leaked credentials")
	}
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: first.Revision, Sources: &masked.Sources, Overlay: &masked.Overlay})
	full := s.GetConfiguration(true)
	if !strings.Contains(full.Sources, "upstream-secret") || !strings.Contains(full.Overlay, "override-secret") {
		t.Fatal("masked round trip lost credentials")
	}
	// Conflict differences must cover both new layers without credentials.
	conflict, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1}})
	if err != nil || conflict.Conflict == nil {
		t.Fatalf("conflict: %+v %v", conflict, err)
	}
	data, _ := json.Marshal(conflict.Conflict)
	if !strings.Contains(string(data), "/sources/") || !strings.Contains(string(data), "/overlay/") || strings.Contains(string(data), "upstream-secret") || strings.Contains(string(data), "override-secret") {
		t.Fatalf("bad conflict: %s", data)
	}
}

func TestLayersCrashPoints(t *testing.T) {
	for _, point := range []string{"revision-written", "intent-written", "activated", "active-written", "op-committed"} {
		t.Run(point, func(t *testing.T) {
			e := newEnv(t)
			s := e.open(DefaultProfile, "")
			s.opts.FailPoint = func(p string) error {
				if p == point {
					return errors.New("crash")
				}
				return nil
			}
			_, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: layerRequest(1), OperationID: "crash-layers"})
			if !errors.Is(err, ErrCrashed) {
				t.Fatalf("no crash: %v", err)
			}
			s.Close()
			s = e.open("", "")
			defer s.Close()
			if point == "active-written" || point == "op-committed" {
				assertLayers(t, s, 2, sourceSnapshot)
			} else {
				cfg := s.GetConfiguration(true)
				if cfg.Revision != 1 || cfg.Sources != "" || cfg.Overlay != "" || cfg.Profile != DefaultProfile {
					t.Fatal("partial snapshot restored")
				}
			}
		})
	}
}

func TestMissingSourceKeepsActiveAndLayerPatches(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	first := mustLayerCommit(t, s, layerRequest(1))
	renamed := strings.Replace(sourceSnapshot, "id: b,", "id: renamed,", 1)
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: first.Revision, Sources: &renamed}})
	if err != nil || res.State != store.OpRejected || s.ActiveRevision() != first.Revision {
		t.Fatalf("missing member activated: %+v %v", res, err)
	}
	second := mustLayerCommit(t, s, ChangeRequest{BaseRevision: first.Revision, OverlayPatch: []model.Op{{Op: "set", Path: "/patches/#0/value", Value: []byte(`"sub/a"`)}}})
	cfg := s.GetConfiguration(true)
	out, _, _ := cfg.Effective.Router.Resolve("sub/proxy")
	if second.Revision <= first.Revision || out != "sub/a" {
		t.Fatal("overlay patch not applied")
	}
}

func TestLayerCandidateFiles(t *testing.T) {
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	mustLayerCommit(t, s, layerRequest(1))
	candidate := s.NewCandidate(t.TempDir())
	if err := candidate.export(); err != nil {
		t.Fatal(err)
	}
	overlay := strings.Replace(sourceOverlay, "value: sub/b", "value: sub/a", 1)
	path := filepath.Join(candidate.Dir, "overlay.yaml")
	if err := os.WriteFile(path, []byte(overlay), 0600); err != nil {
		t.Fatal(err)
	}
	candidate.poll(context.Background())
	if cfg := s.GetConfiguration(true); cfg.Overlay != overlay {
		t.Fatal("overlay candidate not committed")
	}
	if err := candidate.export(); err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(sourceSnapshot, "id: a,", "id: renamed,", 1)
	path = filepath.Join(candidate.Dir, "sources.yaml")
	if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	before := s.ActiveRevision()
	candidate.poll(context.Background())
	if s.ActiveRevision() != before {
		t.Fatal("invalid source candidate activated")
	}
	if _, err := os.Stat(path + ".errors"); err != nil {
		t.Fatal("missing source candidate diagnostics", err)
	}
}
