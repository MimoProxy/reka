package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

func TestManagedResourceUpdatesRoutingWithoutClient(t *testing.T) {
	var malformed atomic.Bool
	var validator atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := r.Header.Get("If-None-Match")
		validator.Store(tag)
		if malformed.Load() {
			w.Header().Set("ETag", `"bad"`)
			_, _ = w.Write([]byte{0})
		} else if tag == `"good"` {
			w.WriteHeader(http.StatusNotModified)
		} else {
			w.Header().Set("ETag", `"good"`)
			_, _ = w.Write([]byte("updated.test\n"))
		}
	}))
	defer server.Close()
	e := newEnv(t)
	blobs, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := blobs.Put([]byte("original.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`schema-version: 1
rule-sets:
  - id: websites
    behavior: domain
    format: text
    hash: %s
    download: {url: %q, interval: 300, automatic: true}
rules:
  - {match: {rule-set: websites}, outbound: reject}
  - {match: {all: true}, outbound: direct}
`, seed, server.URL+"?key=private-value")
	s := e.open(profile, "")
	defer func() { s.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	decision := func(domain string) string {
		return s.GetConfiguration(true).Effective.Router.Route(ctx, router.Metadata{Domain: domain}, nil).Outbound
	}
	if decision("original.test") != "reject" || decision("updated.test") != "direct" {
		t.Fatal("seed rules not active")
	}
	if err := s.StartSubscriptions(RefreshOptions{PollInterval: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	for {
		statuses, err := s.ListManagedResources()
		if err != nil {
			t.Fatal(err)
		}
		if len(statuses) == 1 && statuses[0].State == "ready" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("background refresh did not complete: %+v", statuses)
		case <-time.After(10 * time.Millisecond):
		}
	}
	revision := s.ActiveRevision()
	if decision("original.test") != "direct" || decision("updated.test") != "reject" {
		t.Fatal("background refresh did not replace active rules")
	}
	req := api.RefreshManagedResourceRequest{Kind: "rule-set", ID: "websites", Wait: true}
	status, err := s.RefreshManagedResource(ctx, req)
	if err != nil || status.State != "ready" || status.Revision != revision || validator.Load() != `"good"` {
		t.Fatal("304 did not preserve the revision", status, err)
	}
	malformed.Store(true)
	status, err = s.RefreshManagedResource(ctx, req)
	if err != nil || status.State != "stale" || status.ErrorCode != "resource_invalid" || s.ActiveRevision() != revision || decision("updated.test") != "reject" {
		t.Fatal("malformed result replaced active rules", status, err)
	}
	if _, err := blobs.Read(resource.Hash([]byte{0})); err == nil {
		t.Fatalf("malformed bytes were stored: %v", err)
	}
	view, _ := json.Marshal(s.GetConfiguration(false))
	if strings.Contains(string(view), "private-value") {
		t.Fatal("resource URL credential was exposed")
	}
	if _, err := s.ExportProfileArchive(api.ExportManifestRequest{BaseRevision: revision, Reveal: true}); err != nil {
		t.Fatalf("resource metadata broke history export: %v", err)
	}
	malformed.Store(false)
	s.Close()
	s = e.open("", "")
	status, err = s.RefreshManagedResource(ctx, req)
	if err != nil || status.State != "ready" || status.Revision != revision || validator.Load() != `"good"` {
		t.Fatal("previous active hash and validators did not survive restart", status, err)
	}
}

func TestManagedResourceDoesNotResurrectRemovedRuleSet(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-finish:
			_, _ = w.Write([]byte("late.test\n"))
		}
	}))
	defer server.Close()
	e := newEnv(t)
	blobs, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := blobs.Put([]byte("seed.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf("schema-version: 1\nrule-sets: [{id: disposable, behavior: domain, format: text, hash: %s, download: {url: %q, interval: 300}}]\n", hash, server.URL)
	s := e.open(profile, "")
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		t.Fatal(err)
	}
	def, exists := m.managedDefinition(managedKey{"rule-set", "disposable"})
	if !exists {
		t.Fatal("managed definition missing")
	}
	job, err := m.queueManaged(def)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result, err := s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: s.ActiveRevision(),
		Patch: []model.Op{{Op: "remove", Path: "/rule-sets/disposable"}}}})
	if err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
	close(finish)
	select {
	case <-job.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if job.status.ErrorCode != "refresh_conflict" || s.ActiveRevision() != result.Revision {
		t.Fatalf("late update was applied: %+v", job.status)
	}
}
