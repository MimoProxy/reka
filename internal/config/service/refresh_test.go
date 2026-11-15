package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
)

const refreshRoot = `proxies:
 - {name: one, type: direct}
 - {name: two, type: direct}
proxy-groups: [{name: Choice, type: select, proxies: [one, two]}]
rules: ["MATCH,Choice"]
`

func configureRefresh(t *testing.T, s *Service, id, url string) *RefreshManager {
	t.Helper()
	result, err := s.ConfigureSubscription(context.Background(), s.ActiveRevision(), id, &model.Subscription{URL: url, Interval: 30})
	if err != nil || result.State != "committed" {
		t.Fatalf("configure: %+v %v", result, err)
	}
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func refreshNow(t *testing.T, s *Service, id string) SubscriptionStatus {
	t.Helper()
	status, err := s.RefreshSubscription(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return status
}
func TestRefreshConditionalFailureRestartRestore(t *testing.T) {
	var mode atomic.Int32
	var lastValidator atomic.Value
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		lastValidator.Store(r.Header.Get("If-None-Match"))
		switch mode.Load() {
		case 1:
			w.Header().Set("ETag", "bad")
			w.Write([]byte("<not a subscription>"))
			return
		case 2:
			w.WriteHeader(503)
			return
		}
		w.Header().Set("ETag", "good")
		if r.Header.Get("If-None-Match") == "good" {
			w.WriteHeader(304)
			return
		}
		w.Write([]byte(refreshRoot))
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	configureRefresh(t, s, "airport", server.URL+"?token=private-token")
	status := refreshNow(t, s, "airport")
	if status.State != "current" || status.RootHash == "" {
		t.Fatal(status)
	}
	good := s.GetConfiguration(true)
	goodRev := good.Revision
	masked := s.GetConfiguration(false)
	bytes, _ := json.Marshal(masked)
	if strings.Contains(string(bytes), "private-token") {
		t.Fatal("URL credential leaked")
	}
	if _, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: goodRev, Sources: &masked.Sources}}); err != nil {
		t.Fatal("masked definition roundtrip", err)
	}
	if !strings.Contains(s.GetConfiguration(true).Sources, "private-token") {
		t.Fatal("masked URL lost")
	}
	status = refreshNow(t, s, "airport")
	if status.State != "current" || s.ActiveRevision() != goodRev || lastValidator.Load() != "good" {
		t.Fatal("304 created a new revision", status)
	}
	mode.Store(1)
	status = refreshNow(t, s, "airport")
	if !status.Stale || status.ErrorCode != "provider_document_invalid" && status.ErrorCode != "conversion_rejected" || s.ActiveRevision() != goodRev {
		t.Fatal("bad content replaced good version", status)
	}
	mode.Store(0)
	status = refreshNow(t, s, "airport")
	if status.State != "current" || lastValidator.Load() != "good" {
		t.Fatal("failed candidate promoted its validator", status)
	}
	mode.Store(2)
	status = refreshNow(t, s, "airport")
	if !status.Stale || status.ErrorCode != "http_status_503" || !status.NextAttempt.After(time.Now().Add(20*time.Second)) {
		t.Fatal("failure/backoff", status)
	}
	s.Close()
	mode.Store(0)
	s = e.open("", "")
	defer s.Close()
	status = refreshNow(t, s, "airport")
	if status.State != "current" || lastValidator.Load() != "good" {
		t.Fatal("restart lost validators", status)
	}
	restored, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: goodRev, BaseRevision: s.ActiveRevision()})
	if err != nil || restored.State != "committed" {
		t.Fatal("locked revision restore", restored, err)
	}
	if requests.Load() < 5 {
		t.Fatal("network assertions did not execute")
	}
}
func TestRefreshFirstFailureIsNotEmptySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	configureRefresh(t, s, "first", server.URL)
	before := s.GetConfiguration(true)
	status := refreshNow(t, s, "first")
	if status.State != "failed" || !status.LastSuccess.IsZero() || s.ActiveRevision() != before.Revision || s.GetConfiguration(true).Sources != before.Sources {
		t.Fatal("first failure fabricated success", status)
	}
}
func TestRefreshProvider304AndFailureIsAtomic(t *testing.T) {
	var providerVersion atomic.Int32
	var fail atomic.Bool
	var validator atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/root" {
			w.Header().Set("ETag", "root")
			if r.Header.Get("If-None-Match") == "root" {
				w.WriteHeader(304)
				return
			}
			fmt.Fprintf(w, "proxy-providers: {pool: {type: http, url: '%s/provider', interval: 30, header: {user-agent: [ProviderCustom]}}}\nproxy-groups: [{name: Choice, type: select, use: [pool]}]\nrules: ['MATCH,Choice']", "http://"+r.Host)
			return
		}
		if r.Header.Get("User-Agent") != "ProviderCustom" {
			t.Error("provider header case changed semantics")
		}
		validator.Store(r.Header.Get("If-None-Match"))
		if fail.Load() {
			w.WriteHeader(502)
			return
		}
		version := fmt.Sprint(providerVersion.Load())
		w.Header().Set("ETag", version)
		if r.Header.Get("If-None-Match") == version {
			w.WriteHeader(304)
			return
		}
		fmt.Fprintf(w, "proxies: [{name: Node, type: direct, udp: %t}]", providerVersion.Load() == 0)
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	configureRefresh(t, s, "sub", server.URL+"/root")
	if status := refreshNow(t, s, "sub"); status.State != "current" {
		t.Fatal(status)
	}
	first := s.GetConfiguration(true)
	sources, _, _ := model.ParseSources([]byte(first.Sources))
	lock := sources.Sources[0].Lock
	if lock == nil || len(lock.Resources) != 2 {
		t.Fatal("provider not independently locked")
	}
	providerVersion.Store(1)
	if status := refreshNow(t, s, "sub"); status.State != "current" {
		t.Fatal(status)
	}
	second := s.GetConfiguration(true)
	if second.Revision == first.Revision || validator.Load() != "0" {
		t.Fatal("root 304 hid provider update")
	}
	fail.Store(true)
	status := refreshNow(t, s, "sub")
	if !status.Stale || s.GetConfiguration(true).Sources != second.Sources {
		t.Fatal("provider failure partially activated", status)
	}
	restored, err := s.RestoreRevision(context.Background(), RestoreRequest{Revision: first.Revision, BaseRevision: s.ActiveRevision()})
	if err != nil || restored.State != "committed" {
		t.Fatal("provider lock restore", restored, err)
	}
	statuses, err := s.ListSubscriptions()
	if err != nil || len(statuses) != 1 || statuses[0].State != "pending" || !statuses[0].Stale {
		t.Fatal("old child lock falsely reported current", statuses, err)
	}
}
func TestRefreshRebasesOverlayButRejectsSourceEdits(t *testing.T) {
	var block atomic.Bool
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block.Load() {
			entered <- struct{}{}
			<-release
		}
		w.Write([]byte(refreshRoot))
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	configureRefresh(t, s, "sub", server.URL)
	if status := refreshNow(t, s, "sub"); status.State != "current" {
		t.Fatal(status)
	}
	profile := "schema-version: 1\nimports: [{source: sub, outbounds: true, groups: true}]\nrules: [{source: sub}]\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	block.Store(true)
	done := make(chan SubscriptionStatus, 1)
	go func() { status, _ := s.RefreshSubscription(context.Background(), "sub"); done <- status }()
	<-entered
	overlay := fmt.Sprintf("patches: [{op: set, path: /groups/sub~1%s/selected, value: sub/%s}]", importer.StableID("g", "Choice"), importer.StableID("p", "two"))
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Overlay: &overlay})
	release <- struct{}{}
	if status := <-done; status.State != "current" || s.GetConfiguration(true).Overlay != overlay {
		t.Fatal("overlay edit lost", status)
	}
	go func() { status, _ := s.RefreshSubscription(context.Background(), "sub"); done <- status }()
	<-entered
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), SourcesPatch: []model.Op{{Op: "set", Path: model.JoinPath("/sources", "sub", "outbounds", importer.StableID("p", "one"), "name"), Value: []byte(`"manual"`)}}})
	before := s.GetConfiguration(true)
	release <- struct{}{}
	if status := <-done; status.ErrorCode != "refresh_conflict" || s.GetConfiguration(true).Sources != before.Sources {
		t.Fatal("manual source edit overwritten", status)
	}
}
func TestRefreshDeduplicatesAndLimitsConcurrency(t *testing.T) {
	var count, max, active atomic.Int32
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		n := active.Add(1)
		for old := max.Load(); n > old && !max.CompareAndSwap(old, n); old = max.Load() {
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		w.Write([]byte(refreshRoot))
	}))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	defer s.Close()
	configureRefresh(t, s, "same", server.URL)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.RefreshSubscription(context.Background(), "same") }()
	}
	<-entered
	time.Sleep(30 * time.Millisecond)
	release <- struct{}{}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("same-source refresh not coalesced", count.Load())
	}
	for i := 0; i < 6; i++ {
		configureRefresh(t, s, fmt.Sprint("s", i), server.URL)
	}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, _ = s.RefreshSubscription(context.Background(), fmt.Sprint("s", i)) }(i)
	}
	for i := 0; i < 4; i++ {
		<-entered
	}
	close(release)
	wg.Wait()
	if max.Load() > 4 {
		t.Fatal("concurrency limit", max.Load())
	}
}
func TestRefreshSchedulerPauseAndShutdown(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(refreshRoot)) }))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	spec := &model.Subscription{URL: server.URL + "?private=value", Interval: 30, Paused: true, Headers: []model.SubscriptionHeader{{Name: "X-Token", Value: "header-private"}}}
	result, err := s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "paused", spec)
	if err != nil || result.State != "committed" {
		t.Fatal(err, result)
	}
	if err := s.StartSubscriptions(RefreshOptions{PollInterval: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("paused subscription fetched")
	}
	masked := s.GetConfiguration(false)
	config, _, _ := model.ParseSources([]byte(masked.Sources))
	copy := config.Sources[0].Subscription
	copy.Paused = false
	result, err = s.ConfigureSubscription(context.Background(), s.ActiveRevision(), "paused", copy)
	if err != nil || result.State != "committed" {
		t.Fatal("masked resume", err, result)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatal("scheduler failed to refresh", calls.Load())
	}
	s.Close()
	count := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != count {
		t.Fatal("refresh continued after close")
	}
}

func TestRefreshResourceCrashRecovery(t *testing.T) {
	for _, point := range []string{"revision-written", "active-written"} {
		t.Run(point, func(t *testing.T) {
			var version atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", fmt.Sprint(version.Load()))
				fmt.Fprintf(w, "proxies: [{name: route, type: direct, udp: %t}]", version.Load() == 0)
			}))
			defer server.Close()
			e := newEnv(t)
			s := e.open(DefaultProfile, "")
			configureRefresh(t, s, "sub", server.URL)
			first := refreshNow(t, s, "sub")
			if first.State != "current" {
				t.Fatal(first)
			}
			good := s.GetConfiguration(true)
			version.Store(1)
			s.opts.FailPoint = func(p string) error {
				if p == point {
					return fmt.Errorf("crash")
				}
				return nil
			}
			if status := refreshNow(t, s, "sub"); status.ErrorCode != "commit_failed" {
				t.Fatal("crash did not abort", status)
			}
			s.Close()
			s = e.open("", "")
			defer s.Close()
			cfg := s.GetConfiguration(true)
			if cfg.StartError != "" {
				t.Fatal("locked resources unavailable after crash", cfg.StartError)
			}
			if point == "revision-written" && cfg.Revision != good.Revision || point == "active-written" && cfg.Revision == good.Revision {
				t.Fatal("wrong recovered revision")
			}
			if status := refreshNow(t, s, "sub"); status.State != "current" {
				t.Fatal("cache recovery failed", status)
			}
		})
	}
}

func TestRefreshShutdownCancelsInflightRequest(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer server.Close()
	e := newEnv(t)
	s := e.open(DefaultProfile, "")
	configureRefresh(t, s, "slow", server.URL)
	if err := s.StartSubscriptions(RefreshOptions{PollInterval: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel subscription request")
	}
}
