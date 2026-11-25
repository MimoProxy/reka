package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

type managedScriptTransport func(*http.Request) (*http.Response, error)

func (f managedScriptTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestManagedScriptDownloadRefresh(t *testing.T) {
	e := newEnv(t)
	blobs, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	const seed = `$done({});`
	const updated = `$done();`
	hash, err := blobs.Put([]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`schema-version: 1
scripts:
  - id: response
    type: http-response
    pattern: '^https://example\.test/'
    hash: %s
    download: {url: 'https://cdn.example.test/script?token=private-value', automatic: true}
`, hash)
	s := e.open(profile, "")
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mode atomic.Int32
	var conditional atomic.Bool
	client := &http.Client{Transport: managedScriptTransport(func(r *http.Request) (*http.Response, error) {
		res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {`"script"`}}}
		body := updated
		switch mode.Load() {
		case 1:
			body = "\xff"
		case 2:
			res.ContentLength = model.MaxScriptSize + 1
		case 3:
			body = ""
		default:
			if r.Header.Get("If-None-Match") == `"script"` {
				conditional.Store(true)
				res.StatusCode = http.StatusNotModified
				body = ""
			}
		}
		res.Body = io.NopCloser(strings.NewReader(body))
		return res, nil
	})}
	if err := s.StartSubscriptions(RefreshOptions{Client: client, PollInterval: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	for {
		statuses, err := s.ListManagedResources()
		if err != nil || len(statuses) != 1 {
			t.Fatal(statuses, err)
		}
		status := statuses[0]
		if status.State == "ready" {
			delay := status.NextAttempt.Sub(status.LastAttempt)
			interval := model.DefaultResourceInterval * time.Second
			if status.Kind != "script" || !status.Automatic || status.Hash != resource.Hash([]byte(updated)) ||
				delay < interval || delay >= interval+10*time.Second {
				t.Fatalf("unexpected automatic refresh: %+v", status)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("automatic refresh did not finish: %+v", status)
		case <-time.After(10 * time.Millisecond):
		}
	}
	req := api.RefreshManagedResourceRequest{Kind: "script", ID: "response", Wait: true}
	revision := s.ActiveRevision()
	status, err := s.RefreshManagedResource(ctx, req)
	if err != nil || status.State != "ready" || status.Revision != revision || !conditional.Load() {
		t.Fatal("conditional refresh did not preserve the revision", status, err)
	}
	for _, tc := range []struct {
		mode int32
		code string
	}{{1, "resource_invalid"}, {2, "body_too_large"}, {3, "empty_body"}} {
		mode.Store(tc.mode)
		status, err := s.RefreshManagedResource(ctx, req)
		if err != nil || status.State != "stale" || status.ErrorCode != tc.code || status.Hash != resource.Hash([]byte(updated)) || s.ActiveRevision() != revision {
			t.Fatalf("invalid source replaced the active script: %+v %v", status, err)
		}
	}
	configuration := s.GetConfiguration(false)
	if strings.Contains(configuration.Profile, "private-value") || configuration.Effective == nil || len(configuration.Effective.Scripts) != 1 || configuration.Effective.Scripts[0].Hash != resource.Hash([]byte(updated)) {
		t.Fatal("unexpected active script state")
	}
}

func TestManagedScriptFileRefresh(t *testing.T) {
	e := newEnv(t)
	blobs, err := resource.Open(e.root)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := blobs.Put([]byte(`$done({});`))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "response.js")
	const updated = `$done();`
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf("schema-version: 1\nscripts: [{id: response, type: http-response, pattern: '.*', hash: %s, file: %q}]\n", hash, path)
	s := e.open(profile, "")
	defer s.Close()
	statuses, err := s.ListManagedResources()
	if err != nil || len(statuses) != 1 || statuses[0].State != "pending" || statuses[0].Automatic {
		t.Fatal(statuses, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := s.ActiveRevision()
	req := api.RefreshManagedResourceRequest{Kind: "script", ID: "response", Wait: true}
	status, err := s.RefreshManagedResource(ctx, req)
	if err != nil || status.State != "ready" || status.Hash != resource.Hash([]byte(updated)) || status.Revision <= before || !status.NextAttempt.IsZero() {
		t.Fatal(status, err)
	}
	if snapshot, err := blobs.Read(status.Hash); err != nil || string(snapshot) != updated {
		t.Fatalf("file content was not pinned: %s %v", snapshot, err)
	}
	if err := os.WriteFile(path, []byte{0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	failed, err := s.RefreshManagedResource(ctx, req)
	if err != nil || failed.State != "stale" || failed.ErrorCode != "resource_invalid" || failed.Hash != status.Hash || s.ActiveRevision() != status.Revision {
		t.Fatal(failed, err)
	}
	_, err = s.InstallManagedResource(ctx, api.InstallManagedResourceRequest{Kind: "script", ID: "new"})
	exportErrorCode(t, err, CodeBadRequest)
}

func TestManagedScriptRejectsRelativeFileHiddenByOverlay(t *testing.T) {
	e := newEnv(t)
	hash := resource.Hash([]byte(`$done();`))
	s := e.open(DefaultProfile, "")
	defer s.Close()
	profile := fmt.Sprintf("schema-version: 1\nscripts: [{id: response, type: http-response, pattern: '.*', hash: %s, file: response.js}]\n", hash)
	overlay := "patches: [{op: remove, path: /scripts/response}]\n"
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile, Overlay: &overlay})
	statuses, err := s.ListManagedResources()
	if err != nil || len(statuses) != 0 {
		t.Fatal(statuses, err)
	}
	_, err = s.RefreshManagedResource(context.Background(), api.RefreshManagedResourceRequest{Kind: "script", ID: "response", Wait: true})
	exportErrorCode(t, err, CodeNotFound)
}
