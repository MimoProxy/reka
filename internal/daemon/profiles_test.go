//go:build !windows

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"golang.org/x/net/proxy"
)

const profileA = "schema-version: 1\ngroups: [{id: policy, type: select, members: [direct,reject], selected: direct}]\nrules: [{match: {all: true}, outbound: policy}]\n"

func profileOptions(t *testing.T, root string) Options {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	ln.Close()
	return Options{ProfileRoot: root, ProfileID: "alpha", ProfileResume: true, StateRoot: filepath.Join(root, "alpha"), ControlAddress: "-", DeferNetwork: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), InitialProfile: []byte(profileA), InitialLocal: []byte(fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\nnetwork: {mode: off}\n", address))}
}
func switchProfile(t *testing.T, k *Kernel, id, operation string) api.SwitchProfileResult {
	t.Helper()
	state, err := k.Service.ProfileState("")
	if err != nil {
		t.Fatal(err)
	}
	profile := profileA
	result, err := k.Service.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: id, BaseProfile: state.ProfileID, BaseEpoch: state.Epoch, BaseRevision: state.Revision, OperationID: operation, PreserveNetwork: true, InitialProfile: &profile})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func choose(t *testing.T, k *Kernel, member, op string) {
	t.Helper()
	raw, _ := json.Marshal(member)
	result, err := k.Service.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: k.Service.ActiveRevision(), Patch: []model.Op{{Op: "set", Path: "/groups/policy/selected", Value: raw}}}, OperationID: op})
	if err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
}
func TestAtomicProfilesKeepHistorySelectionsResourcesAndResume(t *testing.T) {
	root := t.TempDir()
	options := profileOptions(t, root)
	k, err := Start(options)
	if err != nil {
		t.Fatal(err)
	}
	choose(t, k, "reject", "alpha-choice")
	if result := switchProfile(t, k, "beta", "to-beta"); result.State != "committed" {
		t.Fatal(result)
	}
	if got := k.Service.GetConfiguration(true).Effective.Router.Route(context.Background(), router.Metadata{Domain: "example.test"}, nil); got.Outbound != "direct" {
		t.Fatal(got)
	}
	choose(t, k, "reject", "beta-choice")
	if result := switchProfile(t, k, "alpha", "back-alpha"); result.State != "committed" {
		t.Fatal(result)
	}
	if got := k.Service.GetConfiguration(true).Effective.Router.Route(context.Background(), router.Metadata{Domain: "example.test"}, nil); got.Outbound != "reject" {
		t.Fatal(got)
	}
	for _, id := range []string{"alpha", "beta"} {
		st, err := store.Open(filepath.Join(root, id))
		if err != nil {
			t.Fatal(err)
		}
		numbers, err := st.RevisionNumbers()
		if err != nil || len(numbers) != 2 {
			t.Fatal(id, numbers, err)
		}
	}
	if result := switchProfile(t, k, "beta", "resume-beta"); result.State != "committed" {
		t.Fatal(result)
	}
	k.Close()
	k, err = Start(options)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	state, _ := k.Service.ProfileState("")
	if state.ProfileID != "beta" || state.Revision != 2 {
		t.Fatal("durable workspace selection was not resumed", state)
	}
	if _, err := k.Service.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: "../escape", OperationID: "path-rejected"}); err == nil {
		t.Fatal("path accepted")
	}
}

func TestProfilePreparationFailureKeepsOldListenerAndConnection(t *testing.T) {
	root := t.TempDir()
	k, err := Start(profileOptions(t, root))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	config := k.Service.GetConfiguration(true)
	dialer, err := proxy.SOCKS5("tcp", config.Effective.Listeners[0].Listen.String(), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	check := func() {
		if _, err := connection.Write([]byte("same")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(connection, b); err != nil || string(b) != "same" {
			t.Fatal(string(b), err)
		}
	}
	check()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	target, err := store.Open(filepath.Join(root, "blocked"))
	if err != nil {
		t.Fatal(err)
	}
	local := []byte(fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", occupied.Addr().String()))
	rev, err := target.WriteRevision(store.Revision{Number: 1, Operation: "fixture", Source: "fixture"}, []byte(profileA), local, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.WriteActive(store.Active{Revision: 1, Profile: rev.Profile, Local: rev.Local, Sources: rev.Sources, Overlay: rev.Overlay, Operation: "fixture"}); err != nil {
		t.Fatal(err)
	}
	result := switchProfile(t, k, "blocked", "failed-port")
	if result.State != "rejected" || result.ProfileID != "alpha" {
		t.Fatal(result)
	}
	if k.Service.GetConfiguration(true).ProfileID != "alpha" {
		t.Fatal("failed switch changed active profile")
	}
	check()
	if success := switchProfile(t, k, "beta", "healthy-switch"); success.State != "committed" {
		t.Fatal(success)
	}
	check()
}
func TestProfileContextRejectsLateClientAndSlowSubscriptionCannotCrossProfiles(t *testing.T) {
	root := t.TempDir()
	k, err := Start(profileOptions(t, root))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	old, _ := k.Service.ProfileState("")
	var started atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started.Store(true); <-r.Context().Done() }))
	defer server.Close()
	result, err := k.Service.ConfigureSubscription(context.Background(), old.Revision, "shared", &model.Subscription{URL: server.URL, NodesOnly: true, Interval: 3600})
	if err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
	_, err = k.Service.QueueSubscription(context.Background(), "shared")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && !started.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	begin := time.Now()
	switched := switchProfile(t, k, "beta", "cancel-old-job")
	if switched.State != "committed" || time.Since(begin) > 3*time.Second {
		t.Fatal(switched, time.Since(begin))
	}
	release, err := k.Service.AcquireProfileCall(old.ProfileID, old.Epoch)
	if err == nil {
		release()
		t.Fatal("late profile context accepted")
	}
	if sources := k.Service.GetConfiguration(true).Sources; sources != "" && sources != "sources: []\n" {
		var parsed model.Sources
		_ = parsed
		if len(sources) > 0 {
			config, _, ds := model.ParseSources([]byte(sources))
			if ds.HasErrors() || len(config.Sources) != 0 {
				t.Fatal("old subscription reached new profile", sources)
			}
		}
	}
	statuses, err := k.Service.ListSubscriptions()
	if err != nil || len(statuses) != 0 {
		t.Fatal(statuses, err)
	}
}
func TestProfileSwitchCrashRecoveryAndDurableWriteFailure(t *testing.T) {
	for _, point := range []string{"profile-switch-intent", "profile-switch-activated", "profile-switch-before-pointer"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			options := profileOptions(t, root)
			options.FailPoint = func(at string) error {
				if at == point {
					return service.ErrCrashed
				}
				return nil
			}
			k, err := Start(options)
			if err != nil {
				t.Fatal(err)
			}
			state, _ := k.Service.ProfileState("")
			profile := profileA
			result, err := k.Service.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: "beta", BaseProfile: state.ProfileID, BaseEpoch: state.Epoch, BaseRevision: state.Revision, OperationID: "interrupted", PreserveNetwork: true, InitialProfile: &profile})
			if point == "profile-switch-before-pointer" {
				if err != nil || result.State != "failed" {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, service.ErrCrashed) {
				t.Fatal(result, err)
			}
			k.Close()
			k, err = Start(options)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()
			current, _ := k.Service.ProfileState("")
			if current.ProfileID != "alpha" {
				t.Fatal(current)
			}
			recorded, err := k.Service.ProfileSwitchOperation("interrupted")
			if err != nil || recorded.State != "failed" {
				t.Fatal(recorded, err)
			}
		})
	}
}

func TestProfileArchivePreservesImmutableHistorySubscriptionsAndCapabilities(t *testing.T) {
	root := t.TempDir()
	k, err := Start(profileOptions(t, root))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"profile-version\"")
		w.Header().Set("Subscription-Userinfo", "upload=12; download=34; total=1024; expire=2000000000")
		_, _ = io.WriteString(w, "proxies: [{name: Saved, type: socks5, server: 127.0.0.1, port: 9}]\n")
	}))
	defer server.Close()
	configured, err := k.Service.ConfigureSubscription(context.Background(), k.Service.ActiveRevision(), "subscription", &model.Subscription{URL: server.URL, Format: "clash", NodesOnly: true, Interval: 3600})
	if err != nil || configured.State != "committed" {
		t.Fatal(configured, err)
	}
	status, err := k.Service.RefreshSubscription(context.Background(), "subscription")
	if err != nil || status.State != "current" {
		t.Fatal(status, err)
	}
	choose(t, k, "reject", "record-choice")
	manifest, err := k.Service.ExportProfileArchive(api.ExportManifestRequest{Reveal: true, BaseRevision: k.Service.ActiveRevision()})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Resources) < 2 {
		t.Fatal("history and raw subscription not exported", manifest)
	}
	for _, desc := range manifest.Resources {
		read, err := k.Service.ReadResource(api.ReadResourceRequest{Reveal: true, BaseRevision: manifest.Revision, ArchiveHash: manifest.ArchiveHash, Hash: desc.Hash})
		if err != nil {
			t.Fatal(err)
		}
		if len(read.Data) != desc.Size {
			t.Fatal("unexpected small fixture chunk")
		}
		staged, err := k.Service.StageResource(api.StageResourceRequest{ProfileID: "clone", Hash: desc.Hash, Size: desc.Size, Data: read.Data})
		if err != nil || !staged.Ready {
			t.Fatal(staged, err)
		}
	}
	installed, err := k.Service.InstallProfile(api.InstallProfileRequest{ProfileID: "clone", ArchiveHash: manifest.ArchiveHash})
	if err != nil || installed.TargetRevision != manifest.Revision {
		t.Fatal(installed, err)
	}
	original, _ := store.Open(filepath.Join(root, "alpha"))
	cloned, _ := store.Open(filepath.Join(root, "clone"))
	versions, _ := original.RevisionNumbers()
	copies, _ := cloned.RevisionNumbers()
	if len(versions) != len(copies) {
		t.Fatal(versions, copies)
	}
	for _, n := range versions {
		before, p, l, e := original.ReadRevision(n)
		if e != nil {
			t.Fatal(e)
		}
		after, cp, cl, e := cloned.ReadRevision(n)
		if e != nil || before != after || !bytes.Equal(p, cp) || !bytes.Equal(l, cl) {
			t.Fatal("history changed", n, e)
		}
	}
	beforeCache, _ := os.ReadFile(filepath.Join(root, "alpha", "subscriptions", "subscription.json"))
	afterCache, _ := os.ReadFile(filepath.Join(root, "clone", "subscriptions", "subscription.json"))
	var before, after any
	_ = json.Unmarshal(beforeCache, &before)
	_ = json.Unmarshal(afterCache, &after)
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if !bytes.Equal(b, a) {
		t.Fatal("refresh validators/usage changed")
	}
	if _, err = k.Service.InstallProfile(api.InstallProfileRequest{ProfileID: "clone", ArchiveHash: manifest.ArchiveHash}); err == nil {
		t.Fatal("independent history overwritten")
	}
	if result := switchProfile(t, k, "clone", "activate-clone"); result.State != "committed" {
		t.Fatal(result)
	}
	statuses, err := k.Service.ListSubscriptions()
	if err != nil || len(statuses) != 1 || statuses[0].SourceID != "subscription" {
		t.Fatal(statuses, err)
	}
	if _, err = k.Service.ReadResource(api.ReadResourceRequest{Reveal: true, BaseRevision: manifest.Revision, ArchiveHash: manifest.ArchiveHash, Hash: manifest.ArchiveHash}); err == nil {
		t.Fatal("old archive capability survived switch")
	}
	// A malformed import cannot initialize or select another namespace.
	bad := []byte(`{"version":1,"active":{"revision":99},"revisions":[]}`)
	hash := resource.Hash(bad)
	_, err = k.Service.StageResource(api.StageResourceRequest{Hash: hash, Size: len(bad), Data: bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.Service.InstallProfile(api.InstallProfileRequest{ProfileID: "broken", ArchiveHash: hash}); err == nil {
		t.Fatal("invalid history installed")
	}
	state, _ := k.Service.ProfileState("broken")
	if state.ProfileID != "clone" || state.TargetExists {
		t.Fatal(state)
	}
}

func TestProfileSwitchOperationRetryAndStaleSessionCannotCrossEqualRevisions(t *testing.T) {
	k, err := Start(profileOptions(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	var response api.Message
	session := k.Handler.NewSession(func(raw []byte) error { response = api.Message{}; return json.Unmarshal(raw, &response) })
	defer session.Close()
	call := func(method string, params any) api.Message {
		p, _ := json.Marshal(params)
		raw, _ := json.Marshal(api.Request{ID: 1, Method: method, Params: p})
		session.Handle(raw)
		return response
	}
	if reply := call("Hello", map[string]any{"versions": []int{1}}); reply.Error != nil {
		t.Fatal(reply.Error)
	}
	base, _ := k.Service.ProfileState("")
	req := api.SwitchProfileRequest{ProfileID: "beta", BaseProfile: base.ProfileID, BaseEpoch: base.Epoch, BaseRevision: base.Revision, OperationID: "retry-switch", PreserveNetwork: true}
	first, err := k.Service.SwitchProfile(context.Background(), req)
	if err != nil || first.State != "committed" {
		t.Fatal(first, err)
	}
	if first.Revision != base.Revision {
		t.Fatal("fixture requires equal revision numbers")
	}
	if reply := call("GetConfiguration", nil); reply.Error == nil || reply.Error.Code != service.CodeConflict {
		t.Fatal("stale session accepted", reply)
	}
	if reply := call("GetProfileState", nil); reply.Error != nil {
		t.Fatal("recovery query blocked", reply.Error)
	}
	retry, err := k.Service.SwitchProfile(context.Background(), req)
	if err != nil || retry.Epoch != first.Epoch || retry.State != "committed" {
		t.Fatal(retry, err)
	}
	req.ProfileID = "gamma"
	if _, err = k.Service.SwitchProfile(context.Background(), req); err == nil {
		t.Fatal("operation ID reuse accepted")
	}
	if result := switchProfile(t, k, "alpha", "return-to-original"); result.State != "committed" {
		t.Fatal(result)
	}
	replay, err := k.Service.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: "beta", BaseProfile: base.ProfileID, BaseEpoch: base.Epoch, BaseRevision: base.Revision, OperationID: "retry-switch", PreserveNetwork: true})
	current, _ := k.Service.ProfileState("")
	if err != nil || replay.State != "committed" || current.ProfileID != "alpha" {
		t.Fatal("historical retry switched again", replay, current, err)
	}
}

func TestProfileCommittedCursorRecoversLostFinalOperationRecord(t *testing.T) {
	root := t.TempDir()
	options := profileOptions(t, root)
	kernel, err := Start(options)
	if err != nil {
		t.Fatal(err)
	}
	result := switchProfile(t, kernel, "beta", "lost-final-record")
	if result.State != "committed" {
		t.Fatal(result)
	}
	kernel.Close()
	path := filepath.Join(root, "profile-switches", "lost-final-record.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record["result"].(map[string]any)["state"] = "pending"
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	kernel, err = Start(options)
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Close()
	state, _ := kernel.Service.ProfileState("")
	recovered, err := kernel.Service.ProfileSwitchOperation("lost-final-record")
	if err != nil || state.ProfileID != "beta" || recovered.State != "committed" || state.Epoch != result.Epoch {
		t.Fatal(state, recovered, err)
	}
}

func TestManagedResourceRefreshStopsBeforeProfileSwitch(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{})
	cancelled := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = io.WriteString(w, "seed.test\n")
			return
		}
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer remote.Close()
	k, err := Start(profileOptions(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	added, err := k.Service.InstallManagedResource(ctx, api.InstallManagedResourceRequest{
		BaseRevision: k.Service.ActiveRevision(), Kind: "rule-set", ID: "sites", URL: remote.URL, Format: "text", Behavior: "domain",
	})
	if err != nil || added.State != "committed" {
		t.Fatal(added, err)
	}
	_, err = k.Service.RefreshManagedResource(ctx, api.RefreshManagedResourceRequest{Kind: "rule-set", ID: "sites"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if result := switchProfile(t, k, "beta", "managed-to-beta"); result.State != "committed" {
		t.Fatal(result)
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("old network request survived the switch")
	}
	statuses, err := k.Service.ListManagedResources()
	if err != nil || len(statuses) != 0 {
		t.Fatalf("the old resource crossed profiles: %+v %v", statuses, err)
	}
	if result := switchProfile(t, k, "alpha", "managed-back-alpha"); result.State != "committed" {
		t.Fatal(result)
	}
	statuses, err = k.Service.ListManagedResources()
	if err != nil || len(statuses) != 1 || statuses[0].Hash != resource.Hash([]byte("seed.test\n")) {
		t.Fatalf("the old profile lost its pinned resource: %+v %v", statuses, err)
	}
}
