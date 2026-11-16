package service

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

type profileTUNCloser func() error

func (f profileTUNCloser) Close() error { return f() }

func TestProfileSwitchPreservesUnchangedTUNAndRollsBackActivationFailure(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenProfileWorkspace(root, "alpha", false, true)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := workspace.StateRoot()
	starts, closes := 0, 0
	hooks := &platform.NetworkHooks{StartTUN: func(c platform.TUNConfig) (io.Closer, string, error) {
		if c.MTU == 1400 {
			return nil, "", errors.New("injected TUN preparation failure")
		}
		starts++
		return profileTUNCloser(func() error { closes++; return nil }), "isolated-fake-tun", nil
	}}
	engine := generation.NewEngine(generation.EngineOptions{StateRoot: state, NetworkHooks: hooks})
	profile := "schema-version: 1\ndns: {nameserver: [1.1.1.1], default-nameserver: [1.1.1.1], proxy-server-nameserver: [1.1.1.1]}\nrules: [{match: {all: true}, outbound: direct}]\n"
	local := "network: {mode: tun, tun: {mtu: 1500, address4: 172.29.0.1/30, dns-hijack: true}}\n"
	svc, err := Open(Options{StateRoot: state, Engine: engine, InitialProfile: []byte(profile), InitialLocal: []byte(local)})
	if err != nil {
		workspace.Close()
		engine.Close()
		t.Fatal(err)
	}
	defer svc.Close()
	if err = svc.BindProfiles(workspace); err != nil {
		t.Fatal(err)
	}
	if svc.GetConfiguration(true).StartError != "" || starts != 1 {
		t.Fatal(svc.GetConfiguration(true).StartError, starts)
	}
	first, _ := svc.ProfileState("")
	moved, err := svc.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: "beta", BaseProfile: first.ProfileID, BaseEpoch: first.Epoch, BaseRevision: first.Revision, OperationID: "reuse-tun", PreserveNetwork: true, InitialProfile: &profile})
	if err != nil || moved.State != "committed" || starts != 1 || closes != 0 {
		t.Fatal(moved, starts, closes, err)
	}
	target, err := store.Open(filepath.Join(root, "gamma"))
	if err != nil {
		t.Fatal(err)
	}
	revision, err := target.WriteRevision(store.Revision{Number: 1}, []byte(profile), []byte("network: {mode: tun, tun: {mtu: 1400, address4: 172.29.0.1/30, dns-hijack: true}}\n"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.WriteActive(store.Active{Revision: 1, Profile: revision.Profile, Local: revision.Local, Sources: revision.Sources, Overlay: revision.Overlay}); err != nil {
		t.Fatal(err)
	}
	second, _ := svc.ProfileState("")
	failed, err := svc.SwitchProfile(context.Background(), api.SwitchProfileRequest{ProfileID: "gamma", BaseProfile: second.ProfileID, BaseEpoch: second.Epoch, BaseRevision: second.Revision, OperationID: "restore-tun", PreserveNetwork: true})
	network := engine.Status().Network
	after, _ := svc.ProfileState("")
	if err != nil || failed.State != "failed" || failed.Degraded || after.ProfileID != "beta" || after.Epoch != second.Epoch || network.Mode != "tun" || network.State != "Running" {
		t.Fatal(failed, after, network, err)
	}
	if starts != 2 || closes != 1 {
		t.Fatal("failed target did not restore previous TUN", starts, closes)
	}
	if err = svc.DeleteInactiveProfile("alpha", after.ProfileID, after.Epoch); err == nil {
		t.Fatal("live runtime journal deleted")
	}
	if err = svc.DeleteInactiveProfile("gamma", after.ProfileID, after.Epoch); err != nil {
		t.Fatal(err)
	}
	deleted, err := svc.ProfileState("gamma")
	if err != nil || deleted.TargetExists {
		t.Fatal(deleted, err)
	}
}
