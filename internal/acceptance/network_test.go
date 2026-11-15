package acceptance

import (
	"context"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"io"
	"path/filepath"
	"runtime"
	"testing"
)

type networkCloser struct{ n *int }

func (c networkCloser) Close() error { *c.n++; return nil }

// Tests coordinator integration on every desktop CI runner without changing
// any host routes or DNS. Real driver checks live in tools/tunsmoke.
func TestNetworkTransactionsKeepDeviceForRules(t *testing.T) {
	starts, closes := 0, 0
	h := platform.NetworkHooks{StartTUN: func(platform.TUNConfig) (io.Closer, string, error) {
		starts++
		return networkCloser{&closes}, "fake", nil
	}}
	root := filepath.Join(t.TempDir(), "state")
	eng := generation.NewEngine(generation.EngineOptions{StateRoot: root, NetworkHooks: &h})
	defer eng.Close()
	svc, e := service.Open(service.Options{StateRoot: root, Engine: eng, InitialProfile: []byte("schema-version: 1\nrules: [{id: final, match: {all: true}, outbound: direct}]\n")})
	if e != nil {
		t.Fatal(e)
	}
	defer svc.Close()
	if runtime.GOOS == "linux" {
		t.Skip("Linux takeover intentionally unsupported")
	}
	local := "network: {mode: tun, tun: {routes: [198.18.0.0/24]}}\n"
	res, e := svc.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: svc.ActiveRevision(), Local: &local}})
	if e != nil || res.State != "committed" {
		t.Fatal(res, e)
	}
	before := eng.Status()
	r, e := svc.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: svc.ActiveRevision(), Patch: []model.Op{{Op: "set", Path: "/rules/final/outbound", Value: []byte(`"reject"`)}}}})
	if e != nil || r.State != "committed" {
		t.Fatal(r, e)
	}
	if r.Plan.NetworkChanged || r.Plan.Interrupts || starts != 1 || closes != 0 || eng.Status().Network != before.Network {
		t.Fatal(r.Plan, eng.Status())
	}
	_ = starts
	_ = closes
}
