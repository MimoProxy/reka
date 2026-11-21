package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/testnet"
)

func TestDeferredStartupAllowsAlreadyOffSecretRepairOnly(t *testing.T) {
	for _, tc := range []struct {
		name, local string
		repair      bool
	}{
		{name: "already off", local: "network: {mode: off}\n", repair: true},
		{name: "takeover requires valid standby transaction", local: "network: {mode: tun}\n"},
		{name: "invalid local cannot confirm standby", local: "network: [broken]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t)
			storage, err := store.Open(env.root)
			if err != nil {
				t.Fatal(err)
			}
			profile := []byte(strings.Replace(profileWith("alt"), "outbounds:\n", "outbounds:\n  - {id: ss, type: shadowsocks, server: 192.0.2.1, port: 8388, method: aes-128-gcm, password: secret://outbounds/ss/missing}\n", 1))
			local := []byte(tc.local)
			if _, err := storage.WriteRevision(store.Revision{Number: 1, Operation: "seed", Created: time.Now()}, profile, local, nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := storage.WriteActive(store.Active{Revision: 1, Profile: store.Hash(profile), Local: store.Hash(local), Sources: store.Hash(nil), Overlay: store.Hash(nil), Operation: "seed"}); err != nil {
				t.Fatal(err)
			}
			engine := generation.NewEngine(generation.EngineOptions{Backend: backendOptions()})
			defer engine.Close()
			svc, err := Open(Options{StateRoot: env.root, Engine: engine, Secrets: env.sec, Logger: quiet(), DeferNetwork: true})
			if !tc.repair {
				if err == nil {
					svc.Close()
					t.Fatal("unsafe standby failure exposed as a successful startup")
				}
				if eff, _ := engine.Effective(); eff != nil {
					t.Fatal("invalid standby activated a runtime")
				}
				active, readErr := storage.ReadActive()
				if readErr != nil || active.Revision != 1 {
					t.Fatal("invalid standby replaced stored revision", active, readErr)
				}
				return
			}
			if err != nil {
				t.Fatal("already-off configuration must remain repairable", err)
			}
			defer svc.Close()
			if svc.StartError() == "" {
				t.Fatal("missing secret startup error was lost")
			}
			cfg := svc.GetConfiguration(true)
			if cfg.Revision != 1 || cfg.Profile != string(profile) || cfg.Local != tc.local {
				t.Fatal("repair documents were lost", cfg)
			}
			if eff, _ := engine.Effective(); eff != nil {
				t.Fatal("bad profile started before repair")
			}
			repaired := profileWith("alt")
			result, err := svc.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Profile: &repaired}, OperationID: "repair-off-profile"})
			if err != nil || result.State != store.OpCommitted || svc.StartError() != "" {
				t.Fatal("repair failed", result, err, svc.StartError())
			}
			eff, _ := engine.Effective()
			if eff == nil || eff.Network.Mode != "off" {
				t.Fatal("repair enabled network takeover")
			}
		})
	}
}

func TestProfileSwitchWriteFailureRestoresRepairMode(t *testing.T) {
	if !profileWorkspaceSupported() {
		t.Skip("profile workspaces are unavailable")
	}
	root := t.TempDir()
	workspace, err := OpenProfileWorkspace(root, "repair", false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	state, err := workspace.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	engine := generation.NewEngine(generation.EngineOptions{ProfileID: "repair", Backend: backendOptions()})
	defer engine.Close()
	profile := strings.Replace(profileWith("alt"), "outbounds:\n", "outbounds:\n  - {id: ss, type: shadowsocks, server: 192.0.2.1, port: 8388, method: aes-128-gcm, password: secret://outbounds/ss/missing}\n", 1)
	s, err := Open(Options{StateRoot: state, Engine: engine, Logger: quiet(), InitialProfile: []byte(profile),
		ProfileSecrets: func(string) (secret.Store, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BindProfiles(workspace); err != nil {
		t.Fatal(err)
	}
	startError := s.StartError()
	if eff, _ := engine.Effective(); startError == "" || eff != nil {
		t.Fatalf("initial profile did not start in repair mode: %s", startError)
	}
	before, err := s.ProfileState("")
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := os.ReadFile(workspace.cursorPath())
	if err != nil {
		t.Fatal(err)
	}

	var (
		req      api.SwitchProfileRequest
		res      api.SwitchProfileResult
		injected bool
		attempt  int
	)
	s.writeActive = func(st *store.Store, active store.Active) error {
		if err := st.WriteActive(active); err != nil {
			return err
		}
		if !injected {
			injected = true
			return errors.New("could not sync target active record")
		}
		return nil
	}
	// The switch binds the target listener itself. If another process takes
	// the port first, the switch fails before the injected write and is
	// retried on another port.
	address := testnet.RetryAddr(t, func(listen netip.AddrPort) (err error) {
		attempt++
		targetProfile := DefaultProfile + fmt.Sprintf("listeners: [{id: ready, type: http, listen: %q}]\n", listen.String())
		req = api.SwitchProfileRequest{ProfileID: "ready", BaseProfile: before.ProfileID, BaseEpoch: before.Epoch,
			BaseRevision: before.Revision, OperationID: fmt.Sprintf("switch-to-ready-%d", attempt), InitialProfile: &targetProfile}
		injected = false
		if res, err = s.SwitchProfile(context.Background(), req); err != nil {
			return err
		}
		if !injected && res.Error != nil && testnet.InUse(errors.New(res.Error.Message)) {
			return errors.New(res.Error.Message)
		}
		return nil
	}).String()
	if !injected || res.State != store.OpFailed || res.Degraded {
		t.Fatalf("switch after active write error: %+v", res)
	}
	after, err := s.ProfileState("")
	if err != nil || after != before || s.StartError() != startError {
		t.Fatalf("recorded repair state changed: %+v, %s, %v", after, s.StartError(), err)
	}
	saved, err := os.ReadFile(workspace.cursorPath())
	if err != nil || !bytes.Equal(saved, cursor) {
		t.Fatalf("workspace cursor changed: %s, %v", saved, err)
	}
	if eff, revision := engine.Effective(); eff != nil || revision != 0 {
		t.Errorf("target runtime remained active at revision %d", revision)
	}
	if _, ok := engine.ListenerAddr("ready"); ok {
		t.Error("target listener remained tracked")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("target listener did not release its address: %v", err)
	}
	ln.Close()
	_, scope := engine.History()
	if scope.ProfileID != before.ProfileID {
		t.Fatalf("runtime profile was not restored: %+v", scope)
	}
	req.OperationID = "retry-switch-to-ready"
	if res, err := s.SwitchProfile(context.Background(), req); err != nil || res.State != store.OpCommitted || s.StartError() != "" {
		t.Fatalf("retrying the switch: %+v, %v", res, err)
	}
}
