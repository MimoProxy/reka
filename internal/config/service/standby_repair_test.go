package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/runtime/generation"
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
