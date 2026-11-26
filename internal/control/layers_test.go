package control

import (
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/service"
)

func TestLayerAPIContract(t *testing.T) {
	addr, _ := startServer(t)
	c, err := Connect(addr, "source-test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var caps Capabilities
	if err = c.Call("GetCapabilities", nil, &caps); err != nil || len(caps.ConfigurationLayers) != 5 || !slices.Equal(caps.SourceFormats, []string{"native", "clash", "links", "wireguard", "surge-module", "loon-module", "stash-module"}) {
		t.Fatalf("capabilities: %+v %v", caps, err)
	}
	profile := "schema-version: 1\nimports: [{source: sub, outbounds: true, groups: true}]\nrules: [{match: {all: true}, outbound: sub/proxy}]\n"
	sources := "sources: [{id: sub, outbounds: [{id: node, type: socks, server: 127.0.0.1, port: 1080, username: usr, password: private-value}], groups: [{id: proxy, type: select, members: [node]}]}]\n"
	overlay := "patches: [{op: set, path: /outbounds/sub~1node/port, value: 2080}]\n"
	req := service.ChangeRequest{BaseRevision: 1, Profile: &profile, Sources: &sources, Overlay: &overlay}
	var plan service.PlanResult
	if err = c.Call("PlanConfiguration", req, &plan); err != nil || !plan.Valid {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	var result service.Result
	if err = c.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: req, PlanHash: plan.PlanHash}, &result); err != nil || result.State != "committed" {
		t.Fatalf("commit: %+v %v", result, err)
	}
	var cfg service.Configuration
	if err = c.Call("GetConfiguration", nil, &cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg.Sources, "private-value") || cfg.Overlay != overlay || len(cfg.Effective.SourceHashes["sub"]) != 64 {
		t.Fatalf("configuration: %+v", cfg)
	}
	var restored service.Result
	if err = c.Call("RestoreRevision", service.RestoreRequest{Revision: 1, BaseRevision: result.Revision}, &restored); err != nil || restored.State != "committed" {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	if err = c.Call("GetConfiguration", nil, &cfg); err != nil || cfg.Sources != "" || cfg.Overlay != "" {
		t.Fatalf("restored: %+v %v", cfg, err)
	}
}
