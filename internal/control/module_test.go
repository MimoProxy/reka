package control

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	rt "github.com/MimoProxy/reka/internal/runtime/generation"
)

func TestModuleAPI(t *testing.T) {
	dir := t.TempDir()
	engine := rt.NewEngine(rt.EngineOptions{Backend: sagernet.Options{Logger: quiet()}})
	svc, err := service.Open(service.Options{StateRoot: dir, Engine: engine, Logger: quiet(), InitialProfile: []byte(testProfile)})
	if err != nil {
		engine.Close()
		t.Fatal(err)
	}
	defer svc.Close()
	server := NewServer(NewHandler(svc))
	defer server.Close()
	clientConn, serverConn := net.Pipe()
	go server.ServeConn(serverConn)
	client, err := api.NewClient(clientConn, "module-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var caps Capabilities
	if err := client.Call("GetCapabilities", nil, &caps); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.SourceFormats, "surge-module") {
		t.Fatalf("module source format missing from capabilities: %v", caps.SourceFormats)
	}
	for _, method := range []string{
		"AddModule", "RemoveModule", "SetModuleEnabled", "SetModuleArguments",
		"RefreshModule", "ListModules", "GetModuleReport", "PreviewModule",
	} {
		if !slices.Contains(caps.Methods, method) {
			t.Fatalf("%s missing from capabilities", method)
		}
	}

	const data = "#!name=Example rules\n#!arguments=TARGET:DIRECT\n[Rule]\nDOMAIN,ads.example.com,{{{TARGET}}}\n"
	path := filepath.Join(dir, "example.sgmodule")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := client.PreviewModule(api.PreviewModuleRequest{Data: data, Arguments: map[string]string{"TARGET": "REJECT"}})
	if err != nil || !preview.CanApply || preview.Rules.Imported != 1 || len(preview.Arguments) != 1 || preview.Arguments[0].Value != "REJECT" {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	modules, err := client.ListModules()
	if err != nil || len(modules) != 0 {
		t.Fatalf("preview changed module list: %+v %v", modules, err)
	}

	assertCommit := func(result api.Result, err error) uint64 {
		t.Helper()
		if err != nil || result.State != "committed" {
			t.Fatalf("commit: %+v %v", result, err)
		}
		return result.Revision
	}
	var cfg api.Configuration
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil {
		t.Fatal(err)
	}
	position := 0
	revision := assertCommit(client.AddModule(api.AddModuleRequest{
		Module: model.Module{ID: "example", File: path}, BaseRevision: cfg.Revision, Position: &position,
	}))
	modules, err = client.ListModules()
	if err != nil || len(modules) != 1 || !modules[0].Enabled || modules[0].SourceType != "file" ||
		modules[0].Name != "Example rules" || len(modules[0].Arguments) != 1 || modules[0].Status.RootHash == "" ||
		modules[0].Report == nil || modules[0].Report.Rules.Imported != 1 {
		t.Fatalf("list: %+v %v", modules, err)
	}
	reply, err := client.GetModuleReport(api.GetModuleReportRequest{ModuleID: "example"})
	if err != nil || !reply.CanApply || reply.ModuleID != "example" || len(reply.Lines) == 0 {
		t.Fatalf("report: %+v %v", reply, err)
	}
	raw, err := json.Marshal(reply.Lines)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ads.example.com") {
		t.Fatal("report includes rule text")
	}
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil || cfg.Effective == nil || !cfg.Effective.Modules["example"].CanApply {
		t.Fatalf("configuration has no module report: %v", err)
	}

	disabled, enabled := false, true
	revision = assertCommit(client.SetModuleEnabled(api.SetModuleEnabledRequest{ModuleID: "example", Enabled: &disabled, BaseRevision: revision}))
	modules, err = client.ListModules()
	if err != nil || len(modules) != 1 || modules[0].Enabled {
		t.Fatalf("disabled: %+v %v", modules, err)
	}
	revision = assertCommit(client.SetModuleArguments(api.SetModuleArgumentsRequest{
		ModuleID: "example", Arguments: map[string]string{"TARGET": "REJECT"}, BaseRevision: revision,
	}))
	revision = assertCommit(client.SetModuleEnabled(api.SetModuleEnabledRequest{ModuleID: "example", Enabled: &enabled, BaseRevision: revision}))
	reply, err = client.GetModuleReport(api.GetModuleReportRequest{ModuleID: "example"})
	if err != nil || len(reply.Arguments) != 1 || reply.Arguments[0].Value != "REJECT" {
		t.Fatalf("updated arguments: %+v %v", reply, err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(data, "ads.example.com", "cdn.example.com", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.Call("Subscribe", map[string][]string{"types": {"module.updated"}}, nil); err != nil {
		t.Fatal(err)
	}
	status, err := client.RefreshModule(api.RefreshModuleRequest{ModuleID: "example", Wait: true})
	if err != nil || status.State != "current" || status.Revision <= revision ||
		status.RootHash == "" || status.RootHash == modules[0].Status.RootHash {
		t.Fatalf("refresh: %+v %v", status, err)
	}
	deadline := time.After(3 * time.Second)
waitForRefresh:
	for {
		select {
		case event, ok := <-client.Events:
			if !ok {
				t.Fatal("event stream closed")
			}
			fields, _ := event.Data.(map[string]any)
			if event.Type == "module.updated" && fields["module_id"] == "example" && fields["root_hash"] == status.RootHash {
				break waitForRefresh
			}
		case <-deadline:
			t.Fatal("refresh event missing")
		}
	}
	assertCommit(client.RemoveModule(api.RemoveModuleRequest{ModuleID: "example", BaseRevision: status.Revision}))
	modules, err = client.ListModules()
	if err != nil || len(modules) != 0 {
		t.Fatalf("remove: %+v %v", modules, err)
	}
	if _, err := client.GetModuleReport(api.GetModuleReportRequest{ModuleID: "example"}); err == nil {
		t.Fatal("removed module still has a report")
	}
}
