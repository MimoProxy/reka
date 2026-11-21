package service

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

func TestStageResourceChunkRetryAndStrictImport(t *testing.T) {
	env := newEnv(t)
	s := env.open(DefaultProfile, "")
	defer s.Close()
	large := bytes.Repeat([]byte("resource-data"), 170000)
	hash := resource.Hash(large)
	first := api.StageResourceRequest{Hash: hash, Size: len(large), Data: large[:1<<20]}
	result, err := s.StageResource(first)
	if err != nil || result.Ready || result.Received != 1<<20 {
		t.Fatal(result, err)
	}
	retry, err := s.StageResource(first)
	if err != nil || retry.Received != result.Received {
		t.Fatal("chunk retry appended twice", retry, err)
	}
	if _, err := s.StageResource(api.StageResourceRequest{Hash: hash, Size: len(large), Offset: 1, Data: []byte("wrong")}); err == nil {
		t.Fatal("conflicting retry accepted")
	}
	for offset := 1 << 20; offset < len(large); offset += 1 << 20 {
		result, err = s.StageResource(api.StageResourceRequest{Hash: hash, Size: len(large), Offset: offset, Data: large[offset:min(offset+1<<20, len(large))]})
		if err != nil {
			t.Fatal(result, err)
		}
	}
	if !result.Ready {
		t.Fatal(result)
	}
	got, err := resource.At(env.root).Read(hash)
	if err != nil || !bytes.Equal(got, large) || s.ActiveRevision() != 1 {
		t.Fatal("staging changed config or bytes", err)
	}
	provider := []byte("example.test\n")
	providerHash := resource.Hash(provider)
	if _, err := s.StageResource(api.StageResourceRequest{Hash: providerHash, Size: len(provider), Data: provider}); err != nil {
		t.Fatal(err)
	}
	request := importer.Request{SourceID: "owned", Format: "clash", Data: `proxies: [{name: node, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: private}]
proxy-groups: [{name: proxy, type: select, proxies: [node, DIRECT]}]
rule-providers: {domains: {type: file, path: never-read.txt, behavior: domain, format: text}}
rules: ["RULE-SET,domains,proxy", "MATCH,DIRECT"]
`, ProviderResources: map[string]string{"rule-providers/domains": providerHash}}
	preview := s.PreviewImport(request, false)
	if !preview.Report.CanApply {
		t.Fatal(preview.Report.Diagnostics)
	}
	profile := "schema-version: 1\nimports: [{source: owned, outbounds: true, groups: true, rule-sets: true}]\nrules: [{source: owned}]\n"
	resultCommit, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Profile: &profile, Import: &request}, OperationID: "owned-import"})
	if err != nil || resultCommit.State != store.OpCommitted {
		t.Fatal(resultCommit, err)
	}
	explanation, err := s.Engine().Explain(context.Background(), generation.ExplainRequest{Destination: "example.test:443"})
	if err != nil || explanation.OutboundType != "shadowsocks" {
		t.Fatal(explanation, err)
	}
	request.ProviderResources["rule-providers/domains"] = strings.Repeat("0", 64)
	if s.PreviewImport(request, false).Report.CanApply {
		t.Fatal("missing immutable blob accepted")
	}
}

func TestLocalAuthenticationMaskRoundTripAndConflict(t *testing.T) {
	env := newEnv(t)
	var local string
	s, _ := env.openOn(DefaultProfile, func(port int) string {
		local = strings.Replace(localWith(port), "}", ", users: [{username: Alice, password: local-private-password}]}", 1)
		return local
	})
	defer s.Close()
	masked := s.GetConfiguration(false)
	if strings.Contains(masked.Local, "local-private-password") || strings.Contains(masked.Local, "Alice") || !strings.Contains(masked.Local, "********") {
		t.Fatal("local authentication was not masked")
	}
	updated := masked.Local + "log: {level: warn}\n"
	res, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Local: &updated}, OperationID: "masked-local"})
	if err != nil || res.State != store.OpCommitted {
		t.Fatal(res, err)
	}
	if !strings.Contains(s.GetConfiguration(true).Local, "local-private-password") {
		t.Fatal("mask overwrote the credential")
	}
	stale := strings.Replace(local, "local-private-password", "another-private-password", 1)
	conflict, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1, Local: &stale}})
	if err != nil || conflict.Conflict == nil {
		t.Fatal(conflict, err)
	}
	for _, change := range conflict.Conflict.Changes {
		if change.From == "local-private-password" || change.To == "local-private-password" {
			t.Fatal("conflict exposed local credentials")
		}
	}
}

func TestDeferredStartupCommitsStandbyBeforePersistedTakeover(t *testing.T) {
	env := newEnv(t)
	storage, err := store.Open(env.root)
	if err != nil {
		t.Fatal(err)
	}
	profile := []byte(profileWith("alt"))
	local := []byte("# keep this comment\nnetwork: {mode: tun}\nlog: {level: warn}\n")
	if _, err := storage.WriteRevision(store.Revision{Number: 1, Operation: "seed", Created: time.Now()}, profile, local, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteActive(store.Active{Revision: 1, Profile: store.Hash(profile), Local: store.Hash(local), Sources: store.Hash(nil), Overlay: store.Hash(nil), Operation: "seed"}); err != nil {
		t.Fatal(err)
	}
	open := func() *Service {
		t.Helper()
		engine := generation.NewEngine(generation.EngineOptions{})
		s, err := Open(Options{StateRoot: env.root, Engine: engine, Secrets: env.sec, Logger: quiet(), DeferNetwork: true})
		if err != nil {
			engine.Close()
			t.Fatal(err)
		}
		return s
	}
	s := open()
	cfg := s.GetConfiguration(true)
	if cfg.Revision != 2 || cfg.StartError != "" || cfg.Effective.Network.Mode != "off" || cfg.Profile != string(profile) || !strings.Contains(cfg.Local, "keep this comment") {
		s.Close()
		t.Fatal("standby was not durable and coherent", cfg.Revision, cfg.StartError)
	}
	if selected, _, err := cfg.Effective.Router.Resolve("proxy"); err != nil || selected != "alt" {
		s.Close()
		t.Fatal("standby lost selection", selected, err)
	}
	s.Close()
	s = open()
	defer s.Close()
	if s.ActiveRevision() != 2 {
		t.Fatal("already-off startup created another revision")
	}
}
