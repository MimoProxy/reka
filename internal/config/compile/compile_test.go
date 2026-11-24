package compile

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/secret"
)

const profile = `schema-version: 1
outbounds:
  - id: vps
    type: vless
    server: vps.example
    port: 443
    uuid: secret://outbounds/vps/uuid
    flow: xtls-rprx-vision
    tls:
      server-name: www.example.com
      fingerprint: chrome
      reality: {public-key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", short-id: "ab12"}
  - id: ss
    type: shadowsocks
    server: 192.0.2.1
    port: 8388
    method: aes-128-gcm
    password: pw
groups:
  - id: proxy
    type: select
    members: [vps, ss, direct]
    selected: ss
rules:
  - id: lan
    match: {ip-cidr: 192.168.0.0/16, no-resolve: true}
    outbound: direct
  - match: {domain-suffix: [example.org]}
    outbound: proxy
  - id: final
    match: {all: true}
    outbound: proxy
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:7890"}
log: {level: warn}
`

func store(t *testing.T) secret.Store {
	s, err := secret.NewFileStore(filepath.Join(t.TempDir(), "s.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Set("outbounds/vps/uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")
	return s
}

func TestCompile(t *testing.T) {
	local := "listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:17890\"}\n"
	eff, diags := Compile([]byte(profile), []byte(local), Options{Secrets: store(t)})
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	vps, _ := eff.Outbound("vps")
	if vps.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" || vps.TLS.Reality == nil {
		t.Fatalf("vps %+v", vps)
	}
	if _, ok := eff.Outbound("direct"); !ok {
		t.Fatal("no built-in direct")
	}
	if len(eff.Listeners) != 1 || eff.Listeners[0].Listen.Port() != 17890 {
		t.Fatalf("listeners %+v", eff.Listeners)
	}
	o, _ := eff.OriginOf("/listeners/mixed/listen")
	if o.Layer != LayerLocal || o.Line != 2 {
		t.Fatalf("listener origin %+v", o)
	}
	o, _ = eff.OriginOf("/listeners")
	if o.Overrides == nil || o.Overrides.Layer != LayerProfile {
		t.Fatalf("override not recorded: %+v", o)
	}
	if o, _ := eff.OriginOf("/log/level"); o.Layer != LayerProfile || eff.LogLevel != "warn" {
		t.Fatalf("log level %s from %+v", eff.LogLevel, o)
	}
	if o, _ := eff.OriginOf("/outbounds/reject"); o.Layer != LayerDefault {
		t.Fatalf("reject origin %+v", o)
	}
	if o, _ := eff.OriginOf("/groups/proxy/selected"); o.Layer != LayerProfile || o.Line != 23 {
		t.Fatalf("selected origin %+v", o)
	}
	if eff.Router == nil {
		t.Fatal("no router")
	}
	if out, chain, _ := eff.Router.Resolve("proxy"); out != "ss" || len(chain) != 1 {
		t.Fatalf("proxy -> %s %v", out, chain)
	}
}

func TestFingerprintFollowsSecret(t *testing.T) {
	s := store(t)
	a, _ := Compile([]byte(profile), nil, Options{Secrets: s})
	b, _ := Compile([]byte(strings.Replace(profile, "selected: ss", "selected: vps", 1)), nil, Options{Secrets: s})
	s.Set("outbounds/vps/uuid", "c831381d-6324-4d53-ad4f-8cda48b30811")
	c, _ := Compile([]byte(profile), nil, Options{Secrets: s})
	fa, _ := a.Outbound("vps")
	fb, _ := b.Outbound("vps")
	fc, _ := c.Outbound("vps")
	if fa.Fingerprint != fb.Fingerprint {
		t.Fatal("selection change changed the outbound fingerprint")
	}
	if fa.Fingerprint == fc.Fingerprint {
		t.Fatal("credential change kept the fingerprint")
	}
	if a.RulesFingerprint != b.RulesFingerprint {
		t.Fatal("rules fingerprint changed without a rule change")
	}
}

type recordingSecretStore struct {
	secret.Store
	reads []string
}

func (s *recordingSecretStore) Get(name string) (string, error) {
	s.reads = append(s.reads, name)
	return "", secret.ErrNotFound
}

func TestReservedSecretReference(t *testing.T) {
	s := &recordingSecretStore{}
	doc := strings.Replace(profile, "secret://outbounds/vps/uuid", "secret://mitm/ca", 1)
	eff, diags := Compile([]byte(doc), nil, Options{Secrets: s})
	if len(s.reads) != 0 {
		t.Errorf("secret reads = %v, want none", s.reads)
	}
	if eff != nil {
		t.Error("compiled with a reserved secret reference")
	}
	for _, d := range diags {
		if d.Code == "secret.reserved" && d.Path == "/outbounds/vps/uuid" {
			return
		}
	}
	t.Fatalf("missing secret.reserved diagnostic: %v", diags)
}

func TestDiagnostics(t *testing.T) {
	cases := []struct {
		name, edit, with, code, path string
	}{
		{"dangling rule", "outbound: direct\n  - match: {domain-suffix", "outbound: nowhere\n  - match: {domain-suffix", "rule.outbound", "/rules/lan/outbound"},
		{"dangling member", "members: [vps, ss, direct]", "members: [vps, ghost]", "group.member", "/groups/proxy/members"},
		{"field for other type", "    method: aes-128-gcm\n", "    method: aes-128-gcm\n    flow: xtls-rprx-vision\n", "outbound.field", "/outbounds/ss/flow"},
		{"bad method", "method: aes-128-gcm", "method: rc4", "outbound.method", "/outbounds/ss/method"},
		{"missing secret", "secret://outbounds/vps/uuid", "secret://outbounds/vps/other", "secret.missing", "/outbounds/vps/uuid"},
		{"duplicate id", "  - id: ss\n", "  - id: vps\n", "schema.duplicate-id", "/outbounds/vps/id"},
		{"bad cidr", "192.168.0.0/16", "192.168.0.0/99", "rule.match", "/rules/lan/match/ip-cidr"},
		{"bad listen", `listen: "127.0.0.1:7890"`, `listen: "localhost:7890"`, "listener.listen", "/listeners/mixed/listen"},
		{"bad level", "level: warn", "level: loud", "log.level", "/log/level"},
		{"bad port", "port: 8388", "port: 70000", "outbound.port", "/outbounds/ss/port"},
		{"selected", "selected: ss", "selected: nope", "group.selected", "/groups/proxy/selected"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := strings.Replace(profile, c.edit, c.with, 1)
			if doc == profile {
				t.Fatal("edit did not apply")
			}
			eff, diags := Compile([]byte(doc), nil, Options{Secrets: store(t)})
			if eff != nil {
				t.Fatal("compiled")
			}
			for _, d := range diags {
				if d.Code == c.code && d.Path == c.path && d.Line > 0 {
					return
				}
			}
			t.Fatalf("want %s at %s with a line, got:\n%v", c.code, c.path, diags)
		})
	}
}

func TestCycleAndWarnings(t *testing.T) {
	doc := strings.Replace(profile, "groups:\n", "groups:\n  - {id: a, type: select, members: [b]}\n  - {id: b, type: select, members: [a, direct]}\n", 1)
	if _, diags := Compile([]byte(doc), nil, Options{Secrets: store(t)}); !has(diags, "group.cycle") {
		t.Fatalf("cycle: %v", diags)
	}
	doc = profile + "  - id: after\n    match: {domain: x.test}\n    outbound: direct\n  - match: {process-name: curl}\n    outbound: direct\n"
	doc = strings.Replace(doc, "listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:7890\"}\nlog: {level: warn}\n", "", 1)
	// Rules appended after the final rule: move listeners/log before rules.
	doc = strings.Replace(doc, "rules:\n", "listeners: []\nrules:\n", 1)
	eff, diags := Compile([]byte(doc), nil, Options{Secrets: store(t)})
	if eff == nil || !has(diags, "rule.unreachable") || !has(diags, "rule.process") {
		t.Fatalf("warnings: %v", diags)
	}
	noFinal := strings.Replace(profile, "  - id: final\n    match: {all: true}\n    outbound: proxy\n", "", 1)
	if _, diags := Compile([]byte(noFinal), nil, Options{Secrets: store(t)}); !has(diags, "rule.no-final") {
		t.Fatalf("no final: %v", diags)
	}
}

func has(ds model.Diagnostics, code string) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}
