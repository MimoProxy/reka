package model

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const sample = `# Reka profile
schema-version: 1
outbounds:
  # my own server
  - id: my-vps
    type: vless
    server: vps.example
    port: 443
    uuid: secret://outbounds/my-vps/uuid
    flow: xtls-rprx-vision
    tls:
      server-name: www.example.com
      fingerprint: chrome
      reality: {public-key: "pk", short-id: "ab12"}
  - id: ss
    type: shadowsocks
    server: 192.0.2.1
    port: 8388
    method: 2022-blake3-aes-128-gcm
    password: inline-secret   # written inline
groups:
  - id: proxy
    type: select
    members: [my-vps, ss, direct]
    selected: my-vps    # current choice
rules:
  - id: lan
    match: {ip-cidr: 192.168.0.0/16, no-resolve: true}
    outbound: direct
  # work sites
  - id: work
    match: {domain-suffix: [corp.example, corp.test]}
    outbound: proxy
  # everything else
  - id: final
    match: {all: true}
    outbound: proxy
`

func TestParseProfile(t *testing.T) {
	p, pos, diags := ParseProfile([]byte(sample))
	if len(diags) != 0 {
		t.Fatal(diags)
	}
	if len(p.Outbounds) != 2 || p.Outbounds[0].TLS.Reality.ShortID != "ab12" || p.Outbounds[1].Port != 8388 {
		t.Fatalf("decoded %+v", p.Outbounds)
	}
	if m := p.Rules[1].Match; m.Kind != "domain-suffix" || len(m.Values) != 2 {
		t.Fatalf("match %+v", m)
	}
	if !p.Rules[0].Match.NoResolve || p.Rules[2].Match.Kind != "all" {
		t.Fatalf("rules %+v", p.Rules)
	}
	if got := pos["/outbounds/ss/port"]; got.Line != 18 {
		t.Fatalf("position of /outbounds/ss/port = %+v", got)
	}
}

func TestDiagnostics(t *testing.T) {
	cases := []struct {
		name, doc, code, path string
		line                  int
	}{
		{"syntax", "schema-version: 1\nrules: [\n", "yaml.syntax", "", 2},
		{"duplicate", "schema-version: 1\nlog: {level: info}\nlog: {level: debug}\n", "yaml.duplicate", "/log", 3},
		{"type", "schema-version: 1\noutbounds:\n  - id: a\n    type: direct\n    port: \"x\"\n", "yaml.type", "/outbounds/a/port", 5},
		{"unknown", "schema-version: 1\noutbounds:\n  - id: a\n    type: direct\n    colour: red\n", "schema.unknown-field", "/outbounds/a/colour", 5},
		{"version", "schema-version: 9\n", "schema.version", "/schema-version", 1},
		{"missing version", "rules: []\n", "schema.version", "/schema-version", 1},
		{"two conditions", "schema-version: 1\nrules:\n  - match: {domain: a, network: tcp}\n    outbound: direct\n", "schema.match", "/rules/#0/match/network", 3},
		{"two documents", "schema-version: 1\n---\nschema-version: 1\n", "yaml.documents", "", 2},
		{"not a mapping", "- a\n- b\n", "yaml.type", "/", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, diags := ParseProfile([]byte(c.doc))
			if !diags.HasErrors() {
				t.Fatal("no error")
			}
			d := diags[0]
			if d.Code != c.code || d.Path != c.path || d.Line != c.line {
				t.Fatalf("got %s (path %q line %d), want %s %q line %d", d, d.Path, d.Line, c.code, c.path, c.line)
			}
		})
	}
}

func TestDepthAndAliasLimits(t *testing.T) {
	deep := "schema-version: 1\nrules:\n  - match:\n      domain: " + strings.Repeat("[", 40) + "a" + strings.Repeat("]", 40) + "\n"
	if _, _, diags := ParseProfile([]byte(deep)); !diags.HasErrors() {
		t.Fatal("deep nesting accepted")
	}
	// Each level doubles the expansion: 2^24 nodes.
	var b strings.Builder
	b.WriteString("schema-version: 1\nx0: &a0 [a, a]\n")
	for i := 1; i <= 24; i++ {
		b.WriteString("x" + itoa(i) + ": &a" + itoa(i) + " [*a" + itoa(i-1) + ", *a" + itoa(i-1) + "]\n")
	}
	// The strict decoder only follows aliases into typed fields, so the bomb
	// is rejected without being expanded.
	start := time.Now()
	_, _, diags := ParseProfile([]byte(b.String()))
	if !diags.HasErrors() || time.Since(start) > time.Second {
		t.Fatalf("alias bomb: %d diagnostics after %v", len(diags), time.Since(start))
	}
	// Aliases into typed fields do expand, within the node budget.
	ok := "schema-version: 1\nx-tls: &t {server-name: a.test}\n"
	if _, _, diags := ParseProfile([]byte(ok)); !diags.HasErrors() {
		t.Fatal("unknown top-level key accepted")
	}
	shared := "schema-version: 1\noutbounds:\n  - &o {id: a, type: direct}\nlisteners:\n  - {id: m, type: mixed, listen: \"127.0.0.1:1\"}\n"
	if _, _, diags := ParseProfile([]byte(shared)); diags.HasErrors() {
		t.Fatal(diags)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestCanonicalRoundTrip(t *testing.T) {
	doc, diags := LoadDoc(DocProfile, []byte(sample))
	if diags != nil {
		t.Fatal(diags)
	}
	once := doc.Bytes()
	for _, c := range []string{"# Reka profile", "# my own server", "# written inline", "# current choice", "# work sites", "# everything else"} {
		if !strings.Contains(string(once), c) {
			t.Errorf("lost comment %q:\n%s", c, once)
		}
	}
	doc2, _ := LoadDoc(DocProfile, once)
	if twice := doc2.Bytes(); string(twice) != string(once) {
		t.Fatalf("canonical form not stable:\n--- once\n%s\n--- twice\n%s", once, twice)
	}
	if !strings.Contains(string(once), "\n\ngroups:") || !strings.Contains(string(once), "\n\nrules:") {
		t.Fatalf("no blank line between sections:\n%s", once)
	}
	if _, _, diags := ParseProfile(once); len(diags) != 0 {
		t.Fatal(diags)
	}
}

func TestEdits(t *testing.T) {
	doc, _ := LoadDoc(DocProfile, []byte(sample))
	err := doc.Apply(
		Op{Op: "set", Path: "/groups/proxy/selected", Value: []byte(`"ss"`)},
		Op{Op: "insert", Path: "/rules", Before: "final", Value: []byte(`{"id":"cn","match":{"domain-suffix":"cn"},"outbound":"direct"}`)},
		Op{Op: "remove", Path: "/rules/lan"},
		Op{Op: "set", Path: "/log/level", Value: []byte(`"debug"`)},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := string(doc.Bytes())
	p, _, diags := ParseProfile([]byte(out))
	if len(diags) != 0 {
		t.Fatalf("%v\n%s", diags, out)
	}
	if p.Groups[0].Selected != "ss" || p.Log.Level != "debug" {
		t.Fatalf("edits not applied:\n%s", out)
	}
	var ids []string
	for _, r := range p.Rules {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "work,cn,final" {
		t.Fatalf("rule order %v", ids)
	}
	if !strings.Contains(out, "selected: ss # current choice") {
		t.Fatalf("line comment not kept on edited value:\n%s", out)
	}
	if !strings.Contains(out, "# everything else") {
		t.Fatalf("comment lost:\n%s", out)
	}
	if err := doc.Apply(Op{Op: "remove", Path: "/rules/nope"}); err == nil {
		t.Fatal("removing a missing rule succeeded")
	}
	if err := doc.Apply(Op{Op: "insert", Path: "/rules", Value: []byte(`{"id":"cn","match":{"all":true},"outbound":"direct"}`)}); err == nil {
		t.Fatal("duplicate id inserted")
	}
}

func TestMaskSecrets(t *testing.T) {
	doc, _ := LoadDoc(DocProfile, []byte(sample))
	if n := doc.MaskSecrets(); n != 1 {
		t.Fatalf("masked %d values, want 1 (the secret:// reference stays)", n)
	}
	masked := doc.Bytes()
	if strings.Contains(string(masked), "inline-secret") || !strings.Contains(string(masked), "secret://outbounds/my-vps/uuid") {
		t.Fatalf("masked doc:\n%s", masked)
	}
	// A client edits something else and sends the mask back.
	edited, _ := LoadDoc(DocProfile, masked)
	edited.Apply(Op{Op: "set", Path: "/outbounds/ss/port", Value: []byte(`9000`)})
	base, _ := LoadDoc(DocProfile, []byte(sample))
	if err := edited.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
	}
	p, _, _ := ParseProfile(edited.Bytes())
	if p.Outbounds[1].Password != "inline-secret" || p.Outbounds[1].Port != 9000 {
		t.Fatalf("after unmask: %+v", p.Outbounds[1])
	}
	// A mask with nothing to keep is an error.
	fresh, _ := LoadDoc(DocProfile, []byte("schema-version: 1\noutbounds:\n  - id: n\n    type: shadowsocks\n    password: \"********\"\n"))
	if err := fresh.UnmaskSecrets(base); err == nil {
		t.Fatal("mask without stored value accepted")
	}
}

func TestFlatten(t *testing.T) {
	doc, _ := LoadDoc(DocProfile, []byte(sample))
	f := Flatten(doc.Mapping())
	if f["/groups/proxy/selected"] != "my-vps" || f["/outbounds/ss/port"] != int64(8388) {
		t.Fatalf("flatten: %v", f)
	}
	if _, ok := f["/groups/proxy/members"].([]any); !ok {
		t.Fatalf("scalar list not a leaf: %v", f["/groups/proxy/members"])
	}
}
