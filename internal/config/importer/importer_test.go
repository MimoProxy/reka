package importer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

const sample = `mixed-port: 7890
proxies:
 - {name: "香港/一", type: socks5, server: 127.0.0.1, port: "1080", username: user-secret, password: password-secret}
 - {name: SS, type: ss, server: node.example, port: 8388, cipher: aes-128-gcm, password: ss-secret, udp: true}
 - {name: VL, type: vless, server: node.example, port: 443, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", tls: true, flow: xtls-rprx-vision, servername: tls.example, client-fingerprint: chrome, reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: ab12, support-x25519mlkem768: true}, alterId: 0, cipher: auto, encryption: none}
proxy-groups:
 - {name: Choice, type: select, proxies: ["香港/一", SS, VL, DIRECT], icon: 'https://icons.example/proxy.svg'}
rules:
 - DOMAIN-SUFFIX,example.org,Choice
 - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
 - NETWORK,UDP,SS
 - MATCH,Choice
`

func request(data string) Request { return Request{SourceID: "airport", Data: data} }
func snapshot(t *testing.T, r Result) *model.Source {
	t.Helper()
	p := r.Preview(true)
	sources, _, ds := model.ParseSources([]byte(p.Sources))
	if ds.HasErrors() || len(sources.Sources) != 1 {
		t.Fatalf("snapshot: %v %s", ds, p.Sources)
	}
	return &sources.Sources[0]
}
func compileImport(t *testing.T, r Result) *compile.Effective {
	t.Helper()
	profile := "schema-version: 1\nimports: [{source: airport, outbounds: true, groups: true}]\nrules: [{source: airport}]\n"
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{Sources: []byte(r.Preview(true).Sources), ProcessLookup: true})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	return eff
}
func TestClashMappingDefaultsProvenanceAndSecrets(t *testing.T) {
	result := Import(request(sample))
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatalf("report: %+v", result.Report)
	}
	src := snapshot(t, result)
	if len(src.Outbounds) != 3 || len(src.Groups) != 1 || len(src.Rules) != 4 {
		t.Fatalf("counts %+v", result.Report)
	}
	if *src.Outbounds[0].UDP || !*src.Outbounds[1].UDP || *src.Outbounds[2].UDP {
		t.Fatal("Clash UDP defaults changed")
	}
	if src.Outbounds[2].TLS.Reality == nil || !src.Outbounds[2].TLS.Reality.X25519MLKEM768 || src.Outbounds[2].PacketEncoding != "xudp" {
		t.Fatal("VLESS mapping")
	}
	eff := compileImport(t, result)
	group := eff.GroupMetadata["airport/"+StableID("g", "Choice")]
	if group.Name != "Choice" || group.Icon != "https://icons.example/proxy.svg" {
		t.Fatalf("metadata: %+v", group)
	}
	p := result.Preview(false)
	b, _ := json.Marshal(p)
	for _, secret := range []string{"user-secret", "password-secret", "ss-secret", "b831381d"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("preview leaked credential")
		}
	}
	if p.Masked < 4 {
		t.Fatal("missing masks", p.Masked)
	}
	if len(result.Report.Ignored) != 1 || result.Report.Ignored[0] != "/mixed-port" {
		t.Fatal("machine setting not reported")
	}
	// Reordering and rotating credentials/addresses never renames nodes.
	reordered := strings.Replace(sample, "password-secret", "rotated-secret", 1)
	second := snapshot(t, Import(request(reordered)))
	if src.Outbounds[0].ID != second.Outbounds[0].ID {
		t.Fatal("credential update changed identity")
	}
}
func TestImportStableIDsSurviveReorderAndRuleInsertion(t *testing.T) {
	base := Import(request(sample))
	src := snapshot(t, base)
	lines := strings.Split(sample, "\n")
	lines[2], lines[3] = lines[3], lines[2]
	modified := strings.Join(lines, "\n")
	modified = strings.Replace(modified, "rules:\n", "rules:\n - DOMAIN,new.test,DIRECT\n", 1)
	out := Import(request(modified))
	if !out.Report.CanApply {
		t.Fatal(out.Report)
	}
	next := snapshot(t, out)
	if next.Outbounds[0].ID != src.Outbounds[1].ID || next.Outbounds[1].ID != src.Outbounds[0].ID {
		t.Fatal("node reorder changed IDs")
	}
	if next.Rules[1].ID != src.Rules[0].ID {
		t.Fatal("preceding rule insertion changed an existing ID")
	}
}
func TestImportUnsupportedIsExplicitAndAtomic(t *testing.T) {
	input := sample + "dns: {enable: true, nameserver: [1.1.1.1], enhanced-mode: fake-ip, made-up: true}\n"
	result := Import(request(input))
	if result.Report.CanApply || !result.Report.Partial {
		t.Fatal("DNS silently dropped", result.Report)
	}
	req := request(input)
	req.NodesOnly = true
	if result = Import(req); !result.Report.CanApply || result.Report.Groups.Total != 0 || result.Report.Rules.Total != 0 {
		t.Fatal("nodes-only failed", result.Report)
	}
	req = request(input)
	req.AllowPartial = true
	if result = Import(req); !result.Report.CanApply || !result.Report.Partial {
		t.Fatal("explicit partial failed", result.Report)
	}
	cases := []struct{ name, data, code string }{
		{"type", strings.Replace(sample, "type: socks5", "type: unsupported-protocol", 1), "import.protocol"},
		{"tls socks", strings.Replace(sample, "type: socks5", "type: socks5, tls: true", 1), "import.tls"},
		{"pinning", strings.Replace(sample, "type: socks5", "type: socks5, fingerprint: pinned", 1), "import.unsupported-field"},
		{"transport", strings.Replace(sample, "type: vless", "type: vless, network: quic", 1), "import.transport"},
		{"VLESS encryption", strings.Replace(sample, "encryption: none", "encryption: encrypted", 1), "import.encryption"},
		{"REALITY without TLS", strings.Replace(sample, "tls: true", "tls: false", 1), "import.tls"},
		{"packet", strings.Replace(sample, "encryption: none", "packet-encoding: packetaddr", 1), "import.packet-encoding"},
		{"group", strings.Replace(sample, "type: select", "type: relay", 1), "import.group-type"},
		{"filter", strings.Replace(sample, "type: select", "type: select, made-up: HK", 1), "import.unsupported-field"},
		{"unknown target", strings.Replace(sample, "DOMAIN-SUFFIX,example.org,Choice", "DOMAIN-SUFFIX,example.org,missing", 1), "import.rule-target"},
		{"process regex", strings.Replace(sample, "MATCH,Choice", "PROCESS-NAME-REGEX,^test$,REJECT", 1), "import.rule-unsupported"},
		{"unknown node field", strings.Replace(sample, "port: 8388", "port: 8388, dialer-proxy: Choice", 1), "import.unsupported-field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Import(request(tc.data))
			if result.Report.CanApply || !result.Report.Partial {
				t.Fatal("unsupported content applied", result.Report)
			}
			for _, d := range result.Report.Diagnostics {
				if d.Code == tc.code {
					if d.Line == 0 || d.Path == "" {
						t.Fatal("missing location", d)
					}
					return
				}
			}
			t.Fatalf("missing %s: %+v", tc.code, result.Report.Diagnostics)
		})
	}
}
func TestImportBadYAMLNamesCyclesAndLimits(t *testing.T) {
	cases := []string{
		"proxies: []\nproxies: []\n",
		"proxies: [{name: same, type: direct}, {name: same, type: direct}]",
		"proxies: [{name: DIRECT, type: direct}]",
		"proxies: [{name: X, type: direct}]\nproxy-groups: [{name: X, type: select, proxies: [DIRECT]}]",
		"proxies: {}", "[]", "proxies: []\n---\nproxies: []",
		"proxies: &recursive [*recursive]",
	}
	for i, data := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			r := Import(request(data))
			if r.Report.CanApply || len(r.Source) > 0 {
				t.Fatal("fatal input accepted", r.Report)
			}
		})
	}
	cycles := "proxy-groups: [{name: A, type: select, proxies: [B, DIRECT]}, {name: B, type: select, proxies: [A]}]"
	if r := Import(request(cycles)); r.Report.CanApply || r.Report.Groups.Imported != 0 {
		t.Fatal("cycle hidden by fallback", r.Report)
	}
	req := request(sample)
	req.SourceID = "../bad"
	if r := Import(req); r.Report.CanApply {
		t.Fatal("invalid source ID")
	}
}
func TestImportPrunesUnavailableGroupsWithoutInputOrderDependence(t *testing.T) {
	data := `proxies:
 - {name: good, type: direct}
 - {name: bad, type: trojan}
proxy-groups:
 - {name: outer, type: select, proxies: [empty, inner]}
 - {name: empty, type: select, proxies: [bad]}
 - {name: inner, type: select, proxies: [good, bad]}
rules: ["MATCH,outer"]
`
	req := request(data)
	req.AllowPartial = true
	r := Import(req)
	if !r.Report.CanApply || r.Report.Groups.Imported != 2 {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	out, _, err := eff.Router.Resolve("airport/" + StableID("g", "outer"))
	if err != nil || out != "airport/"+StableID("p", "good") {
		t.Fatalf("wrong remaining group %s %v", out, err)
	}
}
func TestShareLinksAndWholeBase64(t *testing.T) {
	vless := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@node.example:443?security=reality&sni=tls.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&flow=xtls-rprx-vision&support-x25519mlkem768=true#VLESS"
	user := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:password-secret"))
	ss := "ss://" + user + "@node.example:8388#SS"
	list := vless + "\n" + ss
	for _, data := range []string{list, "# comment\n\n" + list, base64.StdEncoding.EncodeToString([]byte(list)), base64.RawURLEncoding.EncodeToString([]byte(list))} {
		r := Import(request(data))
		if !r.Report.CanApply || r.Report.Nodes.Imported != 2 {
			t.Fatal(r.Report)
		}
		_ = compileImport(t, r)
		if strings.Contains(r.Preview(false).Sources, "password-secret") {
			t.Fatal("link secret exposed")
		}
	}
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:password-secret@node.example:8388")) + "#Legacy"
	if r := Import(request(legacy)); !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	for _, data := range []string{strings.Replace(ss, "#SS", "?unknown=true#SS", 1), strings.Replace(vless, "#VLESS", "&unknown=x#VLESS", 1), strings.Replace(vless, "#VLESS", "&type=ws#VLESS", 1), "ss://not-base64", "trojan://secret@node.example:443?unknown=x#unsupported"} {
		req := request(data)
		req.Format = "links"
		r := Import(req)
		if r.Report.CanApply {
			t.Fatal("invalid link accepted")
		}
	}
}

// TestSubscriptionFixtures converts anonymized real subscriptions. They are
// kept out of the repository; the test runs when testdata/import/real holds
// the four local fixtures (or REKA_IMPORT_FIXTURES names their directory).
func TestSubscriptionFixtures(t *testing.T) {
	dir := os.Getenv("REKA_IMPORT_FIXTURES")
	if dir == "" {
		dir = "../../../testdata/import/real"
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err == nil && len(files) == 0 {
		t.Skip("local subscription fixtures are not present")
	}
	if err != nil || len(files) != 4 {
		t.Fatalf("fixtures: %v %v", files, err)
	}
	for i, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			req := request(string(data))
			req.AllowPartial = true
			r := Import(req)
			t.Logf("nodes %d/%d, groups %d/%d, rules %d/%d, partial %t, can apply %t", r.Report.Nodes.Imported, r.Report.Nodes.Total, r.Report.Groups.Imported, r.Report.Groups.Total, r.Report.Rules.Imported, r.Report.Rules.Total, r.Report.Partial, r.Report.CanApply)
			if i == 2 || i == 3 {
				if r.Report.Nodes.Imported == 0 {
					t.Fatal("VLESS subscription did not import", r.Report)
				}
			}
			if i == 1 && r.Report.Nodes.Imported != 60 {
				t.Fatal("VMess subscription regression")
			}
			if r.Report.CanApply {
				_ = compileImport(t, r)
			}
			// Default mode refuses unsupported DNS/rules, while nodes-only remains
			// useful for the VLESS subscription, preserving its exact name mapping.
			req.AllowPartial = false
			req.NodesOnly = true
			only := Import(req)
			if i == 2 && (!only.Report.CanApply || only.Report.Nodes.Imported != 29) {
				t.Fatal("VLESS nodes-only regression", only.Report)
			}
		})
	}
}

func TestImportSecretReferencesAndAliasSizeLimit(t *testing.T) {
	data := "proxies: [{name: node, type: socks5, server: node.example, port: 1080, username: secret://node/user, password: inline}]"
	if r := Import(request(data)); !r.Report.CanApply {
		t.Fatal("secret reference was rejected before commit", r.Report)
	}
	data = strings.Replace(data, ", password: inline", "", 1)
	if r := Import(request(data)); r.Report.CanApply {
		t.Fatal("missing credential partner accepted")
	}
	// Small YAML can expand into a much larger snapshot. Bound expanded
	// scalar bytes, not only the number of alias visits.
	large := strings.Repeat("x", 1<<20)
	data = "ignored: &large '" + large + "'\nunused: [" + strings.Repeat("*large,", 20) + "]\nproxies: [{name: node, type: direct}]"
	if r := Import(request(data)); r.Report.CanApply {
		t.Fatal("unbounded alias bytes accepted")
	}
}
