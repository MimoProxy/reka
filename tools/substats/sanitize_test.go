package main

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const sample = `# provider comment that names the airport
mixed-port: 7890
secret: hunter2-controller
proxies:
  - {name: "BrandCloud HK 01", type: vless, server: hk1.brandcloud.example, port: 443, uuid: 0b9a8c6e-1111-2222-3333-444455556666, flow: xtls-rprx-vision, tls: true, servername: sni.brandcloud.example, client-fingerprint: chrome, reality-opts: {public-key: PUBKEYbrandcloudAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: abcd1234}}
  - {name: "BrandCloud JP 02", type: ss, server: 203.0.113.77, port: 8388, cipher: aes-128-gcm, password: sspassword-brand}
  - {name: "BrandCloud US ws", type: vmess, server: us.brandcloud.example, port: 443, uuid: 0b9a8c6e-7777-2222-3333-444455556666, network: ws, ws-opts: {path: /brand-secret-path, headers: {Host: cdn.brandcloud.example, X-Token: tokentokentoken}}}
proxy-groups:
  - {name: "BrandCloud Select", type: select, proxies: ["BrandCloud HK 01", "BrandCloud JP 02", "BrandCloud US ws", DIRECT], icon: "https://icons.brandcloud.example/hk.png"}
  - {name: Auto, type: url-test, proxies: ["BrandCloud HK 01"], url: "https://www.gstatic.com/generate_204?brand=1", interval: 300, use: [brand-provider]}
proxy-providers:
  brand-provider: {type: http, url: "https://sub.brandcloud.example/api?token=SUBTOKEN123", path: ./brand.yaml, interval: 3600}
rule-providers:
  brand-rules: {type: http, behavior: classical, url: "https://rules.brandcloud.example/r.yaml", interval: 86400}
rules:
  - DOMAIN-SUFFIX,brandcloud.example,DIRECT
  - 'DOMAIN-KEYWORD,brandcloud,BrandCloud Select'
  - IP-CIDR,203.0.113.0/24,DIRECT,no-resolve
  - RULE-SET,brand-rules,Auto
  - AND,((AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((DOMAIN,api.brandcloud.example)))),REJECT
  - AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((DOMAIN,cdn.brandcloud.example))),Auto
  - GEOIP,CN,DIRECT
  - 'MATCH,BrandCloud Select'
dns:
  enable: true
  nameserver: [https://doh.brandcloud.example/dns-query/brandtoken, https://dns.alidns.example/dns-query, 223.5.5.5]
  nameserver-policy: {"+.brandcloud.example": 10.9.8.7}
  fake-ip-filter: ["*.brandcloud.example", "+.lan"]
tun: {enable: true, device: brand-utun}
`

var secrets = []string{
	"airport", "hunter2", "BrandCloud", "brandcloud", "0b9a8c6e", "PUBKEY", "abcd1234", "sspassword",
	"203.0.113.77", "brand-secret-path", "tokentokentoken", "X-Token", "icons.", "SUBTOKEN", "brand.yaml",
	"brand-rules", "brand-provider", "brandtoken", "10.9.8.7", "brand-utun", "?brand=1",
}

func sanitizeSample(t *testing.T) (*yaml.Node, string) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(sample), &doc); err != nil {
		t.Fatal(err)
	}
	sanitize(&doc)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	return &doc, string(out)
}

func TestSanitizeRemovesIdentifyingValues(t *testing.T) {
	_, out := sanitizeSample(t)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("sanitized output still contains %q", s)
		}
	}
	for _, keep := range []string{"xtls-rprx-vision", "chrome", "aes-128-gcm", "GEOIP,CN,DIRECT", "no-resolve", "+.lan", "www.gstatic.com", "/dns-query"} {
		if !strings.Contains(out, keep) {
			t.Errorf("sanitized output lost %q", keep)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + out)
	}
}

func TestSanitizeKeepsReferencesConsistent(t *testing.T) {
	doc, _ := sanitizeSample(t)
	root := docRoot(doc)
	names := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, p := range mapGet(root, "proxies").Content {
		names[mapGet(p, "name").Value] = true
	}
	for _, g := range mapGet(root, "proxy-groups").Content {
		names[mapGet(g, "name").Value] = true
	}
	for _, g := range mapGet(root, "proxy-groups").Content {
		if ps := mapGet(g, "proxies"); ps != nil {
			for _, p := range ps.Content {
				if !names[p.Value] {
					t.Errorf("group references unknown %q", p.Value)
				}
			}
		}
		if use := mapGet(g, "use"); use != nil {
			for _, u := range use.Content {
				if mapGet(mapGet(root, "proxy-providers"), u.Value) == nil {
					t.Errorf("group uses unknown provider %q", u.Value)
				}
			}
		}
	}
	for _, r := range mapGet(root, "rules").Content {
		parts := splitRule(r.Value)
		target := parts[len(parts)-1]
		if target == "no-resolve" {
			target = parts[len(parts)-2]
		}
		if !names[target] {
			t.Errorf("rule %q targets unknown %q", r.Value, target)
		}
		if strings.HasPrefix(r.Value, "RULE-SET,") && mapGet(mapGet(root, "rule-providers"), parts[1]) == nil {
			t.Errorf("rule %q uses unknown rule provider", r.Value)
		}
	}
}

func TestLogicalItemsBothSpellings(t *testing.T) {
	for arg, want := range map[string]int{
		"((DST-PORT,443),(NETWORK,UDP))":                          2,
		"((AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOIP,CN))))": 2,
		"(DST-PORT,443),(NETWORK,UDP)":                            2,
		"((GEOIP,CN))":                                            1,
		"(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOIP,CN)))":   2,
	} {
		if got := len(logicalItems(arg)); got != want {
			t.Errorf("logicalItems(%q) = %d items, want %d", arg, got, want)
		}
	}
}

func TestStatsCountsNestedLogical(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(sample), &doc); err != nil {
		t.Fatal(err)
	}
	st := newStats()
	st.add(docRoot(&doc))
	for _, k := range []string{"sub:AND", "sub:NOT", "sub:DST-PORT", "sub:NETWORK", "sub:DOMAIN"} {
		if st.ruleLogical.n[k] != 2 {
			t.Errorf("%s counted %d times, want 2", k, st.ruleLogical.n[k])
		}
	}
	if st.ruleParam.n["IP-CIDR,no-resolve"] != 1 {
		t.Error("no-resolve not counted")
	}
}
