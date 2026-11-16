package compile

import "testing"

func TestDNSLayerSelectionAndOverlay(t *testing.T) {
	sources := `sources:
 - id: airport
   outbounds: [{id: node, type: direct}]
   groups: [{id: proxy, type: select, members: [node]}]
   rule-sets: [{id: websites, entries: [{domain-suffix: example.test}]}]
   dns:
    nameserver: ['1.1.1.1#proxy']
    nameserver-policy: [{id: site, pattern: 'rule-set:websites', servers: [192.0.2.1]}]
    enhanced-mode: fake-ip
    fake-ip-filter: ['+.lan']
`
	profile := "schema-version: 1\nimports: [{source: airport, outbounds: true, groups: true}]\ndns: {from: airport, listen: '127.0.0.1:5353'}\nrules: [{match: {all: true}, outbound: direct}]"
	overlay := `patches: [{op: set, path: /dns/fake-ip-filter, value: ['+.local']}]`
	eff, ds := Compile([]byte(profile), nil, Options{Sources: []byte(sources), Overlay: []byte(overlay)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if eff.DNS == nil || eff.DNS.Nameservers[0] != "1.1.1.1#airport/proxy" || eff.DNS.Policies[0].Pattern != "rule-set:airport/websites" || eff.DNS.FakeFilter[0] != "+.local" {
		t.Fatal(eff.DNS)
	}
	for path, layer := range map[string]string{"/dns/nameserver/#0": LayerSource, "/dns/listen": LayerProfile, "/dns/fake-ip-filter/#0": LayerOverlay} {
		origin, ok := eff.OriginOf(path)
		if !ok || origin.Layer != layer {
			t.Fatal(path, origin)
		}
	}
}
func TestSourceIncludeAllKeepsNamespace(t *testing.T) {
	sources := `sources:
 - id: first
   outbounds: [{id: one, type: direct}]
   groups: [{id: auto, type: url-test, include-all: true}]
 - id: second
   outbounds: [{id: two, type: direct}]
`
	profile := "schema-version: 1\nimports: [{source: first, outbounds: true, groups: true},{source: second, outbounds: true}]"
	eff, ds := Compile([]byte(profile), nil, Options{Sources: []byte(sources)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if len(eff.AutoGroups) != 1 || len(eff.AutoGroups[0].Members) != 1 || eff.AutoGroups[0].Members[0] != "first/one" {
		t.Fatal(eff.AutoGroups)
	}
}

func TestTransportHeaderSecretRotation(t *testing.T) {
	s := store(t)
	if err := s.Set("ws/key", "first-key"); err != nil {
		t.Fatal(err)
	}
	input := []byte("schema-version: 1\noutbounds: [{id: node, type: vmess, server: node.test, port: 80, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, transport: {type: ws, headers: [{name: Authorization, value: 'secret://ws/key'}]}}]")
	a, ds := Compile(input, nil, Options{Secrets: s})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	first, _ := a.Outbound("node")
	if first.Transport.Headers[0].Value != "first-key" {
		t.Fatal("transport secret unresolved")
	}
	if err := s.Set("ws/key", "second-key"); err != nil {
		t.Fatal(err)
	}
	b, ds := Compile(input, nil, Options{Secrets: s})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	second, _ := b.Outbound("node")
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("secret rotation did not replace outbound")
	}
}

func TestDNSEndpointOptionsKeepSourceScope(t *testing.T) {
	source := `sources:
 - id: airport
   outbounds: [{id: proxy, type: direct}]
   dns:
    nameserver: ['https://1.1.1.1/dns-query#h3=true&proxy&ecs=192.0.2.1/24']
`
	eff, ds := Compile([]byte("schema-version: 1\nimports: [{source: airport, outbounds: true}]\ndns: {from: airport}\n"), nil, Options{Sources: []byte(source)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if eff.DNS.Nameservers[0] != "https://1.1.1.1/dns-query#h3=true&airport/proxy&ecs=192.0.2.1/24" {
		t.Fatal(eff.DNS.Nameservers)
	}
}
