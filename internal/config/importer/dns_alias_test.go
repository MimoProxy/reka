package importer

import "testing"

func TestDNSAliasAndExplicitZeroTTL(t *testing.T) {
	r := Import(request("dns: {enable: true, nameserver: [1.1.1.1], enhanced-mode: fake-ip, fake-ip-ttl: 0}\nhosts: {alias.test: target.test, target.test: 192.0.2.1}\n"))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	d := snapshot(t, r).DNS
	if d == nil || d.TTL == nil || *d.TTL != 0 || len(d.Hosts) != 2 || d.Hosts[0].Addresses[0] != "target.test" {
		t.Fatalf("%+v", d)
	}
	compileImport(t, r)
}
