package importer

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"reflect"
	"testing"
)

func TestHysteriaPortHoppingImport(t *testing.T) {
	for _, port := range []string{"", ", port: 0", ", port: 443"} {
		r := Import(request("proxies: [{name: hopping, type: hysteria2, server: node.test, password: test, ports: '443, 9000-9002, [9010-9008]', hop-interval: '2-8'" + port + "}]"))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		p := snapshot(t, r).Outbounds[0].Protocol
		if p == nil || !reflect.DeepEqual(p.ServerPorts, []string{"443:443", "9000:9002", "9008:9010"}) || p.HopInterval != 5 || p.HopIntervalMax != 8 {
			t.Fatalf("%+v", p)
		}
		compileImport(t, r)
	}
	for _, value := range []string{"0", "65536", "443,,444", "443-no", "1-2-3"} {
		if _, e := model.PortHops(value); e == nil {
			t.Fatal("invalid port range accepted", value)
		}
	}
	for _, tc := range []struct {
		input  string
		lo, hi int
	}{{"", 30, 30}, {"0", 30, 30}, {"1", 5, 5}, {"10-5", 5, 10}, {"[5-20]", 5, 20}} {
		lo, hi, e := model.HopSeconds(tc.input)
		if e != nil || lo != tc.lo || hi != tc.hi {
			t.Fatal(tc, lo, hi, e)
		}
	}
}
