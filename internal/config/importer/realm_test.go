package importer

import (
	"strings"
	"testing"
)

func TestClashHysteriaRealmAndBandwidth(t *testing.T) {
	input := `proxies:
 - name: relay
   type: hysteria2
   password: hy-secret
   sni: proxy.test
   up: 500 Kbps
   down: 2MBps
   realm-opts:
     enable: true
     server-url: https://control.test
     realm-id: room
     token: realm-secret
     stun-servers: [stun.test, '127.0.0.1:3478']
     sni: control.test
     fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`
	r := Import(request(input))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	p := eff.Outbounds[0].Protocol
	if p.UpBPS == nil || *p.UpBPS != 62500 || *p.DownBPS != 2000000 || p.Realm == nil || p.Realm.TLS.ServerName != "control.test" || p.Realm.Token != "realm-secret" {
		t.Fatal("Realm or exact bandwidth lost")
	}
	for _, change := range []string{"enable: true\n     typo: true", "server-url: ftp://control.test", "stun-servers: []", "up: invalid"} {
		altered := input
		switch {
		case strings.HasPrefix(change, "enable:"):
			altered = strings.Replace(input, "enable: true", change, 1)
		case strings.HasPrefix(change, "server-url:"):
			altered = strings.Replace(input, "server-url: https://control.test", change, 1)
		case strings.HasPrefix(change, "stun-servers:"):
			altered = strings.Replace(input, "stun-servers: [stun.test, '127.0.0.1:3478']", change, 1)
		default:
			altered = strings.Replace(input, "up: 500 Kbps", change, 1)
		}
		if Import(request(altered)).Report.CanApply {
			t.Fatal("invalid Realm/rate accepted", change)
		}
	}
	changed := Import(request(strings.Replace(input, "realm-secret", "rotated-secret", 1)))
	if compileImport(t, changed).Outbounds[0].Fingerprint == eff.Outbounds[0].Fingerprint {
		t.Fatal("Realm token rotation reused old transport")
	}
}

func TestClashHysteriaGeckoPacketBounds(t *testing.T) {
	input := `proxies: [{name: node, type: hysteria2, server: proxy.test, port: 443, password: test, obfs: gecko, obfs-password: secret, obfs-min-packet-size: 600, obfs-max-packet-size: 1400}]`
	r := Import(request(input))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	if p := compileImport(t, r).Outbounds[0].Protocol.Obfs; p.Type != "gecko" || p.MinPacketSize != 600 || p.MaxPacketSize != 1400 {
		t.Fatal(p)
	}
	for _, value := range []string{"obfs: salamander", "obfs: gecko, ignored: true", "obfs: gecko, other: false"} {
		if Import(request(strings.Replace(input, "obfs: gecko", value, 1))).Report.CanApply {
			t.Fatal("invalid gecko options accepted", value)
		}
	}
	if Import(request(strings.Replace(input, "1400", "2049", 1))).Report.CanApply {
		t.Fatal("oversize gecko accepted")
	}
}
