package importer

import (
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func FuzzSubscriptions(f *testing.F) {
	for _, s := range []string{
		"proxies: [{name: x, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: key}]",
		"ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#test",
		"proxies: [{name: x, type: anytls, server: node.test, port: 443, password: test-password, idle-session-timeout: 30}]",
		"anytls://test-password@node.test:443?sni=cover.test&insecure=1#test",
		"proxies: [{name: x, type: ssr, server: ssr.example, port: 8388, cipher: aes-256-cfb, password: test-password, obfs: http_post, obfs-param: cover.example, protocol: auth_chain_a, protocol-param: '64:test-key'}]",
		ssrTestLink("ssr.example:8388:origin:none:plain:cGFzcw/?remarks=dGVzdA"),
		"proxies: [{name: x, type: ssh, server: node.test, port: 22, username: alice, password: test-password, host-key: [], udp: true}]",
		"hysteria://node.test:443?auth=test-password&upmbps=3&down=2MBps#test",
		"proxies: &a [*a]",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64<<10 {
			t.Skip()
		}
		for _, format := range []string{"auto", "clash", "links"} {
			r := Import(Request{SourceID: "fuzz", Format: format, Data: s, AllowPartial: true})
			if r.Report.CanApply {
				p := r.Preview(false)
				if p.Sources == "" {
					t.Fatal("applicable import has no preview")
				}
				if _, _, d := model.ParseSources([]byte(p.Sources)); d.HasErrors() {
					t.Fatal(d)
				}
			}
		}
	})
}
