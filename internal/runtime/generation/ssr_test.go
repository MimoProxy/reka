package generation

import (
	"encoding/json"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestSSRBackendOptions(t *testing.T) {
	const profile = `schema-version: 1
outbounds:
  - id: proxy
    type: ssr
    server: proxy.test
    port: 8388
    method: aes-256-cfb
    password: test-password
`
	for _, tc := range []struct {
		name, extra, obfs, obfsParam, protocol, protocolParam string
		udp                                                   bool
	}{
		{name: "defaults", obfs: "plain", protocol: "origin", udp: true},
		{name: "configured", extra: "    udp: false\n    protocol: {obfs: {type: http_post, param: cdn.test}, protocol: auth_chain_b, protocol-param: '64:key'}\n",
			obfs: "http_post", obfsParam: "cdn.test", protocol: "auth_chain_b", protocolParam: "64:key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ds := compile.Compile([]byte(profile+tc.extra), nil, compile.Options{})
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			spec, ok := specFor(cfg.Outbounds[0]).(sagernet.ProxySpec)
			if !ok || spec.Type != "ssr" || spec.Server != "proxy.test" || spec.Port != 8388 || spec.Method != "aes-256-cfb" || spec.Password != "test-password" {
				t.Fatal("incorrect SSR backend selection or credentials")
			}
			var options struct {
				Obfs          string `json:"obfs"`
				ObfsParam     string `json:"obfs_param"`
				Protocol      string `json:"protocol"`
				ProtocolParam string `json:"protocol_param"`
				UDP           *bool  `json:"udp"`
			}
			if err := json.Unmarshal(spec.Options, &options); err != nil {
				t.Fatal(err)
			}
			if options.UDP == nil || *options.UDP != tc.udp || options.Obfs != tc.obfs || options.ObfsParam != tc.obfsParam || options.Protocol != tc.protocol || options.ProtocolParam != tc.protocolParam {
				t.Fatal("incorrect SSR backend options")
			}
		})
	}
}
