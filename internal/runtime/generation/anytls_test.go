package generation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/sagernet/sing-box/option"
)

func TestAnyTLSBackendOptions(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protocol       *model.Protocol
		interval, idle time.Duration
		minIdle        int
		clientMetadata string
	}{
		{name: "omitted"},
		{name: "zero", protocol: &model.Protocol{}},
		{
			name: "configured",
			protocol: &model.Protocol{
				IdleSessionCheckIntervalSeconds: 15,
				IdleSessionTimeoutSeconds:       45,
				MinIdleSession:                  2,
				ClientMetadata:                  "reka-test",
			},
			interval: 15 * time.Second, idle: 45 * time.Second, minIdle: 2, clientMetadata: "reka-test",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := specFor(compile.Outbound{
				Type: "anytls", Server: "server.test", Port: 443, Password: "test-password",
				TLS: &compile.TLS{}, Protocol: tc.protocol,
			}).(sagernet.ProxySpec)
			if !ok || spec.Type != "anytls" || spec.TLS == nil {
				t.Fatal("AnyTLS did not select the TLS proxy backend")
			}
			var options option.AnyTLSOutboundOptions
			if err := json.Unmarshal(spec.Options, &options); err != nil {
				t.Fatal(err)
			}
			if options.IdleSessionCheckInterval.Build() != tc.interval || options.IdleSessionTimeout.Build() != tc.idle || options.MinIdleSession != tc.minIdle || options.ClientMetadata != tc.clientMetadata {
				t.Fatalf("wrong AnyTLS protocol options: %s", spec.Options)
			}
		})
	}
}
