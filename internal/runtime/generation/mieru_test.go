package generation

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

func TestMieruBackendOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		port     uint16
		udp      bool
		protocol model.Protocol
	}{
		{"TCP with library defaults", 443, false, model.Protocol{Transport: "TCP"}},
		{"UDP port range", 0, true, model.Protocol{
			Transport: "UDP", ServerPorts: []string{"2000-2010"}, Multiplexing: "MULTIPLEXING_HIGH",
			HandshakeMode: "HANDSHAKE_NO_WAIT", TrafficPattern: "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := specFor(compile.Outbound{
				Type: model.OutboundMieru, Server: "proxy.test", Port: tc.port, Username: "alice", Password: "password",
				Dialer: &model.Dialer{Interface: "test0", RoutingMark: 42, IPVersion: "ipv4-prefer"},
				UDP:    tc.udp, Protocol: &tc.protocol,
			}).(sagernet.ProxySpec)
			if !ok || spec.Type != "mieru" || spec.Server != "proxy.test" || spec.Port != tc.port ||
				spec.Username != "alice" || spec.Password != "password" {
				t.Fatal("Mieru endpoint or credentials missing from backend spec")
			}
			var options struct {
				Transport      string
				ServerPorts    []string `json:"server_ports"`
				UDP            bool
				Multiplexing   string
				HandshakeMode  string `json:"handshake_mode"`
				TrafficPattern string `json:"traffic_pattern"`
				BindInterface  string `json:"bind_interface"`
				RoutingMark    int    `json:"routing_mark"`
				DomainStrategy string `json:"domain_strategy"`
			}
			if err := json.Unmarshal(spec.Options, &options); err != nil {
				t.Fatal(err)
			}
			p := tc.protocol
			if options.Transport != p.Transport || !slices.Equal(options.ServerPorts, p.ServerPorts) ||
				options.UDP != tc.udp || options.Multiplexing != p.Multiplexing || options.HandshakeMode != p.HandshakeMode ||
				options.TrafficPattern != p.TrafficPattern || options.BindInterface != "test0" || options.RoutingMark != 42 || options.DomainStrategy != "prefer_ipv4" {
				t.Errorf("wrong Mieru backend options: %s", spec.Options)
			}
		})
	}
}
