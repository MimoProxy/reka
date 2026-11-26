package generation

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/sagernet/sing-box/option"
)

func TestHysteriaBackendOptions(t *testing.T) {
	up, down := uint64(62501), uint64(93751)
	for _, tc := range []struct {
		name, password string
		protocol       model.Protocol
	}{
		{name: "password", password: "plain-auth", protocol: model.Protocol{UpMbps: 3, DownBPS: &down}},
		{name: "anonymous", protocol: model.Protocol{UpMbps: 1, DownMbps: 2}},
		{name: "binary auth and QUIC options", protocol: model.Protocol{
			AuthBase64: "AP8=", UpBPS: &up, DownMbps: 5,
			ServerPorts: []string{"443:443", "20000:20100"}, HopInterval: 9,
			Obfs:                &model.Obfs{Type: "xplus", Password: "obfs-password"},
			StreamReceiveWindow: 123456, ConnectionReceiveWindow: math.MaxUint64, DisableMTUDiscovery: true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.protocol
			spec, ok := specFor(compile.Outbound{
				Type: "hysteria", Server: "proxy.test", Port: 443,
				TLS: &compile.TLS{}, Password: tc.password, Protocol: &p,
			}).(sagernet.ProxySpec)
			if !ok || spec.Type != "hysteria" || spec.TLS == nil || spec.Password != tc.password {
				t.Fatal("Hysteria TLS or password missing from backend specification")
			}
			var options option.HysteriaOutboundOptions
			decoder := json.NewDecoder(bytes.NewReader(spec.Options))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&options); err != nil {
				t.Fatal(err)
			}
			if options.UpMbps != p.UpMbps || options.DownMbps != p.DownMbps ||
				!reflect.DeepEqual(spec.UpBPS, p.UpBPS) || !reflect.DeepEqual(spec.DownBPS, p.DownBPS) {
				t.Fatal("Hysteria bandwidth changed during generation")
			}
			if !slices.Equal(options.ServerPorts, p.ServerPorts) || options.HopInterval.Build() != time.Duration(p.HopInterval)*time.Second {
				t.Fatal("wrong Hysteria port hopping options")
			}
			if options.StreamReceiveWindow.Value() != p.StreamReceiveWindow || options.ConnectionReceiveWindow.Value() != p.ConnectionReceiveWindow ||
				options.DisablePathMTUDiscovery != p.DisableMTUDiscovery {
				t.Fatal("wrong Hysteria QUIC settings")
			}
			if p.AuthBase64 != "" {
				if !bytes.Equal(options.Auth, []byte{0, 255}) || options.Obfs != p.Obfs.Password {
					t.Fatal("wrong Hysteria binary authentication or XPlus password")
				}
			} else if len(options.Auth) != 0 || options.Obfs != "" {
				t.Fatal("unexpected Hysteria binary authentication or obfuscation")
			}
		})
	}
}
