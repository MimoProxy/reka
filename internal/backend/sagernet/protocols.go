package sagernet

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

type ProxySpec struct {
	Type, Server, UUID, Password string
	Port                         uint16
	TLS                          *TLSSpec
	Options                      json.RawMessage
}

func (b *Backend) newProtocol(tag string, s ProxySpec) (adapter.Outbound, error) {
	var values map[string]any
	if len(s.Options) > 0 {
		if err := json.Unmarshal(s.Options, &values); err != nil {
			return nil, err
		}
	}
	if values == nil {
		values = map[string]any{}
	}
	values["server"], values["server_port"] = s.Server, s.Port
	if s.UUID != "" && (s.Type == "vmess" || s.Type == "vless" || s.Type == "tuic") {
		values["uuid"] = s.UUID
	}
	if s.Password != "" {
		values["password"] = s.Password
	}
	if s.TLS != nil {
		t := s.TLS.build()
		if (s.Type == "hysteria2" || s.Type == "tuic") && len(t.ALPN) == 0 {
			t.ALPN = []string{"h3"}
		}
		values["tls"] = t
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	logger := b.componentLogger("outbound", s.Type, tag)
	switch s.Type {
	case "vmess":
		var o option.VMessOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return vmess.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "trojan":
		var o option.TrojanOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return trojan.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "hysteria2":
		var o option.Hysteria2OutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return hysteria2.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "tuic":
		var o option.TUICOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return tuic.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "snell":
		values["psk"] = s.Password
		delete(values, "password")
		data, _ = json.Marshal(values)
		var o option.SnellOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return snell.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "vless":
		var o option.VLESSOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return vless.NewOutbound(b.ctx, b.router, logger, tag, o)
	}
	return nil, fmt.Errorf("unsupported protocol %q", s.Type)
}
