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
		if e := json.Unmarshal(s.Options, &values); e != nil {
			return nil, e
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
	data, e := json.Marshal(values)
	if e != nil {
		return nil, e
	}
	logger := b.componentLogger("outbound", s.Type, tag)
	switch s.Type {
	case "vmess":
		var o option.VMessOutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return vmess.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "trojan":
		var o option.TrojanOutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return trojan.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "hysteria2":
		var o option.Hysteria2OutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return hysteria2.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "tuic":
		var o option.TUICOutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return tuic.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "snell":
		values["psk"] = s.Password
		delete(values, "password")
		data, _ = json.Marshal(values)
		var o option.SnellOutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return snell.NewOutbound(b.ctx, b.router, logger, tag, o)
	case "vless":
		var o option.VLESSOutboundOptions
		if e = json.Unmarshal(data, &o); e != nil {
			return nil, e
		}
		return vless.NewOutbound(b.ctx, b.router, logger, tag, o)
	}
	return nil, fmt.Errorf("unsupported protocol %q", s.Type)
}
