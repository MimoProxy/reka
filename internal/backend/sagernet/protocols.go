package sagernet

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
	"strings"
)

type ProxySpec struct {
	Encryption                                     string
	Detour                                         *DetourSpec
	Type, Server, UUID, Password, Username, Method string
	Port                                           uint16
	TLS                                            *TLSSpec
	Options                                        json.RawMessage
}

func (b *Backend) newProtocol(tag string, s ProxySpec) (result adapter.Outbound, returnErr error) {
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
	if s.Username != "" {
		values["username"] = s.Username
	}
	if s.Method != "" {
		values["method"] = s.Method
	}
	if user, _ := values["username"].(string); user != "" {
		if headers, ok := values["headers"].(map[string]any); ok {
			for key := range headers {
				if strings.EqualFold(key, "Proxy-Authorization") {
					delete(headers, key)
				}
			}
		}
	}
	if s.Type == "socks" {
		values["version"] = "5"
	}
	ctx, configured := configureTLSContext(configureECHContext(detourContext(b.ctx, s.Detour), s.TLS), s.TLS)
	ctx, encryptionConfigured, err := configureEncryptionContext(ctx, s.Encryption)
	if err != nil {
		return nil, err
	}
	if s.Detour != nil {
		values["detour"] = "reka-detour"
	}
	defer func() {
		if returnErr == nil && encryptionConfigured != nil && !encryptionConfigured.Load() {
			common.Close(result)
			result = nil
			returnErr = fmt.Errorf("required VLESS encryption overlay is unavailable")
		}
		if returnErr == nil && configured != nil && !configured.Load() {
			common.Close(result)
			result = nil
			returnErr = fmt.Errorf("required TLS verification overlay is unavailable")
		}
	}()
	if bind, _ := values["bind_interface"].(string); bind != "" && b.protect != nil {
		ctx = service.ExtendContext(ctx)
		service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: b.protect, explicitProtect: true})
	}
	ctx, err = streamContext(ctx, b.componentLogger("outbound", s.Type, tag), values, s.Server, s.Port)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	logger := b.componentLogger("outbound", s.Type, tag)
	switch s.Type {
	case "direct":
		if s.Detour != nil {
			return &nativeDetour{Adapter: outbound.NewAdapter("direct", tag, []string{"tcp", "udp"}, nil), spec: s.Detour}, nil
		}
		var o option.DirectOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return direct.NewOutbound(ctx, b.router, logger, tag, o)
	case "http":
		var o option.HTTPOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return http.NewOutbound(ctx, b.router, logger, tag, o)
	case "socks":
		var o option.SOCKSOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return socks.NewOutbound(ctx, b.router, logger, tag, o)
	case "shadowsocks":
		var o option.ShadowsocksOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return shadowsocks.NewOutbound(ctx, b.router, logger, tag, o)
	case "vmess":
		var o option.VMessOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return vmess.NewOutbound(ctx, b.router, logger, tag, o)
	case "trojan":
		var o option.TrojanOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return trojan.NewOutbound(ctx, b.router, logger, tag, o)
	case "hysteria2":
		var o option.Hysteria2OutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return hysteria2.NewOutbound(ctx, b.router, logger, tag, o)
	case "tuic":
		var o option.TUICOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return tuic.NewOutbound(ctx, b.router, logger, tag, o)
	case "snell":
		values["psk"] = s.Password
		delete(values, "password")
		data, _ = json.Marshal(values)
		var o option.SnellOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return snell.NewOutbound(ctx, b.router, logger, tag, o)
	case "vless":
		var o option.VLESSOutboundOptions
		if err = json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return vless.NewOutbound(ctx, b.router, logger, tag, o)
	}
	return nil, fmt.Errorf("unsupported protocol %q", s.Type)
}
