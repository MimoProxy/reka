package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	XC "github.com/MimoProxy/reka/internal/compat/xhttp"
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
	"github.com/sagernet/sing-box/transport/sip003"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"io"
	"strings"
	"sync/atomic"
)

type ProxySpec struct {
	ECHLookup                                      func(context.Context, string) ([]byte, error)
	Plugin                                         *SSPluginSpec
	Realm                                          *RealmSpec
	UpBPS, DownBPS                                 *uint64
	Encryption                                     string
	Detour                                         *DetourSpec
	Type, Server, UUID, Password, Username, Method string
	Port                                           uint16
	TLS                                            *TLSSpec
	Options                                        json.RawMessage
}

func decodeProtocolOptions(data []byte) (map[string]any, error) {
	values := map[string]any{}
	if len(data) == 0 {
		return values, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("outbound options must contain one JSON object")
	}
	if values == nil {
		values = map[string]any{}
	}
	return values, nil
}

func (b *Backend) newProtocol(tag string, s ProxySpec) (result adapter.Outbound, returnErr error) {
	values, err := decodeProtocolOptions(s.Options)
	if err != nil {
		return nil, err
	}
	if values["realm"] != nil && s.Realm == nil {
		return nil, fmt.Errorf("Realm requires a scoped RealmSpec")
	}
	if s.Realm != nil && s.Type != "hysteria2" {
		return nil, fmt.Errorf("Realm applies only to Hysteria2")
	}
	var realmTransport *realmHTTPTransport
	var plugin *ssPlugin
	var xhttpTransport outboundResource
	var bandwidthConfigured *atomic.Bool
	multiplex, err := popMultiplex(values)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr == nil && result != nil {
			if xhttpTransport != nil {
				result = &ownedResourceOutbound{Outbound: result, resource: xhttpTransport}
			}
			if realmTransport != nil {
				result = &ownedResourceOutbound{Outbound: result, resource: realmTransport}
			}
			if plugin != nil {
				result = &ownedResourceOutbound{Outbound: result, resource: plugin}
			}
			base := result
			result, returnErr = wrapMultiplex(base, multiplex, b.componentLogger("multiplex", s.Type, tag))
			if returnErr != nil {
				common.Close(base)
			}
		}
		if returnErr != nil && xhttpTransport != nil {
			_ = xhttpTransport.Close()
		}
		if returnErr != nil && plugin != nil {
			plugin.Close()
		}
		if returnErr != nil && realmTransport != nil {
			realmTransport.CloseIdleConnections()
		}
	}()
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
	baseContext := detourContext(b.ctx, s.Detour)
	if s.ECHLookup != nil {
		baseContext = context.WithValue(baseContext, "reka.tls.ech.lookup.v1", s.ECHLookup)
	}
	ctx, carrierConfigured := configureTLSCarrierContext(baseContext, s.TLS)
	ctx, configured := configureTLSContext(configureECHContext(ctx, s.TLS), s.TLS)
	if s.Type == "hysteria2" && (s.UpBPS != nil || s.DownBPS != nil) {
		bandwidthConfigured = &atomic.Bool{}
		ctx = context.WithValue(ctx, "reka.hysteria.bandwidth.v1", func(up, down *uint64) {
			if s.UpBPS != nil {
				*up = *s.UpBPS
			}
			if s.DownBPS != nil {
				*down = *s.DownBPS
			}
			bandwidthConfigured.Store(true)
		})
	}
	ctx, encryptionConfigured, err := configureEncryptionContext(ctx, s.Encryption)
	if err != nil {
		return nil, err
	}
	if s.Detour != nil {
		values["detour"] = "reka-detour"
	}
	defer func() {
		if returnErr == nil && carrierConfigured != nil && !carrierConfigured.Load() {
			common.Close(result)
			result = nil
			returnErr = fmt.Errorf("required security carrier overlay is unavailable")
		}
		if returnErr == nil && bandwidthConfigured != nil && !bandwidthConfigured.Load() {
			common.Close(result)
			result = nil
			returnErr = fmt.Errorf("required Hysteria bandwidth overlay is unavailable")
		}
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
	if values["reka_xhttp"] != nil {
		if s.Type != "vless" {
			return nil, fmt.Errorf("XHTTP applies only to VLESS")
		}
		var scoped *XC.Client
		ctx, scoped, err = xhttpContext(ctx, b.componentLogger("outbound", s.Type, tag), values, s.Server, s.Port, s.TLS)
		if err != nil {
			return nil, err
		}
		if scoped != nil {
			xhttpTransport = scoped
		}
	}
	ctx, err = streamContext(ctx, b.componentLogger("outbound", s.Type, tag), values, s.Server, s.Port)
	if err != nil {
		return nil, err
	}
	if s.Plugin != nil {
		if s.Type != "shadowsocks" {
			return nil, fmt.Errorf("SS plugins apply only to Shadowsocks")
		}
		ctx = context.WithValue(ctx, ssPluginFactoryKey{}, func(pluginCtx context.Context, base N.Dialer, dst M.Socksaddr) (sip003.Plugin, error) {
			var createErr error
			plugin, createErr = newSSPlugin(pluginCtx, b.componentLogger("plugin", s.Plugin.Type, tag), base, dst, *s.Plugin)
			return plugin, createErr
		})
		values["plugin"] = "reka-scoped"
		if s.Plugin.Type == "kcptun" {
			uot, ok := values["udp_over_tcp"].(map[string]any)
			if !ok {
				uot = map[string]any{"version": 1}
			}
			uot["enabled"] = true
			values["udp_over_tcp"] = uot
		}
	}
	ctx, realmTransport, err = configureRealmContext(ctx, b.componentLogger("realm", s.Type, tag), values, s.Realm)
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
