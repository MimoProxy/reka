package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	ST "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	L "github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type RealmSpec struct {
	ServerURL, Token, RealmID string
	STUNServers               []string
	TLS                       *TLSSpec
}

type realmHTTPTransport struct{ *http.Transport }

func (r *realmHTTPTransport) Reset() { r.CloseIdleConnections() }

type realmHTTPManager struct{ transport *realmHTTPTransport }

func (r *realmHTTPManager) ResolveTransport(context.Context, L.ContextLogger, option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	return r.transport, nil
}
func (r *realmHTTPManager) DefaultTransport() adapter.HTTPTransport { return r.transport }
func (r *realmHTTPManager) ResetNetwork()                           { r.transport.Reset() }

func configureRealmContext(ctx context.Context, logger log.ContextLogger, values map[string]any, s *RealmSpec) (context.Context, *realmHTTPTransport, error) {
	if s == nil {
		return ctx, nil, nil
	}
	u, err := url.Parse(s.ServerURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, errors.New("invalid Realm control URL")
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, nil, err
	}
	var physical option.DialerOptions
	if err = json.Unmarshal(raw, &physical); err != nil {
		return nil, nil, err
	}
	base, err := dialer.New(ctx, physical, true)
	if err != nil {
		return nil, nil, err
	}
	tlsSpec := s.TLS
	if tlsSpec == nil {
		tlsSpec = &TLSSpec{}
	}
	// The control server is a different TLS peer from the QUIC proxy. A node
	// pin/verification override must never leak into this configuration.
	tlsCtx := context.WithValue(ctx, "reka.tls.configure.v1", func(any) error { return nil })
	tlsCtx, configured := configureTLSContext(tlsCtx, tlsSpec)
	config, err := ST.NewClient(tlsCtx, logger, u.Hostname(), *tlsSpec.build())
	if err != nil {
		return nil, nil, err
	}
	if configured != nil && !configured.Load() {
		return nil, nil, errors.New("required Realm TLS verification overlay is unavailable")
	}
	standard, err := config.STDConfig()
	if err != nil {
		return nil, nil, err
	}
	transport := &realmHTTPTransport{&http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return base.DialContext(ctx, network, M.ParseSocksaddr(address))
	}, TLSClientConfig: standard, ForceAttemptHTTP2: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second}}
	values["realm"] = map[string]any{"server_url": s.ServerURL, "token": s.Token, "realm_id": s.RealmID, "stun_servers": s.STUNServers}
	// The reference uses Realm instead of the static address. Keep a configured
	// proxy TLS identity, but let the component derive it from the control host
	// when there was no explicit static server name.
	delete(values, "server")
	delete(values, "server_port")
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.HTTPClientManager](ctx, &realmHTTPManager{transport})
	return ctx, transport, nil
}

func (r *realmHTTPTransport) Close() error { r.CloseIdleConnections(); return nil }
func (r *realmHTTPTransport) SetKeepIdleConnections(keep bool) {
	if !keep {
		r.CloseIdleConnections()
	}
}
