package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	MUX "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type multiplexSpec struct {
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol"`
	MaxConnections int    `json:"max_connections"`
	MinStreams     int    `json:"min_streams"`
	MaxStreams     int    `json:"max_streams"`
	Padding        bool   `json:"padding"`
	OnlyTCP        bool   `json:"only_tcp"`
	Brutal         *struct {
		Enabled bool   `json:"enabled"`
		UpBPS   uint64 `json:"up_bps"`
		DownBPS uint64 `json:"down_bps"`
	} `json:"brutal"`
}

func popMultiplex(values map[string]any) (*multiplexSpec, error) {
	value, ok := values["multiplex"]
	if !ok {
		return nil, nil
	}
	delete(values, "multiplex")
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var spec multiplexSpec
	if err = json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	if !spec.Enabled {
		return nil, nil
	}
	if !slices.Contains([]string{"", "h2mux", "smux", "yamux"}, spec.Protocol) || spec.MaxConnections < 0 || spec.MinStreams < 0 || spec.MaxStreams < 0 {
		return nil, errors.New("invalid multiplex options")
	}
	return &spec, nil
}
func wrapMultiplex(base adapter.Outbound, spec *multiplexSpec, logger log.ContextLogger) (adapter.Outbound, error) {
	if spec == nil {
		return base, nil
	}
	brutal := MUX.BrutalOptions{}
	if spec.Brutal != nil && spec.Brutal.Enabled {
		if spec.Brutal.UpBPS < 65536 || spec.Brutal.DownBPS < 65536 {
			return nil, errors.New("invalid Brutal bandwidth")
		}
		brutal = MUX.BrutalOptions{Enabled: true, SendBPS: spec.Brutal.UpBPS, ReceiveBPS: spec.Brutal.DownBPS}
	}
	client, err := MUX.NewClient(MUX.Options{Dialer: &multiplexDialer{base}, Logger: logger, Protocol: spec.Protocol, MaxConnections: spec.MaxConnections, MinStreams: spec.MinStreams, MaxStreams: spec.MaxStreams, Padding: spec.Padding, Brutal: brutal})
	if err != nil {
		return nil, err
	}
	return &multiplexOutbound{Outbound: base, client: client, onlyTCP: spec.OnlyTCP}, nil
}

type multiplexOutbound struct {
	adapter.Outbound
	client   *MUX.Client
	onlyTCP  bool
	once     sync.Once
	closeErr error
}

func (m *multiplexOutbound) Network() []string {
	result := slices.Clone(m.Outbound.Network())
	if !m.onlyTCP && !slices.Contains(result, "udp") {
		result = append(result, "udp")
	}
	return result
}
func (m *multiplexOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if m.onlyTCP && N.NetworkName(network) == "udp" {
		return m.Outbound.DialContext(ctx, network, dst)
	}
	return m.client.DialContext(ctx, network, dst)
}
func (m *multiplexOutbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if m.onlyTCP {
		return m.Outbound.ListenPacket(ctx, dst)
	}
	return m.client.ListenPacket(ctx, dst)
}
func (m *multiplexOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if base, ok := m.Outbound.(adapter.Lifecycle); ok {
		if err := base.Start(stage, scope); err != nil {
			return err
		}
	}
	if stage == adapter.StartStateInitialize {
		scope.Add(m.Close)
	}
	return nil
}
func (m *multiplexOutbound) Close() error {
	m.once.Do(func() { m.closeErr = errors.Join(m.client.Close(), common.Close(m.Outbound)) })
	return m.closeErr
}
func (m *multiplexOutbound) MultiplexEnabled() bool { return true }
func (m *multiplexOutbound) InterfaceUpdated(ctx context.Context) {
	if base, ok := m.Outbound.(adapter.InterfaceUpdateListener); ok {
		base.InterfaceUpdated(ctx)
	}
	m.client.Reset()
}
func (m *multiplexOutbound) SetKeepIdleConnections(keep bool) {
	m.client.SetKeepIdleConnections(keep)
	if base, ok := m.Outbound.(adapter.IdleConnectionKeeper); ok {
		base.SetKeepIdleConnections(keep)
	}
}
func (m *multiplexOutbound) CloseIdleConnections() {
	m.client.CloseIdleConnections()
	if base, ok := m.Outbound.(adapter.IdleConnectionKeeper); ok {
		base.CloseIdleConnections()
	}
}

type multiplexDialer struct{ adapter.Outbound }

func (m *multiplexDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return m.Outbound.DialContext(adapter.ContextForMultiplexSession(ctx), network, dst)
}
func (m *multiplexDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return m.Outbound.ListenPacket(adapter.ContextForMultiplexSession(ctx), dst)
}
