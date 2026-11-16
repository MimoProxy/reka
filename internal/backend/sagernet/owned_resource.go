package sagernet

import (
	"context"
	"io"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
)

type outboundResource interface {
	io.Closer
	adapter.IdleConnectionKeeper
	Reset()
}

// A scoped carrier/control resource shares the outbound's lease lifetime.
// Retiring a generation first drains its flows; Close then destroys pools.
type ownedResourceOutbound struct {
	adapter.Outbound
	resource outboundResource
	once     sync.Once
	err      error
}

func (r *ownedResourceOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if base, ok := r.Outbound.(adapter.Lifecycle); ok {
		if err := base.Start(stage, scope); err != nil {
			return err
		}
	}
	if stage == adapter.StartStateInitialize {
		scope.Add(r.Close)
	}
	return nil
}
func (r *ownedResourceOutbound) Close() error {
	r.once.Do(func() { r.err = common.Close(r.Outbound, r.resource) })
	return r.err
}
func (r *ownedResourceOutbound) InterfaceUpdated(ctx context.Context) {
	if base, ok := r.Outbound.(adapter.InterfaceUpdateListener); ok {
		base.InterfaceUpdated(ctx)
	}
	r.resource.Reset()
}
func (r *ownedResourceOutbound) SetKeepIdleConnections(keep bool) {
	if base, ok := r.Outbound.(adapter.IdleConnectionKeeper); ok {
		base.SetKeepIdleConnections(keep)
	}
	r.resource.SetKeepIdleConnections(keep)
}
func (r *ownedResourceOutbound) CloseIdleConnections() {
	if base, ok := r.Outbound.(adapter.IdleConnectionKeeper); ok {
		base.CloseIdleConnections()
	}
	r.resource.CloseIdleConnections()
}
func (r *ownedResourceOutbound) MultiplexEnabled() bool {
	if base, ok := r.Outbound.(adapter.OutboundWithMultiplex); ok {
		return base.MultiplexEnabled()
	}
	return false
}
