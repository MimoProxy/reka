package generation

import (
	"context"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/runtime"
)

// prepareFlow pins routing resources during bounded sniffing. Selecting an
// outbound transfers its lease to the resulting flow; only its resolver's
// possible transports retain separate dependency pins until that flow ends.
// Both remain usable if a concurrent commit retires the captured generation.
func (e *Engine) prepareFlow(ctx context.Context, md sagernet.Metadata) sagernet.PreparedFlow {
	for {
		if ctx.Err() != nil {
			return sagernet.PreparedFlow{Route: func(context.Context, sagernet.Metadata) sagernet.Route { return sagernet.Route{} }}
		}
		snap, g := e.current()
		if g.eff == nil || !g.eff.Sniff.Enabled {
			return sagernet.PreparedFlow{Route: e.route}
		}
		pins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		dnsPins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		valid := true
		for _, outbound := range snap.Resources {
			if pins[outbound] != nil {
				continue
			}
			pin, err := outbound.Pin()
			if err != nil {
				valid = false
				break
			}
			pins[outbound] = pin
		}
		if valid {
			for outbound := range sniffDNSDependencies(g, snap.Resources) {
				pin, err := outbound.Pin()
				if err != nil {
					valid = false
					break
				}
				dnsPins[outbound] = pin
			}
		}
		if !valid {
			closeSniffPins(pins)
			closeSniffPins(dnsPins)
			// Retirement without a newer snapshot is shutdown (or an invalid
			// resource), not a publication race. Do not spin waiting for one.
			if e.rt.Current() == snap {
				return sagernet.PreparedFlow{Route: func(context.Context, sagernet.Metadata) sagernet.Route { return sagernet.Route{} }}
			}
			continue
		}
		var mu sync.Mutex
		borrowPins := make(map[*sagernet.Outbound]*sagernet.PinnedOutbound, len(pins))
		for outbound, pin := range pins {
			borrowPins[outbound] = pin
		}
		closed := false
		release := func() {
			mu.Lock()
			defer mu.Unlock()
			if closed {
				return
			}
			closed = true
			for outbound, pin := range pins {
				_ = pin.Close()
				delete(pins, outbound)
			}
			closeSniffPins(dnsPins)
			dnsPins = nil
		}
		acquire := func(pick func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error) {
			outbound, ok := pick(snap)
			mu.Lock()
			defer mu.Unlock()
			if closed || !ok || pins[outbound] == nil {
				return snap.Generation, nil, nil, false, nil
			}
			release, transferred := pins[outbound].TransferToFlow()
			if !transferred {
				return snap.Generation, nil, nil, false, nil
			}
			delete(pins, outbound)
			return snap.Generation, outbound, release, true, nil
		}
		cfg := g.eff.Sniff
		return sagernet.PreparedFlow{
			Sniff: sagernet.SniffOptions{Enabled: true, Protocols: append([]string(nil), cfg.Protocols...), Timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond, MaxBytes: cfg.MaxBytes, MaxPackets: cfg.MaxPackets, OverrideDestination: cfg.OverrideDestination},
			Route: func(ctx context.Context, md sagernet.Metadata) sagernet.Route {
				ctx = sniffSnapshotContext(ctx, snap)
				result := e.routeWithAcquire(sagernet.WithPinnedOutbounds(ctx, borrowPins), md, acquire, snap)
				if result.Outbound == nil {
					return result
				}
				mu.Lock()
				if closed {
					mu.Unlock()
					result.Release()
					return sagernet.Route{Info: result.Info}
				}
				flowPins := dnsPins
				dnsPins = nil
				mu.Unlock()
				return retainSniffSnapshot(retainFlowDNS(result, flowPins), snap)
			},
			Release: release,
		}
	}
}
