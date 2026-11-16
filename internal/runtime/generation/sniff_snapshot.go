package generation

import (
	"context"
	"net/netip"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/runtime"
)

type sniffSnapshotKey struct{}

func sniffSnapshotContext(ctx context.Context, snapshot *runtime.Snapshot[*sagernet.Outbound]) context.Context {
	return context.WithValue(ctx, sniffSnapshotKey{}, snapshot)
}

// retainSniffSnapshot carries the already chosen generation through nested
// dialer-proxy and DNS work. Ordinary flows keep the existing active-policy
// behavior; only flows prepared for sniffing install this private context key.
func retainSniffSnapshot(result sagernet.Route, snapshot *runtime.Snapshot[*sagernet.Outbound]) sagernet.Route {
	baseContext := result.Context
	result.Context = func(ctx context.Context) context.Context {
		if baseContext != nil {
			ctx = baseContext(ctx)
		}
		return sniffSnapshotContext(ctx, snapshot)
	}
	if lookup := result.Lookup; lookup != nil {
		result.Lookup = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return lookup(sniffSnapshotContext(ctx, snapshot), domain)
		}
	}
	return result
}
