package sagernet

import "github.com/MimoProxy/reka/internal/history"

// PreMatchAction is what to do with a new flow before it is accepted.
type PreMatchAction uint8

const (
	PreMatchContinue PreMatchAction = iota
	PreMatchReject
	PreMatchDrop
)

// PreMatchVerdict is a decision made from a flow's first packet.
type PreMatchVerdict struct {
	Action PreMatchAction
	// Info and Scope describe the flow for connection history, as in Route.
	Info  any
	Scope history.Scope
}

// PreMatchFunc judges a new TUN flow. It must not block: no DNS lookups,
// no process lookups and no network I/O.
type PreMatchFunc func(md Metadata) PreMatchVerdict

// SetPreMatch installs a flow pre-matching callback. A nil callback clears it.
func (b *Backend) SetPreMatch(fn PreMatchFunc) { b.router.preMatchFn.Store(&fn) }

func (r *router) preMatch(md Metadata) PreMatchVerdict {
	if fn := r.preMatchFn.Load(); fn != nil && *fn != nil {
		return (*fn)(md)
	}
	return PreMatchVerdict{Action: PreMatchContinue}
}
