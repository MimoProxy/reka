package sagernet

import (
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

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
	// Info may be read asynchronously and must remain immutable.
	Info  any
	Scope history.Scope
}

// PreMatchFunc judges a new TUN flow. It must not block: no DNS lookups,
// no process lookups and no network I/O.
type PreMatchFunc func(md Metadata) PreMatchVerdict

// SetPreMatch installs a flow pre-matching callback. A nil callback clears it.
func (b *Backend) SetPreMatch(fn PreMatchFunc) {
	if fn != nil {
		b.preMatchReportOnce.Do(func() {
			// Match sing-box's observable log subscriber buffer.
			b.preMatchReports = make(chan preMatchReport, 128)
			go b.runPreMatchReports()
		})
	}
	b.router.preMatchFn.Store(&fn)
}

func (r *router) preMatch(md Metadata) PreMatchVerdict {
	if fn := r.preMatchFn.Load(); fn != nil && *fn != nil {
		return (*fn)(md)
	}
	return PreMatchVerdict{Action: PreMatchContinue}
}

type preMatchReport struct {
	metadata Metadata
	verdict  PreMatchVerdict
	start    time.Time
}

func (b *Backend) reportPreMatched(md Metadata, verdict PreMatchVerdict) {
	if b.ctx.Err() != nil {
		return
	}
	// History serialization and logging can block. Skip reports if the worker falls behind.
	select {
	case b.preMatchReports <- preMatchReport{metadata: md, verdict: verdict, start: time.Now()}:
	default:
	}
}

func (b *Backend) runPreMatchReports() {
	for {
		select {
		case report := <-b.preMatchReports:
			b.recordPreMatched(report)
		case <-b.ctx.Done():
			for len(b.preMatchReports) > 0 {
				b.recordPreMatched(<-b.preMatchReports)
			}
			return
		}
	}
}

func (b *Backend) recordPreMatched(report preMatchReport) {
	md, verdict := report.metadata, report.verdict
	if b.history != nil {
		attempt := b.beginConnectionAt(b.ctx, md, report.start)
		attempt.setRoute(Route{Info: verdict.Info, Scope: verdict.Scope}, md.Destination.Addr)
		attempt.complete(connectionReason(nil, "rejected"), "pre-match")
	}
	action := "reject"
	if verdict.Action == PreMatchDrop {
		action = "drop"
	}
	b.logger.DebugContext(b.ctx, "pre-match ", action, " ", md.Destination)
}
