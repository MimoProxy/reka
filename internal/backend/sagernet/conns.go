package sagernet

import (
	"cmp"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/api"
)

// ConnInfo is a point-in-time view of one relayed connection (a TCP
// connection, or one UDP destination flow).
type ConnInfo struct {
	ID           uint64
	Metadata     Metadata
	Outbound     string
	OutboundType string
	// Info is what the RouteFunc attached to the route.
	Info     any
	Start    time.Time
	Upload   int64
	Download int64
	State    string

	OriginalDestination string
	api.MITMConnectionInfo
	api.ConnectionNetwork
}

type tracked struct {
	attempt *connectionAttempt
	id      uint64
	md      Metadata
	out     *Outbound
	info    any
	start   time.Time
	close   func()

	originalDestination string
}

func (c *tracked) snapshot() ConnInfo {
	state, mitm, network := c.attempt.activeInfo()
	return ConnInfo{
		ID: c.id, Metadata: c.md, Outbound: c.out.Tag(), OutboundType: c.out.Type(), Info: c.info,
		Start: c.start, Upload: c.attempt.up.Load(), Download: c.attempt.down.Load(),
		State:               state,
		OriginalDestination: c.originalDestination,
		MITMConnectionInfo:  mitm,
		ConnectionNetwork:   network,
	}
}

func (b *Backend) ConnectionTrace(id uint64, profile string) (api.ConnectionTrace, bool) {
	b.conns.mu.Lock()
	tracked := b.conns.conns[id]
	b.conns.mu.Unlock()
	if tracked == nil {
		return api.ConnectionTrace{}, false
	}
	trace := tracked.attempt.trace()
	return trace, trace.Scope.ProfileID == profile
}

type connTable struct {
	next  atomic.Uint64
	mu    sync.Mutex
	conns map[uint64]*tracked

	onClosed func(ConnInfo)
}

func (t *connTable) add(c *tracked) func() {
	t.mu.Lock()
	if t.conns == nil {
		t.conns = map[uint64]*tracked{}
	}
	t.conns[c.id] = c
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.onClosed != nil && t.conns[c.id] == c {
			t.onClosed(c.snapshot())
		}
		delete(t.conns, c.id)
	}
}

// Connections lists the active connections, oldest first.
func (b *Backend) Connections() []ConnInfo {
	var out []ConnInfo
	b.WithConnectionSnapshot(func(active []ConnInfo) { out = active })
	// Ranking still needs completed connections until onClosed takes their totals.
	out = slices.DeleteFunc(out, func(c ConnInfo) bool { return c.State == "" })
	slices.SortFunc(out, func(a, b ConnInfo) int { return int(a.ID - b.ID) })
	return out
}

// WithConnectionSnapshot visits the unordered active connections while close
// notifications are excluded. The callback must not access the connection table.
func (b *Backend) WithConnectionSnapshot(visit func([]ConnInfo)) {
	b.conns.mu.Lock()
	defer b.conns.mu.Unlock()
	out := make([]ConnInfo, 0, len(b.conns.conns))
	for _, c := range b.conns.conns {
		out = append(out, c.snapshot())
	}
	visit(out)
}

// ConnectionCount is the number of active connections.
func (b *Backend) ConnectionCount() int {
	b.conns.mu.Lock()
	defer b.conns.mu.Unlock()
	return len(b.conns.conns)
}

// CloseIdleConnections frees memory with the least disruption: it closes
// connections that already ended, then those that carried no traffic for
// at least idle, then more of the longest idle until it has closed at least
// share of all connections. It reports how many it closed and how many
// there were.
func (b *Backend) CloseIdleConnections(now time.Time, idle time.Duration, share float64) (closed, total int) {
	type candidate struct {
		c     *tracked
		ended bool
		last  time.Time
	}
	b.conns.mu.Lock()
	candidates := make([]candidate, 0, len(b.conns.conns))
	for _, c := range b.conns.conns {
		state, _, _ := c.attempt.activeInfo()
		last := c.attempt.up.lastActive()
		if down := c.attempt.down.lastActive(); down.After(last) {
			last = down
		}
		candidates = append(candidates, candidate{c: c, ended: state == "", last: last})
	}
	b.conns.mu.Unlock()
	total = len(candidates)
	atLeast := int(math.Ceil(share * float64(total)))
	slices.SortFunc(candidates, func(x, y candidate) int {
		switch {
		case x.ended != y.ended:
			if x.ended {
				return -1
			}
			return 1
		case !x.last.Equal(y.last):
			return x.last.Compare(y.last)
		}
		return cmp.Compare(x.c.id, y.c.id)
	})
	for _, v := range candidates {
		if closed >= atLeast && !v.ended && now.Sub(v.last) < idle {
			break
		}
		v.c.close()
		closed++
	}
	return closed, total
}

// CloseConnections closes the connections with the given IDs, or all of
// them when ids is nil, and reports how many it closed.
func (b *Backend) CloseConnections(ids []uint64) int {
	b.conns.mu.Lock()
	var victims []*tracked
	for id, c := range b.conns.conns {
		if ids == nil || slices.Contains(ids, id) {
			victims = append(victims, c)
		}
	}
	b.conns.mu.Unlock()
	for _, c := range victims {
		c.close()
	}
	return len(victims)
}
