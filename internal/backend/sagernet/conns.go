package sagernet

import (
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

	OriginalDestination string
}

type tracked struct {
	attempt *connectionAttempt
	id      uint64
	md      Metadata
	out     *Outbound
	info    any
	start   time.Time
	up      *atomic.Int64
	down    *atomic.Int64
	close   func()

	originalDestination string
}

func (c *tracked) snapshot() ConnInfo {
	return ConnInfo{
		ID: c.id, Metadata: c.md, Outbound: c.out.Tag(), OutboundType: c.out.Type(), Info: c.info,
		Start: c.start, Upload: c.up.Load(), Download: c.down.Load(),
		OriginalDestination: c.originalDestination,
	}
}

func (b *Backend) ConnectionTrace(id uint64, profile string) (api.ConnectionTrace, bool) {
	b.conns.mu.Lock()
	tracked := b.conns.conns[id]
	b.conns.mu.Unlock()
	if tracked == nil || tracked.attempt == nil {
		return api.ConnectionTrace{}, false
	}
	trace := tracked.attempt.trace(tracked.up.Load(), tracked.down.Load())
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
