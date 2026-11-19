package sagernet

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
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
}

type tracked struct {
	id    uint64
	md    Metadata
	out   *Outbound
	info  any
	start time.Time
	up    *atomic.Int64
	down  *atomic.Int64
	close func()
}

type connTable struct {
	next  atomic.Uint64
	mu    sync.Mutex
	conns map[uint64]*tracked
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
		delete(t.conns, c.id)
		t.mu.Unlock()
	}
}

// Connections lists the active connections, oldest first.
func (b *Backend) Connections() []ConnInfo {
	b.conns.mu.Lock()
	out := make([]ConnInfo, 0, len(b.conns.conns))
	for _, c := range b.conns.conns {
		out = append(out, ConnInfo{
			ID: c.id, Metadata: c.md, Outbound: c.out.Tag(), OutboundType: c.out.Type(), Info: c.info,
			Start: c.start, Upload: c.up.Load(), Download: c.down.Load(),
		})
	}
	b.conns.mu.Unlock()
	slices.SortFunc(out, func(a, b ConnInfo) int { return int(a.ID - b.ID) })
	return out
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
