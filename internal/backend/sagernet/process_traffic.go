package sagernet

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
)

// MaxProcessTrafficEntries limits retained executable identities, with two
// additional fixed buckets for unavailable owners and cardinality overflow.
const MaxProcessTrafficEntries = 1024

type ProcessTrafficRow struct {
	ID                  string
	Path                string
	UID                 *uint32
	Unknown             bool
	Overflow            bool
	Upload, Download    uint64
	Active, Connections uint64
}

type processTrafficCounter struct {
	id, path          string
	uid               *uint32
	unknown, overflow bool
	upload, download  atomic.Uint64
	active            atomic.Int64
	connections       atomic.Uint64
}

type processTrafficTable struct {
	sync.Mutex
	entries map[string]*processTrafficCounter
	order   []*processTrafficCounter
}

func (b *Backend) beginProcessTraffic(owner ProcessInfo) (*processTrafficCounter, func()) {
	t := &b.processTraffic
	t.Lock()
	if t.entries == nil {
		t.entries = make(map[string]*processTrafficCounter)
	}
	unknown := owner.Path == "" && !owner.UIDKnown
	key := fmt.Sprintf("%t:%d:%s", owner.UIDKnown, owner.UID, owner.Path)
	if !owner.UIDKnown {
		key = fmt.Sprintf("false:0:%s", owner.Path)
	}
	if unknown {
		key = "unknown"
	}
	counter := t.entries[key]
	if counter == nil {
		// Bound both entry count and retained string size. Never evict counters:
		// active flows may still hold them, and closed-flow totals must not vanish.
		knownCount := len(t.order)
		if t.entries["unknown"] != nil {
			knownCount--
		}
		if t.entries["overflow"] != nil {
			knownCount--
		}
		overflow := !unknown && (knownCount >= MaxProcessTrafficEntries || len(owner.Path) > 4096)
		if overflow {
			key = "overflow"
			counter = t.entries[key]
		}
		if counter == nil {
			digest := sha256.Sum256([]byte(key))
			counter = &processTrafficCounter{id: fmt.Sprintf("%x", digest[:16]), unknown: unknown, overflow: overflow}
			if !unknown && !overflow {
				counter.path = owner.Path
				if owner.UIDKnown {
					uid := owner.UID
					counter.uid = &uid
				}
			}
			t.entries[key] = counter
			t.order = append(t.order, counter)
		}
	}
	counter.active.Add(1)
	counter.connections.Add(1)
	t.Unlock()
	var once sync.Once
	return counter, func() { once.Do(func() { counter.active.Add(-1) }) }
}

// ProcessTraffic retains application-flow counters for this Backend lifetime.
// PID is deliberately excluded from aggregation to avoid PID reuse and churn.
func (b *Backend) ProcessTraffic(offset, limit int) ([]ProcessTrafficRow, int) {
	t := &b.processTraffic
	t.Lock()
	defer t.Unlock()
	total := len(t.order)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows := make([]ProcessTrafficRow, 0, min(limit, total-offset))
	for _, c := range t.order[offset:min(total, offset+limit)] {
		row := ProcessTrafficRow{ID: c.id, Path: c.path, Unknown: c.unknown, Overflow: c.overflow, Upload: c.upload.Load(), Download: c.download.Load(), Active: uint64(max(0, c.active.Load())), Connections: c.connections.Load()}
		if c.uid != nil {
			uid := *c.uid
			row.UID = &uid
		}
		rows = append(rows, row)
	}
	return rows, total
}
