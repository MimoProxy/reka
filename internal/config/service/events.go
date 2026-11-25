package service

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Event types.
const (
	EventSnapshot  = "snapshot"
	EventCommitted = "config.committed"
	EventRejected  = "config.rejected"
	EventOperation = "operation"
	EventRuntime   = "runtime.generation"
	EventCandidate = "candidate.invalid"
	EventLog       = "log"
)

// EventScriptNotification is Reka's control event for notifications posted by scripts.
const EventScriptNotification = "script.notification"

const (
	historySize     = 512
	subscriberSize  = 256
	snapshotRetries = 3
)

// Broker fans events out to subscribers through bounded queues. A slow
// subscriber loses events (counted in Dropped) instead of slowing the
// publisher.
type Broker struct {
	epoch   string
	mu      sync.Mutex
	seq     uint64
	history []Event
	subs    map[*Subscription]struct{}
}

// NewBroker starts a new epoch.
func NewBroker() *Broker {
	b := make([]byte, 8)
	rand.Read(b)
	return &Broker{epoch: hex.EncodeToString(b), subs: map[*Subscription]struct{}{}}
}

// Epoch identifies this process run.
func (b *Broker) Epoch() string { return b.epoch }

// Recent returns a bounded chronological view from the same event history
// used by cursor replay. It does not synthesize logs or bypass drop tracking.
func (b *Broker) Recent(typ string, limit int) []Event {
	if limit <= 0 || limit > 256 {
		limit = 100
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Event{}
	for i := len(b.history) - 1; i >= 0 && len(out) < limit; i-- {
		if b.history[i].Type == typ {
			out = append(out, b.history[i])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Subscription receives events on C until Close.
type Subscription struct {
	b       *Broker
	C       chan Event
	types   map[string]bool
	dropped uint64
	closed  bool
}

func (s *Subscription) wants(t string) bool {
	return len(s.types) == 0 || s.types[t] || t == EventSnapshot
}

// Publish appends an event and delivers it.
func (b *Broker) Publish(typ string, data any) Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	ev := Event{Epoch: b.epoch, Seq: b.seq, Type: typ, Time: time.Now().UTC(), Data: data}
	b.history = append(b.history, ev)
	if len(b.history) > historySize {
		b.history = b.history[len(b.history)-historySize:]
	}
	for s := range b.subs {
		if s.wants(typ) {
			s.deliver(ev)
		}
	}
	return ev
}

// deliver is called with b.mu held.
func (s *Subscription) deliver(ev Event) {
	ev.Dropped = s.dropped
	select {
	case s.C <- ev:
		s.dropped = 0
	default:
		s.dropped++
	}
}

// Subscribe starts a subscription. A cursor from this epoch that is still
// covered by history resumes with the missed events. Otherwise the stream
// starts with a snapshot of the current state, followed by events published
// while building it. The snapshot callback may run more than once, and
// replayed events may already be reflected in the snapshot. If the final
// attempt outlasts the history window, replay starts at the oldest retained
// event.
func (b *Broker) Subscribe(types []string, epoch string, after uint64, snapshot func() any) *Subscription {
	s := &Subscription{b: b, types: map[string]bool{}}
	for _, t := range types {
		s.types[t] = true
	}
	b.mu.Lock()
	replay := epoch == b.epoch && after <= b.seq &&
		(after == b.seq || (len(b.history) > 0 && b.history[0].Seq <= after+1))
	var data any
	if !replay {
		after, data = b.readSnapshot(snapshot)
	}
	pending := b.history[len(b.history)-int(b.seq-after):]
	queueSize := subscriberSize
	if !replay {
		// Leave room for live events alongside the snapshot and its replay.
		queueSize += len(pending)
	}
	s.C = make(chan Event, queueSize)
	if !replay {
		s.deliver(Event{Epoch: b.epoch, Seq: after, Type: EventSnapshot, Time: time.Now().UTC(), Data: data})
	}
	for _, ev := range pending {
		if s.wants(ev.Type) {
			s.deliver(ev)
		}
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// readSnapshot starts and returns with b.mu held, releasing it around the
// callback so it can read state from publishers.
func (b *Broker) readSnapshot(snapshot func() any) (uint64, any) {
	if snapshot == nil {
		return b.seq, nil
	}
	var data any
	for retry := 0; retry <= snapshotRetries+1; retry++ {
		seq := b.seq
		b.mu.Unlock()
		data = snapshot()
		b.mu.Lock()
		if b.seq == seq || (retry >= snapshotRetries && b.history[0].Seq <= seq+1) {
			return seq, data
		}
	}
	// The final retry also lost history. Place the snapshot before the
	// retained events so the new stream starts with a contiguous sequence.
	return b.history[0].Seq - 1, data
}

// Close stops delivery and closes C.
func (s *Subscription) Close() {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	delete(s.b.subs, s)
	close(s.C)
}
