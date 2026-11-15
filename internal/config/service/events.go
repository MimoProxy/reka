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
)

const (
	historySize    = 512
	subscriberSize = 256
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

// Subscribe starts a subscription. With a cursor from this epoch whose
// events are still in history, the missed events are replayed first;
// otherwise the subscriber gets a snapshot event built by snapshot (the
// full current state) and continues from there.
func (b *Broker) Subscribe(types []string, epoch string, after uint64, snapshot func() any) *Subscription {
	s := &Subscription{b: b, C: make(chan Event, subscriberSize), types: map[string]bool{}}
	for _, t := range types {
		s.types[t] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	replay := epoch == b.epoch && after <= b.seq &&
		(after == b.seq || (len(b.history) > 0 && b.history[0].Seq <= after+1))
	if replay {
		for _, ev := range b.history {
			if ev.Seq > after && s.wants(ev.Type) {
				s.deliver(ev)
			}
		}
	} else {
		var data any
		if snapshot != nil {
			data = snapshot()
		}
		s.deliver(Event{Epoch: b.epoch, Seq: b.seq, Type: EventSnapshot, Time: time.Now().UTC(), Data: data})
	}
	b.subs[s] = struct{}{}
	return s
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
