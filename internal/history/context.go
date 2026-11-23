package history

import (
	"context"
	"time"
)

type contextKey uint8

const (
	flowKey contextKey = iota
	dnsOriginKey
	dnsObserverKey
)

func WithFlow(ctx context.Context, id uint64) context.Context {
	return context.WithValue(ctx, flowKey, id)
}

func Flow(ctx context.Context) uint64 {
	id, _ := ctx.Value(flowKey).(uint64)
	return id
}

type DNSOrigin struct {
	Kind      string
	Network   string
	Client    string
	Requested string
}

func WithDNSOrigin(ctx context.Context, origin DNSOrigin) context.Context {
	return context.WithValue(ctx, dnsOriginKey, origin)
}

func Origin(ctx context.Context) DNSOrigin {
	origin, _ := ctx.Value(dnsOriginKey).(DNSOrigin)
	return origin
}

type DNSObservation struct {
	Name, Type, Source string
	Answers            int    // Records in the answer section.
	AddressAnswers     [2]int // Usable IPv4 and IPv6 answers.
	Duration           time.Duration
	Err                error
}

// WithDNSObserver attaches a callback to the caller's DNS exchanges. The
// callback runs before each exchange returns and may be called concurrently
// when the context is shared. A nil callback clears an inherited observer.
func WithDNSObserver(ctx context.Context, fn func(DNSObservation)) context.Context {
	return context.WithValue(ctx, dnsObserverKey, fn)
}

func DNSObserver(ctx context.Context) func(DNSObservation) {
	fn, _ := ctx.Value(dnsObserverKey).(func(DNSObservation))
	return fn
}
