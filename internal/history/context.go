package history

import "context"

type contextKey uint8

const (
	flowKey contextKey = iota
	dnsOriginKey
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
