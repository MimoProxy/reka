package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/MimoProxy/reka/internal/config/service"
)

// eventLogHandler keeps the application's configured sink and mirrors actual
// enabled records into the bounded native event stream. WithAttrs/WithGroup
// share one target, so protocol component loggers attach after service startup.
type eventLogHandler struct {
	slog.Handler
	target *atomic.Pointer[service.Broker]
}

func (h *eventLogHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.Handler.Handle(ctx, record)
	if broker := h.target.Load(); broker != nil {
		broker.Publish(service.EventLog, map[string]any{"level": strings.ToLower(record.Level.String()), "message": record.Message, "time": record.Time.UTC()})
	}
	return err
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{Handler: h.Handler.WithAttrs(attrs), target: h.target}
}
func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{Handler: h.Handler.WithGroup(name), target: h.target}
}
