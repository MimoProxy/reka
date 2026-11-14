package sagernet

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/sagernet/sing/common/logger"
)

// slogLogger forwards upstream log calls to a Reka-owned slog.Logger, so
// upstream components never write logs on their own.
type slogLogger struct {
	l *slog.Logger
}

var _ logger.ContextLogger = (*slogLogger)(nil)

func newLogger(l *slog.Logger, component string) *slogLogger {
	if l == nil {
		l = slog.Default()
	}
	if component != "" {
		l = l.With("component", component)
	}
	return &slogLogger{l: l}
}

// levelTrace sits below slog.LevelDebug; upstream logs per-packet detail at
// trace level.
const levelTrace = slog.LevelDebug - 4

func (s *slogLogger) log(ctx context.Context, level slog.Level, args []any) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.l.Enabled(ctx, level) {
		return
	}
	s.l.Log(ctx, level, fmt.Sprint(args...))
}

func (s *slogLogger) Trace(args ...any) { s.log(nil, levelTrace, args) }
func (s *slogLogger) Debug(args ...any) { s.log(nil, slog.LevelDebug, args) }
func (s *slogLogger) Info(args ...any)  { s.log(nil, slog.LevelInfo, args) }
func (s *slogLogger) Warn(args ...any)  { s.log(nil, slog.LevelWarn, args) }
func (s *slogLogger) Error(args ...any) { s.log(nil, slog.LevelError, args) }
func (s *slogLogger) Fatal(args ...any) {
	s.log(nil, slog.LevelError, args)
	os.Exit(1)
}
func (s *slogLogger) Panic(args ...any) {
	s.log(nil, slog.LevelError, args)
	panic(fmt.Sprint(args...))
}

func (s *slogLogger) TraceContext(ctx context.Context, args ...any) { s.log(ctx, levelTrace, args) }
func (s *slogLogger) DebugContext(ctx context.Context, args ...any) {
	s.log(ctx, slog.LevelDebug, args)
}
func (s *slogLogger) InfoContext(ctx context.Context, args ...any) { s.log(ctx, slog.LevelInfo, args) }
func (s *slogLogger) WarnContext(ctx context.Context, args ...any) { s.log(ctx, slog.LevelWarn, args) }
func (s *slogLogger) ErrorContext(ctx context.Context, args ...any) {
	s.log(ctx, slog.LevelError, args)
}
func (s *slogLogger) FatalContext(ctx context.Context, args ...any) {
	s.log(ctx, slog.LevelError, args)
	os.Exit(1)
}
func (s *slogLogger) PanicContext(ctx context.Context, args ...any) {
	s.log(ctx, slog.LevelError, args)
	panic(fmt.Sprint(args...))
}
