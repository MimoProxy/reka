//go:build with_gvisor

package packettunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

const (
	logMessageBytes = 320
	logFieldCount   = 12
	logFieldKey     = 40
	logFieldValue   = 200
	// The log file outlives the extension process, so it shows how a session
	// ended even when the system killed the extension. One rotated copy is
	// kept, so at most twice this much stays on disk.
	logFileBytes = 192 << 10
)

// logEntry is one tunnel log line, both in the ring and in the log file.
type logEntry struct {
	TimeMS    int64             `json:"timeMs"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Component string            `json:"component,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type tunnelLogHandler struct {
	events    *history.Store
	sink      *logFile
	component string
	attrs     []slog.Attr
}

func newTunnelLogHandler(events *history.Store) tunnelLogHandler {
	return tunnelLogHandler{events: events, sink: &logFile{}}
}

func (h tunnelLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Library components log each dial at Info. Keep those messages out of the
	// extension's small ring, leaving room for lifecycle events and errors.
	if h.component != "" {
		return level >= slog.LevelWarn
	}
	return level >= slog.LevelInfo
}

func (h tunnelLogHandler) Handle(_ context.Context, record slog.Record) error {
	entry := logEntry{
		TimeMS: record.Time.UnixMilli(), Level: strings.ToLower(record.Level.String()),
		Message: history.Text(record.Message, logMessageBytes), Component: h.component,
	}
	add := func(attr slog.Attr) bool {
		if len(entry.Fields) >= logFieldCount {
			return false
		}
		value := attr.Value.Resolve()
		if attr.Key == "" || value.Kind() == slog.KindGroup {
			return true
		}
		if entry.Fields == nil {
			entry.Fields = make(map[string]string, 4)
		}
		entry.Fields[history.Text(attr.Key, logFieldKey)] = history.Text(logValue(value), logFieldValue)
		return true
	}
	for _, attr := range h.attrs {
		add(attr)
	}
	record.Attrs(add)
	h.events.Record(history.Logs, history.Scope{}, record.Time, entry, nil)
	h.sink.write(entry)
	return nil
}

func logValue(value slog.Value) string {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindDuration:
		return value.Duration().Round(time.Millisecond).String()
	case slog.KindTime:
		return value.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindAny:
		if err, ok := value.Any().(error); ok && err != nil {
			return err.Error()
		}
		return fmt.Sprint(value.Any())
	default:
		return value.String()
	}
}

func (h tunnelLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for _, attr := range attrs {
		if attr.Key == "component" && attr.Value.Kind() == slog.KindString {
			h.component = history.Text(attr.Value.String(), 64)
			continue
		}
		h.attrs = append(h.attrs[:len(h.attrs):len(h.attrs)], attr)
	}
	return h
}

func (h tunnelLogHandler) WithGroup(string) slog.Handler { return h }

// logFile appends log entries as JSON lines to a file the host names, and
// keeps one rotated copy at path + ".1".
type logFile struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

func (f *logFile) open(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeLocked()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	f.path, f.file, f.size = path, file, info.Size()
	return nil
}

func (f *logFile) write(entry logEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if f.size+int64(len(line)) > logFileBytes {
		_ = f.file.Close()
		_ = os.Rename(f.path, f.path+".1")
		file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
		if err != nil {
			f.file = nil
			return
		}
		f.file, f.size = file, 0
	}
	n, _ := f.file.Write(line)
	f.size += int64(n)
}

func (f *logFile) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeLocked()
}

func (f *logFile) closeLocked() {
	if f.file != nil {
		_ = f.file.Close()
		f.file = nil
	}
}

// Package-level slog calls in the runtime have no session logger. While an
// extension session runs, they go to its log too.
var defaultLogger struct {
	mu       sync.Mutex
	owner    *Session
	previous *slog.Logger
}

func (s *Session) captureDefaultLogger() {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	if defaultLogger.owner == nil {
		defaultLogger.previous = slog.Default()
	}
	defaultLogger.owner = s
	slog.SetDefault(s.logger.With("component", "runtime"))
}

func (s *Session) releaseDefaultLogger() {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	if defaultLogger.owner != s {
		return
	}
	slog.SetDefault(defaultLogger.previous)
	defaultLogger.owner, defaultLogger.previous = nil, nil
}
