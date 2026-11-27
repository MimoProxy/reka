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
	// kept, so at most twice this much stays on disk. Writes go straight to
	// the file, so its size costs no extension memory.
	logFileBytes = 512 << 10

	// A network outage makes every dial log the same error. Without a limit,
	// a few minutes of them push out the lines that show how it started.
	// Each kind of warning or error is kept logRepeatBurst times per window;
	// the rest are counted and summarized in one line, written with the first
	// line logged after the window ends.
	logRepeatWindow = 30 * time.Second
	logRepeatBurst  = 3
	logRepeatKinds  = 128
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
	repeats   *logRepeats
	component string
	attrs     []slog.Attr
}

func newTunnelLogHandler(events *history.Store) tunnelLogHandler {
	return tunnelLogHandler{events: events, sink: &logFile{}, repeats: newLogRepeats()}
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
	keep, summaries := h.repeats.admit(entry, record.Level >= slog.LevelWarn)
	for _, summary := range summaries {
		h.write(summary)
	}
	if keep {
		h.write(entry)
	}
	return nil
}

func (h tunnelLogHandler) write(entry logEntry) {
	h.events.Record(history.Logs, history.Scope{}, time.UnixMilli(entry.TimeMS), entry, nil)
	h.sink.write(entry)
}

// logRepeats limits how often one kind of log line is kept. Lines are the
// same kind when they differ only in names, addresses and numbers, such as
// the same dial error for different hosts.
type logRepeats struct {
	mu        sync.Mutex
	kinds     map[string]*logRepeat
	nextSweep int64
}

type logRepeat struct {
	startMS    int64
	seen       int
	suppressed int
	last       logEntry
}

func newLogRepeats() *logRepeats {
	return &logRepeats{kinds: make(map[string]*logRepeat)}
}

// admit reports whether entry should be written, and returns summaries for
// windows that ended with suppressed lines. Only warnings and errors are
// limited.
func (r *logRepeats) admit(entry logEntry, limited bool) (bool, []logEntry) {
	if r == nil {
		return true, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := entry.TimeMS
	window := logRepeatWindow.Milliseconds()
	var summaries []logEntry
	if now >= r.nextSweep {
		r.nextSweep = now + time.Second.Milliseconds()
		for key, kind := range r.kinds {
			if now-kind.startMS < window {
				continue
			}
			if kind.suppressed > 0 {
				summaries = append(summaries, kind.summary(now))
			}
			delete(r.kinds, key)
		}
	}
	if !limited {
		return true, summaries
	}
	key := entry.Level + "\x00" + entry.Component + "\x00" + logKind(entry.Message)
	kind := r.kinds[key]
	if kind == nil {
		if len(r.kinds) < logRepeatKinds {
			r.kinds[key] = &logRepeat{startMS: now, seen: 1}
		}
		return true, summaries
	}
	kind.seen++
	if kind.seen <= logRepeatBurst {
		return true, summaries
	}
	kind.suppressed++
	kind.last = entry
	return false, summaries
}

func (k *logRepeat) summary(now int64) logEntry {
	fields := map[string]string{
		"count":  fmt.Sprint(k.suppressed),
		"window": logRepeatWindow.String(),
		"last":   history.Text(k.last.Message, logFieldValue),
	}
	return logEntry{
		TimeMS: now, Level: k.last.Level, Component: k.last.Component,
		Message: "Similar log lines suppressed", Fields: fields,
	}
}

// logKind replaces each word that holds a digit or a dot, such as a host,
// address, port or count, so lines that differ only in those match.
func logKind(message string) string {
	words := strings.Fields(message)
	for i, word := range words {
		if strings.ContainsAny(word, "0123456789.") {
			words[i] = "*"
		}
	}
	return strings.Join(words, " ")
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
