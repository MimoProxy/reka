//go:build with_gvisor

package packettunnel

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/mobile/profile"
)

func TestTunnelLogKeepsFieldsAndOutlivesSession(t *testing.T) {
	const raw = `
schema-version: 1
rules:
  - {match: {all: true}, outbound: reject}
`
	path := filepath.Join(t.TempDir(), "core.jsonl")
	controls := profile.Controls{Mode: "rule", ProfileID: "p1", LogFile: path}
	session, err := StartProfile(prepareSnapshot(t, raw), controls, false)
	if err != nil {
		t.Fatal(err)
	}
	session.logger.With("component", "test").Warn("dial failed", "outbound", "hk", "err", errors.New("timeout"))
	slog.Error("engine failure", "err", errors.New("broken"))

	value, err := session.RunOperation(Operation{Action: "logs"})
	if err != nil {
		t.Fatal(err)
	}
	var dial *logEntry
	for _, row := range value.(history.Page).Rows {
		var entry logEntry
		if json.Unmarshal(row.Data, &entry) == nil && entry.Message == "dial failed" {
			dial = &entry
		}
	}
	if dial == nil || dial.Component != "test" || dial.Fields["outbound"] != "hk" || dial.Fields["err"] != "timeout" {
		t.Fatalf("log fields were dropped: %+v", dial)
	}
	session.Close()
	slog.Error("after close")

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var messages []string
	var started, stopped logEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry logEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("invalid log line %q: %v", scanner.Text(), err)
		}
		messages = append(messages, entry.Message)
		switch entry.Message {
		case "Packet tunnel started":
			started = entry
		case "Packet tunnel stopping":
			stopped = entry
		}
	}
	joined := strings.Join(messages, "|")
	if !strings.Contains(joined, "dial failed") || !strings.Contains(joined, "engine failure") || strings.Contains(joined, "after close") {
		t.Fatalf("unexpected log file messages: %v", messages)
	}
	if started.Fields["profile"] != "p1" || started.Fields["mode"] != "rule" || stopped.Fields["uptime"] == "" {
		t.Fatalf("lifecycle lines lack fields: %+v %+v", started, stopped)
	}
}

func TestTunnelLogFileRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.jsonl")
	var sink logFile
	if err := sink.open(path); err != nil {
		t.Fatal(err)
	}
	defer sink.close()
	entry := logEntry{Level: "info", Message: strings.Repeat("x", logMessageBytes)}
	for range logFileBytes / logMessageBytes * 2 {
		sink.write(entry)
	}
	current, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if current.Size() > logFileBytes || rotated.Size() > logFileBytes {
		t.Fatalf("log files exceed the limit: %d, %d", current.Size(), rotated.Size())
	}
}
