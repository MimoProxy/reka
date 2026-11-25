package generation

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/secret"
)

const (
	// Reka bounds key memory and coalesces frequent writes into one disk flush.
	scriptStoreKeyMax     = 1 << 10
	scriptStoreFlushDelay = time.Second
)

type scriptStore struct {
	mu     sync.Mutex
	path   string
	log    *slog.Logger
	values map[string]string
	bytes  int
	dirty  bool
	closed bool
	timer  *time.Timer
}

var _ script.Store = (*scriptStore)(nil)

func newScriptStore(root string, logger *slog.Logger) *scriptStore {
	if logger == nil {
		logger = slog.Default()
	}
	s := &scriptStore{log: logger, values: make(map[string]string)}
	if root != "" {
		s.path = filepath.Join(root, "scripts", "store.json")
		if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Warn("load script store", "err", err)
		}
	}
	return s
}

func (s *scriptStore) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	// A JSON escape takes at most six bytes per input byte. Allow another
	// six bytes of syntax per entry, including an empty key if present.
	limit := int64(12*scriptStoreTotalMax + len(`{"":""}`) + 1)
	r := &io.LimitedReader{R: f, N: limit}
	decoder := json.NewDecoder(r)
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errors.New("invalid script store JSON")
	}
	values := make(map[string]string)
	size := 0
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || len(key) > scriptStoreKeyMax {
			return errors.New("invalid script store key")
		}
		if _, duplicate := values[key]; duplicate {
			return errors.New("duplicate script store key")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		size += len(key) + len(value)
		if len(value) > scriptStoreValueMax || size > scriptStoreTotalMax {
			return errors.New("script store size limit exceeded")
		}
		values[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF || r.N == 0 {
		return errors.New("invalid script store JSON")
	}
	s.values, s.bytes = values, size
	return nil
}

func (s *scriptStore) Read(key string) (string, bool, error) {
	if err := validateScriptStoreKey(key); err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *scriptStore) Write(key, value string) error {
	if err := validateScriptStoreKey(key); err != nil {
		return err
	}
	if len(value) > scriptStoreValueMax || !utf8.ValidString(value) {
		return errors.New("invalid script store value or size limit exceeded")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("script store closed")
	}
	old, ok := s.values[key]
	size := s.bytes + len(value) - len(old)
	if !ok {
		size += len(key)
	}
	if size > scriptStoreTotalMax {
		return errors.New("script store total size limit exceeded")
	}
	s.values[key], s.bytes = value, size
	s.scheduleFlush()
	return nil
}

func (s *scriptStore) Delete(key string) error {
	if err := validateScriptStoreKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("script store closed")
	}
	if value, ok := s.values[key]; ok {
		delete(s.values, key)
		s.bytes -= len(key) + len(value)
		s.scheduleFlush()
	}
	return nil
}

func validateScriptStoreKey(key string) error {
	if len(key) > scriptStoreKeyMax || !utf8.ValidString(key) {
		return errors.New("invalid script store key or size limit exceeded")
	}
	return nil
}

// scheduleFlush is called with s.mu held. A fixed window also flushes when
// writes continue indefinitely.
func (s *scriptStore) scheduleFlush() {
	if s.path == "" {
		return
	}
	s.dirty = true
	if s.timer == nil {
		s.timer = time.AfterFunc(scriptStoreFlushDelay, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.timer = nil
			if !s.closed {
				s.flush()
			}
		})
	}
}

func (s *scriptStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.flush()
}

// flush holds s.mu so an older snapshot cannot replace a newer write on disk.
func (s *scriptStore) flush() {
	if !s.dirty {
		return
	}
	if err := s.persist(); err != nil {
		s.log.Warn("save script store", "err", err)
		return
	}
	s.dirty = false
}

func (s *scriptStore) persist() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s.values)
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(s.path, data, 0o600)
}
