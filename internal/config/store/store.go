// Package store keeps configuration revisions on disk under a state root:
//
//	active.json                the confirmed active revision
//	revisions/<n>/             immutable profile.yaml, local.yaml, meta.json
//	operations/<id>.json       commit intent, target revision and outcome
//
// Every write goes to a temporary name, is synced, renamed into place and
// the directory is synced, so a crash leaves either the old or the new
// file, never a torn one.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/MimoProxy/reka/internal/secret"
)

// Revision is the metadata of one stored revision.
type Revision struct {
	Number    uint64    `json:"revision"`
	Base      uint64    `json:"base"`
	Operation string    `json:"operation,omitempty"`
	Source    string    `json:"source"`
	Message   string    `json:"message,omitempty"`
	Created   time.Time `json:"created"`
	Profile   string    `json:"profile_sha256"`
	Local     string    `json:"local_sha256"`
	// RestoredFrom is set when this revision restores an older one.
	RestoredFrom uint64 `json:"restored_from,omitempty"`
}

// Active is the content of active.json.
type Active struct {
	Revision  uint64    `json:"revision"`
	Profile   string    `json:"profile_sha256"`
	Local     string    `json:"local_sha256"`
	Operation string    `json:"operation,omitempty"`
	Updated   time.Time `json:"updated"`
}

// Operation states.
const (
	OpPending   = "pending"
	OpCommitted = "committed"
	OpRejected  = "rejected"
	OpFailed    = "failed"
)

// Operation is the durable record of one commit request.
type Operation struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	RequestHash string          `json:"request_hash"`
	Base        uint64          `json:"base"`
	Revision    uint64          `json:"revision,omitempty"`
	Created     time.Time       `json:"created"`
	Updated     time.Time       `json:"updated"`
	Result      json.RawMessage `json:"result,omitempty"`
}

// Store is a state root. It is not safe for concurrent writers; the
// config service serializes commits.
type Store struct {
	root string
}

// Open creates the layout under root if needed.
func Open(root string) (*Store, error) {
	for _, d := range []string{root, filepath.Join(root, "revisions"), filepath.Join(root, "operations")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

// Root is the state root directory.
func (s *Store) Root() string { return s.root }

// Hash is the content hash recorded for documents.
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *Store) revDir(n uint64) string {
	return filepath.Join(s.root, "revisions", fmt.Sprintf("%010d", n))
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteRevision stores an immutable revision. rev.Profile and rev.Local are
// filled in from the content.
func (s *Store) WriteRevision(rev Revision, profile, local []byte) (Revision, error) {
	rev.Profile, rev.Local = Hash(profile), Hash(local)
	final := s.revDir(rev.Number)
	if _, err := os.Stat(final); err == nil {
		return rev, fmt.Errorf("store: revision %d already exists", rev.Number)
	}
	tmp, err := os.MkdirTemp(filepath.Join(s.root, "revisions"), ".tmp-")
	if err != nil {
		return rev, err
	}
	defer os.RemoveAll(tmp)
	meta, _ := json.MarshalIndent(rev, "", "  ")
	for name, data := range map[string][]byte{"profile.yaml": profile, "local.yaml": local, "meta.json": append(meta, '\n')} {
		if err := writeSynced(filepath.Join(tmp, name), data); err != nil {
			return rev, err
		}
	}
	if err := secret.SyncDir(tmp); err != nil {
		return rev, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return rev, err
	}
	return rev, secret.SyncDir(filepath.Join(s.root, "revisions"))
}

// ReadRevision loads a revision and checks its content hashes.
func (s *Store) ReadRevision(n uint64) (Revision, []byte, []byte, error) {
	dir := s.revDir(n)
	var rev Revision
	if err := readJSON(filepath.Join(dir, "meta.json"), &rev); err != nil {
		return rev, nil, nil, err
	}
	profile, err := os.ReadFile(filepath.Join(dir, "profile.yaml"))
	if err != nil {
		return rev, nil, nil, err
	}
	local, err := os.ReadFile(filepath.Join(dir, "local.yaml"))
	if err != nil {
		return rev, nil, nil, err
	}
	if Hash(profile) != rev.Profile || Hash(local) != rev.Local {
		return rev, nil, nil, fmt.Errorf("store: revision %d content does not match its hashes", n)
	}
	return rev, profile, local, nil
}

// DeleteRevision removes a revision that never became active.
func (s *Store) DeleteRevision(n uint64) error {
	if err := os.RemoveAll(s.revDir(n)); err != nil {
		return err
	}
	return secret.SyncDir(filepath.Join(s.root, "revisions"))
}

// RevisionNumbers lists stored revisions in ascending order.
func (s *Store) RevisionNumbers() ([]uint64, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "revisions"))
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range entries {
		if n, err := strconv.ParseUint(e.Name(), 10, 64); err == nil && e.IsDir() {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ListRevisions returns the metadata of every stored revision, newest
// first.
func (s *Store) ListRevisions() ([]Revision, error) {
	ns, err := s.RevisionNumbers()
	if err != nil {
		return nil, err
	}
	out := make([]Revision, 0, len(ns))
	for i := len(ns) - 1; i >= 0; i-- {
		var rev Revision
		if err := readJSON(filepath.Join(s.revDir(ns[i]), "meta.json"), &rev); err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, nil
}

// ReadActive returns the active record, or nil if none was written yet.
func (s *Store) ReadActive() (*Active, error) {
	var a Active
	err := readJSON(filepath.Join(s.root, "active.json"), &a)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// WriteActive records the confirmed active revision.
func (s *Store) WriteActive(a Active) error {
	return writeJSON(filepath.Join(s.root, "active.json"), a)
}

var opIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidOperationID checks an operation ID.
func ValidOperationID(id string) error {
	if !opIDRE.MatchString(id) || id == "." || id == ".." {
		return fmt.Errorf("invalid operation id %q (1-128 letters, digits, '.', '_', '-')", id)
	}
	return nil
}

func (s *Store) opPath(id string) string { return filepath.Join(s.root, "operations", id+".json") }

// WriteOperation creates or replaces an operation record.
func (s *Store) WriteOperation(op Operation) error {
	if err := ValidOperationID(op.ID); err != nil {
		return err
	}
	return writeJSON(s.opPath(op.ID), op)
}

// ReadOperation loads an operation; ok is false if it does not exist.
func (s *Store) ReadOperation(id string) (Operation, bool, error) {
	var op Operation
	if err := ValidOperationID(id); err != nil {
		return op, false, err
	}
	err := readJSON(s.opPath(id), &op)
	if errors.Is(err, os.ErrNotExist) {
		return op, false, nil
	}
	return op, err == nil, err
}

// ListOperations returns every operation record.
func (s *Store) ListOperations() ([]Operation, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "operations"))
	if err != nil {
		return nil, err
	}
	var out []Operation
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".json" || name[0] == '.' {
			continue
		}
		var op Operation
		if err := readJSON(filepath.Join(s.root, "operations", name), &op); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, nil
}
