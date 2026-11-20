// Package history keeps local diagnostic records in three bounded, independent
// buffers. A record owns serialized values only, never connections or DNS messages.
package history

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRows    = 2000
	totalBytes = 8 << 20
	maxPage    = 100
	rowBytes   = 12 << 10
)

type Kind string

const (
	Connections Kind = "connections"
	DNS         Kind = "dns"
	Requests    Kind = "requests"
)

var ErrCursor = errors.New("invalid history cursor")

type Scope struct {
	ProfileID  string `json:"profile_id,omitempty"`
	Generation uint64 `json:"generation"`
	Revision   uint64 `json:"revision"`
}

type ListOptions struct {
	Before string `json:"before,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Query  string `json:"query,omitempty"`
}

type Row struct {
	Cursor string          `json:"cursor"`
	Data   json.RawMessage `json:"data"`
}

type Page struct {
	Epoch   string `json:"epoch"`
	Rows    []Row  `json:"rows"`
	Next    string `json:"next,omitempty"`
	Expired bool   `json:"expired,omitempty"`
}

type entry struct {
	seq     uint64
	flow    uint64
	profile string
	search  string
	data    json.RawMessage
	detail  json.RawMessage
	size    int
}

type bucket struct {
	rows  [maxRows]entry
	first int
	count int
	bytes int
	seq   uint64
	floor uint64
}

func (b *bucket) at(i int) *entry { return &b.rows[(b.first+i)%len(b.rows)] }

type Store struct {
	mu      sync.Mutex
	epoch   string
	buckets map[Kind]*bucket
	cleared map[Kind]map[string]time.Time
}

func New() *Store {
	var epoch [8]byte
	_, _ = rand.Read(epoch[:])
	return &Store{epoch: hex.EncodeToString(epoch[:]), buckets: make(map[Kind]*bucket),
		cleared: make(map[Kind]map[string]time.Time)}
}

func (s *Store) Record(kind Kind, scope Scope, started time.Time, summary, detail any) {
	s.RecordFlow(kind, scope, started, 0, summary, detail)
}

// RecordFlow adds a summary and its exact connection ID to the bounded history.
func (s *Store) RecordFlow(kind Kind, scope Scope, started time.Time, flow uint64, summary, detail any) {
	if s == nil {
		return
	}
	data, err := json.Marshal(summary)
	if err != nil || len(data) > rowBytes {
		return
	}
	var private json.RawMessage
	if detail != nil {
		private, err = json.Marshal(detail)
		if err != nil || len(private) > 64<<10 {
			private = nil
		}
	}
	// Search the summary only. A detail can include authorized body previews.
	search := strings.ToLower(string(data))
	size := len(data) + len(private) + len(search) + len(scope.ProfileID) + 128
	s.mu.Lock()
	defer s.mu.Unlock()
	if started.Before(s.cleared[kind][scope.ProfileID]) {
		return
	}
	b := s.buckets[kind]
	if b == nil {
		b = &bucket{}
		s.buckets[kind] = b
	}
	for b.count == maxRows || b.bytes+size > totalBytes/3 {
		old := b.at(0)
		b.bytes -= old.size
		b.floor = old.seq
		*old = entry{}
		b.first = (b.first + 1) % len(b.rows)
		b.count--
	}
	b.seq++
	*b.at(b.count) = entry{seq: b.seq, flow: flow, profile: scope.ProfileID, search: search, data: data, detail: private, size: size}
	b.count++
	b.bytes += size
}

func (s *Store) Epoch() string { return s.epoch }

// FlowRows fetches summaries only, without exposing HTTP request details.
func (s *Store) FlowRows(profile string, flow uint64) (map[Kind][]Row, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make(map[Kind][]Row, 3)
	truncated := false
	for _, kind := range []Kind{Connections, DNS, Requests} {
		b := s.buckets[kind]
		if b == nil {
			continue
		}
		for i := b.count - 1; i >= 0; i-- {
			r := b.at(i)
			if flow == 0 || r.flow != flow || r.profile != profile {
				continue
			}
			if len(rows[kind]) == 50 {
				truncated = true
				break
			}
			rows[kind] = append(rows[kind], Row{Cursor: s.cursor(kind, r.seq), Data: r.data})
			if kind == Connections {
				break
			}
		}
	}
	return rows, truncated
}

func (s *Store) cursor(kind Kind, seq uint64) string {
	return s.epoch + "." + string(kind) + "." + strconv.FormatUint(seq, 10)
}

func (s *Store) parseCursor(kind Kind, cursor string) (uint64, error) {
	tail, ok := strings.CutPrefix(cursor, s.epoch+"."+string(kind)+".")
	if !ok {
		return 0, ErrCursor
	}
	seq, err := strconv.ParseUint(tail, 10, 64)
	if err != nil || seq == 0 {
		return 0, ErrCursor
	}
	return seq, nil
}

func (s *Store) List(kind Kind, profile string, opts ListOptions) (Page, error) {
	page := Page{Epoch: s.epoch, Rows: []Row{}}
	limit := opts.Limit
	if limit <= 0 || limit > maxPage {
		limit = maxPage
	}
	query := strings.ToLower(strings.TrimSpace(Text(opts.Query, 256)))
	var before uint64
	if opts.Before != "" {
		var err error
		before, err = s.parseCursor(kind, opts.Before)
		if err != nil {
			return page, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[kind]
	if b == nil {
		return page, nil
	}
	if before != 0 && before <= b.floor {
		page.Expired = true
		return page, nil
	}
	for i := b.count - 1; i >= 0; i-- {
		r := b.at(i)
		if r.profile != profile || before != 0 && r.seq >= before || !strings.Contains(r.search, query) {
			continue
		}
		if len(page.Rows) == limit {
			page.Next = page.Rows[len(page.Rows)-1].Cursor
			break
		}
		page.Rows = append(page.Rows, Row{Cursor: s.cursor(kind, r.seq), Data: r.data})
	}
	return page, nil
}

func (s *Store) Detail(kind Kind, profile, cursor string) (json.RawMessage, bool) {
	seq, err := s.parseCursor(kind, cursor)
	if err != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[kind]
	if b != nil {
		for i := b.count - 1; i >= 0; i-- {
			r := b.at(i)
			if r.seq == seq && r.profile == profile {
				return r.detail, len(r.detail) > 0
			}
		}
	}
	return nil, false
}

func (s *Store) Clear(kind Kind, profile string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleared[kind] == nil {
		s.cleared[kind] = make(map[string]time.Time)
	}
	s.cleared[kind][profile] = time.Now()
	b := s.buckets[kind]
	if b == nil {
		return 0
	}
	kept := 0
	for i := 0; i < b.count; i++ {
		r := b.at(i)
		if r.profile == profile {
			b.bytes -= r.size
			continue
		}
		*b.at(kept) = *r
		kept++
	}
	for i := kept; i < b.count; i++ {
		*b.at(i) = entry{}
	}
	n := b.count - kept
	b.count = kept
	return n
}

// Text limits untrusted labels before they can be retained in a history row.
func Text(s string, size int) string {
	if len(s) > size {
		s = strings.ToValidUTF8(s[:size], "")
	}
	return s
}
