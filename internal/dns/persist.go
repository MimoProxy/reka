package dns

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/secret"
)

const (
	// Match the sing-box cache_file interval for saving Fake IP metadata.
	fakeIPSaveInterval = 10 * time.Second
	maxFakeStateBytes  = 32 << 20
)

type fakeStateFile struct {
	path  string
	dirty bool
	timer *time.Timer

	// Serialize snapshots and file writes with the final flush.
	writeMu sync.Mutex
	warned  bool
}

type savedMapping struct {
	IP         netip.Addr `json:"ip"`
	Domain     string     `json:"domain"`
	Generation uint64     `json:"generation"`
	// Expires is for legacy v1 readers. The pool ignores it on restore.
	Expires time.Time `json:"expires"`
}
type savedPool struct {
	Version  int                         `json:"version"`
	Mappings []savedMapping              `json:"mappings"` // Least to most recently used.
	Ranges   []netip.Prefix              `json:"ranges"`
	Next     map[netip.Prefix]netip.Addr `json:"next,omitempty"`
}

func (p *FakePool) UseFile(path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errFakePoolClosed
	}
	if p.file.path != "" || path == "" {
		return nil
	}
	saved, err := readFakeIPState(path)
	if err != nil {
		return err
	}
	if len(saved.Mappings) > p.limit || len(saved.Ranges) > maxFakeRanges || len(saved.Next) > maxFakeRanges {
		return errors.New("fake-IP state exceeds limits")
	}

	ranges := maps.Clone(p.ranges)
	for _, r := range saved.Ranges {
		if !r.IsValid() {
			return errors.New("invalid fake-IP range")
		}
		ranges[r.Masked()] = true
	}
	for r, ip := range saved.Next {
		if !ranges[r] || !r.Contains(ip) || ip == r.Addr() {
			return errors.New("invalid fake-IP cursor")
		}
	}
	count := len(p.entries)
	for _, m := range saved.Mappings {
		if !m.IP.IsValid() || m.Domain == "" {
			return errors.New("invalid fake-IP mapping")
		}
		if p.entries[m.IP] == nil {
			count++
		}
	}
	if count > p.limit || len(ranges) > maxFakeRanges {
		return errors.New("fake-IP state exceeds limits")
	}

	// Preserve live mappings and their leases if the file is attached late.
	hadMappings := len(p.entries) != 0
	for i := len(saved.Mappings) - 1; i >= 0; i-- {
		item := saved.Mappings[i]
		if p.entries[item.IP] == nil {
			m := &mapping{ip: item.IP, key: mappingKey{domain: item.Domain, generation: item.Generation}}
			p.addMapping(m)
			p.lru.MoveToFront(m.lru)
		}
	}
	for r, ip := range saved.Next {
		if !p.next[r].IsValid() {
			p.next[r] = ip
		}
	}
	p.ranges = ranges
	p.file.path = path
	if hadMappings {
		p.markDirty()
	}
	return nil
}

func readFakeIPState(path string) (savedPool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return savedPool{}, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return savedPool{}, nil
	}
	if err != nil {
		return savedPool{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFakeStateBytes+1))
	if err != nil {
		return savedPool{}, err
	}
	if len(b) > maxFakeStateBytes {
		return savedPool{}, errors.New("fake-IP state too large")
	}
	var saved savedPool
	if len(b) > 0 && (json.Unmarshal(b, &saved) != nil || saved.Version != 1) {
		return savedPool{}, errors.New("corrupt fake-IP state")
	}
	return saved, nil
}

// markDirty is called with the pool locked. The first change starts a batch.
func (p *FakePool) markDirty() {
	if p.file.path == "" {
		return
	}
	p.file.dirty = true
	if p.file.timer == nil {
		p.file.timer = time.AfterFunc(fakeIPSaveInterval, func() { p.flush(false) })
	}
}

// Close stops allocations and flushes pending state synchronously.
func (p *FakePool) Close() { p.flush(true) }

func (p *FakePool) flush(closing bool) {
	p.file.writeMu.Lock()
	defer p.file.writeMu.Unlock()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if closing {
		p.closed = true
		if p.file.timer != nil {
			p.file.timer.Stop()
		}
	}
	p.file.timer = nil
	if !p.file.dirty {
		p.mu.Unlock()
		return
	}
	path := p.file.path
	saved := p.snapshot()
	p.file.dirty = false
	p.mu.Unlock()

	data, err := json.Marshal(saved)
	if err == nil {
		err = secret.WriteFileAtomic(path, data, 0600)
	}
	if err != nil {
		// The file is only for restart recovery. DNS must keep serving from memory.
		p.mu.Lock()
		p.file.dirty = true
		p.mu.Unlock()
		if !p.file.warned {
			p.file.warned = true
			slog.Warn("Could not save fake IP state", "err", err)
		}
	}
}

func (p *FakePool) snapshot() savedPool {
	saved := savedPool{
		Version:  1,
		Mappings: make([]savedMapping, 0, len(p.entries)),
		Ranges:   make([]netip.Prefix, 0, len(p.ranges)),
		Next:     maps.Clone(p.next),
	}
	// Keep the former minimum lease for readers that still honor Expires.
	legacyExpiry := time.Now().Add(time.Minute)
	for entry := p.lru.Front(); entry != nil; entry = entry.Next() {
		m := entry.Value.(*mapping)
		saved.Mappings = append(saved.Mappings, savedMapping{
			IP: m.ip, Domain: m.key.domain, Generation: m.key.generation, Expires: legacyExpiry,
		})
	}
	for r := range p.ranges {
		saved.Ranges = append(saved.Ranges, r)
	}
	return saved
}
