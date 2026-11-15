package dns

import (
	"encoding/json"
	"errors"
	"github.com/MimoProxy/reka/internal/secret"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type savedMapping struct {
	IP         netip.Addr `json:"ip"`
	Domain     string     `json:"domain"`
	Generation uint64     `json:"generation"`
	Expires    time.Time  `json:"expires"`
}
type savedPool struct {
	Version  int            `json:"version"`
	Mappings []savedMapping `json:"mappings"`
	Ranges   []netip.Prefix `json:"ranges"`
}

func (p *FakePool) UseFile(path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path != "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(b) > 32<<20 {
		return errors.New("fake-IP state too large")
	}
	if len(b) > 0 {
		var saved savedPool
		if err = json.Unmarshal(b, &saved); err != nil || saved.Version != 1 {
			return errors.New("corrupt fake-IP state")
		}
		if len(saved.Mappings) > p.limit || len(saved.Ranges) > 1024 {
			return errors.New("fake-IP state exceeds limits")
		}
		for _, r := range saved.Ranges {
			if !r.IsValid() {
				return errors.New("invalid fake-IP range")
			}
			p.ranges[r] = true
		}
		for _, m := range saved.Mappings {
			if !m.IP.IsValid() || m.Domain == "" {
				return errors.New("invalid fake-IP mapping")
			}
			if time.Now().Before(m.Expires) {
				p.entries[m.IP] = &mapping{m.Domain, m.Generation, m.Expires, 0}
			}
		}
	}
	p.path = path
	return nil
}
func (p *FakePool) save() error {
	if p.path == "" {
		return nil
	}
	saved := savedPool{Version: 1}
	for ip, m := range p.entries {
		saved.Mappings = append(saved.Mappings, savedMapping{ip, m.domain, m.generation, m.expires})
	}
	for r := range p.ranges {
		saved.Ranges = append(saved.Ranges, r)
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(p.path, data, 0600)
}
