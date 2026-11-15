package platform

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sync"
)

type NetworkStatus struct {
	Mode   string `json:"mode"`
	State  string `json:"state"`
	Device string `json:"device,omitempty"`
	IPv6   bool   `json:"ipv6"`
	Error  string `json:"error,omitempty"`
}
type NetworkHooks struct {
	StartTUN func(TUNConfig) (io.Closer, string, error)
	Bypass   func(bool, TUNConfig) error
	Settings Settings
	// SettingsFor computes only the settings applicable to the chosen mode.
	SettingsFor func(Network, string) (map[string]string, error)
}
type Takeover struct {
	mu      sync.Mutex
	hooks   NetworkHooks
	journal *Journal
	config  Network
	proxy   string
	tun     io.Closer
	status  NetworkStatus
}

func NewTakeover(root string, h NetworkHooks) (*Takeover, error) {
	t := &Takeover{hooks: h, config: Network{Mode: "off"}, status: NetworkStatus{Mode: "off", State: "Stopped"}}
	if h.Settings != nil {
		t.journal = &Journal{Path: filepath.Join(root, "network", "ownership.json"), OS: h.Settings}
		if e := t.journal.Recover(); e != nil {
			t.status.State = "Degraded"
			t.status.Error = e.Error()
			return t, e
		}
	}
	return t, nil
}
func (t *Takeover) Status() NetworkStatus { t.mu.Lock(); defer t.mu.Unlock(); return t.status }
func (t *Takeover) Check() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.journal == nil {
		return nil
	}
	e := t.journal.Check()
	if e != nil {
		t.status.State = "Degraded"
		t.status.Error = e.Error()
	}
	return e
}
func (t *Takeover) Apply(c Network, proxy string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if reflect.DeepEqual(t.config, c) && t.proxy == proxy {
		if t.status.State == "Degraded" && c.Mode == "off" {
			return t.stop()
		}
		if t.status.State == "Degraded" {
			return fmt.Errorf("network is degraded: %s; explicitly switch off before retrying takeover", t.status.Error)
		}
		if c.Mode != "off" && t.status.State != "Running" {
			return fmt.Errorf("takeover is not running; explicitly switch off before retrying")
		}
		if t.journal != nil {
			if e := t.journal.Check(); e != nil {
				t.status.State = "Degraded"
				t.status.Error = e.Error()
				return e
			}
		}
		return nil
	}
	old, oldProxy := t.config, t.proxy
	if e := t.stop(); e != nil {
		t.degraded(e)
		return e
	}
	if e := t.start(c, proxy); e != nil {
		cleanup := t.stop()
		back := t.start(old, oldProxy)
		combined := errors.Join(e, cleanup, back)
		if cleanup != nil || back != nil {
			t.degraded(combined)
		}
		return combined
	}
	return nil
}
func (t *Takeover) degraded(e error) { t.status.State = "Degraded"; t.status.Error = e.Error() }
func (t *Takeover) start(c Network, proxy string) error {
	t.config = c
	t.proxy = proxy
	t.status = NetworkStatus{Mode: c.Mode, State: "Stopped"}
	if c.Mode == "off" || c.Mode == "" {
		return nil
	}
	if c.Mode == "tun" {
		if t.hooks.StartTUN == nil {
			return fmt.Errorf("TUN is unavailable")
		}
		if t.hooks.Bypass != nil {
			if e := t.hooks.Bypass(true, c.TUN); e != nil {
				return e
			}
		}
		d, name, e := t.hooks.StartTUN(c.TUN)
		if e != nil {
			return e
		}
		t.tun = d
		t.status.Device = name
		t.status.IPv6 = c.TUN.Address6 != ""
	}
	if t.hooks.SettingsFor != nil {
		desired, e := t.hooks.SettingsFor(c, proxy)
		if e != nil {
			return e
		}
		if len(desired) > 0 && t.journal == nil {
			return errors.New("OS settings unavailable")
		}
		// Sorted keys make crash/failure points deterministic.
		for _, k := range settingKeys(desired) {
			if e = t.journal.Apply(k, desired[k]); e != nil {
				return e
			}
		}
	}
	t.status.State = "Running"
	return nil
}
func (t *Takeover) stop() error {
	var errs []error
	// Restore DNS/proxy before removing the device. Failed restores stay in
	// the journal and block future takeover rather than being overwritten.
	if t.journal != nil {
		errs = append(errs, t.journal.Restore())
	}
	if t.tun != nil {
		errs = append(errs, t.tun.Close())
		t.tun = nil
	}
	if t.hooks.Bypass != nil {
		errs = append(errs, t.hooks.Bypass(false, TUNConfig{}))
	}
	t.config = Network{Mode: "off"}
	t.proxy = ""
	t.status = NetworkStatus{Mode: "off", State: "Stopped"}
	return errors.Join(errs...)
}
func (t *Takeover) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.stop()
	if e != nil {
		t.degraded(e)
	}
	return e
}

// Rebuild is an explicit host descriptor replacement, not a config mutation.
func (t *Takeover) Rebuild() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, p := t.config, t.proxy
	if c.Mode != "tun" {
		return errors.New("TUN is not active")
	}
	if e := t.stop(); e != nil {
		t.degraded(e)
		return e
	}
	if e := t.start(c, p); e != nil {
		t.degraded(e)
		return e
	}
	return nil
}
