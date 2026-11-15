package platform

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sync"
)

// NetworkStatus is the state of system takeover. State is Stopped, Running
// or Degraded; Degraded means some OS setting could not be restored and
// takeover stays off until it is explicitly switched off.
type NetworkStatus struct {
	Mode   string `json:"mode"`
	State  string `json:"state"`
	Device string `json:"device,omitempty"`
	IPv6   bool   `json:"ipv6"`
	Error  string `json:"error,omitempty"`
}

// NetworkHooks are the platform operations Takeover drives.
type NetworkHooks struct {
	StartTUN func(TUNConfig) (io.Closer, string, error)
	Bypass   func(bool, TUNConfig) error
	Settings Settings
	// SettingsFor computes only the settings applicable to the chosen mode.
	SettingsFor func(Network, string) (map[string]string, error)
}

// Takeover applies the local network intent (off, system proxy or TUN) and
// undoes it. Every OS setting it changes goes through a Journal.
type Takeover struct {
	mu      sync.Mutex
	hooks   NetworkHooks
	journal *Journal
	config  Network
	proxy   string
	tun     io.Closer
	status  NetworkStatus
}

// NewTakeover restores whatever a previous run left behind, then starts in
// the off state. If that restore fails the takeover starts Degraded.
func NewTakeover(root string, h NetworkHooks) (*Takeover, error) {
	t := &Takeover{hooks: h, config: Network{Mode: "off"}, status: NetworkStatus{Mode: "off", State: "Stopped"}}
	if h.Settings != nil {
		t.journal = &Journal{Path: filepath.Join(root, "network", "ownership.json"), OS: h.Settings}
		if err := t.journal.Recover(); err != nil {
			t.status.State = "Degraded"
			t.status.Error = err.Error()
			return t, err
		}
	}
	return t, nil
}

// Status reports the current state.
func (t *Takeover) Status() NetworkStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// Check marks the takeover Degraded if someone else changed an owned
// setting.
func (t *Takeover) Check() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.journal == nil {
		return nil
	}
	err := t.journal.Check()
	if err != nil {
		t.status.State = "Degraded"
		t.status.Error = err.Error()
	}
	return err
}

// Apply switches to configuration c. An unchanged configuration only
// re-checks ownership. Otherwise the current takeover is undone and the new
// one started; if starting fails, the previous one is put back, and if that
// fails too the takeover is Degraded.
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
			if err := t.journal.Check(); err != nil {
				t.status.State = "Degraded"
				t.status.Error = err.Error()
				return err
			}
		}
		return nil
	}
	old, oldProxy := t.config, t.proxy
	if err := t.stop(); err != nil {
		t.degraded(err)
		return err
	}
	if err := t.start(c, proxy); err != nil {
		cleanup := t.stop()
		back := t.start(old, oldProxy)
		combined := errors.Join(err, cleanup, back)
		if cleanup != nil || back != nil {
			t.degraded(combined)
		}
		return combined
	}
	return nil
}
func (t *Takeover) degraded(err error) {
	t.status.State = "Degraded"
	t.status.Error = err.Error()
}

// start brings up the TUN device (with own-traffic bypass) and then the OS
// settings the mode needs.
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
			if err := t.hooks.Bypass(true, c.TUN); err != nil {
				return err
			}
		}
		d, name, err := t.hooks.StartTUN(c.TUN)
		if err != nil {
			return err
		}
		t.tun = d
		t.status.Device = name
		t.status.IPv6 = c.TUN.Address6 != ""
	}
	if t.hooks.SettingsFor != nil {
		desired, err := t.hooks.SettingsFor(c, proxy)
		if err != nil {
			return err
		}
		if len(desired) > 0 && t.journal == nil {
			return errors.New("OS settings unavailable")
		}
		// Sorted keys make crash/failure points deterministic.
		for _, k := range settingKeys(desired) {
			if err = t.journal.Apply(k, desired[k]); err != nil {
				return err
			}
		}
	}
	t.status.State = "Running"
	return nil
}

// stop undoes start: OS settings first, then the device and the bypass.
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

// Close undoes the takeover at shutdown.
func (t *Takeover) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	err := t.stop()
	if err != nil {
		t.degraded(err)
	}
	return err
}

// Rebuild is an explicit host descriptor replacement, not a config mutation.
func (t *Takeover) Rebuild() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, p := t.config, t.proxy
	if c.Mode != "tun" {
		return errors.New("TUN is not active")
	}
	if err := t.stop(); err != nil {
		t.degraded(err)
		return err
	}
	if err := t.start(c, p); err != nil {
		t.degraded(err)
		return err
	}
	return nil
}
