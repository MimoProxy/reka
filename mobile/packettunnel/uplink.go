//go:build with_gvisor

package packettunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// A network can stay "available" to the system while it passes no traffic,
// for example a Wi-Fi network whose router has lost its uplink. The tunnel
// then sees every outbound dial fail and nothing else. The monitor reports
// that state so the host can tell the user, instead of the tunnel silently
// filling its flow table with dials that cannot finish.
//
// Neither sing-box nor mihomo detects this. The window is three sing-box
// TCP connect timeouts (5s each), so a single slow or failing server never
// trips it, and the failure count keeps a quiet device from tripping it on
// one or two unlucky dials.
const (
	uplinkStallAfter    = 15 * time.Second
	uplinkStallFailures = 8
)

// UplinkStatus is the network health the tunnel infers from its dials.
type UplinkStatus struct {
	Stalled bool `json:"stalled"`
	// SinceMS is when the current run of failed dials began. Zero when no
	// dial has failed since the last one that reached a server.
	SinceMS  int64 `json:"sinceMs,omitempty"`
	Failures int   `json:"failures,omitempty"`
}

type dialOutcome int

const (
	dialIgnored dialOutcome = iota
	dialReached
	dialFailed
)

// classifyDial separates failures that say nothing left the device from
// failures that prove a server answered. A refused or reset connection, a
// DNS answer that the name does not exist, or a proxy handshake error all
// mean the network works.
func classifyDial(err error) dialOutcome {
	if err == nil {
		return dialReached
	}
	if errors.Is(err, context.Canceled) {
		return dialIgnored
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return dialReached
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return dialReached
		case dnsErr.IsTimeout:
			return dialFailed
		}
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN) {
		return dialFailed
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return dialFailed
	}
	return dialIgnored
}

type uplinkMonitor struct {
	mu           sync.Mutex
	now          func() time.Time
	onChange     func(UplinkStatus, time.Duration)
	failures     int
	firstFailure time.Time
	stalled      bool
}

func newUplinkMonitor(onChange func(UplinkStatus, time.Duration)) *uplinkMonitor {
	return &uplinkMonitor{now: time.Now, onChange: onChange}
}

func (m *uplinkMonitor) record(err error) {
	if m == nil {
		return
	}
	outcome := classifyDial(err)
	if outcome == dialIgnored {
		return
	}
	m.mu.Lock()
	now := m.now()
	var changed bool
	var stalledFor time.Duration
	if outcome == dialReached {
		if m.stalled {
			changed, stalledFor = true, now.Sub(m.firstFailure)
		}
		m.failures, m.firstFailure, m.stalled = 0, time.Time{}, false
	} else {
		if m.failures == 0 {
			m.firstFailure = now
		}
		m.failures++
		if !m.stalled && m.failures >= uplinkStallFailures && now.Sub(m.firstFailure) >= uplinkStallAfter {
			m.stalled, changed = true, true
		}
	}
	status := m.statusLocked()
	m.mu.Unlock()
	if changed && m.onChange != nil {
		m.onChange(status, stalledFor)
	}
}

// reset forgets earlier failures after the system reports a different
// network, whose dials have not been tried yet.
func (m *uplinkMonitor) reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.failures, m.firstFailure, m.stalled = 0, time.Time{}, false
	m.mu.Unlock()
}

func (m *uplinkMonitor) status() UplinkStatus {
	if m == nil {
		return UplinkStatus{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *uplinkMonitor) statusLocked() UplinkStatus {
	status := UplinkStatus{Stalled: m.stalled, Failures: m.failures}
	if m.failures > 0 {
		status.SinceMS = m.firstFailure.UnixMilli()
	}
	return status
}

// Uplink reports whether outbound dials have all been failing.
func (s *Session) Uplink() UplinkStatus { return s.uplink.status() }

func (s *Session) uplinkChanged(status UplinkStatus, stalledFor time.Duration) {
	if status.Stalled {
		s.logger.Warn("Network stalled: outbound connections are failing", "failures", status.Failures,
			"since", time.UnixMilli(status.SinceMS))
		return
	}
	s.logger.Info("Network stall cleared", "stalledFor", stalledFor)
}
