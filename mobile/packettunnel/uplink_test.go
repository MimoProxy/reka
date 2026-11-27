//go:build with_gvisor

package packettunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func TestClassifyDial(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	cases := []struct {
		name string
		err  error
		want dialOutcome
	}{
		{"success", nil, dialReached},
		{"cancelled", fmt.Errorf("open connection: %w", context.Canceled), dialIgnored},
		{"dial timeout", fmt.Errorf("open connection: %w", timeout), dialFailed},
		{"no route", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, dialFailed},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, dialReached},
		{"lookup timeout", &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}, dialFailed},
		{"no such host", &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}, dialReached},
		{"proxy handshake", errors.New("vless: bad response"), dialIgnored},
		// One address answering proves the network works even if others timed out.
		{"mixed addresses", E.Errors(timeout, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}), dialReached},
		{"all addresses", E.Errors(timeout, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}), dialFailed},
	}
	for _, c := range cases {
		if got := classifyDial(c.err); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestUplinkMonitorStallsAndRecovers(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	type change struct {
		status     UplinkStatus
		stalledFor time.Duration
	}
	var changes []change
	m := newUplinkMonitor(func(status UplinkStatus, stalledFor time.Duration) {
		changes = append(changes, change{status, stalledFor})
	})
	m.now = func() time.Time { return now }
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}

	// Many failures in a short burst are not a stall yet.
	for range uplinkStallFailures * 2 {
		m.record(timeout)
	}
	if m.status().Stalled || len(changes) != 0 {
		t.Fatalf("stalled before the window passed: %+v", m.status())
	}
	// Ignored errors do not end the run of failures.
	now = now.Add(uplinkStallAfter)
	m.record(context.Canceled)
	m.record(timeout)
	status := m.status()
	if !status.Stalled || status.SinceMS != 1_000_000 || status.Failures != uplinkStallFailures*2+1 || len(changes) != 1 {
		t.Fatalf("status %+v, changes %+v", status, changes)
	}
	m.record(timeout)
	if len(changes) != 1 {
		t.Fatalf("a stall was reported twice: %+v", changes)
	}

	now = now.Add(5 * time.Second)
	m.record(nil)
	if m.status() != (UplinkStatus{}) || len(changes) != 2 || changes[1].status.Stalled || changes[1].stalledFor != 20*time.Second {
		t.Fatalf("status %+v, changes %+v", m.status(), changes)
	}
}

func TestUplinkMonitorNeedsFailuresAndResetsOnNetworkChange(t *testing.T) {
	now := time.UnixMilli(0)
	m := newUplinkMonitor(nil)
	m.now = func() time.Time { return now }
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}

	// A quiet device with a few slow dials spread out is not stalled.
	for range uplinkStallFailures - 1 {
		m.record(timeout)
		now = now.Add(uplinkStallAfter)
	}
	if m.status().Stalled {
		t.Fatal("stalled with too few failures")
	}
	m.record(timeout)
	if !m.status().Stalled {
		t.Fatal("not stalled")
	}
	m.reset()
	if m.status() != (UplinkStatus{}) {
		t.Fatalf("reset kept %+v", m.status())
	}
	var nilMonitor *uplinkMonitor
	nilMonitor.record(timeout)
	nilMonitor.reset()
	if nilMonitor.status() != (UplinkStatus{}) {
		t.Fatal("nil monitor reported a status")
	}
}
