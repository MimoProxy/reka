package sagernet

import (
	"context"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestUDPSessionReaperClosesIdleFlows(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	backend := &Backend{udpTimeout: 80 * time.Millisecond}
	session := &udpSession{b: backend, ctx: ctx, cancel: cancel, flows: make(map[M.Socksaddr]*udpFlow)}
	newFlow := func(address string) *udpFlow {
		flowCtx, flowCancel := context.WithCancel(ctx)
		f := &udpFlow{
			s: session, ctx: flowCtx, cancel: flowCancel, dest: M.ParseSocksaddr(address),
			ready: make(chan struct{}), processTraffic: &processTrafficCounter{},
			attempt: backend.beginConnection(ctx, Metadata{Network: N.NetworkUDP}),
		}
		session.flows[f.dest] = f
		return f
	}
	idle, active := newFlow("192.0.2.1:53"), newFlow("192.0.2.2:53")
	idle.last.Store(time.Now().Add(-time.Hour).UnixNano())
	active.touch()

	session.startReaper()
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				active.touch()
			}
		}
	}()
	defer close(stop)

	deadline := time.Now().Add(2 * time.Second)
	for {
		session.mu.Lock()
		_, idleOpen := session.flows[idle.dest]
		_, activeOpen := session.flows[active.dest]
		session.mu.Unlock()
		if !activeOpen {
			t.Fatal("reaper closed an active flow")
		}
		if !idleOpen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reaper did not close the idle flow")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The close reason is recorded once the flow has finished closing.
	for {
		idle.attempt.mu.Lock()
		reason := idle.attempt.CloseReason
		idle.attempt.mu.Unlock()
		if reason == "idle_timeout" {
			break
		}
		if reason != "" || time.Now().After(deadline) {
			t.Fatalf("idle flow close reason = %q", reason)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	time.Sleep(20 * time.Millisecond)
	session.mu.Lock()
	stopped := !session.reaper.Stop()
	session.mu.Unlock()
	if !stopped {
		t.Fatal("reaper timer still armed after the session ended")
	}
}
