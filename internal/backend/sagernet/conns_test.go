package sagernet

import (
	"testing"
	"time"
)

func TestUDPConnectionCloseObservesInFlightCountersOnce(t *testing.T) {
	closed := make(chan ConnInfo, 2)
	backend := New(Options{OnConnectionClosed: func(conn ConnInfo) { closed <- conn }})
	defer backend.Close()
	flow := &udpFlow{
		s: &udpSession{b: backend}, cancel: func() {},
		ready: make(chan struct{}), receiveDone: make(chan struct{}),
		attempt: backend.beginConnection(Metadata{Network: "udp"}),
	}
	flow.untrack = backend.conns.add(&tracked{
		id: flow.attempt.ID, out: &Outbound{tag: "direct"}, up: &flow.up, down: &flow.down,
	})
	flow.up.Store(4)
	flow.down.Store(4)
	flow.sendMu.Lock()
	flow.close()
	active := backend.Connections()
	// The in-flight receive and send complete after close starts.
	flow.down.Add(7)
	close(flow.receiveDone)
	flow.up.Add(3)
	flow.sendMu.Unlock()
	if len(active) != 1 || active[0].Upload != 4 || active[0].Download != 4 {
		t.Fatalf("in-flight connection missing from active snapshot: %+v", active)
	}
	select {
	case conn := <-closed:
		if conn.ID != flow.attempt.ID || conn.Upload != 7 || conn.Download != 11 {
			t.Fatalf("incomplete close counters: %+v", conn)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not reach the observer")
	}
	if backend.ConnectionCount() != 0 {
		t.Fatal("completed connection remained active")
	}
	flow.close()
	select {
	case <-closed:
		t.Fatal("close was reported more than once")
	default:
	}
}
