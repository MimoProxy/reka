package sagernet

import (
	"testing"
	"time"
)

func TestConnectionSnapshotStateTracksDial(t *testing.T) {
	backend := &Backend{}
	md := Metadata{Network: "udp", Protocol: "quic"}
	attempt := backend.beginConnection(t.Context(), md)
	out := &Outbound{tag: "direct"}
	untrack := backend.conns.add(&tracked{attempt: attempt, id: attempt.ID, md: md, out: out})
	defer untrack()
	checkState := func(want string) {
		t.Helper()
		active := backend.Connections()
		if len(active) != 1 || active[0].State != want || active[0].Metadata.Protocol != "quic" {
			t.Fatalf("expected a QUIC connection in state %q, got %+v", want, active)
		}
	}
	checkState("connecting")
	now := time.Now()
	attempt.dialed(now, now, nil, socketDialResult{}, false)
	checkState("active")
	attempt.up.Add(11)
	attempt.down.Add(22)
	trace, ok := backend.ConnectionTrace(attempt.ID, "")
	if !ok || trace.PeakUpBPS != 11 || trace.PeakDownBPS != 22 || trace.Upload != 11 || trace.Download != 22 {
		t.Fatalf("invalid active trace counters: %+v", trace)
	}
	attempt.complete("eof", "")
	if active := backend.Connections(); len(active) != 0 {
		t.Fatalf("completed connection in active list: %+v", active)
	}
}

func TestUDPConnectionCloseObservesInFlightCountersOnce(t *testing.T) {
	closed := make(chan ConnInfo, 2)
	backend := New(Options{OnConnectionClosed: func(conn ConnInfo) { closed <- conn }})
	defer backend.Close()
	flow := &udpFlow{
		s: &udpSession{b: backend}, cancel: func() {},
		ready: make(chan struct{}), receiveDone: make(chan struct{}),
		attempt: backend.beginConnection(t.Context(), Metadata{Network: "udp"}),
	}
	flow.untrack = backend.conns.add(&tracked{
		attempt: flow.attempt, id: flow.attempt.ID, out: &Outbound{tag: "direct"},
	})
	flow.attempt.up.Add(4)
	flow.attempt.down.Add(4)
	flow.sendMu.Lock()
	flow.close()
	active := backend.Connections()
	// The in-flight receive and send complete after close starts.
	flow.attempt.down.Add(7)
	close(flow.receiveDone)
	flow.attempt.up.Add(3)
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
