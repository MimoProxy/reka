package sagernet

import (
	"slices"
	"testing"
	"time"
)

func TestCloseIdleConnectionsOrder(t *testing.T) {
	for _, tc := range []struct {
		share float64
		want  []string
	}{
		// Ended and idle connections go even when they exceed the share.
		{share: 0.5, want: []string{"ended", "idle-60s", "idle-10s"}},
		// A larger share adds the least recently active ones.
		{share: 0.8, want: []string{"ended", "idle-60s", "idle-10s", "idle-2s", "idle-1s"}},
		{share: 0, want: []string{"ended", "idle-60s", "idle-10s"}},
	} {
		backend := &Backend{}
		now := time.Now()
		var closed []string
		add := func(name string, age time.Duration) *connectionAttempt {
			attempt := backend.beginConnectionAt(t.Context(), Metadata{Network: "tcp"}, now.Add(-age))
			backend.conns.add(&tracked{
				attempt: attempt, id: attempt.ID, out: &Outbound{tag: "direct"},
				close: func() { closed = append(closed, name) },
			})
			return attempt
		}
		add("active", time.Minute).down.Add(1)
		add("ended", 3*time.Second).complete("eof", "")
		add("idle-60s", time.Minute)
		add("idle-10s", 10*time.Second)
		add("idle-2s", 2*time.Second)
		add("idle-1s", time.Second)

		n, total := backend.CloseIdleConnections(now, 5*time.Second, tc.share)
		if total != 6 || n != len(tc.want) || !slices.Equal(closed, tc.want) {
			t.Fatalf("share %v: closed %d of %d %v, want %v", tc.share, n, total, closed, tc.want)
		}
	}
}

func TestRateCounterLastActive(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	c := rateCounter{start: start}
	if got := c.lastActive(); !got.Equal(start) {
		t.Fatalf("without bytes = %v, want start %v", got, start)
	}
	c.Add(1)
	if got := time.Since(c.lastActive()); got < 0 || got > 2*time.Second {
		t.Fatalf("after a write, last active was %v ago", got)
	}
}
