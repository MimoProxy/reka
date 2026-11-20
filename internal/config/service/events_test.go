package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/MimoProxy/reka/internal/config/store"
)

func TestSubscribeDuringCommits(t *testing.T) {
	s := newEnv(t).open(profileWith("direct"), "")
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := s.Events()
	initialSeq := broker.seq
	activated := make(chan struct{})
	snapshotStarted := make(chan struct{})
	subscribed := make(chan struct{})
	var firstActivation sync.Once
	s.opts.FailPoint = func(point string) error {
		if point == "activated" {
			firstActivation.Do(func() {
				close(activated)
				select {
				case <-snapshotStarted:
				case <-ctx.Done():
				}
			})
		}
		return ctx.Err()
	}

	const count = 8
	committed := make(chan error, 1)
	go func() {
		for i := range count {
			profile := profileWith("alt") + fmt.Sprintf("# commit %d\n", i)
			res, err := s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: 1 + uint64(i), Profile: &profile}})
			if err != nil || res.State != store.OpCommitted {
				committed <- fmt.Errorf("commit returned %+v, %v", res, err)
				return
			}
			if i == 0 {
				select {
				case <-subscribed:
				case <-ctx.Done():
					committed <- ctx.Err()
					return
				}
			}
		}
		committed <- nil
	}()
	subscriptions := make(chan *Subscription, count)
	go func() {
		select {
		case <-activated:
		case <-ctx.Done():
			return
		}
		var firstSnapshot sync.Once
		for i := range count {
			subscriptions <- broker.Subscribe(nil, "", 0, func() any {
				firstSnapshot.Do(func() { close(snapshotStarted) })
				return s.ActiveRevision()
			})
			if i == 0 {
				close(subscribed)
			}
		}
	}()

	select {
	case err := <-committed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("commits did not finish while subscriptions were starting")
	}
	var subs []*Subscription
	for range count {
		select {
		case sub := <-subscriptions:
			subs = append(subs, sub)
			defer sub.Close()
		case <-ctx.Done():
			t.Fatal("subscriptions did not finish starting")
		}
	}
	last := broker.Publish("test.complete", nil)
	read := func(sub *Subscription) Event {
		t.Helper()
		select {
		case ev := <-sub.C:
			return ev
		case <-ctx.Done():
			t.Fatal("subscription did not receive the full stream")
			return Event{}
		}
	}
	for _, sub := range subs {
		snapshot := read(sub)
		revision, ok := snapshot.Data.(uint64)
		if !ok || snapshot.Type != EventSnapshot || revision < 1 || snapshot.Seq != initialSeq+2*(revision-1) {
			t.Fatalf("snapshot sequence does not describe its revision: %+v", snapshot)
		}
		for seq := snapshot.Seq + 1; seq <= last.Seq; seq++ {
			if ev := read(sub); ev.Seq != seq || ev.Epoch != snapshot.Epoch || ev.Dropped != 0 || ev.Type == EventSnapshot {
				t.Fatalf("expected live event %d, got %+v", seq, ev)
			}
		}
	}
}

func TestSubscribeDuringContinuousLogging(t *testing.T) {
	for _, tc := range []struct {
		name            string
		logsPerSnapshot int
		wantAttempts    int
	}{
		{name: "history retained", logsPerSnapshot: historySize, wantAttempts: 4},
		{name: "history evicted", logsPerSnapshot: historySize + 1, wantAttempts: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b := NewBroker()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				const logInterval = 10 * time.Millisecond
				ticker := time.NewTicker(logInterval)
				defer ticker.Stop()
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							b.Publish(EventLog, nil)
						}
					}
				}()

				ready := make(chan *Subscription, 1)
				go func() {
					// Finish between log ticks to control how far history advances.
					delay := time.Duration(tc.logsPerSnapshot)*logInterval + time.Millisecond
					attempts := 0
					ready <- b.Subscribe([]string{EventLog}, "", 0, func() any {
						attempts++
						select {
						case <-time.After(delay):
						case <-ctx.Done():
						}
						return attempts
					})
				}()
				var sub *Subscription
				select {
				case sub = <-ready:
					defer sub.Close()
				case <-ctx.Done():
					t.Fatal("Subscribe did not return during continuous logging")
				}
				last := b.Publish(EventLog, nil)
				read := func() Event {
					t.Helper()
					select {
					case ev := <-sub.C:
						return ev
					case <-ctx.Done():
						t.Fatal("subscription did not receive the full stream")
						return Event{}
					}
				}
				snapshot := read()
				wantSeq := last.Seq - historySize - 1
				if snapshot.Type != EventSnapshot || snapshot.Seq != wantSeq || snapshot.Data != tc.wantAttempts {
					t.Fatalf("expected snapshot at sequence %d after %d attempts, got %+v", wantSeq, tc.wantAttempts, snapshot)
				}
				for seq := snapshot.Seq + 1; seq <= last.Seq; seq++ {
					if ev := read(); ev.Type != EventLog || ev.Seq != seq || ev.Epoch != snapshot.Epoch || ev.Dropped != 0 {
						t.Fatalf("expected log event %d, got %+v", seq, ev)
					}
				}
			})
		})
	}
}
