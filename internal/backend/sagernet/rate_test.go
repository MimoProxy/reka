package sagernet

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestRateCounterWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		counter := rateCounter{start: time.Now()}
		check := func(total, peak int64) {
			t.Helper()
			if gotTotal, gotPeak := counter.Load(), counter.Peak(); gotTotal != total || gotPeak != peak {
				t.Fatalf("total = %d, peak = %d, want %d and %d", gotTotal, gotPeak, total, peak)
			}
		}
		check(0, 0)
		counter.Add(5)
		time.Sleep(999 * time.Millisecond)
		counter.Add(11)
		check(16, 16)
		time.Sleep(time.Millisecond)
		counter.Add(7)
		check(23, 16)
		counter.Add(15)
		check(38, 22)
		time.Sleep(10 * time.Second)
		check(38, 22)
		counter.Add(20)
		check(58, 22)
		counter.Add(4)
		check(62, 24)
	})
}

func TestRateCounterConcurrentAdd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		counter := rateCounter{start: time.Now()}
		const writers, writes, bytes = 8, 100, 32
		const windowBytes = writers * writes * bytes
		for second := 1; second <= 2; second++ {
			start := make(chan struct{})
			var workers sync.WaitGroup
			for range writers {
				workers.Go(func() {
					<-start
					for range writes {
						counter.Add(bytes)
					}
				})
			}
			close(start)
			workers.Wait()
			if total, peak := counter.Load(), counter.Peak(); total != int64(second*windowBytes) || peak != windowBytes {
				t.Fatalf("after window %d, total = %d, peak = %d", second, total, peak)
			}
			time.Sleep(time.Second)
		}
	})
}
