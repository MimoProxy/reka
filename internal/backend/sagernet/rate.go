package sagernet

import (
	"sync/atomic"
	"time"
)

const (
	rateByteBits  = 36
	rateByteMask  = 1<<rateByteBits - 1
	rateMaxSecond = 1<<(64-rateByteBits) - 1
)

// rateCounter groups bytes into one-second windows relative to the
// connection's monotonic start time. It rolls the window only on writes.
type rateCounter struct {
	start time.Time
	total atomic.Int64
	// Pack the second and its byte count together so a concurrent writer
	// cannot increment a window while another writer is clearing it.
	window atomic.Uint64
	peak   atomic.Int64
}

func (c *rateCounter) Add(n int64) {
	if n <= 0 {
		return
	}
	// Match mihomo's one-second rate interval without periodic sampling.
	// Saturate the packed fields at over eight years and nearly 64 GiB/s.
	second := min(uint64(time.Since(c.start)/time.Second), rateMaxSecond)
	c.total.Add(n)
	for {
		window := c.window.Load()
		previous := window >> rateByteBits
		bytes := window & rateByteMask
		if second > previous {
			// Publish the old window before replacing it so Peak cannot dip.
			c.recordPeak(int64(bytes))
			bytes = 0
		}
		// A concurrent write sampled just before rollover can land in the
		// newer window. Its bytes still count toward the lifetime total.
		next := max(second, previous)<<rateByteBits | min(bytes+uint64(n), rateByteMask)
		if c.window.CompareAndSwap(window, next) {
			return
		}
	}
}

func (c *rateCounter) recordPeak(bytes int64) {
	for peak := c.peak.Load(); bytes > peak; peak = c.peak.Load() {
		if c.peak.CompareAndSwap(peak, bytes) {
			return
		}
	}
}

func (c *rateCounter) Load() int64 { return c.total.Load() }

// lastActive returns the start of the latest second that counted bytes, or
// the counter's start when it counted none.
func (c *rateCounter) lastActive() time.Time {
	if c.total.Load() == 0 {
		return c.start
	}
	return c.start.Add(time.Duration(c.window.Load()>>rateByteBits) * time.Second)
}

// Peak returns the largest window's bytes, including bytes already counted in
// the current window without extrapolating its partial second.
func (c *rateCounter) Peak() int64 {
	return max(int64(c.window.Load()&rateByteMask), c.peak.Load())
}
