package gojaengine

import (
	"math"
	"slices"
	"time"

	"github.com/dop251/goja"
)

type sessionTimer struct {
	when time.Time
	fn   goja.Callable
	args []goja.Value
}

func (s *session) installTimers() {
	s.timers = make(map[int64]sessionTimer)
	s.global("setTimeout", func(call goja.FunctionCall) goja.Value {
		fn, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			panic(s.vm.NewTypeError("setTimeout requires a function"))
		}
		delay := timerDelay(call.Argument(1).ToFloat())
		if len(s.timers) >= s.job.Limits.MaxTimers {
			panic(s.vm.NewTypeError("too many pending timers"))
		}

		var args []goja.Value
		if len(call.Arguments) > 2 {
			args = slices.Clone(call.Arguments[2:])
		}
		s.nextTimerID++
		s.timers[s.nextTimerID] = sessionTimer{when: time.Now().Add(delay), fn: fn, args: args}
		return s.vm.ToValue(s.nextTimerID)
	})
	s.global("clearTimeout", func(call goja.FunctionCall) goja.Value {
		delete(s.timers, call.Argument(0).ToInteger())
		return goja.Undefined()
	})
}

func timerDelay(milliseconds float64) time.Duration {
	switch {
	case math.IsNaN(milliseconds), milliseconds <= 0:
		return 0
	case milliseconds >= float64(math.MaxInt64)/float64(time.Millisecond):
		return time.Duration(math.MaxInt64)
	default:
		return time.Duration(milliseconds * float64(time.Millisecond))
	}
}

func (s *session) waitForEvent() {
	// The number of active timers is bounded by MaxTimers. A scan keeps
	// cancellation simple and leaves at most one Go timer running per turn.
	var next sessionTimer
	var nextID int64
	for id, timer := range s.timers {
		if nextID == 0 || timer.when.Before(next.when) || (timer.when.Equal(next.when) && id < nextID) {
			next, nextID = timer, id
		}
	}
	var timerReady <-chan time.Time
	if nextID != 0 {
		timer := time.NewTimer(time.Until(next.when))
		defer timer.Stop()
		timerReady = timer.C
	}

	select {
	case <-s.ctx.Done():
	case result := <-s.httpResults:
		if s.ctx.Err() == nil {
			s.httpPending--
			s.deliverHTTP(result)
		}
	case <-timerReady:
		if s.ctx.Err() == nil {
			delete(s.timers, nextID)
			s.call(next.fn, next.args...)
		}
	}
}
