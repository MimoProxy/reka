//go:build with_gvisor

package packettunnel

import (
	"time"

	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing/common/memory"
)

// StartMemoryGuard watches the process footprint and closes every connection
// before the extension reaches the system memory limit, as sing-box does for
// its iOS Network Extension. Only the extension host calls it; other hosts
// share their process with unrelated memory.
func (s *Session) StartMemoryGuard() {
	s.guardOnce.Do(func() {
		s.guard = newMemoryGuard(defaultMemoryGuardConfig(), memory.Total, s.resetForMemory)
		s.guard.start()
	})
}

// MemoryPressure reports a critical memory pressure notice from the system.
func (s *Session) MemoryPressure() {
	if g := s.guard; g != nil {
		g.notifyPressure()
	}
}

func (s *Session) resetForMemory(reason string) int {
	if s.ctx.Err() != nil {
		return 0
	}
	ca.PurgeAll()
	script.PurgeAll()
	all := reason == memoryResetAll
	var closed, total int
	switch {
	case s.profile != nil && all:
		closed = s.profile.engine.CloseConnections(nil)
		total = closed
	case s.profile != nil:
		closed, total = s.profile.engine.CloseIdleConnections(time.Now(), memoryResetIdle, memoryResetShare)
	case s.backend != nil && all:
		closed = s.backend.CloseConnections(nil)
		total = closed
	case s.backend != nil:
		closed, total = s.backend.CloseIdleConnections(time.Now(), memoryResetIdle, memoryResetShare)
	}
	message := "Memory is near the extension limit; closed idle connections"
	if all {
		message = "Memory is near the extension limit; closed all connections"
	}
	s.logger.Warn(message, "reason", reason, "footprintMiB", memory.Total()>>20, "closed", closed, "connections", total)
	return closed
}

// A memory reset first closes connections idle this long, the same idle
// time after which the packet flow table evicts a flow, and at least half
// of all connections, longest idle first.
const (
	memoryResetIdle  = 5 * time.Second
	memoryResetShare = 0.5
)
