//go:build with_gvisor

package packettunnel

import (
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
	var closed int
	if s.profile != nil {
		closed = s.profile.engine.CloseConnections(nil)
	} else if s.backend != nil {
		closed = s.backend.CloseConnections(nil)
	}
	s.logger.Warn("Memory is near the extension limit; closed all connections",
		"reason", reason, "footprintMiB", memory.Total()>>20, "closed", closed)
	return closed
}
