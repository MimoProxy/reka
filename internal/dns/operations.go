package dns

// FlushCache clears ordinary DNS observations, independently of Fake IP
// leases. Existing flows retain their address mappings.
func (s *Service) FlushCache() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.cache)
	clear(s.cache)
	s.cacheEpoch++
	return n
}

func (s *Service) NetworkChanged() int {
	n := s.FlushCache()
	if s.opts.ResetIdle != nil {
		s.opts.ResetIdle()
	}
	return n
}
