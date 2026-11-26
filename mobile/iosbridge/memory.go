//go:build darwin && cgo && with_gvisor

package main

/*
#include <malloc/malloc.h>
static inline void rekaMallocStats(size_t *inUse, size_t *allocated) {
	malloc_statistics_t stats;
	malloc_zone_statistics(NULL, &stats);
	*inUse = stats.size_in_use;
	*allocated = stats.size_allocated;
}
*/
import "C"

import "github.com/MimoProxy/reka/mobile/packettunnel"

func init() {
	// The native heap holds Swift, JavaScriptCore and system framework
	// memory that the Go runtime does not report.
	packettunnel.ProfileExtra = func() map[string]float64 {
		var inUse, allocated C.size_t
		C.rekaMallocStats(&inUse, &allocated)
		return map[string]float64{"mallocInUse": float64(inUse), "mallocAllocated": float64(allocated)}
	}
}
