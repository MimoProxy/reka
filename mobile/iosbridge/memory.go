//go:build ios && cgo && with_gvisor

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

import (
	"runtime"

	"github.com/MimoProxy/reka/mobile/packettunnel"
)

func init() {
	// Heap profiling keeps a 1.4 MiB bucket table, which counts against
	// the extension's footprint once samples touch it. Only diagnostics
	// read heap profiles, and a runtime profile restores the default rate
	// when it starts. Allocations during package initialization may still
	// have touched a few pages.
	runtime.MemProfileRate = 0
	// The native heap holds Swift, JavaScriptCore and system framework
	// memory that the Go runtime does not report.
	packettunnel.ProfileExtra = func() map[string]float64 {
		var inUse, allocated C.size_t
		C.rekaMallocStats(&inUse, &allocated)
		return map[string]float64{"mallocInUse": float64(inUse), "mallocAllocated": float64(allocated)}
	}
}
