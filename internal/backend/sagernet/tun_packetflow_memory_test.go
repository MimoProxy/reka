//go:build with_gvisor && !race

package sagernet

import (
	"runtime"
	"testing"
)

func TestPacketFlowIdleTCPHeap(t *testing.T) {
	lab := newPacketFlowLab(t, 256, 128)
	baseline := packetFlowHeapInuse()
	for count := 1; count <= 256; count++ {
		lab.open(t, "tcp")
		switch count {
		case 32, 64, 128, 256:
			used := int64(packetFlowHeapInuse()) - int64(baseline)
			t.Logf("%d idle TCP flows: HeapInuse +%d bytes (%.2f MiB, %.2f KiB/flow)",
				count, used, float64(used)/(1<<20), float64(used)/float64(count)/(1<<10))
		}
	}
}

func packetFlowHeapInuse() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapInuse
}
