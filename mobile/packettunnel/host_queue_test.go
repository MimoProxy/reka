package packettunnel

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestHostQueueCountsWrittenAndDroppedPackets(t *testing.T) {
	device := &packetDevice{endpoint: channel.New(2, DefaultMTU, "")}
	defer device.Close()
	endpoint, _, err := device.NewEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	var packets stack.PacketBufferList
	for range 3 {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 20})})
		packets.PushBack(packet)
		defer packet.DecRef()
	}
	n, _ := endpoint.WritePackets(packets)
	if n != 2 || device.written.Load() != 2 || device.dropped.Load() != 1 {
		t.Fatalf("wrote %d, counted %d written and %d dropped", n, device.written.Load(), device.dropped.Load())
	}
}
