//go:build with_gvisor

package sagernet

import (
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketFlowPacketWaiterRefreshesActivity(t *testing.T) {
	reader := &udpTestPacketWaiter{
		packets: make(chan udpTestPacket, 1),
		waiting: make(chan struct{}, 2),
	}
	flow := &admittedPacketFlow{}
	conn := &packetFlowPacketConn{PacketConn: reader, flow: flow}
	waiter, ok := bufio.CreatePacketReadWaiter(conn)
	if !ok {
		t.Fatal("packet flow did not expose a read waiter")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	if flow.last.Load() != 0 {
		t.Fatal("initialization refreshed activity")
	}
	addr := M.ParseSocksaddr("192.0.2.1:53")
	reader.packets <- udpTestPacket{addr: addr}
	b, gotAddr, err := waiter.WaitReadPacket()
	defer b.Release()
	if err != nil || gotAddr != addr || b.Len() != 0 {
		t.Fatalf("empty datagram read from %v: %v", gotAddr, err)
	}
	previous := flow.last.Load()
	if previous == 0 {
		t.Fatal("reading an empty datagram did not refresh activity")
	}
	close(reader.packets)
	if _, _, err := waiter.WaitReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty source returned %v, want EOF", err)
	}
	if flow.last.Load() != previous {
		t.Fatal("reading EOF refreshed activity")
	}
}
