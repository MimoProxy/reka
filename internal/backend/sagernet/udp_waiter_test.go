package sagernet

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestUDPRelayWithPacketWaiter(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			destination := M.ParseSocksaddr("192.0.2.1:53")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			backend := &Backend{}
			session := &udpSession{b: backend, ctx: ctx, cancel: cancel, flows: make(map[M.Socksaddr]*udpFlow)}
			flow := &udpFlow{
				s: session, ctx: ctx, cancel: cancel, dest: destination,
				ready: make(chan struct{}), processTraffic: &processTrafficCounter{},
				attempt: backend.beginConnection(ctx, Metadata{Network: N.NetworkUDP}),
			}
			flow.readyOnce.Do(func() { close(flow.ready) })
			session.flows[destination] = flow

			reader := &udpTestPacketWaiter{
				packets: make(chan udpTestPacket, 2),
				waiting: make(chan struct{}, 3),
			}
			writeErr := errors.New("failed to write packet")
			writer := &udpTestPacketWriter{writes: make(chan udpTestPacketWrite, 2), err: writeErr}
			run := session.run
			session.conn, flow.remote = reader, writer
			packetAddr, wantCloseErr := destination, error(io.EOF)
			if direction == "download" {
				run = flow.receive
				session.conn, flow.remote = writer, reader
				packetAddr, wantCloseErr = M.ParseSocksaddr("192.0.2.2:53"), writeErr
			}
			var closeErr error
			session.onClose = func(err error) { closeErr = err }
			done := make(chan struct{})
			go func() {
				defer close(done)
				run()
			}()
			defer close(reader.packets)

			waitUDPTestValue(t, reader.waiting)
			reader.packets <- udpTestPacket{payload: "forwarded", addr: packetAddr}
			written := waitUDPTestValue(t, writer.writes)
			waitUDPTestValue(t, reader.waiting)
			if written.payload != "forwarded" || written.addr != packetAddr {
				t.Fatalf("written packet = %q to %v", written.payload, written.addr)
			}
			if written.front != writer.FrontHeadroom() || written.rear < writer.RearHeadroom() {
				t.Fatalf("write headroom = %d front, %d rear", written.front, written.rear)
			}
			if got := string(written.buffer.Bytes()); got != "forwarded" {
				t.Fatalf("successful write returned owned bytes to the pool: %q", got)
			}
			written.buffer.Release()
			if written.buffer.Cap() != 0 {
				t.Fatal("receiving writer could not release the buffer after success")
			}
			if flow.last.Load() == 0 {
				t.Fatal("forwarded packet did not refresh flow activity")
			}

			reader.packets <- udpTestPacket{payload: "rejected", addr: packetAddr}
			failed := waitUDPTestValue(t, writer.writes)
			if direction == "upload" {
				waitUDPTestValue(t, reader.waiting)
				reader.packets <- udpTestPacket{err: io.EOF}
			}
			waitUDPTestValue(t, done)
			if failed.payload != "rejected" || failed.addr != packetAddr {
				t.Fatalf("failed packet = %q to %v", failed.payload, failed.addr)
			}
			if !errors.Is(closeErr, wantCloseErr) {
				t.Fatalf("session close error = %v, want %v", closeErr, wantCloseErr)
			}

			wantUp, wantDown := uint64(len(written.payload)), uint64(0)
			if direction == "download" {
				wantUp, wantDown = wantDown, wantUp
			}
			if gotUp, gotDown := backend.trafficUpload.Load(), backend.trafficDownload.Load(); gotUp != wantUp || gotDown != wantDown {
				t.Fatalf("backend traffic = %d up, %d down, want %d up, %d down", gotUp, gotDown, wantUp, wantDown)
			}
			if gotUp, gotDown := flow.attempt.up.Load(), flow.attempt.down.Load(); gotUp != int64(wantUp) || gotDown != int64(wantDown) {
				t.Fatalf("flow traffic = %d up, %d down, want %d up, %d down", gotUp, gotDown, wantUp, wantDown)
			}
			if gotUp, gotDown := flow.processTraffic.upload.Load(), flow.processTraffic.download.Load(); gotUp != wantUp || gotDown != wantDown {
				t.Fatalf("process traffic = %d up, %d down, want %d up, %d down", gotUp, gotDown, wantUp, wantDown)
			}
		})
	}
}

type udpTestPacket struct {
	payload string
	addr    M.Socksaddr
	err     error
}

type udpTestPacketWaiter struct {
	N.PacketConn
	packets chan udpTestPacket
	waiting chan struct{}
	options N.ReadWaitOptions
}

func (c *udpTestPacketWaiter) Close() error { return nil }

func (c *udpTestPacketWaiter) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errors.New("read called without the packet waiter")
}

func (c *udpTestPacketWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.options = options
	return options.NeedHeadroom()
}

func (c *udpTestPacketWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.waiting <- struct{}{}
	packet, ok := <-c.packets
	if !ok {
		return nil, M.Socksaddr{}, io.EOF
	}
	if packet.err != nil {
		return nil, M.Socksaddr{}, packet.err
	}
	b := c.options.NewPacketBuffer()
	_, err := b.WriteString(packet.payload)
	if err == nil {
		c.options.PostReturn(b)
	}
	return b, packet.addr, err
}

type udpTestPacketWrite struct {
	payload     string
	addr        M.Socksaddr
	buffer      *buf.Buffer
	front, rear int
}

type udpTestPacketWriter struct {
	N.PacketConn
	writes chan udpTestPacketWrite
	err    error
}

func (c *udpTestPacketWriter) Close() error       { return nil }
func (c *udpTestPacketWriter) FrontHeadroom() int { return 5 }
func (c *udpTestPacketWriter) RearHeadroom() int  { return 7 }

func (c *udpTestPacketWriter) WritePacket(b *buf.Buffer, addr M.Socksaddr) error {
	payload := string(b.Bytes())
	c.writes <- udpTestPacketWrite{payload: payload, addr: addr, buffer: b, front: b.Start(), rear: b.FreeLen()}
	if payload == "rejected" {
		b.Release()
		return c.err
	}
	// A queued writer passes the buffer to its sender on success.
	return nil
}

func waitUDPTestValue[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("UDP relay did not complete the expected operation")
		var zero T
		return zero
	}
}
