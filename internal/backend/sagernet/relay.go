package sagernet

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// relayTCP dials through out and copies both directions. It follows the
// upstream route.ConnectionManager.NewConnection flow (dial, report handshake
// success to the inbound, kick lazy outbound handshakes, copy), minus
// sniffing, TLS fragmenting and URL-test bookkeeping.
func (b *Backend) relayTCP(ctx context.Context, out *Outbound, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	release := out.acquire()
	remote, err := out.out.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		release()
		err = E.Cause(err, "open connection to ", metadata.Destination, " using outbound/", out.Type(), "[", out.Tag(), "]")
		N.CloseOnHandshakeFailure(conn, onClose, err)
		b.logger.ErrorContext(ctx, err)
		return
	}
	if err = N.ReportConnHandshakeSuccess(conn, remote); err != nil {
		release()
		remote.Close()
		N.CloseOnHandshakeFailure(conn, onClose, E.Cause(err, "report handshake success"))
		return
	}
	var done atomic.Bool
	// finish runs once per direction; the second call tears the pair down.
	finish := func(err error) {
		if done.Swap(true) {
			release()
			if onClose != nil {
				onClose(err)
			}
			common.Close(conn, remote)
		}
	}
	// abort tears the pair down before any copy goroutine has started.
	abort := func(err error) {
		if !done.Swap(true) {
			release()
			if onClose != nil {
				onClose(err)
			}
		}
		common.Close(conn, remote)
		b.logger.ErrorContext(ctx, E.Cause(err, "outbound handshake"))
	}
	// No sniffing yet, so treat every protocol as client-first.
	if kickHandshake(conn, remote, abort) || kickHandshake(remote, conn, abort) {
		return
	}
	go copyHalf(conn, remote, finish)
	go copyHalf(remote, conn, finish)
}

// copyHalf copies source to destination, then half-closes destination so
// the peer sees EOF while the other direction keeps flowing.
func copyHalf(source, destination net.Conn, finish func(error)) {
	_, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	if err != nil {
		common.Close(source, destination)
	} else {
		writer, _ := N.UnwrapCountWriter(destination, nil)
		if duplex, ok := N.UnwrapWriter(writer).(N.WriteCloser); ok {
			if err = duplex.CloseWrite(); err != nil {
				common.Close(source, destination)
			}
		} else {
			destination.Close()
		}
	}
	finish(err)
}

// kickHandshake flushes a lazy outbound handshake (VLESS, Shadowsocks and
// others write their request header together with the first payload). If the
// inbound already buffered client data, that data is sent with the header.
// It reports whether the connection was torn down.
func kickHandshake(source, destination net.Conn, finish func(error)) bool {
	if !N.NeedHandshakeForWrite(destination) {
		return false
	}
	var (
		err          error
		wrotePayload bool
	)
	reader, _ := N.UnwrapCountReader(source, nil)
	writer, _ := N.UnwrapCountWriter(destination, nil)
	var cached *buf.Buffer
	if cr, ok := reader.(N.CachedReader); ok {
		cached = cr.ReadCached()
	}
	if cached != nil {
		wrotePayload = true
		_, err = writer.Write(cached.Bytes())
		cached.Release()
	} else {
		_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
		_, err = writer.Write(nil)
		_ = destination.SetWriteDeadline(time.Time{})
	}
	if err == nil {
		return false
	}
	// Some outbounds refuse an empty write; the header then goes out with the
	// first real payload, which is fine for client-first protocols.
	if !wrotePayload && (E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) || E.IsTimeout(err)) {
		return false
	}
	finish(err)
	return true
}

// relayUDP opens a packet session through out and copies both directions
// until either side closes.
func (b *Backend) relayUDP(ctx context.Context, out *Outbound, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	release := out.acquire()
	remote, err := out.out.ListenPacket(ctx, metadata.Destination)
	if err != nil {
		release()
		err = E.Cause(err, "open packet connection to ", metadata.Destination, " using outbound/", out.Type(), "[", out.Tag(), "]")
		N.CloseOnHandshakeFailure(conn, onClose, err)
		b.logger.ErrorContext(ctx, err)
		return
	}
	if err = N.ReportPacketConnHandshakeSuccess(conn, remote); err != nil {
		release()
		remote.Close()
		N.CloseOnHandshakeFailure(conn, onClose, E.Cause(err, "report handshake success"))
		return
	}
	go func() {
		err := bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(remote))
		release()
		if onClose != nil {
			onClose(err)
		}
	}()
}
