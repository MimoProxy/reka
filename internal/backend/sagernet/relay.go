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
	var (
		done      atomic.Bool
		finished  = make(chan struct{})
		up, down  atomic.Int64
		closeBoth = func() { common.Close(conn, remote) }
	)
	// finish runs once per direction; the second call tears the pair down.
	finish := func(err error) {
		if done.Swap(true) {
			close(finished)
			release()
			if onClose != nil {
				onClose(err)
			}
			closeBoth()
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
		closeBoth()
		b.logger.ErrorContext(ctx, E.Cause(err, "outbound handshake"))
	}
	// No sniffing yet, so treat every protocol as client-first.
	if kickHandshake(conn, remote, abort) || kickHandshake(remote, conn, abort) {
		return
	}
	grace := b.halfCloseTimeout
	go copyHalf(conn, remote, &up, finish, func() { watchIdle(&down, grace, finished, closeBoth) })
	go copyHalf(remote, conn, &down, finish, func() { watchIdle(&up, grace, finished, closeBoth) })
}

// copyHalf copies source to destination, counting bytes into moved. At EOF
// it half-closes destination so the peer sees EOF while the other direction
// keeps flowing. Many proxy connections cannot half-close (Shadowsocks has no
// CloseWrite, REALITY servers mishandle TLS close_notify); closing them
// outright would drop the reply still in flight. For those, drain is called
// instead: the other direction keeps relaying until it goes idle.
func copyHalf(source, destination net.Conn, moved *atomic.Int64, finish func(error), drain func()) {
	count := []N.CountFunc{func(n int64) { moved.Add(n) }}
	_, err := bufio.CopyWithCounters(destination, source, source, count, nil, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	switch {
	case err != nil:
		common.Close(source, destination)
	default:
		writer, _ := N.UnwrapCountWriter(destination, nil)
		if duplex, ok := N.UnwrapWriter(writer).(N.WriteCloser); ok {
			if err = duplex.CloseWrite(); err != nil {
				common.Close(source, destination)
			}
		} else {
			drain()
		}
	}
	finish(err)
}

// watchIdle closes the pair once moved has not changed for grace, unless
// the relay finishes first.
func watchIdle(moved *atomic.Int64, grace time.Duration, finished <-chan struct{}, closeBoth func()) {
	tick := time.NewTicker(grace / 4)
	defer tick.Stop()
	last, idleSince := moved.Load(), time.Now()
	for {
		select {
		case <-finished:
			return
		case now := <-tick.C:
			if cur := moved.Load(); cur != last {
				last, idleSince = cur, now
			} else if now.Sub(idleSince) >= grace {
				closeBoth()
				return
			}
		}
	}
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
