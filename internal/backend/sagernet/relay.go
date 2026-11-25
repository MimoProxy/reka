package sagernet

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// relayTCP dials through out and copies both directions. It follows the
// upstream route.ConnectionManager.NewConnection flow (dial, report handshake
// success to the inbound, kick lazy outbound handshakes, copy). Optional
// sniffing has already finished before the route was selected.
func (b *Backend) relayTCP(ctx context.Context, rt Route, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc, attempt *connectionAttempt) {
	out, release := rt.Outbound, rt.Release
	var originalDestination string
	if rt.Destination != nil {
		destination := rt.Destination.String()
		if destination != attempt.Destination {
			originalDestination = attempt.Destination
		}
		metadata.Destination = M.ParseSocksaddr(destination)
	}
	if _, debug := conn.(*debugBridge); !debug && rt.MITM != nil {
		if rt.MITM.H2 {
			go b.relayMITM(ctx, rt, conn, metadata, originalDestination, onClose, attempt)
			return
		}
		go func() {
			conn, requiresH2 := peekMITMClientHello(conn)
			if !requiresH2 {
				b.relayMITM(ctx, rt, conn, metadata, originalDestination, onClose, attempt)
				return
			}
			// An HTTP/1.1-only MITM handshake would fail for this client, and
			// the app would retry or fall back slowly. Relaying it undecrypted
			// keeps the app working; only this connection's rewrites and
			// scripts are lost.
			attempt.mu.Lock()
			attempt.MITMSkipped = mitmSkipH2Disabled
			attempt.mu.Unlock()
			rt.MITM = nil
			b.relayTCP(ctx, rt, conn, metadata, onClose, attempt)
		}()
		return
	}
	ctx = tcpRouteContext(ctx, rt, metadata)
	remote, err := dialTCP(ctx, out, metadata.Destination, attempt)
	if err != nil {
		attempt.complete(connectionReason(err, "error"), "dial")
		release()
		err = E.Cause(err, "open connection to ", metadata.Destination, " using outbound/", out.Type(), "[", out.Tag(), "]")
		N.CloseOnHandshakeFailure(conn, onClose, err)
		b.logger.ErrorContext(ctx, err)
		return
	}
	stopCancel := func() {}
	if attempt.releasePacketFlow != nil {
		stop := context.AfterFunc(ctx, func() { _ = remote.Close() })
		stopCancel = func() { stop() }
	}
	if err = N.ReportConnHandshakeSuccess(conn, remote); err != nil {
		stopCancel()
		attempt.complete(connectionReason(err, "error"), "handshake")
		release()
		remote.Close()
		N.CloseOnHandshakeFailure(conn, onClose, E.Cause(err, "report handshake success"))
		return
	}
	var (
		done      atomic.Bool
		manual    atomic.Bool
		drained   atomic.Bool
		errMu     sync.Mutex
		firstErr  error
		finished  = make(chan struct{})
		closeBoth = func() { common.Close(conn, remote) }
	)
	up, down := &attempt.up, &attempt.down
	processTraffic, finishProcess := b.beginProcessTraffic(rt.Owner)
	untrackConnection := b.conns.add(&tracked{attempt: attempt, id: attempt.ID, start: time.Now(), md: toMetadata(metadata), out: out,
		originalDestination: originalDestination,
		info:                rt.Info, close: func() { manual.Store(true); closeBoth() }})
	untrack := func() { stopCancel(); untrackConnection(); finishProcess() }
	// finish runs once per direction; the second call tears the pair down.
	finish := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		if done.Swap(true) {
			errMu.Lock()
			cause := firstErr
			errMu.Unlock()
			reason := connectionReason(cause, "eof")
			if manual.Load() {
				reason = "manual"
			} else if drained.Load() {
				reason = "idle_timeout"
			}
			stage := ""
			if cause != nil && reason != "manual" && reason != "idle_timeout" {
				stage = "relay"
			}
			attempt.complete(reason, stage)
			close(finished)
			untrack()
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
			attempt.complete(connectionReason(err, "error"), "handshake")
			untrack()
			release()
			if onClose != nil {
				onClose(err)
			}
		}
		closeBoth()
		b.logger.ErrorContext(ctx, E.Cause(err, "outbound handshake"))
	}
	// Kick lazy outbound handshakes before either copy loop waits for data.
	if kickHandshake(conn, remote, abort) || kickHandshake(remote, conn, abort) {
		return
	}
	grace := b.halfCloseTimeout
	closeIdle := func() { drained.Store(true); closeBoth() }
	go copyHalf(conn, remote, up, finish, func() { watchIdle(down, grace, finished, closeIdle) }, &b.trafficUpload, &processTraffic.upload)
	go copyHalf(remote, conn, down, finish, func() { watchIdle(up, grace, finished, closeIdle) }, &b.trafficDownload, &processTraffic.download)
}

func tcpRouteContext(ctx context.Context, rt Route, metadata adapter.InboundContext) context.Context {
	if rt.Context != nil {
		ctx = rt.Context(ctx)
	}
	ctx = WithLookup(ctx, observeRequestLookup(ctx, rt.Lookup))
	return adapter.WithContext(ctx, &metadata)
}

func dialTCP(ctx context.Context, out *Outbound, destination M.Socksaddr, attempt *connectionAttempt) (net.Conn, error) {
	start := time.Now()
	attempt.dialing(start, out)
	ctx, socketDial := withSocketDial(ctx)
	remote, err := out.out.DialContext(ctx, N.NetworkTCP, destination)
	finished := time.Now()
	observed := socketDial.finish(remote, err)
	observeRequestDial(ctx, attempt.dialed(start, finished, err, observed, out.Type() == "direct" && out.dependencyCloser == nil))
	return remote, err
}

// copyHalf copies source to destination, counting bytes into moved. At EOF
// it half-closes destination so the peer sees EOF while the other direction
// keeps flowing. Many proxy connections cannot half-close (Shadowsocks has no
// CloseWrite, REALITY servers mishandle TLS close_notify); closing them
// outright would drop the reply still in flight. For those, drain is called
// instead: the other direction keeps relaying until it goes idle.
func copyHalf(source, destination net.Conn, moved *rateCounter, finish func(error), drain func(), totals ...*atomic.Uint64) {
	err := copyOwned(destination, source, moved, totals...)
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

// copyOwned waits for data before borrowing a buffer when the reader supports
// it. Readers that need a copy or cannot wait use a private buffer.
func copyOwned(destination io.Writer, source io.Reader, moved *rateCounter, totals ...*atomic.Uint64) error {
	var (
		waiter   N.ReadWaiter
		needCopy bool
		private  []byte
	)
	for {
		// A reader such as sniffReplayConn can expose its waiter after a
		// fallback read drains its prefix.
		if waiter == nil && !needCopy {
			if candidate, ok := bufio.CreateReadWaiter(source); ok {
				// Plain Write needs no headroom. The default size is buf.BufferSize.
				needCopy = candidate.InitializeReadWaiter(N.ReadWaitOptions{})
				if !needCopy {
					waiter = candidate
					private = nil
				}
			}
		}
		var (
			buffer  *buf.Buffer
			data    []byte
			readErr error
		)
		if waiter != nil {
			buffer, readErr = waiter.WaitReadBuffer()
			if buffer != nil {
				data = buffer.Bytes()
			}
		} else {
			if private == nil {
				private = make([]byte, buf.BufferSize)
			}
			var n int
			n, readErr = source.Read(private)
			if n > 0 {
				data = private[:n]
			}
		}
		if len(data) > 0 {
			written, err := destination.Write(data)
			moved.Add(int64(written))
			if written > 0 {
				for _, total := range totals {
					total.Add(uint64(written))
				}
			}
			// On an error or short write a multiplexed sender may still
			// reference data after Write returns. Let GC reclaim the buffer
			// once those references are gone to prevent reuse by another relay.
			if err != nil {
				return err
			}
			if written != len(data) {
				return io.ErrShortWrite
			}
		}
		buffer.Release()
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

// watchIdle closes the pair once moved has not changed for grace, unless
// the relay finishes first.
func watchIdle(moved *rateCounter, grace time.Duration, finished <-chan struct{}, closeBoth func()) {
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
		// The same asynchronous-close ownership rule applies to cached input.
		payload := append([]byte(nil), cached.Bytes()...)
		cached.Release()
		_, err = writer.Write(payload)
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
