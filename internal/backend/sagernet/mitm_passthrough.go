package sagernet

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/http/httpguts"
)

func httpUpgradeProtocol(header http.Header) string {
	if httpguts.HeaderValuesContainsToken(header.Values("Connection"), "upgrade") {
		return header.Get("Upgrade")
	}
	return ""
}

func stripMITMRequestHopHeaders(header http.Header, allowUpgrade bool) {
	var protocol, settings string
	if allowUpgrade {
		protocol = httpUpgradeProtocol(header)
		if strings.EqualFold(protocol, "h2c") && httpguts.HeaderValuesContainsToken(header.Values("Connection"), "http2-settings") {
			settings = header.Get("HTTP2-Settings")
		}
	}
	stripHTTPHopHeaders(header)
	if protocol != "" {
		header.Set("Connection", "Upgrade")
		header.Set("Upgrade", protocol)
		if settings != "" {
			header.Set("Connection", "Upgrade, HTTP2-Settings")
			header.Set("HTTP2-Settings", settings)
		}
	}
}

func (s *mitmHTTPHandler) forwardHTTPProxyRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, reason string) error {
	s.attempt.setMITMPassthrough(reason)
	remote, err := dialTCP(tcpRouteContext(ctx, s.upstream.route, s.metadata), s.upstream.route.Outbound, s.metadata.Destination, s.attempt)
	if err != nil {
		return err
	}
	closeRemote := sync.OnceFunc(func() { _ = remote.Close() })
	defer closeRemote()
	stop := context.AfterFunc(ctx, closeRemote)
	defer stop()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return err
	}
	defer client.Close()
	if err = writeHTTPProxyHead(remote, r); err != nil {
		return err
	}
	return s.relayHTTPDuplex(ctx, client, buffered.Reader, remote, closeRemote)
}

func writeHTTPProxyHead(w io.Writer, r *http.Request) error {
	// Keep the original request-target and framing. The hijacked reader still
	// contains the wire body, including any chunk boundaries and trailers.
	head := bufio.NewWriter(w)
	if _, err := fmt.Fprintf(head, "%s %s %s\r\n", r.Method, r.RequestURI, r.Proto); err != nil {
		return err
	}
	if r.Host != "" {
		if _, err := fmt.Fprintf(head, "Host: %s\r\n", r.Host); err != nil {
			return err
		}
	}
	if err := r.Header.Write(head); err != nil {
		return err
	}
	if len(r.TransferEncoding) != 0 {
		fmt.Fprintf(head, "Transfer-Encoding: %s\r\n", strings.Join(r.TransferEncoding, ", "))
	}
	for name := range r.Trailer {
		fmt.Fprintf(head, "Trailer: %s\r\n", name)
	}
	head.WriteString("\r\n")
	return head.Flush()
}

func (s *mitmHTTPHandler) relayHTTPDuplex(ctx context.Context, client net.Conn, reader *bufio.Reader, upstream io.ReadWriter, closeUpstream func()) error {
	// The client wire already counts both directions, including read-ahead.
	done := make(chan error, 1)
	closeBoth := sync.OnceFunc(func() {
		s.closeWire()
		closeUpstream()
	})
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	go func() {
		err := copyHTTPStream(upstream, reader)
		closeBoth()
		done <- err
	}()
	err := copyHTTPStream(client, upstream)
	closeBoth()
	upErr := <-done
	if err == nil || upErr == nil {
		return nil
	}
	return err
}

func copyHTTPStream(dst io.Writer, src io.Reader) error {
	if writer, ok := src.(io.WriterTo); ok {
		_, err := writer.WriteTo(dst)
		return err
	}
	buffer := buf.Get(buf.BufferSize)
	_, err := io.CopyBuffer(dst, src, buffer)
	// On error a multiplexed writer may still reference its last payload.
	if err == nil {
		_ = buf.Put(buffer)
	}
	return err
}
