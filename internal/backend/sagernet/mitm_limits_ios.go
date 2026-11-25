//go:build ios

package sagernet

import "net/http"

// Reka caps bytes held for input body rewrites and scripts across all MITM
// streams and connections. sing-box and mihomo have no equivalent budget.
// Leave room for flow control, TLS and script execution in Packet Tunnel.
const mitmBodyBufferBytes = 4 << 20

func mitmHTTP2Config() *http.HTTP2Config {
	// Use smaller limits than Go's defaults within the Packet Tunnel Go
	// memory budget (about 28 MiB). On an iPhone, two minutes of real app
	// traffic through gRPC and video MITM modules peaked at 32.5 MiB with
	// HTTP/2 and 32.0 MiB without it, so these limits add little. Go's
	// HTTP/2 client still allocates a write buffer of up to 512 KiB for
	// each upstream request body without a declared length.
	// The inbound server caps concurrent streams. The upstream transport
	// cannot set its own stream count, so it honors the peer's limit without
	// opening extra connections when that limit is reached.
	// MaxHeaderBytes and MaxResponseHeaderBytes also bound HTTP/2 headers.
	return &http.HTTP2Config{
		MaxConcurrentStreams:          32,
		StrictMaxConcurrentRequests:   true,
		MaxReadFrameSize:              16 << 10,
		MaxReceiveBufferPerConnection: 256 << 10,
		MaxReceiveBufferPerStream:     64 << 10,
		MaxDecoderHeaderTableSize:     4096,
		MaxEncoderHeaderTableSize:     4096,
	}
}
