//go:build !ios

package sagernet

import "net/http"

// Reka caps bytes held for input body rewrites and scripts across all MITM
// streams and connections. sing-box and mihomo have no equivalent budget.
// This allows multiple desktop-sized rewrites without unbounded buffering.
const mitmBodyBufferBytes = 64 << 20

func mitmHTTP2Config() *http.HTTP2Config {
	// Like sing-box's unset HTTP2Options, use Go's defaults for protocol
	// settings. MaxHeaderBytes and MaxResponseHeaderBytes bound header size.
	return &http.HTTP2Config{}
}
