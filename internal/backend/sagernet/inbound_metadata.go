package sagernet

import "context"

func inboundProtocol(ctx context.Context, listenerType string) string {
	if value, _ := ctx.Value("reka.inbound.protocol.v1").(string); value != "" {
		return value
	}
	switch listenerType {
	case "http":
		return "HTTP"
	case "tun":
		return "TUN"
	}
	// A mixed or SOCKS listener needs the parser's actual protocol version.
	return ""
}
