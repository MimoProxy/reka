package sagernet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

func (b *Backend) newWireGuardOutbound(tag string, spec ProxySpec) (*Outbound, error) {
	var options option.WireGuardEndpointOptions
	if err := json.Unmarshal(spec.Options, &options); err != nil {
		return nil, err
	}
	if len(options.Peers) != 1 {
		return nil, errors.New("WireGuard requires one peer")
	}
	if spec.Server == "" || spec.Port == 0 {
		return nil, errors.New("WireGuard requires a peer server and port")
	}
	if spec.Detour != nil || options.Detour != "" {
		return nil, errors.New("WireGuard does not support a detour")
	}
	if options.System || options.ListenPort != 0 {
		return nil, errors.New("WireGuard outbounds require a userspace endpoint with an ephemeral port")
	}
	if len(options.Address) == 0 {
		return nil, errors.New("WireGuard requires a local address")
	}
	if options.MTU != 0 && (options.MTU < 576 || options.MTU > math.MaxUint16) {
		return nil, errors.New("invalid WireGuard MTU")
	}
	peer := &options.Peers[0]
	validKey := func(key string) bool {
		decoded, err := base64.StdEncoding.DecodeString(key)
		return err == nil && len(decoded) == 32
	}
	if !validKey(options.PrivateKey) || !validKey(peer.PublicKey) || peer.PreSharedKey != "" && !validKey(peer.PreSharedKey) {
		return nil, errors.New("WireGuard requires base64-encoded 32-byte keys")
	}
	if len(peer.Reserved) != 0 && len(peer.Reserved) != 3 {
		return nil, errors.New("WireGuard reserved must contain three bytes")
	}
	if len(peer.AllowedIPs) == 0 {
		return nil, errors.New("WireGuard requires allowed IP prefixes")
	}
	for _, prefix := range peer.AllowedIPs {
		if !prefix.IsValid() {
			return nil, errors.New("invalid WireGuard allowed IP prefix")
		}
	}
	// The upstream stack allocates workers before installing its addresses.
	// Reject duplicates before construction can leave a partially built stack.
	addresses := make(map[netip.Addr]bool, len(options.Address))
	for _, prefix := range options.Address {
		if !prefix.IsValid() {
			return nil, errors.New("invalid WireGuard local address")
		}
		// gVisor already owns the IPv4 limited broadcast address on the NIC.
		if prefix.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return nil, errors.New("WireGuard local address is the IPv4 broadcast address")
		}
		if addresses[prefix.Addr()] {
			return nil, errors.New("duplicate WireGuard local address")
		}
		addresses[prefix.Addr()] = true
	}
	peer.Address, peer.Port = spec.Server, spec.Port
	peerLookup := spec.PeerLookup
	logger := b.componentLogger("endpoint", spec.Type, tag)
	return b.newEndpointOutbound(tag, spec.Type, func(ctx context.Context, router adapter.Router) (adapter.Endpoint, error) {
		ctx = WithLookup(ctx, peerLookup)
		return wireguard.NewEndpoint(ctx, router, logger, tag, options)
	})
}
