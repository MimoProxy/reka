package compile

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *compiler) wireGuard(path string, p *model.Protocol) {
	fail := func(field, message string) {
		c.errorf(model.DocProfile, path+"/"+field, "outbound.wireguard", "%s", message)
	}
	validKey := func(field, value string) {
		key, err := base64.StdEncoding.DecodeString(value)
		if (err != nil || len(key) != 32) && !c.hasErrorAt(path+"/"+field) {
			fail(field, "expected a base64-encoded 32-byte WireGuard key")
		}
	}
	p.PrivateKey = c.resolveSecret(path+"/private-key", p.PrivateKey)
	validKey("private-key", p.PrivateKey)
	validKey("public-key", p.PublicKey)
	if _, present := c.ppos[path+"/pre-shared-key"]; present {
		p.PreSharedKey = c.resolveSecret(path+"/pre-shared-key", p.PreSharedKey)
		validKey("pre-shared-key", p.PreSharedKey)
	}
	p.Address = slices.Clone(p.Address)
	p.AllowedIPs = slices.Clone(p.AllowedIPs)
	p.Reserved = slices.Clone(p.Reserved)
	if len(p.Address) == 0 {
		fail("address", "at least one local address prefix is required")
	}
	if _, present := c.ppos[path+"/allowed-ips"]; !present {
		p.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	} else if len(p.AllowedIPs) == 0 {
		fail("allowed-ips", "at least one allowed IP prefix is required")
	}
	addresses := make(map[netip.Addr]bool, len(p.Address))
	for i, value := range p.Address {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			fail(fmt.Sprintf("address/#%d", i), "expected an IPv4 or IPv6 address with a prefix length")
			continue
		}
		if prefix.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			fail(fmt.Sprintf("address/#%d", i), "the IPv4 limited broadcast address cannot be an interface address")
		} else if addresses[prefix.Addr()] {
			fail(fmt.Sprintf("address/#%d", i), "duplicate WireGuard interface address")
		}
		addresses[prefix.Addr()] = true
	}
	for i, value := range p.AllowedIPs {
		if _, err := netip.ParsePrefix(value); err != nil {
			fail(fmt.Sprintf("allowed-ips/#%d", i), "expected an IPv4 or IPv6 network prefix")
		}
	}
	if p.PersistentKeepalive < 0 || p.PersistentKeepalive > math.MaxUint16 {
		fail("persistent-keepalive", "persistent-keepalive must be between 0 and 65535 seconds")
	}
	if len(p.Reserved) != 0 && len(p.Reserved) != 3 {
		fail("reserved", "reserved must be empty or contain three bytes")
	}
	if p.MTU != 0 && (p.MTU < 576 || p.MTU > math.MaxUint16) {
		fail("mtu", "mtu must be zero or between 576 and 65535")
	}
}
