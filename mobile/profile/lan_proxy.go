package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

// LANProxyListenerID names the listener that shares the tunnel with other
// devices on the local network.
const LANProxyListenerID = "lan-proxy"

// DefaultLANProxyPort matches the mixed port mihomo uses by default.
const DefaultLANProxyPort = 7890

// LANProxy opens a mixed HTTP and SOCKS listener on every IPv4 interface so
// that other devices on the same network can use the tunnel as a proxy.
type LANProxy struct {
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Validate reports whether the port and credentials can be used.
func (p LANProxy) Validate() error {
	_, err := p.listener()
	return err
}

func (p LANProxy) listener() (compile.Listener, error) {
	if p.Port < 1024 || p.Port > 65535 {
		return compile.Listener{}, errors.New("LAN proxy port must be between 1024 and 65535")
	}
	if (p.Username == "") != (p.Password == "") {
		return compile.Listener{}, errors.New("LAN proxy needs both a username and a password, or neither")
	}
	var users []model.ListenerUser
	if p.Username != "" {
		users = []model.ListenerUser{{Username: p.Username, Password: p.Password}}
	}
	// The fingerprint decides whether a running listener is kept or rebound,
	// so it covers the credentials without exposing them.
	sum := sha256.Sum256([]byte(model.ListenerMixed + "\x00" + p.Username + "\x00" + p.Password))
	return compile.Listener{
		ID:          LANProxyListenerID,
		Type:        model.ListenerMixed,
		Listen:      netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(p.Port)),
		UDP:         true,
		Users:       users,
		Fingerprint: hex.EncodeToString(sum[:8]),
	}, nil
}

func applyLANProxy(eff *compile.Effective, proxy *LANProxy) error {
	if proxy == nil {
		return nil
	}
	listener, err := proxy.listener()
	if err != nil {
		return err
	}
	eff.Listeners = append(slices.Clone(eff.Listeners), listener)
	return nil
}
