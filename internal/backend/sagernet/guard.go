package sagernet

import (
	"errors"
	"github.com/MimoProxy/reka/internal/platform"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// SocketGuard resolves the current physical interface for each NEW socket.
// Interface changes never reset existing proxy connections or generations.
type SocketGuard struct {
	mu      sync.RWMutex
	enabled bool
	bind    string
	finder  *control.DefaultInterfaceFinder
	netMon  tun.NetworkUpdateMonitor
	ifMon   tun.DefaultInterfaceMonitor
	protect func(int) error
}

func NewSocketGuard(protect func(int) error) *SocketGuard {
	return &SocketGuard{protect: protect, finder: control.NewDefaultInterfaceFinder()}
}
func (g *SocketGuard) Set(enabled bool, c platform.TUNConfig) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enabled = enabled
	g.bind = c.BindInterface
	if !enabled || runtime.GOOS == "android" {
		if enabled && g.protect == nil {
			return errors.New("Android TUN requires protect")
		}
		return nil
	}
	if g.netMon != nil {
		return nil
	}
	log := newLogger(nil, "network")
	n, err := tun.NewNetworkUpdateMonitor(log)
	if err != nil {
		return err
	}
	m, err := tun.NewDefaultInterfaceMonitor(n, log, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: g.finder})
	if err != nil {
		n.Close()
		return err
	}
	if err = n.Start(); err != nil {
		m.Close()
		n.Close()
		return err
	}
	if err = m.Start(); err != nil {
		m.Close()
		n.Close()
		return err
	}
	if err = g.finder.Update(); err != nil {
		m.Close()
		n.Close()
		return err
	}
	g.netMon = n
	g.ifMon = m
	return nil
}
func (g *SocketGuard) Control(network, address string, c syscall.RawConn) error {
	if g.protect != nil {
		var e error
		if err := c.Control(func(fd uintptr) { e = g.protect(int(fd)) }); err != nil {
			return err
		}
		if e != nil {
			return e
		}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.enabled || runtime.GOOS == "android" {
		return nil
	}
	name := g.bind
	if name == "" && g.ifMon != nil {
		if d := g.ifMon.DefaultInterface(); d != nil {
			name = d.Name
		}
	}
	if name == "" {
		return errors.New("no physical default interface; refusing an unbound TUN outbound")
	}
	lower := strings.ToLower(name)
	for _, prefix := range []string{"utun", "tun", "tap", "tailscale", "wireguard", "reka"} {
		if strings.HasPrefix(lower, prefix) {
			return errors.New("default interface belongs to a VPN; select a physical bind-interface explicitly")
		}
	}
	return control.BindToInterface(g.finder, name, -1)(network, address, c)
}
func (g *SocketGuard) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ifMon != nil {
		g.ifMon.Close()
		g.ifMon = nil
	}
	if g.netMon != nil {
		g.netMon.Close()
		g.netMon = nil
	}
	g.enabled = false
}
