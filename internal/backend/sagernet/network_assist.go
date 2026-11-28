package sagernet

import (
	"context"
	"net"
	"slices"
	"sync"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

// NetworkInterface is one physical network the host reports, for example
// from NWPath.availableInterfaces on iOS. Type is wifi, cellular, ethernet or
// other.
type NetworkInterface struct {
	Name        string `json:"name"`
	Index       int    `json:"index,omitempty"`
	Type        string `json:"type"`
	Expensive   bool   `json:"expensive,omitempty"`
	Constrained bool   `json:"constrained,omitempty"`
	// Label is a name for the user, such as the Wi-Fi network's SSID.
	Label string `json:"label,omitempty"`
}

// Limit a host report; a phone has a handful of networks.
const maxNetworkInterfaces = 16

// hostNetworks holds the networks the host last reported, most preferred
// first. The first one is the default interface. It is shared by every
// outbound that uses a network strategy.
type hostNetworks struct {
	mu         sync.RWMutex
	reported   bool
	interfaces []adapter.NetworkInterface
	// described names every reported network, including those not used for
	// dialing, so connections can show which network carried them.
	described map[string]api.ConnectionNetwork
}

// unknownInterface stands in until the host reports its networks. It matches
// the stand-in default interface, so the upstream dialer opens an unbound
// socket, exactly as it would without a network strategy.
var unknownInterface = adapter.NetworkInterface{Interface: control.Interface{Index: 0}}

func (h *hostNetworks) set(reported []NetworkInterface) []adapter.NetworkInterface {
	interfaces := make([]adapter.NetworkInterface, 0, min(len(reported), maxNetworkInterfaces))
	described := make(map[string]api.ConnectionNetwork, min(len(reported), maxNetworkInterfaces))
	for _, value := range reported {
		if len(interfaces) == maxNetworkInterfaces {
			break
		}
		if value.Name == "" || len(value.Name) > 64 {
			continue
		}
		kind, ok := C.StringToInterfaceType[value.Type]
		if !ok {
			kind = C.InterfaceTypeOther
		}
		if _, seen := described[value.Name]; !seen {
			described[value.Name] = api.ConnectionNetwork{
				NetworkType: kind.String(), NetworkName: history.Text(value.Label, connectionLabelBytes),
			}
		}
		index := value.Index
		if iface, err := net.InterfaceByName(value.Name); err == nil {
			// The kernel index is authoritative; a host value can be stale.
			index = iface.Index
		}
		if index <= 0 || slices.ContainsFunc(interfaces, func(it adapter.NetworkInterface) bool { return it.Index == index }) {
			continue
		}
		// Low Data Mode asks apps not to use a network in the background. Only
		// the network the system already chose is used when it is constrained.
		if value.Constrained && len(interfaces) > 0 {
			continue
		}
		interfaces = append(interfaces, adapter.NetworkInterface{
			Interface:   control.Interface{Name: value.Name, Index: index},
			Type:        kind,
			Expensive:   value.Expensive,
			Constrained: value.Constrained,
		})
	}
	h.mu.Lock()
	h.reported, h.interfaces, h.described = true, interfaces, described
	h.mu.Unlock()
	return interfaces
}

// describe names the network behind a local interface. It is empty for an
// interface the host has not reported.
func (h *hostNetworks) describe(name string) api.ConnectionNetwork {
	if h == nil || name == "" {
		return api.ConnectionNetwork{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.described[name]
}

func (h *hostNetworks) list() []adapter.NetworkInterface {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.reported {
		return []adapter.NetworkInterface{unknownInterface}
	}
	return h.interfaces
}

func (h *hostNetworks) defaultInterface() *control.Interface {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.reported {
		value := unknownInterface.Interface
		return &value
	}
	if len(h.interfaces) == 0 {
		return nil
	}
	value := h.interfaces[0].Interface
	return &value
}

// SetNetworkInterfaces replaces the networks outbounds with a network
// strategy may use. The first entry is the network the system prefers.
// Connections already open stay on their network.
func (b *Backend) SetNetworkInterfaces(interfaces []NetworkInterface) {
	accepted := b.networks.set(interfaces)
	names := make([]string, 0, len(accepted))
	for _, iface := range accepted {
		names = append(names, iface.Name+"/"+iface.Type.String())
	}
	b.logger.Debug("network interfaces updated: ", names)
}

// networkStrategyContext registers the upstream services that turn on the
// multi-network dialer for one outbound. Upstream enables it only when the
// platform reports typed interfaces and interface auto-detection is on, so
// the outbound gets its own network manager instead of changing the shared
// one, and outbounds without a strategy dial exactly as before.
func (b *Backend) networkStrategyContext(ctx context.Context) context.Context {
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: b.protect, networks: &b.networks})
	service.MustRegister[adapter.PlatformInterface](ctx, hostPlatform{})
	return ctx
}

// hostPlatform answers the one platform question the upstream dialer asks.
// It is registered only in the scoped context of an outbound with a network
// strategy, which never builds the components that use the rest.
type hostPlatform struct{ adapter.PlatformInterface }

func (hostPlatform) UsePlatformNetworkInterfaces() bool { return true }

// hostInterfaceMonitor reports the host's preferred network as the default
// interface. Interface changes reach the dialer through each dial reading the
// current list, so no callbacks are delivered.
type hostInterfaceMonitor struct{ networks *hostNetworks }

var _ tun.DefaultInterfaceMonitor = hostInterfaceMonitor{}

func (hostInterfaceMonitor) Start() error { return nil }
func (hostInterfaceMonitor) Close() error { return nil }
func (m hostInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.networks.defaultInterface()
}
func (hostInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (hostInterfaceMonitor) AndroidVPNEnabled() bool  { return false }
func (hostInterfaceMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (hostInterfaceMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {}
func (hostInterfaceMonitor) RegisterMyInterface(string)                                           {}
func (hostInterfaceMonitor) MyInterfaces() []string                                               { return nil }
