package sagernet

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

// networkManager is the minimal adapter.NetworkManager the upstream dialer and
// listener need. Upstream looks it up from the context; a nil manager is
// tolerated by the default dialer but not by the domain resolver path, so one
// is always registered.
//
// Reka owns network monitoring and TUN takeover outside this adapter. protect
// includes Android's VpnService.protect() and desktop TUN bypass controls.
type networkManager struct {
	explicitProtect bool
	protect         control.Func
	// networks is set only in the scoped context of an outbound with a
	// network strategy. It supplies the typed interfaces the upstream
	// multi-network dialer chooses from.
	networks *hostNetworks
}

var _ adapter.NetworkManager = (*networkManager)(nil)

func (m *networkManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *networkManager) Initialize([]adapter.RuleSet)                   {}
func (m *networkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (m *networkManager) UpdateInterfaces() error                            { return nil }
func (m *networkManager) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }
func (m *networkManager) NetworkInterfaces() []adapter.NetworkInterface {
	if m.networks == nil {
		return nil
	}
	return m.networks.list()
}
func (m *networkManager) NetworkEnvironment() uint64 { return 0 }
func (m *networkManager) AutoDetectInterface() bool {
	return !m.explicitProtect && (m.protect != nil || m.networks != nil)
}
func (m *networkManager) AutoDetectInterfaceFunc() control.Func       { return m.protect }
func (m *networkManager) ProtectFunc() control.Func                   { return m.protect }
func (m *networkManager) DefaultOptions() adapter.NetworkOptions      { return adapter.NetworkOptions{} }
func (m *networkManager) RegisterAutoRedirectOutputMark(uint32) error { return nil }
func (m *networkManager) AutoRedirectOutputMark() uint32              { return 0 }

// Explicit interface binding suppresses upstream auto-detect hooks. Keep the
// mandatory Android protect control on the unconditional socket-control path.
func (m *networkManager) AutoRedirectOutputMarkFunc() control.Func {
	if m.explicitProtect {
		return m.protect
	}
	return nil
}
func (m *networkManager) NetworkMonitor() tun.NetworkUpdateMonitor { return nil }
func (m *networkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	if m.networks == nil {
		return nil
	}
	return hostInterfaceMonitor{networks: m.networks}
}
func (m *networkManager) PackageManager() tun.PackageManager { return nil }
func (m *networkManager) NeedWIFIState() bool                { return false }
func (m *networkManager) WIFIState() adapter.WIFIState       { return adapter.WIFIState{} }
func (m *networkManager) UpdateWIFIState(context.Context)    {}
func (m *networkManager) ResetNetwork(context.Context)       {}
func (m *networkManager) FlushSystemDNSCache()               {}
