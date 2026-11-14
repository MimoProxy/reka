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
// Interface monitoring, auto-detect-interface and TUN integration come later
// later. protect is the hook for Android's VpnService.protect().
type networkManager struct {
	protect control.Func
}

var _ adapter.NetworkManager = (*networkManager)(nil)

func (m *networkManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *networkManager) Initialize([]adapter.RuleSet)                   {}
func (m *networkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (m *networkManager) UpdateInterfaces() error                            { return nil }
func (m *networkManager) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }
func (m *networkManager) NetworkInterfaces() []adapter.NetworkInterface      { return nil }
func (m *networkManager) NetworkEnvironment() uint64                         { return 0 }
func (m *networkManager) AutoDetectInterface() bool                          { return m.protect != nil }
func (m *networkManager) AutoDetectInterfaceFunc() control.Func              { return m.protect }
func (m *networkManager) ProtectFunc() control.Func                          { return m.protect }
func (m *networkManager) DefaultOptions() adapter.NetworkOptions             { return adapter.NetworkOptions{} }
func (m *networkManager) RegisterAutoRedirectOutputMark(uint32) error        { return nil }
func (m *networkManager) AutoRedirectOutputMark() uint32                     { return 0 }
func (m *networkManager) AutoRedirectOutputMarkFunc() control.Func           { return nil }
func (m *networkManager) NetworkMonitor() tun.NetworkUpdateMonitor           { return nil }
func (m *networkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor      { return nil }
func (m *networkManager) PackageManager() tun.PackageManager                 { return nil }
func (m *networkManager) NeedWIFIState() bool                                { return false }
func (m *networkManager) WIFIState() adapter.WIFIState                       { return adapter.WIFIState{} }
func (m *networkManager) UpdateWIFIState(context.Context)                    {}
func (m *networkManager) ResetNetwork(context.Context)                       {}
func (m *networkManager) FlushSystemDNSCache()                               {}
