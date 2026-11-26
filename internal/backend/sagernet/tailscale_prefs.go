//go:build with_gvisor

package sagernet

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/tsaddr"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/wgengine"
)

type tailscaleLocalBackend interface {
	State() ipn.State
	Status() *ipnstate.Status
	Prefs() ipn.PrefsView
	EditPrefs(*ipn.MaskedPrefs) (ipn.PrefsView, error)
	NetMapWithPeers() *netmap.NetworkMap
	PeerForIP(netip.Addr) (wgengine.PeerForIP, bool)
}

func (n *tailscaleNode) SetPreferences(prefs TailscalePreferences) error {
	n.statusMu.Lock()
	defer n.statusMu.Unlock()
	n.prefs = prefs
	return n.applyPreferencesLocked()
}

func (n *tailscaleNode) applyPreferencesLocked() error {
	if n.closed.Load() {
		return net.ErrClosed
	}
	var id tailcfg.StableNodeID
	n.exitError = ""
	if selector := n.prefs.ExitNode; selector != "" {
		id, n.exitError = selectTailscaleExitNode(selector, n.local.NetMapWithPeers())
	}
	cur := n.local.Prefs()
	// Clear a persisted IP alongside the ID so it cannot resolve to a
	// previous exit after a change or restart. Keep OS DNS and inbound off.
	changeExit := !cur.Valid() || cur.ExitNodeID() != id || cur.ExitNodeIP().IsValid() || cur.AutoExitNode() != ""
	edit := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll:               n.prefs.AcceptRoutes,
			ExitNodeID:             id,
			ExitNodeAllowLANAccess: n.prefs.ExitNodeAllowLANAccess,
			ShieldsUp:              true,
		},
		RouteAllSet:               !cur.Valid() || cur.RouteAll() != n.prefs.AcceptRoutes,
		ExitNodeIDSet:             changeExit,
		ExitNodeIPSet:             changeExit,
		ExitNodeAllowLANAccessSet: !cur.Valid() || cur.ExitNodeAllowLANAccess() != n.prefs.ExitNodeAllowLANAccess,
		ShieldsUpSet:              !cur.Valid() || !cur.ShieldsUp(),
		CorpDNSSet:                !cur.Valid() || cur.CorpDNS(),
	}
	if !edit.IsEmpty() {
		if _, err := n.local.EditPrefs(edit); err != nil {
			n.exitID = ""
			n.exitError = fmt.Sprintf("update Tailscale preferences: %v", err)
			return err
		}
	}
	n.exitID = id
	return nil
}

func selectTailscaleExitNode(selector string, nm *netmap.NetworkMap) (tailcfg.StableNodeID, string) {
	if nm == nil {
		return "", "waiting for the Tailscale network map"
	}
	auto := selector == "auto"
	ip, _ := netip.ParseAddr(selector)
	var match tailcfg.NodeView
	for _, peer := range nm.Peers {
		if auto {
			if !availableTailscaleExit(peer) {
				continue
			}
		} else if !matchesTailscalePeer(peer, selector, ip) {
			continue
		}
		if match.Valid() {
			if auto {
				return "", "multiple online Tailscale exit nodes are available"
			}
			return "", fmt.Sprintf("ambiguous Tailscale exit node %q", selector)
		}
		match = peer
	}
	if !match.Valid() {
		if auto {
			return "", "no online Tailscale exit node is available"
		}
		return "", fmt.Sprintf("Tailscale exit node %q was not found", selector)
	}
	if !availableTailscaleExit(match) {
		return "", fmt.Sprintf("Tailscale peer %q is offline or does not offer an exit route", selector)
	}
	return match.StableID(), ""
}

func availableTailscaleExit(peer tailcfg.NodeView) bool {
	return peer.StableID() != "" && peer.Online().Get() && !peer.Expired() && tsaddr.ContainsExitRoutes(peer.AllowedIPs())
}

func matchesTailscalePeer(peer tailcfg.NodeView, selector string, ip netip.Addr) bool {
	if ip.IsValid() {
		ip = ip.Unmap()
		if tsaddr.IsTailscaleIP(ip) {
			for _, prefix := range peer.Addresses().All() {
				if prefix.IsSingleIP() && prefix.Addr() == ip {
					return true
				}
			}
		}
		return false
	}
	name := strings.TrimSuffix(selector, ".")
	dns := strings.TrimSuffix(peer.Name(), ".")
	label, _, _ := strings.Cut(dns, ".")
	return name != "" && (strings.EqualFold(name, dns) || strings.EqualFold(name, label) ||
		peer.Hostinfo().Valid() && strings.EqualFold(name, peer.Hostinfo().Hostname()))
}
