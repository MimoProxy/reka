package generation

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
)

type sceneObservation struct {
	name                 string
	addresses            []netip.Addr
	addressesUnavailable bool
	at                   time.Time
	err                  string
}

type manualScene struct {
	profile string
	id      string
}

// refreshSceneObservation is called under the engine lifecycle lock.
func (e *Engine) refreshSceneObservation(g *generation) *sceneObservation {
	if g.eff == nil || !slices.ContainsFunc(g.eff.NetworkScenes, func(scene compile.NetworkScene) bool {
		return scene.Interface != "" || len(scene.CIDRs) != 0
	}) {
		e.sceneObservation.Store(nil)
		return nil
	}
	obs := e.observeSceneInterface()
	e.sceneObservation.Store(obs)
	return obs
}

func (e *Engine) observeSceneInterface() *sceneObservation {
	obs := &sceneObservation{at: time.Now().UTC()}
	iface, err := e.sceneInterface()
	if err != nil {
		obs.err = err.Error()
	} else if iface.Flags&net.FlagUp == 0 {
		obs.err = "default interface is down"
	} else {
		obs.name = iface.Name
		if addrs, err := iface.Addrs(); err != nil {
			obs.addressesUnavailable = true
		} else {
			for _, value := range addrs {
				if p, err := netip.ParsePrefix(value.String()); err == nil {
					obs.addresses = append(obs.addresses, p.Addr().Unmap())
				}
			}
		}
	}
	return obs
}

func (e *Engine) sceneInterface() (*net.Interface, error) {
	if !e.opts.HostPacketFlow {
		return e.guard.SceneInterface()
	}
	name := e.packetInterface.Load()
	if name == nil || *name == "" {
		return nil, errors.New("no active physical network interface")
	}
	return net.InterfaceByName(*name)
}

func (e *Engine) SetPacketFlowInterface(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || !e.opts.HostPacketFlow {
		return
	}
	e.packetInterface.Store(&name)
	_, g := e.current()
	e.refreshSceneObservation(g)
}

func matchNetworkScene(scenes []compile.NetworkScene, obs *sceneObservation) string {
	if obs == nil || obs.name == "" {
		return ""
	}
	for _, scene := range scenes {
		if scene.Interface != "" && scene.Interface != obs.name {
			continue
		}
		if len(scene.CIDRs) == 0 {
			if scene.Interface != "" {
				return scene.ID
			}
			continue
		}
		for _, prefix := range scene.CIDRs {
			if slices.ContainsFunc(obs.addresses, prefix.Contains) {
				return scene.ID
			}
		}
	}
	return ""
}

func (e *Engine) activeNetworkScene(g *generation) string {
	if g.eff == nil || len(g.eff.NetworkScenes) == 0 {
		return ""
	}
	if id := e.manualNetworkScene(g); id != "" {
		return id
	}
	return matchNetworkScene(g.eff.NetworkScenes, e.sceneObservation.Load())
}

func (e *Engine) manualNetworkScene(g *generation) string {
	if scene := e.sceneManual.Load(); scene != nil && scene.profile == g.historyScope.ProfileID && networkSceneExists(g, scene.id) {
		return scene.id
	}
	return ""
}

func networkSceneExists(g *generation, id string) bool {
	return g.eff != nil && slices.ContainsFunc(g.eff.NetworkScenes, func(scene compile.NetworkScene) bool { return scene.ID == id })
}

func (e *Engine) NetworkScene() api.NetworkSceneStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, g := e.current()
	if !e.closed {
		e.refreshSceneObservation(g)
	}
	return e.networkSceneStatus(g)
}

func (e *Engine) SetNetworkScene(id string) (api.NetworkSceneStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, g := e.current()
	if e.closed || (id != "" && !networkSceneExists(g, id)) {
		return api.NetworkSceneStatus{}, errors.New("unknown network scene")
	}
	if id == "" {
		e.sceneManual.Store(nil)
	} else {
		e.sceneManual.Store(&manualScene{profile: g.historyScope.ProfileID, id: id})
	}
	e.refreshSceneObservation(g)
	return e.networkSceneStatus(g), nil
}

func (e *Engine) networkSceneStatus(g *generation) api.NetworkSceneStatus {
	status := api.NetworkSceneStatus{Current: e.activeNetworkScene(g), Manual: e.manualNetworkScene(g), Scenes: []string{}}
	if g.eff != nil {
		for _, scene := range g.eff.NetworkScenes {
			status.Scenes = append(status.Scenes, scene.ID)
		}
	}
	if obs := e.sceneObservation.Load(); obs != nil {
		status.Interface, status.ObservedAt, status.Error = obs.name, obs.at, obs.err
		for _, addr := range obs.addresses {
			status.Addresses = append(status.Addresses, addr.String())
		}
	}
	return status
}
