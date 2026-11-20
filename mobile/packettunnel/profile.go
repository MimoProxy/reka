//go:build with_gvisor

package packettunnel

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/mobile/profile"
)

const ProfileAddress4 = "172.27.255.1/30"

type profileSession struct {
	mu      sync.Mutex
	engine  *generation.Engine
	base    *compile.Effective
	summary profile.Summary
	rev     uint64
	trace   *routeTrace
	sets    map[string]*router.RuleSet
}

type ProfileStatus struct {
	Mode   string        `json:"mode"`
	Groups []GroupStatus `json:"groups"`
	Routes []RouteHit    `json:"routes,omitempty"`
}

type GroupStatus struct {
	ID        string `json:"id"`
	Selected  string `json:"selected"`
	Checked   int    `json:"checked"`
	Available int    `json:"available"`
}

type RouteHit struct {
	Destination string   `json:"destination"`
	Address     string   `json:"address,omitempty"`
	Failure     string   `json:"failure,omitempty"`
	TimeMS      int64    `json:"timeMs"`
	Kind        string   `json:"kind"`
	Target      string   `json:"target"`
	Chain       []string `json:"chain,omitempty"`
	Outbound    string   `json:"outbound"`
}

const traceCapacity = 64

type routeTrace struct {
	mu    sync.Mutex
	items [traceCapacity]RouteHit
	next  int
	count int
}

func (t *routeTrace) record(route generation.RouteObservation) {
	destination := route.Domain
	if destination == "" && route.Address.IsValid() {
		destination = route.Address.String()
	}
	if destination == "" {
		return
	}
	dec := route.Decision
	item := RouteHit{
		Destination: destination, Failure: route.Failure, TimeMS: time.Now().UnixMilli(),
		Kind: dec.Rule.Kind.String(), Target: dec.Target, Chain: dec.Chain, Outbound: dec.Outbound,
	}
	if route.Address.IsValid() {
		item.Address = route.Address.String()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items[t.next] = item
	t.next = (t.next + 1) % traceCapacity
	t.count = min(t.count+1, traceCapacity)
}

func (t *routeTrace) read() []RouteHit {
	t.mu.Lock()
	defer t.mu.Unlock()
	items := make([]RouteHit, t.count)
	for i := range items {
		items[i] = t.items[(t.next+traceCapacity-1-i)%traceCapacity]
	}
	return items
}

func StartProfile(snapshot []byte, controls profile.Controls, trace bool) (*Session, error) {
	s, err := openProfileSession(snapshot, controls, trace, false)
	if err != nil {
		return nil, err
	}
	tunnel, err := s.profile.engine.AttachPacketFlow(s.device, MTU, netip.MustParsePrefix(ProfileAddress4), netip.MustParsePrefix(Address6), maxTCP, maxUDP)
	if err != nil {
		s.Close()
		return nil, errors.New("could not attach profile packet flow")
	}
	s.tunnel = tunnel
	s.logger.Info("Packet tunnel started")
	return s, nil
}

// StartProbeProfile gives the foreground app a short-lived engine for node
// tests while the VPN is off. It neither installs routes nor opens inbounds.
func StartProbeProfile(snapshot []byte, controls profile.Controls) (*Session, error) {
	return openProfileSession(snapshot, controls, false, true)
}

func (s *Session) ProviderClient(name string) (*http.Client, error) {
	return s.profile.engine.SubscriptionProxyClient("ios", name)
}

func openProfileSession(snapshot []byte, controls profile.Controls, trace, probeOnly bool) (*Session, error) {
	bundle, err := profile.Decode(snapshot)
	if err != nil {
		return nil, err
	}
	base, err := bundle.CompileWithSecrets(controls.Secrets)
	if err != nil {
		return nil, err
	}
	if probeOnly {
		for i := range base.AutoGroups {
			base.AutoGroups[i].Lazy = true
		}
	}
	s := newSession()
	opts := generation.EngineOptions{
		HostPacketFlow: true, PacketHistory: s.events,
		Backend: sagernet.Options{Logger: s.logger.With("component", "core")},
	}
	if runtime.GOOS == "ios" {
		opts.Resolver = net.DefaultResolver
	}
	p := &profileSession{base: base, summary: profile.Describe(base), sets: collectRuleSets(base.Router.Rules())}
	if trace {
		p.trace = &routeTrace{}
		opts.ObserveRoute = p.trace.record
	}
	p.engine = generation.NewEngine(opts)
	if err := p.publish(p.base, p.summary, controls); err != nil {
		s.cancel()
		p.engine.Close()
		return nil, err
	}
	s.profile = p
	return s, nil
}

func (s *Session) SetRealDNS(real bool) {
	if s.profile != nil {
		s.profile.engine.SetPacketFlowRealDNS(real)
	}
}

func (p *profileSession) publish(base *compile.Effective, summary profile.Summary, controls profile.Controls) error {
	eff, err := profile.ApplyControls(base, summary, controls)
	if err != nil {
		return errors.New("invalid policy or routing mode")
	}
	prepared, err := p.engine.Prepare(eff)
	if err != nil {
		return errors.New("could not prepare profile outbounds or DNS")
	}
	_, scope := p.engine.History()
	profileID := controls.ProfileID
	if profileID == "" {
		profileID = scope.ProfileID
	}
	if _, err := p.engine.ActivateProfile(prepared, p.rev+1, profileID); err != nil {
		return errors.New("could not activate profile")
	}
	p.rev++
	p.base, p.summary = base, summary
	return nil
}

func (s *Session) ApplyControls(controls profile.Controls) error {
	p := s.profile
	if p == nil {
		return errors.New("tunnel is not using a profile")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	err := p.publish(p.base, p.summary, controls)
	if err == nil {
		s.logger.Info("Routing updated")
	}
	return err
}

// ReplaceProfile publishes a prepared snapshot through the same runtime as
// policy changes. The packet link and leases belonging to existing flows stay
// valid. The old profile is kept on any preparation failure.
func (s *Session) ReplaceProfile(snapshot []byte, controls profile.Controls) error {
	p := s.profile
	if p == nil {
		return errors.New("tunnel is not using a profile")
	}
	bundle, err := profile.Decode(snapshot)
	if err != nil {
		return err
	}
	base, err := bundle.CompileWithSecrets(controls.Secrets)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := p.publish(base, profile.Describe(base), controls); err != nil {
		s.logger.Warn("Profile refresh could not be applied")
		return err
	}
	p.sets = collectRuleSets(base.Router.Rules())
	s.logger.Info("Profile refreshed")
	return nil
}

func (s *Session) ProfileStatus() (*ProfileStatus, error) {
	p := s.profile
	if p == nil {
		return nil, errors.New("tunnel is not using a profile")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	eff, _ := p.engine.Effective()
	status := &ProfileStatus{Mode: eff.Routing.Mode, Groups: make([]GroupStatus, 0, len(eff.Groups))}
	observed := p.engine.GroupStatus()
	for _, group := range eff.Groups {
		row := GroupStatus{ID: group.ID, Selected: group.Selected}
		if row.Selected == "" && len(group.Members) > 0 {
			row.Selected = group.Members[0]
		}
		if i := slices.IndexFunc(observed, func(o policy.Status) bool { return o.ID == group.ID }); i >= 0 {
			auto := observed[i]
			row.Selected = auto.Selected
			for _, result := range auto.Results {
				if !result.Checked.IsZero() {
					row.Checked++
				}
				if result.Alive {
					row.Available++
				}
			}
		}
		status.Groups = append(status.Groups, row)
	}
	if p.trace != nil {
		status.Routes = p.trace.read()
	}
	return status, nil
}
