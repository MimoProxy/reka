//go:build with_gvisor

package packettunnel

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/policy"
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
	item := RouteHit{Destination: destination, Kind: dec.Rule.Kind.String(), Target: dec.Target, Chain: dec.Chain, Outbound: dec.Outbound}
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
	bundle, err := profile.Decode(snapshot)
	if err != nil {
		return nil, err
	}
	base, err := bundle.Compile()
	if err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opts := generation.EngineOptions{HostPacketFlow: true, Backend: sagernet.Options{Logger: logger}}
	p := &profileSession{base: base, summary: profile.Describe(base)}
	if trace {
		p.trace = &routeTrace{}
		opts.ObserveRoute = p.trace.record
	}
	p.engine = generation.NewEngine(opts)
	if err := p.apply(controls); err != nil {
		p.engine.Close()
		return nil, err
	}
	s := newSession()
	tunnel, err := p.engine.AttachPacketFlow(s.device, MTU, netip.MustParsePrefix(ProfileAddress4), netip.MustParsePrefix(Address6), maxTCP, maxUDP)
	if err != nil {
		s.cancel()
		p.engine.Close()
		return nil, errors.New("could not attach profile packet flow")
	}
	s.profile, s.tunnel = p, tunnel
	return s, nil
}

func (p *profileSession) apply(controls profile.Controls) error {
	eff, err := profile.ApplyControls(p.base, p.summary, controls)
	if err != nil {
		return errors.New("invalid policy or routing mode")
	}
	prepared, err := p.engine.Prepare(eff)
	if err != nil {
		return errors.New("could not prepare profile outbounds or DNS")
	}
	if _, err := p.engine.Activate(prepared, p.rev+1); err != nil {
		return errors.New("could not activate profile")
	}
	p.rev++
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
	return p.apply(controls)
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
			row.Checked = len(auto.Results)
			for _, result := range auto.Results {
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
