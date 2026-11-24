package generation

import (
	"errors"

	"github.com/MimoProxy/reka/internal/config/model"
)

// DiagnosticRoute identifies the leaf selected for a single diagnostic.
// It leaves the policy group's selection, counters and pins untouched.
type DiagnosticRoute struct {
	Outbound string `json:"outbound"`
	Direct   bool   `json:"direct"`
}

func (e *Engine) ResolveDiagnosticRoute(member, target string) (DiagnosticRoute, error) {
	snapshot, g := e.current()
	if member == "" || len(member) > 128 || len(target) > 512 || g.eff == nil || g.router == nil {
		return DiagnosticRoute{}, errors.New("diagnostic policy unavailable")
	}
	id, err := g.resolveProbe(member, target)
	if err != nil || snapshot.Resources[id] == nil {
		return DiagnosticRoute{}, errors.New("diagnostic policy unavailable or rejected")
	}
	configured, _ := g.eff.Outbound(id)
	return DiagnosticRoute{Outbound: id, Direct: configured.Type == model.OutboundDirect && configured.Builtin}, nil
}
