package compile

import (
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

// detours validates the combined outbound/group dependency graph and folds
// every possible parent transport into a child's replacement fingerprint.
func (c *compiler) detours(e *Effective) {
	hasDetour := false
	nodes := map[string]*Outbound{}
	groups := map[string]router.Group{}
	for i := range e.Outbounds {
		o := &e.Outbounds[i]
		nodes[o.ID] = o
		hasDetour = hasDetour || o.Dialer != nil && o.Dialer.Proxy != ""
		if d := o.Dialer; d != nil && d.Proxy != "" && (d.Interface != "" || d.RoutingMark != 0 || d.IPVersion != "" || d.TFO || d.MPTCP) {
			c.warnf(model.DocProfile, "/outbounds/"+o.ID+"/dialer", "outbound.detour-options", "dialer proxy uses its parent's physical socket options; set interface, routing mark, IP version, TFO and MPTCP on the parent")
		}
	}
	if !hasDetour || c.diags.HasErrors() {
		return
	}
	for _, g := range e.Groups {
		groups[g.ID] = g
	}
	state := map[string]int{}
	hashes := map[string]string{}
	stack := []string{}
	var visit func(string) string
	visit = func(id string) string {
		if state[id] == 2 {
			return hashes[id]
		}
		if state[id] == 1 {
			c.errorf(model.DocProfile, "/outbounds", "outbound.detour", "cyclic dialer dependency: %s", strings.Join(append(stack, id), " -> "))
			return ""
		}
		state[id] = 1
		stack = append(stack, id)
		defer func() { stack = stack[:len(stack)-1] }()
		if g, ok := groups[id]; ok {
			dependencies := []string{}
			for _, member := range g.Members {
				dependencies = append(dependencies, visit(member))
			}
			hashes[id] = fingerprint(struct {
				Group       router.Group
				UDPDisabled bool
			}{g, e.GroupUDPDisabled[id]}, dependencies...)
		} else if o := nodes[id]; o != nil {
			hashes[id] = o.Fingerprint
			if o.Dialer != nil && o.Dialer.Proxy != "" {
				parent := visit(o.Dialer.Proxy)
				hashes[id] = fingerprint(o.Fingerprint, parent)
			}
		} else {
			c.errorf(model.DocProfile, "/outbounds", "outbound.detour", "dialer target %q is unavailable", id)
		}
		state[id] = 2
		return hashes[id]
	}
	for _, o := range e.Outbounds {
		if o.Dialer != nil && o.Dialer.Proxy != "" {
			visit(o.ID)
		}
	}
	if c.diags.HasErrors() {
		return
	}
	for _, o := range nodes {
		if o.Dialer != nil && o.Dialer.Proxy != "" {
			o.Fingerprint = hashes[o.ID]
		}
	}
}

// DetourLeaves returns the direct possible parents of one detour (all group
// members, not just today's selection). Each parent owns its own dependencies.
func (e *Effective) DetourLeaves(target string) []string {
	groups := map[string]router.Group{}
	for _, g := range e.Groups {
		groups[g.ID] = g
	}
	seen := map[string]bool{}
	leaves := []string{}
	var walk func(string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		if g, ok := groups[id]; ok {
			for _, member := range g.Members {
				walk(member)
			}
		} else {
			leaves = append(leaves, id)
		}
	}
	walk(target)
	slices.Sort(leaves)
	return leaves
}
