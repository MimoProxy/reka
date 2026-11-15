package generation

import "github.com/MimoProxy/reka/internal/api"

// Plan, explanation and status types are defined in internal/api so
// clients can use them without linking the runtime.
type (
	ResourceChange = api.ResourceChange
	GroupChange    = api.GroupChange
	Plan           = api.Plan
	FlowInfo       = api.FlowInfo
	ExplainRequest = api.ExplainRequest
	Explanation    = api.Explanation
	Connection     = api.Connection
	Status         = api.RuntimeStatus
)

// Change actions in a plan.
const (
	ActionKeep    = api.ActionKeep
	ActionCreate  = api.ActionCreate
	ActionReplace = api.ActionReplace
	ActionRemove  = api.ActionRemove
	ActionRebind  = api.ActionRebind
	ActionRestart = api.ActionRestart
)
