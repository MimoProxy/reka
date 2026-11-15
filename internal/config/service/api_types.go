package service

import "github.com/MimoProxy/reka/internal/api"

// The request and result types are defined in internal/api so clients can
// use them without linking the runtime.
type (
	Error              = api.Error
	ChangeRequest      = api.ChangeRequest
	CommitRequest      = api.CommitRequest
	FieldChange        = api.FieldChange
	Conflict           = api.Conflict
	Result             = api.Result
	ValidateResult     = api.ValidateResult
	PlanResult         = api.PlanResult
	Configuration      = api.Configuration
	RestoreRequest     = api.RestoreRequest
	SubscriptionStatus = api.SubscriptionStatus
	Event              = api.Event
)
