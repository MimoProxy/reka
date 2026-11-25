package api

import (
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

type AddModuleRequest struct {
	Module       model.Module `json:"module"`
	BaseRevision uint64       `json:"base_revision"`
	Position     *int         `json:"position,omitempty"`
}

type RemoveModuleRequest struct {
	ModuleID     string `json:"module_id"`
	BaseRevision uint64 `json:"base_revision"`
}

type SetModuleEnabledRequest struct {
	ModuleID     string `json:"module_id"`
	Enabled      *bool  `json:"enabled"`
	BaseRevision uint64 `json:"base_revision"`
}

type SetModuleArgumentsRequest struct {
	ModuleID     string            `json:"module_id"`
	Arguments    map[string]string `json:"arguments"`
	BaseRevision uint64            `json:"base_revision"`
}

type RefreshModuleRequest struct {
	ModuleID string `json:"module_id"`
	Wait     bool   `json:"wait,omitempty"`
}

type GetModuleReportRequest struct {
	ModuleID string `json:"module_id"`
}

type PreviewModuleRequest struct {
	Data      string            `json:"data"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type ModuleStatus struct {
	ModuleID     string              `json:"module_id"`
	State        string              `json:"state"`
	Stale        bool                `json:"stale"`
	LastAttempt  time.Time           `json:"last_attempt,omitempty"`
	LastSuccess  time.Time           `json:"last_success,omitempty"`
	NextAttempt  time.Time           `json:"next_attempt,omitempty"`
	ErrorCode    string              `json:"error_code,omitempty"`
	Revision     uint64              `json:"revision,omitempty"`
	RootHash     string              `json:"root_hash,omitempty"`
	ScriptErrors []ModuleScriptError `json:"script_errors,omitempty"`
}

type ModuleScriptError struct {
	Request string `json:"request"`
	Code    string `json:"code"`
}

type ModuleReportSummary struct {
	Partial     bool                `json:"partial"`
	CanApply    bool                `json:"can_apply"`
	Rules       module.Count        `json:"rules"`
	Rewrites    module.Count        `json:"rewrites"`
	Hostnames   module.Count        `json:"hostnames"`
	Scripts     module.Count        `json:"scripts"`
	ScriptItems []module.ScriptItem `json:"script_items,omitempty"`
}

type ModuleInfo struct {
	ID         string               `json:"id"`
	Enabled    bool                 `json:"enabled"`
	SourceType string               `json:"source_type"`
	Name       string               `json:"name,omitempty"`
	Desc       string               `json:"desc,omitempty"`
	Arguments  []module.Argument    `json:"arguments,omitempty"`
	Status     ModuleStatus         `json:"status"`
	Report     *ModuleReportSummary `json:"report,omitempty"`
}
