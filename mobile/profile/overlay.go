package profile

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/secret"
)

func parseOverlay(raw json.RawMessage) ([]model.Op, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if !json.Valid(raw) {
		return nil, &ValidationError{Message: "Invalid overlay", Diagnostics: model.Diagnostics{{
			Severity: model.SeverityError, Code: "overlay.json", Document: model.DocOverlay,
			Message: "overlay must be valid JSON",
		}}}
	}
	overlay, _, diagnostics := model.ParseOverlay(raw)
	if diagnostics.HasErrors() {
		return nil, &ValidationError{Message: "Invalid overlay", Diagnostics: diagnostics}
	}
	return overlay.Patches, nil
}

// compileOverlay retains the validated overlay in the snapshot so the tunnel
// can compile it in one pass. A patch is reported against its original index.
func (b *Bundle) compileOverlay(ctx context.Context, patches []model.Op, secrets secret.Store) (*compile.Effective, model.Diagnostics, []PatchStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	eff, diagnostics := b.compile(secrets)
	if len(patches) == 0 {
		return eff, diagnostics, nil, nil
	}
	statuses := make([]PatchStatus, len(patches))
	for i := range statuses {
		statuses[i] = PatchStatus{Index: i, Applied: true}
	}
	if !diagnostics.HasErrors() {
		return eff, diagnostics, statuses, nil
	}

	try := func(patches []model.Op) (*compile.Effective, model.Diagnostics, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate := *b
		candidate.Overlay = nil
		if len(patches) > 0 {
			raw, err := json.Marshal(struct {
				Version int        `json:"schema-version"`
				Patches []model.Op `json:"patches"`
			}{model.SchemaVersion, patches})
			if err != nil {
				return nil, nil, err
			}
			candidate.Overlay = raw
		}
		eff, diagnostics := candidate.compile(secrets)
		if !diagnostics.HasErrors() {
			b.Overlay = candidate.Overlay
		}
		return eff, diagnostics, nil
	}

	// Retry without structurally invalid patches as a batch. Related edits
	// such as removing a node and repairing its group can validate together.
	remaining := withoutInvalidPaths(patches, diagnostics, statuses)
	if len(remaining) < len(patches) {
		eff, diagnostics, err := try(remaining)
		if err != nil || !diagnostics.HasErrors() {
			return eff, diagnostics, statuses, err
		}
	}

	// A semantic error can affect paths in later patches. Retry in order
	// against the accepted prefix so failed changes cannot affect later edits.
	eff, diagnostics, err := try(nil)
	if err != nil || diagnostics.HasErrors() {
		return eff, diagnostics, nil, err
	}
	accepted := make([]model.Op, 0, len(patches))
	for i, patch := range patches {
		candidate := append(accepted, patch)
		next, ds, err := try(candidate)
		if err != nil {
			return nil, nil, nil, err
		}
		if ds.HasErrors() {
			statuses[i] = PatchStatus{Index: i, Reason: diagnosticError("Patch could not be applied", ds.Errors()).Error()}
			continue
		}
		accepted, eff, diagnostics = candidate, next, ds
		statuses[i] = PatchStatus{Index: i, Applied: true}
	}
	return eff, diagnostics, statuses, nil
}

func withoutInvalidPaths(patches []model.Op, diagnostics model.Diagnostics, statuses []PatchStatus) []model.Op {
	for _, d := range diagnostics {
		if d.Document != model.DocOverlay || d.Code != "overlay.path" {
			continue
		}
		suffix, ok := strings.CutPrefix(d.Path, "/patches/#")
		if !ok {
			continue
		}
		if i, err := strconv.Atoi(suffix); err == nil && i >= 0 && i < len(patches) {
			statuses[i] = PatchStatus{Index: i, Reason: "Invalid patch target or operation (overlay.path)"}
		}
	}
	remaining := make([]model.Op, 0, len(patches))
	for i, patch := range patches {
		if statuses[i].Applied {
			remaining = append(remaining, patch)
		}
	}
	return remaining
}
