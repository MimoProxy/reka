package profile

import (
	"context"
	"encoding/json"
	"slices"
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

func marshalOverlay(patches []model.Op) (json.RawMessage, error) {
	return json.Marshal(struct {
		Version int        `json:"schema-version"`
		Patches []model.Op `json:"patches"`
	}{model.SchemaVersion, patches})
}

// overlayAssets loads the resources of rule sets that the overlay adds or
// whose download it changes. An added definition receives its digest in the
// patch. A changed download updates the digest of the base definition, which
// the patch then edits. It reports whether any patch changed.
func (p *preparer) overlayAssets(ctx context.Context, document map[string]any, patches []model.Op, resources map[string][]byte) ([]model.Op, bool, error) {
	updated := slices.Clone(patches)
	changed := false
	for i, op := range updated {
		segments, err := model.SplitPath(op.Path)
		if err != nil || len(segments) == 0 || segments[0] != "rule-sets" {
			continue
		}
		switch {
		case op.Op == "insert" && len(segments) == 1, op.Op == "set" && len(segments) == 2:
			var definition map[string]any
			if json.Unmarshal(op.Value, &definition) != nil || definition == nil {
				continue // The compiler reports the invalid value.
			}
			before := definition["hash"]
			if err := p.definitionAsset(ctx, "rule-sets", definition, resources); err != nil {
				return nil, false, err
			}
			if definition["hash"] != before {
				value, err := json.Marshal(definition)
				if err != nil {
					return nil, false, err
				}
				updated[i].Value = value
				changed = true
			}
		case op.Op != "insert" && len(segments) > 2:
			base := ruleSetDefinition(document, segments[1])
			if base == nil {
				continue
			}
			edited, ok := editedCopy(base, segments[2:], op)
			if !ok || downloadURL(edited) == "" || downloadURL(edited) == downloadURL(base) {
				continue
			}
			if err := p.definitionAsset(ctx, "rule-sets", edited, resources); err != nil {
				return nil, false, err
			}
			base["hash"] = edited["hash"]
		}
	}
	return updated, changed, nil
}

func ruleSetDefinition(document map[string]any, id string) map[string]any {
	definitions, _ := document["rule-sets"].([]any)
	for _, value := range definitions {
		if definition, _ := value.(map[string]any); definition != nil && definition["id"] == id {
			return definition
		}
	}
	return nil
}

func downloadURL(definition map[string]any) string {
	download, _ := definition["download"].(map[string]any)
	address, _ := download["url"].(string)
	return address
}

// editedCopy returns a copy of definition with a set or remove applied at
// path. It reports false when the edit cannot be applied.
func editedCopy(definition map[string]any, path []string, op model.Op) (map[string]any, bool) {
	raw, err := json.Marshal(definition)
	if err != nil {
		return nil, false
	}
	var edited map[string]any
	if json.Unmarshal(raw, &edited) != nil {
		return nil, false
	}
	parent := edited
	for _, segment := range path[:len(path)-1] {
		next, _ := parent[segment].(map[string]any)
		if next == nil {
			if op.Op == "remove" {
				return edited, true
			}
			next = map[string]any{}
			parent[segment] = next
		}
		parent = next
	}
	last := path[len(path)-1]
	switch op.Op {
	case "remove":
		delete(parent, last)
	case "set":
		var value any
		if json.Unmarshal(op.Value, &value) != nil {
			return nil, false
		}
		parent[last] = value
	default:
		return nil, false
	}
	return edited, true
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
			raw, err := marshalOverlay(patches)
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
