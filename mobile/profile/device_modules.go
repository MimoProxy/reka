package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (b *Bundle) mergeDeviceModules(document map[string]any, profile *model.Profile, options PrepareOptions) ([]ModuleSummary, error) {
	var shadowed []ModuleSummary
	if options.DeviceModules == nil {
		for _, entry := range b.Summary.Modules {
			if entry.Shadowed {
				shadowed = append(shadowed, entry)
			}
		}
		return shadowed, nil
	}

	// Preserve the profile's own declarations as they appear in the document.
	definitions, _ := document["modules"].([]any)
	removed := len(b.DeviceModules) > 0
	if removed {
		if len(definitions) != len(profile.Modules) {
			return nil, errors.New("invalid archived modules")
		}
		kept := 0
		for i, def := range profile.Modules {
			if !slices.Contains(b.DeviceModules, def.ID) {
				definitions[kept], profile.Modules[kept] = definitions[i], def
				kept++
			}
		}
		definitions, profile.Modules = definitions[:kept], profile.Modules[:kept]
		b.DeviceModules = nil
	}
	if len(options.DeviceModules) == 0 && !removed {
		return nil, nil
	}

	sourceIDs, err := b.sourceIDs(profile, options.Sources)
	if err != nil {
		return nil, err
	}
	profileIDs := make(map[string]bool, len(profile.Modules))
	for _, def := range profile.Modules {
		profileIDs[def.ID] = true
	}
	deviceIDs := make(map[string]bool, len(options.DeviceModules))
	for _, def := range options.DeviceModules {
		if profileIDs[def.ID] {
			shadowed = append(shadowed, ModuleSummary{ID: def.ID, Origin: "device", Enabled: def.IsEnabled(), Shadowed: true})
			continue
		}
		if sourceIDs[def.ID] {
			return nil, deviceModuleError(def.ID, "module.source-conflict", "module id is already used by a source")
		}
		if deviceIDs[def.ID] {
			return nil, deviceModuleError(def.ID, "module.duplicate", "duplicate device module id")
		}
		if err := model.ValidModule(&def); err != nil {
			return nil, deviceModuleError(def.ID, "module.definition", err.Error())
		}
		deviceIDs[def.ID] = true
		b.DeviceModules = append(b.DeviceModules, def.ID)
		profile.Modules = append(profile.Modules, def)
		definitions = append(definitions, def)
	}
	if len(definitions) > 0 {
		document["modules"] = definitions
	} else if removed {
		delete(document, "modules")
	}
	return shadowed, nil
}

func (b *Bundle) sourceIDs(profile *model.Profile, paths map[string]string) (map[string]bool, error) {
	ids := make(map[string]bool)
	for id := range paths {
		ids[id] = true
	}
	for _, imp := range profile.Imports {
		ids[imp.Source] = true
	}
	if profile.DNS != nil && profile.DNS.From != "" {
		ids[profile.DNS.From] = true
	}
	for _, rule := range profile.Rules {
		if rule.Source != "" {
			ids[rule.Source] = true
		}
	}
	if len(b.Sources) > 0 {
		var archived sourceDocument
		if json.Unmarshal(b.Sources, &archived) != nil {
			return nil, errors.New("invalid archived sources")
		}
		for _, entry := range archived.Sources {
			var source sourceResources
			if json.Unmarshal(entry, &source) != nil {
				return nil, errors.New("invalid archived source")
			}
			if source.Module == nil {
				ids[source.ID] = true
			}
		}
	}
	return ids, nil
}

func deviceModuleError(id, code, message string) *ValidationError {
	return &ValidationError{fmt.Sprintf("Device module %q: %s", id, message), model.Diagnostics{{
		Severity: model.SeverityError, Code: code, Document: model.DocProfile,
		Path: model.JoinPath("/modules", id), Message: message,
	}}}
}
