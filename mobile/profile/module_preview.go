package profile

import (
	"context"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
)

// ModuleInput accepts exactly one of text, file (raw module), or snapshot
// (acquired JSON). A snapshot supplies its arguments by default.
type ModuleInput struct {
	Text      *string           `json:"text,omitempty"`
	File      string            `json:"file,omitempty"`
	Snapshot  string            `json:"snapshot,omitempty"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type ModulePreviewRequest struct {
	ModuleInput
	ProfileSnapshot string `json:"profileSnapshot,omitempty"`
}

type ModulePreviewResult struct {
	Report    module.Report   `json:"report"`
	Hostnames ModuleHostnames `json:"hostnames"`
}

// ModuleHostnames retains the order and placement of the converted names.
type ModuleHostnames struct {
	Insert []string `json:"insert"`
	Append []string `json:"append"`
}

// PreviewModule converts a module with the supplied arguments and optionally
// resolves rule policies using an existing prepared profile. It uses only
// locked Map Local and script resources from an acquired module snapshot.
func PreviewModule(ctx context.Context, req ModulePreviewRequest, secrets secret.Store) (ModulePreviewResult, error) {
	text, opts, err := readModuleInput(ctx, req.ModuleInput)
	if err != nil {
		return ModulePreviewResult{}, err
	}
	if req.ProfileSnapshot != "" {
		eff, err := compilePreparedSnapshot(ctx, req.ProfileSnapshot, secrets)
		if err != nil {
			return ModulePreviewResult{}, err
		}
		opts.Resolve = eff.ModulePolicyResolver()
	}
	result, report := module.Convert(text, opts)
	if err := ctx.Err(); err != nil {
		return ModulePreviewResult{}, err
	}
	return ModulePreviewResult{Report: report, Hostnames: moduleHostnames(result)}, nil
}

// InspectModule reads the module's metadata and argument declarations.
func InspectModule(ctx context.Context, input ModuleInput) (module.Metadata, error) {
	text, opts, err := readModuleInput(ctx, input)
	if err != nil {
		return module.Metadata{}, err
	}
	metadata, _ := module.Inspect(text, opts.Arguments)
	if err := ctx.Err(); err != nil {
		return module.Metadata{}, err
	}
	return metadata, nil
}

func readModuleInput(ctx context.Context, input ModuleInput) ([]byte, module.Options, error) {
	if err := ctx.Err(); err != nil {
		return nil, module.Options{}, err
	}
	opts := module.Options{Arguments: input.Arguments}
	switch {
	case input.Text != nil && input.File == "" && input.Snapshot == "":
		if len(*input.Text) > model.MaxDocumentSize {
			return nil, opts, &subscription.Error{Code: "module_text_too_large"}
		}
		return []byte(*input.Text), opts, nil
	case input.Text == nil && input.File != "" && input.Snapshot == "":
		text, err := moduleacquire.ReadFile(input.File, model.MaxDocumentSize)
		return text, opts, err
	case input.Text == nil && input.File == "" && input.Snapshot != "":
		snapshot, err := LoadModuleSnapshot(input.Snapshot)
		if err != nil {
			return nil, opts, err
		}
		opts.ID, opts.ResourceForKind = snapshot.Source.ID, snapshot.resourceResolver()
		if opts.Arguments == nil {
			opts.Arguments = snapshot.Arguments
		}
		return snapshot.readRoot(), opts, nil
	default:
		return nil, opts, &subscription.Error{Code: "module_input_invalid"}
	}
}

func moduleHostnames(result *module.Result) ModuleHostnames {
	hosts := ModuleHostnames{
		Insert: make([]string, 0, len(result.InsertHostnames)),
		Append: make([]string, 0, len(result.AppendHostnames)),
	}
	for _, host := range result.InsertHostnames {
		hosts.Insert = append(hosts.Insert, host.Value)
	}
	for _, host := range result.AppendHostnames {
		hosts.Append = append(hosts.Append, host.Value)
	}
	return hosts
}
