package compile

import (
	"regexp/syntax"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

// Script is a validated script definition. Hash is the locked source reference.
type Script struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Type           string `json:"type"`
	Supported      bool   `json:"supported"`
	Pattern        string `json:"pattern,omitempty"`
	RequiresBody   bool   `json:"requires-body"`
	BinaryBodyMode bool   `json:"binary-body-mode"`
	MaxSize        int64  `json:"max-size"`
	Timeout        int    `json:"timeout"` // Seconds.
	Argument       string `json:"argument,omitempty"`
	Engine         string `json:"engine"`
	Format         string `json:"format"`
	Hash           string `json:"hash,omitempty"`
	Module         string `json:"module,omitempty"`
	Origin         Origin `json:"origin"`
}

// Check duplicates before an overlay can remove one of the conflicting entries.
func (c *compiler) checkProfileScriptDuplicates() {
	seen := make(map[string]bool, len(c.profile.Scripts))
	for i, script := range c.profile.Scripts {
		if script.ID == "" {
			continue
		}
		if seen[script.ID] {
			path := model.JoinPath("/scripts", seg(script.ID, i), "id")
			c.errorf(model.DocProfile, path, "schema.duplicate-id", "duplicate script id %q", script.ID)
		}
		seen[script.ID] = true
	}
}

func (c *compiler) scripts(eff *Effective) {
	if len(c.profile.Scripts) == 0 {
		return
	}
	eff.Scripts = make([]Script, 0, len(c.profile.Scripts))
	for i, def := range c.profile.Scripts {
		path := model.JoinPath("/scripts", seg(def.ID, i))
		if def.ID == "" {
			c.errorf(model.DocProfile, path+"/id", "schema.id", "id is required")
		} else {
			c.checkID(model.DocProfile, path, def.ID)
		}
		ent := c.compileScript(def, path)
		if origin, ok := c.origins[path]; ok {
			ent.Origin = origin
			for origin.Layer == LayerOverlay && origin.Overrides != nil {
				origin = *origin.Overrides
			}
			if origin.Layer == LayerModule {
				ent.Module = origin.Source
			}
		} else {
			pos := c.ppos[path]
			ent.Origin = Origin{Layer: LayerProfile, Document: model.DocProfile, Path: path, Line: pos.Line, Column: pos.Column}
		}
		eff.Scripts = append(eff.Scripts, ent)
	}
	eff.ScriptFingerprint = fingerprint(c.profile.Scripts)
}

func (c *compiler) compileScript(def model.Script, path string) Script {
	const doc = model.DocProfile
	script := Script{
		ID: def.ID, Name: valueOr(def.Name, ""), Type: def.Type, Pattern: valueOr(def.Pattern, ""),
		RequiresBody: valueOr(def.RequiresBody, false), BinaryBodyMode: valueOr(def.BinaryBodyMode, false),
		Timeout: valueOr(def.Timeout, model.DefaultScriptTimeout), Argument: valueOr(def.Argument, ""),
		Engine: valueOr(def.Engine, "auto"), Format: valueOr(def.Format, "surge"), Hash: valueOr(def.Hash, ""),
	}
	switch script.Type {
	case "http-request", "http-response":
		script.Supported = true
		if script.Pattern == "" {
			c.errorf(doc, path+"/pattern", "script.pattern", "HTTP scripts require a URL pattern")
		} else if _, err := syntax.Parse(script.Pattern, syntax.Perl); err != nil {
			c.errorf(doc, path+"/pattern", "script.pattern", "invalid RE2 pattern: %v", err)
		}
	case "cron", "generic", "event", "dns", "rule":
		c.warnf(doc, path+"/type", "script.unsupported-type", "script type %q is not supported", script.Type)
	default:
		c.errorf(doc, path+"/type", "script.type", "invalid script type %q", script.Type)
	}
	maxSize := valueOr(def.MaxSize, int64(ScriptDefaultMaxSize))
	switch {
	case maxSize < -1:
		c.errorf(doc, path+"/max-size", "script.max-size", "max-size must be -1, 0 or a positive byte count")
	case maxSize <= 0:
		maxSize = ScriptMaxBodySize
	}
	script.MaxSize = min(maxSize, ScriptMaxBodySize)
	if script.Timeout < 1 || script.Timeout > model.MaxScriptTimeout {
		c.errorf(doc, path+"/timeout", "script.timeout", "timeout must be 1–%d seconds", model.MaxScriptTimeout)
	}
	switch script.Engine {
	case "auto", "jsc", "webview":
	default:
		c.errorf(doc, path+"/engine", "script.engine", "engine must be auto, jsc or webview")
	}
	switch script.Format {
	case "surge", "loon", "stash":
	default:
		c.errorf(doc, path+"/format", "script.format", "format must be surge, loon or stash")
	}
	if def.Download != nil {
		if err := model.ValidResourceDownload(def.Download.WithDefaultInterval()); err != nil {
			c.errorf(doc, path+"/download", "resource.download", "%v", err)
		}
	}
	if def.File != nil {
		if def.Download != nil {
			c.errorf(doc, path+"/file", "script.source", "specify at most one script download or file")
		} else if !model.ValidScriptFile(*def.File) {
			c.errorf(doc, path+"/file", "script.file", "script file must be an absolute local path without NUL")
		}
	}
	if script.Supported || def.Hash != nil {
		c.validateScriptResource(path+"/hash", script.Hash)
	}
	return script
}

func valueOr[T any](value *T, fallback T) T {
	if value != nil {
		return *value
	}
	return fallback
}

func (c *compiler) validateScriptResource(path, hash string) {
	const doc, code = model.DocProfile, "script.resource"
	if !resource.ValidHash(hash) || c.opts.ReadResource == nil {
		c.errorf(doc, path, code, "script requires a locked resource hash")
		return
	}
	data, err := c.opts.ReadResource(hash)
	switch {
	case err != nil:
		c.errorf(doc, path, code, "read script resource: %v", err)
	case len(data) == 0:
		c.errorf(doc, path, code, "script source is empty")
	case len(data) > model.MaxScriptSize:
		c.errorf(doc, path, code, "script source exceeds %d bytes", model.MaxScriptSize)
	case resource.Hash(data) != hash:
		c.errorf(doc, path, code, "script resource hash mismatch")
	}
}
