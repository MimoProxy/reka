package compile

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	scriptapi "github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/cron"
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
	ArgumentType   string `json:"argument-type,omitempty"`
	CronExp        string `json:"cronexp,omitempty"`
	EventName      string `json:"event-name,omitempty"`
	WakeSystem     *bool  `json:"wake-system,omitempty"`
	Engine         string `json:"engine"`
	Format         string `json:"format"`
	Hash           string `json:"hash,omitempty"`
	Path           string `json:"-"` // Default persistent store scope; may contain credentials.
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
		if keepScriptReader && ent.Supported {
			eff.readScriptSource = c.opts.ReadResource
		}
	}
	eff.ScriptFingerprint = fingerprint(c.profile.Scripts)
}

func (c *compiler) compileScript(def model.Script, path string) Script {
	const doc = model.DocProfile
	script := Script{
		ID: def.ID, Name: valueOr(def.Name, ""), Type: def.Type, Pattern: valueOr(def.Pattern, ""),
		RequiresBody: valueOr(def.RequiresBody, false), BinaryBodyMode: valueOr(def.BinaryBodyMode, false),
		Timeout: valueOr(def.Timeout, model.DefaultScriptTimeout), Argument: valueOr(def.Argument, ""),
		ArgumentType: valueOr(def.ArgumentType, ""),
		CronExp:      valueOr(def.CronExp, ""), EventName: strings.TrimSpace(valueOr(def.EventName, "")), WakeSystem: def.WakeSystem,
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
	case "cron":
		script.Supported = true
		if _, err := cron.Parse(script.CronExp); err != nil {
			c.errorf(doc, path+"/cronexp", "script.cronexp", "%v", err)
		}
	case "generic":
		script.Supported = true
	case "event":
		switch script.EventName {
		case "":
			c.errorf(doc, path+"/event-name", "script.event-name", "event scripts require an event name")
		case "network-changed":
			script.Supported = true
		default:
			c.warnf(doc, path+"/event-name", "script.unsupported-event", "script event %q is not supported", script.EventName)
		}
	case "dns", "rule":
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
	if !model.ValidModuleFormat(script.Format) {
		c.errorf(doc, path+"/format", "script.format", "format must be surge, loon or stash")
	}
	switch valueOr(def.ArgumentType, "string") {
	case "string":
	case "object":
		if _, err := scriptapi.ParseArgumentObject(def.Argument); err != nil {
			c.errorf(doc, path+"/argument", "script.argument", "%v", err)
		}
	default:
		c.errorf(doc, path+"/argument-type", "script.argument-type", "argument-type must be string or object")
	}
	if def.Download != nil {
		script.Path = def.Download.URL
		if err := model.ValidResourceDownload(def.Download.WithDefaultInterval()); err != nil {
			c.errorf(doc, path+"/download", "resource.download", "%v", err)
		}
	}
	if def.File != nil {
		if def.Download != nil {
			c.errorf(doc, path+"/file", "script.source", "specify at most one script download or file")
		} else if !model.ValidScriptFile(*def.File) {
			c.errorf(doc, path+"/file", "script.file", "script file must be an absolute local path without NUL")
		} else {
			script.Path = *def.File
		}
	}
	if script.Path == "" {
		script.Path = script.ID
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
	if _, err := readScriptSource(c.opts.ReadResource, hash); err != nil {
		c.errorf(doc, path, code, "%v", err)
	}
}

// ScriptSource loads a locked script resource for execution.
func (e *Effective) ScriptSource(hash string) ([]byte, error) {
	if e.readScriptSource == nil || !resource.ValidHash(hash) {
		return nil, errors.New("script source unavailable")
	}
	return readScriptSource(e.readScriptSource, hash)
}

func readScriptSource(read func(string) ([]byte, error), hash string) ([]byte, error) {
	data, err := read(hash)
	switch {
	case err != nil:
		return nil, fmt.Errorf("read script resource: %w", err)
	case len(data) == 0:
		return nil, errors.New("script source is empty")
	case len(data) > model.MaxScriptSize:
		return nil, fmt.Errorf("script source exceeds %d bytes", model.MaxScriptSize)
	case resource.Hash(data) != hash:
		return nil, errors.New("script resource hash mismatch")
	}
	return data, nil
}
