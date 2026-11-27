package module

import (
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func inspectStash(text []byte, interval int) (Metadata, ResourceReferences) {
	root, _ := model.ParseNode(model.DocSources, text)
	fields, ok := stashMapping(root)
	if !ok {
		return Metadata{}, ResourceReferences{}
	}
	refs := newReferenceCollector(interval)
	providers := parseStashProviders(fields["script-providers"])
	for _, group := range stashScriptGroups(fields) {
		for _, item := range group.items {
			_, ref, issue := parseStashScript(item, providers, group.kind)
			if !issue.skips() {
				refs.script(ref)
			}
		}
	}
	if seq := stashSequence(fields["rules"]); seq != nil {
		for _, item := range seq.Content {
			if text, ok := stashString(item); ok {
				refs.ruleSet(text)
			}
		}
	}
	return stashMetadata(fields), refs.refs
}

// Stash script entries come from three places. Each selects a provider by name.
const (
	stashHTTPScript = "http"
	stashCronScript = "cron"
	stashTileScript = "tile"
)

type stashScriptGroup struct {
	kind  string
	items []*yaml.Node
}

func stashScriptGroups(fields map[string]*yaml.Node) []stashScriptGroup {
	var groups []stashScriptGroup
	http, _ := stashMapping(fields["http"])
	if scripts := stashSequence(http["script"]); scripts != nil {
		groups = append(groups, stashScriptGroup{stashHTTPScript, scripts.Content})
	}
	cron, _ := stashMapping(fields["cron"])
	if scripts := stashSequence(cron["script"]); scripts != nil {
		groups = append(groups, stashScriptGroup{stashCronScript, scripts.Content})
	}
	if tiles := stashSequence(fields["tiles"]); tiles != nil {
		groups = append(groups, stashScriptGroup{stashTileScript, tiles.Content})
	}
	return groups
}

// parseStashScript converts an http.script entry, a cron.script entry, or a
// tile. Tiles become generic scripts: Stash runs the tile script without a
// request and displays the object passed to $done.
func parseStashScript(node *yaml.Node, providers map[string]stashProvider, kind string) (model.Script, ScriptReference, outcome) {
	var script model.Script
	var ref ScriptReference
	fields, ok := stashMapping(node)
	if !ok {
		return script, ref, unsupported("module.script-syntax", "expected a script mapping with unique keys")
	}
	name, ok := stashString(fields["name"])
	if !ok || strings.TrimSpace(name) == "" {
		return script, ref, unsupported("module.script-provider", "the script requires a provider name")
	}
	provider, ok := providers[name]
	if !ok {
		return script, ref, unsupported("module.script-provider", "the script provider is not defined")
	}
	if provider.issue.skips() {
		return script, ref, provider.issue
	}
	settings := []scriptSetting{{"script-path", provider.url}}
	if provider.interval != "" {
		settings = append(settings, scriptSetting{"script-update-interval", provider.interval})
	}
	switch kind {
	case stashCronScript:
		settings = append(settings, scriptSetting{"type", "cron"})
	case stashTileScript:
		settings = append(settings, scriptSetting{"type", "generic"})
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		switch {
		case key == "name" || key == "debug":
			continue
		case kind == stashTileScript && stashTileDisplayKey(key):
			// Tile defaults and refresh interval belong to the client display.
			continue
		case key == "argument" || kind == stashHTTPScript && (key == "type" || key == "match") || kind == stashCronScript && key == "cron":
			text, ok := stashString(value)
			if !ok {
				return script, ref, unsupported("module.script-syntax", "expected a script setting string")
			}
			switch key {
			case "type":
				switch text = strings.ToLower(text); text {
				case "request", "response":
					text = "http-" + text
				default:
					return script, ref, unsupported("module.script-type", "only request and response scripts are supported")
				}
			case "match":
				key = "pattern"
			case "cron":
				key = "cronexp"
			}
			settings = append(settings, scriptSetting{key, text})
		case key == "timeout" || kind == stashHTTPScript && (key == "require-body" || key == "binary-mode" || key == "max-size"):
			text, ok := stashScriptScalar(value)
			if !ok {
				return script, ref, unsupported("module.script-syntax", "expected a boolean or numeric script setting")
			}
			switch key {
			case "require-body":
				key = "requires-body"
			case "binary-mode":
				key = "binary-body-mode"
			}
			settings = append(settings, scriptSetting{key, text})
		default:
			return script, ref, unsupported("module.script-setting", "unsupported script setting")
		}
	}
	return parseScriptFields(name, model.ModuleFormatStash, settings)
}

func stashTileDisplayKey(key string) bool {
	switch key {
	case "interval", "title", "content", "icon", "backgroundColor", "url", "collapsed":
		return true
	default:
		return false
	}
}

type stashProvider struct {
	url, interval string
	issue         outcome
}

func parseStashProviders(node *yaml.Node) map[string]stashProvider {
	fields, ok := stashMapping(node)
	if !ok {
		return nil
	}
	providers := make(map[string]stashProvider, len(fields))
	for name, provider := range fields {
		providers[name] = parseStashProvider(provider)
	}
	return providers
}

func parseStashProvider(node *yaml.Node) stashProvider {
	fields, ok := stashMapping(node)
	if !ok {
		return stashProvider{issue: unsupported("module.script-provider", "expected a script provider mapping with unique keys")}
	}
	for key := range fields {
		if key != "url" && key != "interval" {
			return stashProvider{issue: unsupported("module.script-provider", "unsupported script provider setting")}
		}
	}
	url, ok := stashString(fields["url"])
	if !ok || url == "" {
		return stashProvider{issue: unsupported("module.script-provider", "the script provider requires a URL")}
	}
	provider := stashProvider{url: url}
	if node := fields["interval"]; node != nil {
		if provider.interval, ok = stashScriptScalar(node); !ok || provider.interval == "" {
			return stashProvider{issue: unsupported("module.script-provider", "the script provider interval must be an integer")}
		}
	}
	return provider
}

func stashScriptScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	switch n.ShortTag() {
	case "!!str", "!!bool", "!!int":
		return n.Value, true
	default:
		return "", false
	}
}
