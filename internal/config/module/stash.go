package module

import (
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func (c *converter) convertStash(text []byte) {
	root, diags := model.ParseNode(model.DocSources, text)
	for _, diagnostic := range diags {
		c.report.record(diagnostic.Line, "", failed(diagnostic.Code, diagnostic.Message))
	}
	if root == nil {
		return
	}
	fields, ok := stashMapping(root)
	if !ok {
		c.report.record(root.Line, "", failed("yaml.mapping", "expected unique YAML mapping keys"))
		return
	}
	providers := parseStashProviders(fields["script-providers"])
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		switch key.Value {
		case "http":
			c.stashHTTP(key.Line, value, providers)
		case "rules":
			if seq := stashSequence(value); seq != nil {
				for _, item := range seq.Content {
					var rule model.Rule
					issue := unsupported("module.rule-syntax", "expected a rule string")
					if text, ok := stashString(item); ok {
						rule, issue = convertRule(text, text, c.opts.Resolve)
					}
					c.report.record(item.Line, "rules", c.addRule(item.Line, rule, issue))
				}
			} else {
				c.report.record(key.Line, "rules", stashExpectedList())
			}
		case "script-providers":
			if providers == nil {
				c.report.record(key.Line, key.Value, unsupported("module.script-provider", "expected a mapping of script providers with unique names"))
				continue
			}
			for i := 0; i < len(value.Content); i += 2 {
				providerName := value.Content[i]
				c.report.record(providerName.Line, key.Value, providers[providerName.Value].issue)
			}
		case "name", "desc", "icon", "category":
			issue := outcome{}
			if _, ok := stashString(value); !ok {
				issue = unsupported("module.metadata", "expected a metadata string")
			}
			c.report.record(key.Line, key.Value, issue)
		default:
			c.report.record(key.Line, key.Value, stashTopLevel(key.Value))
		}
	}
	c.report.Metadata = stashMetadata(fields)
}

func stashMetadata(fields map[string]*yaml.Node) Metadata {
	name, _ := stashString(fields["name"])
	desc, _ := stashString(fields["desc"])
	icon, _ := stashString(fields["icon"])
	category, _ := stashString(fields["category"])
	return Metadata{Name: name, Desc: desc, Icon: icon, Category: category}
}

func stashTopLevel(key string) outcome {
	switch key {
	case "author", "homepage", "date", "raw-url", "tg-channel", "openUrl", "open-url", "tag", "tags", "version", "license", "system",
		"author-url", "description", "repository", "url":
		return outcome{Supported, "module.metadata", "metadata is informational only"}
	case "arguments", "arguments-version":
		return unsupported("module.arguments", "Stash arguments are not supported")
	case "rule-providers":
		return ignored("module.rule-set", "modules cannot define rule sets")
	case "proxies", "proxy-groups", "proxy-providers":
		return ignored("module.proxy", "modules cannot define policies")
	case "dns", "hosts":
		return unsupported("module.host", "modules cannot change DNS settings")
	case "cron", "tiles":
		return ignored("module.script-type", "modules support only request and response scripts")
	case "external-controller", "secret", "mode", "log-level", "tun", "mixed-port", "port", "socks-port", "allow-lan", "bind-address", "ipv6":
		return ignored("module.general", "modules cannot modify general settings")
	default:
		return unsupported("module.section", "unknown module field")
	}
}

func (c *converter) stashHTTP(line int, node *yaml.Node, providers map[string]stashProvider) {
	if _, ok := stashMapping(node); !ok {
		c.report.record(line, "http", unsupported("module.section", "expected an HTTP mapping with unique keys"))
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		section := "http." + key.Value
		switch key.Value {
		case "mitm", "url-rewrite", "header-rewrite", "body-rewrite", "mock", "script":
			if seq := stashSequence(value); seq != nil {
				c.stashHTTPItems(section, key.Value, seq.Content, providers)
			} else {
				c.report.record(key.Line, section, stashExpectedList())
			}
		case "force-http-engine", "rewrite", "ca", "ca-passphrase":
			c.report.record(key.Line, section, ignored("module.http-setting", "this HTTP setting is ignored"))
		default:
			c.report.record(key.Line, section, unsupported("module.http-setting", "unknown HTTP setting"))
		}
	}
}

func (c *converter) stashHTTPItems(section, key string, nodes []*yaml.Node, providers map[string]stashProvider) {
	var hostnamePrefix string
	for _, node := range nodes {
		var issue outcome
		switch key {
		case "mitm":
			host, _ := stashString(node)
			host = strings.TrimSpace(host)
			switch upper := strings.ToUpper(host); upper {
			case "%APPEND%", "%INSERT%":
				// A standalone directive selects the mode of subsequent entries.
				hostnamePrefix = upper + " "
			default:
				rest := strings.TrimPrefix(strings.TrimPrefix(upper, "%APPEND%"), "%INSERT%")
				if strings.Trim(rest, ", \t\r\n") == "" {
					c.report.Hostnames.record(false)
					issue = unsupported("module.mitm-syntax", "expected a MITM hostname string")
					break
				}
				if rest == upper {
					host = hostnamePrefix + host
				}
				issue = c.mitm(node.Line, "hostname="+host)
			}
		case "script":
			script, ref, parsed := parseStashScript(node, providers)
			issue = parsed
			if !issue.skips() {
				issue = c.addScript(node.Line, script, ref)
			}
			c.report.Scripts.record(!issue.skips())
		default:
			issue = c.stashRewrite(node, key)
			c.report.Rewrites.record(!issue.skips())
		}
		c.report.record(node.Line, section, issue)
	}
}

func stashExpectedList() outcome {
	return unsupported("module.section", "expected a list of module entries")
}

// Read literal YAML nodes to retain source locations and avoid alias expansion.
func stashString(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", false
	}
	return n.Value, true
}

func stashSequence(n *yaml.Node) *yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n
}

func stashMapping(n *yaml.Node) (map[string]*yaml.Node, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	fields := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || fields[key.Value] != nil {
			return nil, false
		}
		fields[key.Value] = n.Content[i+1]
	}
	return fields, true
}
