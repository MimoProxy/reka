// Package module converts locked Surge modules into native profile fragments.
package module

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

type Options struct {
	ID        string
	Arguments map[string]string
	// Resolve returns the effective policy ID on success. On failure a nonempty
	// string is a diagnostic message, such as an ambiguous display name.
	Resolve  func(policy string) (string, bool)
	Resource func(url string) (hash string, ok bool)
}

type Result struct {
	Rules           []model.Rule
	HTTPRewrites    []model.HTTPRewrite
	HeaderRewrites  []model.HeaderRewrite
	BodyRewrites    []model.BodyRewrite
	MapLocal        []model.MapLocal
	MITM            model.MITM
	InsertHostnames []Hostname
	AppendHostnames []Hostname
	ItemLines       map[string]int
	MITMLines       map[string]int
}

type Hostname struct {
	Value string
	Line  int
}

type Metadata struct {
	Name          string     `json:"name,omitempty"`
	Desc          string     `json:"desc,omitempty"`
	System        string     `json:"system,omitempty"`
	Category      string     `json:"category,omitempty"`
	Icon          string     `json:"icon,omitempty"`
	ArgumentsDesc string     `json:"arguments_desc,omitempty"`
	Arguments     []Argument `json:"arguments,omitempty"`
}

type Argument struct {
	Name        string `json:"name"`
	Default     string `json:"default"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

type Count struct {
	Total       int `json:"total"`
	Imported    int `json:"imported"`
	Unavailable int `json:"unavailable"`
}

type Report struct {
	Metadata
	ModuleID    string            `json:"module_id"`
	Format      string            `json:"format"`
	Partial     bool              `json:"partial"`
	CanApply    bool              `json:"can_apply"`
	Rules       Count             `json:"rules"`
	Rewrites    Count             `json:"rewrites"`
	Hostnames   Count             `json:"hostnames"`
	Lines       []Line            `json:"lines,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}

type Line struct {
	Line    int    `json:"line"`
	Section string `json:"section,omitempty"`
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

const (
	Supported   = "supported"
	Ignored     = "ignored"
	Unsupported = "unsupported"
	Error       = "error"
)

type outcome struct{ status, code, message string }

func unsupported(code, message string) outcome { return outcome{Unsupported, code, message} }
func ignored(code, message string) outcome     { return outcome{Ignored, code, message} }
func failed(code, message string) outcome      { return outcome{Error, code, message} }

func (o outcome) skips() bool { return o.status == Unsupported || o.status == Error }

func (r *Report) record(line int, section string, issue outcome) {
	if issue.status == "" {
		issue.status = Supported
	}
	r.Lines = append(r.Lines, Line{line, section, issue.status, issue.code, issue.message})
	switch issue.status {
	case Ignored, Unsupported:
		r.Partial = true
	case Error:
		r.CanApply = false
		r.Diagnostics = append(r.Diagnostics, model.Diagnostic{
			Severity: model.SeverityError, Code: issue.code, Message: issue.message,
			Document: model.DocSources, Line: line, Column: 1,
		})
	}
}

func (c *Count) record(imported bool) {
	c.Total++
	if imported {
		c.Imported++
	} else {
		c.Unavailable++
	}
}

type converter struct {
	result Result
	report Report
	opts   Options
	seen   map[string]int
}

// Convert parses a module using the supplied arguments and already available
// policies and resources. It performs no acquisition.
func Convert(text []byte, opts Options) (*Result, Report) {
	c := converter{
		result: Result{ItemLines: make(map[string]int), MITMLines: make(map[string]int)},
		report: Report{ModuleID: opts.ID, Format: model.ModuleFormatSurge, CanApply: true},
		opts:   opts,
		seen:   make(map[string]int),
	}
	metadata, warnings := scan(text, opts.Arguments, c.line)
	c.report.Metadata = metadata
	c.report.Diagnostics = append(c.report.Diagnostics, warnings...)
	return &c.result, c.report
}

func (c *converter) line(line int, section, raw, expanded string, issue outcome) {
	if !issue.skips() && issue.status != Ignored && section != "metadata" && !isSection(expanded) {
		issue = c.convertLine(line, section, raw, expanded)
	} else if issue.skips() {
		switch section {
		case "rule":
			c.report.Rules.record(false)
		case "url rewrite", "header rewrite", "body rewrite", "map local":
			c.report.Rewrites.record(false)
		}
	}
	c.report.record(line, section, issue)
}

func (c *converter) convertLine(line int, section, raw, expanded string) outcome {
	switch section {
	case "mitm":
		return c.mitm(line, expanded)
	case "rule":
		rule, issue := convertRule(raw, expanded, c.opts.Resolve)
		c.report.Rules.record(!issue.skips())
		if !issue.skips() {
			rule.ID = c.id("r", struct {
				Match    model.Match
				Outbound string
			}{rule.Match, rule.Outbound}, line)
			c.result.Rules = append(c.result.Rules, rule)
		}
		return issue
	case "url rewrite", "header rewrite", "body rewrite", "map local":
		issue := c.rewrite(line, section, expanded)
		c.report.Rewrites.record(!issue.skips())
		return issue
	case "general":
		return ignored("module.general", "modules cannot modify general settings")
	case "proxy", "proxy group":
		return ignored("module.proxy", "modules cannot define policies")
	case "replica":
		return ignored("module.replica", "modules cannot modify replica settings")
	case "ruleset", "rule set":
		return ignored("module.rule-set", "modules cannot define rule sets")
	case "host":
		return unsupported("module.host", "modules cannot change DNS host mappings")
	case "script", "panel", "mtproto", "ssid setting", "snell server":
		return unsupported("module.section", "this module section is not supported")
	default:
		if strings.HasPrefix(section, "ruleset ") {
			return ignored("module.rule-set", "modules cannot define rule sets")
		}
		if section == "wireguard" || strings.HasPrefix(section, "wireguard ") {
			return ignored("module.wireguard", "modules cannot define tunnel settings")
		}
		return unsupported("module.section", "unknown module section")
	}
}

func (c *converter) id(prefix string, value any, line int) string {
	canonical, _ := json.Marshal(value)
	sum := sha256.Sum256(canonical)
	id := prefix + "-" + hex.EncodeToString(sum[:12])
	c.seen[id]++
	if c.seen[id] > 1 {
		id += fmt.Sprintf("-%d", c.seen[id])
	}
	c.result.ItemLines[id] = line
	return id
}

func ptr[T any](v T) *T { return &v }
