// Package model defines Reka's native configuration documents (the profile
// and local settings, source snapshots and overlay), parses them strictly with
// line, column and field-path diagnostics, and edits them structurally
// without losing comments.
package model

import (
	"fmt"
	"strings"
)

// Severity of a diagnostic.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Document names used in diagnostics and provenance.
const (
	DocProfile = "profile"
	DocLocal   = "local"
	DocSources = "sources"
	DocOverlay = "overlay"
)

// Diagnostic is one problem found while parsing, validating or compiling.
// Path uses stable IDs ("/outbounds/my-vps/port"); entries without an ID
// are addressed by position ("/rules/#3").
type Diagnostic struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Document string   `json:"document,omitempty"`
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Column   int      `json:"column,omitempty"`
}

func (d Diagnostic) String() string {
	var b strings.Builder
	if d.Document != "" {
		b.WriteString(d.Document)
	}
	if d.Line > 0 {
		fmt.Fprintf(&b, ":%d:%d", d.Line, d.Column)
	}
	if b.Len() > 0 {
		b.WriteString(": ")
	}
	b.WriteString(string(d.Severity))
	if d.Code != "" {
		b.WriteString(" [" + d.Code + "]")
	}
	if d.Path != "" {
		b.WriteString(" " + d.Path)
	}
	b.WriteString(": " + d.Message)
	return b.String()
}

// Diagnostics is a list of diagnostics.
type Diagnostics []Diagnostic

// HasErrors reports whether any diagnostic is an error.
func (ds Diagnostics) HasErrors() bool {
	for _, d := range ds {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Errors returns only the error diagnostics.
func (ds Diagnostics) Errors() Diagnostics {
	var out Diagnostics
	for _, d := range ds {
		if d.Severity == SeverityError {
			out = append(out, d)
		}
	}
	return out
}

func (ds Diagnostics) Error() string {
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.String()
	}
	return strings.Join(parts, "\n")
}

// Pos is a position in a source document.
type Pos struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Positions maps field paths to where their values are written.
type Positions map[string]Pos

// JoinPath appends segments to a path.
func JoinPath(base string, segs ...string) string {
	for _, s := range segs {
		base += "/" + escapeSeg(s)
	}
	return base
}

// escapeSeg escapes "/" and "~" in a path segment as JSON Pointer does.
func escapeSeg(s string) string {
	if !strings.ContainsAny(s, "/~") {
		return s
	}
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}

// SplitPath splits a path into unescaped segments.
func SplitPath(p string) ([]string, error) {
	if p == "" || p == "/" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("path %q must start with /", p)
	}
	segs := strings.Split(p[1:], "/")
	r := strings.NewReplacer("~1", "/", "~0", "~")
	for i, s := range segs {
		segs[i] = r.Replace(s)
	}
	return segs, nil
}
