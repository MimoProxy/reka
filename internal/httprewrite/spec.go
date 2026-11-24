// Package httprewrite evaluates HTTP rewrite rules without performing forwarding.
package httprewrite

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/itchyny/gojq"
	"golang.org/x/net/http/httpguts"
)

const (
	// DefaultMaxBodySize follows Surge's iOS limit for modifiable bodies.
	DefaultMaxBodySize = 1 << 20
	// DesktopMaxBodySize follows Surge's macOS limit for modifiable bodies.
	DesktopMaxBodySize = 10 << 20
	// MaxMapLocalSize follows Surge's documented iOS Map Local URL data limit.
	MaxMapLocalSize = 15 << 20
)

// Options configures evaluation. A nonpositive MaxBodySize uses DefaultMaxBodySize.
type Options struct {
	MaxBodySize int64
	// ReadResource, if provided, must support concurrent calls. Returned bytes
	// are handed to the caller of Request and are not retained by the Set.
	ReadResource func(hash string) ([]byte, error)
}

// Spec holds each list in evaluation order. Pointer fields distinguish omission
// from explicit empty values.
type Spec struct {
	HTTPRewrites   []HTTPRewrite
	HeaderRewrites []HeaderRewrite
	BodyRewrites   []BodyRewrite
	MapLocal       []MapLocal
}

type HTTPRewrite struct {
	ID, Match, Action string
	Target, Response  *string
}

type HeaderRewrite struct {
	ID, Match, Op, Name   string
	Phase, Pattern, Value *string
}

type BodyRewrite struct {
	ID, Phase, Match string
	Replace          []Replacement
	JQ               *string
}

type Replacement struct {
	Pattern, Value *string
}

type MapLocal struct {
	ID, Match                         string
	DataType, Data, Hash, DownloadURL *string
	StatusCode                        *int
	Headers                           []Header
}

type Header struct {
	Name  string
	Value *string
}

// ValidationError identifies the resource kind, zero-based list index and field
// path of an invalid value or warning.
type ValidationError struct {
	Kind  string
	Index int
	Field string
	Err   error
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s[%d].%s: %v", e.Kind, e.Index, e.Field, e.Err)
}

func (e ValidationError) Unwrap() error { return e.Err }

// ValidationErrors contains all errors found in a Spec.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var out strings.Builder
	for i, issue := range e {
		if i > 0 {
			out.WriteString("\n")
		}
		out.WriteString(issue.Error())
	}
	return out.String()
}

// New validates a set and prepares its indexes without compiling any RE2
// program. An empty spec yields a nil set.
func New(spec Spec, opts Options) (*Set, error) {
	if len(spec.HTTPRewrites)+len(spec.HeaderRewrites)+len(spec.BodyRewrites)+len(spec.MapLocal) == 0 {
		return nil, nil
	}
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = DefaultMaxBodySize
	}
	s := &Set{
		opts:     opts,
		http:     make([]urlRule, 0, len(spec.HTTPRewrites)),
		mapLocal: make([]mapRule, 0, len(spec.MapLocal)),
	}
	var errs ValidationErrors
	v := validator{errs: &errs, warnings: &s.warnings}
	for i, r := range spec.HTTPRewrites {
		v.kind, v.index = "http-rewrites", i
		s.addURLRule(r, v)
	}
	for i, r := range spec.HeaderRewrites {
		v.kind, v.index = "header-rewrites", i
		s.addHeaderRule(r, v)
	}
	for i, r := range spec.BodyRewrites {
		v.kind, v.index = "body-rewrites", i
		s.addBodyRule(r, v)
	}
	for i, r := range spec.MapLocal {
		v.kind, v.index = "map-local", i
		s.addMapRule(r, v)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return s, nil
}

// ReuseCompiled returns a set that evaluates s's rules with the expressions
// already compiled by prev, which must come from the same definitions. The
// result keeps s's options, so a resource reader for another profile's store
// is not carried over.
func (s *Set) ReuseCompiled(prev *Set) *Set {
	if s == nil || prev == nil || s == prev {
		return s
	}
	reused := *prev
	reused.opts = s.opts
	reused.warnings = s.warnings
	return &reused
}

// Warnings returns nonfatal validation diagnostics, such as missing captures.
func (s *Set) Warnings() []ValidationError {
	if s == nil {
		return nil
	}
	return slices.Clone(s.warnings)
}

type validator struct {
	errs     *ValidationErrors
	warnings *[]ValidationError
	kind     string
	index    int
}

func (v validator) fail(field string, format string, args ...any) {
	*v.errs = append(*v.errs, ValidationError{Kind: v.kind, Index: v.index, Field: field, Err: fmt.Errorf(format, args...)})
}

func (v validator) regexp(field string, pattern *string) (*lazyRegexp, *syntax.Regexp) {
	if pattern == nil {
		v.fail(field, "is required")
		return nil, nil
	}
	re, parsed, err := newLazyRegexp(*pattern)
	if err != nil {
		v.fail(field, "invalid regular expression: %v", err)
	}
	return re, parsed
}

func (v validator) match(pattern string) (*lazyRegexp, *syntax.Regexp) {
	if pattern == "" {
		v.fail("match", "is required")
		return nil, nil
	}
	return v.regexp("match", &pattern)
}

func (v validator) template(field string, value *string, parsed *syntax.Regexp) string {
	if value == nil {
		v.fail(field, "is required")
		return ""
	}
	if parsed == nil {
		return *value
	}
	maxCapture := parsed.MaxCap()
	var warned [100]bool
	return normalizeTemplate(*value, func(capture int) {
		if capture > maxCapture && !warned[capture] {
			warned[capture] = true
			*v.warnings = append(*v.warnings, ValidationError{
				Kind: v.kind, Index: v.index, Field: field,
				Err: fmt.Errorf("capture $%d exceeds the %d capture groups in the regular expression", capture, maxCapture),
			})
		}
	})
}

func (s *Set) addURLRule(r HTTPRewrite, v validator) {
	re, parsed := v.match(r.Match)
	rule := urlRule{id: r.ID, match: re, action: r.Action}
	switch r.Action {
	case "header", "302", "307":
		rule.target = v.template("target", r.Target, parsed)
		if r.Response != nil {
			v.fail("response", "is only allowed for reject")
		}
	case "reject":
		if r.Target != nil {
			v.fail("target", "is not allowed for reject")
		}
		rule.response = "error"
		if r.Response != nil {
			rule.response = *r.Response
		}
		switch rule.response {
		case "close", "error", "200", "gif", "dict", "array", "drop":
		default:
			v.fail("response", "must be close, error, 200, gif, dict, array, or drop")
		}
	default:
		v.fail("action", "must be header, 302, 307, or reject")
	}
	if parsed != nil {
		s.httpIndex.add(len(s.http), parsed)
		s.http = append(s.http, rule)
	}
}

func (v validator) phase(phase string) (rewritePhase, bool) {
	switch phase {
	case "request":
		return requestPhase, true
	case "response":
		return responsePhase, true
	default:
		v.fail("phase", "must be request or response")
		return requestPhase, false
	}
}

func (s *Set) addHeaderRule(r HeaderRewrite, v validator) {
	phase := requestPhase
	validPhase := true
	if r.Phase != nil {
		phase, validPhase = v.phase(*r.Phase)
	}
	re, parsed := v.match(r.Match)
	rule := headerRule{id: r.ID, match: re, op: r.Op, name: v.headerName("name", r.Name)}
	switch r.Op {
	case "del":
		if r.Pattern != nil {
			v.fail("pattern", "is not allowed for del")
		}
		if r.Value != nil {
			v.fail("value", "is not allowed for del")
		}
	case "add", "replace":
		if r.Pattern != nil {
			v.fail("pattern", "is only allowed for replace-regex")
		}
		rule.value = v.template("value", r.Value, parsed)
	case "replace-regex":
		var pattern *syntax.Regexp
		rule.pattern, pattern = v.regexp("pattern", r.Pattern)
		rule.value = v.template("value", r.Value, pattern)
	default:
		v.fail("op", "must be add, del, replace, or replace-regex")
	}
	if r.Value != nil && !httpguts.ValidHeaderFieldValue(*r.Value) {
		v.fail("value", "invalid HTTP header field value")
	}
	if parsed != nil && validPhase {
		s.headerIndex[phase].add(len(s.header[phase]), parsed)
		s.header[phase] = append(s.header[phase], rule)
	}
}

func (s *Set) addBodyRule(r BodyRewrite, v validator) {
	phase, validPhase := v.phase(r.Phase)
	re, parsed := v.match(r.Match)
	rule := bodyRule{id: r.ID, match: re}
	if (r.Replace == nil) == (r.JQ == nil) {
		v.fail("replace", "specify exactly one of replace and jq")
	}
	if r.Replace != nil {
		if len(r.Replace) == 0 {
			v.fail("replace", "must contain at least one replacement")
		}
		rule.replace = make([]bodyReplacement, 0, len(r.Replace))
		for i, pair := range r.Replace {
			prefix := fmt.Sprintf("replace/#%d/", i)
			re, pattern := v.regexp(prefix+"pattern", pair.Pattern)
			value := v.template(prefix+"value", pair.Value, pattern)
			rule.replace = append(rule.replace, bodyReplacement{pattern: re, value: value})
		}
	}
	if r.JQ != nil {
		query, err := gojq.Parse(*r.JQ)
		if err == nil {
			// The default compiler exposes no environment values or input iterator.
			rule.jq, err = gojq.Compile(query)
		}
		if err != nil {
			v.fail("jq", "invalid jq expression: %v", err)
		}
	}
	if parsed != nil && validPhase {
		s.bodyIndex[phase].add(len(s.body[phase]), parsed)
		s.body[phase] = append(s.body[phase], rule)
	}
}

func (s *Set) addMapRule(r MapLocal, v validator) {
	re, parsed := v.match(r.Match)
	rule := mapRule{id: r.ID, match: re, statusCode: http.StatusOK, header: make(http.Header)}
	if r.StatusCode != nil {
		rule.statusCode = *r.StatusCode
		if rule.statusCode < 100 || rule.statusCode > 999 {
			v.fail("status-code", "must be between 100 and 999")
		}
	}
	for i, header := range r.Headers {
		prefix := fmt.Sprintf("headers/#%d/", i)
		name := v.headerName(prefix+"name", header.Name)
		if header.Value == nil {
			v.fail(prefix+"value", "is required")
		} else if !httpguts.ValidHeaderFieldValue(*header.Value) {
			v.fail(prefix+"value", "invalid HTTP header field value")
		} else {
			rule.header.Add(name, *header.Value)
		}
	}
	kind := "file"
	if r.DataType != nil {
		kind = *r.DataType
	}
	if kind != "file" {
		if r.Hash != nil {
			v.fail("hash", "is only allowed for file")
		}
		if r.DownloadURL != nil {
			v.fail("download", "is only allowed for file")
		}
	}
	var contentType string
	switch kind {
	case "file":
		if r.Hash == nil || *r.Hash == "" {
			v.fail("hash", "is required for file")
		} else {
			rule.hash = *r.Hash
		}
		contentType = fileContentType(r.DownloadURL)
		if r.Data != nil {
			v.fail("data", "is not allowed for file")
		}
	case "tiny-gif":
		contentType = "image/gif"
		rule.data = []byte(tinyGIF)
		if r.Data != nil {
			v.fail("data", "is not allowed for tiny-gif")
		}
	case "text", "json", "base64":
		contentType = v.mapData(kind, r.Data, &rule)
	default:
		v.fail("data-type", "must be file, text, json, tiny-gif, or base64")
	}
	if _, ok := rule.header["Content-Type"]; !ok {
		rule.header.Set("Content-Type", contentType)
	}
	if parsed != nil {
		s.mapIndex.add(len(s.mapLocal), parsed)
		s.mapLocal = append(s.mapLocal, rule)
	}
}

func (v validator) mapData(kind string, data *string, rule *mapRule) string {
	if data == nil {
		v.fail("data", "is required for %s", kind)
		return ""
	}
	switch kind {
	case "base64":
		var err error
		rule.data, err = base64.StdEncoding.DecodeString(*data)
		if err != nil {
			v.fail("data", "invalid standard base64: %v", err)
		}
		return "application/octet-stream"
	case "json":
		rule.data = []byte(*data)
		if !utf8.Valid(rule.data) || !json.Valid(rule.data) {
			v.fail("data", "invalid JSON")
		}
		return "application/json"
	default:
		rule.data = []byte(*data)
		return "text/plain"
	}
}

func (v validator) headerName(field, name string) string {
	canonical := http.CanonicalHeaderKey(name)
	switch {
	case strings.HasPrefix(name, ":"):
		v.fail(field, "HTTP pseudo-headers cannot be rewritten")
	case !httpguts.ValidHeaderFieldName(name):
		v.fail(field, "invalid HTTP header field name")
	case forbiddenHeader(canonical):
		v.fail(field, "%s is a framing or hop-by-hop header and cannot be rewritten", canonical)
	}
	return canonical
}

func forbiddenHeader(name string) bool {
	switch name {
	case "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Connection",
		"Te", "Trailer", "Upgrade":
		return true
	}
	return false
}

var fileContentTypes = map[string]string{
	".json":  "application/json",
	".js":    "text/javascript",
	".mjs":   "text/javascript",
	".html":  "text/html",
	".htm":   "text/html",
	".css":   "text/css",
	".txt":   "text/plain",
	".xml":   "application/xml",
	".plist": "application/x-plist",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".mp4":   "video/mp4",
	".m3u8":  "application/vnd.apple.mpegurl",
	".wasm":  "application/wasm",
}

func fileContentType(rawURL *string) string {
	if rawURL != nil {
		u, err := url.Parse(*rawURL)
		if err == nil {
			if contentType, ok := fileContentTypes[strings.ToLower(path.Ext(u.Path))]; ok {
				return contentType
			}
		}
	}
	return "application/octet-stream"
}

// SharesCompiled reports whether s and other evaluate the same compiled rules.
func (s *Set) SharesCompiled(other *Set) bool {
	if s == nil || other == nil {
		return s == other
	}
	return sameRules(s.http, other.http) && sameRules(s.mapLocal, other.mapLocal) &&
		sameRules(s.header[0], other.header[0]) && sameRules(s.header[1], other.header[1]) &&
		sameRules(s.body[0], other.body[0]) && sameRules(s.body[1], other.body[1])
}

func sameRules[T any](a, b []T) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}
