package httprewrite

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/itchyny/gojq"
	"golang.org/x/net/http/httpguts"
)

// Request describes an HTTP request. A nil Body indicates that it was not buffered.
type Request struct {
	URL    string
	Method string
	Header http.Header
	Body   []byte
}

type RequestResult struct {
	URL           string
	HostChanged   bool
	Header        http.Header
	Body          []byte
	Local         *Response
	Connection    ConnectionAction
	MatchedIDs    []string
	ResourceError error
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type ResponseResult struct {
	Response
	MatchedIDs []string
}

// ConnectionAction describes a terminal action without an HTTP response.
type ConnectionAction string

const (
	// Close closes the client connection.
	Close ConnectionAction = "close"
	// Drop leaves the connection open without a response until the client gives up.
	Drop ConnectionAction = "drop"
)

// Set is safe to reuse concurrently. Evaluation does not mutate input headers
// or bodies. Unchanged results may share the original data.
type Set struct {
	opts        Options
	http        []urlRule
	header      [2][]headerRule
	body        [2][]bodyRule
	mapLocal    []mapRule
	httpIndex   ruleIndex
	headerIndex [2]ruleIndex
	bodyIndex   [2]ruleIndex
	mapIndex    ruleIndex
	warnings    []ValidationError
}

type rewritePhase int

const (
	requestPhase rewritePhase = iota
	responsePhase
)

type urlRule struct {
	match    *lazyRegexp
	id       string
	action   string
	target   string
	response string
}

type headerRule struct {
	match   *lazyRegexp
	pattern *lazyRegexp
	id      string
	op      string
	name    string
	value   string
}

type bodyRule struct {
	match   *lazyRegexp
	id      string
	replace []bodyReplacement
	jq      *gojq.Code
}

type bodyReplacement struct {
	pattern *lazyRegexp
	value   string
}

type mapRule struct {
	match      *lazyRegexp
	id         string
	data       []byte
	hash       string
	statusCode int
	header     http.Header
}

// MayChangeRequestURL reports whether the set has a transparent URL rewrite.
// Such rewrites can choose an upstream authority at request time.
func (s *Set) MayChangeRequestURL() bool {
	return s != nil && slices.ContainsFunc(s.http, func(rule urlRule) bool { return rule.action == "header" })
}

// MayMatchHTTP reports whether any rule could apply to a plain HTTP
// connection. An empty host or zero port leaves that part unconstrained.
func (s *Set) MayMatchHTTP(host string, port uint16) bool {
	if s == nil {
		return false
	}
	var scratch httpHostBuffer
	return s.mayMatchHTTP(scratch.key([]byte(trimHostKey(host))), port, false)
}

// NamesHTTP is MayMatchHTTP without rules that name no host. Such rules
// match every port, so sniffing for them is limited to the default port.
func (s *Set) NamesHTTP(host string, port uint16) bool {
	if s == nil {
		return false
	}
	var scratch httpHostBuffer
	return s.mayMatchHTTP(scratch.key([]byte(trimHostKey(host))), port, true)
}

// MayMatchHTTPAddr avoids allocating the textual address on a passthrough flow.
func (s *Set) MayMatchHTTPAddr(addr netip.Addr, port uint16) bool {
	if s == nil {
		return false
	}
	var host httpHostBuffer
	return s.mayMatchHTTP(addr.Unmap().AppendTo(host[:0]), port, false)
}

func (s *Set) mayMatchHTTP(host []byte, port uint16, named bool) bool {
	for _, index := range [...]*ruleIndex{
		&s.httpIndex, &s.mapIndex, &s.headerIndex[requestPhase], &s.headerIndex[responsePhase],
		&s.bodyIndex[requestPhase], &s.bodyIndex[responsePhase],
	} {
		if index.mayMatchHTTP(host, port, named) {
			return true
		}
	}
	return false
}

// A transparent one-pixel GIF89a image.
const tinyGIF = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"

// Request applies the first matching URL rule, request headers, the first
// matching local resource, and request body rules in that order.
func (s *Set) Request(req Request) RequestResult {
	result := s.RequestBeforeBody(req)
	s.ApplyRequestBody(&result, req.Body)
	return result
}

// RequestBeforeBody applies URL and header rewrites and checks for a local
// response. A relay can then size its buffer using the rewritten URL.
func (s *Set) RequestBeforeBody(req Request) RequestResult {
	result := RequestResult{URL: req.URL, Header: req.Header, Body: req.Body}
	if s == nil {
		return result
	}
	if r, re, matches := s.findURLRule(req.URL); r != nil {
		result.MatchedIDs = append(result.MatchedIDs, r.id)
		switch r.action {
		case "reject":
			result.Local, result.Connection = r.reject()
			return result
		case "302", "307":
			location := replaceFirst(re, req.URL, matches, r.target)
			if httpguts.ValidHeaderFieldValue(location) {
				status, _ := strconv.Atoi(r.action)
				result.Local = localResponse(status, "", nil)
				result.Local.Header.Set("Location", location)
				return result
			}
		case "header":
			result.URL = replaceFirst(re, req.URL, matches, r.target)
			result.HostChanged = !strings.EqualFold(urlHostname(req.URL), urlHostname(result.URL))
		}
	}

	header := editedHeader{value: result.Header}
	s.rewriteHeaders(requestPhase, result.URL, &header, &result.MatchedIDs)
	if r := s.findMapRule(result.URL); r != nil {
		result.MatchedIDs = append(result.MatchedIDs, r.id)
		result.Local, result.ResourceError = r.response(s.opts.ReadResource)
	}
	result.Header = header.value
	return result
}

// ApplyRequestBody completes a request rewrite using a buffered body.
func (s *Set) ApplyRequestBody(result *RequestResult, body []byte) {
	if s == nil || result.Local != nil || result.Connection != "" || result.ResourceError != nil {
		return
	}
	header := editedHeader{value: result.Header}
	result.Body = s.rewriteBody(requestPhase, result.URL, &header, body, &result.MatchedIDs)
	result.Header = header.value
}

// NeedsRewrittenRequestBody checks body rules after URL and local rewrites.
func (s *Set) NeedsRewrittenRequestBody(url string) bool {
	return s != nil && s.needsBody(requestPhase, url)
}

// Response applies response header rules before response body rules.
func (s *Set) Response(url string, resp Response) ResponseResult {
	result := ResponseResult{Response: resp}
	if s == nil {
		return result
	}
	header := editedHeader{value: result.Header}
	s.rewriteHeaders(responsePhase, url, &header, &result.MatchedIDs)
	result.Body = s.rewriteBody(responsePhase, url, &header, resp.Body, &result.MatchedIDs)
	result.Header = header.value
	return result
}

// NeedsRequestBody reports whether request rules may need a buffered body for
// the original URL. URL rules are evaluated before checking the rewritten URL.
func (s *Set) NeedsRequestBody(url string) bool {
	if s == nil || len(s.body[requestPhase]) == 0 {
		return false
	}
	if r, re, matches := s.findURLRule(url); r != nil {
		switch r.action {
		case "reject":
			return false
		case "302", "307":
			if httpguts.ValidHeaderFieldValue(replaceFirst(re, url, matches, r.target)) {
				return false
			}
		case "header":
			url = replaceFirst(re, url, matches, r.target)
		}
	}
	return s.needsBody(requestPhase, url) && s.findMapRule(url) == nil
}

// NeedsResponseBody reports whether response rules may need a buffered body.
func (s *Set) NeedsResponseBody(url string) bool {
	return s != nil && s.needsBody(responsePhase, url)
}

func (s *Set) needsBody(phase rewritePhase, url string) bool {
	needs := false
	s.bodyIndex[phase].each(url, func(i int) bool {
		needs = s.body[phase][i].match.MatchString(url)
		return !needs
	})
	return needs
}

func (s *Set) findURLRule(url string) (*urlRule, *regexp.Regexp, []int) {
	var rule *urlRule
	var re *regexp.Regexp
	var matches []int
	s.httpIndex.each(url, func(i int) bool {
		r := &s.http[i]
		if !r.match.mayMatch(url) {
			return true
		}
		pattern := r.match.get()
		if r.action == "reject" {
			if !pattern.MatchString(url) {
				return true
			}
		} else {
			matches = pattern.FindStringSubmatchIndex(url)
			if matches == nil {
				return true
			}
		}
		rule, re = r, pattern
		return false
	})
	return rule, re, matches
}

func replaceFirst(re *regexp.Regexp, value string, match []int, template string) string {
	var out []byte
	out = append(out, value[:match[0]]...)
	out = re.ExpandString(out, template, value, match)
	out = append(out, value[match[1]:]...)
	return string(out)
}

func urlHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// normalizeTemplate brackets numeric captures so that $1x uses group 1.
// Only $0, $1 through $99 and $$ have special meaning in a template.
func normalizeTemplate(value string, capture func(int)) string {
	if !strings.Contains(value, "$") {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '$' {
			out.WriteByte(value[i])
			continue
		}
		if i+1 == len(value) || value[i+1] < '0' || value[i+1] > '9' {
			out.WriteString("$$")
			if i+1 < len(value) && value[i+1] == '$' {
				i++
			}
			continue
		}
		start := i + 1
		i++
		group := int(value[i] - '0')
		if group != 0 && i+1 < len(value) && value[i+1] >= '0' && value[i+1] <= '9' {
			i++
			group = group*10 + int(value[i]-'0')
		}
		capture(group)
		out.WriteString("${")
		out.WriteString(value[start : i+1])
		out.WriteByte('}')
	}
	return out.String()
}

func (r *urlRule) reject() (*Response, ConnectionAction) {
	switch r.response {
	case "close":
		return nil, Close
	case "drop":
		return nil, Drop
	case "200":
		return localResponse(http.StatusOK, "", nil), ""
	case "gif":
		return localResponse(http.StatusOK, "image/gif", []byte(tinyGIF)), ""
	case "dict":
		return localResponse(http.StatusOK, "application/json", []byte("{}")), ""
	case "array":
		return localResponse(http.StatusOK, "application/json", []byte("[]")), ""
	default:
		return RejectResponse(), ""
	}
}

// RejectResponse is the reply to a rejected HTTP request: an empty 404, as
// Stash answers its reject rewrites.
func RejectResponse() *Response { return localResponse(http.StatusNotFound, "", nil) }

func (s *Set) findMapRule(url string) *mapRule {
	var result *mapRule
	s.mapIndex.each(url, func(i int) bool {
		r := &s.mapLocal[i]
		if r.match.MatchString(url) {
			result = r
		}
		return result == nil
	})
	return result
}

func (r *mapRule) response(read func(string) ([]byte, error)) (*Response, error) {
	if r.hash == "" {
		return r.respond(slices.Clone(r.data)), nil
	}
	if read == nil {
		return localResponse(http.StatusNotFound, "", nil), fmt.Errorf("no resource reader for %s", r.hash)
	}
	body, err := read(r.hash)
	if err != nil {
		return localResponse(http.StatusNotFound, "", nil), fmt.Errorf("read map-local resource %s: %w", r.hash, err)
	}
	if len(body) > MaxMapLocalSize {
		return localResponse(http.StatusNotFound, "", nil), fmt.Errorf("map-local resource %s exceeds %d bytes", r.hash, MaxMapLocalSize)
	}
	return r.respond(body), nil
}

func (r *mapRule) respond(body []byte) *Response {
	header := r.header.Clone()
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &Response{StatusCode: r.statusCode, Header: header, Body: body}
}

func localResponse(status int, contentType string, body []byte) *Response {
	h := make(http.Header, 2)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &Response{StatusCode: status, Header: h, Body: body}
}
