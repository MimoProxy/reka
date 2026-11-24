package module

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
)

func parseMapLocal(text string) (model.MapLocal, string, outcome) {
	var r model.MapLocal
	fields, ok := words(text, true)
	if !ok || len(fields) < 2 {
		return r, "", badRewrite("invalid Map Local syntax")
	}
	r.Match = fields[0]
	if issue := validateMatch(r.Match); issue.skips() {
		return r, "", issue
	}
	r.DataType = ptr("file")
	seen := make(map[string]bool)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		key = strings.ToLower(key)
		if !ok || seen[key] {
			return r, "", badRewrite("expected unique Map Local key=value fields")
		}
		seen[key] = true
		switch key {
		case "data-type":
			kind := strings.ToLower(value)
			switch kind {
			case "file", "text", "json", "tiny-gif", "base64":
				r.DataType = ptr(kind)
			default:
				return r, "", unsupported("module.map-local-type", "unknown Map Local data type")
			}
		case "data":
			r.Data = ptr(value)
		case "header":
			headers, ok := parseMapHeaders(value)
			if !ok {
				return r, "", unsupported("module.map-local-header", "expected a header list or its standard base64 encoding")
			}
			r.Headers = headers
		case "status-code":
			code, err := strconv.Atoi(value)
			if err != nil || code < 100 || code > 999 {
				return r, "", unsupported("module.map-local-status", "Map Local status code must be between 100 and 999")
			}
			r.StatusCode = ptr(code)
		default:
			return r, "", unsupported("module.map-local-setting", "unknown Map Local setting")
		}
	}
	var remote string
	if r.Data != nil {
		value := *r.Data
		lower := strings.ToLower(value)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			parsed, err := url.Parse(value)
			if err != nil || parsed.Hostname() == "" || parsed.Fragment != "" {
				return r, "", unsupported("module.map-local-url", "invalid Map Local URL")
			}
			remote = value
		}
	}
	validation := r
	if remote != "" {
		validation = lockMapLocal(r, strings.Repeat("0", 64))
	} else if *r.DataType == "file" {
		return r, "", unsupported("module.map-local-file", "modules cannot read local Map Local files")
	} else if *r.DataType == "tiny-gif" && r.Data != nil && *r.Data == "" {
		r.Data, validation.Data = nil, nil
	}
	if !validMapLocal(validation) {
		return r, "", unsupported("module.map-local-value", "invalid or unsupported Map Local data or headers")
	}
	return r, remote, outcome{}
}

func parseMapHeaders(value string) ([]model.MapLocalHeader, bool) {
	if !strings.Contains(value, ":") {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, false
		}
		value = string(decoded)
	}
	var headers []model.MapLocalHeader
	for field := range strings.SplitSeq(value, "|") {
		if strings.TrimSpace(field) == "" {
			continue
		}
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return nil, false
		}
		headers = append(headers, model.MapLocalHeader{
			Name: http.CanonicalHeaderKey(strings.TrimSpace(key)), Value: ptr(strings.TrimSpace(value)),
		})
	}
	return headers, true
}

func validMapLocal(r model.MapLocal) bool {
	native := httprewrite.MapLocal{
		Match: r.Match, DataType: r.DataType, Data: r.Data, Hash: r.Hash, StatusCode: r.StatusCode,
	}
	for _, header := range r.Headers {
		native.Headers = append(native.Headers, httprewrite.Header{Name: header.Name, Value: header.Value})
	}
	_, err := httprewrite.New(httprewrite.Spec{MapLocal: []httprewrite.MapLocal{native}}, httprewrite.Options{})
	return err == nil
}

func lockMapLocal(r model.MapLocal, hash string) model.MapLocal {
	kind := *r.DataType
	r.DataType, r.Data, r.Hash = ptr("file"), nil, ptr(hash)
	for _, header := range r.Headers {
		if header.Name == "Content-Type" {
			return r
		}
	}
	var contentType string
	switch kind {
	case "json":
		contentType = "application/json"
	case "text":
		contentType = "text/plain"
	}
	if contentType != "" {
		r.Headers = append(r.Headers, model.MapLocalHeader{Name: "Content-Type", Value: ptr(contentType)})
	}
	return r
}
