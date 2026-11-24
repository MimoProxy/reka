package httprewrite

import (
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type editedHeader struct {
	value  http.Header
	copied bool
}

func (h *editedHeader) writable() http.Header {
	if !h.copied {
		h.value = h.value.Clone()
		if h.value == nil {
			h.value = make(http.Header)
		}
		h.copied = true
	}
	return h.value
}

func (s *Set) rewriteHeaders(phase rewritePhase, url string, header *editedHeader, ids *[]string) {
	s.headerIndex[phase].each(url, func(i int) bool {
		r := &s.header[phase][i]
		if !r.match.mayMatch(url) {
			return true
		}
		re := r.match.get()
		if !re.MatchString(url) {
			return true
		}
		*ids = append(*ids, r.id)
		if forbiddenHeader(r.name) || strings.HasPrefix(r.name, ":") || connectionHeader(header.value, r.name) {
			return true
		}

		values, present := headerValues(header.value, r.name)
		switch r.op {
		case "del":
			if present {
				deleteHeader(header.writable(), r.name)
			}
		case "add", "replace":
			if r.op == "replace" && !present {
				return true
			}
			value := r.value
			if strings.Contains(value, "$") {
				value = string(re.ExpandString(nil, value, url, re.FindStringSubmatchIndex(url)))
			}
			if !httpguts.ValidHeaderFieldValue(value) {
				return true
			}
			if r.op == "add" {
				replaceHeader(header.writable(), r.name, append(slices.Clone(values), value))
			} else if len(values) != 1 || values[0] != value {
				replaceHeader(header.writable(), r.name, []string{value})
			}
		case "replace-regex":
			if len(values) > 0 {
				if updated := r.replaceValues(values); updated != nil {
					replaceHeader(header.writable(), r.name, updated)
				}
			}
		}
		return true
	})
}

func (r *headerRule) replaceValues(values []string) []string {
	re := r.pattern.get()
	var result []string
	for i, value := range values {
		if !re.MatchString(value) {
			continue
		}
		updated := re.ReplaceAllString(value, r.value)
		if updated == value {
			continue
		}
		if !httpguts.ValidHeaderFieldValue(updated) {
			return nil
		}
		if result == nil {
			result = slices.Clone(values)
		}
		result[i] = updated
	}
	return result
}

// Noncanonical keys are possible in a caller-constructed http.Header. Keep
// the normal value order and use key order for duplicates with other spellings.
func headerValues(h http.Header, canonical string) ([]string, bool) {
	values, present := h[canonical]
	var aliases []string
	for key := range h {
		if key != canonical && strings.EqualFold(key, canonical) {
			aliases = append(aliases, key)
		}
	}
	if len(aliases) == 0 {
		return values, present
	}
	slices.Sort(aliases)
	values = slices.Clone(values)
	for _, key := range aliases {
		values = append(values, h[key]...)
	}
	return values, true
}

func connectionHeader(h http.Header, name string) bool {
	values, _ := headerValues(h, "Connection")
	return httpguts.HeaderValuesContainsToken(values, name)
}

func replaceHeader(h http.Header, name string, values []string) {
	deleteHeader(h, name)
	h[name] = values
}

func deleteHeader(h http.Header, name string) {
	for key := range h {
		if strings.EqualFold(key, name) {
			delete(h, key)
		}
	}
}
