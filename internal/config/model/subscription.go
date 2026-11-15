package model

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func ValidSubscription(s *Subscription) error {
	if s == nil {
		return nil
	}
	if strings.HasPrefix(s.URL, SecretPrefix) {
		if len(s.URL) == len(SecretPrefix) {
			return errors.New("subscription URL reference is empty")
		}
	} else {
		u, e := url.Parse(s.URL)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Fragment != "" {
			return errors.New("subscription URL must be HTTP(S) or a secret reference")
		}
	}
	if s.Format != "" && s.Format != "auto" && s.Format != "clash" && s.Format != "links" {
		return errors.New("subscription format must be auto, clash or links")
	}
	if s.Interval < 0 || s.Interval > 604800 || s.Interval > 0 && s.Interval < 30 {
		return errors.New("subscription interval must be 0 (default) or 30–604800 seconds")
	}
	assets := map[string]bool{}
	for _, a := range s.Geodata {
		if (a.ID != "geoip" && a.ID != "geosite") || assets[a.ID] {
			return errors.New("geodata IDs must be unique geoip or geosite")
		}
		assets[a.ID] = true
		if err := ValidSubscription(&Subscription{URL: a.URL}); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, h := range s.Headers {
		key := strings.ToLower(h.Name)
		if !headerName.MatchString(h.Name) || strings.ContainsAny(h.Value, "\r\n") || seen[key] {
			return errors.New("subscription header is invalid or duplicated")
		}
		seen[key] = true
		switch key {
		case "host", "content-length", "connection", "transfer-encoding", "if-none-match", "if-modified-since":
			return errors.New("subscription header is reserved")
		}
	}
	return nil
}
