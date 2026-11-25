package model

import (
	"errors"
	"net/url"

	"strings"
)

const DefaultResourceInterval = 86400

func (d ResourceDownload) WithDefaultInterval() ResourceDownload {
	if d.Interval == 0 {
		d.Interval = DefaultResourceInterval
	}
	return d
}

func ValidResourceDownload(d ResourceDownload) error {
	if strings.HasPrefix(d.URL, SecretPrefix) {
		if len(d.URL) == len(SecretPrefix) {
			return errors.New("download URL reference is empty")
		}
	} else {
		u, err := url.Parse(d.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
			return errors.New("download URL must be HTTP(S) without embedded credentials or a secret reference")
		}
	}
	if d.Interval < 300 || d.Interval > 604800 {
		return errors.New("resource update interval must be 300–604800 seconds")
	}
	return nil
}
