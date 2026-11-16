package xhttp

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

func CloneConfig(c *Config) *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Headers = maps.Clone(c.Headers)
	if c.ReuseConfig != nil {
		v := *c.ReuseConfig
		out.ReuseConfig = &v
	}
	if c.DownloadConfig != nil {
		v := *c.DownloadConfig
		v.DownloadConfig = nil
		v.Headers = maps.Clone(c.DownloadConfig.Headers)
		if v.ReuseConfig != nil {
			r := *v.ReuseConfig
			v.ReuseConfig = &r
		}
		out.DownloadConfig = &v
	}
	return &out
}

// ValidateConfig bounds memory, generated headers and timers before the client
// is installed. Remote configuration cannot request unbounded session IDs.
func ValidateConfig(c *Config) error { return validateConfig(c, false) }
func validateConfig(c *Config, download bool) error {
	if c == nil {
		return errors.New("xhttp configuration is missing")
	}
	if c.Host == "" || strings.ContainsAny(c.Host, "\r\n\x00 /?#") {
		return errors.New("invalid xhttp host")
	}
	if len(c.Path) > 8192 || strings.ContainsAny(c.Path, "\r\n\x00?#") {
		return errors.New("invalid xhttp path")
	}
	switch c.NormalizedMode() {
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return errors.New("invalid xhttp mode")
	}
	if c.Mode == "stream-one" && c.DownloadConfig != nil {
		return errors.New("xhttp stream-one cannot use a separate download")
	}
	if c.DownloadConfig != nil {
		if download || c.DownloadConfig.DownloadConfig != nil {
			return errors.New("nested xhttp download settings are forbidden")
		}
		if err := validateConfig(c.DownloadConfig, true); err != nil {
			return fmt.Errorf("xhttp download: %w", err)
		}
	}
	if c.UplinkHTTPMethod != "" && !httpguts.ValidHeaderFieldName(c.UplinkHTTPMethod) {
		return errors.New("invalid xhttp HTTP method")
	}
	total := 0
	for k, v := range c.Headers {
		total += len(k) + len(v)
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
			return errors.New("invalid xhttp header")
		}
	}
	if total > 16384 {
		return errors.New("xhttp headers exceed 16 KiB")
	}
	for _, f := range []struct {
		name, value, fallback string
		min, max              int
	}{
		{"x-padding-bytes", c.XPaddingBytes, "100-1000", 0, 8192},
		{"sc-max-each-post-bytes", c.ScMaxEachPostBytes, "1000000", 1, 4 << 20},
		{"sc-min-posts-interval-ms", c.ScMinPostsIntervalMs, "30", 1, 60000},
		{"session-length", c.SessionLength, "16-32", 1, 256},
		{"uplink-chunk-size", c.UplinkChunkSize, "0", 0, 1 << 20},
	} {
		r, err := ParseRange(f.value, f.fallback)
		if err != nil || r.Min < f.min || r.Max > f.max {
			return fmt.Errorf("xhttp %s must be within %d..%d", f.name, f.min, f.max)
		}
	}
	if len(c.SessionTable) > 256 {
		return errors.New("xhttp session table exceeds 256 bytes")
	}
	if c.ReuseConfig != nil {
		if v := c.ReuseConfig.HKeepAlivePeriod; v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < -1 || n > 3600 {
				return errors.New("xhttp h-keep-alive-period must be -1..3600 seconds")
			}
		}
		for _, f := range []struct {
			name, value string
			max         int
		}{
			{"max-concurrency", c.ReuseConfig.MaxConcurrency, 65536}, {"max-connections", c.ReuseConfig.MaxConnections, 1024},
			{"c-max-reuse-times", c.ReuseConfig.CMaxReuseTimes, 1 << 30}, {"h-max-request-times", c.ReuseConfig.HMaxRequestTimes, 1 << 30}, {"h-max-reusable-secs", c.ReuseConfig.HMaxReusableSecs, 604800},
		} {
			r, err := ParseRange(f.value, "0")
			if err != nil || r.Min < 0 || r.Max > f.max {
				return fmt.Errorf("xhttp %s exceeds its supported range", f.name)
			}
		}
	}
	for name, value := range map[string]string{"session-placement": c.SessionPlacement, "seq-placement": c.SeqPlacement} {
		switch value {
		case "", PlacementPath, PlacementQuery, PlacementHeader, PlacementCookie:
		default:
			return fmt.Errorf("invalid xhttp %s", name)
		}
	}
	switch c.UplinkDataPlacement {
	case "", PlacementBody, PlacementHeader, PlacementCookie:
	default:
		return errors.New("invalid xhttp uplink-data-placement")
	}

	switch c.XPaddingPlacement {
	case "", PlacementHeader, PlacementQueryInHeader, PlacementQuery, PlacementCookie:
	default:
		return errors.New("invalid xhttp x-padding-placement")
	}
	switch PaddingMethod(c.XPaddingMethod) {
	case "", PaddingMethodRepeatX, PaddingMethodTokenish:
	default:
		return errors.New("invalid xhttp x-padding-method")
	}
	if c.XPaddingObfsMode {
		if c.XPaddingPlacement == "" {
			return errors.New("xhttp obfuscated padding requires an explicit placement")
		}
		if (c.XPaddingPlacement == PlacementHeader || c.XPaddingPlacement == PlacementQueryInHeader) && c.XPaddingHeader == "" {
			return errors.New("xhttp padding requires a header name")
		}
		if c.XPaddingPlacement != PlacementHeader && c.XPaddingKey == "" {
			return errors.New("xhttp padding requires a key")
		}
	}
	for _, field := range []struct{ name, value, placement string }{
		{"session-key", c.SessionKey, c.GetNormalizedSessionPlacement()}, {"seq-key", c.SeqKey, c.GetNormalizedSeqPlacement()},
		{"uplink-data-key", c.UplinkDataKey, c.GetNormalizedUplinkDataPlacement()}, {"x-padding-key", c.XPaddingKey, c.XPaddingPlacement},
		{"x-padding-header", c.XPaddingHeader, PlacementHeader},
	} {
		if field.value == "" {
			continue
		}
		if len(field.value) > 128 || strings.ContainsAny(field.value, "\r\n\x00") {
			return fmt.Errorf("invalid xhttp %s", field.name)
		}
		if (field.placement == PlacementHeader || field.placement == PlacementCookie) && !httpguts.ValidHeaderFieldName(field.value) {
			return fmt.Errorf("invalid xhttp %s token", field.name)
		}
	}
	if (c.UplinkDataPlacement == PlacementHeader || c.UplinkDataPlacement == PlacementCookie) && c.UplinkDataKey == "" {
		return errors.New("xhttp uplink-data-key is required for header/cookie payloads")
	}
	if c.SessionTable != "" && c.SessionTable != "uuid" {
		table := c.SessionTable
		if predefined, ok := predefinedTable[table]; ok {
			table = predefined
		}
		for i := 0; i < len(table); i++ {
			b := table[i]
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("-._~", rune(b))) {
				return errors.New("xhttp session table requires URL-safe ASCII characters")
			}
		}
	}
	return nil
}
