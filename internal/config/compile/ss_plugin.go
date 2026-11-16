package compile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"golang.org/x/net/http/httpguts"
)

func (c *compiler) ssPlugin(path string, value *model.SSPlugin) *model.SSPlugin {
	if value == nil {
		return nil
	}
	p := *value
	fail := func(field, message string) {
		c.errorf(model.DocProfile, path+"/"+field, "outbound.plugin", "%s", message)
	}
	fields := map[string][]string{
		"obfs":         {"type", "mode", "host"},
		"v2ray-plugin": {"type", "mode", "host", "path", "tls", "mux", "headers", "http-upgrade", "fast-open"},
		"gost-plugin":  {"type", "mode", "host", "path", "tls", "mux", "headers"},
		"shadow-tls":   {"type", "host", "version", "password", "tls"},
	}
	allowed, ok := fields[p.Type]
	if !ok {
		fail("type", "unsupported SS plugin")
		return &p
	}
	for _, field := range c.present(path) {
		if !slices.Contains(allowed, field) {
			fail(field, "field does not apply to this plugin")
		}
	}
	if p.Host == "" && p.Type != "shadow-tls" {
		p.Host = "bing.com"
	}
	if p.Host == "" || strings.ContainsAny(p.Host, " /\\\r\n\x00") {
		fail("host", "a valid plugin host is required")
	}
	switch p.Type {
	case "obfs":
		if p.Mode != "http" && p.Mode != "tls" {
			fail("mode", "obfs requires http or tls")
		}
	case "v2ray-plugin", "gost-plugin":
		if p.Mode != "websocket" {
			fail("mode", "this plugin requires websocket")
		}
		if strings.ContainsAny(p.Path, "\r\n\x00") {
			fail("path", "invalid websocket path")
		}
		if p.FastOpen && !p.HTTPUpgrade {
			fail("fast-open", "fast-open requires http-upgrade")
		}
		mux := p.Mux == nil || *p.Mux
		p.Mux = &mux
	case "shadow-tls":
		if p.Version == 0 {
			p.Version = 2
		}
		if p.Version < 1 || p.Version > 3 {
			fail("version", "ShadowTLS version must be 1, 2 or 3")
		}
		p.Password = c.resolveSecret(path+"/password", p.Password)
		if p.TLS == nil {
			p.TLS = &model.TLS{}
		}
	}
	p.Headers = slices.Clone(p.Headers)
	for i := range p.Headers {
		h := &p.Headers[i]
		h.Value = c.resolveSecret(fmt.Sprintf("%s/headers/#%d/value", path, i), h.Value)
		if !httpguts.ValidHeaderFieldName(h.Name) || !httpguts.ValidHeaderFieldValue(h.Value) {
			fail("headers", "invalid plugin HTTP header")
		}
	}
	if p.TLS != nil {
		if p.TLS.Reality != nil {
			fail("tls/reality", "plugin TLS does not use REALITY")
		}
		if p.Type == "shadow-tls" && p.TLS.ECH != nil {
			fail("tls/ech", "ShadowTLS does not use ECH")
		}
		modelTLS := *p.TLS
		if len(modelTLS.ALPN) == 0 && modelTLS.ALPN == nil {
			if p.Type == "shadow-tls" {
				modelTLS.ALPN = []string{"h2", "http/1.1"}
			} else {
				modelTLS.ALPN = []string{"http/1.1"}
			}
		}
		// Like the reference, an explicit websocket Host header also sets SNI.
		server := p.Host
		if p.Type != "shadow-tls" {
			for _, h := range p.Headers {
				if strings.EqualFold(h.Name, "Host") {
					server = h.Value
					modelTLS.ServerName = server
					break
				}
			}
		}
		tls := c.tls(path+"/tls", model.Outbound{Type: "http", Server: server, TLS: &modelTLS})
		p.TLS = &model.TLS{ServerName: tls.ServerName, Insecure: tls.Insecure, ALPN: slices.Clone(tls.ALPN), Fingerprint: tls.Fingerprint, CertificatePin: tls.CertificatePin, VerifyName: tls.VerifyName, Certificate: tls.Certificate, PrivateKey: tls.PrivateKey, ECH: tls.ECH}
	}
	return &p
}
