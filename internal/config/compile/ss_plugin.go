package compile

import (
	"fmt"
	RT "github.com/metacubex/restls-client-go"
	"slices"
	"strings"

	KC "github.com/MimoProxy/reka/internal/compat/kcptun"
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
		"restls":       {"type", "host", "password", "version-hint", "restls-script", "force-tls12", "client-fingerprint", "tls"},
		"jls":          {"type", "host", "username", "password", "alpn", "client-fingerprint"},
		"kcptun":       {"type", "kcp"},
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
	if p.Host == "" && slices.Contains([]string{"obfs", "v2ray-plugin", "gost-plugin"}, p.Type) {
		p.Host = "bing.com"
	}
	if p.Type != "kcptun" && (p.Host == "" || strings.ContainsAny(p.Host, " /\\\r\n\x00")) {
		fail("host", "a valid plugin host is required")
	}
	switch p.Type {
	case "kcptun":
		if p.KCP == nil {
			p.KCP = &KC.Config{}
		} else {
			copy := *p.KCP
			p.KCP = &copy
		}
		p.KCP.Key = c.resolveSecret(path+"/kcp/key", p.KCP.Key)
		if err := p.KCP.Normalize(); err != nil {
			fail("kcp", err.Error())
		}
	case "jls":
		p.Username = c.resolveSecret(path+"/username", p.Username)
		p.Password = c.resolveSecret(path+"/password", p.Password)
		p.ALPN = slices.Clone(p.ALPN)
		if p.Username == "" || p.Password == "" {
			fail("username", "JLS requires username and password")
		}
		for _, a := range p.ALPN {
			if len(a) < 1 || len(a) > 255 {
				fail("alpn", "invalid ALPN protocol")
			}
		}
	case "restls":
		p.Password = c.resolveSecret(path+"/password", p.Password)
		if len(p.RestlsScript) > 8192 {
			fail("restls-script", "record script exceeds budget")
		} else if _, err := RT.NewRestlsConfig(p.Host, p.Password, p.VersionHint, p.RestlsScript, p.ClientFingerprint); err != nil {
			fail("version-hint", err.Error())
		}
		if p.TLS == nil {
			p.TLS = &model.TLS{}
		}

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
		if p.TLS.Carrier != nil {
			fail("tls/carrier", "SS plugins already select their own carrier")
		}
		if p.TLS.Reality != nil {
			fail("tls/reality", "plugin TLS does not use REALITY")
		}
		if (p.Type == "shadow-tls" || p.Type == "restls") && p.TLS.ECH != nil {
			fail("tls/ech", "this plugin does not use ECH")
		}
		modelTLS := *p.TLS
		if p.Type == "restls" && modelTLS.Fingerprint != "" {
			fail("tls/fingerprint", "Restls ClientHello preset belongs in client-fingerprint")
		}

		if len(modelTLS.ALPN) == 0 && modelTLS.ALPN == nil && p.Type != "restls" {
			if p.Type == "shadow-tls" {
				modelTLS.ALPN = []string{"h2", "http/1.1"}
			} else {
				modelTLS.ALPN = []string{"http/1.1"}
			}
		}
		// Like the reference, an explicit websocket Host header also sets SNI.
		server := p.Host
		if p.Type != "shadow-tls" && p.Type != "restls" {
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
