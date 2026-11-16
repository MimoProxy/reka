package compile

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	XC "github.com/MimoProxy/reka/internal/compat/xhttp"
	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *compiler) xhttp(base string, ob model.Outbound, out *Outbound) {
	path := base + "/transport/xhttp"
	fail := func(field, message string) {
		c.errorf(model.DocProfile, path+field, "outbound.xhttp", "%s", message)
	}
	if ob.Type != "vless" {
		fail("", "XHTTP applies to VLESS only")
	}
	t := out.Transport
	x := cloneXHTTP(t.XHTTP)
	if x == nil {
		x = &model.XHTTPOptions{}
	}
	t.XHTTP = x
	for _, field := range c.present(path) {
		if slices.Contains([]string{"server", "port", "tls", "disable-tls", "host", "path", "headers"}, field) {
			fail("/"+field, "endpoint options belong to transport or download-settings")
		}
	}
	c.xhttpALPN(base+"/tls", out.TLS)
	main := xhttpConfig(x, xhttpHost(t.Host, out.TLS, ob.Server), t.Path, t.Headers)
	c.xhttpHeaders(base+"/transport/headers", t.Headers)
	c.xhttpReuse(path+"/xmux", x.XMUX)
	if d := x.DownloadSettings; d != nil {
		dp := path + "/download-settings"
		if d.DownloadSettings != nil {
			fail("/download-settings/download-settings", "nested XHTTP download settings are forbidden")
			// Never descend into attacker-controlled recursive input.
			d.DownloadSettings = nil
		}
		if d.Server != "" && strings.ContainsAny(d.Server, " /\\\r\n\x00") {
			fail("/download-settings/server", "invalid download server")
		}
		if d.Port < 0 || d.Port > 65535 || d.Port == 0 && slices.Contains(c.present(dp), "port") {
			fail("/download-settings/port", "download port must be 1..65535 or omitted")
		}
		if d.DisableTLS && d.TLS != nil {
			fail("/download-settings/tls", "disable-tls and TLS options are mutually exclusive")
		}
		server := d.Server
		if server == "" {
			server = ob.Server
		}
		tls := out.TLS
		if d.DisableTLS {
			tls = nil
		} else if d.TLS != nil {
			tls = c.tls(dp+"/tls", model.Outbound{Type: ob.Type, Server: server, Flow: ob.Flow, Encryption: ob.Encryption, TLS: d.TLS})
			d.TLS = xhttpModelTLS(tls)
		}
		c.xhttpALPN(dp+"/tls", tls)
		for i := range d.Headers {
			d.Headers[i].Value = c.resolveSecret(fmt.Sprintf("%s/headers/#%d/value", dp, i), d.Headers[i].Value)
		}
		c.xhttpHeaders(dp+"/headers", d.Headers)
		c.xhttpReuse(dp+"/xmux", d.XMUX)
		host := d.Host
		if host == "" {
			host = main.Host
		}
		dpath := d.Path
		if dpath == "" {
			dpath = main.Path
		}
		main.DownloadConfig = xhttpConfig(d, host, dpath, d.Headers)
	}
	if err := XC.ValidateConfig(main); err != nil {
		fail("", err.Error())
	}
}

func (c *compiler) xhttpALPN(path string, tls *TLS) {
	if tls == nil || len(tls.ALPN) == 0 {
		return
	}
	if len(tls.ALPN) != 1 || !slices.Contains([]string{"http/1.1", "h2", "h3"}, tls.ALPN[0]) {
		c.errorf(model.DocProfile, path+"/alpn", "outbound.xhttp", "XHTTP requires one ALPN: http/1.1, h2 or h3")
		return
	}
	if tls.ALPN[0] == "h3" && (tls.Reality != nil || tls.Carrier != nil || tls.Fingerprint != "") {
		c.errorf(model.DocProfile, path+"/alpn", "outbound.xhttp", "XHTTP HTTP/3 cannot use REALITY, a TCP security carrier or a ClientHello preset")
	}
}

func (c *compiler) xhttpHeaders(path string, headers []model.SubscriptionHeader) {
	seen := map[string]bool{}
	for i, h := range headers {
		name := http.CanonicalHeaderKey(h.Name)
		if seen[name] {
			c.errorf(model.DocProfile, fmt.Sprintf("%s/#%d/name", path, i), "outbound.xhttp", "XHTTP header names must be unique")
		}
		seen[name] = true
	}
}

func (c *compiler) xhttpReuse(path string, reuse *model.XHTTPReuse) {
	if reuse == nil || reuse.HKeepAlivePeriod == "" {
		return
	}
	value, err := strconv.ParseInt(reuse.HKeepAlivePeriod, 10, 32)
	if err != nil || value < -1 || value > 3600 {
		c.errorf(model.DocProfile, path+"/h-keep-alive-period", "outbound.xhttp", "XHTTP keepalive must be -1..3600 seconds")
	}
}

func xhttpHost(host string, tls *TLS, server string) string {
	if host != "" {
		return host
	}
	if tls != nil && tls.ServerName != "" {
		return tls.ServerName
	}
	return server
}

// cloneXHTTP copies only one download level. Invalid deeper input is retained
// only as a marker for validation and is never mutated or recursively copied.
func cloneXHTTP(in *model.XHTTPOptions) *model.XHTTPOptions {
	if in == nil {
		return nil
	}
	out := *in
	out.Headers = slices.Clone(in.Headers)
	if in.XMUX != nil {
		r := *in.XMUX
		out.XMUX = &r
	}
	if in.DownloadSettings != nil {
		d := *in.DownloadSettings
		d.Headers = slices.Clone(d.Headers)
		if d.XMUX != nil {
			r := *d.XMUX
			d.XMUX = &r
		}
		out.DownloadSettings = &d
	}
	return &out
}

func xhttpModelTLS(t *TLS) *model.TLS {
	out := &model.TLS{Carrier: t.Carrier, ECH: t.ECH, ServerName: t.ServerName, Insecure: t.Insecure, Fingerprint: t.Fingerprint, ALPN: slices.Clone(t.ALPN), CertificatePin: t.CertificatePin, VerifyName: t.VerifyName, Certificate: t.Certificate, PrivateKey: t.PrivateKey}
	if t.Reality != nil {
		out.Reality = &model.Reality{PublicKey: t.Reality.PublicKey, ShortID: t.Reality.ShortID, X25519MLKEM768: t.Reality.X25519MLKEM768}
	}
	return out
}

func xhttpConfig(x *model.XHTTPOptions, host, path string, headers []model.SubscriptionHeader) *XC.Config {
	out := &XC.Config{Host: host, Path: path, Mode: x.Mode, Headers: map[string]string{}, NoGRPCHeader: x.NoGRPCHeader, XPaddingBytes: x.XPaddingBytes, XPaddingObfsMode: x.XPaddingObfsMode, XPaddingKey: x.XPaddingKey, XPaddingHeader: x.XPaddingHeader, XPaddingPlacement: x.XPaddingPlacement, XPaddingMethod: x.XPaddingMethod, UplinkHTTPMethod: x.UplinkHTTPMethod, SessionPlacement: x.SessionPlacement, SessionKey: x.SessionKey, SessionTable: x.SessionTable, SessionLength: x.SessionLength, SeqPlacement: x.SeqPlacement, SeqKey: x.SeqKey, UplinkDataPlacement: x.UplinkDataPlacement, UplinkDataKey: x.UplinkDataKey, UplinkChunkSize: x.UplinkChunkSize, ScMaxEachPostBytes: x.ScMaxEachPostBytes, ScMinPostsIntervalMs: x.ScMinPostsIntervalMS}
	for _, h := range headers {
		out.Headers[http.CanonicalHeaderKey(h.Name)] = h.Value
	}
	if r := x.XMUX; r != nil {
		out.ReuseConfig = &XC.ReuseConfig{MaxConcurrency: r.MaxConcurrency, MaxConnections: r.MaxConnections, CMaxReuseTimes: r.CMaxReuseTimes, HMaxRequestTimes: r.HMaxRequestTimes, HMaxReusableSecs: r.HMaxReusableSecs, HKeepAlivePeriod: r.HKeepAlivePeriod}
	}
	return out
}
