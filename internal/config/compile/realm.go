package compile

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

func (c *compiler) realm(path string, p *model.Protocol) {
	if p.Realm == nil {
		return
	}
	r := *p.Realm
	r.STUNServers = slices.Clone(r.STUNServers)
	p.Realm = &r
	fail := func(field, message string) {
		c.errorf(model.DocProfile, path+"/"+field, "outbound.realm", "%s", message)
	}
	if !r.Enabled {
		return
	}
	u, err := url.Parse(r.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		fail("server-url", "expected an HTTP(S) control URL without credentials, query or fragment")
	}
	if r.RealmID == "" || len(r.RealmID) > 1024 || strings.ContainsAny(r.RealmID, "\x00\r\n") {
		fail("realm-id", "a valid realm ID is required")
	}
	r.Token = c.resolveSecret(path+"/token", r.Token)
	if strings.ContainsAny(r.Token, "\r\n\x00") {
		fail("token", "invalid bearer token")
	}
	if len(r.STUNServers) == 0 || len(r.STUNServers) > 64 {
		fail("stun-servers", "configure between 1 and 64 STUN servers")
	}
	for _, server := range r.STUNServers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			host, port = server, "3478"
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if host == "" || strings.ContainsAny(host, " /\\\r\n\x00") || e != nil || n == 0 {
			fail("stun-servers", "invalid STUN host/port")
		}
	}
	if len(p.ServerPorts) > 0 {
		fail("enabled", "Realm and port hopping cannot be combined")
	}
	if r.TLS != nil {
		if r.TLS.Reality != nil || r.TLS.ECH != nil || r.TLS.Fingerprint != "" {
			fail("tls", "Realm control TLS does not use REALITY, ECH or a ClientHello preset")
		}
		server := ""
		if u != nil {
			server = u.Hostname()
		}
		tls := c.tls(path+"/tls", model.Outbound{Type: "http", Server: server, TLS: r.TLS})
		r.TLS = &model.TLS{ServerName: tls.ServerName, Insecure: tls.Insecure, ALPN: slices.Clone(tls.ALPN), CertificatePin: tls.CertificatePin, VerifyName: tls.VerifyName, Certificate: tls.Certificate, PrivateKey: tls.PrivateKey}
	}
}
