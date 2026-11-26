package importer

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/MimoProxy/reka/internal/compat/ssr"
)

func (c *converter) convertSSR(r *proxyReader, out object) {
	allowed := map[string]bool{
		"name": true, "type": true, "server": true, "port": true, "udp": true,
		"password": true, "cipher": true, "obfs": true, "obfs-param": true,
		"protocol": true, "protocol-param": true,
	}
	c.convertDialer(r, out, allowed)
	if dialer, ok := out["dialer"].(object); ok && dialer["tfo"] == true {
		r.fail("tfo", "import.unsupported-field", "TCP Fast Open is unsupported for SSR")
	}
	for i := 0; i+1 < len(r.n.Content); i += 2 {
		key := r.n.Content[i].Value
		if key == "smux" || !allowed[key] {
			r.fail(key, "import.unsupported-field", "unsupported SSR option")
		}
	}
	method, obfs, protocol := r.str("cipher"), r.str("obfs"), r.str("protocol")
	if err := ssr.ValidateMethod(method); err != nil {
		r.fail("cipher", "import.ssr.cipher", err.Error())
	}
	if err := ssr.ValidateObfs(obfs); err != nil {
		r.fail("obfs", "import.ssr.obfs", err.Error())
	}
	if err := ssr.ValidateProtocol(protocol); err != nil {
		r.fail("protocol", "import.ssr.protocol", err.Error())
	}
	out["server"], out["port"], out["udp"] = r.str("server"), r.port(), r.boolean("udp", false)
	out["method"], out["password"] = method, r.str("password")
	obfsOptions := object{"type": obfs}
	if value := r.str("obfs-param"); value != "" {
		obfsOptions["param"] = value
	}
	protocolOptions := object{"obfs": obfsOptions, "protocol": protocol}
	if value := r.str("protocol-param"); value != "" {
		protocolOptions["protocol-param"] = value
	}
	out["protocol"] = protocolOptions
}

func parseSSRLink(body string) (object, error) {
	raw, err := decodeBase64(body)
	if err != nil {
		return nil, err
	}
	authority, query, ok := strings.Cut(string(raw), "/?")
	// mihomo's six colon-delimited fields exclude literal IPv6 addresses.
	fields := strings.SplitN(authority, ":", 7)
	if !ok || len(fields) != 6 {
		return nil, fmt.Errorf("invalid SSR link fields")
	}
	// Convert the standard base64 alphabet before query parsing so a literal
	// plus sign in a value is not interpreted as a space.
	urlSafe := strings.NewReplacer("+", "-", "/", "_")
	password, err := base64.RawURLEncoding.DecodeString(urlSafe.Replace(fields[5]))
	if err != nil {
		return nil, fmt.Errorf("invalid SSR password encoding")
	}
	out := object{
		"type": "ssr", "name": "ssr@" + fields[0] + ":" + fields[1],
		"server": fields[0], "port": fields[1], "protocol": fields[2],
		"cipher": fields[3], "obfs": fields[4], "password": string(password), "udp": true,
	}
	params, err := url.ParseQuery(urlSafe.Replace(query))
	if err != nil {
		return nil, fmt.Errorf("invalid SSR link query")
	}
	// mihomo reads the first value of these three parameters. In particular,
	// group, udpport and uot do not change the endpoint or UDP transport.
	for _, option := range []struct{ link, clash string }{
		{"remarks", "name"}, {"obfsparam", "obfs-param"}, {"protoparam", "protocol-param"},
	} {
		value, err := base64.RawURLEncoding.DecodeString(params.Get(option.link))
		if err != nil {
			return nil, fmt.Errorf("invalid SSR link option encoding")
		}
		if len(value) > 0 {
			out[option.clash] = string(value)
		}
	}
	return out, nil
}
