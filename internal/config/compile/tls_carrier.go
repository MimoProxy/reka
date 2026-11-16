package compile

import (
	"github.com/MimoProxy/reka/internal/config/model"
	RT "github.com/metacubex/restls-client-go"
	"slices"
)

func (c *compiler) tlsCarrier(path string, ob model.Outbound) *model.TLSCarrier {
	if ob.TLS.Carrier == nil {
		return nil
	}
	value := *ob.TLS.Carrier
	fail := func(field, message string) { c.errorf(model.DocProfile, path+"/"+field, "tls.carrier", "%s", message) }
	if !slices.Contains([]string{"vmess", "vless", "trojan"}, ob.Type) {
		fail("type", "security carriers apply to VMess, VLESS or Trojan")
	}
	if ob.TLS.Reality != nil || ob.TLS.ECH != nil {
		fail("type", "security carriers are mutually exclusive with REALITY and ECH")
	}
	fields := map[string][]string{"shadow-tls": {"type", "version", "password"}, "restls": {"type", "password", "version-hint", "script"}, "jls": {"type", "username", "password"}}
	allowed, ok := fields[value.Type]
	if !ok {
		fail("type", "unknown security carrier")
	}
	for _, field := range c.present(path) {
		if !slices.Contains(allowed, field) {
			fail(field, "field does not apply to this security carrier")
		}
	}
	value.Password = c.resolveSecret(path+"/password", value.Password)
	value.Username = c.resolveSecret(path+"/username", value.Username)
	switch value.Type {
	case "shadow-tls":
		if value.Version == 0 {
			value.Version = 2
		}
		if value.Version < 1 || value.Version > 3 {
			fail("version", "ShadowTLS version must be 1, 2 or 3")
		}
	case "restls":
		if len(value.Script) > 8192 {
			fail("script", "Restls record script exceeds budget")
		} else if _, err := RT.NewRestlsConfig(ob.TLS.ServerName, value.Password, value.VersionHint, value.Script, ob.TLS.Fingerprint); err != nil {
			fail("version-hint", err.Error())
		}
	case "jls":
		if value.Username == "" || value.Password == "" {
			fail("username", "JLS requires username and password")
		}
		if ob.TLS.CertificatePin != "" || ob.TLS.VerifyName != "" || ob.TLS.Certificate != "" || ob.TLS.PrivateKey != "" || ob.TLS.Insecure {
			fail("type", "JLS uses credential authentication rather than certificate options")
		}
	}
	if ob.Flow == "xtls-rprx-vision" && (ob.Encryption == "" || ob.Encryption == "none") && (value.Type != "jls" || ob.TLS.Fingerprint == "" || ob.TLS.Fingerprint == "none") {
		fail("type", "this Vision carrier combination requires VLESS encryption, matching the reference's supported TLS connection types")
	}
	return &value
}
