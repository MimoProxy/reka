package sagernet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/mitm/ca"
)

type debugAuthority struct {
	host string
	port string
}

func (a debugAuthority) String() string { return net.JoinHostPort(a.host, a.port) }

func parseDebugAuthority(value string) (debugAuthority, error) {
	value = strings.TrimSpace(value)
	host, port := value, "443"
	if strings.Contains(value, ":") {
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return debugAuthority{}, fmt.Errorf("expected an exact DNS name with an optional port")
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return debugAuthority{}, fmt.Errorf("invalid HTTPS debug target port")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, ip := netip.ParseAddr(host); ip == nil || len(host) > 253 {
		return debugAuthority{}, fmt.Errorf("HTTPS debug requires DNS names")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return debugAuthority{}, fmt.Errorf("invalid HTTPS debug target name")
		}
		for _, c := range label {
			if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
				return debugAuthority{}, fmt.Errorf("use an exact ASCII DNS name (punycode for internationalized domains)")
			}
		}
	}
	return debugAuthority{host: host, port: strconv.FormatUint(number, 10)}, nil
}

func newDebugCertificates(targets []string, expires time.Time) (string, map[debugAuthority]tls.Certificate, error) {
	if len(targets) == 0 || len(targets) > 32 {
		return "", nil, fmt.Errorf("select 1–32 HTTPS debug targets")
	}
	certificates := make(map[debugAuthority]tls.Certificate, len(targets))
	for _, value := range targets {
		authority, err := parseDebugAuthority(value)
		if err != nil {
			return "", nil, err
		}
		certificates[authority] = tls.Certificate{}
	}
	root, err := ca.Generate(ca.GenerateOptions{CommonName: "Mimo Reka HTTPS Debug", NotAfter: expires})
	if err != nil {
		return "", nil, err
	}
	for authority := range certificates {
		certificate, err := root.Issue(authority.host, expires)
		if err != nil {
			return "", nil, err
		}
		certificates[authority] = certificate
	}
	// Only leaf keys survive initialization. The signing key is never stored or exported.
	return string(root.CertificatePEM()), certificates, nil
}
