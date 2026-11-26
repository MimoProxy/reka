package compile

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"golang.org/x/crypto/ssh"
)

var sshHostKeyAlgorithms = append(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys...)

func (c *compiler) ssh(base string, raw *model.Protocol, out *Outbound) {
	fail := func(field, message string) {
		c.errorf(model.DocProfile, base+"/"+field, "outbound.ssh", "%s", message)
	}
	if out.Username == "" {
		out.Username = "root"
	}
	p := model.Protocol{}
	if raw != nil {
		p = *raw
		p.HostKey = slices.Clone(raw.HostKey)
		p.HostKeyAlgorithms = slices.Clone(raw.HostKeyAlgorithms)
	}
	out.Protocol = &p
	keyPath := base + "/protocol/private-key"
	passphrasePath := base + "/protocol/private-key-passphrase"
	p.PrivateKey = c.resolveSecret(keyPath, p.PrivateKey)
	p.PrivateKeyPassphrase = c.resolveSecret(passphrasePath, p.PrivateKeyPassphrase)
	if p.PrivateKey == "" {
		if _, present := c.ppos[keyPath]; present && !c.hasErrorAt(keyPath) {
			fail("protocol/private-key", "expected an inline SSH private key")
		} else if out.Password == "" && !c.hasErrorAt(keyPath) && !c.hasErrorAt(base+"/password") {
			fail("password", "SSH requires a password or protocol/private-key")
		}
		if _, present := c.ppos[passphrasePath]; present && !c.hasErrorAt(keyPath) {
			fail("protocol/private-key-passphrase", "private-key-passphrase requires a private-key")
		}
	} else if !c.hasErrorAt(passphrasePath) {
		var key any
		var err error
		if p.PrivateKeyPassphrase == "" {
			key, err = ssh.ParseRawPrivateKey([]byte(p.PrivateKey))
		} else {
			key, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(p.PrivateKey), []byte(p.PrivateKeyPassphrase))
		}
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			fail("protocol/private-key-passphrase", "encrypted SSH private key requires a passphrase")
		case errors.Is(err, x509.IncorrectPasswordError):
			fail("protocol/private-key-passphrase", "incorrect SSH private key passphrase")
		case err != nil:
			fail("protocol/private-key", "cannot parse inline SSH private key with the supplied settings")
		default:
			if _, err := ssh.NewSignerFromKey(key); err != nil {
				fail("protocol/private-key", "private key cannot be used for SSH authentication")
			}
		}
	}
	if len(p.HostKey) == 0 && !p.InsecureSkipHostKey {
		fail("protocol/host-key", "set host-key or explicitly set insecure-skip-host-key to true")
	}
	if len(p.HostKey) > 0 && p.InsecureSkipHostKey {
		fail("protocol/insecure-skip-host-key", "insecure-skip-host-key conflicts with host-key")
	}
	for i, value := range p.HostKey {
		line := strings.TrimSpace(value)
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil || strings.ContainsAny(line, "\r\n") {
			fail(fmt.Sprintf("protocol/host-key/#%d", i), "expected one authorized_keys public key line")
		}
	}
	seen := make(map[string]bool, len(p.HostKeyAlgorithms))
	for i, algo := range p.HostKeyAlgorithms {
		field := fmt.Sprintf("protocol/host-key-algorithms/#%d", i)
		if !slices.Contains(sshHostKeyAlgorithms, algo) {
			fail(field, "unsupported SSH host key algorithm")
		} else if seen[algo] {
			fail(field, "duplicate SSH host key algorithm")
		}
		seen[algo] = true
	}
	if _, present := c.ppos[base+"/protocol/client-version"]; present {
		// x/crypto/ssh appends CRLF to the identification string on the wire.
		if !strings.HasPrefix(p.ClientVersion, "SSH-2.0-") || len(p.ClientVersion)+2 > 255 ||
			strings.IndexFunc(p.ClientVersion, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
			fail("protocol/client-version", "client-version must start with SSH-2.0-, contain printable ASCII, and fit in 255 bytes including CRLF")
		}
	}
}
