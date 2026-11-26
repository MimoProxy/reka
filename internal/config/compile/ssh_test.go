package compile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"golang.org/x/crypto/ssh"
)

const sshProfile = `schema-version: 1
outbounds:
  - id: jump
    type: ssh
    server: jump.example
    password: example-password
    protocol:
      insecure-skip-host-key: true
`

func sshTestKeys(t *testing.T, passphrase string) (private, public string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host)))
}

func TestSSHCompileDefaults(t *testing.T) {
	e, ds := Compile([]byte(sshProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	node, _ := e.Outbound("jump")
	if node.Port != 22 || node.Username != "root" || node.UDP || node.Protocol == nil || !node.Protocol.InsecureSkipHostKey {
		t.Fatal("incorrect SSH defaults")
	}
	private, host := sshTestKeys(t, "")
	input := strings.Replace(sshProfile, "    password: example-password", "    udp: false", 1)
	input = strings.Replace(input, "insecure-skip-host-key: true", "host-key: ["+strconv.Quote(host)+"]", 1)
	input += "      private-key: " + strconv.Quote(private) + "\n"
	input += "      client-version: " + "SSH-2.0-" + strings.Repeat("a", 253-len("SSH-2.0-")) + "\n"
	e, ds = Compile([]byte(input), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	node, _ = e.Outbound("jump")
	if node.UDP || node.Protocol.PrivateKey != private || node.Protocol.InsecureSkipHostKey || !slices.Equal(node.Protocol.HostKey, []string{host}) {
		t.Fatal("SSH key authentication or host pin was lost")
	}
}

func TestSSHCompileOptionsAndSecrets(t *testing.T) {
	const passphrase = "private-key-passphrase-value"
	private, host := sshTestKeys(t, passphrase)
	secrets := store(t)
	for k, v := range map[string]string{"ssh/password": "server-password-value", "ssh/key": private, "ssh/passphrase": passphrase} {
		if err := secrets.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	input := strings.Replace(sshProfile, "    password: example-password",
		"    username: alice\n    port: 2222\n    password: secret://ssh/password", 1)
	input = strings.Replace(input, "insecure-skip-host-key: true", "host-key: ["+strconv.Quote(host)+"]", 1)
	input += `      private-key: secret://ssh/key
      private-key-passphrase: secret://ssh/passphrase
      host-key-algorithms: [ssh-ed25519, ssh-rsa]
      client-version: SSH-2.0-OpenSSH_9.6
`
	e, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o, _ := e.Outbound("jump")
	p := o.Protocol
	if o.Username != "alice" || o.Port != 2222 || o.UDP || o.Password != "server-password-value" ||
		p.PrivateKey != private || p.PrivateKeyPassphrase != passphrase || !slices.Equal(p.HostKey, []string{host}) ||
		!slices.Equal(p.HostKeyAlgorithms, []string{"ssh-ed25519", "ssh-rsa"}) || p.ClientVersion != "SSH-2.0-OpenSSH_9.6" {
		t.Fatal("SSH options did not survive compilation")
	}
	b, err := json.Marshal(o)
	if err != nil || bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, []byte(passphrase)) || bytes.Contains(b, []byte(o.Password)) {
		t.Fatal("effective outbound exposed SSH credentials", err)
	}
	// Isolate each resolved field, including the passphrase (re-encrypting a
	// real key under a new passphrase necessarily changes its PEM as well).
	for name, clear := range map[string]func(*model.Protocol){
		"private key": func(p *model.Protocol) { p.PrivateKey = "" },
		"passphrase":  func(p *model.Protocol) { p.PrivateKeyPassphrase = "" },
		"host key":    func(p *model.Protocol) { p.HostKey = nil },
		"algorithms":  func(p *model.Protocol) { p.HostKeyAlgorithms = nil },
		"version":     func(p *model.Protocol) { p.ClientVersion = "" },
		"skip":        func(p *model.Protocol) { p.InsecureSkipHostKey = true },
	} {
		copy := *p
		clear(&copy)
		changed := o
		changed.Protocol = &copy
		if outboundFingerprint(changed) == o.Fingerprint {
			t.Errorf("changing %s kept the SSH outbound fingerprint", name)
		}
	}
}

func TestSSHCompileValidation(t *testing.T) {
	const passphrase = "private-test-passphrase"
	private, host := sshTestKeys(t, passphrase)
	key := "private-key: " + strconv.Quote(private)
	pin := "host-key: [" + strconv.Quote(host) + "]"
	protocol := func(option string) string { return sshProfile + "      " + option + "\n" }
	option := func(field string) string {
		return strings.Replace(sshProfile, "    protocol:", "    "+field+"\n    protocol:", 1)
	}
	replace := func(old, new string) string { return strings.Replace(sshProfile, old, new, 1) }
	for _, tc := range []struct{ name, input, path, message string }{
		{"no authentication", replace("    password: example-password\n", ""), "password", "password or protocol/private-key"},
		{"empty private key", protocol("private-key: ''"), "protocol/private-key", "inline SSH private key"},
		{"invalid key", protocol("private-key: private-test-invalid"), "protocol/private-key", "cannot parse inline"},
		{"key path", protocol("private-key: /home/alice/.ssh/id_work"), "protocol/private-key", "cannot parse inline"},
		{"missing passphrase", protocol(key), "protocol/private-key-passphrase", "requires a passphrase"},
		{"wrong passphrase", protocol(key + "\n      private-key-passphrase: private-test-wrong"), "protocol/private-key-passphrase", "incorrect"},
		{"passphrase without key", protocol("private-key-passphrase: private-test-invalid"), "protocol/private-key-passphrase", "requires a private-key"},
		{"key reference", protocol("private-key: secret://missing-key"), "protocol/private-key", "no secret store"},
		{"passphrase reference", protocol(key + "\n      private-key-passphrase: secret://missing-phrase"), "protocol/private-key-passphrase", "no secret store"},
		{"no protocol", replace("    protocol:\n      insecure-skip-host-key: true\n", ""), "protocol/host-key", "set host-key or explicitly"},
		{"no host key", replace("insecure-skip-host-key: true", "host-key: []"), "protocol/host-key", "set host-key or explicitly"},
		{"verification without pins", replace("insecure-skip-host-key: true", "insecure-skip-host-key: false"), "protocol/host-key", "set host-key or explicitly"},
		{"conflicting host key", protocol(pin), "protocol/insecure-skip-host-key", "conflicts with host-key"},
		{"invalid host key", replace("insecure-skip-host-key: true", "host-key: ["+strconv.Quote(host)+", bad]"), "protocol/host-key/#1", "authorized_keys"},
		{"multiline host key", replace("insecure-skip-host-key: true", "host-key: ["+strconv.Quote("bad\n"+host)+"]"), "protocol/host-key/#0", "one authorized_keys"},
		{"invalid algorithm", protocol("host-key-algorithms: [invalid]"), "protocol/host-key-algorithms/#0", "unsupported"},
		{"duplicate algorithm", protocol("host-key-algorithms: [ssh-rsa, ssh-rsa]"), "protocol/host-key-algorithms/#1", "duplicate"},
		{"empty version", protocol("client-version: ''"), "protocol/client-version", "start with SSH-2.0-"},
		{"version prefix", protocol("client-version: HTTP-2.0-client"), "protocol/client-version", "start with SSH-2.0-"},
		{"long version", protocol("client-version: SSH-2.0-" + strings.Repeat("a", 254-len("SSH-2.0-"))), "protocol/client-version", "255 bytes including CRLF"},
		{"CRLF in version", protocol(`client-version: "SSH-2.0-test\r\njunk"`), "protocol/client-version", "printable ASCII"},
		{"control in version", protocol(`client-version: "SSH-2.0-test\x7f"`), "protocol/client-version", "printable ASCII"},
		{"missing server", replace("    server: jump.example\n", ""), "server", "server is required"},
		{"zero port", option("port: 0"), "port", "between 1 and 65535"},
		{"large port", option("port: 65536"), "port", "between 1 and 65535"},
		{"UDP", option("udp: true"), "udp", "SSH carries TCP only"},
		{"TLS", option("tls: {}"), "tls", "does not apply"},
		{"transport", option("transport: {type: ws}"), "transport", "does not apply"},
		{"multiplex", option("multiplex: {enabled: true}"), "multiplex", "does not accept multiplex"},
		{"disabled multiplex", option("multiplex: {enabled: false}"), "multiplex", "does not accept multiplex"},
		{"foreign option", protocol("public-key: abc"), "protocol/public-key", "does not apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ds := Compile([]byte(tc.input), nil, Options{})
			if e != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Path == "/outbounds/jump/"+tc.path && strings.Contains(d.Message, tc.message)
			}) {
				t.Fatalf("expected %s error containing %q, got %v", tc.path, tc.message, ds)
			}
			for _, d := range ds {
				if strings.Contains(d.Message, "PRIVATE KEY") || strings.Contains(d.Message, "private-test-") {
					t.Fatal("SSH validation diagnostic exposed credentials")
				}
			}
		})
	}
}
