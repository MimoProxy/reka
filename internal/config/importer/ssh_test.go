package importer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

func TestSSHClashNode(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const passphrase = "ssh-test-passphrase"
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(pem.EncodeToMemory(block))
	hostKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	hostKeys := []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))}
	algorithms := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512}
	node := object{
		"name": "SSH example", "type": "ssh", "server": "node.example", "port": "2222",
		"username": "ssh-test-user", "password": "ssh-test-password", "private-key": privateKey,
		"private-key-passphrase": passphrase, "host-key": hostKeys, "host-key-algorithms": algorithms,
		"tfo": true, "mptcp": true, "interface-name": "test-interface", "routing-mark": 42,
		"ip-version": "ipv6-prefer", "dialer-proxy": "DIRECT",
	}
	data, err := yaml.Marshal(object{"proxies": []object{node}})
	if err != nil {
		t.Fatal(err)
	}
	r := Import(request(string(data)))
	if !r.Report.CanApply || r.Report.Partial || len(r.Report.Diagnostics) != 0 {
		t.Fatal(r.Report)
	}
	out := compileImport(t, r).Outbounds[0]
	if out.Type != model.OutboundSSH || out.Server != "node.example" || out.Port != 2222 || out.Name != "SSH example" || out.Username != "ssh-test-user" || out.Password != "ssh-test-password" || out.UDP {
		t.Fatal("SSH endpoint or credentials changed during import")
	}
	p := out.Protocol
	if p == nil || p.PrivateKey != privateKey || p.PrivateKeyPassphrase != passphrase || !slices.Equal(p.HostKey, hostKeys) || !slices.Equal(p.HostKeyAlgorithms, algorithms) || p.InsecureSkipHostKey {
		t.Fatal("SSH key or algorithm options changed during import")
	}
	if d := out.Dialer; d == nil || !d.TFO || !d.MPTCP || d.Interface != "test-interface" || d.RoutingMark != 42 || d.IPVersion != "ipv6-prefer" || d.Proxy != "direct" {
		t.Fatal("SSH dialer options changed during import")
	}
	preview := r.Preview(false)
	if preview.Masked != 4 || !strings.Contains(preview.Sources, hostKeys[0]) {
		t.Fatal("SSH credential masking or public host key rendering changed")
	}
	for _, secret := range []string{"ssh-test-user", "ssh-test-password", passphrase, "BEGIN OPENSSH PRIVATE KEY", strings.Split(privateKey, "\n")[1]} {
		if strings.Contains(preview.Sources, secret) {
			t.Fatal("SSH preview exposed a credential")
		}
	}
}

func TestSSHClashUnpinnedHostAndUDP(t *testing.T) {
	const node = "proxies: [{name: test, type: ssh, server: node.example, port: 22, password: test-password, udp: true"
	for _, keys := range []string{"", ", host-key: []", ", host-key: null"} {
		r := Import(request(node + keys + "}]"))
		if !r.Report.CanApply || r.Report.Partial {
			t.Fatal(r.Report)
		}
		out := compileImport(t, r).Outbounds[0]
		if out.UDP || !out.Protocol.InsecureSkipHostKey || len(out.Protocol.HostKey) != 0 {
			t.Fatal("expected TCP-only SSH with explicit skip for an unpinned Clash node")
		}
		for path, code := range map[string]string{"/proxies/#0/host-key": "import.ssh.unverified-host-key", "/proxies/#0/udp": "import.ignored-field"} {
			if !slices.ContainsFunc(r.Preview(false).Report.Diagnostics, func(d model.Diagnostic) bool {
				return d.Severity == model.SeverityWarning && d.Code == code && d.Path == path && d.Line > 0
			}) {
				t.Fatal("missing SSH import warning", path, r.Report)
			}
		}
		if !slices.Contains(r.Report.Ignored, "/proxies/#0/udp") {
			t.Fatal("ignored UDP flag was omitted from the report")
		}
	}
}

func TestSSHClashRejectsUnsupportedOptions(t *testing.T) {
	const node = "proxies: [{name: test, type: ssh, server: node.example, password: test-password"
	for _, tc := range []struct{ options, field, code string }{
		{", port: 22, private-key: keys/ssh.pem", "private-key", "import.unsupported-field"},
		{", port: 22, host-key: invalid", "host-key", "import.type"},
		{", port: 22, host-key: [false]", "host-key", "import.type"},
		{", port: 22, host-key-algorithms: ssh-ed25519", "host-key-algorithms", "import.type"},
		{", port: 22, smux: {enabled: true}", "smux", "import.unsupported-field"},
		{", port: 22, client-version: SSH-2.0-example", "client-version", "import.unsupported-field"},
		{"", "port", "import.port"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			r := Import(request(node + tc.options + "}]"))
			if r.Report.CanApply || r.Report.Nodes.Unavailable != 1 || !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
				return d.Path == "/proxies/#0/"+tc.field && d.Code == tc.code
			}) {
				t.Fatal(r.Report)
			}
		})
	}
}
