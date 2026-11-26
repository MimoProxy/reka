package generation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"golang.org/x/crypto/ssh"
)

func TestSSHBackendOptions(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		p    *model.Protocol
	}{
		{"pinned", &model.Protocol{
			PrivateKey: string(pem.EncodeToMemory(block)), PrivateKeyPassphrase: "phrase",
			HostKey:           []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))},
			HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, ClientVersion: "SSH-2.0-test",
		}},
		{"explicit skip", &model.Protocol{InsecureSkipHostKey: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := specFor(compile.Outbound{Type: model.OutboundSSH, Server: "server.test", Port: 2222,
				Username: "alice", Password: "password", Protocol: tc.p,
			}).(sagernet.ProxySpec)
			if !ok || spec.Type != "ssh" || spec.Server != "server.test" || spec.Port != 2222 ||
				spec.Username != "alice" || spec.Password != "password" {
				t.Fatal("SSH endpoint or credentials did not reach the proxy backend")
			}
			var options struct {
				option.SSHOutboundOptions
				Skip bool `json:"reka_insecure_skip_host_key"`
			}
			if err := json.UnmarshalContext(t.Context(), spec.Options, &options); err != nil {
				t.Fatal(err)
			}
			if strings.Join(options.PrivateKey, "\n") != tc.p.PrivateKey || options.PrivateKeyPassphrase != tc.p.PrivateKeyPassphrase ||
				!slices.Equal(options.HostKey, tc.p.HostKey) || !slices.Equal(options.HostKeyAlgorithms, tc.p.HostKeyAlgorithms) ||
				options.ClientVersion != tc.p.ClientVersion || options.Skip != tc.p.InsecureSkipHostKey {
				t.Fatal("SSH options did not survive backend serialization")
			}
		})
	}
}
