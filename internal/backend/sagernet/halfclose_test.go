package sagernet

import (
	"testing"
	"time"
)

// TestHalfCloseKeepsReply: after the client half-closes, the reply that is
// still on its way back must arrive in full, including over outbounds whose
// connections cannot half-close (Shadowsocks, REALITY).
func TestHalfCloseKeepsReply(t *testing.T) {
	ssPass := newSSPassword()
	ss := ssServer(t, ssMethod, ssPass, false)
	reality, pub, sid := realityServer(t, testUUID, "")
	cases := []struct {
		name string
		spec any
	}{
		{"direct", DirectSpec{}},
		{"shadowsocks", ShadowsocksSpec{Server: "127.0.0.1", Port: ss.Port(), Method: ssMethod, Password: ssPass}},
		{"vless-reality", realitySpec(reality, testUUID, "", pub, sid)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			socks, out := startClient(t, c.spec)
			target := echoServer(t)
			for i := range 10 {
				s := openStream(t, socks, target, false)
				time.Sleep(50 * time.Millisecond)
				if err := s.finish(); err != nil {
					t.Fatalf("round %d: %v", i, err)
				}
			}
			waitIdle(t, out)
		})
	}
}
