package sagernet

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// HTTPUpgrade can cache a partial Trojan key while hijacking the HTTP
// connection. The loopback node must accept a key split across stream reads.
func TestTrojanNodeFragmentedAuthentication(t *testing.T) {
	for _, fragment := range []int{1, 17, 55} {
		t.Run(fmt.Sprint(fragment), func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			handler := &fragmentHandler{packets: make(chan bool, 1)}
			service := trojan.NewService[int](handler, nil, logger.NOP())
			if err := service.UpdateUsers([]int{1}, []string{"fragmented-password"}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- service.NewConnection(context.Background(), &firstFragmentConn{Conn: server, limit: fragment}, M.Socksaddr{}, nil)
				_ = server.Close()
			}()
			err := trojan.ClientHandshakeRaw(client, trojan.Key("fragmented-password"), trojan.CommandUDP, M.ParseSocksaddr("127.0.0.1:5353"), nil)
			serverErr := <-done
			if err != nil || serverErr != nil {
				t.Fatalf("fragmented authentication: client=%v server=%v", err, serverErr)
			}
			select {
			case udp := <-handler.packets:
				if !udp {
					t.Fatal("UDP command was not preserved")
				}
			default:
				t.Fatal("authenticated packet connection was not delivered")
			}
		})
	}
}

type firstFragmentConn struct {
	net.Conn
	limit int
}

func (c *firstFragmentConn) Read(p []byte) (int, error) {
	if c.limit > 0 && len(p) > c.limit {
		p = p[:c.limit]
	}
	c.limit = 0
	return c.Conn.Read(p)
}

type fragmentHandler struct{ packets chan bool }

func (h *fragmentHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	h.packets <- false
}

func (h *fragmentHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	h.packets <- true
}
