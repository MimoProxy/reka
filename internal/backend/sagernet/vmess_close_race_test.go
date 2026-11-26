package sagernet

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	VM "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type vmessCloseTestHandler struct{}

func (vmessCloseTestHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	if _, err := conn.Write([]byte("reply")); err == nil {
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (vmessCloseTestHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	_ = conn.Close()
}

// A multiplexed VMess client closes its connection while the session's
// receive loop may still be in the first Read, which installs the response
// reader. Under -race this covers Close not touching that reader.
func TestVMessClientCloseDuringFirstRead(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	service := VM.NewService[int](vmessCloseTestHandler{})
	if err := service.UpdateUsers([]int{0}, []string{id}, []int{0}); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	client, err := VM.NewClient(id, "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		local, remote := net.Pipe()
		go func() {
			_ = service.NewConnection(context.Background(), remote, M.Socksaddr{}, nil)
			_ = remote.Close()
		}()
		conn, err := client.DialConn(local, M.ParseSocksaddr("127.0.0.1:80"))
		if err != nil {
			t.Fatal(err)
		}
		read := make(chan struct{})
		go func() {
			defer close(read)
			_, _ = conn.Read(make([]byte, 16))
		}()
		// Give the reply time to arrive so the reader is usually installed
		// before Close, with nothing ordering the two goroutines.
		time.Sleep(5 * time.Millisecond)
		_ = conn.Close()
		<-read
	}
}
