package kcptun

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/sagernet/smux"
)

type countedPacket struct {
	net.PacketConn
	once   sync.Once
	closed *atomic.Int32
}

func (p *countedPacket) Close() error {
	var err error
	p.once.Do(func() { err = p.PacketConn.Close(); p.closed.Add(1) })
	return err
}
func poolPeer(t *testing.T, config Config) net.Addr {
	t.Helper()
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := kcp.ServeConn(config.NewBlock(), config.DataShard, config.ParityShard, pc)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		pc.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := listener.AcceptKCP()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			c.SetStreamMode(true)
			c.SetNoDelay(1, 10, 2, 1)
			go func() {
				var carrier net.Conn = c
				if !config.NoComp {
					carrier = NewCompStream(c)
				}
				s, err := smux.Server(carrier, smux.DefaultConfig())
				if err != nil {
					c.Close()
					return
				}
				defer s.Close()
				for {
					stream, err := s.AcceptStream()
					if err != nil {
						return
					}
					go func() { defer stream.Close(); io.Copy(stream, stream) }()
				}
			}()
		}
	}()
	return pc.LocalAddr()
}
func TestPoolReuseRetirementResetAndClose(t *testing.T) {
	config := Config{Key: "pool-secret", AutoExpire: 1, ScavengeTTL: 1}
	addr := poolPeer(t, config)
	var opened, closed atomic.Int32
	client, err := NewClient(config, func(context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		opened.Add(1)
		return &countedPacket{PacketConn: pc, closed: &closed}, addr, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func() net.Conn {
		t.Helper()
		c, err := client.DialContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	round := func(c net.Conn) {
		t.Helper()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("pool")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "pool" {
			t.Fatalf("roundtrip %q %v", b, err)
		}
	}
	first := dial()
	defer first.Close()
	round(first)
	second := dial()
	round(second)
	second.Close()
	if opened.Load() != 1 {
		t.Fatal("idle pool was not reused", opened.Load())
	}
	client.mu.Lock()
	client.slots[0].expires = time.Now().Add(-time.Millisecond)
	client.mu.Unlock()
	replacement := dial()
	defer replacement.Close()
	round(replacement)
	round(first)
	if opened.Load() != 2 || closed.Load() != 0 {
		t.Fatal("retired active carrier did not drain", opened.Load(), closed.Load())
	}
	first.Close()
	if closed.Load() != 1 {
		t.Fatal("drained retired carrier leaked", closed.Load())
	}
	client.Reset()
	if closed.Load() != 2 {
		t.Fatal("reset leaked carrier", closed.Load())
	}
	afterReset := dial()
	round(afterReset)
	afterReset.Close()
	if opened.Load() != 3 {
		t.Fatal("reset reused stale carrier")
	}
	client.SetKeepIdleConnections(false)
	if closed.Load() != 3 {
		t.Fatal("idle carrier leaked after retirement")
	}
	client.Close()
	client.Close()
	if closed.Load() != opened.Load() {
		t.Fatal("physical UDP sockets leaked")
	}
	if _, err := client.DialContext(ctx); err == nil {
		t.Fatal("closed pool accepted a new stream")
	}
}
func TestCloseCancelsInflightPacketDial(t *testing.T) {
	entered := make(chan struct{})
	c, err := NewClient(Config{}, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		close(entered)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.DialContext(context.Background()); done <- err }()
	<-entered
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pool close did not cancel packet dial")
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled packet dial succeeded")
	}
}
func TestConfigAllocationBudgets(t *testing.T) {
	for _, config := range []Config{{Conn: -1}, {Conn: 65}, {MTU: 20000}, {SmuxBuf: 1 << 30}, {DataShard: 250, ParityShard: 200}, {KeepAlive: -1}, {StreamBuf: 32 << 20, SmuxBuf: 1 << 20}} {
		if err := config.Normalize(); err == nil {
			t.Fatal("invalid config accepted", config)
		}
	}
	config := Config{}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	if config.Key != "it's a secrect" || config.Interval != 30 || config.MTU != 1350 || config.SmuxVer != 1 {
		t.Fatal("reference defaults changed")
	}
}
