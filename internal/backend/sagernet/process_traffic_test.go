package sagernet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
)

func TestProcessTrafficCardinalityUnknownAndClosedCounters(t *testing.T) {
	b := New(Options{})
	defer b.Close()
	var wg sync.WaitGroup
	for i := 0; i < MaxProcessTrafficEntries+40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, end := b.beginProcessTraffic(ProcessInfo{Path: fmt.Sprintf("/app/%d", i), UID: 501, UIDKnown: true, PID: uint32(i + 1)})
			c.upload.Add(3)
			c.download.Add(5)
			end()
			end()
		}(i)
	}
	wg.Wait()
	u, end := b.beginProcessTraffic(ProcessInfo{})
	u.upload.Add(7)
	end()
	var rows []ProcessTrafficRow
	total := 0
	for offset := 0; ; offset += 1000 {
		page, n := b.ProcessTraffic(offset, 1000)
		total = n
		rows = append(rows, page...)
		if offset+len(page) >= n {
			break
		}
	}
	if total != MaxProcessTrafficEntries+2 {
		t.Fatalf("unbounded identities: %d", total)
	}
	var upload, download uint64
	var overflow, unknown bool
	for _, r := range rows {
		upload += r.Upload
		download += r.Download
		if r.Active != 0 {
			t.Fatal("closed flow still active")
		}
		overflow = overflow || r.Overflow
		unknown = unknown || r.Unknown
	}
	if !overflow || !unknown || upload != uint64((MaxProcessTrafficEntries+40)*3+7) || download != uint64((MaxProcessTrafficEntries+40)*5) {
		t.Fatalf("lost retained bytes %d %d", upload, download)
	}
	// A new PID for an existing executable/user must retain the same bucket.
	c, end := b.beginProcessTraffic(ProcessInfo{Path: rows[0].Path, UID: 501, UIDKnown: true, PID: 999999})
	end()
	if c.id != rows[0].ID {
		t.Fatal("PID churn split stable application counter")
	}
}

func TestProcessTrafficRealTCPUDPClosedTotals(t *testing.T) {
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	b.SetRoute(func(ctx context.Context, md Metadata) Route {
		rt := Fixed(direct)(ctx, md)
		rt.Owner = ProcessInfo{Path: "/app/echo", UID: 501, UIDKnown: true, PID: 321}
		return rt
	})
	var inbound *Inbound
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		inbound, err = b.NewMixedInbound("mixed", address)
		return err
	})
	defer inbound.Close()
	roundTrip(t, listen, echoServer(t), false, 4096)
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 256)
		n, peer, err := echo.ReadFrom(buffer)
		if err == nil {
			_, _ = echo.WriteTo(buffer[:n], peer)
		}
	}()
	client := New(Options{})
	defer client.Close()
	out, err := client.NewOutbound("socks", SOCKSSpec{Server: "127.0.0.1", Port: listen.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := out.Dial(ctx, "udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 32)
	n, err := conn.Read(reply)
	if err != nil || string(reply[:n]) != "packet" {
		t.Fatal(n, err)
	}
	conn.Close()
	b.CloseConnections(nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, _ := b.ProcessTraffic(0, 100)
		if len(rows) == 1 && rows[0].Active == 0 {
			if rows[0].Upload != 4102 || rows[0].Download != 4102 || rows[0].Connections != 2 {
				t.Fatal(rows)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	rows, _ := b.ProcessTraffic(0, 100)
	t.Fatal("connections did not close", rows)
}

func TestDarwinProcessLookupRetainsActualPID(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin socket owner contract")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	b := New(Options{FindProcess: true})
	defer b.Close()
	md := Metadata{Network: "tcp", Source: client.LocalAddr().(*net.TCPAddr).AddrPort(), Local: server.LocalAddr().(*net.TCPAddr).AddrPort()}
	info, ok := b.FindProcessInfo(context.Background(), md)
	if !ok || info.Path == "" || info.PID != uint32(os.Getpid()) {
		t.Fatalf("owner=%+v known=%v", info, ok)
	}
}

func TestDarwinHTTPProxyFindsCurlProcess(t *testing.T) {
	if os.Getenv("REKA_TEST_PROCESS_OWNER_INTEGRATION") != "1" {
		t.Skip("Set REKA_TEST_PROCESS_OWNER_INTEGRATION=1 and run the compiled test directly in a context with cross-process socket visibility")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin owner integration")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("owner")) }))
	defer server.Close()
	b := New(Options{FindProcess: true, Logger: testLogger(t)})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	observed := make(chan ProcessInfo, 1)
	ports := make(chan uint16, 1)
	var previousPort uint16
	var previousPID uint32
	b.SetRoute(func(ctx context.Context, md Metadata) Route {
		owner, _ := b.FindProcessInfo(ctx, md)
		observed <- owner
		ports <- md.Source.Port()
		rt := Fixed(direct)(ctx, md)
		rt.Owner = owner
		return rt
	})
	var in *Inbound
	address := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		in, err = b.NewMixedInbound("test", address)
		return err
	})
	defer in.Close()
	for request := 0; request < 2; request++ {
		command := exec.Command("/usr/bin/curl", "--silent", "--show-error", "--max-time", "5", "--noproxy", "", "--proxy", "http://"+address.String(), server.URL)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(output))
		}
		owner := <-observed
		port := <-ports
		if request > 0 && (port == previousPort || owner.PID == previousPID) {
			t.Fatal("regression must exercise a new process and client source port")
		}
		previousPort, previousPID = port, owner.PID
		if owner.Path != "/usr/bin/curl" || !owner.UIDKnown || owner.PID == 0 {
			t.Fatal("native HTTP did not attribute actual curl", owner)
		}
	}
}
