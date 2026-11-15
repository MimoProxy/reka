// benchserver is a local-only controlled Shadowsocks server for compare-bench.py.
package main

import (
	"flag"
	"fmt"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	address := flag.String("listen", "127.0.0.1:18388", "local test listener")
	flag.Parse()
	a, e := netip.ParseAddrPort(*address)
	if e != nil || !a.Addr().IsLoopback() {
		panic("loopback address required")
	}
	s, e := sagernet.StartShadowsocksServer(a, "aes-128-gcm", "reka-controlled-benchmark", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		panic(e)
	}
	defer s.Close()
	fmt.Println("ready")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
