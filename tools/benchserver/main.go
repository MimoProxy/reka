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
	a, err := netip.ParseAddrPort(*address)
	if err != nil || !a.Addr().IsLoopback() {
		panic("loopback address required")
	}
	s, err := sagernet.StartShadowsocksServer(a, "aes-128-gcm", "reka-controlled-benchmark", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		panic(err)
	}
	defer s.Close()
	fmt.Println("ready")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
