// The peer serves only a TCP echo, a UDP echo and a test DNS zone.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/MimoProxy/reka/internal/packettunnellab"
)

func main() {
	bind := flag.String("bind", "", "private IPv4 address of the test host")
	fixturePath := flag.String("fixture", "", "path for the private device test fixture")
	port := flag.Uint("port", 0, "Shadowsocks port, zero for auto")
	flag.Parse()
	address, err := netip.ParseAddr(*bind)
	if err != nil || *fixturePath == "" || *port > 65535 {
		flag.Usage()
		os.Exit(2)
	}
	peer, err := packettunnellab.Start(address, uint16(*port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer peer.Close()
	if err := writeFixture(*fixturePath, peer.Fixture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		peer.Close()
		os.Exit(1)
	}
	fmt.Println("Reka iOS test peer ready")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

func writeFixture(path string, fixture packettunnellab.Fixture) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(file).Encode(fixture); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}
