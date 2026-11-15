// Command tunprobe checks TUN support on a desktop OS. It routes one IPv4
// and one IPv6 test host into a sing-tun device, then talks to both hosts
// over TCP (HTTPS) and UDP (DNS) using the normal system routing. Each
// request must arrive through the TUN exactly once and be relayed out via
// a socket bound to the physical interface; a second arrival means the
// relay looped back into the TUN. See internal/backend/sagernet/tunprobe.
//
// Needs root (macOS) or Administrator (Windows).
//
//	tunprobe [-stack mixed|system|gvisor] [-bind en0] [-v4 223.5.5.5] [-v6 2400:3200::1]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet/tunprobe"
)

func main() {
	def := tunprobe.DefaultTargets()
	stack := flag.String("stack", "mixed", "sing-tun stack: mixed, system or gvisor")
	bind := flag.String("bind", "", "interface relay sockets bind to (default: system default interface)")
	v4 := flag.String("v4", def.V4.String(), "IPv4 test host (serves HTTPS on its IP and DNS)")
	v6 := flag.String("v6", def.V6.String(), "IPv6 test host; empty to skip IPv6")
	sni := flag.String("sni", def.SNI, "TLS server name for the HTTPS check")
	path := flag.String("path", def.Path, "HTTPS path to fetch")
	verbose := flag.Bool("v", false, "debug logs")
	hold := flag.Duration("hold", 0, "keep the TUN up this long after the checks")
	flag.Parse()

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	targets := tunprobe.Targets{V4: netip.MustParseAddr(*v4), SNI: *sni, Path: *path}
	if *v6 != "" {
		targets.V6 = netip.MustParseAddr(*v6)
	}

	start := time.Now()
	p, err := tunprobe.Start(tunprobe.Options{
		Stack:         *stack,
		Inet4Address:  netip.MustParsePrefix("172.19.0.1/30"),
		Inet6Address:  netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		Routes:        targets.Routes(),
		BindInterface: *bind,
		Logger:        log,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	defer p.Close()
	up := time.Since(start)
	time.Sleep(time.Second) // let routes settle
	r := p.Run(targets)
	r.Checks = append([]tunprobe.Check{{Name: "tun up", OK: true, Detail: p.Name(), Duration: up.Round(time.Millisecond).String()}}, r.Checks...)
	fmt.Print(r.String())
	js, _ := json.Marshal(r)
	fmt.Println("JSON", string(js))
	if *hold > 0 {
		time.Sleep(*hold)
	}
	if !r.Pass {
		os.Exit(1)
	}
}
