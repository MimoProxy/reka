package tunprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Targets are the hosts the checks talk to. Their addresses must be routed
// into the TUN. The defaults (AliDNS) serve HTTPS on their IPs and are
// directly reachable from mainland China networks.
type Targets struct {
	V4, V6 netip.Addr
	SNI    string
	Path   string
}

func DefaultTargets() Targets {
	return Targets{
		V4:   netip.MustParseAddr("223.5.5.5"),
		V6:   netip.MustParseAddr("2400:3200::1"),
		SNI:  "dns.alidns.com",
		Path: "/resolve?name=one.one.one.one&type=1",
	}
}

// Routes returns single-host prefixes for the targets.
func (t Targets) Routes() []netip.Prefix {
	routes := []netip.Prefix{netip.PrefixFrom(t.V4, 32)}
	if t.V6.IsValid() {
		routes = append(routes, netip.PrefixFrom(t.V6, 128))
	}
	return routes
}

type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail"`
	Duration string `json:"duration"`
}

type Report struct {
	OS, Arch, Stack, Device, BindInterface string
	Checks                                 []Check
	Warnings                               []string
	Stats                                  Stats
	GoSysMB, HeapInuseMB                   float64
	Pass                                   bool
}

// Run talks to the targets over TCP (HTTPS) and UDP (DNS) with ordinary,
// unbound sockets, so traffic follows the OS routing into the TUN, then
// checks that each request entered the TUN exactly once.
func (p *Probe) Run(t Targets) Report {
	r := Report{OS: runtime.GOOS, Arch: runtime.GOARCH, Stack: p.opts.Stack, Device: p.name, BindInterface: p.bindName}
	r.Checks = append(r.Checks, httpsCheck("tcp4 https", t.V4, t.SNI, t.Path))
	r.Checks = append(r.Checks, dnsCheck("udp4 dns", t.V4))
	if t.V6.IsValid() {
		r.Checks = append(r.Checks, httpsCheck("tcp6 https", t.V6, t.SNI, t.Path))
		r.Checks = append(r.Checks, dnsCheck("udp6 dns", t.V6))
	}
	time.Sleep(300 * time.Millisecond)
	st := p.Stats()
	r.Stats = st
	want6 := int64(0)
	if t.V6.IsValid() {
		want6 = 1
	}
	// A loop shows up as extra flows to the targets. Flows addressed to the
	// TUN itself come from elsewhere on the machine; they are dropped
	// (relaying them would loop) and only produce a warning. UDP may exceed
	// one flow when the OS itself sends DNS into the TUN.
	loopOK := st.TCP4 == 1 && st.TCP6 == want6 && st.UDP4 >= 1 && st.UDP6 >= want6 && st.RelayFailures == 0
	detail := fmt.Sprintf("tun saw tcp4=%d tcp6=%d udp4=%d udp6=%d (want 1/%d/>=1/>=%d), relay failures=%d",
		st.TCP4, st.TCP6, st.UDP4, st.UDP6, want6, want6, st.RelayFailures)
	if p.opts.Protect != nil {
		loopOK = loopOK && st.ProtectCalls > 0 && st.ProtectFailures == 0
		detail += fmt.Sprintf(", protect calls=%d failures=%d", st.ProtectCalls, st.ProtectFailures)
	}
	r.Checks = append(r.Checks, Check{Name: "through tun once, no loop", OK: loopOK, Detail: detail})
	if st.SelfDestined > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d flows addressed to the TUN's own address were dropped", st.SelfDestined))
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.GoSysMB = float64(ms.Sys) / (1 << 20)
	r.HeapInuseMB = float64(ms.HeapInuse) / (1 << 20)
	r.Pass = true
	for _, c := range r.Checks {
		r.Pass = r.Pass && c.OK
	}
	return r
}

// String renders the report as text.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tunprobe %s/%s stack=%s device=%s bind=%s\n", r.OS, r.Arch, r.Stack, r.Device, r.BindInterface)
	for _, c := range r.Checks {
		mark := "PASS"
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  %-4s %-26s %-8s %s\n", mark, c.Name, c.Duration, c.Detail)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  WARN %s\n", w)
	}
	fmt.Fprintf(&b, "  go sys %.1f MB, heap in use %.1f MB\n", r.GoSysMB, r.HeapInuseMB)
	return b.String()
}

func httpsCheck(name string, host netip.Addr, sni, path string) Check {
	start := time.Now()
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:   &tls.Config{ServerName: sni},
		},
	}
	resp, err := client.Get("https://" + netip.AddrPortFrom(host, 443).String() + path)
	c := Check{Name: name, Duration: time.Since(start).Round(time.Millisecond).String()}
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	c.Duration = time.Since(start).Round(time.Millisecond).String()
	c.OK = resp.StatusCode == 200
	c.Detail = fmt.Sprintf("status %d, %d bytes, %s", resp.StatusCode, len(body), resp.Proto)
	return c
}

func dnsCheck(name string, server netip.Addr) Check {
	start := time.Now()
	m := new(dns.Msg)
	m.SetQuestion("one.one.one.one.", dns.TypeA)
	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	resp, _, err := cl.ExchangeContext(ctx, m, netip.AddrPortFrom(server, 53).String())
	c := Check{Name: name, Duration: time.Since(start).Round(time.Millisecond).String()}
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	c.OK = resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
	c.Detail = fmt.Sprintf("rcode %s, %d answers", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	return c
}
