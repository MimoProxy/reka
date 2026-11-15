// tunsmoke exercises the production TUN path. Default-route takeover requires
// the explicit -full flag; the default uses narrow test-host routes.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/secret"
	D "github.com/miekg/dns"
	"io"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	v4 := flag.String("v4", "223.5.5.5", "IPv4 test target")
	v6 := flag.String("v6", "", "optional IPv6 test target")
	bind := flag.String("bind", "", "physical interface override")
	networkService := flag.String("service", "", "macOS network service for full takeover DNS")
	full := flag.Bool("full", false, "capture default routes for configured families; excludes 10.0.0.0/8 for management")
	hijack := flag.Bool("hijack", true, "consume DNS locally; false tests real forwarded DNS on partial routes")
	stack := flag.String("stack", "mixed", "TUN stack")
	flag.Parse()
	root, e := os.MkdirTemp("", "reka-tunsmoke-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(root)
	sec, e := secret.NewFileStore(root+"/secrets.json", nil)
	if e != nil {
		return e
	}
	profile := `schema-version: 1
dns:
 nameserver: [223.5.5.5]
 default-nameserver: [223.5.5.5]
 proxy-server-nameserver: [223.5.5.5]
 hosts: [{id: fixture.reka.test, addresses: [192.0.2.7]}]
 use-hosts: true
`
	profile += fmt.Sprintf("rules:\n - {id: probe, match: {and: [{ip-cidr: '%s/32'}, {dst-port: '443'}, {network: tcp}]}, outbound: direct}\n - {id: final, match: {all: true}, outbound: direct}\n", *v4)
	local := fmt.Sprintf("network:\n mode: tun\n tun:\n  stack: %s\n  mtu: 1500\n  dns-hijack: true\n  bind-interface: %q\n  routes: [%s/32]\n", *stack, *bind, *v4)
	if *v6 != "" {
		local = fmt.Sprintf("network:\n mode: tun\n tun:\n  stack: %s\n  mtu: 1500\n  dns-hijack: true\n  bind-interface: %q\n  address6: 'fdfe:dcba:9876::1/126'\n  routes: [%s/32, '%s/128']\n", *stack, *bind, *v4, *v6)
	}
	if !*hijack {
		local = strings.Replace(local, "dns-hijack: true", "dns-hijack: false", 1)
	}
	if *full {
		start := strings.Index(local, "  routes:")
		if start >= 0 {
			end := strings.Index(local[start:], "\n")
			local = local[:start] + local[start+end+1:]
		}
		local += "  exclude-routes: [10.0.0.0/8]\n"
	}
	if *networkService != "" {
		local = strings.Replace(local, " mode: tun\n", fmt.Sprintf(" mode: tun\n service: %q\n", *networkService), 1)
	}
	k, e := daemon.Start(daemon.Options{StateRoot: root, Secrets: sec, InitialProfile: []byte(profile), InitialLocal: []byte(local), ControlAddress: "-"})
	if e != nil {
		return e
	}
	defer k.Close()
	if s := k.Service.StartError(); s != "" {
		return fmt.Errorf("start: %s", s)
	}
	before := k.Service.Engine().Status()
	if before.Network.State != "Running" {
		return fmt.Errorf("not running: %+v", before)
	}
	for _, ip := range []string{*v4, *v6} {
		if ip == "" {
			continue
		}
		if e = checkDNS(ip, *hijack); e != nil {
			return e
		}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: "dns.alidns.com"}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	url := "https://" + netip.AddrPortFrom(netip.MustParseAddr(*v4), 443).String() + "/resolve?name=one.one.one.one&type=1"
	get := func() error {
		res, e := client.Get(url)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		_, e = io.Copy(io.Discard, res.Body)
		if res.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", res.StatusCode)
		}
		return e
	}
	if e = get(); e != nil {
		return fmt.Errorf("initial HTTPS: %w", e)
	}
	if *v6 != "" {
		ipv6URL := "https://" + netip.AddrPortFrom(netip.MustParseAddr(*v6), 443).String() + "/resolve?name=one.one.one.one&type=1"
		res, err := client.Get(ipv6URL)
		if err != nil {
			return fmt.Errorf("IPv6 HTTPS: %w", err)
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 {
			return fmt.Errorf("IPv6 HTTPS response: %v HTTP %d", err, res.StatusCode)
		}
	}
	req := service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: k.Service.ActiveRevision(), Patch: []model.Op{{Op: "set", Path: "/rules/probe/outbound", Value: []byte(`"reject"`)}}}}
	r, e := k.Service.Commit(context.Background(), req)
	if e != nil || r.State != "committed" {
		return fmt.Errorf("commit %+v: %v", r, e)
	}
	after := k.Service.Engine().Status()
	if after.Network.Device != before.Network.Device || r.Plan.NetworkChanged || r.Plan.Interrupts {
		return fmt.Errorf("TUN rebuilt on rule update")
	}
	if e = get(); e != nil {
		return fmt.Errorf("existing HTTPS connection interrupted: %w", e)
	}
	newTr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: "dns.alidns.com"}}
	defer newTr.CloseIdleConnections()
	fresh := &http.Client{Transport: newTr, Timeout: 3 * time.Second}
	res, e := fresh.Get(url)
	if e == nil {
		res.Body.Close()
		return fmt.Errorf("new connection bypassed rejection")
	}
	report := map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "stack": *stack, "before": before, "after": after, "dns_tcp_udp": "pass", "new_connection_rejected": true, "existing_https_intact": true, "scope": map[bool]string{false: "test-host routes only", true: "default routes for configured families; assertions use selected test targets"}[*full], "dns_hijacked": *hijack, "pass": true}
	b, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(b))
	return nil
}
func checkDNS(ip string, fixture bool) error {
	for _, network := range []string{"udp", "tcp"} {
		q := new(D.Msg)
		if fixture {
			q.SetQuestion("fixture.reka.test.", D.TypeA)
		} else {
			q.SetQuestion("one.one.one.one.", D.TypeA)
		}
		cl := &D.Client{Net: network, Timeout: 5 * time.Second}
		m, _, e := cl.Exchange(q, netip.AddrPortFrom(netip.MustParseAddr(ip), 53).String())
		if e != nil {
			return fmt.Errorf("%s DNS %s: %w", network, ip, e)
		}
		if !fixture {
			if m.Rcode != D.RcodeSuccess || len(m.Answer) == 0 {
				return fmt.Errorf("forwarded DNS failed: %v", m)
			}
			continue
		}
		if len(m.Answer) != 1 || m.Answer[0].String() != "fixture.reka.test.\t60\tIN\tA\t192.0.2.7" {
			rr, ok := firstA(m)
			if !ok || rr != "192.0.2.7" {
				return fmt.Errorf("DNS hijack failed: %v", m)
			}
		}
	}
	return nil
}
func firstA(m *D.Msg) (string, bool) {
	if len(m.Answer) == 0 {
		return "", false
	}
	v, ok := m.Answer[0].(*D.A)
	if !ok {
		return "", false
	}
	return v.A.String(), true
}
