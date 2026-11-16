// This separate module keeps the reference implementation out of Reka binaries.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MimoProxy/reka/internal/router"
	C "github.com/metacubex/mihomo/constant"
	MR "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	"net/netip"
	"os"
	"strings"
)

type test struct {
	Name                string
	Rules               []string
	Domain, Network, IP string
	Port                uint16
}
type env struct {
	calls   int
	address netip.Addr
}

func (e *env) Resolve(context.Context, string) ([]netip.Addr, error) {
	e.calls++
	return []netip.Addr{e.address}, nil
}
func (e *env) Process(context.Context) (string, bool) { return "", false }
func main() {
	cases := []test{
		{"domain-first", []string{"DOMAIN-KEYWORD,example,reject", "DOMAIN-SUFFIX,example.test,direct", "MATCH,direct"}, "a.example.test", "tcp", "", 443},
		{"domain-boundary", []string{"DOMAIN-SUFFIX,example.test,reject", "MATCH,direct"}, "badexample.test", "tcp", "", 443},
		{"domain-case", []string{"DOMAIN,EXAMPLE.TEST,reject", "MATCH,direct"}, "example.test", "tcp", "", 443},
		{"regex", []string{`DOMAIN-REGEX,^a[0-9]+\.test$,reject`, "MATCH,direct"}, "a12.test", "tcp", "", 443},
		{"ip-lazy", []string{"IP-CIDR,192.0.2.0/24,reject", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"no-resolve", []string{"IP-CIDR,192.0.2.0/24,reject,no-resolve", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"cached-no-resolve", []string{"IP-CIDR,198.51.100.0/24,direct", "IP-CIDR,192.0.2.0/24,reject,no-resolve", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"and-short-circuit", []string{"AND,((NETWORK,UDP),(IP-CIDR,192.0.2.0/24)),reject", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"and-match", []string{"AND,((NETWORK,TCP),(IP-CIDR,192.0.2.0/24)),reject", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"or-short-circuit", []string{"OR,((NETWORK,TCP),(IP-CIDR,192.0.2.0/24)),reject", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"nested-not", []string{"AND,((NETWORK,TCP),(NOT,((DST-PORT,80)))),reject", "MATCH,direct"}, "lookup.test", "tcp", "", 443},
		{"lan", []string{"GEOIP,LAN,reject,no-resolve", "MATCH,direct"}, "", "tcp", "192.168.1.2", 443},
		{"ipv6", []string{"IP-CIDR6,2001:db8::/32,reject,no-resolve", "MATCH,direct"}, "", "tcp", "2001:db8::1", 443},
		{"port-range", []string{"DST-PORT,8000-9000,reject", "MATCH,direct"}, "x.test", "tcp", "", 8080},
	}
	type result struct {
		Name, Native, Reference string
		NativeDNS, ReferenceDNS int
		Pass                    bool
	}
	out := struct {
		Version   string
		Cases     []result
		Passed    int
		Groups    []map[string]any
		Processes []map[string]any
	}{Version: "mihomo v1.19.34"}
	for _, tc := range cases {
		var native []router.RuleSpec
		var reference []C.Rule
		for _, line := range tc.Rules {
			spec, call, e := router.ParseClashRule(line)
			if e != nil || call != "" {
				panic(fmt.Sprint(line, e))
			}
			native = append(native, spec)
			tp, payload, target, params := RC.ParseRulePayload(line, true)
			rule, e := MR.ParseRule(tp, payload, target, params, nil)
			if e != nil {
				panic(fmt.Sprint(line, e))
			}
			reference = append(reference, rule)
		}
		set, e := router.CompileRules(native)
		if e != nil {
			panic(e)
		}
		r, e := router.New(set, router.Options{Outbounds: []string{"direct", "reject"}, Final: "direct"})
		if e != nil {
			panic(e)
		}
		md := router.Metadata{Domain: strings.ToLower(tc.Domain), Network: tc.Network, Port: tc.Port}
		if tc.IP != "" {
			md.Addr = netip.MustParseAddr(tc.IP)
		}
		en := &env{address: netip.MustParseAddr("192.0.2.1")}
		decision := r.Route(context.Background(), md, en)
		rm := &C.Metadata{Host: md.Domain, DstIP: md.Addr, DstPort: md.Port, NetWork: C.TCP}
		if tc.Network == "udp" {
			rm.NetWork = C.UDP
		}
		count := 0
		helper := C.RuleMatchHelper{ResolveIP: func() {
			if !rm.DstIP.IsValid() {
				count++
				rm.DstIP = en.address
			}
		}, FindProcess: func() {}, CheckPassRule: func(string) bool { return false }}
		target := "direct"
		for _, rule := range reference {
			if match, action := rule.Match(rm, helper); match {
				target = action
				break
			}
		}
		pass := target == decision.Outbound && count == en.calls
		if pass {
			out.Passed++
		}
		out.Cases = append(out.Cases, result{tc.Name, decision.Outbound, target, en.calls, count, pass})
	}
	out.Groups = groupDiff()
	out.Processes = processDiff()
	groupsPass := true
	for _, g := range append(out.Groups, out.Processes...) {
		groupsPass = groupsPass && g["pass"].(bool)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(out)
	if out.Passed != len(cases) || !groupsPass {
		os.Exit(1)
	}
}
