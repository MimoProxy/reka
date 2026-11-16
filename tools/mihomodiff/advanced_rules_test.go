package main

import (
	"context"
	"net/netip"
	"runtime"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
	C "github.com/metacubex/mihomo/constant"
	MR "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

type advancedOwnerEnv struct{}

func (advancedOwnerEnv) Resolve(context.Context, string) ([]netip.Addr, error) {
	return nil, router.ErrNoLookup
}
func (advancedOwnerEnv) Process(context.Context) (string, bool) {
	return `C:\Program Files\APP.exe`, true
}
func (advancedOwnerEnv) ProcessInfo(context.Context) (router.ProcessInfo, bool) {
	return router.ProcessInfo{Path: `C:\Program Files\APP.exe`, UID: 10042, UIDKnown: true}, true
}

func TestAdvancedRulesAgainstPinnedMihomo(t *testing.T) {
	lines := []string{
		`PROCESS-PATH,c:\program files\app.exe,reject`,
		`PROCESS-PATH,c:\other\app.exe,reject`,
		`PROCESS-PATH-REGEX,(?<=Files\\)app(?=\.exe$),reject`,
		`PROCESS-NAME-WILDCARD,app.???,reject`,
		`PROCESS-PATH-WILDCARD,c:\*\app.???,reject`,
		`PROCESS-PATH-WILDCARD,c:\other\*,reject`,
		`IN-NAME,other/auth,reject`, `IN-NAME,AUTH,reject`,
		`IN-TYPE,http/socks,reject`, `IN-TYPE,TUN,reject`,
		`IN-PORT,80/17900-17800,reject`, `IN-PORT,80-90,reject`,
		`IN-USER,Bob/Alice,reject`, `IN-USER,alice,reject`,
		`AND,((IN-USER,Alice),(PROCESS-PATH-REGEX,APP\.exe$)),reject`,
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		lines = append(lines, `UID,10000/10100-10001,reject`, `UID,20000-21000,reject`)
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			native, _, err := router.ParseClashRule(line)
			if err != nil {
				t.Fatal(err)
			}
			set, err := router.CompileRules([]router.RuleSpec{native})
			if err != nil {
				t.Fatal(err)
			}
			r, err := router.New(set, router.Options{Outbounds: []string{"direct", "reject"}, Final: "direct"})
			if err != nil {
				t.Fatal(err)
			}
			tp, payload, target, params := RC.ParseRulePayload(line, true)
			ref, err := MR.ParseRule(tp, payload, target, params, nil)
			if err != nil {
				t.Fatal(err)
			}
			md := router.Metadata{Inbound: "auth", InboundType: "SOCKS5", InboundPort: 17890, InboundUser: "Alice"}
			rm := &C.Metadata{InName: "auth", Type: C.SOCKS5, InPort: 17890, InUser: "Alice", Process: "APP.exe", ProcessPath: `C:\Program Files\APP.exe`, Uid: 10042}
			got := r.Route(context.Background(), md, advancedOwnerEnv{})
			match, _ := ref.Match(rm, C.RuleMatchHelper{FindProcess: func() {}})
			if (got.Outbound == "reject") != match {
				t.Fatalf("Reka %+v differs from mihomo match=%v", got, match)
			}
		})
	}
}
