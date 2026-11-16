package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/MimoProxy/reka/internal/router"
	C "github.com/metacubex/mihomo/constant"
	MR "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

type processEnv string

func (p processEnv) Resolve(context.Context, string) ([]netip.Addr, error) { return nil, nil }
func (p processEnv) Process(context.Context) (string, bool)                { return string(p), p != "" }

func processDiff() []map[string]any {
	var results []map[string]any
	for _, tc := range []struct{ name, pattern, process string }{
		{"process-case", `^curl$`, "CURL"},
		{"process-lookbehind", `(?<=Google )Chrome`, "Google Chrome"},
		{"process-negative-lookahead", `^(?!curl$).+`, "curl"},
		{"process-comma", `^name,[a-z]+$`, "name,test"},
		{"process-escaped-parenthesis", `^name\(test\)$`, "name(test)"},
		{"process-no-match", `^curl$`, "other"},
	} {
		line := "PROCESS-NAME-REGEX," + tc.pattern + ",reject"
		spec, _, e := router.ParseClashRule(line)
		if e != nil {
			panic(e)
		}
		set, e := router.CompileRules([]router.RuleSpec{spec})
		if e != nil {
			panic(e)
		}
		r, e := router.New(set, router.Options{Outbounds: []string{"direct", "reject"}, Final: "direct"})
		if e != nil {
			panic(e)
		}
		decision := r.Route(context.Background(), router.Metadata{Network: "tcp"}, processEnv(tc.process))
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		ref, e := MR.ParseRule(tp, payload, target, params, nil)
		if e != nil {
			panic(fmt.Sprint(line, e))
		}
		match, action := ref.Match(&C.Metadata{Process: tc.process}, C.RuleMatchHelper{FindProcess: func() {}})
		if !match {
			action = "direct"
		}
		results = append(results, map[string]any{"name": tc.name, "native": decision.Outbound, "reference": action, "pass": decision.Outbound == action})
	}
	return results
}
