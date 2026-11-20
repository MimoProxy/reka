package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

func cmdTimeline(args []string) error {
	fs := flag.NewFlagSet("timeline", flag.ExitOnError)
	epoch := fs.String("epoch", "", "connection history epoch")
	limit := fs.Int("limit", 20, "recent connections to list without an ID (1..100)")
	parse(fs, args)
	if fs.NArg() == 0 && *epoch == "" && *limit >= 1 && *limit <= 100 {
		var page history.Page
		if err := call("ListConnectionHistory", history.ListOptions{Limit: *limit}, &page); err != nil || *jsonFlag {
			return err
		}
		fmt.Println("History epoch", page.Epoch)
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tDESTINATION\tOUTBOUND\tCLOSED\tDURATION")
		for _, row := range page.Rows {
			var trace api.ConnectionTrace
			if json.Unmarshal(row.Data, &trace) == nil {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%dms\n", trace.ID, trace.Destination, trace.Outbound, trace.CloseReason, trace.DurationMS)
			}
		}
		return w.Flush()
	}
	if fs.NArg() != 1 {
		return errors.New("usage: timeline [CONNECTION-ID] [-epoch EPOCH] [-limit N]")
	}
	id, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil || id == 0 {
		return errors.New("connection ID must be a positive number")
	}
	var result api.ConnectionTimeline
	if err := call("GetConnectionTimeline", api.TimelineRequest{ID: id, Epoch: *epoch}, &result); err != nil || *jsonFlag {
		return err
	}
	trace := result.Trace
	fmt.Printf("%d  %s  %s\n", trace.ID, trace.Network, trace.Destination)
	for _, event := range result.Events {
		fmt.Printf("%s  %-13s %s\n", event.At.Local().Format("15:04:05.000"), event.Stage, timelineEventDetail(event, trace))
	}
	return nil
}

func timelineEventDetail(event api.TimelineEvent, trace api.ConnectionTrace) string {
	switch event.Stage {
	case "sniff-finish":
		return strings.TrimSpace(trace.Protocol + " " + trace.SniffedDomain)
	case "routed":
		return strings.TrimSpace(strings.Join([]string{trace.NetworkScene, trace.RuleID, trace.Outbound}, " "))
	case "dial-start":
		return trace.DialDestination
	case "dial-finish":
		return trace.DialPeer
	case "closed":
		return fmt.Sprintf("%s  ↑%d ↓%d bytes", trace.CloseReason, trace.Upload, trace.Download)
	case "dns", "http":
		var summary struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Host   string `json:"host"`
			Method string `json:"method"`
		}
		if json.Unmarshal(event.Data, &summary) == nil {
			return strings.TrimSpace(summary.Type + summary.Method + " " + summary.Name + summary.Host)
		}
	}
	return ""
}

func cmdTemporaryRule(args []string) error {
	if len(args) == 0 || (len(args) == 1 && args[0] == "list") {
		var list []api.TemporaryRule
		if err := call("ListTemporaryRules", nil, &list); err != nil || *jsonFlag {
			return err
		}
		for _, rule := range list {
			fmt.Printf("%s  %s  expires %s  active=%t\n", rule.ID, rule.Rule, rule.ExpiresAt.Local().Format(time.RFC3339), rule.Active)
		}
		return nil
	}
	if args[0] == "add" {
		fs := flag.NewFlagSet("temp-rule add", flag.ExitOnError)
		ttl := fs.Duration("ttl", 5*time.Minute, "lifetime (1s..24h, in whole seconds)")
		parse(fs, args[1:])
		if fs.NArg() != 1 || *ttl < time.Second || *ttl > 24*time.Hour || *ttl%time.Second != 0 {
			return errors.New("usage: temp-rule add [-ttl 5m] 'DOMAIN-SUFFIX,example.com,direct'")
		}
		var rule api.TemporaryRule
		if err := call("AddTemporaryRule", api.TemporaryRuleRequest{Rule: fs.Arg(0), TTLSeconds: int(*ttl / time.Second)}, &rule); err != nil || *jsonFlag {
			return err
		}
		fmt.Printf("%s  expires %s  active=%t\n", rule.ID, rule.ExpiresAt.Local().Format(time.RFC3339), rule.Active)
		return nil
	}
	if len(args) == 2 && args[0] == "remove" {
		return call("RemoveTemporaryRule", map[string]string{"id": args[1]}, nil)
	}
	return errors.New("usage: temp-rule list | add [-ttl 5m] RULE | remove ID")
}

func cmdScene(args []string) error {
	var status api.NetworkSceneStatus
	var err error
	switch {
	case len(args) == 0:
		err = call("GetNetworkScene", nil, &status)
	case len(args) == 1 && args[0] == "auto":
		err = call("SetNetworkScene", map[string]string{"scene": ""}, &status)
	case len(args) == 2 && args[0] == "use" && args[1] != "":
		err = call("SetNetworkScene", map[string]string{"scene": args[1]}, &status)
	default:
		return errors.New("usage: scene [use ID | auto]")
	}
	if err != nil || *jsonFlag {
		return err
	}
	mode := "auto"
	if status.Manual != "" {
		mode = "manual"
	}
	current := status.Current
	if current == "" {
		current = "none"
	}
	fmt.Printf("Scene %s (%s)\n", current, mode)
	if status.Interface != "" {
		fmt.Printf("Interface %s  %s\n", status.Interface, strings.Join(status.Addresses, ", "))
	}
	if status.Error != "" {
		fmt.Println(status.Error)
	}
	fmt.Println("Configured scenes", strings.Join(status.Scenes, ", "))
	return nil
}
