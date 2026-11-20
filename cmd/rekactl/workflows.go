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
		return strings.TrimSpace(strings.Join([]string{trace.RuleID, trace.Outbound}, " "))
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
