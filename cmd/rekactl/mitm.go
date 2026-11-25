package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

func cmdMITMStatus(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: mitm-status")
	}
	var status api.MITMStatus
	if err := call("GetMITMStatus", nil, &status); err != nil || *jsonFlag {
		return err
	}
	fmt.Printf("MITM enabled=%t CA loaded=%t HTTP/2=%s hostnames=%d connections=%d requests=%d\n",
		status.Enabled, status.CALoaded, status.H2, status.HostnameCount, status.Connections, status.Requests)
	if status.CAError != "" {
		fmt.Println("CA error", status.CAError)
	}
	for _, bypass := range status.PinningBypasses {
		fmt.Printf("bypass %s  %s  expires %s\n", bypass.Hostname, bypass.Reason, bypass.ExpiresAt.Local().Format(time.RFC3339))
	}
	scripts := status.Scripts
	fmt.Printf("Scripts %s count=%d runs=%d modified=%d failed=%d timeouts=%d oversize=%d circuit_open=%d notifications=%d notifications_dropped=%d\n",
		scripts.Status, scripts.Count, scripts.Runs, scripts.Modified, scripts.Failed, scripts.Timeouts,
		scripts.Oversize, scripts.CircuitOpen, scripts.Notifications, scripts.NotificationsDropped)
	return nil
}

func mitmProtocols(info api.MITMConnectionInfo) string {
	var protocols []string
	if info.MITMClientProtocol != "" {
		protocols = append(protocols, "client="+info.MITMClientProtocol)
	}
	if len(info.MITMUpstreamProtocols) != 0 {
		protocols = append(protocols, "upstream="+strings.Join(info.MITMUpstreamProtocols, ","))
	}
	if info.MITMSkipped != "" {
		protocols = append(protocols, "mitm-skipped="+info.MITMSkipped)
	}
	return strings.Join(protocols, " ")
}

func cmdRequests(args []string) error {
	fs := flag.NewFlagSet("requests", flag.ExitOnError)
	limit := fs.Int("limit", 20, "recent requests to list")
	before := fs.String("before", "", "request history cursor")
	query := fs.String("query", "", "search request history")
	parse(fs, args)
	if fs.NArg() != 0 {
		return errors.New("usage: requests [-limit N] [-before CURSOR] [-query TEXT]")
	}
	var page history.Page
	if err := call("ListRequestHistory", history.ListOptions{Limit: *limit, Before: *before, Query: *query}, &page); err != nil || *jsonFlag {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCONNECTION\tMETHOD\tHOST\tPATH\tSTATUS\tDURATION\tSCRIPTS")
	for _, row := range page.Rows {
		var request struct {
			ID           uint64              `json:"id"`
			ConnectionID uint64              `json:"connection_id"`
			Method       string              `json:"method"`
			Host         string              `json:"host"`
			Path         string              `json:"path"`
			StatusCode   int                 `json:"status_code"`
			DurationMS   int64               `json:"duration_ms"`
			Scripts      []api.MITMScriptRun `json:"scripts"`
		}
		if err := json.Unmarshal(row.Data, &request); err != nil {
			return err
		}
		fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%d\t%dms\t%s\n", request.ID, request.ConnectionID, request.Method,
			request.Host, request.Path, request.StatusCode, request.DurationMS, scriptRuns(request.Scripts))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if page.Expired {
		fmt.Println("History cursor expired")
	}
	if page.Next != "" {
		fmt.Println("Next cursor", page.Next)
	}
	return nil
}

func scriptStats(stats []api.MITMScriptStats) string {
	rows := make([]string, 0, len(stats))
	for _, stat := range stats {
		rows = append(rows, fmt.Sprintf("%s ×%d (%s)", stat.ID, stat.Count, stat.LastResult))
	}
	return strings.Join(rows, ", ")
}

func scriptRuns(runs []api.MITMScriptRun) string {
	rows := make([]string, 0, len(runs))
	for _, run := range runs {
		row := fmt.Sprintf("%s %s %s %dms", run.ID, run.Phase, run.Result, run.DurationMS)
		if run.Error != "" {
			row += fmt.Sprintf(" %q", run.Error)
		}
		rows = append(rows, row)
	}
	return strings.Join(rows, ", ")
}
