package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/MimoProxy/reka/internal/api"
)

func cmdScripts(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: scripts")
	}
	var list api.ScriptList
	if err := call("ListScripts", nil, &list); err != nil || *jsonFlag {
		return err
	}
	fmt.Println("Scripts", list.Status)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tNAME\tSCHEDULE / EVENT\tNEXT RUN\tLAST RESULT")
	for _, item := range list.Scripts {
		next, last := "-", "-"
		if item.NextRun != nil {
			next = item.NextRun.Local().Format(time.RFC3339)
		}
		if item.LastRun != nil {
			last = item.LastRun.Result
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", item.ID, item.Type, item.Name, cmp.Or(item.CronExp, item.EventName, "-"), next, last)
	}
	return w.Flush()
}

func cmdScriptRun(args []string) error {
	fs := flag.NewFlagSet("script-run", flag.ExitOnError)
	var req api.RunScriptRequest
	fs.Func("argument", "override the script argument", func(value string) error {
		req.Argument = &value
		return nil
	})
	noWait := fs.Bool("no-wait", false, "return after starting the script")
	parse(fs, args)
	if fs.NArg() != 1 {
		return errors.New("usage: script-run ID [-argument TEXT] [-no-wait]")
	}
	req.ID = fs.Arg(0)
	if *noWait {
		wait := false
		req.Wait = &wait
	}
	var run api.ScriptRun
	if err := call("RunScript", req, &run); err != nil || *jsonFlag {
		return err
	}
	fmt.Printf("%s run %d  %s  %dms\n", run.ID, run.RunID, run.Result, run.DurationMS)
	if run.Error != "" {
		fmt.Println("Error", run.Error)
	}
	if len(run.Value) > 0 {
		fmt.Printf("Value %s\n", run.Value)
	}
	if run.ValueTruncated {
		fmt.Println("Value truncated")
	}
	for _, line := range run.Logs {
		fmt.Printf("[%s] %s\n", line.Level, line.Message)
	}
	if run.LogsTruncated {
		fmt.Println("Logs truncated")
	}
	return nil
}

func cmdScriptRuns(args []string) error {
	fs := flag.NewFlagSet("script-runs", flag.ExitOnError)
	id := fs.String("id", "", "filter by script ID")
	limit := fs.Int("limit", 20, "recent runs to list")
	parse(fs, args)
	if fs.NArg() != 0 {
		return errors.New("usage: script-runs [-id ID] [-limit N]")
	}
	var runs []api.ScriptRun
	if err := call("GetScriptRuns", api.GetScriptRunsRequest{ID: *id, Limit: *limit}, &runs); err != nil || *jsonFlag {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RUN\tID\tTRIGGER\tSTARTED\tDURATION\tRESULT\tERROR")
	for _, run := range runs {
		trigger := run.Trigger
		if run.Event != "" {
			trigger += "/" + run.Event
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%dms\t%s\t%s\n", run.RunID, run.ID, trigger, run.StartedAt.Local().Format(time.RFC3339), run.DurationMS, run.Result, run.Error)
	}
	return w.Flush()
}
