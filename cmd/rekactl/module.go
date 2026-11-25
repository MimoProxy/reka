package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

func cmdModule(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: module add|remove|enable|disable|set-arguments|refresh|list|report|preview")
	}
	action, args := args[0], args[1:]
	switch action {
	case "list":
		if len(args) != 0 {
			return errors.New("usage: module list")
		}
		var modules []api.ModuleInfo
		if err := call("ListModules", nil, &modules); err != nil {
			return err
		}
		if !*jsonFlag {
			for _, m := range modules {
				enabled := "enabled"
				if !m.Enabled {
					enabled = "disabled"
				}
				fmt.Printf("%s (%s, %s", m.ID, m.SourceType, enabled)
				if m.Format != "" {
					fmt.Printf(", %s", m.Format)
				}
				fmt.Printf("): %s", m.Status.State)
				if m.Status.ErrorCode != "" {
					fmt.Printf(" (%s)", m.Status.ErrorCode)
				}
				if m.Name != "" {
					fmt.Printf(" — %q", m.Name)
				}
				if m.Report != nil {
					fmt.Printf(" — scripts %d/%d", m.Report.Scripts.Imported, m.Report.Scripts.Total)
				}
				fmt.Println()
				if m.Report != nil {
					printModuleScripts(m.Report.ScriptItems)
				}
				printModuleScriptErrors(m.Status.ScriptErrors)
			}
		}
		return nil
	case "refresh":
		fs := flag.NewFlagSet("module refresh", flag.ExitOnError)
		async := fs.Bool("async", false, "return without waiting")
		parse(fs, args)
		if fs.NArg() != 1 {
			return errors.New("usage: module refresh ID [-async]")
		}
		var status api.ModuleStatus
		if err := call("RefreshModule", api.RefreshModuleRequest{ModuleID: fs.Arg(0), Wait: !*async}, &status); err != nil {
			return err
		}
		if !*jsonFlag {
			fmt.Printf("%s: %s", status.ModuleID, status.State)
			if status.ErrorCode != "" {
				fmt.Printf(" (%s)", status.ErrorCode)
			}
			fmt.Println()
			printModuleScriptErrors(status.ScriptErrors)
		}
		if !*async && status.State != "current" {
			return exitError
		}
		return nil
	case "report":
		if len(args) != 1 {
			return errors.New("usage: module report ID")
		}
		return showModuleReport("GetModuleReport", api.GetModuleReportRequest{ModuleID: args[0]})
	case "preview":
		fs := flag.NewFlagSet("module preview", flag.ExitOnError)
		format := fs.String("format", "", "module format (surge, loon, or stash)")
		arguments := moduleArguments(fs)
		parse(fs, args)
		if fs.NArg() != 1 {
			return errors.New("usage: module preview FILE [-format FORMAT] [-argument NAME=VALUE]...")
		}
		filename := fs.Arg(0)
		f := os.Stdin
		if filename != "-" {
			var err error
			f, err = os.Open(filename)
			if err != nil {
				return err
			}
			defer f.Close()
			filename = filepath.Base(filename)
		} else {
			filename = ""
		}
		data, err := io.ReadAll(io.LimitReader(f, model.MaxDocumentSize+1))
		if err != nil {
			return err
		}
		if len(data) > model.MaxDocumentSize {
			return errors.New("module exceeds the document size limit")
		}
		return showModuleReport("PreviewModule", api.PreviewModuleRequest{
			Data: string(data), Format: *format, Filename: filename, Arguments: arguments,
		})
	case "add", "remove", "enable", "disable", "set-arguments":
		return editModule(action, args)
	default:
		return errors.New("unknown module action")
	}
}

func editModule(action string, args []string) error {
	fs := flag.NewFlagSet("module "+action, flag.ExitOnError)
	var spec model.Module
	var position *int
	var disabled *bool
	if action == "add" {
		fs.StringVar(&spec.File, "file", "", "absolute path on the kernel host")
		fs.StringVar(&spec.Format, "format", "", "module format (surge, loon, or stash)")
		fs.IntVar(&spec.Interval, "interval", 0, "refresh interval in seconds")
		disabled = fs.Bool("disabled", false, "add without enabling")
		fs.Func("position", "zero-based insertion index", func(s string) error {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return errors.New("expected a non-negative index")
			}
			position = &n
			return nil
		})
	}
	if action == "add" || action == "set-arguments" {
		spec.Arguments = moduleArguments(fs)
	}
	parse(fs, args)
	if action == "add" {
		if spec.File == "" && fs.NArg() == 2 {
			spec.URL = fs.Arg(1)
		} else if spec.File == "" || fs.NArg() != 1 {
			return errors.New("usage: module add ID URL | module add ID -file PATH [-format FORMAT] [-interval N] [-disabled] [-position N] [-argument NAME=VALUE]...")
		}
		if *disabled {
			enabled := false
			spec.Enabled = &enabled
		}
	} else if fs.NArg() != 1 {
		return fmt.Errorf("usage: module %s ID", action)
	}
	spec.ID = fs.Arg(0)
	base, err := activeRevision()
	if err != nil {
		return err
	}
	var method string
	var params any
	switch action {
	case "add":
		method, params = "AddModule", api.AddModuleRequest{Module: spec, BaseRevision: base, Position: position}
	case "remove":
		method, params = "RemoveModule", api.RemoveModuleRequest{ModuleID: spec.ID, BaseRevision: base}
	case "enable", "disable":
		enabled := action == "enable"
		method, params = "SetModuleEnabled", api.SetModuleEnabledRequest{ModuleID: spec.ID, Enabled: &enabled, BaseRevision: base}
	case "set-arguments":
		method, params = "SetModuleArguments", api.SetModuleArgumentsRequest{ModuleID: spec.ID, BaseRevision: base, Arguments: spec.Arguments}
	}
	var result api.Result
	if err := call(method, params, &result); err != nil {
		return err
	}
	return printResult(result)
}

func moduleArguments(fs *flag.FlagSet) map[string]string {
	arguments := map[string]string{}
	fs.Func("argument", "module argument NAME=VALUE (repeatable)", func(value string) error {
		name, value, ok := strings.Cut(value, "=")
		if !ok || name == "" {
			return errors.New("expected NAME=VALUE")
		}
		arguments[name] = value
		return nil
	})
	return arguments
}

func showModuleReport(method string, params any) error {
	var report module.Report
	if err := call(method, params, &report); err != nil {
		return err
	}
	if !*jsonFlag {
		if report.Name != "" {
			fmt.Printf("%q\n", report.Name)
		}
		if report.Desc != "" {
			fmt.Printf("%q\n", report.Desc)
		}
		fmt.Printf("format %s, rules %d/%d, rewrites %d/%d, hostnames %d/%d, scripts %d/%d; partial: %t, can apply: %t\n",
			report.Format, report.Rules.Imported, report.Rules.Total, report.Rewrites.Imported, report.Rewrites.Total,
			report.Hostnames.Imported, report.Hostnames.Total, report.Scripts.Imported, report.Scripts.Total, report.Partial, report.CanApply)
		printModuleScripts(report.ScriptItems)
		for _, arg := range report.Arguments {
			fmt.Printf("  %q=%q (default %q)", arg.Name, arg.Value, arg.Default)
			if arg.Description != "" {
				fmt.Printf(" %q", arg.Description)
			}
			fmt.Println()
		}
		for _, line := range report.Lines {
			if line.Message != "" {
				fmt.Printf("  line %d [%q] %s: %s\n", line.Line, line.Section, line.Status, line.Message)
			}
		}
		printDiagnostics(report.Diagnostics)
	}
	if !report.CanApply {
		return exitError
	}
	return nil
}

func printModuleScripts(scripts []module.ScriptItem) {
	for _, script := range scripts {
		fmt.Printf("  script %s %q (%s) pattern %q, requires body %t, binary body %t, timeout %ds, engine %s",
			script.ID, script.Name, script.Type, script.Pattern, script.RequiresBody, script.BinaryBodyMode, script.Timeout, script.Engine)
		if script.MaxSize != nil {
			fmt.Printf(", max size %d", *script.MaxSize)
		}
		if script.Locked {
			fmt.Printf(", hash %s", script.Hash)
		} else {
			fmt.Print(", unlocked")
		}
		fmt.Println()
	}
}

func printModuleScriptErrors(errs []api.ModuleScriptError) {
	for _, err := range errs {
		fmt.Printf("  script request %s: %s\n", err.Request, err.Code)
	}
}
