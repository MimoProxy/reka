package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
)

func cmdResource(args []string) error {
	usage := errors.New("usage: resource list | add KIND ID URL -format FORMAT [-behavior BEHAVIOR] [-interval SECONDS] [-manual] | refresh KIND ID")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return usage
		}
		var statuses []api.ManagedResourceStatus
		if err := call("ListManagedResources", nil, &statuses); err != nil {
			return err
		}
		if !*jsonFlag {
			for _, status := range statuses {
				printResourceStatus(status)
			}
		}
		return nil
	case "refresh":
		if len(args) != 3 {
			return usage
		}
		var status api.ManagedResourceStatus
		if err := call("RefreshManagedResource", api.RefreshManagedResourceRequest{Kind: args[1], ID: args[2], Wait: true}, &status); err != nil {
			return err
		}
		if !*jsonFlag {
			printResourceStatus(status)
		}
		if status.ErrorCode != "" {
			return fmt.Errorf("resource refresh: %s", status.ErrorCode)
		}
		return nil
	case "add":
		if len(args) < 4 {
			return usage
		}
		req := api.InstallManagedResourceRequest{Kind: args[1], ID: args[2], URL: args[3]}
		fs := flag.NewFlagSet("resource add", flag.ContinueOnError)
		fs.StringVar(&req.Format, "format", "", "text, yaml, mrs, dat or mmdb")
		fs.StringVar(&req.Behavior, "behavior", "", "domain, ipcidr or classical (rule-set only)")
		fs.IntVar(&req.Interval, "interval", model.DefaultResourceInterval, "time between checks in seconds")
		manual := fs.Bool("manual", false, "only update when requested")
		if err := fs.Parse(args[4:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usage
		}
		base, err := activeRevision()
		if err != nil {
			return err
		}
		req.BaseRevision, req.Automatic = base, !*manual
		var result api.Result
		if err := call("InstallManagedResource", req, &result); err != nil {
			return err
		}
		return printResult(result)
	default:
		return usage
	}
}

func printResourceStatus(status api.ManagedResourceStatus) {
	fmt.Printf("%s/%s\t%s\trevision %d\t%s", status.Kind, status.ID, status.State, status.Revision, status.Hash)
	if status.ErrorCode != "" {
		fmt.Printf("\t%s", status.ErrorCode)
	}
	fmt.Println()
}
