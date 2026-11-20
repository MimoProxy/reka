// Command reka is the Reka proxy core. It owns the configuration under a
// state root, runs the active revision and serves the control API that
// rekactl and GUIs use.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/MimoProxy/reka/internal/clashapi"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/platform"
)

var version = "dev"

func main() {
	if err := serve(run); err != nil {
		fmt.Fprintln(os.Stderr, "reka:", err)
		os.Exit(1)
	}
}

func run() error {
	defRoot, _ := platform.DefaultStateRoot()
	var (
		profileArchive = flag.String("profile-archive", "", "initialize an empty state root from a staged immutable history archive")
		profileRoot    = flag.String("profile-root", "", "enable ID-scoped atomic profiles beneath this trusted directory")
		profileID      = flag.String("profile-id", "", "initial profile ID when enabling a workspace")
		profileNested  = flag.Bool("profile-state-subdir", false, "store each profile under <id>/state")
		profileResume  = flag.Bool("profile-resume", true, "resume the durable active profile in the workspace")
		owner          = flag.String("owner", "", "control API owner: numeric UID on Unix, SID on Windows (privileged service)")
		stateRoot      = flag.String("state-root", defRoot, "directory holding configuration revisions and state")
		ctl            = flag.String("control", "", "control API address (unix:///path or pipe://name); default from local settings or the state root")
		clashListen    = flag.String("clash-listen", "", "optional Clash HTTP API (numeric loopback IP:port, requires REKA_CLASH_SECRET)")
		clashOrigins   = flag.String("clash-allow-origin", "", "comma-separated exact origins for browser dashboards")
		editDir        = flag.String("edit-dir", "", `directory for candidate files edited by hand; default <state-root>/edit, "-" to disable`)
		profile        = flag.String("profile", "", "profile to import as revision 1 when the state root is empty")
		local          = flag.String("local", "", "local settings to import as revision 1 when the state root is empty")
		sources        = flag.String("sources", "", "normalized sources to import as revision 1")
		overlay        = flag.String("overlay", "", "overlay to import as revision 1")
		logLevel       = flag.String("log-level", "", "log level until the configuration sets one (debug, info, warn, error)")
		showVer        = flag.Bool("version", false, "print the version and exit")
		deferNetwork   = flag.Bool("defer-network", false, "commit network takeover off before startup for a client handoff")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("reka", version)
		return nil
	}
	if err := control.ConfigureOwner(*owner); err != nil {
		return err
	}
	if *stateRoot == "" {
		return errors.New("no state root; pass -state-root")
	}
	level := new(slog.LevelVar)
	if *logLevel != "" {
		if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
			return fmt.Errorf("-log-level: %w", err)
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	control.Version = version

	opts := daemon.Options{InitialArchiveHash: *profileArchive, ProfileRoot: *profileRoot, ProfileID: *profileID, ProfileNested: *profileNested, ProfileResume: *profileResume, StateRoot: *stateRoot, Logger: logger, LogLevel: level, ControlAddress: *ctl, DeferNetwork: *deferNetwork}
	opts.ClashAPI = clashapi.Options{Listen: *clashListen, Token: os.Getenv("REKA_CLASH_SECRET"), Version: version}
	for origin := range strings.SplitSeq(*clashOrigins, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			opts.ClashAPI.AllowOrigins = append(opts.ClashAPI.AllowOrigins, origin)
		}
	}
	switch *editDir {
	case "":
		opts.EditDir = filepath.Join(*stateRoot, "edit")
	case "-":
	default:
		opts.EditDir = *editDir
	}
	if *profile != "" || *local != "" || *sources != "" || *overlay != "" {
		st, err := store.Open(*stateRoot)
		if err != nil {
			return err
		}
		if a, err := st.ReadActive(); err != nil {
			return err
		} else if a != nil {
			logger.Warn("state root already has a configuration; initial document flags are ignored", "revision", a.Revision)
		} else {
			if opts.InitialProfile, err = readOptional(*profile); err != nil {
				return err
			}
			if opts.InitialLocal, err = readOptional(*local); err != nil {
				return err
			}
			if opts.InitialSources, err = readOptional(*sources); err != nil {
				return err
			}
			if opts.InitialOverlay, err = readOptional(*overlay); err != nil {
				return err
			}
		}
	}
	k, err := daemon.Start(opts)
	if err != nil {
		return err
	}
	logger.Info("reka started", "version", version, "state_root", *stateRoot, "control", k.ControlAddress,
		"revision", k.Service.ActiveRevision(), "edit_dir", opts.EditDir)
	if k.ClashAddress != "" {
		logger.Info("Clash API listening", "address", k.ClashAddress)
	}
	if e := k.Service.StartError(); e != "" {
		logger.Error("the active configuration is not running", "err", e)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	ready()
	select {
	case s := <-sig:
		logger.Info("stopping", "signal", s.String())
	case <-serviceStop:
		logger.Info("stopping service")
	}
	k.Close()
	return nil
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}
