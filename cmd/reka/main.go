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
	"syscall"

	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/platform"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "reka:", err)
		os.Exit(1)
	}
}

func run() error {
	defRoot, _ := platform.DefaultStateRoot()
	var (
		stateRoot = flag.String("state-root", defRoot, "directory holding configuration revisions and state")
		ctl       = flag.String("control", "", "control API address (unix:///path or pipe://name); default from local settings or the state root")
		editDir   = flag.String("edit-dir", "", `directory for candidate files edited by hand; default <state-root>/edit, "-" to disable`)
		profile   = flag.String("profile", "", "profile to import as revision 1 when the state root is empty")
		local     = flag.String("local", "", "local settings to import as revision 1 when the state root is empty")
		logLevel  = flag.String("log-level", "", "log level until the configuration sets one (debug, info, warn, error)")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("reka", version)
		return nil
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

	opts := daemon.Options{StateRoot: *stateRoot, Logger: logger, LogLevel: level, ControlAddress: *ctl}
	switch *editDir {
	case "":
		opts.EditDir = filepath.Join(*stateRoot, "edit")
	case "-":
	default:
		opts.EditDir = *editDir
	}
	if *profile != "" || *local != "" {
		st, err := store.Open(*stateRoot)
		if err != nil {
			return err
		}
		if a, err := st.ReadActive(); err != nil {
			return err
		} else if a != nil {
			logger.Warn("state root already has a configuration; -profile and -local are ignored", "revision", a.Revision)
		} else {
			if opts.InitialProfile, err = readOptional(*profile); err != nil {
				return err
			}
			if opts.InitialLocal, err = readOptional(*local); err != nil {
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
	if e := k.Service.StartError(); e != "" {
		logger.Error("the active configuration is not running", "err", e)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	logger.Info("stopping", "signal", s.String())
	k.Close()
	return nil
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}
