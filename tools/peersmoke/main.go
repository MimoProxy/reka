//go:build !windows

// peersmoke runs the real control server and client under distinct Unix UIDs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/secret"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	client := flag.String("client", "", "probe an existing test server")
	denied := flag.Bool("expect-denied", false, "require a non-timeout refusal")
	owner := flag.Int("owner", -1, "authorized positive-client UID")
	negative := flag.Int("negative", 65534, "untrusted test-client UID")
	output := flag.String("output", "", "JSON receipt")
	flag.Parse()
	if *client != "" {
		c, err := api.Connect(*client, "peer-acceptance")
		if c != nil {
			defer c.Close()
		}
		if *denied {
			if err == nil {
				return fmt.Errorf("unauthorized UID connected")
			}
			if n, ok := err.(net.Error); ok && n.Timeout() {
				return fmt.Errorf("timeout does not prove refusal")
			}
			return nil
		}
		return err
	}
	if os.Geteuid() != 0 || *owner <= 0 || *negative <= 0 || *owner == *negative || *negative == 0 || *output == "" {
		return fmt.Errorf("requires root, distinct non-root -owner/-negative UIDs and -output")
	}
	root, err := os.MkdirTemp("/tmp", "reka-peer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0755); err != nil {
		return err
	}
	if err = control.ConfigureOwner(strconv.Itoa(*owner)); err != nil {
		return err
	}
	state := filepath.Join(root, "state")
	store, err := secret.NewFileStore(filepath.Join(state, "secrets.json"), nil)
	if err != nil {
		return err
	}
	address := "unix://" + filepath.Join(root, "control.sock")
	k, err := daemon.Start(daemon.Options{StateRoot: state, Secrets: store, ControlAddress: address, InitialProfile: []byte("schema-version: 1\nlog: {level: error}\nrules: [{id: final, match: {all: true}, outbound: direct}]\n")})
	if err != nil {
		return err
	}
	defer k.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	probe := func(uid int, wantDenied bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		args := []string{"-client", address}
		if wantDenied {
			args = append(args, "-expect-denied")
		}
		command := exec.CommandContext(ctx, executable, args...)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
		result, e := command.CombinedOutput()
		if e != nil {
			return fmt.Errorf("UID %d probe: %w %s", uid, e, result)
		}
		return nil
	}
	if err = probe(*owner, false); err != nil {
		return err
	}
	if err = probe(*negative, true); err != nil {
		return err
	}
	// Widen only this disposable test socket to exercise the peer credential
	// gate independently of filesystem permissions. The state remains private.
	if err = os.Chmod(filepath.Join(root, "control.sock"), 0666); err != nil {
		return err
	}
	defer os.Chmod(filepath.Join(root, "control.sock"), 0600)
	if err = probe(*negative, true); err != nil {
		return err
	}
	if err = probe(*owner, false); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(map[string]any{"passed": true, "owner_uid": *owner, "denied_uid": *negative, "filesystem_gate": true, "peer_credential_gate": true, "owner_still_connected": true}, "", "  ")
	return os.WriteFile(*output, append(data, '\n'), 0600)
}
