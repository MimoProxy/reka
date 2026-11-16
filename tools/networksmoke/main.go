// networksmoke tests production TUN recovery around an explicitly supplied OS
// transition hook. The hook must restore the physical network before returning.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/secret"
	D "github.com/miekg/dns"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	hook := flag.String("hook", "", "authorized transition executable")
	hookArgs := flag.String("hook-args", "[]", "JSON array of transition arguments")
	hookArgsFile := flag.String("hook-args-file", "", "JSON argument file (avoids Windows shell quoting)")
	service := flag.String("service", "", "macOS network service for DNS")
	full := flag.Bool("full", false, "explicitly authorize both default routes for this run")
	routes := flag.String("routes", "", "comma-separated partial routes (alternative to -full)")
	bind := flag.String("bind", "", "explicit physical interface, for VPN coexistence")
	output := flag.String("output", "", "JSON evidence output")
	flag.Parse()
	if (*full == (*routes != "")) || *hook == "" || *output == "" {
		return fmt.Errorf("requires exactly one of -full/-routes, plus -hook and -output")
	}
	var args []string
	argData := []byte(*hookArgs)
	if *hookArgsFile != "" {
		argData, err = os.ReadFile(*hookArgsFile)
		if err != nil {
			return err
		}
	}
	if err = json.Unmarshal(argData, &args); err != nil {
		return err
	}
	report := map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "scope": "dual default routes, excluding 10.0.0.0/8 management"}
	if !*full {
		report["scope"] = "partial routes: " + *routes
	}
	report["bind_interface"] = *bind
	checkpoint := func(stage string) {
		report["stage"] = stage
		data, _ := json.MarshalIndent(report, "", "  ")
		_ = os.WriteFile(*output, append(data, '\n'), 0600)
	}
	watchdog := time.AfterFunc(90*time.Second, func() {
		data := make([]byte, 4<<20)
		n := runtime.Stack(data, true)
		_ = os.WriteFile(*output+".goroutines.txt", data[:n], 0600)
	})
	defer watchdog.Stop()
	defer func() {
		report["passed"] = err == nil
		if err != nil {
			report["error"] = err.Error()
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		if writeErr := os.WriteFile(*output, append(data, '\n'), 0600); err == nil && writeErr != nil {
			err = writeErr
		}
	}()
	root, err := os.MkdirTemp("", "reka-transition-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	secrets, err := secret.NewFileStore(root+"/secrets.json", nil)
	if err != nil {
		return err
	}
	profile := "schema-version: 1\nlog: {level: error}\ndns:\n nameserver: [223.5.5.5]\n default-nameserver: [223.5.5.5]\n proxy-server-nameserver: [223.5.5.5]\n use-hosts: true\n hosts: [{id: fixture.reka.test, addresses: [192.0.2.7]}]\nrules: [{id: final, match: {all: true}, outbound: direct}]\n"
	local := fmt.Sprintf("network:\n mode: tun\n service: %q\n tun:\n  dns-hijack: true\n  address6: 'fdfe:dcba:9876::1/126'\n  exclude-routes: [10.0.0.0/8]\n", *service)
	if *routes != "" {
		values := strings.Split(*routes, ",")
		encoded, _ := json.Marshal(values)
		local += "  routes: " + string(encoded) + "\n"
	}
	if *bind != "" {
		local += fmt.Sprintf("  bind-interface: %q\n", *bind)
	}
	k, err := daemon.Start(daemon.Options{StateRoot: root, Secrets: secrets, InitialProfile: []byte(profile), InitialLocal: []byte(local), ControlAddress: "-"})
	if err != nil {
		return err
	}
	defer func() { checkpoint("closing"); k.Close() }()
	if message := k.Service.StartError(); message != "" {
		return fmt.Errorf("start: %s", message)
	}
	before := k.Service.Engine().Status()
	report["before"] = before
	checkpoint("initial_probe")
	if before.Network.State != "Running" {
		return fmt.Errorf("TUN not running")
	}
	if err = probe(); err != nil {
		return fmt.Errorf("initial probe: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	checkpoint("transition_hook")
	result, hookErr := exec.CommandContext(ctx, *hook, args...).CombinedOutput()
	report["hook_output"] = string(result)
	report["transition_wall_seconds"] = float64(time.Now().UnixMilli()-start.UnixMilli()) / 1000
	checkpoint("hook_finished")
	if hookErr != nil {
		return fmt.Errorf("transition: %w", hookErr)
	}
	var attempts []string
	recovery := time.Now()
	for {
		if probeErr := probe(); probeErr != nil {
			attempts = append(attempts, probeErr.Error())
			if time.Since(recovery) > 60*time.Second {
				report["recovery_errors"] = attempts
				return fmt.Errorf("network did not recover: %w", probeErr)
			}
			time.Sleep(time.Second)
			continue
		}
		break
	}
	report["recovery_seconds"] = time.Since(recovery).Seconds()
	report["recovery_errors"] = attempts
	after := k.Service.Engine().Status()
	report["after"] = after
	if after.Network.State != "Running" || after.Network.Device != before.Network.Device || after.Generation != before.Generation {
		return fmt.Errorf("TUN generation/device changed or lost Running state")
	}
	return nil
}

func probe() error {
	for _, ip := range []string{"223.5.5.5:53", "[2400:3200::1]:53"} {
		for _, network := range []string{"tcp", "udp"} {
			question := new(D.Msg)
			question.SetQuestion("fixture.reka.test.", D.TypeA)
			answer, _, err := (&D.Client{Net: network, Timeout: 3 * time.Second}).Exchange(question, ip)
			if err != nil {
				return fmt.Errorf("%s DNS %s: %w", network, ip, err)
			}
			if len(answer.Answer) != 1 {
				return fmt.Errorf("DNS fixture response %s", ip)
			}
			address, ok := answer.Answer[0].(*D.A)
			if !ok || address.A.String() != "192.0.2.7" {
				return fmt.Errorf("DNS fixture bypass %s", ip)
			}
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "dns.alidns.com"}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, ip := range []string{"223.5.5.5", "[2400:3200::1]"} {
		response, err := client.Get("https://" + ip + "/resolve?name=one.one.one.one&type=1")
		if err != nil {
			return fmt.Errorf("HTTPS %s: %w", ip, err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 {
			return fmt.Errorf("HTTPS response %s: HTTP %d, %v", ip, response.StatusCode, readErr)
		}
	}
	return nil
}
