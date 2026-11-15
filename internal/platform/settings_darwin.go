//go:build darwin

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type NativeSettings struct{}
type proxyValue struct {
	Enabled bool
	Server  string
	Port    int
}

func (s NativeSettings) Read(key string) (string, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid setting key")
	}
	kind, service := parts[0], parts[1]
	if kind == "dns" {
		b, err := command("/usr/sbin/networksetup", "-getdnsservers", service)
		if err != nil {
			return "", fmt.Errorf("read DNS: %s: %w", b, err)
		}
		v := strings.TrimSpace(string(b))
		if strings.Contains(v, "There aren't any DNS Servers") {
			v = ""
		}
		return v, nil
	}
	b, err := command("/usr/sbin/networksetup", "-get"+kind, service)
	if err != nil {
		return "", fmt.Errorf("read %s: %s: %w", kind, b, err)
	}
	v := proxyValue{}
	for _, line := range strings.Split(string(b), "\n") {
		kv := strings.SplitN(line, ": ", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "Enabled":
			v.Enabled = kv[1] == "Yes"
		case "Server":
			v.Server = kv[1]
		case "Port":
			v.Port, _ = strconv.Atoi(kv[1])
		case "Authenticated Proxy Enabled":
			if kv[1] == "1" {
				return "", fmt.Errorf("authenticated system proxy cannot be restored without its secret")
			}
		}
	}
	raw, _ := json.Marshal(v)
	return string(raw), nil
}
func (s NativeSettings) Write(key, value string) error {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid setting key")
	}
	kind, service := parts[0], parts[1]
	run := func(args ...string) error {
		b, err := command("/usr/sbin/networksetup", args...)
		if err != nil {
			return fmt.Errorf("networksetup: %s: %w", b, err)
		}
		return nil
	}
	if kind == "dns" {
		v := strings.Fields(value)
		if len(v) == 0 {
			v = []string{"Empty"}
		}
		return run(append([]string{"-setdnsservers", service}, v...)...)
	}
	var v proxyValue
	if err := json.Unmarshal([]byte(value), &v); err != nil {
		return err
	}
	path, present, fields, err := proxyPreferencePath(service)
	if err != nil {
		return err
	}
	script, err := proxyPreferenceScript(path, present, fields, kind, v)
	if err != nil {
		return err
	}
	output, err := commandInput("/usr/sbin/scutil", script, "--prefs")
	text := strings.ToLower(string(output))
	for _, marker := range []string{"failed", "error", "no such", "not valid", "unknown command", "permission"} {
		if strings.Contains(text, marker) {
			return fmt.Errorf("SystemConfiguration proxy update failed: %s", output)
		}
	}
	return err
}
func SystemSettings(c Network, proxy string) (map[string]string, error) {
	out := map[string]string{}
	if c.Mode == "off" {
		return out, nil
	}
	service := c.Service
	if c.Mode == "tun" && len(c.TUN.Routes) > 0 {
		return out, nil
	}
	if service == "" {
		return out, fmt.Errorf("network.service must name the macOS network service (for example Wi-Fi)")
	}
	if c.Mode == "tun" {
		if len(c.TUN.Routes) == 0 {
			p, _ := netip.ParsePrefix(c.TUN.Address4)
			out["dns/"+service] = p.Addr().Next().String()
		}
		return out, nil
	}
	// A PAC/WPAD can override manual endpoints; report conflict instead of
	// silently claiming system takeover.
	for _, kind := range []string{"autoproxyurl", "proxyautodiscovery"} {
		b, err := command("/usr/sbin/networksetup", "-get"+kind, service)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(b), "Enabled: Yes") || strings.Contains(string(b), "On") {
			return nil, fmt.Errorf("disable PAC/WPAD before manual system proxy takeover")
		}
	}
	host, port, err := net.SplitHostPort(proxy)
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(port)
	b, _ := json.Marshal(proxyValue{true, host, n})
	for _, k := range []string{"webproxy", "securewebproxy", "socksfirewallproxy"} {
		out[k+"/"+service] = string(b)
	}
	return out, nil
}

// Use one preference dictionary commit per endpoint: disabled/empty prior
// endpoints can be cleared exactly, and a crash cannot split server/port/state.
func proxyPreferencePath(service string) (string, bool, map[string]json.RawMessage, error) {
	b, err := command("/usr/bin/plutil", "-extract", "NetworkServices", "json", "-o", "-", "/Library/Preferences/SystemConfiguration/preferences.plist")
	if err != nil {
		return "", false, nil, err
	}
	var services map[string]struct {
		UserDefinedName string
		Proxies         map[string]json.RawMessage
	}
	if err = json.Unmarshal(b, &services); err != nil {
		return "", false, nil, err
	}
	for id, v := range services {
		if v.UserDefinedName != service {
			continue
		}
		if len(id) != 36 {
			return "", false, nil, fmt.Errorf("invalid service identifier")
		}
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f' || c == '-') {
				return "", false, nil, fmt.Errorf("invalid service identifier")
			}
		}
		return "/NetworkServices/" + id + "/Proxies", v.Proxies != nil, v.Proxies, nil
	}
	return "", false, nil, fmt.Errorf("unknown network service %q", service)
}
func proxyPreferenceScript(path string, present bool, fields map[string]json.RawMessage, kind string, v proxyValue) (string, error) {
	prefix := map[string]string{"webproxy": "HTTP", "securewebproxy": "HTTPS", "socksfirewallproxy": "SOCKS"}[kind]
	if prefix == "" {
		return "", fmt.Errorf("unknown proxy setting")
	}
	var b strings.Builder
	if present {
		fmt.Fprintf(&b, "get %s\n", path)
	} else {
		b.WriteString("d.init\n")
	}
	enabled := 0
	if v.Enabled {
		enabled = 1
	}
	fmt.Fprintf(&b, "d.add %sEnable # %d\n", prefix, enabled)
	if v.Server != "" && v.Port > 0 {
		server, _ := json.Marshal(v.Server)
		fmt.Fprintf(&b, "d.add %sProxy %s\nd.add %sPort # %d\n", prefix, server, prefix, v.Port)
	} else {
		for _, suffix := range []string{"Proxy", "Port"} {
			key := prefix + suffix
			if _, ok := fields[key]; ok {
				fmt.Fprintf(&b, "d.remove %s\n", key)
			}
		}
	}
	fmt.Fprintf(&b, "set %s\ncommit\napply\nquit\n", path)
	return b.String(), nil
}
