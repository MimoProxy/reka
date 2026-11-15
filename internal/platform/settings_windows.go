//go:build windows

package platform

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"strings"
)

// OwnerSID is set before startup by the service launcher. Empty uses HKCU.
var OwnerSID string

type NativeSettings struct{}
type regValue struct {
	Present bool
	Number  uint64
	Text    string
	Kind    uint32
}

func internetKey(access uint32) (registry.Key, error) {
	if OwnerSID != "" {
		return registry.OpenKey(registry.USERS, OwnerSID+`\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, access)
	}
	return registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, access)
}
func (NativeSettings) Read(key string) (string, error) {
	k, e := internetKey(registry.QUERY_VALUE)
	if e != nil {
		return "", e
	}
	defer k.Close()
	v := regValue{}
	switch key {
	case "ProxyEnable", "AutoDetect":
		v.Number, v.Kind, e = k.GetIntegerValue(key)
	case "ProxyServer", "ProxyOverride", "AutoConfigURL":
		v.Text, v.Kind, e = k.GetStringValue(key)
	default:
		return "", fmt.Errorf("unsupported setting")
	}
	if e == registry.ErrNotExist {
		e = nil
	} else if e == nil {
		v.Present = true
	}
	b, _ := json.Marshal(v)
	return string(b), e
}
func (NativeSettings) Write(key, value string) error {
	var v regValue
	if e := json.Unmarshal([]byte(value), &v); e != nil {
		return e
	}
	k, e := internetKey(registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	if !v.Present {
		e = k.DeleteValue(key)
		if e == registry.ErrNotExist {
			e = nil
		}
	} else if v.Kind == registry.DWORD {
		e = k.SetDWordValue(key, uint32(v.Number))
	} else {
		e = k.SetStringValue(key, v.Text)
	}
	if e != nil {
		return e
	}
	dll := windows.NewLazySystemDLL("wininet.dll")
	p := dll.NewProc("InternetSetOptionW")
	p.Call(0, 39, 0, 0)
	p.Call(0, 37, 0, 0)
	return nil
}
func SystemSettings(c Network, proxy string) (map[string]string, error) {
	if c.Mode != "system-proxy" {
		return nil, nil
	}
	key, err := internetKey(registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	conn, err := registry.OpenKey(key, "Connections", registry.QUERY_VALUE)
	key.Close()
	if err == nil {
		raw, _, readErr := conn.GetBinaryValue("DefaultConnectionSettings")
		conn.Close()
		if readErr == nil && len(raw) > 8 && raw[8]&12 != 0 {
			return nil, fmt.Errorf("disable automatic proxy discovery/PAC before manual system proxy takeover")
		}
	}
	out := map[string]string{}
	for k, v := range map[string]regValue{"ProxyEnable": {true, 1, "", registry.DWORD}, "ProxyServer": {true, 0, "http=" + proxy + ";https=" + proxy + ";socks=" + proxy, registry.SZ}, "ProxyOverride": {true, 0, "<local>", registry.SZ}} {
		b, _ := json.Marshal(v)
		out[k] = string(b)
	}
	s, e := (NativeSettings{}).Read("AutoConfigURL")
	if e != nil {
		return nil, e
	}
	var v regValue
	json.Unmarshal([]byte(s), &v)
	if strings.TrimSpace(v.Text) != "" {
		return nil, fmt.Errorf("disable PAC before manual system proxy takeover")
	}
	return out, nil
}
