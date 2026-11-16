package importer

import (
	"fmt"
	"strconv"
	"strings"
)

// SIP003 escapes delimiters with a backslash. Decode only after finding
// each delimiter, so an escaped semicolon stays inside a path/host value.
func sip003Part(value string, terminators string) (int, string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if strings.IndexByte(terminators, c) >= 0 {
			return i, out.String(), nil
		}
		if c == '\\' {
			i++
			if i == len(value) {
				return 0, "", fmt.Errorf("incomplete SIP003 escape")
			}
			c = value[i]
		}
		out.WriteByte(c)
	}
	return len(value), out.String(), nil
}
func ssLinkPlugin(value string) (string, object, error) {
	name, rest, _ := strings.Cut(value, ";")
	args := map[string]string{}
	for rest != "" {
		n, key, err := sip003Part(rest, "=;")
		if err != nil || key == "" {
			return "", nil, fmt.Errorf("invalid SIP003 key")
		}
		rest = rest[n:]
		argument := "1"
		if strings.HasPrefix(rest, "=") {
			rest = rest[1:]
			n, argument, err = sip003Part(rest, ";")
			if err != nil {
				return "", nil, err
			}
			rest = rest[n:]
		}
		rest = strings.TrimPrefix(rest, ";")
		if _, exists := args[key]; exists {
			return "", nil, fmt.Errorf("duplicate SIP003 option")
		}
		args[key] = argument
	}
	result := object{}
	switch name {
	case "obfs", "obfs-local", "simple-obfs":
		for key, argument := range args {
			switch key {
			case "obfs":
				result["mode"] = argument
			case "obfs-host":
				result["host"] = argument
			default:
				return "", nil, fmt.Errorf("unknown obfs link option")
			}
		}
		return "obfs", result, nil
	case "v2ray-plugin":
		for key, argument := range args {
			switch key {
			case "mode", "host", "path":
				result[key] = argument
			case "obfs":
				if _, ok := args["mode"]; !ok {
					result["mode"] = argument
				}
			case "obfs-host":
				if _, ok := args["host"]; !ok {
					result["host"] = argument
				}
			case "tls":
				result["tls"] = true // SIP003 presence flag, including tls=0.
			case "mux":
				count, err := strconv.Atoi(argument)
				if err != nil || count < 0 {
					return "", nil, fmt.Errorf("invalid v2ray mux link count")
				}
				result[key] = count > 0
			case "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open":
				flag, err := strconv.ParseBool(argument)
				if err != nil {
					return "", nil, fmt.Errorf("invalid upgrade flag")
				}
				result[key] = flag
			default:
				return "", nil, fmt.Errorf("unknown v2ray-plugin link option")
			}
		}
		return name, result, nil
	default:
		return "", nil, fmt.Errorf("unknown SS link plugin")
	}
}
