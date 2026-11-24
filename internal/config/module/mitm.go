package module

import "strings"

func (c *converter) mitm(line int, text string) outcome {
	key, value, ok := strings.Cut(text, "=")
	if !ok {
		return unsupported("module.mitm-syntax", "expected a MITM setting and value")
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	upper := strings.ToUpper(value)
	insert, appendHosts := strings.HasPrefix(upper, "%INSERT%"), strings.HasPrefix(upper, "%APPEND%")
	if insert || appendHosts {
		value = strings.TrimSpace(value[len("%INSERT%"):])
	}
	switch key {
	case "hostname":
		for field := range strings.SplitSeq(value, ",") {
			if host := strings.TrimSpace(field); host != "" {
				dest := &c.result.AppendHostnames
				if insert {
					dest = &c.result.InsertHostnames
				}
				*dest = append(*dest, Hostname{Value: host, Line: line})
				c.report.Hostnames.record(true)
			}
		}
		if !insert && !appendHosts {
			return outcome{Supported, "module.hostname-append", "modules cannot replace profile hostnames, so hostnames were appended"}
		}
		return outcome{}
	case "h2", "skip-server-cert-verify":
		if !strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
			return unsupported("module.mitm-boolean", "MITM setting requires true or false")
		}
		v := ptr(strings.EqualFold(value, "true"))
		if key == "h2" {
			c.result.MITM.H2 = v
		} else {
			c.result.MITM.SkipServerCertVerify = v
		}
		c.result.MITMLines[key] = line
		return outcome{}
	case "hostname-disabled":
		return ignored("module.hostname-disabled", "use an overlay to remove individual MITM hostnames")
	case "tcp-connection", "client-source-address":
		return ignored("module.mitm-setting", "the module cannot change this MITM setting")
	default:
		if key == "ca" || strings.HasPrefix(key, "ca-") {
			return ignored("module.mitm-ca", "modules cannot provide a CA")
		}
		return unsupported("module.mitm-setting", "unknown MITM setting")
	}
}
