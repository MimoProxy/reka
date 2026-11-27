package router

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ProcessInfo is an owner lookup result. UIDKnown distinguishes an unavailable
// UID from an explicitly queried value; UID zero follows the reference's
// unknown-owner behavior and does not match UID rules.
type ProcessInfo struct {
	PID      uint32
	Path     string
	UID      uint32
	UIDKnown bool
}

// ProcessInfoEnv is optional. Older embedders may retain Env.Process; current
// platforms expose path and UID in one lookup shared by all owner conditions.
type ProcessInfoEnv interface {
	ProcessInfo(context.Context) (ProcessInfo, bool)
}

type uidRange struct{ lo, hi uint32 }

func isProcessKind(kind Kind) bool {
	return slices.Contains([]Kind{KindProcessName, KindProcessNameRegex, KindProcessNameWildcard, KindProcessPath, KindProcessPathRegex, KindProcessPathWildcard, KindUID}, kind)
}

func compileAdvancedRule(r *rule, value string) error {
	switch r.spec.Kind {
	case KindUID, KindInboundPort:
		bits := 32
		if r.spec.Kind == KindInboundPort {
			bits = 16
		}
		ranges, err := advancedRanges(value, bits)
		if err != nil {
			return err
		}
		if r.spec.Kind == KindUID {
			r.uidRanges = append(r.uidRanges, ranges...)
		} else {
			for _, bounds := range ranges {
				r.ports = append(r.ports, portRange{uint16(bounds.lo), uint16(bounds.hi)})
			}
		}
	default:
		for _, item := range strings.Split(value, "/") {
			item = strings.TrimSpace(item)
			if item == "" || len(item) > 8192 || strings.ContainsAny(item, "\r\n\x00") {
				return fmt.Errorf("condition needs nonempty metadata values")
			}
			if r.spec.Kind == KindInboundType {
				item = strings.ToUpper(item)
				if item == "SOCKS" {
					r.strs = append(r.strs, "SOCKS4", "SOCKS5")
					continue
				}
				if !slices.Contains([]string{"HTTP", "HTTPS", "SOCKS4", "SOCKS5", "SHADOWSOCKS", "SNELL", "VMESS", "VLESS", "REDIR", "TPROXY", "TROJAN", "TUNNEL", "TUN", "TUIC", "HYSTERIA2", "ANYTLS", "MIERU", "SUDOKU", "TRUSTTUNNEL", "SHADOWQUIC", "INNER"}, item) {
					return fmt.Errorf("unknown inbound type")
				}
			}
			r.strs = append(r.strs, item)
		}
	}
	return nil
}

func advancedRanges(value string, bits int) ([]uidRange, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" {
		return nil, fmt.Errorf("condition needs explicit unsigned ranges")
	}
	parts := strings.Split(strings.ReplaceAll(value, ",", "/"), "/")
	if len(parts) > 28 {
		return nil, fmt.Errorf("condition exceeds 28 ranges")
	}
	var out []uidRange
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid unsigned range")
		}
		parse := func(text string) (uint64, error) { return strconv.ParseUint(strings.Trim(text, "[ ]"), 10, bits) }
		lo, err := parse(bounds[0])
		if err != nil {
			return nil, fmt.Errorf("invalid unsigned range")
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = parse(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid unsigned range")
			}
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		out = append(out, uidRange{uint32(lo), uint32(hi)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("condition needs explicit unsigned ranges")
	}
	return out, nil
}

// Wildcards use the pinned reference's case-insensitive byte semantics: '*'
// matches any span (including path separators), '?' matches exactly one byte.
func matchProcessWildcard(pattern, value string) bool {
	return matchWildcard(strings.ToLower(pattern), strings.ToLower(value))
}

// matchWildcard matches '*' against any span and '?' against one byte, with
// case-sensitive comparison of all other bytes.
func matchWildcard(pattern, value string) bool {
	p, v, star, resume := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]) {
			p++
			v++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			star, resume = p, v
			p++
			continue
		}
		if star < 0 {
			return false
		}
		resume++
		v = resume
		p = star + 1
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
