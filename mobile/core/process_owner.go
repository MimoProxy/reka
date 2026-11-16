package core

import (
	"encoding/json"
	"strings"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
)

// ProcessInfoHost is an optional extension to Host. Its result is a JSON object
// with an optional executable/package "path" and optional unsigned "uid".
// Omit path for a shared UID, and omit uid when unavailable. An empty string
// requests legacy FindProcess fallback; an empty object means unknown ownership.
type ProcessInfoHost interface {
	FindProcessInfo(network, source, destination string) string
}

type legacyProcessHost interface {
	FindProcess(network, source, destination string) string
}

func processOwnerForHost(host Host, md sagernet.Metadata) (sagernet.ProcessInfo, bool) {
	// Ownership belongs to the original socket tuple. Destination may already
	// have been rewritten by Fake IP or sniffing; Local preserves the peer the
	// OS actually knows (including the proxy listener for loopback traffic).
	destination := md.Destination.String()
	if md.Local.IsValid() {
		destination = md.Local.String()
	}
	if h, ok := host.(ProcessInfoHost); ok {
		data := h.FindProcessInfo(md.Network, md.Source.String(), destination)
		if data != "" {
			var info struct {
				Path string  `json:"path"`
				UID  *uint32 `json:"uid"`
			}
			if len(data) > 16384 || json.Unmarshal([]byte(data), &info) != nil || !validOwnerPath(info.Path) {
				return sagernet.ProcessInfo{}, false
			}
			result := sagernet.ProcessInfo{Path: info.Path}
			if info.UID != nil {
				result.UID, result.UIDKnown = *info.UID, true
			}
			return result, result.Path != "" || result.UIDKnown
		}
	}
	if h, ok := host.(legacyProcessHost); ok {
		path := h.FindProcess(md.Network, md.Source.String(), destination)
		if !validOwnerPath(path) {
			return sagernet.ProcessInfo{}, false
		}
		return sagernet.ProcessInfo{Path: path}, path != ""
	}
	return sagernet.ProcessInfo{}, false
}

func validOwnerPath(path string) bool {
	return len(path) <= 8192 && !strings.ContainsAny(path, "\r\n\x00")
}
