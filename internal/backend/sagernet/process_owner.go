package sagernet

import (
	"context"
	"runtime"
)

// ProcessInfo preserves the owning executable and optional OS UID. UIDKnown
// distinguishes a real root UID from unavailable ownership information.
type ProcessInfo struct {
	Path     string
	UID      uint32
	UIDKnown bool
}

func (b *Backend) FindProcessInfo(ctx context.Context, md Metadata) (ProcessInfo, bool) {
	if b.processInfoLookup != nil {
		return b.processInfoLookup(ctx, md)
	}
	if b.processLookup != nil {
		path, ok := b.processLookup(ctx, md)
		return ProcessInfo{Path: path}, ok
	}
	if b.searcher == nil || !md.Source.IsValid() || !md.Local.IsValid() {
		return ProcessInfo{}, false
	}
	info, err := b.searcher.FindProcessInfo(ctx, md.Network, md.Source, md.Local)
	if err != nil || info == nil {
		return ProcessInfo{}, false
	}
	result := ProcessInfo{Path: info.ProcessPath}
	if info.UserId >= 0 && runtime.GOOS != "windows" {
		result.UID, result.UIDKnown = uint32(info.UserId), true
	}
	return result, result.Path != "" || result.UIDKnown
}
