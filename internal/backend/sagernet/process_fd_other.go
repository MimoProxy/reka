//go:build !darwin

package sagernet

import "context"

func fallbackProcessInfo(context.Context, Metadata) (ProcessInfo, bool) { return ProcessInfo{}, false }
