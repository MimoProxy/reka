//go:build !ios

package compile

const (
	// ScriptMaxBodySize follows Surge's request body hard limit.
	ScriptMaxBodySize = 32 << 20
	// ScriptDefaultMaxSize follows Surge's macOS default.
	ScriptDefaultMaxSize = 10 << 20
)
