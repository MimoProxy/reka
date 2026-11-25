//go:build ios

package compile

// ScriptMaxBodySize limits body buffering to fit the Packet Tunnel memory budget.
const ScriptMaxBodySize = 512 << 10

// ScriptDefaultMaxSize follows the hard limit because Surge's iOS default of
// 1 MiB exceeds the Packet Tunnel budget.
const ScriptDefaultMaxSize = ScriptMaxBodySize

// iOS catalogs scripts without executing them. Its snapshot reader can borrow
// the application's input buffer and must not outlive compilation.
const keepScriptReader = false
