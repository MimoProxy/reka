//go:build darwin || windows || (linux && !android)

package sagernet

// processSupported: the upstream searcher works on these platforms. On
// Android, other apps' sockets are not visible; the host will supply a UID
// lookup instead.
const processSupported = true
