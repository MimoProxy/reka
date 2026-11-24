//go:build ios

package ca

// sing-box and mihomo have no MITM cache to use as a baseline. A cached leaf
// uses about 1–2 KB, so limit the cache for the iOS Packet Tunnel's 28 MiB Go cap.
const DefaultCacheSize = 64
