//go:build ios

package compile

// MITMMaxBodySize is the maximum rewritable HTTP body. The Packet Tunnel
// extension's Go memory budget is about 28 MiB, so use 512 KiB instead of
// Surge's 1 MiB iOS limit.
const MITMMaxBodySize = 512 << 10
