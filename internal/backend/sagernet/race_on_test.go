//go:build race

package sagernet

// raceEnabled is true under -race. sing-vmess's VisionConn updates its TLS
// filter state from both the read and the write goroutine without locking,
// so any full-duplex Vision relay trips the race detector. That is upstream
// behaviour, so Vision tests are skipped under -race; REALITY without Vision
// still runs.
const raceEnabled = true
