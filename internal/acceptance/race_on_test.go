//go:build race

package acceptance

// raceEnabled is true under -race. sing's SOCKS5 UDP associate conn
// (common/bufio serverPacketConn) stores the client address on every read
// and loads it on every write without synchronization, so any relay that
// reads and writes it concurrently, sing-box's own included, trips the race
// detector. The UDP test is skipped under -race for that upstream reason.
const raceEnabled = true
