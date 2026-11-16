//go:build darwin

package sagernet

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS can restrict the global PCB view to the calling process. The per-PID
// descriptor interface can still expose same-user sockets. This fallback only
// scans same-UID processes and matches client-side tuples, never server peers.
type darwinFDEntry struct {
	source, destination netip.AddrPort
	network             string
	owner               ProcessInfo
	fd                  uint32
	bornSec, bornUSec   int64
}

var darwinFDSnapshot struct {
	sync.Mutex
	at          time.Time
	entries     []darwinFDEntry
	seen        map[uint32][2]int64
	lastPartial time.Time
}
var darwinFDSlots = make(chan struct{}, 64)

func fallbackProcessInfo(ctx context.Context, md Metadata) (ProcessInfo, bool) {
	if !md.Source.IsValid() || !md.Local.IsValid() {
		return ProcessInfo{}, false
	}
	select {
	case darwinFDSlots <- struct{}{}:
		defer func() { <-darwinFDSlots }()
	default:
		return ProcessInfo{}, false
	}
	snapshot := &darwinFDSnapshot
	snapshot.Lock()
	defer snapshot.Unlock()
	if time.Since(snapshot.at) > 200*time.Millisecond {
		processes := listDarwinProcesses()
		snapshot.entries = scanDarwinFDs(ctx, processes, 100*time.Millisecond)
		snapshot.seen = darwinPIDBirths(processes)
		snapshot.at = time.Now()
		snapshot.lastPartial = time.Time{}
	}
	entry, ok := matchDarwinFDEntry(snapshot.entries, md)
	if !ok && (snapshot.lastPartial.IsZero() || time.Since(snapshot.lastPartial) >= 10*time.Millisecond) && ctx.Err() == nil {
		// New connections change client ports inside the full snapshot TTL.
		// Recheck hot applications and new PIDs, avoiding a full FD walk for
		// each flow. Concurrent misses coalesce behind the shared snapshot.
		hot := make(map[uint32]bool)
		for _, cached := range snapshot.entries {
			hot[cached.owner.PID] = true
		}
		processes := listDarwinProcesses()
		selected := make([]unix.KinfoProc, 0, 16)
		for _, process := range processes {
			pid := uint32(process.Proc.P_pid)
			birth := [2]int64{process.Proc.P_starttime.Sec, int64(process.Proc.P_starttime.Usec)}
			if previous, found := snapshot.seen[pid]; hot[pid] || !found || previous != birth {
				hot[pid] = true
				selected = append(selected, process)
			}
		}
		fresh := scanDarwinFDs(ctx, selected, 25*time.Millisecond)
		retained := snapshot.entries[:0]
		for _, cached := range snapshot.entries {
			if !hot[cached.owner.PID] {
				retained = append(retained, cached)
			}
		}
		snapshot.entries = append(retained, fresh...)
		snapshot.seen = darwinPIDBirths(processes)
		snapshot.lastPartial = time.Now()
		entry, ok = matchDarwinFDEntry(snapshot.entries, md)
	}
	if !ok || ctx.Err() != nil {
		return ProcessInfo{}, false
	}
	current, err := unix.SysctlKinfoProc("kern.proc.pid", int(entry.owner.PID))
	if err != nil || current == nil || current.Proc.P_starttime.Sec != entry.bornSec || int64(current.Proc.P_starttime.Usec) != entry.bornUSec || current.Eproc.Ucred.Uid != entry.owner.UID {
		return ProcessInfo{}, false
	}
	// Revalidate the exact descriptor, not only PID lifetime: an application
	// can close a socket while keeping the same PID and UID alive.
	socket := make([]byte, 4096)
	size := darwinProcInfo(3, uintptr(entry.owner.PID), 3, uintptr(entry.fd), socket)
	if size < 328 {
		return ProcessInfo{}, false
	}
	protocol := binary.NativeEndian.Uint32(socket[180:184])
	if (entry.network == "tcp" && protocol != unix.IPPROTO_TCP) || (entry.network == "udp" && protocol != unix.IPPROTO_UDP) {
		return ProcessInfo{}, false
	}
	source, destination, valid := parseDarwinFDSocket(socket[:size])
	if !valid || source != entry.source || destination != entry.destination {
		return ProcessInfo{}, false
	}
	return entry.owner, true
}

func matchDarwinFDEntry(entries []darwinFDEntry, md Metadata) (darwinFDEntry, bool) {
	source := netip.AddrPortFrom(md.Source.Addr().Unmap(), md.Source.Port())
	destination := netip.AddrPortFrom(md.Local.Addr().Unmap(), md.Local.Port())
	var result darwinFDEntry
	matches := 0
	for _, entry := range entries {
		if entry.network != md.Network || entry.source.Port() != source.Port() {
			continue
		}
		exact := entry.source == source && entry.destination == destination
		udpUnconnected := md.Network == "udp" && (entry.source.Addr() == source.Addr() || entry.source.Addr().IsUnspecified()) && entry.destination.Port() == 0
		if !exact && !udpUnconnected {
			continue
		}
		if matches > 0 && (result.owner.PID != entry.owner.PID || result.owner.UID != entry.owner.UID || result.bornSec != entry.bornSec || result.bornUSec != entry.bornUSec) {
			return darwinFDEntry{}, false
		}
		result = entry
		matches++
	}
	return result, matches > 0
}

func darwinProcInfo(call, pid, flavor, arg uintptr, buffer []byte) int {
	var pointer uintptr
	if len(buffer) > 0 {
		pointer = uintptr(unsafe.Pointer(&buffer[0]))
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, call, pid, flavor, arg, pointer, uintptr(len(buffer)))
	runtime.KeepAlive(buffer)
	if errno != 0 || n > uintptr(len(buffer)) {
		return 0
	}
	return int(n)
}

func listDarwinProcesses() []unix.KinfoProc {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Getuid())
	if err != nil {
		return nil
	}
	return processes[:min(len(processes), 2048)]
}
func darwinPIDBirths(processes []unix.KinfoProc) map[uint32][2]int64 {
	result := make(map[uint32][2]int64, len(processes))
	for _, p := range processes {
		result[uint32(p.Proc.P_pid)] = [2]int64{p.Proc.P_starttime.Sec, int64(p.Proc.P_starttime.Usec)}
	}
	return result
}
func scanDarwinFDs(ctx context.Context, processes []unix.KinfoProc, budget time.Duration) []darwinFDEntry {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	entries := make([]darwinFDEntry, 0, 128)
	descriptors := make([]byte, 64*1024)
	socket := make([]byte, 4096)
	path := make([]byte, 4096)
	queries := 0
	for index, process := range processes {
		if index >= 2048 || queries >= 16384 || len(entries) >= 8192 || ctx.Err() != nil {
			break
		}
		pid := uintptr(process.Proc.P_pid)
		if pid == 0 {
			continue
		}
		n := darwinProcInfo(2, pid, 1, 0, descriptors)
		if n == 0 || n%8 != 0 {
			continue
		}
		var owner *ProcessInfo
		for offset := 0; offset < n; offset += 8 {
			if queries >= 16384 || len(entries) >= 8192 || ctx.Err() != nil {
				break
			}
			if binary.NativeEndian.Uint32(descriptors[offset+4:offset+8]) != 2 {
				continue
			}
			fd := binary.NativeEndian.Uint32(descriptors[offset : offset+4])
			queries++
			clear(socket)
			size := darwinProcInfo(3, pid, 3, uintptr(fd), socket)
			if size < 328 {
				continue
			}
			family := binary.NativeEndian.Uint32(socket[184:188])
			protocol := binary.NativeEndian.Uint32(socket[180:184])
			if (family != unix.AF_INET && family != unix.AF_INET6) || (protocol != unix.IPPROTO_TCP && protocol != unix.IPPROTO_UDP) {
				continue
			}
			source, destination, ok := parseDarwinFDSocket(socket[:size])
			if !ok {
				continue
			}
			if owner == nil {
				clear(path)
				_ = darwinProcInfo(2, pid, 11, 0, path)
				processPath := unix.ByteSliceToString(path)
				if processPath == "" {
					break
				}
				owner = &ProcessInfo{PID: uint32(pid), UID: uint32(os.Getuid()), UIDKnown: true, Path: processPath}
			}
			network := "tcp"
			if protocol == unix.IPPROTO_UDP {
				network = "udp"
			}
			entries = append(entries, darwinFDEntry{source: source, destination: destination, network: network, owner: *owner, bornSec: process.Proc.P_starttime.Sec, bornUSec: int64(process.Proc.P_starttime.Usec), fd: fd})
		}
	}
	return entries
}

// These offsets are the stable proc_info.h ABI; accept only full fields and
// recognized families/protocols. Addresses and ports remain network byte order.
func parseDarwinFDSocket(value []byte) (netip.AddrPort, netip.AddrPort, bool) {
	if len(value) < 328 {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	localPort := binary.BigEndian.Uint16(value[268:270])
	foreignPort := binary.BigEndian.Uint16(value[264:266])
	var local, foreign netip.Addr
	switch {
	case value[288]&1 != 0:
		local = netip.AddrFrom4([4]byte(value[324:328]))
		foreign = netip.AddrFrom4([4]byte(value[308:312]))
	case value[288]&2 != 0:
		local = netip.AddrFrom16([16]byte(value[312:328]))
		foreign = netip.AddrFrom16([16]byte(value[296:312]))
	default:
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(local.Unmap(), localPort), netip.AddrPortFrom(foreign.Unmap(), foreignPort), true
}
