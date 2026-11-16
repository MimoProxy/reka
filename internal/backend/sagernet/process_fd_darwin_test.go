//go:build darwin

package sagernet

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestDarwinFDSocketABIAndExactOwnerMatch(t *testing.T) {
	value := make([]byte, 792)
	value[288] = 1
	binary.BigEndian.PutUint16(value[268:270], 23456)
	binary.BigEndian.PutUint16(value[264:266], 17891)
	copy(value[324:328], []byte{127, 0, 0, 1})
	copy(value[308:312], []byte{127, 0, 0, 1})
	source, destination, ok := parseDarwinFDSocket(value)
	if !ok || source.String() != "127.0.0.1:23456" || destination.String() != "127.0.0.1:17891" {
		t.Fatal(source, destination, ok)
	}
	md := Metadata{Network: "tcp", Source: source, Local: destination}
	entry := darwinFDEntry{source: source, destination: destination, network: "tcp", owner: ProcessInfo{PID: 123, UID: 501, UIDKnown: true}}
	if _, ok := matchDarwinFDEntry([]darwinFDEntry{entry}, md); !ok {
		t.Fatal("exact TCP not found")
	}
	md.Local = netip.MustParseAddrPort("127.0.0.1:17892")
	if _, ok := matchDarwinFDEntry([]darwinFDEntry{entry}, md); ok {
		t.Fatal("matched wrong TCP peer")
	}
	md = Metadata{Network: "udp", Source: source, Local: destination}
	entry.network = "udp"
	entry.destination = netip.MustParseAddrPort("0.0.0.0:0")
	if _, ok := matchDarwinFDEntry([]darwinFDEntry{entry}, md); !ok {
		t.Fatal("unconnected UDP not found")
	}
	second := entry
	second.owner.PID++
	if _, ok := matchDarwinFDEntry([]darwinFDEntry{entry, second}, md); ok {
		t.Fatal("ambiguous UDP owner guessed")
	}
	if _, _, ok := parseDarwinFDSocket(value[:320]); ok {
		t.Fatal("truncated socket accepted")
	}
}

func TestDarwinCachedFDRevalidatesProcessBirthAndSocketLifetime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd uintptr
	_ = raw.Control(func(value uintptr) { fd = value })
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	entry := darwinFDEntry{source: client.LocalAddr().(*net.TCPAddr).AddrPort(), destination: client.RemoteAddr().(*net.TCPAddr).AddrPort(), network: "tcp", owner: ProcessInfo{PID: uint32(os.Getpid()), UID: uint32(os.Getuid()), UIDKnown: true, Path: "test"}, fd: uint32(fd), bornSec: info.Proc.P_starttime.Sec, bornUSec: int64(info.Proc.P_starttime.Usec)}
	set := func(value darwinFDEntry) {
		darwinFDSnapshot.Lock()
		darwinFDSnapshot.at = time.Now()
		darwinFDSnapshot.entries = []darwinFDEntry{value}
		darwinFDSnapshot.Unlock()
	}
	defer func() {
		darwinFDSnapshot.Lock()
		darwinFDSnapshot.at = time.Time{}
		darwinFDSnapshot.entries = nil
		darwinFDSnapshot.Unlock()
	}()
	md := Metadata{Network: "tcp", Source: entry.source, Local: entry.destination}
	set(entry)
	if _, ok := fallbackProcessInfo(context.Background(), md); !ok {
		t.Fatal("valid same-process FD not recognized")
	}
	wrongBirth := entry
	wrongBirth.bornSec++
	set(wrongBirth)
	if _, ok := fallbackProcessInfo(context.Background(), md); ok {
		t.Fatal("PID reuse accepted")
	}
	set(entry)
	client.Close()
	if _, ok := fallbackProcessInfo(context.Background(), md); ok {
		t.Fatal("closed socket retained cached owner")
	}
}
