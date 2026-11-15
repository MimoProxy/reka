//go:build windows

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Named pipe transport. The pipe's DACL grants access only to the current
// user and LocalSystem, remote clients are rejected by the pipe mode, and
// each accepted client's process token is checked against our user SID.
// Handles are opened for overlapped I/O, so os.NewFile attaches them to
// the runtime's I/O completion port and deadlines work.

func currentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

func pipeSuffix(stateRoot string) string {
	abs, _ := filepath.Abs(stateRoot)
	who := ""
	if sid, err := currentSID(); err == nil {
		who = sid.String()
	}
	h := sha256.Sum256([]byte(who + "\x00" + abs))
	return hex.EncodeToString(h[:6])
}

type pipeListener struct {
	path    string
	sa      *windows.SecurityAttributes
	self    *windows.SID
	closeEv windows.Handle

	mu     sync.Mutex
	next   windows.Handle
	closed bool
}

func listenPipe(path string) (net.Listener, error) {
	self, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + self.String() + ")(A;;GA;;;SY)")
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{
		path:    path,
		sa:      &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd},
		self:    self,
		closeEv: ev,
	}
	// The first instance fails if another process owns the name.
	h, err := l.create(true)
	if err != nil {
		windows.CloseHandle(ev)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("control: %s is in use by another process", path)
		}
		return nil, err
	}
	l.next = h
	return l, nil
}

func (l *pipeListener) create(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, l.sa)
}

func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		c, err := l.accept()
		if errors.Is(err, ErrPeerDenied) {
			slog.Warn("control: refused connection", "err", err)
			continue
		}
		return c, err
	}
}

func (l *pipeListener) accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.next
	l.next = 0
	l.mu.Unlock()
	if h == 0 {
		var err error
		if h, err = l.create(false); err != nil {
			return nil, err
		}
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
	case errors.Is(err, windows.ERROR_IO_PENDING):
		r, werr := windows.WaitForMultipleObjects([]windows.Handle{ev, l.closeEv}, false, windows.INFINITE)
		if werr != nil || r != windows.WAIT_OBJECT_0 {
			windows.CancelIoEx(h, &ov)
			var n uint32
			windows.GetOverlappedResult(h, &ov, &n, true)
			windows.CloseHandle(h)
			return nil, net.ErrClosed
		}
		var n uint32
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
	default:
		windows.CloseHandle(h)
		return nil, err
	}
	// Have the next instance ready while this client is served.
	if next, err := l.create(false); err == nil {
		l.mu.Lock()
		if l.closed {
			windows.CloseHandle(next)
		} else {
			l.next = next
		}
		l.mu.Unlock()
	}
	if err := l.checkClient(h); err != nil {
		windows.DisconnectNamedPipe(h)
		windows.CloseHandle(h)
		return nil, err
	}
	return &pipeConn{File: os.NewFile(uintptr(h), l.path), path: l.path}, nil
}

var systemSID, _ = windows.StringToSid("S-1-5-18")

func (l *pipeListener) checkClient(h windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return fmt.Errorf("%w: client process: %v", ErrPeerDenied, err)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("%w: open client process %d: %v", ErrPeerDenied, pid, err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return fmt.Errorf("%w: client token: %v", ErrPeerDenied, err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: client user: %v", ErrPeerDenied, err)
	}
	if !u.User.Sid.Equals(l.self) && (systemSID == nil || !u.User.Sid.Equals(systemSID)) {
		return fmt.Errorf("%w (%s)", ErrPeerDenied, u.User.Sid)
	}
	return nil
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	windows.SetEvent(l.closeEv)
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.path) }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeConn struct {
	*os.File
	path string
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.path) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.path) }

func dialPipe(path string) (net.Conn, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return &pipeConn{File: os.NewFile(uintptr(h), path), path: path}, nil
		}
		// Busy: every instance is taken; not found: between instances.
		if (errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return nil, err
	}
}

func checkPeer(net.Conn) error { return nil } // pipes check in Accept
