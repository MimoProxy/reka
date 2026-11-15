//go:build windows

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// CurrentSID is the SID of the user running this process.
func CurrentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

func pipeSuffix(stateRoot string) string {
	abs, _ := filepath.Abs(stateRoot)
	who := ""
	if sid, err := CurrentSID(); err == nil {
		who = sid.String()
	}
	h := sha256.Sum256([]byte(who + "\x00" + abs))
	return hex.EncodeToString(h[:6])
}

// PipeAddr is a named pipe address.
type PipeAddr string

func (a PipeAddr) Network() string { return "pipe" }
func (a PipeAddr) String() string  { return string(a) }

type pipeConn struct {
	*os.File
	path string
}

func (c *pipeConn) LocalAddr() net.Addr  { return PipeAddr(c.path) }
func (c *pipeConn) RemoteAddr() net.Addr { return PipeAddr(c.path) }

// NewPipeConn wraps a named pipe handle opened for overlapped I/O.
func NewPipeConn(f *os.File, path string) net.Conn { return &pipeConn{File: f, path: path} }

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
