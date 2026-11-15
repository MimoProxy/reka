//go:build darwin

package control

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var serr error
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if serr == nil {
			uid = int(cred.Uid)
		}
	})
	if err == nil {
		err = serr
	}
	return uid, err
}

func checkPeer(c net.Conn) error { return checkUID(c) }

func checkUID(c net.Conn) error {
	uid, err := peerUID(c)
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if !allowUID(uid) {
		return fmt.Errorf("%w (uid %d)", ErrPeerDenied, uid)
	}
	return nil
}
