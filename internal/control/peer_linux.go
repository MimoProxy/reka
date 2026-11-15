//go:build linux

package control

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func checkPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	uid := -1
	var serr error
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if serr == nil {
			uid = int(cred.Uid)
		}
	})
	if err == nil {
		err = serr
	}
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if uid != os.Geteuid() && uid != 0 {
		return fmt.Errorf("%w (uid %d)", ErrPeerDenied, uid)
	}
	return nil
}
