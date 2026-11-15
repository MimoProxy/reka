//go:build !windows

package control

import (
	"fmt"
	"os"
	"strconv"
)

var ownerUID = -1

func ConfigureOwner(owner string) error {
	if owner == "" {
		return nil
	}
	n, err := strconv.Atoi(owner)
	if err != nil || n < 0 {
		return fmt.Errorf("owner must be a numeric UID")
	}
	if os.Geteuid() != 0 && n != os.Geteuid() {
		return fmt.Errorf("only root can grant another UID access")
	}
	ownerUID = n
	return nil
}
func allowUID(uid int) bool {
	return uid == os.Geteuid() || uid == 0 || ownerUID >= 0 && uid == ownerUID
}

func ownSocket(path string) error {
	if ownerUID < 0 {
		return nil
	}
	return os.Chown(path, ownerUID, -1)
}
