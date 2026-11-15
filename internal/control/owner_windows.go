//go:build windows

package control

import (
	"github.com/MimoProxy/reka/internal/platform"
	"golang.org/x/sys/windows"
)

var ownerSID *windows.SID

func ConfigureOwner(owner string) error {
	if owner == "" {
		return nil
	}
	s, e := windows.StringToSid(owner)
	if e != nil {
		return e
	}
	ownerSID = s
	platform.OwnerSID = owner
	return nil
}

func ownSocket(string) error { return nil }
