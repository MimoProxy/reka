//go:build !android

package sagernet

func duplicateTUNFD(fd int) (int, error) { return fd, nil }
func closeTUNFD(int)                     {}
