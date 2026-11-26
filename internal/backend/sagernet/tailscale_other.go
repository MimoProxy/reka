//go:build !with_gvisor

package sagernet

import "errors"

func (*Backend) NewTailscaleNode(string, TailscaleOptions) (TailscaleNode, error) {
	return nil, errors.New("Tailscale requires a build with gVisor support")
}
