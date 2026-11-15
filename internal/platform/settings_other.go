//go:build !darwin && !windows

package platform

import "fmt"

type NativeSettings struct{}

func (NativeSettings) Read(string) (string, error) { return "", fmt.Errorf("OS settings unavailable") }
func (NativeSettings) Write(string, string) error  { return fmt.Errorf("OS settings unavailable") }
func SystemSettings(c Network, _ string) (map[string]string, error) {
	if c.Mode == "system-proxy" {
		return nil, fmt.Errorf("system proxy unavailable")
	}
	return nil, nil
}
