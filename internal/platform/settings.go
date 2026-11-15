package platform

import (
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
func settingKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Slice(k, func(i, j int) bool {
		if k[i] == "ProxyEnable" {
			return false
		}
		if k[j] == "ProxyEnable" {
			return true
		}
		return k[i] < k[j]
	})
	return k
}

func commandInput(name string, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}
