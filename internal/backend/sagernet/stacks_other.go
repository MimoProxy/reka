//go:build !with_gvisor

package sagernet

func TUNStacks() []string { return []string{"mixed", "system"} }
