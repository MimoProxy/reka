//go:build !ios || !cgo

package dns

func systemResolverServers() []string { return nil }
