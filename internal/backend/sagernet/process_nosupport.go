//go:build !(darwin || windows || (linux && !android))

package sagernet

const processSupported = false
