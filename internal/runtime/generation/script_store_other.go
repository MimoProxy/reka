//go:build !ios

package generation

import "github.com/MimoProxy/reka/internal/script"

const (
	// The script default matches Surge's iOS limit on one value.
	scriptStoreValueMax = script.DefaultStoreValueMax
	// Reka bounds the desktop and Android persistent memory budget.
	scriptStoreTotalMax = 16 << 20
)
