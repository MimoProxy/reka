package model

import (
	"path/filepath"
	"strings"
)

const (
	// Bundled scripts can reach about 842 KiB. Allow more than twice that
	// size. sing-box and mihomo have no equivalent script source limit.
	MaxScriptSize        = 2 << 20
	MaxModuleScripts     = 128
	DefaultScriptTimeout = 5
	MaxScriptTimeout     = 3600
)

// Script declares a pinned script and its optional refresh source.
type Script struct {
	ID             string            `yaml:"id"`
	Name           *string           `yaml:"name"`
	Type           string            `yaml:"type"`
	Pattern        *string           `yaml:"pattern"`
	RequiresBody   *bool             `yaml:"requires-body"`
	BinaryBodyMode *bool             `yaml:"binary-body-mode"`
	MaxSize        *int64            `yaml:"max-size"`
	Timeout        *int              `yaml:"timeout"`
	Argument       *string           `yaml:"argument"`
	ArgumentType   *string           `yaml:"argument-type,omitempty"`
	Engine         *string           `yaml:"engine"`
	Format         *string           `yaml:"format"`
	Hash           *string           `yaml:"hash"`
	Download       *ResourceDownload `yaml:"download"`
	File           *string           `yaml:"file"`

	// Omit absent settings from JSON so existing module script IDs stay stable.
	CronExp    *string `yaml:"cronexp" json:",omitempty"`
	EventName  *string `yaml:"event-name" json:",omitempty"`
	WakeSystem *bool   `yaml:"wake-system" json:",omitempty"`
}

func ValidScriptFile(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsRune(path, 0)
}
