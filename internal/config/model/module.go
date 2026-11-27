package model

import (
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
)

const (
	// Format names match the dialects used by profile and snapshot documents.
	ModuleFormatSurge = "surge"
	ModuleFormatLoon  = "loon"
	ModuleFormatStash = "stash"

	MaxModuleResources = 32
	// MaxModuleRuleSets and MaxModuleRuleSetSize bound the RULE-SET and
	// DOMAIN-SET lists one module downloads. Neither sing-box nor mihomo
	// limits rule providers; these keep a module's lists within the module
	// bundle, which the iOS app holds in memory while refreshing.
	MaxModuleRuleSets    = 32
	MaxModuleRuleSetSize = 8 << 20
	// MaxModuleLocks bounds every resource a module snapshot pins.
	MaxModuleLocks    = MaxModuleResources + MaxModuleRuleSets + MaxModuleScripts
	ModuleMinInterval = 300
	ModuleMaxInterval = 604800
)

// Module declares an external module and its profile-specific settings.
type Module struct {
	ID        string            `yaml:"id" json:"id"`
	Enabled   *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	URL       string            `yaml:"url,omitempty" json:"url,omitempty"`
	File      string            `yaml:"file,omitempty" json:"file,omitempty"`
	Format    string            `yaml:"format,omitempty" json:"format,omitempty"`
	Interval  int               `yaml:"interval,omitempty" json:"interval,omitempty"`
	Arguments map[string]string `yaml:"arguments,omitempty" json:"arguments,omitempty"`
}

// ModuleSnapshot identifies the original document pinned by the source lock.
type ModuleSnapshot struct {
	Format  string `yaml:"format" json:"format"`
	Request string `yaml:"request" json:"request"`
	Name    string `yaml:"name,omitempty" json:"name,omitempty"`
	Desc    string `yaml:"desc,omitempty" json:"desc,omitempty"`
}

func (m Module) IsEnabled() bool { return m.Enabled == nil || *m.Enabled }

// RequestHash identifies the declared location, without resolving secrets.
func (m Module) RequestHash() string {
	if m.File != "" {
		return resource.Hash([]byte("file:" + m.File))
	}
	return resource.Hash([]byte(m.URL))
}

// MatchesSnapshot reports whether the pinned module has the requested location and format.
func (m Module) MatchesSnapshot(snapshot *ModuleSnapshot) bool {
	return snapshot != nil && ValidModuleFormat(snapshot.Format) &&
		(m.Format == "" || m.Format == snapshot.Format) && snapshot.Request == m.RequestHash()
}

// ValidModuleFormat reports whether the format names a supported module dialect.
func ValidModuleFormat(format string) bool {
	switch format {
	case ModuleFormatSurge, ModuleFormatLoon, ModuleFormatStash:
		return true
	}
	return false
}

var stableID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidStableID reports whether an unscoped native resource ID is valid.
func ValidStableID(id string) bool { return stableID.MatchString(id) }

func ValidModule(m *Module) error {
	if m == nil || !ValidStableID(m.ID) {
		return errors.New("module id must be a native stable ID")
	}
	if (m.URL == "") == (m.File == "") {
		return errors.New("specify exactly one module url or file")
	}
	if m.Format != "" && !ValidModuleFormat(m.Format) {
		return errors.New("module format must be surge, loon or stash")
	}
	if m.File != "" && (!filepath.IsAbs(m.File) || strings.ContainsRune(m.File, 0)) {
		return errors.New("module file must be an absolute local path")
	}
	if m.URL != "" {
		if name, ok := secret.ParseRef(m.URL); ok {
			if secret.ValidName(name) != nil || secret.Reserved(name) {
				return errors.New("module URL must use a valid URL secret reference")
			}
		} else {
			u, err := url.Parse(m.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Fragment != "" {
				return errors.New("module URL must be HTTP(S) or a secret reference")
			}
		}
	}
	if m.Interval != 0 && (m.Interval < ModuleMinInterval || m.Interval > ModuleMaxInterval) {
		return errors.New("module interval must be 0 (default) or 300–604800 seconds")
	}
	return nil
}
