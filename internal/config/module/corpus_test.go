package module

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestModuleCorpus(t *testing.T) {
	dir := os.Getenv("REKA_MODULE_CORPUS")
	if dir == "" {
		t.Skip("REKA_MODULE_CORPUS is unset")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("REKA_MODULE_CORPUS must be a directory")
	}

	type diagnosticKey struct{ section, code string }
	type stats struct {
		complete, partial, failed int
		diagnostics               map[diagnosticKey]int
	}
	formats := []string{model.ModuleFormatSurge, model.ModuleFormatLoon, model.ModuleFormatStash}
	byFormat := make(map[string]*stats, len(formats))
	for _, format := range formats {
		byFormat[format] = &stats{diagnostics: make(map[diagnosticKey]int)}
	}
	seen := make(map[string]bool)
	hash := resource.Hash([]byte("corpus resource"))
	if err := filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".sgmodule", ".plugin", ".lpx", ".stoverride":
		default:
			return nil
		}
		text, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		identity := resource.Hash(text)
		if seen[identity] {
			return nil
		}
		seen[identity] = true
		format := DetectFormat(name, text)
		_, report := Convert(text, Options{
			Format:          format,
			Resolve:         func(policy string) (string, bool) { return policy, true },
			ResourceForKind: func(_, _ string) (string, bool) { return hash, true },
		})
		s := byFormat[format]
		switch {
		case !report.CanApply:
			s.failed++
		case report.Partial:
			s.partial++
		default:
			s.complete++
		}
		for _, line := range report.Lines {
			if line.Code != "" {
				s.diagnostics[diagnosticKey{line.Section, line.Code}]++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, format := range formats {
		s := byFormat[format]
		total := s.complete + s.partial + s.failed
		percentage := func(n int) string {
			if total == 0 {
				return "0.0%"
			}
			return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total))
		}
		t.Logf("%s: %d total, %d complete (%s), %d partial (%s), %d failed (%s)",
			format, total, s.complete, percentage(s.complete), s.partial, percentage(s.partial), s.failed, percentage(s.failed))
		var keys []diagnosticKey
		for key, count := range s.diagnostics {
			if count > 20 {
				keys = append(keys, key)
			}
		}
		slices.SortFunc(keys, func(a, b diagnosticKey) int {
			if bySection := strings.Compare(a.section, b.section); bySection != 0 {
				return bySection
			}
			return strings.Compare(a.code, b.code)
		})
		for _, key := range keys {
			t.Logf("  (%s, %s): %d", key.section, key.code, s.diagnostics[key])
		}
	}
}
