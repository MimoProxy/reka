package module

import (
	"net/url"
	"path"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

// DetectFormat checks the filename or URL path before inspecting the text.
// An empty result means the input did not identify a supported format.
func DetectFormat(name string, text []byte) string {
	if u, err := url.Parse(name); err == nil && u.Scheme != "" && (u.Host != "" || u.Scheme == "file") {
		name = u.Path
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".sgmodule":
		return model.ModuleFormatSurge
	case ".plugin", ".lpx":
		return model.ModuleFormatLoon
	case ".stoverride", ".yaml", ".yml":
		return model.ModuleFormatStash
	}
	if len(text) > model.MaxDocumentSize {
		return ""
	}
	input := strings.TrimPrefix(string(text), "\ufeff")
	for raw := range strings.Lines(input) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#!") || isSection(line) {
			return detectLineFormat(input)
		}
		if !isComment(line) {
			break
		}
	}
	if root, _ := model.ParseNode(model.DocSources, text); root != nil {
		for i := 0; i < len(root.Content); i += 2 {
			switch root.Content[i].Value {
			case "name", "http", "rules", "script-providers":
				return model.ModuleFormatStash
			}
		}
	}
	return ""
}

func detectLineFormat(input string) string {
	for raw := range strings.Lines(input) {
		line := strings.TrimSpace(raw)
		if key, _, _ := metadataLine(line); key == "loon_version" {
			return model.ModuleFormatLoon
		}
		if isComment(line) {
			continue
		}
		if isSection(line) && strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "argument") {
			return model.ModuleFormatLoon
		}
		var previous string
		for field := range strings.FieldsSeq(line) {
			field = strings.ToLower(field)
			if field == "reject-dict" || field == "reject-array" || strings.HasPrefix(field, "response-body-json-") ||
				strings.HasPrefix(field, "request-body-json-") || previous == "if" && field == "${url}" {
				return model.ModuleFormatLoon
			}
			previous = field
		}
	}
	return model.ModuleFormatSurge
}
