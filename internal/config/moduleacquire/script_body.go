package moduleacquire

import (
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/subscription"
)

// ValidateScriptBody checks the source before storage.
func ValidateScriptBody(data []byte) error {
	switch {
	case len(data) > model.MaxScriptSize:
		return &subscription.Error{Code: "body_too_large"}
	case len(data) == 0:
		return &subscription.Error{Code: "empty_body"}
	case !utf8.Valid(data):
		return &subscription.Error{Code: "resource_invalid"}
	default:
		return nil
	}
}
