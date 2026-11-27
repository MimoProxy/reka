package moduleacquire

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/subscription"
)

// ValidateRuleSetBody checks a RULE-SET or DOMAIN-SET list before storage,
// so a list the compiler cannot use fails the refresh instead of the profile.
func ValidateRuleSetBody(kind string, data []byte) error {
	switch {
	case len(data) > model.MaxModuleRuleSetSize:
		return &subscription.Error{Code: "body_too_large"}
	case len(data) == 0:
		return &subscription.Error{Code: "empty_body"}
	}
	if _, err := rulesdata.Decode(module.RuleSetBehavior(kind), "surge", "", data); err != nil {
		return &subscription.Error{Code: "resource_invalid"}
	}
	return nil
}
