package profile

import (
	"fmt"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

// Sing-box uses 50 MiB for Apple network extensions. Budget 30 MiB for
// compiled rules and leave the rest for the runtime, DNS and packet queues.
const iosRuleMemoryBudget = 30 << 20

func appendRuleMemoryDiagnostic(diagnostics model.Diagnostics, estimate compile.RuleMemoryEstimate) model.Diagnostics {
	if estimate.Bytes <= iosRuleMemoryBudget {
		return diagnostics
	}
	const mib = 1 << 20
	name, largest := estimate.Name, float64(estimate.LargestBytes)/mib
	message := fmt.Sprintf("%s needs about %.1f MiB of rule memory, exceeding the iOS rule budget of %d MiB", name, largest, iosRuleMemoryBudget/mib)
	if estimate.LargestBytes <= iosRuleMemoryBudget {
		message = fmt.Sprintf("Rules need about %.1f MiB, exceeding the iOS rule budget of %d MiB. The largest contributor is %s at about %.1f MiB", float64(estimate.Bytes)/mib, iosRuleMemoryBudget/mib, name, largest)
	}
	return append(diagnostics, model.Diagnostic{
		Severity: model.SeverityError, Code: "ios.memory", Document: model.DocProfile, Path: estimate.Path, Message: message,
	})
}

func preparationValidationError(diagnostics model.Diagnostics) *ValidationError {
	for _, d := range diagnostics {
		if d.Code == "ios.memory" {
			return &ValidationError{d.Message, diagnostics}
		}
	}
	return &ValidationError{"Invalid profile", diagnostics}
}
