package api

// ScriptPressure reports script runs that memory limits stopped since the
// previous report.
type ScriptPressure struct {
	// Runs not started because the process had too little memory headroom.
	Skipped uint64 `json:"skipped"`
	// Runs that finished over the memory budget, so their results were dropped.
	Discarded uint64 `json:"discarded"`
	// HTTP scripts not run because the body was over the size limit.
	Oversize uint64                `json:"oversize"`
	Scripts  []ScriptPressureCount `json:"scripts,omitempty"` // Most affected first.
}

type ScriptPressureCount struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Module    string `json:"module,omitempty"`
	Skipped   uint64 `json:"skipped,omitempty"`
	Discarded uint64 `json:"discarded,omitempty"`
	Oversize  uint64 `json:"oversize,omitempty"`
}
