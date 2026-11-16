package api

import "time"

// SubscriptionUsage is the provider's account declaration, not local traffic.
// Pointer fields distinguish an explicit zero from an unknown value.
type SubscriptionUsage struct {
	Upload        *uint64   `json:"upload,omitempty"`
	Download      *uint64   `json:"download,omitempty"`
	Total         *uint64   `json:"total,omitempty"`
	ExpireUnix    *uint64   `json:"expire_unix,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
	InvalidFields []string  `json:"invalid_fields,omitempty"`
}
