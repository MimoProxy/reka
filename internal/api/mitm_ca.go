package api

import (
	"encoding/json"
	"time"
)

type GenerateMITMCARequest struct {
	Replace bool `json:"replace,omitempty"`
}

type ImportMITMCARequest struct {
	PKCS12   string `json:"pkcs12"`
	Password string `json:"password"`
	Replace  bool   `json:"replace,omitempty"`
}

type ExportMITMCARequest struct {
	Format string `json:"format,omitempty"`
}

type MITMCAStatus struct {
	Installed         bool      `json:"installed"`
	Ref               string    `json:"ref"`
	Subject           string    `json:"subject"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	SerialNumber      string    `json:"serial_number"`
	KeyType           string    `json:"key_type"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	Expired           bool      `json:"expired"`
}

func (s MITMCAStatus) MarshalJSON() ([]byte, error) {
	if !s.Installed {
		return []byte(`{"installed":false}`), nil
	}
	type installedStatus MITMCAStatus
	return json.Marshal(installedStatus(s))
}

type ExportMITMCAResult struct {
	Format            string `json:"format"`
	Data              string `json:"data"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type DeleteMITMCAResult struct {
	Deleted bool `json:"deleted"`
}
