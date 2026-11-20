package api

import "time"

type HTTPSDebugRequest struct {
	Targets     []string `json:"targets"`
	CaptureBody bool     `json:"capture_body,omitempty"`
	AllowHTTP   bool     `json:"allow_http,omitempty"`
	MaxClients  int      `json:"-"`
}

type HTTPSDebugStatus struct {
	Running     bool       `json:"running"`
	Address     string     `json:"address,omitempty"`
	Targets     []string   `json:"targets,omitempty"`
	Username    string     `json:"username,omitempty"`
	Password    string     `json:"password,omitempty"`
	Certificate string     `json:"certificate_pem,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CaptureBody bool       `json:"capture_body,omitempty"`
}
