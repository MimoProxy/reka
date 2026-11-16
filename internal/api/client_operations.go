package api

import "time"

type Traffic struct {
	UploadTotal   uint64    `json:"upload_total"`
	DownloadTotal uint64    `json:"download_total"`
	SampledAt     time.Time `json:"sampled_at"`
	Epoch         string    `json:"epoch,omitempty"`
}

type ProbeRequest struct {
	Outbound  string `json:"outbound"`
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

type ProbeResult struct {
	Outbound         string `json:"outbound"`
	ResolvedOutbound string `json:"resolved_outbound"`
	DelayMS          int64  `json:"delay_ms"`
	StatusCode       int    `json:"status_code"`
}

type DNSQueryRequest struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Scope string `json:"scope"`
	Fake  bool   `json:"fake"`
}

type DNSQueryResult struct {
	RCode     int      `json:"rcode"`
	Answer    []string `json:"answer"`
	Authority []string `json:"authority"`
	Extra     []string `json:"extra"`
}

type RuleView struct {
	Index       int    `json:"index"`
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"`
	Payload     string `json:"payload"`
	Outbound    string `json:"outbound"`
	Description string `json:"description"`
}

type RulesPage struct {
	Generation uint64     `json:"generation"`
	Revision   uint64     `json:"revision"`
	Mode       string     `json:"mode"`
	Total      int        `json:"total"`
	Rules      []RuleView `json:"rules"`
}
