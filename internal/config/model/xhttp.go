package model

// XHTTPOptions contains bounded client-side XHTTP options. Endpoint fields are
// only used by DownloadSettings; the main endpoint uses its outbound settings.
type XHTTPOptions struct {
	DisableTLS           bool                 `yaml:"disable-tls" json:"disable-tls,omitempty"`
	Mode                 string               `yaml:"mode" json:"mode,omitempty"`
	NoGRPCHeader         bool                 `yaml:"no-grpc-header" json:"no-grpc-header,omitempty"`
	XPaddingBytes        string               `yaml:"x-padding-bytes" json:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool                 `yaml:"x-padding-obfs-mode" json:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string               `yaml:"x-padding-key" json:"x-padding-key,omitempty"`
	XPaddingHeader       string               `yaml:"x-padding-header" json:"x-padding-header,omitempty"`
	XPaddingPlacement    string               `yaml:"x-padding-placement" json:"x-padding-placement,omitempty"`
	XPaddingMethod       string               `yaml:"x-padding-method" json:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string               `yaml:"uplink-http-method" json:"uplink-http-method,omitempty"`
	SessionPlacement     string               `yaml:"session-placement" json:"session-placement,omitempty"`
	SessionKey           string               `yaml:"session-key" json:"session-key,omitempty"`
	SessionTable         string               `yaml:"session-table" json:"session-table,omitempty"`
	SessionLength        string               `yaml:"session-length" json:"session-length,omitempty"`
	SeqPlacement         string               `yaml:"seq-placement" json:"seq-placement,omitempty"`
	SeqKey               string               `yaml:"seq-key" json:"seq-key,omitempty"`
	UplinkDataPlacement  string               `yaml:"uplink-data-placement" json:"uplink-data-placement,omitempty"`
	UplinkDataKey        string               `yaml:"uplink-data-key" json:"uplink-data-key,omitempty"`
	UplinkChunkSize      string               `yaml:"uplink-chunk-size" json:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   string               `yaml:"sc-max-each-post-bytes" json:"sc-max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMS string               `yaml:"sc-min-posts-interval-ms" json:"sc-min-posts-interval-ms,omitempty"`
	XMUX                 *XHTTPReuse          `yaml:"xmux" json:"xmux,omitempty"`
	DownloadSettings     *XHTTPOptions        `yaml:"download-settings" json:"download-settings,omitempty"`
	Server               string               `yaml:"server" json:"server,omitempty"`
	Port                 int                  `yaml:"port" json:"port,omitempty"`
	TLS                  *TLS                 `yaml:"tls" json:"tls,omitempty"`
	Host                 string               `yaml:"host" json:"host,omitempty"`
	Path                 string               `yaml:"path" json:"path,omitempty"`
	Headers              []SubscriptionHeader `yaml:"headers" json:"headers,omitempty"`
}

type XHTTPReuse struct {
	HKeepAlivePeriod string `yaml:"h-keep-alive-period" json:"h-keep-alive-period,omitempty"`
	MaxConcurrency   string `yaml:"max-concurrency" json:"max-concurrency,omitempty"`
	MaxConnections   string `yaml:"max-connections" json:"max-connections,omitempty"`
	CMaxReuseTimes   string `yaml:"c-max-reuse-times" json:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string `yaml:"h-max-request-times" json:"h-max-request-times,omitempty"`
	HMaxReusableSecs string `yaml:"h-max-reusable-secs" json:"h-max-reusable-secs,omitempty"`
}
