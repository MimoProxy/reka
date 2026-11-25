package model

// LocalMITM controls whether this machine can decrypt HTTPS traffic.
type LocalMITM struct {
	Enabled   bool   `yaml:"enabled"`
	CA        string `yaml:"ca"`
	ScriptLog bool   `yaml:"script-log"`
}

// MITM contains the traffic selection settings shared by profiles and sources.
type MITM struct {
	Hostnames            []string `yaml:"hostnames"`
	ClientSourceAddress  []string `yaml:"client-source-address"`
	H2                   *bool    `yaml:"h2"`
	SkipServerCertVerify *bool    `yaml:"skip-server-cert-verify"`
	QUICBlock            *bool    `yaml:"quic-block"`
}

type HTTPRewrite struct {
	ID       string  `yaml:"id"`
	Match    string  `yaml:"match"`
	Action   string  `yaml:"action"`
	Target   *string `yaml:"target"`
	Response *string `yaml:"response"`
}

type HeaderRewrite struct {
	ID      string  `yaml:"id"`
	Phase   *string `yaml:"phase"`
	Match   string  `yaml:"match"`
	Op      string  `yaml:"op"`
	Name    string  `yaml:"name"`
	Pattern *string `yaml:"pattern"`
	Value   *string `yaml:"value"`
}

type BodyRewrite struct {
	ID      string            `yaml:"id"`
	Phase   string            `yaml:"phase"`
	Match   string            `yaml:"match"`
	Replace []BodyReplacement `yaml:"replace,omitempty"`
	JQ      *string           `yaml:"jq,omitempty"`
}

type BodyReplacement struct {
	Pattern *string `yaml:"pattern"`
	Value   *string `yaml:"value"`
}

type MapLocal struct {
	ID         string            `yaml:"id"`
	Match      string            `yaml:"match"`
	DataType   *string           `yaml:"data-type"`
	Data       *string           `yaml:"data"`
	Hash       *string           `yaml:"hash"`
	Download   *ResourceDownload `yaml:"download"`
	StatusCode *int              `yaml:"status-code"`
	Headers    []MapLocalHeader  `yaml:"headers"`
}

type MapLocalHeader struct {
	Name  string  `yaml:"name"`
	Value *string `yaml:"value"`
}
