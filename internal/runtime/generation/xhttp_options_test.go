package generation

import (
	"encoding/json"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

func TestXHTTPBackendOptionsRetainIndependentIdentity(t *testing.T) {
	o := compile.Outbound{Type: "vless", Server: "upload.test", TLS: &compile.TLS{ServerName: "front.test"}, Transport: &model.Transport{Type: "xhttp", Path: "/split", Headers: []model.SubscriptionHeader{{Name: "X-Key", Value: "upload-key"}}, XHTTP: &model.XHTTPOptions{Mode: "stream-up", XMUX: &model.XHTTPReuse{HKeepAlivePeriod: "45"}, DownloadSettings: &model.XHTTPOptions{Server: "download.test", Port: 8443, Headers: []model.SubscriptionHeader{{Name: "X-Key", Value: "download-key"}}, TLS: &model.TLS{ServerName: "download.test", ALPN: []string{"h3"}, Certificate: "resolved-cert", PrivateKey: "resolved-key", ECH: &model.ECH{Enabled: true, Config: "ech-config"}}}}}}
	var got struct {
		Transport json.RawMessage `json:"transport"`
		XHTTP     struct {
			Host, Path, Mode string
			Headers          map[string]string
			XMUX             struct {
				Period string `json:"h-keep-alive-period"`
			} `json:"xmux"`
			Download struct {
				Server  string
				Port    uint16
				Headers map[string]string
				TLS     *sagernet.TLSSpec `json:"reka_tls"`
			} `json:"download-settings"`
		} `json:"reka_xhttp"`
	}
	if err := json.Unmarshal(protocolOptions(o), &got); err != nil {
		t.Fatal(err)
	}
	x := got.XHTTP
	if len(got.Transport) != 0 || x.Host != "front.test" || x.Path != "/split" || x.Mode != "stream-up" || x.Headers["X-Key"] != "upload-key" || x.XMUX.Period != "45" {
		t.Fatal("XHTTP backend contract was not emitted")
	}
	d := x.Download
	if d.Server != "download.test" || d.Port != 8443 || d.Headers["X-Key"] != "download-key" || d.TLS == nil || d.TLS.Certificate != "resolved-cert" || d.TLS.PrivateKey != "resolved-key" || d.TLS.ECH.Config != "ech-config" || d.TLS.ALPN[0] != "h3" {
		t.Fatal("backend download identity differs from compiled configuration")
	}
}
