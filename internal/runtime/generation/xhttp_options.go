package generation

import (
	"encoding/json"
	"net/http"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
)

func xhttpOptions(o compile.Outbound) map[string]any {
	t := o.Transport
	options := xhttpWireOptions(t.XHTTP)
	host := t.Host
	if host == "" && o.TLS != nil {
		host = o.TLS.ServerName
	}
	if host == "" {
		host = o.Server
	}
	options["host"], options["path"], options["headers"] = host, t.Path, xhttpHeaders(t.Headers)
	return options
}

func xhttpWireOptions(x *model.XHTTPOptions) map[string]any {
	values := map[string]any{}
	if x == nil {
		return values
	}
	raw, _ := json.Marshal(x)
	_ = json.Unmarshal(raw, &values)
	delete(values, "tls")
	values["headers"] = xhttpHeaders(x.Headers)
	if x.TLS != nil {
		values["reka_tls"] = xhttpTLSSpec(x.TLS)
	}
	if x.DownloadSettings != nil {
		values["download-settings"] = xhttpWireOptions(x.DownloadSettings)
	}
	return values
}

func xhttpHeaders(headers []model.SubscriptionHeader) map[string]string {
	values := make(map[string]string, len(headers))
	for _, h := range headers {
		values[http.CanonicalHeaderKey(h.Name)] = h.Value
	}
	return values
}

func xhttpTLSSpec(t *model.TLS) *sagernet.TLSSpec {
	out := &sagernet.TLSSpec{ServerName: t.ServerName, Insecure: t.Insecure, Fingerprint: t.Fingerprint, ALPN: t.ALPN, CertificatePin: t.CertificatePin, VerifyName: t.VerifyName, Certificate: t.Certificate, PrivateKey: t.PrivateKey, Carrier: tlsCarrierSpec(t.Carrier)}
	if t.ECH != nil && t.ECH.Enabled {
		out.ECH = &sagernet.ECHSpec{Config: t.ECH.Config, QueryServerName: t.ECH.QueryServerName}
	}
	if t.Reality != nil {
		out.Reality = &sagernet.RealitySpec{PublicKey: t.Reality.PublicKey, ShortID: t.Reality.ShortID, X25519MLKEM768: t.Reality.X25519MLKEM768}
	}
	return out
}
