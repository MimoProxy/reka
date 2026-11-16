package importer

import (
	"strings"
	"testing"
)

const xhttpClash = `proxies:
 - name: split
   type: vless
   server: upload.test
   port: 443
   uuid: b831381d-6324-4d53-ad4f-8cda48b30811
   tls: true
   servername: upload.test
   alpn: [h2]
   network: xhttp
   xhttp-opts:
    host: front.test
    path: /split
    mode: stream-up
    headers: {X-Upload: upload-private}
    reuse-settings: {max-connections: '4', h-keep-alive-period: 45}
    download-settings:
     server: download.test
     port: 8443
     servername: download.test
     alpn: [h3]
     headers: {X-Download: download-private}
rules: ['MATCH,split']
`

func TestXHTTPClashImportAndMaskedDownload(t *testing.T) {
	r := Import(request(xhttpClash))
	if !r.Report.CanApply || r.Report.Partial {
		t.Fatal(r.Report)
	}
	n := snapshot(t, r).Outbounds[0]
	if n.Transport.Type != "xhttp" || n.Transport.Host != "front.test" || n.Transport.Path != "/split" || n.Transport.XHTTP.XMUX.HKeepAlivePeriod != "45" {
		t.Fatal("XHTTP options not preserved")
	}
	d := n.Transport.XHTTP.DownloadSettings
	if d.Server != "download.test" || d.Port != 8443 || d.TLS.ServerName != "download.test" || len(d.TLS.ALPN) != 1 || d.TLS.ALPN[0] != "h3" {
		t.Fatal("independent download endpoint was lost")
	}
	preview := r.Preview(false).Sources
	if strings.Contains(preview, "upload-private") || strings.Contains(preview, "download-private") {
		t.Fatal("XHTTP headers leaked in preview")
	}
	compileImport(t, r)
	plain := Import(request(strings.Replace(xhttpClash, "servername: download.test\n     alpn: [h3]", "tls: false", 1)))
	if !plain.Report.CanApply || !snapshot(t, plain).Outbounds[0].Transport.XHTTP.DownloadSettings.DisableTLS {
		t.Fatal("explicit plaintext download override not preserved", plain.Report)
	}
}

func TestXHTTPClashRejectsUnknownAndAmbiguousOptions(t *testing.T) {
	for name, data := range map[string]string{
		"unknown main option":       strings.Replace(xhttpClash, "mode: stream-up", "unsupported: true", 1),
		"unknown download option":   strings.Replace(xhttpClash, "server: download.test", "unknown: true", 1),
		"unknown reuse option":      strings.Replace(xhttpClash, "max-connections: '4'", "unknown: '4'", 1),
		"duplicate reuse alias":     strings.Replace(xhttpClash, "mode: stream-up", "mode: stream-up\n    xmux: {}", 1),
		"nested download":           strings.Replace(xhttpClash, "server: download.test", "download-settings: {}", 1),
		"wrong network":             strings.Replace(xhttpClash, "network: xhttp", "network: tcp", 1),
		"TLS option while disabled": strings.Replace(xhttpClash, "servername: download.test", "tls: false\n     servername: download.test", 1),
	} {
		t.Run(name, func(t *testing.T) {
			r := Import(request(data))
			if r.Report.CanApply || r.Report.Nodes.Imported != 0 {
				t.Fatal("unsupported XHTTP silently applied", r.Report)
			}
		})
	}
	found := false
	for _, entry := range SupportMatrix() {
		found = found || entry.Scope == "vless" && entry.Field == "xhttp-opts" && entry.Status == "supported"
	}
	if !found {
		t.Fatal("XHTTP missing from capability support matrix")
	}
}
