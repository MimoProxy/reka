package sagernet

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestRealNode sends an HTTPS request through a real VLESS + REALITY node.
// It only runs when REKA_TEST_NODE holds a share link such as
//
//	vless://UUID@host:443?security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=ID&flow=xtls-rprx-vision
//
// The link is never logged.
func TestRealNode(t *testing.T) {
	link := os.Getenv("REKA_TEST_NODE")
	if link == "" {
		t.Skip("set REKA_TEST_NODE to a vless:// share link to run")
	}
	spec, err := parseVLESSLink(link)
	if err != nil {
		t.Fatalf("parse REKA_TEST_NODE: %v", err)
	}
	if spec.Flow != "" && raceEnabled {
		t.Skip("sing-vmess Vision has an upstream data race between Read and Write")
	}
	socks, out := startClient(t, spec)
	target := os.Getenv("REKA_TEST_URL")
	if target == "" {
		target = "https://www.gstatic.com/generate_204"
	}
	for _, scheme := range []string{"socks5", "http"} {
		t.Run(scheme, func(t *testing.T) {
			client := &http.Client{
				Timeout: 20 * time.Second,
				Transport: &http.Transport{
					Proxy: http.ProxyURL(&url.URL{Scheme: scheme, Host: socks.String()}),
				},
			}
			start := time.Now()
			resp, err := client.Get(target)
			if err != nil {
				t.Fatalf("GET through node: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				t.Fatalf("GET %s: status %d", target, resp.StatusCode)
			}
			t.Logf("%s: status %d in %v", scheme, resp.StatusCode, time.Since(start).Round(time.Millisecond))
			client.CloseIdleConnections()
		})
	}
	waitIdle(t, out)
}

func parseVLESSLink(link string) (VLESSSpec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return VLESSSpec{}, err
	}
	if u.Scheme != "vless" {
		return VLESSSpec{}, &url.Error{Op: "parse", URL: u.Scheme + "://…", Err: errNotVLESS}
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return VLESSSpec{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return VLESSSpec{}, err
	}
	q := u.Query()
	spec := VLESSSpec{
		Server: host,
		Port:   uint16(port),
		UUID:   u.User.Username(),
		Flow:   q.Get("flow"),
	}
	switch q.Get("security") {
	case "reality":
		spec.TLS = &TLSSpec{
			ServerName:  q.Get("sni"),
			Fingerprint: orDefault(q.Get("fp"), "chrome"),
			Reality: &RealitySpec{
				PublicKey:      q.Get("pbk"),
				ShortID:        q.Get("sid"),
				X25519MLKEM768: q.Get("support-x25519mlkem768") == "true",
			},
		}
	case "tls":
		spec.TLS = &TLSSpec{
			ServerName:  orDefault(q.Get("sni"), host),
			Fingerprint: q.Get("fp"),
			Insecure:    q.Get("allowInsecure") == "1",
		}
	}
	if t := q.Get("type"); t != "" && t != "tcp" {
		return VLESSSpec{}, &url.Error{Op: "parse", URL: "vless://…", Err: errTransport}
	}
	return spec, nil
}

type parseError string

func (e parseError) Error() string { return string(e) }

const (
	errNotVLESS  = parseError("not a vless:// link")
	errTransport = parseError("only the raw TCP transport is supported for now")
)

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
