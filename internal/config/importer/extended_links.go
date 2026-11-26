package importer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func parseVMessLink(raw string) (object, error) {
	b, err := decodeBase64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	if err = json.Unmarshal(b, &values); err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, key := range []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp"} {
		known[key] = true
	}
	for k := range values {
		if !known[k] {
			return nil, fmt.Errorf("unknown VMess field")
		}
	}
	text := func(k string) string {
		var value string
		if json.Unmarshal(values[k], &value) == nil {
			return value
		}
		var n json.Number
		if json.Unmarshal(values[k], &n) == nil {
			return n.String()
		}
		return ""
	}
	port, err := strconv.Atoi(text("port"))
	if err != nil {
		return nil, err
	}
	aid := 0
	if a := text("aid"); a != "" {
		aid, err = strconv.Atoi(a)
		if err != nil {
			return nil, err
		}
	}
	out := object{"name": text("ps"), "type": "vmess", "server": text("add"), "port": port, "uuid": text("id"), "alterId": aid, "cipher": text("scy"), "udp": true}
	if out["name"] == "" {
		out["name"] = "vmess@" + text("add")
	}
	if text("type") != "" && text("type") != "none" {
		return nil, fmt.Errorf("unsupported VMess header")
	}
	network := text("net")
	if network != "" && network != "tcp" {
		out["network"] = network
		switch network {
		case "ws":
			out["ws-opts"] = object{"path": text("path"), "headers": object{"Host": text("host")}}
		case "grpc":
			out["grpc-opts"] = object{"grpc-service-name": text("path")}
		case "httpupgrade":
			out["http-upgrade-opts"] = object{"path": text("path"), "host": text("host")}
		default:
			return nil, fmt.Errorf("unsupported VMess transport")
		}
	}
	if tls := text("tls"); tls == "tls" {
		out["tls"] = true
		if text("sni") != "" {
			out["servername"] = text("sni")
		}
		if text("fp") != "" {
			out["client-fingerprint"] = text("fp")
		}
		if text("alpn") != "" {
			out["alpn"] = strings.Split(text("alpn"), ",")
		}
	} else if tls != "" && tls != "none" {
		return nil, fmt.Errorf("unsupported VMess security")
	}
	return out, nil
}
func linkTransport(out object, q url.Values) {
	switch q.Get("type") {
	case "ws":
		out["ws-opts"] = object{"path": q.Get("path"), "headers": object{"Host": q.Get("host")}}
	case "grpc":
		out["grpc-opts"] = object{"grpc-service-name": q.Get("serviceName")}
	case "httpupgrade":
		out["http-upgrade-opts"] = object{"path": q.Get("path"), "host": q.Get("host")}
	}
}

func parseHysteriaLink(out object, q url.Values) error {
	for key := range q {
		switch key {
		case "auth", "peer", "obfs", "protocol", "alpn", "up", "upmbps", "down", "downmbps", "insecure":
		default:
			return fmt.Errorf("unknown Hysteria option")
		}
	}
	out["auth-str"], out["sni"] = q.Get("auth"), q.Get("peer")
	out["obfs"], out["protocol"] = q.Get("obfs"), q.Get("protocol")
	for _, key := range []string{"up", "down"} {
		value := q.Get(key)
		if value == "" {
			value = q.Get(key + "mbps")
		}
		out[key] = value
	}
	if alpn := q.Get("alpn"); alpn != "" {
		out["alpn"] = strings.Split(alpn, ",")
	}
	// mihomo treats an absent or unrecognized insecure value as false.
	out["skip-cert-verify"], _ = strconv.ParseBool(q.Get("insecure"))
	return nil
}

func parseSecureLink(u *url.URL, out object, q url.Values) error {
	known := map[string]bool{}
	for _, k := range []string{"type", "security", "sni", "peer", "fp", "alpn", "allowInsecure", "insecure", "path", "host", "serviceName", "obfs", "obfs-password", "congestion_control", "udp_relay_mode", "zero_rtt"} {
		known[k] = true
	}
	for key := range q {
		if !known[key] {
			return fmt.Errorf("unknown share-link option")
		}
	}
	typ := u.Scheme
	if typ == "hy2" {
		typ = "hysteria2"
	}
	out["type"], out["tls"] = typ, true
	password := u.User.Username()
	if p, ok := u.User.Password(); ok {
		if typ == "tuic" {
			out["uuid"] = u.User.Username()
			password = p
		} else {
			password += ":" + p
		}
	} else if typ == "tuic" {
		return fmt.Errorf("TUIC requires UUID and password")
	}
	out["password"] = password
	if security := q.Get("security"); security != "" && security != "tls" {
		return fmt.Errorf("secure protocol requires TLS")
	}
	for from, to := range map[string]string{"type": "network", "sni": "servername", "peer": "servername", "fp": "client-fingerprint", "obfs": "obfs", "obfs-password": "obfs-password", "congestion_control": "congestion-controller", "udp_relay_mode": "udp-relay-mode"} {
		if v := q.Get(from); v != "" {
			out[to] = v
		}
	}
	for from, to := range map[string]string{"insecure": "skip-cert-verify", "allowInsecure": "skip-cert-verify", "zero_rtt": "reduce-rtt"} {
		if v := q.Get(from); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return err
			}
			out[to] = b
		}
	}
	if a := q.Get("alpn"); a != "" {
		out["alpn"] = strings.Split(a, ",")
	}
	linkTransport(out, q)
	return nil
}
