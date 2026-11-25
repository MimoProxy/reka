package sagernet

import "net/http"

func mitmTLSNextProtos(h2 bool) []string {
	if h2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func mitmHTTPProtocols(h2 bool) *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(h2)
	return p
}
