// livenodes reads only proxy entries and emits credential-free connectivity results.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	D "github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"strings"
	"time"
)

type result struct {
	Protocol string `json:"protocol"`
	Index    int    `json:"index"`
	TCP      string `json:"tcp"`
	HTTP     int    `json:"http_status,omitempty"`
	UDP      string `json:"udp"`
	Elapsed  int64  `json:"elapsed_ms"`
}

func main() {
	path := flag.String("config", "", "local configuration path")
	workspace := flag.String("workspace", "", "Mimo workspace containing stored subscription YAML")
	diagnostic := flag.Bool("diagnostic", false, "write credential-redacted TCP diagnostics to stderr")
	perType := flag.Int("per-type", 2, "maximum samples for each protocol")
	flag.Parse()
	var documents []string
	if *workspace != "" {
		data, err := os.ReadFile(*workspace)
		if err != nil {
			panic("cannot read workspace")
		}
		var saved struct {
			Subscriptions []struct {
				YAML string `json:"yaml"`
			} `json:"subscriptions"`
		}
		if json.Unmarshal(data, &saved) != nil {
			panic("invalid workspace")
		}
		for _, s := range saved.Subscriptions {
			if s.YAML != "" {
				documents = append(documents, s.YAML)
			}
		}
	} else {
		if *path == "" {
			panic("config or workspace required")
		}
		data, err := os.ReadFile(*path)
		if err != nil {
			panic("cannot read configuration")
		}
		documents = []string{string(data)}
	}
	var proxies []*yaml.Node
	for _, data := range documents {
		root, ds := model.ParseNode("private", []byte(data))
		if ds.HasErrors() {
			continue
		}
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "proxies" {
				proxies = append(proxies, root.Content[i+1].Content...)
			}
		}
	}
	counts := map[string]int{}
	encoder := json.NewEncoder(os.Stdout)
	for _, node := range proxies {
		typ := ""
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "type" {
				typ = node.Content[i+1].Value
			}
		}
		if typ == "direct" || typ == "reject" || counts[typ] >= *perType {
			continue
		}
		counts[typ]++
		r := result{Protocol: typ, Index: counts[typ], TCP: "not-tested", UDP: "not-tested"}
		started := time.Now()
		wrapper := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxies"}, {Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{node}}}}
		imported := importer.Import(importer.Request{SourceID: "live", Format: "clash", Data: string(model.Format(wrapper)), NodesOnly: true})
		if !imported.Report.CanApply {
			r.TCP = "import-rejected"
			encoder.Encode(r)
			continue
		}
		snapshot := imported.Preview(true).Sources
		sources, _, _ := model.ParseSources([]byte(snapshot))
		id := "live/" + sources.Sources[0].Outbounds[0].ID
		profile := fmt.Sprintf("schema-version: 1\nimports: [{source: live, outbounds: true}]\nrules: [{match: {all: true}, outbound: %s}]\n", id)
		eff, diags := compile.Compile([]byte(profile), nil, compile.Options{Sources: []byte(snapshot)})
		if diags.HasErrors() {
			r.TCP = "compile-rejected"
			encoder.Encode(r)
			continue
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		engine := generation.NewEngine(generation.EngineOptions{Backend: sagernet.Options{Logger: logger}})
		prepared, err := engine.Prepare(eff)
		if err != nil {
			engine.Close()
			r.TCP = "prepare-failed"
			encoder.Encode(r)
			continue
		}
		if _, err = engine.Activate(prepared, 1); err != nil {
			engine.Close()
			r.TCP = "activate-failed"
			encoder.Encode(r)
			continue
		}
		out := engine.OutboundInstance(id)
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: true, DialContext: out.Dial}
		client := &http.Client{Transport: tr, Timeout: 12 * time.Second}
		request, _ := http.NewRequest("GET", "https://www.gstatic.com/generate_204", nil)
		if *diagnostic {
			trace := &httptrace.ClientTrace{
				TLSHandshakeDone: func(_ tls.ConnectionState, e error) { fmt.Fprintf(os.Stderr, "%s inner_TLS_done: %v\n", typ, e) },
				WroteRequest:     func(w httptrace.WroteRequestInfo) { fmt.Fprintf(os.Stderr, "%s request_written: %v\n", typ, w.Err) },
			}
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
		}
		response, err := client.Do(request)
		if err != nil {
			r.TCP = "http-request-failed"
			if *diagnostic {
				message := err.Error()
				for i := 0; i+1 < len(node.Content); i += 2 {
					switch node.Content[i].Value {
					case "password", "psk", "uuid", "username", "userkey":
						value := node.Content[i+1].Value
						if value != "" {
							message = strings.ReplaceAll(message, value, "[redacted]")
						}
					}
				}
				fmt.Fprintf(os.Stderr, "%s TCP: %s\n", typ, message)
			}
		} else {
			r.HTTP = response.StatusCode
			r.TCP = "passed"
			io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
		}
		tr.CloseIdleConnections()
		if !eff.Outbounds[0].UDP {
			r.UDP = "disabled-by-configuration"
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			conn, err := out.Dial(ctx, "udp", netip.MustParseAddrPort("1.1.1.1:53").String())
			if err != nil {
				r.UDP = "dial-failed"
			} else {
				conn.SetDeadline(time.Now().Add(6 * time.Second))
				q := new(D.Msg)
				q.SetQuestion("example.com.", D.TypeA)
				wire, _ := q.Pack()
				_, err = conn.Write(wire)
				buffer := make([]byte, 4096)
				var n int
				if err == nil {
					n, err = conn.Read(buffer)
				}
				if err != nil {
					r.UDP = "exchange-failed"
				} else {
					m := new(D.Msg)
					if m.Unpack(buffer[:n]) == nil && m.Id == q.Id && m.Rcode == D.RcodeSuccess && len(m.Answer) > 0 {
						r.UDP = "passed"
					} else {
						r.UDP = "invalid-response"
					}
				}
				conn.Close()
			}
			cancel()
		}
		engine.Close()
		r.Elapsed = time.Since(started).Milliseconds()
		encoder.Encode(r)
	}
}
