package clashapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
	"golang.org/x/net/websocket"
)

func (s *Server) rules(w http.ResponseWriter, _ *http.Request) {
	p := s.currentProjection()
	e := s.svc.Engine()
	first := e.RulesPage(0, 1000)
	rules := make([]map[string]any, 0, first.Total)
	for page := first; ; page = e.RulesPage(len(rules), 1000) {
		if page.Generation != first.Generation || page.Revision != first.Revision {
			writeError(w, http.StatusConflict, "rules changed during the request")
			return
		}
		for _, rule := range page.Rules {
			rules = append(rules, map[string]any{"index": rule.Index, "type": clashRuleType(rule.Type), "payload": rule.Payload,
				"proxy": p.display(rule.Outbound), "size": -1})
		}
		if len(rules) >= page.Total || len(page.Rules) == 0 {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func clashRuleType(name string) string {
	switch name {
	case "IP-CIDR":
		return "IPCIDR"
	case "SRC-IP-CIDR":
		return "SrcIPCIDR"
	case "GEOIP":
		return "GeoIP"
	case "GEOSITE":
		return "GeoSite"
	case "IN-NAME":
		return "InName"
	default:
		var out strings.Builder
		for _, part := range strings.Split(strings.ToLower(name), "-") {
			if part != "" {
				out.WriteString(strings.ToUpper(part[:1]) + part[1:])
			}
		}
		return out.String()
	}
}

type connectionMap struct {
	ID          string            `json:"id"`
	Metadata    map[string]string `json:"metadata"`
	Upload      int64             `json:"upload"`
	Download    int64             `json:"download"`
	Start       time.Time         `json:"start"`
	Chains      []string          `json:"chains"`
	Rule        string            `json:"rule"`
	RulePayload string            `json:"rulePayload"`
}

type connectionSnapshot struct {
	UploadTotal   uint64          `json:"uploadTotal"`
	DownloadTotal uint64          `json:"downloadTotal"`
	Connections   []connectionMap `json:"connections"`
	Memory        uint64          `json:"memory"`
}

func (s *Server) connectionSnapshot() (connectionSnapshot, error) {
	release, err := s.svc.AcquireProfileCall("", 0)
	if err != nil {
		return connectionSnapshot{}, err
	}
	defer release()
	p := s.currentProjection()
	e := s.svc.Engine()
	total := e.Traffic()
	items := e.Connections()
	out := connectionSnapshot{UploadTotal: total.UploadTotal, DownloadTotal: total.DownloadTotal, Memory: memoryInUse(),
		Connections: make([]connectionMap, 0, len(items))}
	for _, item := range items {
		source, sourcePort, _ := net.SplitHostPort(item.Source)
		target, targetPort, _ := net.SplitHostPort(item.Destination)
		host := item.DestinationDomain
		if host == "" {
			host = item.SniffedDomain
		}
		ip := ""
		if addr, err := netip.ParseAddr(target); err == nil {
			ip = addr.String()
		} else if host == "" {
			host = target
		}
		chains := []string{p.display(item.Outbound)}
		for i := len(item.Chain) - 1; i >= 0; i-- {
			chains = append(chains, p.display(item.Chain[i]))
		}
		meta := map[string]string{
			"network": item.Network, "type": item.Inbound, "sourceIP": source, "sourcePort": sourcePort,
			"destinationIP": ip, "destinationPort": targetPort, "host": host, "processPath": item.ProcessPath,
			"sniffHost": item.SniffedDomain, "inboundName": item.Inbound,
		}
		rule, payload, _ := strings.Cut(strings.TrimSuffix(item.Rule, ",no-resolve"), ",")
		if target := strings.LastIndexByte(payload, ','); target >= 0 {
			payload = payload[:target]
		} else {
			payload = "" // MATCH has a target but no payload.
		}
		out.Connections = append(out.Connections, connectionMap{ID: strconv.FormatUint(item.ID, 10), Metadata: meta,
			Upload: item.Upload, Download: item.Download, Start: item.Start, Chains: chains,
			Rule: clashRuleType(rule), RulePayload: payload})
	}
	return out, nil
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	if !isWebSocket(r) {
		out, err := s.connectionSnapshot()
		if err != nil {
			writeError(w, http.StatusConflict, "active profile changed")
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	interval := 1000
	if raw := r.URL.Query().Get("interval"); raw != "" {
		interval, _ = strconv.Atoi(raw)
		if interval < 250 || interval > 60000 {
			writeError(w, http.StatusBadRequest, "interval must be 250–60000 ms")
			return
		}
	}
	s.stream(w, r, func(ctx context.Context, send func(any) error) {
		periodic(ctx, time.Duration(interval)*time.Millisecond, func() error {
			out, err := s.connectionSnapshot()
			if err != nil {
				return err
			}
			return send(out)
		})
	})
}

func (s *Server) closeConnections(w http.ResponseWriter, r *http.Request) {
	var ids []uint64
	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || id == 0 {
			writeError(w, http.StatusBadRequest, "invalid connection ID")
			return
		}
		ids = []uint64{id}
	} else {
		for _, c := range s.svc.Engine().Connections() {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) > 0 {
		s.svc.Engine().CloseConnections(ids)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(ctx context.Context, send func(any) error) {
		prev := s.svc.Engine().Traffic()
		periodic(ctx, time.Second, func() error {
			next := s.svc.Engine().Traffic()
			var up, down uint64
			sec := next.SampledAt.Sub(prev.SampledAt).Seconds()
			if sec > 0 && next.UploadTotal >= prev.UploadTotal && next.DownloadTotal >= prev.DownloadTotal {
				up = uint64(float64(next.UploadTotal-prev.UploadTotal) / sec)
				down = uint64(float64(next.DownloadTotal-prev.DownloadTotal) / sec)
			}
			prev = next
			return send(map[string]uint64{"up": up, "down": down, "upTotal": next.UploadTotal, "downTotal": next.DownloadTotal})
		})
	})
}

func memoryInUse() uint64 {
	mem := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(mem)
	return mem[0].Value.Uint64() - mem[1].Value.Uint64()
}

func (s *Server) memory(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(ctx context.Context, send func(any) error) {
		periodic(ctx, time.Second, func() error {
			return send(map[string]uint64{"inuse": memoryInUse(), "oslimit": 0})
		})
	})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	levels := map[string]int{"debug": 1, "info": 2, "warn": 3, "warning": 3, "error": 4, "silent": 5}
	minimum := levels[r.URL.Query().Get("level")]
	if minimum == 0 {
		minimum = levels["info"]
	}
	s.stream(w, r, func(ctx context.Context, send func(any) error) {
		sub := s.svc.Events().Subscribe([]string{service.EventLog}, "", 0, nil)
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-sub.C:
				if !ok {
					return
				}
				fields, _ := event.Data.(map[string]any)
				level, _ := fields["level"].(string)
				message, _ := fields["message"].(string)
				if levels[level] < minimum || message == "" {
					continue
				}
				if level == "warn" {
					level = "warning"
				}
				if send(map[string]string{"type": level, "payload": message}) != nil {
					return
				}
			}
		}
	})
}

func periodic(ctx context.Context, interval time.Duration, send func() error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil && send() == nil {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, serve func(context.Context, func(any) error)) {
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		writeError(w, http.StatusServiceUnavailable, "too many dashboard streams")
		return
	}
	if isWebSocket(r) {
		server := websocket.Server{
			Handshake: func(*websocket.Config, *http.Request) error { return nil }, // the HTTP middleware already checked Origin and token
			Handler: func(ws *websocket.Conn) {
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				ws.MaxPayloadBytes = 4096
				go func() {
					var unused string
					_ = websocket.Message.Receive(ws, &unused)
					cancel()
				}()
				serve(ctx, func(data any) error {
					_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
					return websocket.JSON.Send(ws, data)
				})
			},
		}
		server.ServeHTTP(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	control := http.NewResponseController(w)
	_ = control.SetWriteDeadline(time.Now().Add(5 * time.Second))
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	encoder := json.NewEncoder(w)
	serve(r.Context(), func(data any) error {
		_ = control.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := encoder.Encode(data); err != nil {
			return err
		}
		return control.Flush()
	})
}
