package generation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	ooklaServerListURL = "https://www.speedtest.net/api/js/servers?engine=js&https_functional=true&limit=10"

	// Bound discovery traffic and only probe the five nearest listed servers.
	ooklaServerListLimit = 256 << 10
	ooklaCandidates      = 5
	ooklaProbeLimit      = 3 * time.Second // Keep slow candidates from delaying selection.
)

type ooklaServer struct {
	Host    string `json:"host"`
	Name    string `json:"name"`
	Sponsor string `json:"sponsor"`
}

// ErrOoklaUnreachable reports that the outbound could not reach the Ookla
// server list or any candidate server. Some proxy providers block speed test
// sites, which usually shows up as a closed connection.
var ErrOoklaUnreachable = errors.New("Ookla speed test servers are unreachable through this outbound")

func resolveOoklaEndpoints(ctx context.Context, client *http.Client, listURL string) (speedEndpoints, error) {
	endpoints, err := selectOoklaEndpoints(ctx, client, listURL)
	if err != nil && ctx.Err() == nil {
		return speedEndpoints{}, fmt.Errorf("%w: %w", ErrOoklaUnreachable, err)
	}
	return endpoints, err
}

func selectOoklaEndpoints(ctx context.Context, client *http.Client, listURL string) (speedEndpoints, error) {
	servers, err := fetchOoklaServers(ctx, client, listURL)
	if ctx.Err() != nil {
		return speedEndpoints{}, ctx.Err()
	}
	if err != nil {
		return speedEndpoints{}, err
	}
	type probeResult struct {
		server  ooklaServer
		latency float64
		err     error
	}
	results := make(chan probeResult, ooklaCandidates)
	pending := 0
	for _, server := range servers[:min(len(servers), ooklaCandidates)] {
		if !validOoklaHost(server.Host) {
			continue
		}
		pending++
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, ooklaProbeLimit)
			defer cancel()
			latency, err := measureSpeedLatency(probeCtx, client, "https://"+server.Host+"/hello", SpeedSourceOokla)
			results <- probeResult{server: server, latency: latency, err: err}
		}()
	}

	var best probeResult
	var probeErr error
	for range pending {
		select {
		case <-ctx.Done():
			return speedEndpoints{}, ctx.Err()
		case result := <-results:
			if result.err != nil {
				if probeErr == nil {
					probeErr = result.err
				}
				continue
			}
			if best.server.Host == "" || result.latency < best.latency {
				best = result
			}
		}
	}
	if ctx.Err() != nil {
		return speedEndpoints{}, ctx.Err()
	}
	if best.server.Host == "" {
		if probeErr != nil {
			return speedEndpoints{}, fmt.Errorf("no Ookla server responded: %w", probeErr)
		}
		return speedEndpoints{}, errors.New("no Ookla server responded")
	}

	base := "https://" + best.server.Host
	prefix := rand.Text()
	var sequence atomic.Uint64
	nonce := func() string {
		return prefix + "-" + strconv.FormatUint(sequence.Add(1), 10)
	}
	size := strconv.Itoa(speedDownloadSize)
	return speedEndpoints{
		latency: base + "/hello",
		download: func() string {
			return base + "/download?nocache=" + nonce() + "&size=" + size
		},
		upload: func() string {
			return base + "/upload?nocache=" + nonce()
		},
		server: best.server.Sponsor + " · " + best.server.Name,
	}, nil
}

func fetchOoklaServers(ctx context.Context, client *http.Client, listURL string) ([]ooklaServer, error) {
	request, err := newSpeedRequest(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := speedHTTPError(SpeedSourceOokla, response.StatusCode); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, ooklaServerListLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read Ookla server list: %w", err)
	}
	if len(body) > ooklaServerListLimit {
		return nil, errors.New("Ookla server list exceeds size limit")
	}
	var servers []ooklaServer
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, fmt.Errorf("decode Ookla server list: %w", err)
	}
	return servers, nil
}

func validOoklaHost(host string) bool {
	// A fully qualified DNS name with a trailing dot and a five-digit port fits in 260 bytes.
	if len(host) > 260 || strings.ContainsAny(host, "/?#@\\%") ||
		strings.IndexFunc(host, unicode.IsSpace) >= 0 || strings.HasSuffix(host, ":") {
		return false
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host != host || parsed.Hostname() == "" {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return false
		}
	}
	name := parsed.Hostname()
	if strings.HasPrefix(host, "[") {
		address, err := netip.ParseAddr(name)
		return err == nil && address.Is6()
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}
