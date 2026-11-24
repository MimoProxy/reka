package sagernet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http/httpguts"
)

type mitmHTTPHandler struct {
	backend   *Backend
	route     *MITMRoute
	attempt   *connectionAttempt
	metadata  adapter.InboundContext
	upstream  *mitmUpstream
	host      string
	closeWire func()
}

type mitmRequestStats struct {
	matches       []string
	passthroughs  uint64
	resourceError bool
}

func (s *mitmHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.attempt.mu.Lock()
	s.attempt.MITMRequests++
	s.attempt.mu.Unlock()
	if s.route.OnRequest != nil {
		s.route.OnRequest()
	}

	request := r.Clone(r.Context())
	request.URL = mitmRequestURL(r, s.host, s.metadata.Destination.Port)
	request.RequestURI = ""
	request.TransferEncoding = nil
	request.Trailer = nil
	request.Close = false

	ctx, obs := s.backend.beginRequest(r.Context(), request, s.metadata.Inbound, r.RemoteAddr)
	bindRequestConnection(ctx, s.attempt)
	var stats mitmRequestStats
	var status int
	var err error
	var hijacked net.Conn
	localError := func(code int, message string) {
		status = code
		mitmAllowEarlyResponse(w, r)
		http.Error(w, message, code)
	}
	defer func() {
		s.attempt.mu.Lock()
		s.attempt.MITMMatchedIDs = appendMITMMatches(s.attempt.MITMMatchedIDs, stats.matches)
		s.attempt.MITMBodyPassthroughs += stats.passthroughs
		s.attempt.mu.Unlock()
		obs.setMITM(stats)
		obs.finish(status, err)
		if hijacked != nil {
			// Close and drop do not wait to write a TLS close notification.
			s.closeWire()
			_ = hijacked.Close()
		}
	}()

	if r.Method == http.MethodConnect {
		localError(http.StatusMethodNotAllowed, "HTTPS request tunneling is unsupported")
		return
	}

	rewrite := s.route.Rewrite
	originalURL := request.URL.String()
	request.Header.Set("Host", request.URL.Host)
	var data []byte
	if rewrite.NeedsRequestBody(originalURL) {
		data, request.Body, err = bufferMITMBody(request.Body, request.ContentLength, s.route.MaxBodySize, &stats)
		if err != nil {
			w.Header().Set("Connection", "close")
			localError(http.StatusBadRequest, "Could not read request body")
			return
		}
	}
	rewritten := rewrite.Request(httprewrite.Request{
		URL: originalURL, Method: request.Method, Header: request.Header, Body: data,
	})
	stats.addMatches(rewritten.MatchedIDs)

	if rewritten.ResourceError != nil {
		stats.resourceError, err = true, rewritten.ResourceError
		localError(http.StatusBadGateway, "Could not read local response resource")
		return
	}
	if rewritten.Local != nil {
		local := rewritten.Local
		if local.StatusCode < http.StatusOK {
			localError(http.StatusBadGateway, "Local response needs a final HTTP status")
			return
		}
		status = local.StatusCode
		mitmAllowEarlyResponse(w, r)
		writeMITMHeaders(w, local.Header, status)
		if r.Method != http.MethodHead && len(local.Body) != 0 {
			var n int
			n, err = w.Write(local.Body)
			obs.down.Add(int64(n))
		}
		return
	}

	switch rewritten.Connection {
	case httprewrite.Close, httprewrite.Drop:
		conn, buffered, hijackErr := http.NewResponseController(w).Hijack()
		hijacked, err = conn, hijackErr
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if rewritten.Connection == httprewrite.Close {
			return
		}
		// A hijack allows us to observe peer closure even when the request
		// body has not been read. No response or continue message is sent.
		_ = conn.SetReadDeadline(time.Now().Add(s.backend.halfCloseTimeout))
		_, err = io.Copy(io.Discard, buffered.Reader)
		return
	}

	target, destination, err := mitmUpstreamTarget(rewritten.URL)
	if err != nil {
		localError(http.StatusBadGateway, "Invalid HTTPS rewrite target")
		return
	}
	request.Host = target.Host
	if headerHost := rewritten.Header.Get("Host"); headerHost != "" && headerHost != request.URL.Host {
		request.Host = headerHost
	}
	if !httpguts.ValidHostHeader(request.Host) {
		localError(http.StatusBadGateway, "Invalid HTTPS request authority")
		return
	}
	request.URL, request.Header = target, rewritten.Header
	if r.RequestURI == "*" && target.Path == "/*" && target.RawQuery == "" {
		request.URL.Path, request.URL.RawPath = "*", ""
	}
	request.Header.Del("Host")
	stripHTTPHopHeaders(request.Header)
	if data != nil {
		request.ContentLength = int64(len(rewritten.Body))
		request.Body = http.NoBody
		if len(rewritten.Body) != 0 {
			request.Body = io.NopCloser(bytes.NewReader(rewritten.Body))
		}
	}

	needsResponse := rewrite.NeedsResponseBody(rewritten.URL)
	if needsResponse {
		limitMITMEncodings(request.Header)
	}
	upstream := s.upstream
	if rewritten.HostChanged {
		upstream, err = s.reroute(ctx, destination, target.Hostname())
		if err != nil {
			localError(http.StatusBadGateway, "Could not route rewritten HTTPS request")
			return
		}
		// Close before releasing the new route, even when streaming fails or
		// the transport has started an asynchronous dial.
		defer func() {
			upstream.close()
			upstream.route.Release()
		}()
	}

	res, err := upstream.transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		localError(http.StatusBadGateway, "HTTPS upstream request failed")
		return
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		_ = res.Body.Close()
		localError(http.StatusBadGateway, "HTTPS upstream protocol upgrade is unsupported")
		return
	}
	obs.response(res)
	defer res.Body.Close()
	var responseBody io.ReadCloser = res.Body
	var responseData []byte
	if needsResponse {
		responseData, responseBody, err = bufferMITMBody(res.Body, res.ContentLength, s.route.MaxBodySize, &stats)
		if err != nil {
			// A response whose body could not be read has not been sent.
			obs.clearOriginStatus()
			localError(http.StatusBadGateway, "Could not read HTTPS upstream response")
			return
		}
	}
	result := rewrite.Response(rewritten.URL, httprewrite.Response{
		StatusCode: res.StatusCode, Header: res.Header, Body: responseData,
	})
	stats.addMatches(result.MatchedIDs)
	writeMITMHeaders(w, result.Header, result.StatusCode)
	if responseData != nil {
		if len(result.Body) != 0 {
			_, err = w.Write(result.Body)
		}
	} else if responseBody != http.NoBody {
		var writer io.Writer = w
		if res.ContentLength < 0 {
			// Deliver each chunk of a streaming response as it arrives.
			flusher := http.NewResponseController(w)
			if err = flusher.Flush(); err != nil {
				panic(http.ErrAbortHandler)
			}
			writer = mitmStreamWriter{ResponseWriter: w, flusher: flusher}
		}
		// Reuse relay-sized pooled buffers; io.Copy allocates 32 KiB per response.
		buffer := buf.Get(buf.BufferSize)
		_, err = io.CopyBuffer(writer, responseBody, buffer)
		_ = buf.Put(buffer)
	}
	if err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (s *mitmHTTPHandler) reroute(ctx context.Context, destination Destination, host string) (*mitmUpstream, error) {
	if s.route.Reroute == nil {
		return nil, errRejected
	}
	route := normalizeRoute(s.route.Reroute(ctx, destination))
	if route.Outbound == nil {
		return nil, errRejected
	}
	if route.Destination != nil {
		destination = *route.Destination
	}
	metadata := s.metadata
	metadata.Destination = M.ParseSocksaddr(destination.String())
	metadata.Domain = host
	return newMITMUpstream(ctx, route, metadata, host, s.route.SkipServerCertVerify, s.attempt), nil
}

func mitmRequestURL(r *http.Request, host string, port uint16) *url.URL {
	// The HTTP authority may name a virtual host within the TCP destination.
	// It does not change where the original outbound dials or verifies TLS.
	if authority, err := url.Parse("https://" + r.Host); err == nil &&
		authority.Hostname() != "" && authority.User == nil && authority.Path == "" &&
		authority.RawQuery == "" && authority.Fragment == "" {
		host = authority.Hostname()
		if authority.Port() != "" {
			if number, err := strconv.ParseUint(authority.Port(), 10, 16); err == nil && number != 0 {
				port = uint16(number)
			}
		}
	}
	u := *r.URL
	u.Scheme, u.Host, u.Opaque, u.User = "https", host, "", nil
	switch {
	case port != 443:
		u.Host = net.JoinHostPort(host, itoa(port))
	case strings.Contains(host, ":"):
		u.Host = "[" + host + "]"
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return &u
}

func mitmUpstreamTarget(raw string) (*url.URL, Destination, error) {
	invalid := errors.New("invalid HTTPS rewrite target")
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, Destination{}, invalid
	}
	host := target.Hostname()
	destination := Destination{Domain: host, Port: 443}
	if addr, err := netip.ParseAddr(host); err == nil {
		destination.Addr, destination.Domain = addr.Unmap(), ""
	} else if !M.IsDomainName(host) {
		return nil, Destination{}, invalid
	}
	if port := target.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return nil, Destination{}, invalid
		}
		destination.Port = uint16(number)
	}
	return target, destination, nil
}

func bufferMITMBody(body io.ReadCloser, length int64, limit int, stats *mitmRequestStats) ([]byte, io.ReadCloser, error) {
	if body == nil || body == http.NoBody {
		return nil, body, nil
	}
	if length > int64(limit) {
		stats.passthroughs++
		return nil, body, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, body, err
	}
	if len(data) <= limit {
		return data, body, nil
	}
	stats.passthroughs++
	return nil, prefixedMITMBody{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}, nil
}

type prefixedMITMBody struct {
	io.Reader
	io.Closer
}

func limitMITMEncodings(header http.Header) {
	var accepted []string
	for _, line := range header.Values("Accept-Encoding") {
		for item := range strings.SplitSeq(line, ",") {
			coding, _, _ := strings.Cut(item, ";")
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "gzip", "deflate", "identity":
				accepted = append(accepted, strings.TrimSpace(item))
			}
		}
	}
	if len(accepted) == 0 {
		// Avoid asking the origin for a compressed body the client did not
		// explicitly accept. Unchanged and oversized bodies pass through.
		accepted = append(accepted, "identity")
	}
	header.Set("Accept-Encoding", strings.Join(accepted, ", "))
}

func writeMITMHeaders(w http.ResponseWriter, header http.Header, status int) {
	stripHTTPHopHeaders(header)
	for key, values := range header {
		w.Header()[key] = values
	}
	w.WriteHeader(status)
}

func mitmAllowEarlyResponse(w http.ResponseWriter, request *http.Request) {
	if request.Body == nil || request.Body == http.NoBody {
		return
	}
	// Send local responses before consuming an upload. The server can still
	// drain the body for keep-alive, with the sing-box TCP timeout as a bound.
	controller := http.NewResponseController(w)
	_ = controller.EnableFullDuplex()
	_ = controller.SetReadDeadline(time.Now().Add(C.TCPTimeout))
}

type mitmStreamWriter struct {
	http.ResponseWriter
	flusher *http.ResponseController
}

func (w mitmStreamWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = w.flusher.Flush()
	}
	return n, err
}

func (s *mitmRequestStats) addMatches(ids []string) {
	s.matches = appendMITMMatches(s.matches, ids)
}

// Match the existing connection timeline cap and label size for diagnostics.
func appendMITMMatches(matches, ids []string) []string {
	for _, id := range ids {
		if len(matches) == maxConnectionEvents {
			break
		}
		id = history.Text(id, connectionLabelBytes)
		if !slices.Contains(matches, id) {
			matches = append(matches, id)
		}
	}
	return matches
}
