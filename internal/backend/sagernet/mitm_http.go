package sagernet

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
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

	mu       sync.Mutex
	closing  bool
	requests sync.WaitGroup
}

type mitmRequestStats struct {
	matches       []string
	scripts       []api.MITMScriptRun
	passthroughs  uint64
	resourceError bool
}

func (s *mitmHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		panic(http.ErrAbortHandler)
	}
	s.requests.Add(1)
	s.mu.Unlock()
	defer s.requests.Done()

	s.attempt.mu.Lock()
	if s.route.PlainHTTP {
		s.attempt.MITMClientProtocol = strings.ToLower(r.Proto)
	}
	if s.route.PlainHTTP && r.ProtoMajor == 2 && r.Method == "PRI" && r.RequestURI == "*" {
		s.attempt.MITMClientProtocol = "h2c"
		s.attempt.mu.Unlock()
		if err := s.forwardHTTPProxyRequest(r.Context(), w, r, "h2c"); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	s.attempt.MITMRequests++
	s.attempt.mu.Unlock()
	if s.route.OnRequest != nil {
		s.route.OnRequest()
	}

	request := r.Clone(r.Context())
	originalURL := mitmRequestURL(r, s.host, s.metadata.Destination.Port, s.route.PlainHTTP)
	request.URL = originalURL
	request.RequestURI = ""
	request.TransferEncoding = nil
	request.Close = false
	upgrade := r.ProtoMajor == 1 && httpUpgradeProtocol(r.Header) != ""
	h2 := s.route.H2 && !s.route.PlainHTTP && !upgrade
	clientAcceptsTrailers := h2 && httpguts.HeaderValuesContainsToken(r.Header.Values("TE"), "trailers")
	if h2 {
		for name := range request.Trailer {
			if !validMITMTrailer(name) {
				delete(request.Trailer, name)
			}
		}
		if len(request.Trailer) == 0 {
			request.Trailer = nil
		} else if request.Body != nil && request.Body != http.NoBody {
			// net/http populates the inbound values once Body reaches EOF.
			request.Body = mitmRequestTrailerBody{ReadCloser: request.Body, inbound: r.Trailer, outbound: request.Trailer}
		}
	} else {
		request.Trailer = nil
	}

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
	writeLocal := func(local *httprewrite.Response) {
		status = local.StatusCode
		mitmAllowEarlyResponse(w, r)
		writeMITMHeaders(w, local.Header, status)
		if mitmResponseHasBody(r.Method, status) && len(local.Body) != 0 {
			var n int
			n, err = w.Write(local.Body)
			obs.down.Add(int64(n))
		}
	}
	hijack := func() *bufio.ReadWriter {
		conn, buffered, hijackErr := http.NewResponseController(w).Hijack()
		hijacked, err = conn, hijackErr
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		return buffered
	}
	defer func() {
		s.attempt.mu.Lock()
		s.attempt.MITMMatchedIDs = appendMITMMatches(s.attempt.MITMMatchedIDs, stats.matches)
		s.attempt.MITMScripts = appendMITMScriptStats(s.attempt.MITMScripts, stats.scripts)
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

	if s.route.PlainHTTP && (r.Method == http.MethodConnect || r.URL.IsAbs()) {
		reason := "absolute-form"
		if r.Method == http.MethodConnect {
			reason = "connect"
		}
		err = s.forwardHTTPProxyRequest(ctx, w, r, reason)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	if r.Method == http.MethodConnect {
		localError(http.StatusMethodNotAllowed, "HTTPS request tunneling is unsupported")
		return
	}

	rewrite := s.route.Rewrite
	request.Header.Set("Host", request.URL.Host)
	rewritten := rewrite.RequestBeforeBody(httprewrite.Request{
		URL: request.URL.String(), Method: request.Method, Header: request.Header,
	})
	preBodyMatches := len(rewritten.MatchedIDs)
	stats.addMatches(rewritten.MatchedIDs)

	if rewritten.ResourceError != nil {
		stats.resourceError, err = true, rewritten.ResourceError
		localError(http.StatusBadGateway, "Could not read local response resource")
		return
	}
	if rewritten.Local != nil {
		if rewritten.Local.StatusCode < http.StatusOK {
			localError(http.StatusBadGateway, "Local response needs a final HTTP status")
			return
		}
		writeLocal(rewritten.Local)
		return
	}

	switch rewritten.Connection {
	case httprewrite.Close, httprewrite.Drop:
		if r.ProtoMajor == 2 {
			if rewritten.Connection == httprewrite.Drop {
				timer := time.NewTimer(s.backend.halfCloseTimeout)
				defer timer.Stop()
				select {
				case <-r.Context().Done():
					err = r.Context().Err()
				case <-timer.C:
					err = context.DeadlineExceeded
				}
			}
			panic(http.ErrAbortHandler)
		}
		buffered := hijack()
		if rewritten.Connection == httprewrite.Close {
			return
		}
		// A hijack allows us to observe peer closure even when the request
		// body has not been read. No response or continue message is sent.
		_ = hijacked.SetReadDeadline(time.Now().Add(s.backend.halfCloseTimeout))
		_, err = io.Copy(io.Discard, buffered.Reader)
		return
	}

	target, destination, err := mitmUpstreamTarget(rewritten.URL, s.route.PlainHTTP)
	if err != nil {
		localError(http.StatusBadGateway, "Invalid HTTP rewrite target")
		return
	}

	requestScript := s.matchScript(script.KindHTTPRequest, rewritten.URL)
	needsRequestRewrite := !upgrade && rewrite.NeedsRewrittenRequestBody(rewritten.URL)
	requestBuffer := mitmBufferedBody{reader: request.Body}
	if !upgrade {
		requestBuffer, err = s.bufferBody(request.Body, request.ContentLength, needsRequestRewrite, requestScript)
	}
	if err != nil {
		s.recordScriptInputError(&stats, requestScript, "request")
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		localError(http.StatusBadRequest, "Could not read request body")
		return
	}
	defer requestBuffer.releaseBudget()
	requestPassthrough := needsRequestRewrite && requestBuffer.exceeds(s.route.MaxBodySize)
	if needsRequestRewrite && !requestPassthrough {
		rewrite.ApplyRequestBody(&rewritten, requestBuffer.data)
		requestBuffer.data = rewritten.Body
		stats.addMatches(rewritten.MatchedIDs[preBodyMatches:])
	}

	request.Host = target.Host
	if headerHost := rewritten.Header.Get("Host"); headerHost != "" && headerHost != request.URL.Host {
		request.Host = headerHost
	}
	if !httpguts.ValidHostHeader(request.Host) {
		localError(http.StatusBadGateway, "Invalid HTTP request authority")
		return
	}
	request.URL, request.Header = target, rewritten.Header
	if r.RequestURI == "*" && target.Path == "/*" && target.RawQuery == "" {
		request.URL.Path, request.URL.RawPath = "*", ""
	}
	request.Header.Del("Host")
	stripMITMRequestHopHeaders(request.Header, upgrade)
	request.Body = requestBuffer.reader
	if requestBuffer.data != nil {
		setMITMRequestBody(request, requestBuffer.data)
	}

	reroute := rewritten.HostChanged
	var local *httprewrite.Response
	var abort bool
	teTrailers := httpguts.HeaderValuesContainsToken(r.Header.Values("TE"), "trailers")
	requestInput := mitmScriptInput{id: obs.summary.ID, request: request, teTrailers: teTrailers}
	scriptOversize := s.runScript(r.Context(), requestScript, requestInput, requestBuffer, &stats, func(result script.Result) error {
		switch result.Action {
		case script.ActionModify:
			if upgrade {
				result.BodySet = false
			}
			newDestination, changed, applyErr := applyMITMRequestScript(request, result, s.route.PlainHTTP, upgrade)
			if applyErr != nil {
				return applyErr
			}
			if changed {
				destination, reroute = newDestination, true
			}
			if result.BodySet && requestBuffer.data == nil {
				mitmAllowEarlyResponse(w, r)
				if len(request.Trailer) != 0 && requestBuffer.reader != nil && requestBuffer.reader != http.NoBody {
					// The replacement is complete, but the original upload
					// still needs to reach EOF to make its trailers available.
					request.Body = prefixedMITMBody{
						Reader: io.MultiReader(request.Body, mitmTrailerDrain{requestBuffer.reader}),
						Closer: requestBuffer.reader,
					}
					request.GetBody = nil
				}
			}
		case script.ActionRespond:
			var applyErr error
			local, applyErr = mitmScriptResponse(result.Response)
			return applyErr
		case script.ActionAbort:
			abort = true
		}
		return nil
	})
	if scriptOversize || requestPassthrough {
		stats.passthroughs++
	}
	if local != nil {
		writeLocal(local)
		return
	}
	if abort {
		if r.ProtoMajor == 2 {
			panic(http.ErrAbortHandler)
		}
		hijack()
		return
	}

	if clientAcceptsTrailers {
		request.Header.Set("TE", "trailers")
	}
	if !h2 {
		request.GetBody = nil
	}
	if len(request.Trailer) != 0 {
		// HTTP/1.1 requires chunked framing to send trailers. The HTTP/2
		// transport ignores TransferEncoding and sends trailing HEADERS.
		request.Header.Del("Content-Length")
		if request.Body == http.NoBody {
			setMITMRequestBody(request, nil)
		}
		request.TransferEncoding = []string{"chunked"}
		request.ContentLength = -1
	}

	finalURL := request.URL.String()
	responseScript := s.matchScript(script.KindHTTPResponse, finalURL)
	needsResponseRewrite := rewrite.NeedsResponseBody(finalURL)
	if needsResponseRewrite || responseScript.bodyLimit() > 0 {
		limitMITMEncodings(request.Header)
	}
	if s.route.PlainHTTP {
		reroute = !sameMITMOrigin(originalURL, request.URL)
	}
	upstream := s.upstream
	if reroute {
		upstream, err = s.reroute(ctx, destination, request.URL.Hostname(), h2)
		if err != nil {
			localError(http.StatusBadGateway, "Could not route rewritten HTTP request")
			return
		}
		// Close before releasing the new route, even when streaming fails or
		// the transport has started an asynchronous dial.
		defer func() {
			upstream.close()
			upstream.route.Release()
		}()
	} else if upgrade && s.route.H2 && !s.route.PlainHTTP {
		// HTTP/1 upgrades need a dedicated upstream that cannot negotiate h2.
		upstream = newMITMUpstream(ctx, upstream.route, s.metadata, s.host, s.route.SkipServerCertVerify, false, s.attempt)
		defer upstream.close()
	}

	if h2 && r.ProtoMajor == 1 {
		// The HTTP/2 transport can deliver response headers while it
		// is still reading the HTTP/1.1 client's upload.
		_ = http.NewResponseController(w).EnableFullDuplex()
	}
	ctx = observeMITMUpstreamProtocol(ctx, s.attempt)
	var uploadDone chan error
	if upgrade && request.Body != nil && request.Body != http.NoBody {
		// A 101 can arrive while the transport is still reading the upload.
		// Give the hijacked reader exclusive access to the client stream.
		uploadDone = make(chan error, 1)
		request.GetBody = nil
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			WroteRequest: func(info httptrace.WroteRequestInfo) { uploadDone <- info.Err },
		})
	}
	res, err := upstream.transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		localError(http.StatusBadGateway, "HTTP upstream request failed")
		return
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		tunnel, ok := res.Body.(io.ReadWriteCloser)
		protocol := httpUpgradeProtocol(res.Header)
		if !upgrade || !ok || protocol == "" || !strings.EqualFold(httpUpgradeProtocol(request.Header), protocol) {
			_ = res.Body.Close()
			localError(http.StatusBadGateway, "Unexpected HTTP upstream protocol upgrade")
			return
		}
		defer tunnel.Close()
		if uploadDone != nil {
			select {
			case err = <-uploadDone:
			case <-ctx.Done():
				err = ctx.Err()
			}
			if err != nil {
				panic(http.ErrAbortHandler)
			}
		}
		res.Body, res.ContentLength = nil, 0
		obs.response(res)
		buffered := hijack()
		if err = res.Write(buffered); err == nil {
			err = buffered.Flush()
		}
		if err == nil {
			s.attempt.setMITMPassthrough("upgrade")
			err = s.relayHTTPDuplex(r.Context(), hijacked, buffered.Reader, tunnel, upstream.close)
		}
		return
	}
	obs.response(res)
	defer res.Body.Close()
	responseBuffer, err := s.bufferBody(res.Body, res.ContentLength, needsResponseRewrite, responseScript)
	if err != nil {
		// A response whose body could not be read has not been sent.
		s.recordScriptInputError(&stats, responseScript, "response")
		obs.clearOriginStatus()
		localError(http.StatusBadGateway, "Could not read HTTP upstream response")
		return
	}
	defer responseBuffer.releaseBudget()
	responsePassthrough := needsResponseRewrite && responseBuffer.exceeds(s.route.MaxBodySize)
	rewriteBody := responseBuffer.data
	if responsePassthrough {
		rewriteBody = nil
	}
	rewrittenResponse := rewrite.Response(finalURL, httprewrite.Response{
		StatusCode: res.StatusCode, Header: res.Header, Body: rewriteBody,
	})
	stats.addMatches(rewrittenResponse.MatchedIDs)
	response := rewrittenResponse.Response
	if responsePassthrough {
		response.Body = responseBuffer.data
	}
	length := res.ContentLength
	if response.Body != nil {
		length = int64(len(response.Body))
	}
	responseBuffer.data = response.Body
	responseInput := mitmScriptInput{id: obs.summary.ID, request: request, response: &response, responseH2: res.ProtoMajor == 2, teTrailers: teTrailers}
	scriptOversize = s.runScript(r.Context(), responseScript, responseInput, responseBuffer, &stats, func(result script.Result) error {
		switch result.Action {
		case script.ActionModify:
			var applyErr error
			response, applyErr = applyMITMResponseScript(response, length, result)
			return applyErr
		case script.ActionAbort:
			abort = true
		}
		return nil
	})
	if scriptOversize || responsePassthrough {
		stats.passthroughs++
	}
	if abort {
		if r.ProtoMajor == 2 {
			panic(http.ErrAbortHandler)
		}
		hijack()
		return
	}
	if response.StatusCode != res.StatusCode {
		obs.clearOriginStatus()
		status = response.StatusCode
	}
	if response.Body != nil && responseScript.bodyLimit() > 0 {
		// A script that needed a body can turn chunked input into a fixed
		// length response, including when the original encoding is retained.
		response.Header.Set("Content-Length", strconv.Itoa(len(response.Body)))
	}
	hasBody := mitmResponseHasBody(r.Method, response.StatusCode)
	streaming := hasBody && response.Body == nil && responseBuffer.reader != http.NoBody
	var announced []string
	if h2 && hasBody {
		announced = announceMITMTrailers(w, res.Trailer)
		if r.ProtoMajor == 1 && (len(announced) != 0 || streaming && res.ProtoMajor == 2) {
			// A streaming HTTP/2 origin may send unannounced trailers
			// even with Content-Length. Give HTTP/1.1 a chunked body.
			response.Header.Del("Content-Length")
		}
		preserveMITMGRPCTrailersOnly(response.Header, res)
	}
	writeMITMHeaders(w, response.Header, response.StatusCode)
	if !hasBody {
		return
	}
	if response.Body != nil {
		if len(response.Body) != 0 {
			_, err = w.Write(response.Body)
		}
	} else if streaming {
		var writer io.Writer = w
		if res.ContentLength < 0 || h2 && (r.ProtoMajor == 2 || res.ProtoMajor == 2) {
			// Deliver each chunk of a streaming response as it arrives.
			flusher := http.NewResponseController(w)
			if err = flusher.Flush(); err != nil {
				panic(http.ErrAbortHandler)
			}
			writer = mitmStreamWriter{ResponseWriter: w, flusher: flusher}
		}
		err = copyHTTPStream(writer, responseBuffer.reader)
	}
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	if h2 {
		writeMITMTrailers(w, res.Trailer, announced)
	}
}

func (s *mitmHTTPHandler) waitForRequests() {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.requests.Wait()
}

func (s *mitmHTTPHandler) reroute(ctx context.Context, destination Destination, host string, h2 bool) (*mitmUpstream, error) {
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
	return newMITMUpstream(ctx, route, metadata, host, s.route.SkipServerCertVerify, h2, s.attempt), nil
}

func mitmRequestURL(r *http.Request, host string, port uint16, plainHTTP bool) *url.URL {
	// The HTTP authority may name a virtual host within the TCP destination.
	// It does not change where the original outbound dials or verifies TLS.
	scheme := "https"
	if plainHTTP {
		scheme = "http"
	}
	if authority, err := url.Parse(scheme + "://" + r.Host); err == nil &&
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
	u.Scheme, u.Host, u.Opaque, u.User = scheme, host, "", nil
	switch {
	case port != mitmDefaultPort(scheme):
		u.Host = net.JoinHostPort(host, itoa(port))
	case strings.Contains(host, ":"):
		u.Host = "[" + host + "]"
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return &u
}

func mitmUpstreamTarget(raw string, allowHTTP bool) (*url.URL, Destination, error) {
	invalid := errors.New("invalid HTTP rewrite target")
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" && !(allowHTTP && target.Scheme == "http") || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, Destination{}, invalid
	}
	host := target.Hostname()
	destination := Destination{Domain: host, Port: mitmURLPort(target)}
	if addr, err := netip.ParseAddr(host); err == nil {
		destination.Addr, destination.Domain = addr.Unmap(), ""
	} else if !M.IsDomainName(host) {
		return nil, Destination{}, invalid
	}
	if destination.Port == 0 {
		return nil, Destination{}, invalid
	}
	return target, destination, nil
}

func sameMITMOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && mitmURLPort(a) == mitmURLPort(b)
}

// Use the HTTP origin ports used by sing-box urltest and mihomo adapters.
func mitmDefaultPort(scheme string) uint16 {
	if scheme == "http" {
		return 80
	}
	return 443
}

func mitmURLPort(target *url.URL) uint16 {
	port := target.Port()
	if port == "" {
		return mitmDefaultPort(target.Scheme)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(number)
}

type mitmBufferedBody struct {
	data      []byte
	reader    io.ReadCloser
	truncated bool
	release   func()
}

func (b mitmBufferedBody) exceeds(limit int) bool {
	return b.truncated || len(b.data) > limit
}

func (b mitmBufferedBody) releaseBudget() {
	if b.release != nil {
		b.release()
	}
}

func (s *mitmHTTPHandler) bufferBody(body io.ReadCloser, length int64, needsRewrite bool, match *MITMScript) (mitmBufferedBody, error) {
	buffer := mitmBufferedBody{reader: body}
	limit := match.bodyLimit()
	if needsRewrite {
		limit = max(limit, s.route.MaxBodySize)
	}
	if body == nil || body == http.NoBody || !needsRewrite && limit == 0 {
		return buffer, nil
	}
	return mitmBufferBudget.buffer(body, length, int64(limit))
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

func announceMITMTrailers(w http.ResponseWriter, trailer http.Header) []string {
	var announced []string
	for name := range trailer {
		if validMITMTrailer(name) {
			announced = append(announced, name)
		}
	}
	if len(announced) != 0 {
		slices.Sort(announced)
		w.Header().Set("Trailer", strings.Join(announced, ", "))
	}
	return announced
}

func writeMITMTrailers(w http.ResponseWriter, trailer http.Header, announced []string) {
	for name, values := range trailer {
		if len(values) == 0 || !validMITMTrailer(name) {
			continue
		}
		if !slices.Contains(announced, name) {
			name = http.TrailerPrefix + name
		}
		w.Header()[name] = values
	}
}

func validMITMTrailer(name string) bool {
	return httpguts.ValidHeaderFieldName(name) && httpguts.ValidTrailerHeader(name) &&
		!strings.EqualFold(name, "Upgrade") && !strings.EqualFold(name, "HTTP2-Settings")
}

type mitmRequestTrailerBody struct {
	io.ReadCloser
	inbound, outbound http.Header
}

func (b mitmRequestTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		for name := range b.outbound {
			b.outbound[name] = b.inbound[name]
		}
	}
	return n, err
}

type mitmTrailerDrain struct{ body io.Reader }

func (d mitmTrailerDrain) Read([]byte) (int, error) {
	if _, err := io.Copy(io.Discard, d.body); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func preserveMITMGRPCTrailersOnly(header http.Header, res *http.Response) {
	if res.Body != http.NoBody || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/grpc") ||
		res.Header.Get("Grpc-Status") == "" {
		return
	}
	// Go exposes the trailers-only block in Header. Keep its status and
	// custom metadata even when a rule or script replaces the headers.
	for name, values := range res.Header {
		switch name {
		case "Content-Type", "Content-Length":
			continue
		}
		header[name] = values
	}
}

func mitmResponseHasBody(method string, status int) bool {
	return method != http.MethodHead && status != http.StatusNoContent && status != http.StatusNotModified
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
