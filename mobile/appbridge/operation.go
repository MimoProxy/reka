// Package appbridge implements the main app's local JSON operations.
//
// Each request is a JSON object with an action and the corresponding fields.
// Success returns the result object directly. Failures return an error object
// with code, message, and optional diagnostics.
//
//   - mitmCAGenerate takes optional replace and returns api.MITMCAStatus.
//   - mitmCAImport takes pkcs12 (standard base64), password, and optional
//     replace. It returns api.MITMCAStatus.
//   - mitmCAStatus takes no fields and returns api.MITMCAStatus, or
//     {"installed":false} if the CA has not been installed.
//   - mitmCAExport takes optional format (pem by default, or der) and returns
//     format, data, and fingerprint_sha256. DER data is standard base64.
//   - mitmCADelete takes no fields and returns {"deleted":true}.
//   - mitmCATrustProbe takes no fields and returns hostname, leafDER, and caDER.
//     Both certificates are standard base64. The app can evaluate them with
//     the system SSL policy for hostname.
//   - moduleAcquire takes profile.ModuleAcquireRequest fields and returns
//     profile.ModuleAcquireResult. A failed acquisition has status=failed
//     and an errorCode.
//   - moduleInspect takes text, file, or snapshot, with optional arguments,
//     and returns module.Metadata.
//   - modulePreview takes the same fields as moduleInspect, plus optional
//     profileSnapshot, and returns report and hostnames.
//   - moduleReport takes snapshot (a prepared profile) and moduleId and
//     returns module.Report.
package appbridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/mitm/caops"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
	"github.com/MimoProxy/reka/mobile/profile"
)

// MaxInputBytes matches the prepare options limit. Larger module text must be
// passed by file or snapshot path.
const MaxInputBytes = 256 << 10

// Match foreground RekaGoPrepareProfile. One acquisition can fetch a module
// and several Map Local resources under the same deadline.
const operationTimeout = 75 * time.Second

// Match sing-box common/tls.GenerateKeyPair's one-hour leaf expiration.
const trustProbeValidity = time.Hour
const trustProbeHostname = "reka-trust-check.invalid"

// Bridge serializes operations on one host store and holds one response for a
// caller that needs to grow its buffer.
type Bridge struct {
	store   secret.Store
	mu      sync.Mutex
	running chan struct{}
	pending [sha256.Size]byte
	reply   []byte
}

func New(store secret.Store) *Bridge {
	return &Bridge{store: store, running: make(chan struct{}, 1)}
}

type request struct {
	Action string `json:"action"`
	Format string `json:"format,omitempty"` // Shared by CA export and module inspection or preview.
	api.ImportMITMCARequest
	profile.ModuleAcquireRequest
	profile.ModulePreviewRequest
	ModuleID string `json:"moduleId"`
}

type operationError struct {
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}

type errorResponse struct {
	Error operationError `json:"error"`
}

type trustProbe struct {
	Hostname string `json:"hostname"`
	LeafDER  []byte `json:"leafDER"`
	CADER    []byte `json:"caDER"`
}

// WriteResponse accepts a JSON request and writes its JSON result. If the
// output is short it returns the negative required length. Immediately retry
// with the exact same request bytes to copy the cached result without running
// the operation again. Serialize each request and its retries. A different
// request discards an outstanding result.
func (b *Bridge) WriteResponse(input, output []byte) int32 {
	if len(input) > MaxInputBytes {
		input = nil
	}
	key := sha256.Sum256(input)
	b.mu.Lock()
	defer b.mu.Unlock()
	response := b.reply
	if response == nil || key != b.pending {
		response = b.execute(input)
	}
	if len(response) > len(output) {
		b.pending, b.reply = key, response
		return -int32(len(response))
	}
	b.reply = nil
	return int32(copy(output, response))
}

func (b *Bridge) execute(input []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var req request
	if len(input) == 0 || json.Unmarshal(input, &req) != nil || req.Action == "" {
		return jsonError("bad_request", "expected an app operation JSON object of at most 256 KiB with an action")
	}
	select {
	case b.running <- struct{}{}:
	default:
		return jsonError("busy", "the previous app operation is still finishing")
	}
	// Some local libraries, including the PKCS#12 parser, do not accept a
	// context. The worker retains only decoded Go data, and no new operation
	// starts until it exits. Mutations check the context before committing.
	done := make(chan []byte, 1)
	go func() {
		response := b.respond(ctx, req)
		<-b.running
		done <- response
	}()
	select {
	case response := <-done:
		return response
	case <-ctx.Done():
		select {
		case response := <-done:
			return response
		default:
		}
		return jsonError("timeout", "app operation timed out")
	}
}

func (b *Bridge) respond(ctx context.Context, req request) (data []byte) {
	defer func() {
		if recover() != nil {
			data = jsonError(api.CodeInternal, "app operation failed")
		}
	}()
	result, err := b.dispatch(ctx, req)
	if err != nil {
		result = errorResponse{Error: publicError(err)}
	}
	data, err = json.Marshal(result)
	if err != nil || len(data) > math.MaxInt32 {
		return jsonError(api.CodeInternal, "cannot encode app operation result")
	}
	return data
}

func (b *Bridge) dispatch(ctx context.Context, req request) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch req.Action {
	case "moduleAcquire":
		return profile.AcquireModule(ctx, req.ModuleAcquireRequest, profile.ModuleAcquireOptions{Secrets: b.store}), nil
	case "moduleInspect":
		req.ModuleInput.Format = req.Format
		return profile.InspectModule(ctx, req.ModuleInput)
	case "modulePreview":
		req.ModuleInput.Format = req.Format
		return profile.PreviewModule(ctx, req.ModulePreviewRequest, b.store)
	case "moduleReport":
		return profile.ModuleReport(ctx, req.Snapshot, req.ModuleID, b.store)
	case "mitmCAGenerate", "mitmCAImport", "mitmCAStatus", "mitmCAExport", "mitmCADelete", "mitmCATrustProbe":
		return b.caOperation(ctx, req)
	default:
		return nil, &api.Error{Code: api.CodeUnknownMethod, Message: "unknown app operation"}
	}
}

func (b *Bridge) caOperation(ctx context.Context, req request) (any, error) {
	if b.store == nil {
		return nil, &api.Error{Code: api.CodeInternal, Message: "no secret store"}
	}
	switch req.Action {
	case "mitmCAGenerate":
		return caops.Generate(ctx, b.store, req.Replace)
	case "mitmCAImport":
		return caops.Import(ctx, b.store, req.ImportMITMCARequest)
	case "mitmCAStatus":
		return caops.Status(b.store)
	case "mitmCAExport":
		return caops.Export(b.store, req.Format)
	case "mitmCADelete":
		return caops.Delete(b.store)
	default: // mitmCATrustProbe
		a, err := caops.LoadInstalled(b.store)
		if err != nil {
			return nil, err
		}
		leaf, err := a.Issue(trustProbeHostname, time.Now().Add(trustProbeValidity))
		if err != nil {
			return nil, &api.Error{Code: api.CodeInternal, Message: err.Error()}
		}
		return trustProbe{Hostname: trustProbeHostname, LeafDER: leaf.Certificate[0], CADER: leaf.Certificate[1]}, nil
	}
}

func jsonError(code, message string) []byte {
	data, _ := json.Marshal(errorResponse{Error: operationError{Code: code, Message: message}})
	return data
}

func publicError(err error) operationError {
	var (
		apiErr     *api.Error
		validation *profile.ValidationError
		fetchErr   *subscription.Error
	)
	switch {
	case errors.As(err, &apiErr):
		return operationError{Code: apiErr.Code, Message: apiErr.Message}
	case errors.As(err, &validation):
		return operationError{Code: "invalid", Message: validation.Message, Diagnostics: validation.Diagnostics}
	case errors.Is(err, profile.ErrModuleReportNotFound):
		return operationError{Code: "not_found", Message: err.Error()}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return operationError{Code: "timeout", Message: "app operation timed out"}
	case errors.As(err, &fetchErr):
		return operationError{Code: fetchErr.Code, Message: fetchErr.Error()}
	default:
		return operationError{Code: "bad_request", Message: err.Error()}
	}
}
