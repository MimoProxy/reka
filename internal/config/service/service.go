// Package service is the ConfigService: the only writer of configuration.
// Files, the CLI, the control API and the Android binding all commit
// through it, and a commit is reported successful only after the runtime
// has switched and the new revision is durable as the active one.
//
// Commit steps (each persistence and switch point can be crash-tested
// through Options.FailPoint):
//
//  1. Check the base revision and the operation ID; build the candidate.
//  2. Compile (no side effects); reject on error diagnostics.
//  3. Prepare: build new instances, bind new listeners.
//  4. Write the immutable revision           ("revision-written")
//  5. Write the operation intent             ("intent-written")
//  6. Switch the runtime                     ("activated")
//  7. Write active.json                      ("active-written")
//  8. Mark the operation committed           ("op-committed")
//
// After a crash, Open restores the revision named by active.json: an
// operation whose intent names that revision is marked committed, any
// other pending operation failed, and revisions that never became active
// are removed.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

// Options configure a Service.
type Options struct {
	DeferNetwork     bool
	ProfileSecrets   func(string) (secret.Store, error)
	RuntimeStateRoot string
	StateRoot        string
	Secrets          secret.Store
	Engine           *generation.Engine
	Logger           *slog.Logger
	// InitialProfile and InitialLocal become revision 1 when the state
	// root is empty. Without them revision 1 is an empty profile.
	InitialProfile []byte
	InitialLocal   []byte
	InitialSources []byte
	InitialOverlay []byte
	// FailPoint, for tests, is called at each persistence and switch
	// point; a non-nil error aborts the commit on the spot, as a crash
	// would, leaving disk and runtime as they are.
	FailPoint func(point string) error
}

// DefaultProfile is revision 1 of an empty state root.
const DefaultProfile = "schema-version: 1\n"

// Error codes in results.
const (
	CodeConflict    = "conflict"
	CodeInvalid     = "invalid"
	CodePrepare     = "prepare_failed"
	CodeBlocked     = "blocked"
	CodeActivate    = "activate_failed"
	CodeOpReused    = "operation_reused"
	CodePlanChanged = "plan_changed"
	CodeBadRequest  = "bad_request"
	CodeNotFound    = "not_found"
)

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Service is the ConfigService.
type Service struct {
	profileArchives map[string]map[string]bool
	profiles        *ProfileWorkspace
	uploadMu        sync.Mutex
	uploads         map[string]*resourceUpload
	refreshMu       sync.Mutex
	refresh         *RefreshManager
	closed          bool
	opts            Options
	store           *store.Store
	engine          *generation.Engine
	events          *Broker
	log             *slog.Logger
	// Tests can inject an error after active.json has been written.
	writeActive func(*store.Store, store.Active) error

	mu       sync.Mutex
	active   uint64
	profile  []byte
	local    []byte
	sources  []byte
	overlay  []byte
	eff      *compile.Effective
	warnings model.Diagnostics
	// startErr is set when the active revision could not be started.
	startErr error
}

// ErrCrashed is returned by a commit aborted through FailPoint.
var ErrCrashed = errors.New("service: aborted at fail point")

// Open recovers the state root and starts the active revision.
func Open(opts Options) (*Service, error) {
	st, err := store.Open(opts.StateRoot)
	if err != nil {
		return nil, err
	}
	s := &Service{opts: opts, store: st, writeActive: (*store.Store).WriteActive, engine: opts.Engine, events: NewBroker(), log: opts.Logger}
	if opts.Engine == nil {
		return nil, fmt.Errorf("runtime engine required")
	}
	runtimeRoot := opts.RuntimeStateRoot
	if runtimeRoot == "" {
		runtimeRoot = opts.StateRoot
	}
	if err := s.engine.DNSState(filepath.Join(runtimeRoot, "cache", "fake-ip.json")); err != nil {
		return nil, fmt.Errorf("restore fake-IP state: %w", err)
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if err := s.recover(); err != nil {
		return nil, fmt.Errorf("recover state root: %w", err)
	}
	a, err := st.ReadActive()
	if err != nil {
		return nil, err
	}
	if a == nil {
		profile, local := opts.InitialProfile, opts.InitialLocal
		if opts.DeferNetwork {
			var err error
			local, _, err = networkOffDocument(local)
			if err != nil {
				return nil, err
			}
		}
		if profile == nil {
			profile = []byte(DefaultProfile)
		}
		p, l := string(profile), string(local)
		ss, oo := string(opts.InitialSources), string(opts.InitialOverlay)
		res, err := s.Commit(context.Background(), CommitRequest{
			ChangeRequest: ChangeRequest{Profile: &p, Local: &l, Sources: &ss, Overlay: &oo},
			OperationID:   "initial", Source: "initial",
		})
		if err != nil {
			return nil, err
		}
		if res.State != store.OpCommitted {
			if !onlySecretErrors(res) {
				return nil, fmt.Errorf("initial configuration: %s", describe(res))
			}
			// The documents are valid but reference secrets that cannot be
			// stored before the kernel runs. Keep them as revision 1 without
			// starting them; storing the secrets re-applies them.
			if err := s.storeUnstarted(profile, local, opts.InitialSources, opts.InitialOverlay, res.Diagnostics); err != nil {
				return nil, err
			}
			s.log.Warn("the initial configuration needs secrets before it can start", "missing", res.Diagnostics.Errors().Error())
		}
		return s, nil
	}
	if err := s.startActive(a); err != nil {
		if opts.DeferNetwork {
			// A loaded, already-off document is safe to expose for repair even
			// when its profile cannot compile (for example a missing secret).
			// Never turn a failed standby conversion or unreadable local state
			// into a control-only success: its takeover intent is unconfirmed.
			_, changed, localErr := networkOffDocument(s.local)
			if s.active == 0 || s.active != a.Revision || localErr != nil || changed {
				return nil, fmt.Errorf("defer network takeover: %w", err)
			}
		}
		s.startErr = err
		s.log.Error("active configuration did not start; fix it with a new commit", "revision", a.Revision, "err", err)
	}
	return s, nil
}

func describe(r Result) string {
	if r.Error != nil {
		msg := r.Error.Message
		if len(r.Diagnostics) > 0 {
			msg += "\n" + r.Diagnostics.Errors().Error()
		}
		return msg
	}
	return r.State
}

// onlySecretErrors reports whether a rejection is only about secrets that
// are not stored (or a store that cannot be read).
func onlySecretErrors(res Result) bool {
	if res.Error == nil || res.Error.Code != CodeInvalid {
		return false
	}
	errs := res.Diagnostics.Errors()
	for _, d := range errs {
		if !strings.HasPrefix(d.Code, "secret.") {
			return false
		}
	}
	return len(errs) > 0
}

// storeUnstarted records the initial documents as revision 1 without
// running them, for an empty state root whose import needs secrets.
func (s *Service) storeUnstarted(profile, local, sources, overlay []byte, diags model.Diagnostics) error {
	now := time.Now().UTC()
	if _, err := s.store.WriteRevision(store.Revision{Number: 1, Operation: "initial", Source: "initial", Created: now,
		Message: "imported; waiting for secrets"}, profile, local, sources, overlay); err != nil {
		return err
	}
	res := Result{OperationID: "initial", State: store.OpCommitted, Revision: 1, Diagnostics: diags}
	b, _ := json.Marshal(res)
	if err := s.store.WriteOperation(store.Operation{ID: "initial", State: store.OpCommitted, Revision: 1,
		RequestHash: "initial", Created: now, Updated: now, Result: b}); err != nil {
		return err
	}
	if err := s.store.WriteActive(store.Active{Revision: 1, Profile: store.Hash(profile), Local: store.Hash(local),
		Sources: store.Hash(sources), Overlay: store.Hash(overlay), Operation: "initial", Updated: now}); err != nil {
		return err
	}
	s.mu.Lock()
	s.active, s.profile, s.local, s.warnings = 1, profile, local, diags
	s.sources, s.overlay = sources, overlay

	s.startErr = diags.Errors()
	s.mu.Unlock()
	return nil
}

// recover settles operations left pending by a crash.
func (s *Service) recover() error {
	a, err := s.store.ReadActive()
	if err != nil {
		return err
	}
	var active uint64
	if a != nil {
		active = a.Revision
	}
	ops, err := s.store.ListOperations()
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.State != store.OpPending {
			continue
		}
		var res Result
		_ = json.Unmarshal(op.Result, &res)
		if op.Revision != 0 && op.Revision == active {
			op.State = store.OpCommitted
			res.State = store.OpCommitted
			res.Revision = active
		} else {
			op.State = store.OpFailed
			res.State = store.OpFailed
			res.Error = errf(CodeActivate, "the process stopped before the commit completed; revision %d stays active", active)
			res.Revision = 0
		}
		res.OperationID = op.ID
		op.Result, _ = json.Marshal(res)
		op.Updated = time.Now().UTC()
		if err := s.store.WriteOperation(op); err != nil {
			return err
		}
	}
	revs, err := s.store.RevisionNumbers()
	if err != nil {
		return err
	}
	for _, n := range revs {
		if n > active {
			if err := s.store.DeleteRevision(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) compileOpts(sources, overlay []byte) compile.Options {
	return compile.Options{
		ReadResource:  resource.At(s.store.Root()).Read,
		Secrets:       s.opts.Secrets,
		ProcessLookup: s.engine.ProcessLookup(),
		Sources:       sources,
		Overlay:       overlay,
	}
}

func (s *Service) startActive(a *store.Active) error {
	_, profile, local, err := s.store.ReadRevision(a.Revision)
	if err != nil {
		return err
	}
	sources, overlay, err := s.store.ReadLayers(a.Revision)
	if err != nil {
		return err
	}
	s.active, s.profile, s.local = a.Revision, profile, local
	s.sources, s.overlay = sources, overlay
	if s.opts.DeferNetwork {
		off, changed, err := networkOffDocument(local)
		if err != nil {
			return err
		}
		if changed {
			text := string(off)
			result, err := s.Commit(context.Background(), CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: a.Revision, Local: &text}, OperationID: newOperationID(), Source: "defer-network", Message: "start in standby before client handoff"})
			if err != nil {
				return err
			}
			if result.State != store.OpCommitted {
				return fmt.Errorf("standby transaction: %s", describe(result))
			}
			return nil
		}
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts(sources, overlay))
	s.warnings = diags
	if eff == nil {
		return diags.Errors()
	}
	p, err := s.engine.Prepare(eff)
	if err != nil {
		return err
	}
	if _, err := s.engine.Activate(p, a.Revision); err != nil {
		return err
	}
	s.eff = eff
	return nil
}

// Events is the service's event broker.
func (s *Service) Events() *Broker { return s.events }

// Engine is the runtime the service drives.
func (s *Service) Engine() *generation.Engine { return s.engine }

// ActiveRevision is the confirmed active revision.
func (s *Service) ActiveRevision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func requestHash(req CommitRequest, restoredFrom uint64) string {
	b, _ := json.Marshal(struct {
		ChangeRequest
		Restored uint64
		Plan     string
	}{req.ChangeRequest, restoredFrom, req.PlanHash})
	return store.Hash(b)
}

func newOperationID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "op-" + hex.EncodeToString(b)
}

// candidate builds the documents a change request describes, against the
// active documents. Called with s.mu held.
func (s *Service) candidate(req ChangeRequest) (profile, local, sources, overlay []byte, err error) {
	build := func(name string, active []byte, whole *string, patch []model.Op) ([]byte, error) {
		base := active
		if whole != nil {
			base = []byte(*whole)
		}
		masked := containsMask(base)
		if len(patch) == 0 && !masked {
			return base, nil
		}
		doc, diags := model.LoadDoc(name, base)
		if diags.HasErrors() {
			// Let compilation report the syntax error with positions.
			if len(patch) == 0 {
				return base, nil
			}
			return nil, errf(CodeInvalid, "%s: %v", name, diags.Error())
		}
		if err := doc.Apply(patch...); err != nil {
			return nil, errf(CodeBadRequest, "%s patch: %v", name, err)
		}
		{
			activeDoc, _ := model.LoadDoc(name, active)
			if err := doc.UnmaskSecrets(activeDoc); err != nil {
				return nil, errf(CodeBadRequest, "%v", err)
			}
		}
		return doc.Bytes(), nil
	}
	if profile, err = build(model.DocProfile, s.profile, req.Profile, req.Patch); err != nil {
		return nil, nil, nil, nil, err
	}
	if local, err = build(model.DocLocal, s.local, req.Local, req.LocalPatch); err != nil {
		return nil, nil, nil, nil, err
	}
	if sources, err = build(model.DocSources, s.sources, req.Sources, req.SourcesPatch); err != nil {
		return nil, nil, nil, nil, err
	}
	if overlay, err = build(model.DocOverlay, s.overlay, req.Overlay, req.OverlayPatch); err != nil {
		return nil, nil, nil, nil, err
	}
	if req.Import != nil {
		if sources, err = s.mergeImport(sources, req.Import); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if err := s.store.ValidateResources(sources); err != nil {
		return nil, nil, nil, nil, errf(CodeInvalid, "%s", err)
	}
	return profile, local, sources, overlay, nil
}

func containsMask(b []byte) bool { return bytes.Contains(b, []byte(model.Mask)) }

// conflict computes the field differences between the client's base and
// the active revision. Called with s.mu held.
func (s *Service) conflict(base uint64) *Conflict {
	c := &Conflict{Base: base, Active: s.active}
	_, bp, bl, err := s.store.ReadRevision(base)
	if err != nil {
		return c
	}
	c.Changes = append(diffDocs(model.DocProfile, "", bp, s.profile), diffDocs(model.DocLocal, "/local", bl, s.local)...)
	bs, bo, err := s.store.ReadLayers(base)
	if err == nil {
		c.Changes = append(c.Changes, diffDocs(model.DocSources, "/sources", bs, s.sources)...)
		c.Changes = append(c.Changes, diffDocs(model.DocOverlay, "/overlay", bo, s.overlay)...)
	}
	return c
}

func diffDocs(name, prefix string, a, b []byte) []FieldChange {
	flat := func(data []byte) map[string]any {
		doc, diags := model.LoadDoc(name, data)
		if diags.HasErrors() {
			return map[string]any{}
		}
		doc.MaskSecrets()
		return model.Flatten(doc.Mapping())
	}
	fa, fb := flat(a), flat(b)
	var out []FieldChange
	for p, va := range fa {
		vb, ok := fb[p]
		if !ok {
			out = append(out, FieldChange{Path: prefix + p, From: va})
		} else if !reflect.DeepEqual(va, vb) {
			out = append(out, FieldChange{Path: prefix + p, From: va, To: vb})
		}
	}
	for p, vb := range fb {
		if _, ok := fa[p]; !ok {
			out = append(out, FieldChange{Path: prefix + p, To: vb})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// PlanHash binds a plan to its base revision and candidate content.
func PlanHash(base uint64, profile, local []byte, layers ...[]byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s", base, store.Hash(profile), store.Hash(local))
	for _, layer := range layers {
		fmt.Fprintf(h, "\x00%s", store.Hash(layer))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Validate compiles a candidate without any side effect.
func (s *Service) Validate(req ChangeRequest) (ValidateResult, error) {
	s.mu.Lock()
	profile, local, sources, overlay, err := s.candidate(req)
	s.mu.Unlock()
	if err != nil {
		var failure *importFailure
		if errors.As(err, &failure) {
			return ValidateResult{Diagnostics: failure.diagnostics()}, nil
		}
		return ValidateResult{}, err
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts(sources, overlay))
	return ValidateResult{Valid: eff != nil, Diagnostics: diags}, nil
}

// Plan compiles a candidate and reports what committing it would change.
func (s *Service) Plan(req ChangeRequest) (PlanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.BaseRevision != s.active {
		return PlanResult{Base: req.BaseRevision, Conflict: s.conflict(req.BaseRevision)}, nil
	}
	profile, local, sources, overlay, err := s.candidate(req)
	if err != nil {
		var failure *importFailure
		if errors.As(err, &failure) {
			return PlanResult{Base: s.active, Diagnostics: failure.diagnostics()}, nil
		}
		return PlanResult{}, err
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts(sources, overlay))
	res := PlanResult{Base: s.active, Diagnostics: diags, Valid: eff != nil}
	if eff == nil {
		return res, nil
	}
	plan := s.engine.Plan(eff)
	res.Plan = &plan
	res.PlanHash = PlanHash(s.active, profile, local, sources, overlay)
	return res, nil
}

func (s *Service) fail(point string) error {
	if s.opts.FailPoint == nil {
		return nil
	}
	if err := s.opts.FailPoint(point); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCrashed, point, err)
	}
	return nil
}

// Commit validates, prepares and activates a change. The returned error is
// for failures of the service itself (disk errors, an aborted fail point);
// a rejected change is a Result with State "rejected".
func (s *Service) Commit(ctx context.Context, req CommitRequest) (Result, error) {
	return s.commit(ctx, req, 0)
}

// commit is Commit; restoredFrom names the revision a restore copies, or 0.
func (s *Service) commit(ctx context.Context, req CommitRequest, restoredFrom uint64) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.OperationID == "" {
		req.OperationID = newOperationID()
	}
	if err := store.ValidOperationID(req.OperationID); err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	if req.Source == "" {
		req.Source = "api"
	}
	hash := requestHash(req, restoredFrom)
	if op, ok, err := s.store.ReadOperation(req.OperationID); err != nil {
		return Result{}, err
	} else if ok {
		if op.RequestHash != hash {
			return Result{}, errf(CodeOpReused, "operation %s was already used for a different change", req.OperationID)
		}
		var res Result
		if err := json.Unmarshal(op.Result, &res); err != nil {
			return Result{}, err
		}
		return res, nil
	}
	now := time.Now().UTC()
	op := store.Operation{ID: req.OperationID, RequestHash: hash, Base: req.BaseRevision, Created: now, Updated: now}
	res := Result{OperationID: req.OperationID}
	reject := func(e *Error) (Result, error) {
		res.State, res.Error = store.OpRejected, e
		op.State = store.OpRejected
		op.Result, _ = json.Marshal(res)
		if err := s.store.WriteOperation(op); err != nil {
			return Result{}, err
		}
		s.events.Publish(EventRejected, res)
		return res, nil
	}

	initial := s.active == 0 && req.OperationID == "initial"
	if !initial && req.BaseRevision != s.active {
		res.Conflict = s.conflict(req.BaseRevision)
		return reject(errf(CodeConflict, "revision %d is active, not %d", s.active, req.BaseRevision))
	}
	profile, local, sources, overlay, err := s.candidate(req.ChangeRequest)
	if err != nil {
		var failure *importFailure
		if errors.As(err, &failure) {
			res.Diagnostics = failure.diagnostics()
			return reject(errf(CodeInvalid, "%s", failure.Error()))
		}
		var e *Error
		if errors.As(err, &e) {
			return reject(e)
		}
		return Result{}, err
	}
	if req.PlanHash != "" && req.PlanHash != PlanHash(s.active, profile, local, sources, overlay) {
		return reject(errf(CodePlanChanged, "the candidate differs from the one that was planned"))
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts(sources, overlay))
	res.Diagnostics = diags
	if eff == nil {
		return reject(errf(CodeInvalid, "the configuration has %d errors", len(diags.Errors())))
	}
	unchanged := bytes.Equal(profile, s.profile) && bytes.Equal(local, s.local) &&
		bytes.Equal(sources, s.sources) && bytes.Equal(overlay, s.overlay) && sameInstances(s.eff, eff)
	if !initial && s.startErr == nil && unchanged {
		res.State, res.Revision, res.NoChange = store.OpCommitted, s.active, true
		op.State, op.Revision = store.OpCommitted, s.active
		op.Result, _ = json.Marshal(res)
		return res, s.store.WriteOperation(op)
	}
	before, err := s.store.ReadActive()
	if err != nil {
		return Result{}, err
	}
	prepared, err := s.engine.Prepare(eff)
	if err != nil {
		code := CodePrepare
		if errors.Is(err, generation.ErrBlocked) {
			code = CodeBlocked
		}
		var pe *generation.PrepareError
		if errors.As(err, &pe) {
			res.Diagnostics = append(res.Diagnostics, model.Diagnostic{Severity: model.SeverityError, Code: code, Path: pe.Path, Message: pe.Err.Error()})
		}
		return reject(errf(code, "%v", err))
	}
	plan := prepared.Plan()
	res.Plan = &plan

	number, err := s.nextRevision()
	if err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	rev := store.Revision{Number: number, Base: s.active, Operation: req.OperationID, Source: req.Source,
		Message: req.Message, Created: now, RestoredFrom: restoredFrom}
	if _, err := s.store.WriteRevision(rev, profile, local, sources, overlay); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	if err := s.fail("revision-written"); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	op.State, op.Revision = store.OpPending, number
	res.State, res.Revision = store.OpPending, number
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		s.engine.Abort(prepared)
		s.store.DeleteRevision(number)
		return Result{}, err
	}
	// The revision and the intent must be durable before the switch, so a
	// crash after it can always be recovered.
	if err := s.store.Barrier(); err != nil {
		s.engine.Abort(prepared)
		s.store.DeleteRevision(number)
		return Result{}, err
	}
	if err := s.fail("intent-written"); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}

	gen, actErr := s.engine.Activate(prepared, number)
	if actErr != nil {
		return s.rollback(op, res, actErr, true)
	}
	if err := s.fail("activated"); err != nil {
		return Result{}, err
	}
	if err := s.writeActive(s.store, store.Active{Revision: number, Profile: store.Hash(profile), Local: store.Hash(local),
		Sources: store.Hash(sources), Overlay: store.Hash(overlay), Operation: req.OperationID, Updated: time.Now().UTC()}); err != nil {
		// The rename may already have succeeded. Restore the previous record
		// before removing the revision it could now point to.
		var restoreErr error
		if before == nil {
			restoreErr = s.store.DeleteActive()
		} else {
			restoreErr = s.writeActive(s.store, *before)
		}
		if restoreErr != nil {
			res.Degraded = true
			s.log.Error("restore active revision record", "revision", s.active, "err", restoreErr)
		}
		return s.rollback(op, res, err, restoreErr == nil)
	}
	if err := s.fail("active-written"); err != nil {
		return Result{}, err
	}
	s.active, s.profile, s.local, s.eff, s.warnings, s.startErr = number, profile, local, eff, diags, nil
	s.sources, s.overlay = sources, overlay
	res.State, res.Generation = store.OpCommitted, gen
	op.State = store.OpCommitted
	op.Updated = time.Now().UTC()
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		// active.json is written, so recovery will mark it committed.
		s.log.Error("record committed operation", "operation", op.ID, "err", err)
	}
	if err := s.fail("op-committed"); err != nil {
		return Result{}, err
	}
	s.events.Publish(EventCommitted, map[string]any{"revision": number, "operation": op.ID, "source": req.Source, "generation": gen, "plan": plan})
	s.events.Publish(EventRuntime, map[string]any{"generation": gen, "revision": number})
	return res, nil
}

// rollback returns to the previous runtime after the switch or its recording
// failed. Discard the failed revision only once the active record is safe.
// Called with s.mu held.
func (s *Service) rollback(op store.Operation, res Result, cause error, discard bool) (Result, error) {
	res.State, res.Revision = store.OpFailed, 0
	res.Error = errf(CodeActivate, "%v", cause)
	var ae *generation.ActivateError
	if errors.As(cause, &ae) && ae.Degraded {
		res.Degraded = true
	}
	_, scope := s.engine.History()
	if err := s.restoreRuntime(scope.ProfileID); err != nil {
		res.Degraded = true
		s.log.Error("roll back to the previous revision", "revision", s.active, "err", err)
	}
	op.State = store.OpFailed
	op.Updated = time.Now().UTC()
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		return res, err
	}
	if discard {
		if err := s.store.DeleteRevision(op.Revision); err != nil {
			s.log.Error("remove failed revision", "revision", op.Revision, "err", err)
		}
	}
	s.events.Publish(EventRejected, res)
	return res, nil
}

// restoreRuntime reinstates the confirmed runtime, including an idle repair
// state. It is called with s.mu held.
func (s *Service) restoreRuntime(profileID string) error {
	if s.eff == nil {
		return s.engine.DeactivateProfile(profileID)
	}
	previous, err := s.engine.Prepare(s.eff)
	if err != nil {
		return err
	}
	_, err = s.engine.ActivateProfile(previous, s.active, profileID)
	return err
}

func (s *Service) nextRevision() (uint64, error) {
	max := s.active
	revs, err := s.store.RevisionNumbers()
	if err != nil {
		return 0, err
	}
	for _, n := range revs {
		if n > max {
			max = n
		}
	}
	ops, err := s.store.ListOperations()
	if err != nil {
		return 0, err
	}
	for _, op := range ops {
		if op.Revision > max {
			max = op.Revision
		}
	}
	return max + 1, nil
}

// GetOperation returns the recorded result of an operation.
func (s *Service) GetOperation(id string) (Result, error) {
	op, ok, err := s.store.ReadOperation(id)
	if err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	if !ok {
		return Result{}, errf(CodeNotFound, "no operation %s", id)
	}
	var res Result
	if err := json.Unmarshal(op.Result, &res); err != nil {
		return Result{}, err
	}
	return res, nil
}

// GetConfiguration returns the active documents (inline credentials
// masked unless reveal), the effective configuration with field origins,
// and its warnings.
func (s *Service) GetConfiguration(reveal bool) Configuration {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Configuration{
		Revision:    s.active,
		Profile:     string(s.profile),
		Local:       string(s.local),
		Sources:     string(s.sources),
		Overlay:     string(s.overlay),
		Effective:   s.eff,
		Diagnostics: s.warnings,
	}
	if s.profiles != nil {
		c.ProfileID = s.profiles.cursor.ProfileID
		c.ProfileEpoch = s.profiles.cursor.Epoch
	}
	if s.startErr != nil {
		c.StartError = s.startErr.Error()
	}
	if !reveal {
		for _, item := range []struct {
			name string
			data []byte
			dest *string
		}{
			{model.DocProfile, s.profile, &c.Profile}, {model.DocLocal, s.local, &c.Local}, {model.DocSources, s.sources, &c.Sources}, {model.DocOverlay, s.overlay, &c.Overlay},
		} {
			if doc, diags := model.LoadDoc(item.name, item.data); !diags.HasErrors() {
				if n := doc.MaskSecrets(); n > 0 {
					*item.dest = string(doc.Bytes())
					c.Masked += n
				}
			}
		}
	}
	return c
}

// Documents returns the active documents unmasked, for the candidate
// files.
func (s *Service) Documents() (revision uint64, profile, local []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.profile, s.local
}

// LayerDocuments returns a consistent copy of all four active documents.
func (s *Service) LayerDocuments() (revision uint64, profile, local, sources, overlay []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, bytes.Clone(s.profile), bytes.Clone(s.local), bytes.Clone(s.sources), bytes.Clone(s.overlay)
}

// ListRevisions lists stored revisions, newest first.
func (s *Service) ListRevisions() ([]store.Revision, error) { return s.store.ListRevisions() }

// RestoreRevision commits the content of an older revision as a new
// revision.
func (s *Service) RestoreRevision(ctx context.Context, req RestoreRequest) (Result, error) {
	_, profile, local, err := s.store.ReadRevision(req.Revision)
	if err != nil {
		return Result{}, errf(CodeNotFound, "revision %d: %v", req.Revision, err)
	}
	sources, overlay, err := s.store.ReadLayers(req.Revision)
	if err != nil {
		return Result{}, errf(CodeNotFound, "revision %d: %v", req.Revision, err)
	}
	p, l, ss, oo := string(profile), string(local), string(sources), string(overlay)
	return s.commit(ctx, CommitRequest{
		ChangeRequest: ChangeRequest{BaseRevision: req.BaseRevision, Profile: &p, Local: &l, Sources: &ss, Overlay: &oo},
		OperationID:   req.OperationID, Source: "restore",
		Message: fmt.Sprintf("restore revision %d", req.Revision),
	}, req.Revision)
}

// Close stops the runtime.
func (s *Service) Close() {
	if s.profiles != nil {
		s.profiles.gate.Lock()
		defer s.profiles.gate.Unlock()
	}
	s.refreshMu.Lock()
	s.closed = true
	m := s.refresh
	s.refreshMu.Unlock()
	if m != nil {
		m.Close()
	}
	s.engine.Close()
	if s.profiles != nil {
		s.profiles.Close()
	}
}

// sameInstances reports whether two compilations of the same documents
// produce the same instances; they differ when a referenced secret
// changed.
func sameInstances(a, b *compile.Effective) bool {
	if a == nil || len(a.Outbounds) != len(b.Outbounds) {
		return false
	}
	for i := range a.Outbounds {
		if a.Outbounds[i].Fingerprint != b.Outbounds[i].Fingerprint {
			return false
		}
	}
	return true
}

// Secrets is the service's secret store.
func (s *Service) Secrets() secret.Store { return s.opts.Secrets }

// Reapply recompiles the active documents, for example after a secret
// they reference changed, and activates the result if any instance
// changed.
func (s *Service) Reapply(ctx context.Context, source string) (Result, error) {
	s.mu.Lock()
	base := s.active
	s.mu.Unlock()
	return s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: base}, Source: source, Message: "re-resolve secrets"})
}

// StartError reports why the active revision is not running, if it is
// not.
func (s *Service) StartError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.startErr == nil {
		return ""
	}
	return s.startErr.Error()
}
