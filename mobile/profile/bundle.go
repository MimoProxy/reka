// Package profile prepares and loads the configuration shared with the iOS
// Packet Tunnel. Subscription downloads and geodata filtering happen in the
// app. The packet tunnel only reads the resulting snapshot.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/secret"
)

const bundleVersion = 1
const MaxBundleBytes = 4 << 20

var errBundleTooLarge = errors.New("prepared rules and resources exceed the 4 MiB extension configuration budget")

type Bundle struct {
	Version             int                  `json:"version"`
	Profile             json.RawMessage      `json:"profile"`
	Local               json.RawMessage      `json:"local,omitempty"`
	Sources             json.RawMessage      `json:"sources,omitempty"`
	Overlay             json.RawMessage      `json:"overlay,omitempty"` // Only patches validated during preparation.
	Resources           map[string][]byte    `json:"resources,omitempty"`
	Precompiled         *precompiledRuleSets `json:"precompiled-rule-sets,omitempty"`
	OmittedResources    []string             `json:"omitted-rule-resources,omitempty"`
	Summary             Summary              `json:"summary"`
	precompiledCoverage map[string][]string
}

type Summary struct {
	Groups      []Group           `json:"groups"`
	Names       map[string]string `json:"names"`
	Nodes       int               `json:"nodes"`
	Rules       int               `json:"rules"`
	Outbounds   []Node            `json:"outbounds"`
	Resources   []Asset           `json:"resources,omitempty"`
	Format      string            `json:"format,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
	Patches     []PatchStatus     `json:"patches,omitempty"`
	// Global is the outbound or group global mode uses unless the controls
	// choose another.
	Global string `json:"global,omitempty"`
}

// PatchStatus reports the outcome of a patch in the submitted overlay.
type PatchStatus struct {
	Index   int    `json:"index"` // Zero-based index in PrepareOptions.Overlay.
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"` // Failure message with diagnostic codes.
}

const NodeGroup = "reka-ios-nodes"

type Node struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type Group struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Selected string   `json:"selected"`
	// Icon is the group's configured icon URL, for clients to display.
	Icon string `json:"icon,omitempty"`
}

type Controls struct {
	Mode       string            `json:"mode"`
	Selections map[string]string `json:"selections"`
	Pins       map[string]string `json:"pins,omitempty"`
	ProfileID  string            `json:"profileID,omitempty"`
	// BlockQUIC overrides the profile's routing.block-quic when set.
	BlockQUIC string `json:"blockQuic,omitempty"`
	// IPVersion overrides the dialer IP policy and DNS IPv6 setting when set.
	IPVersion string `json:"ipVersion,omitempty"`
	// Global chooses the outbound or group for global mode. It is ignored
	// unless it names one in the profile.
	Global string `json:"global,omitempty"`
	// FakeIPState is the App Group path opened once per session.
	FakeIPState string `json:"fakeIPState,omitempty"`
	// LogFile is where an extension session appends its log as JSON lines,
	// so the log outlives the extension process.
	LogFile string       `json:"logFile,omitempty"`
	Secrets secret.Store `json:"-"`
}

func readBundleFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBundleBytes {
		return nil, errors.New("invalid snapshot file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() > MaxBundleBytes {
		return nil, errors.New("invalid snapshot file")
	}
	return io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
}

func Decode(data []byte) (*Bundle, error) {
	var bundle Bundle
	if len(data) > MaxBundleBytes || json.Unmarshal(data, &bundle) != nil || bundle.Version != bundleVersion {
		return nil, errInvalidSnapshot
	}
	return &bundle, nil
}

func (b *Bundle) Compile() (*compile.Effective, error) {
	return b.CompileWithSecrets(nil)
}

func (b *Bundle) CompileWithSecrets(secrets secret.Store) (*compile.Effective, error) {
	return b.compileEffective(b.compileOptions(b.readResource, secrets, false))
}

func (b *Bundle) compileEffective(opts compile.Options) (*compile.Effective, error) {
	var needsPreparation bool
	if len(b.OmittedResources) > 0 {
		read := opts.ReadResource
		opts.ReadResource = func(hash string) ([]byte, error) {
			data, err := read(hash)
			needsPreparation = needsPreparation || errors.Is(err, errSnapshotNeedsPreparation)
			return data, err
		}
	}
	eff, diagnostics := b.compile(opts)
	if diagnostics.HasErrors() {
		if needsPreparation {
			return nil, errSnapshotNeedsPreparation
		}
		return nil, diagnosticError("invalid profile", diagnostics)
	}
	return eff, nil
}

var errSnapshotResource = errors.New("rule resource is missing or invalid in this snapshot")
var errSnapshotNeedsPreparation = errors.New("prepare the profile again because precompiled rules cannot be loaded and their original resources were omitted")

func (b *Bundle) readResource(hash string) ([]byte, error) {
	if data := b.Resources[hash]; data != nil {
		return data, nil
	}
	return nil, b.missingResource(hash)
}

func (b *Bundle) missingResource(hash string) error {
	if slices.Contains(b.OmittedResources, hash) {
		return errSnapshotNeedsPreparation
	}
	return errSnapshotResource
}

func (b *Bundle) compileOptions(read func(string) ([]byte, error), secrets secret.Store, estimateMemory bool) compile.Options {
	return compile.Options{
		Sources:                b.Sources,
		Overlay:                b.Overlay,
		Secrets:                secrets,
		EstimateRuleMemory:     estimateMemory,
		OmitProvenance:         true,
		ReadResource:           read,
		ReadPrecompiledRuleSet: b.Precompiled.reader(b.readPrecompiledRuleSet),
	}
}

func (b *Bundle) compile(opts compile.Options) (*compile.Effective, model.Diagnostics) {
	eff, diagnostics := compile.Compile(b.Profile, b.Local, opts)
	if diagnostics.HasErrors() {
		return nil, diagnostics
	}
	if dns := eff.DNS; len(b.Overlay) > 0 && dns != nil &&
		(dns.Listen != "" || dns.CacheSize != boundedNumber(dns.CacheSize, dnsCacheLimit) || dns.Concurrency != boundedNumber(dns.Concurrency, dnsUpstreamLimit)) {
		return nil, append(diagnostics, model.Diagnostic{
			Severity: model.SeverityError, Code: "ios.dns-limit", Path: "/dns",
			Message: "DNS settings exceed the packet tunnel limits",
		})
	}
	if len(eff.Groups) == 0 && eff.Router.Rules().Len() == 0 {
		if err := addNodeGroup(eff); err != nil {
			return nil, append(diagnostics, model.Diagnostic{
				Severity: model.SeverityError, Code: "ios.node-group", Path: "/outbounds", Message: err.Error(),
			})
		}
	}
	return eff, diagnostics
}

func addNodeGroup(eff *compile.Effective) error {
	var members, ids []string
	for _, out := range eff.Outbounds {
		ids = append(ids, out.ID)
		if !out.Builtin {
			members = append(members, out.ID)
		}
	}
	if len(members) == 0 {
		return nil
	}
	id := NodeGroup
	for slices.Contains(ids, id) {
		id += "-1"
	}
	eff.Groups = []router.Group{{ID: id, Members: members, Selected: members[0]}}
	eff.GroupMetadata = map[string]compile.GroupMetadata{id: {Name: "Nodes"}}
	eff.Final = id
	eff.Routing.Global = id
	var err error
	eff.Router, err = router.New(eff.Router.Rules(), router.Options{Outbounds: ids, Groups: eff.Groups, Final: id})
	eff.ActiveRouter = eff.Router
	return err
}

// defaultGlobal picks global mode's target when the controls do not: the
// profile's routing.global, a group named GLOBAL as in Clash, the first
// group, then the first node.
func defaultGlobal(base *compile.Effective, names map[string]string) string {
	if base.Routing.Global != "" {
		return base.Routing.Global
	}
	for _, group := range base.Groups {
		if strings.EqualFold(group.ID, "GLOBAL") || strings.EqualFold(names[group.ID], "GLOBAL") {
			return group.ID
		}
	}
	if len(base.Groups) > 0 {
		return base.Groups[0].ID
	}
	for _, outbound := range base.Outbounds {
		if !outbound.Builtin && outbound.Type != "pass" && outbound.Type != "reject-drop" {
			return outbound.ID
		}
	}
	return base.Final
}

func Describe(eff *compile.Effective) Summary {
	summary := Summary{Names: map[string]string{"direct": "DIRECT", "reject": "REJECT", "reject-drop": "REJECT-DROP", "pass": "PASS"},
		Rules: eff.Router.Rules().Len()}
	for _, outbound := range eff.Outbounds {
		if outbound.Builtin {
			continue
		}
		summary.Nodes++
		summary.Outbounds = append(summary.Outbounds, Node{ID: outbound.ID, Type: outbound.Type})
		if outbound.Name != "" {
			summary.Names[outbound.ID] = outbound.Name
		}
	}
	for _, group := range eff.Groups {
		kind := "select"
		for _, auto := range eff.AutoGroups {
			if auto.ID == group.ID {
				kind = auto.Type
				break
			}
		}
		meta := eff.GroupMetadata[group.ID]
		if meta.Name != "" {
			summary.Names[group.ID] = meta.Name
		}
		summary.Groups = append(summary.Groups, Group{ID: group.ID, Type: kind, Members: group.Members, Selected: group.Selected, Icon: meta.Icon})
	}
	if summary.Groups == nil {
		summary.Groups = []Group{}
	}
	if summary.Outbounds == nil {
		summary.Outbounds = []Node{}
	}
	summary.Global = defaultGlobal(eff, summary.Names)
	return summary
}

// PinnedMember returns the resolved member of a pinned url-test group, if any.
func (c Controls) PinnedMember(group policy.Group, names map[string]string) string {
	if group.Type != "url-test" {
		return ""
	}
	return controlledMember(c.Pins, names, group.ID, group.Members)
}

func controlledMember(values, names map[string]string, groupID string, members []string) string {
	member := values[groupID]
	if member == "" && names[groupID] != "" {
		member = values[names[groupID]]
	}
	if member == "" || slices.Contains(members, member) {
		return member
	}
	for _, id := range members {
		if names[id] == member {
			return id
		}
	}
	return ""
}

// ApplyControls shares the compiled rule index across updates. Stable IDs are
// preferred, with display names supported for older iOS saves.
func ApplyControls(base *compile.Effective, summary Summary, controls Controls) (*compile.Effective, error) {
	eff, err := base.WithIPVersion(controls.IPVersion)
	if err != nil {
		return nil, err
	}
	eff.Groups = slices.Clone(base.Groups)
	ids := make([]string, 0, len(base.Outbounds))
	for _, outbound := range base.Outbounds {
		ids = append(ids, outbound.ID)
	}
	global := controls.Global
	if !slices.Contains(ids, global) && !slices.ContainsFunc(base.Groups, func(g router.Group) bool { return g.ID == global }) {
		global = defaultGlobal(base, summary.Names)
	}
	for i := range eff.Groups {
		group := &eff.Groups[i]
		if summary.Groups[i].Type != "select" {
			continue
		}
		if member := controlledMember(controls.Selections, summary.Names, group.ID, group.Members); member != "" {
			group.Selected = member
		}
	}
	if len(controls.Pins) > 0 {
		eff.AutoGroups = slices.Clone(eff.AutoGroups)
		for i := range eff.AutoGroups {
			group := &eff.AutoGroups[i]
			if member := controls.PinnedMember(*group, summary.Names); member != "" {
				group.Selected = member
			}
		}
	}
	mode := controls.Mode
	if mode == "" {
		mode = base.Routing.Mode
	}
	blockQUIC := controls.BlockQUIC
	if blockQUIC == "" {
		blockQUIC = base.Routing.BlockQUIC
	}
	if blockQUIC == "" {
		blockQUIC = "off"
	}
	if !slices.Contains([]string{"off", "proxy", "all"}, blockQUIC) {
		return nil, errors.New("unknown QUIC blocking mode")
	}
	eff.Routing = model.Routing{Mode: mode, Global: global, BlockQUIC: blockQUIC}
	opts := router.Options{Outbounds: ids, Groups: eff.Groups, Final: base.Final}
	eff.Router, err = router.New(base.Router.Rules(), opts)
	if err != nil {
		return nil, err
	}
	eff.ActiveRouter = eff.Router
	switch mode {
	case "rule":
		return eff, nil
	case "global":
		opts.Final = global
	case "direct":
		opts.Final = model.OutboundDirect
	default:
		return nil, errors.New("unknown routing mode")
	}
	active, err := router.CompileRules([]router.RuleSpec{{ID: "routing-mode-" + mode, Kind: router.KindMatch, Target: opts.Final}})
	if err != nil {
		return nil, err
	}
	eff.ActiveRouter, err = router.New(active, opts)
	return eff, err
}

func diagnosticError(prefix string, diagnostics model.Diagnostics) error {
	// Paths and malformed values can contain credentials. Report stable error
	// codes only to the app and the system VPN log.
	var codes []string
	for _, diagnostic := range diagnostics {
		if diagnostic.Code != "import.partial" && !strings.HasPrefix(diagnostic.Code, "import.ignored") && !slices.Contains(codes, diagnostic.Code) {
			codes = append(codes, diagnostic.Code)
		}
		if len(codes) == 4 {
			break
		}
	}
	if len(codes) == 0 {
		return errors.New(prefix)
	}
	return fmt.Errorf("%s (%s)", prefix, strings.Join(codes, ", "))
}
