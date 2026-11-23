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
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/secret"
)

const bundleVersion = 1
const MaxBundleBytes = 4 << 20

var errBundleTooLarge = errors.New("prepared rules and resources exceed the 4 MiB extension configuration budget")

type Bundle struct {
	Version   int               `json:"version"`
	Profile   json.RawMessage   `json:"profile"`
	Local     json.RawMessage   `json:"local,omitempty"`
	Sources   json.RawMessage   `json:"sources,omitempty"`
	Overlay   json.RawMessage   `json:"overlay,omitempty"` // Only patches validated during preparation.
	Resources map[string][]byte `json:"resources,omitempty"`
	Summary   Summary           `json:"summary"`
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
	ProfileID  string            `json:"profileID,omitempty"`
	// BlockQUIC overrides the profile's routing.block-quic when set.
	BlockQUIC string `json:"blockQuic,omitempty"`
	// IPVersion overrides the dialer IP policy and DNS IPv6 setting when set.
	IPVersion string `json:"ipVersion,omitempty"`
	// FakeIPState is the App Group path opened once per session.
	FakeIPState string       `json:"fakeIPState,omitempty"`
	Secrets     secret.Store `json:"-"`
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
		return nil, errors.New("invalid profile snapshot")
	}
	return &bundle, nil
}

func (b *Bundle) Compile() (*compile.Effective, error) {
	return b.CompileWithSecrets(nil)
}

func (b *Bundle) CompileWithSecrets(secrets secret.Store) (*compile.Effective, error) {
	eff, diagnostics := b.compile(secrets)
	if diagnostics.HasErrors() {
		return nil, diagnosticError("invalid profile", diagnostics)
	}
	return eff, nil
}

func (b *Bundle) compile(secrets secret.Store) (*compile.Effective, model.Diagnostics) {
	eff, diagnostics := compile.Compile(b.Profile, b.Local, compile.Options{
		Sources: b.Sources,
		Overlay: b.Overlay,
		Secrets: secrets,
		ReadResource: func(hash string) ([]byte, error) {
			if data := b.Resources[hash]; data != nil {
				return data, nil
			}
			return nil, errors.New("rule resource is missing from this snapshot")
		},
	})
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
	// These maps describe configuration edits. The phone publishes a read-only
	// snapshot and does not need to retain editor provenance in the extension.
	eff.Provenance = nil
	eff.SourceHashes = nil
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
	return summary
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
	global := base.Routing.Global
	for i := range eff.Groups {
		group := &eff.Groups[i]
		if global == "" && (strings.EqualFold(group.ID, "GLOBAL") || strings.EqualFold(summary.Names[group.ID], "GLOBAL")) {
			global = group.ID
		}
		entry := summary.Groups[i]
		if entry.Type != "select" {
			continue
		}
		member := controls.Selections[group.ID]
		if member == "" && summary.Names[group.ID] != "" {
			member = controls.Selections[summary.Names[group.ID]]
		}
		if slices.Contains(group.Members, member) {
			group.Selected = member
		} else if member != "" {
			for _, id := range group.Members {
				if summary.Names[id] == member {
					group.Selected = id
					break
				}
			}
		}
	}
	if global == "" && len(eff.Groups) > 0 {
		global = eff.Groups[0].ID
	}
	if global == "" {
		global = base.Final
		for _, outbound := range base.Outbounds {
			if !outbound.Builtin && outbound.Type != "pass" && outbound.Type != "reject-drop" {
				global = outbound.ID
				break
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
