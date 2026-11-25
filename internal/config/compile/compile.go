// Package compile composes and validates native configuration layers:
// defaults, source imports, profile, overlay, then local settings, recording
// where every field came from. Compilation has
// no side effects beyond reading secrets and immutable locked resources.
package compile

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	VE "github.com/MimoProxy/reka/internal/compat/vlessenc"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/secret"
	"golang.org/x/net/http/httpguts"
)

// Options for Compile.
type Options struct {
	ReadResource func(string) ([]byte, error)
	Sources      []byte
	Overlay      []byte
	// Precompiled rule sets are optional and keyed by the locked definition.
	ReadPrecompiledRuleSet   func(string) (*router.PrecompiledRuleSet, []byte)
	RecordPrecompiledRuleSet func(string, []byte)
	// RecordPrecompiledCoverage receives source hashes and all keys needed to omit each source.
	RecordPrecompiledCoverage func(string, []string)
	// MaxPrecompiledRuleBytes bounds the expanded cache body during preparation.
	MaxPrecompiledRuleBytes int
	// Secrets resolves "secret://" references. Nil makes every reference
	// an error.
	Secrets secret.Store
	// ProcessLookup reports whether this platform can find the process
	// owning a connection; without it process-name rules never match.
	ProcessLookup bool
	// EstimateRuleMemory includes a structural size estimate for preparation.
	EstimateRuleMemory bool
	// OmitProvenance skips editor provenance and source digests in the result.
	OmitProvenance bool
}

// Layers, in composition order.
const (
	LayerDefault = "default"
	LayerProfile = "profile"
	LayerLocal   = "local"
)

// Origin says where an effective field came from.
type Origin struct {
	Layer    string `json:"layer"`
	Document string `json:"document,omitempty"`
	Path     string `json:"path,omitempty"`
	Source   string `json:"source,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	// Overrides is set when a local setting replaced a profile value.
	Overrides *Origin `json:"overrides,omitempty"`
}

// Outbound is a validated outbound with secrets resolved. Fingerprint
// changes whenever anything that affects the instance changes, including
// a resolved secret; equal fingerprints mean the instance can be reused.
type Outbound struct {
	Plugin            *model.SSPlugin            `json:"-"`
	Encryption        string                     `json:"-"`
	UDPOverTCP        bool                       `json:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int                        `json:"udp-over-tcp-version,omitempty"`
	Headers           []model.SubscriptionHeader `json:"-"`
	Dialer            *model.Dialer              `json:"dialer,omitempty"`
	PacketEncoding    string                     `json:"packet-encoding,omitempty"`
	Protocol          *model.Protocol            `json:"-"`
	Transport         *model.Transport           `json:"-"`
	Multiplex         *model.Multiplex           `json:"multiplex,omitempty"`
	ID                string                     `json:"id"`
	Name              string                     `json:"name,omitempty"`
	Type              string                     `json:"type"`
	Server            string                     `json:"server,omitempty"`
	Port              uint16                     `json:"port,omitempty"`
	UDP               bool                       `json:"udp"`
	Username          string                     `json:"-"`
	Method            string                     `json:"method,omitempty"`
	Flow              string                     `json:"flow,omitempty"`
	TLS               *TLS                       `json:"tls,omitempty"`
	Builtin           bool                       `json:"builtin,omitempty"`
	Fingerprint       string                     `json:"fingerprint"`

	// Resolved credentials; never serialized.
	Password string `json:"-"`
	UUID     string `json:"-"`
}

// TLS is validated client TLS.
type TLS struct {
	Carrier        *model.TLSCarrier `json:"-"`
	ECH            *model.ECH        `json:"ech,omitempty"`
	CertificatePin string            `json:"certificate-sha256,omitempty"`
	VerifyName     string            `json:"verify-name,omitempty"`
	Certificate    string            `json:"-"`
	PrivateKey     string            `json:"-"`
	ServerName     string            `json:"server-name,omitempty"`
	Insecure       bool              `json:"insecure,omitempty"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	ALPN           []string          `json:"alpn,omitempty"`
	Reality        *Reality          `json:"reality,omitempty"`
}

// Reality is validated REALITY client configuration.
type Reality struct {
	PublicKey      string `json:"public-key"`
	ShortID        string `json:"short-id,omitempty"`
	X25519MLKEM768 bool   `json:"x25519mlkem768,omitempty"`
}

// Listener is a validated local listener.
type Listener struct {
	Users       []model.ListenerUser `json:"-"`
	ID          string               `json:"id"`
	Type        string               `json:"type"`
	Listen      netip.AddrPort       `json:"listen"`
	UDP         bool                 `json:"udp"`
	Fingerprint string               `json:"fingerprint"`
}

// GroupMetadata contains display fields that do not affect routing or instances.
type GroupMetadata struct {
	Name string `json:"name,omitempty"`
	Icon string `json:"icon,omitempty"`
}

// Effective is the immutable configuration used by the runtime.
type Effective struct {
	MITM             MITM                      `json:"mitm"`
	NetworkScenes    []NetworkScene            `json:"network-scenes,omitempty"`
	TrafficBudgets   map[string]TrafficBudget  `json:"traffic-budgets,omitempty"`
	Process          model.Process             `json:"process"`
	Routing          model.Routing             `json:"routing"`
	ActiveRouter     *router.Router            `json:"-"`
	Sniff            model.Sniff               `json:"sniff"`
	SniffRules       *router.Router            `json:"-"`
	SniffSkipDomains *router.Router            `json:"-"`
	SniffForRouting  bool                      `json:"-"`
	Network          platform.Network          `json:"network"`
	GroupUDPDisabled map[string]bool           `json:"group-udp-disabled,omitempty"`
	AutoGroups       []policy.Group            `json:"automatic-groups,omitempty"`
	DNS              *RD.Config                `json:"-"`
	DNSFingerprint   string                    `json:"dns-fingerprint,omitempty"`
	DNSMatches       map[string]*router.Router `json:"-"`
	GroupMetadata    map[string]GroupMetadata  `json:"group_metadata,omitempty"`
	SourceHashes     map[string]string         `json:"source_hashes,omitempty"`
	Modules          map[string]module.Report  `json:"modules,omitempty"`
	Outbounds        []Outbound                `json:"outbounds"`
	Groups           []router.Group            `json:"groups"`
	Rules            []router.RuleSpec         `json:"-"`
	RuleIDs          []string                  `json:"-"`
	RuleDescriptions []string                  `json:"-"`
	RuleSetSelectors map[string]string         `json:"-"`
	Listeners        []Listener                `json:"listeners"`
	LogLevel         string                    `json:"log-level"`
	Control          string                    `json:"control,omitempty"`
	// Final is the target when no rule matches.
	Final string `json:"final"`
	// RulesFingerprint changes whenever the rule list changes.
	RulesFingerprint string             `json:"rules-fingerprint"`
	RuleMemory       RuleMemoryEstimate `json:"-"`
	// HTTPRewrite is nil when there are no rewrite rules.
	HTTPRewrite *httprewrite.Set `json:"-"`
	// HTTPRewriteFingerprint identifies the ordered rewrite definitions and their resource hashes.
	HTTPRewriteFingerprint string `json:"http-rewrite-fingerprint,omitempty"`
	// Scripts preserves the order of composed script definitions, including unsupported types.
	Scripts []Script `json:"scripts,omitempty"`
	// ScriptFingerprint identifies the ordered script definitions and source hashes.
	ScriptFingerprint string `json:"script-fingerprint,omitempty"`
	mitmCAStore       secret.Store

	// IPVersionOverride is empty when the profile's IP settings are in use.
	IPVersionOverride string `json:"-"`

	Provenance map[string]Origin `json:"provenance"`

	// Router is compiled once here so that validation catches every rule
	// and group error; the runtime reuses it.
	Router *router.Router `json:"-"`
}

// MITMCAStore returns the profile's local store for runtime CA loading.
// The compiler does not resolve the reserved CA reference.
func (e *Effective) MITMCAStore() secret.Store { return e.mitmCAStore }

// OriginOf returns where path came from, falling back to the closest
// recorded parent.
func (e *Effective) OriginOf(path string) (Origin, bool) {
	for p := path; ; {
		if o, ok := e.Provenance[p]; ok {
			return o, true
		}
		i := strings.LastIndexByte(p, '/')
		if i <= 0 {
			return Origin{}, false
		}
		p = p[:i]
	}
}

func (e *Effective) setOrigin(path string, origin Origin) {
	if e.Provenance != nil {
		e.Provenance[path] = origin
	}
}

// Outbound returns the outbound with id.
func (e *Effective) Outbound(id string) (Outbound, bool) {
	for _, o := range e.Outbounds {
		if o.ID == id {
			return o, true
		}
	}
	return Outbound{}, false
}

type compiler struct {
	ruleResources *ruleCompiler
	origins       map[string]Origin
	scopedIDs     map[string]bool
	sourceHashes  map[string]string
	moduleReports map[string]module.Report
	moduleDigests []string
	modulePaths   map[string]string
	opts          Options
	diags         model.Diagnostics
	ppos          model.Positions
	lpos          model.Positions
	profile       *model.Profile
	local         *model.LocalSettings
}

func (c *compiler) add(sev model.Severity, doc, path, code, format string, args ...any) {
	d := model.Diagnostic{Severity: sev, Code: code, Document: doc, Path: path, Message: fmt.Sprintf(format, args...)}
	pos := c.ppos
	if doc == model.DocLocal {
		pos = c.lpos
	}
	if p, ok := pos[path]; ok {
		d.Line, d.Column = p.Line, p.Column
	}
	c.diags = append(c.diags, d)
}

func (c *compiler) errorf(doc, path, code, format string, args ...any) {
	c.add(model.SeverityError, doc, path, code, format, args...)
}

func (c *compiler) warnf(doc, path, code, format string, args ...any) {
	c.add(model.SeverityWarning, doc, path, code, format, args...)
}

// Compile parses, validates and composes. The result is nil when there are
// error diagnostics; warnings come with a result.
func Compile(profile, local []byte, opts Options) (*Effective, model.Diagnostics) {
	c := &compiler{opts: opts}
	var d1, d2 model.Diagnostics
	var doc *model.Doc
	c.profile, c.ppos, doc, d1 = model.ParseProfileDoc(profile)
	c.local, c.lpos, d2 = model.ParseLocal(local)
	c.diags = append(append(c.diags, d1...), d2...)
	if c.diags.HasErrors() {
		return nil, c.diags
	}
	c.checkProfileScriptDuplicates()
	if c.diags.HasErrors() {
		return nil, c.diags
	}
	needsLayers := len(opts.Sources) > 0 || len(opts.Overlay) > 0 || len(c.profile.Imports) > 0 || len(c.profile.Modules) > 0
	for i, rule := range c.profile.Rules {
		needsLayers = needsLayers || rule.Source != "" || hasKey(c.ppos, model.JoinPath("/rules", seg(rule.ID, i), "module"))
	}
	if needsLayers {
		c.layers(doc)
	}
	if c.diags.HasErrors() {
		return nil, c.diags
	}
	eff := c.compose()
	if c.ruleResources != nil {
		c.ruleResources.validateDeferredDatabases()
	}
	for i, d := range c.diags {
		if d.Document == model.DocProfile {
			if o, ok := diagnosticOrigin(c.origins, d.Path); ok {
				if o.Layer == LayerModule {
					path := c.modulePaths[o.Source]
					c.diags[i].Path = path
					c.diags[i].Line, c.diags[i].Column = c.ppos[path].Line, c.ppos[path].Column
					c.diags[i].Message = fmt.Sprintf("module line %d: %s", o.Line, d.Message)
					continue
				}
				c.diags[i].Document, c.diags[i].Path, c.diags[i].Line, c.diags[i].Column = o.Document, o.Path, o.Line, o.Column
			}
		}
	}
	if c.diags.HasErrors() {
		return nil, c.diags
	}
	if c.ruleResources != nil && opts.RecordPrecompiledCoverage != nil {
		for hash, keys := range c.ruleResources.coverage {
			if len(keys) > 0 {
				opts.RecordPrecompiledCoverage(hash, keys)
			}
		}
	}
	if opts.EstimateRuleMemory {
		eff.RuleMemory = c.estimateRuleMemory(eff)
	}
	return eff, c.diags
}

func seg(id string, i int) string {
	if id != "" && !strings.HasPrefix(id, "#") {
		return id
	}
	return "#" + strconv.Itoa(i)
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (c *compiler) checkID(doc, path, id string) bool {
	if id == "" {
		c.errorf(doc, path, "schema.id", "id is required")
		return false
	}
	if !idRE.MatchString(id) && !c.scopedIDs[id] {
		c.errorf(doc, path+"/id", "schema.id", "id %q must start with a letter or digit and contain only letters, digits, '.', '_' and '-' (at most 64)", id)
		return false
	}
	return true
}

func (c *compiler) compose() *Effective {
	eff := &Effective{Final: model.OutboundDirect, SourceHashes: c.sourceHashes, Modules: c.moduleReports}
	if !c.opts.OmitProvenance {
		if c.origins != nil {
			eff.Provenance = maps.Clone(c.origins)
		} else {
			eff.Provenance = make(map[string]Origin, len(c.ppos))
			for p, pos := range c.ppos {
				eff.Provenance[p] = Origin{Layer: LayerProfile, Line: pos.Line, Column: pos.Column}
			}
		}
	}

	c.outbounds(eff)
	c.groups(eff)
	c.detours(eff)
	c.rules(eff)
	c.dns(eff)
	c.listenersAndLocal(eff)
	c.mitm(eff)
	if eff.MITM.Enabled {
		eff.mitmCAStore = c.opts.Secrets
	}
	c.httpRewrites(eff)
	c.scripts(eff)
	c.process(eff)
	c.sniff(eff)
	c.network(eff)
	c.routing(eff)
	c.networkScenes(eff)
	c.trafficBudgets(eff)
	if c.diags.HasErrors() {
		return eff
	}
	rs, err := router.CompileRules(eff.Rules)
	if err != nil {
		// Each rule was checked already; this only reports leftovers.
		c.errorf(model.DocProfile, "/rules", "rule.invalid", "%v", err)
		return eff
	}
	ids := make([]string, len(eff.Outbounds))
	for i, o := range eff.Outbounds {
		ids[i] = o.ID
	}
	r, err := router.New(rs, router.Options{Outbounds: ids, Groups: eff.Groups, Final: eff.Final})
	if err != nil {
		c.errorf(model.DocProfile, "/groups", "group.invalid", "%v", err)
		return eff
	}
	eff.Router = r
	eff.ActiveRouter = r
	if eff.Routing.Mode != "rule" {
		target := eff.Routing.Global
		if eff.Routing.Mode == "direct" {
			target = model.OutboundDirect
		}
		activeRules, _ := router.CompileRules([]router.RuleSpec{{ID: "routing-mode-" + eff.Routing.Mode, Kind: router.KindMatch, Target: target}})
		eff.ActiveRouter, err = router.New(activeRules, router.Options{Outbounds: ids, Groups: eff.Groups, Final: target})
		if err != nil {
			c.errorf(model.DocProfile, "/routing", "routing.target", "%v", err)
		}
	}
	return eff
}

// fieldsByType lists, per outbound type, the fields that apply. Anything
// else written for that type is an error.
var fieldsByType = map[string][]string{
	model.OutboundDirect: {"udp"},
	model.OutboundReject: {},
	"pass":               {}, "reject-drop": {},
	model.OutboundHTTP:        {"server", "port", "username", "password", "tls", "headers"},
	model.OutboundSOCKS:       {"server", "port", "username", "password", "udp", "tls"},
	model.OutboundShadowsocks: {"server", "port", "method", "password", "udp", "udp-over-tcp", "udp-over-tcp-version", "plugin"},
	model.OutboundVLESS:       {"server", "port", "uuid", "flow", "encryption", "packet-encoding", "tls", "udp", "transport", "multiplex"},
	"vmess":                   {"server", "port", "uuid", "tls", "udp", "protocol", "transport", "multiplex", "packet-encoding"},
	"trojan":                  {"server", "port", "password", "tls", "udp", "transport", "multiplex"},
	"hysteria2":               {"server", "port", "password", "tls", "udp", "protocol"},
	"tuic":                    {"server", "port", "uuid", "password", "tls", "udp", "protocol"},
	"snell":                   {"server", "port", "password", "udp", "protocol"},
}

var commonFields = []string{"id", "name", "type", "dialer", "multiplex"}

// ShadowsocksMethods are the ciphers the Shadowsocks outbound accepts.
var ShadowsocksMethods = []string{
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
}

// Fingerprints are the uTLS ClientHello presets.
var Fingerprints = []string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

// OutboundTypes lists supported outbound types.
func OutboundTypes() []string {
	t := make([]string, 0, len(fieldsByType))
	for k := range fieldsByType {
		t = append(t, k)
	}
	sort.Strings(t)
	return t
}

func (c *compiler) present(base string) []string {
	var keys []string
	prefix := base + "/"
	for p := range c.ppos {
		if rest, ok := strings.CutPrefix(p, prefix); ok && !strings.Contains(rest, "/") {
			keys = append(keys, rest)
		}
	}
	sort.Strings(keys)
	return keys
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var shortIDRE = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)

func (c *compiler) resolveSecret(path, v string) string {
	name, ok := secret.ParseRef(v)
	if !ok {
		return v
	}
	if secret.Reserved(name) {
		c.errorf(model.DocProfile, path, "secret.reserved", "secret %q is reserved", name)
		return ""
	}
	if err := secret.ValidName(name); err != nil {
		c.errorf(model.DocProfile, path, "secret.name", "%v", err)
		return ""
	}
	if c.opts.Secrets == nil {
		c.errorf(model.DocProfile, path, "secret.unavailable", "no secret store to resolve %s", v)
		return ""
	}
	val, err := c.opts.Secrets.Get(name)
	if errors.Is(err, secret.ErrNotFound) {
		c.errorf(model.DocProfile, path, "secret.missing", "secret %q is not stored", name)
		return ""
	}
	if err != nil {
		c.errorf(model.DocProfile, path, "secret.unavailable", "read secret %q: %v", name, err)
		return ""
	}
	return val
}

func (c *compiler) outbounds(eff *Effective) {
	seen := map[string]bool{}
	const doc = model.DocProfile
	for i, ob := range c.profile.Outbounds {
		base := model.JoinPath("/outbounds", seg(ob.ID, i))
		if !c.checkID(doc, base, ob.ID) {
			continue
		}
		if seen[ob.ID] {
			c.errorf(doc, base+"/id", "schema.duplicate-id", "duplicate outbound id %q", ob.ID)
			continue
		}
		seen[ob.ID] = true
		allowed, ok := fieldsByType[ob.Type]
		if !ok {
			c.errorf(doc, base+"/type", "outbound.type", "unsupported outbound type %q (supported: %s)", ob.Type, strings.Join(OutboundTypes(), ", "))
			continue
		}
		for _, k := range c.present(base) {
			if !slices.Contains(allowed, k) && !slices.Contains(commonFields, k) {
				c.errorf(doc, base+"/"+k, "outbound.field", "field %q does not apply to %s outbounds", k, ob.Type)
			}
		}
		if (ob.ID == model.OutboundDirect && ob.Type != model.OutboundDirect) || (ob.ID == model.OutboundReject && ob.Type != model.OutboundReject) {
			c.errorf(doc, base+"/type", "outbound.builtin", "id %q is reserved for the built-in %s outbound", ob.ID, ob.ID)
		}
		out := Outbound{PacketEncoding: ob.PacketEncoding, Protocol: ob.Protocol, Transport: ob.Transport, Multiplex: ob.Multiplex, ID: ob.ID, Name: ob.Name, Type: ob.Type, Method: ob.Method, Flow: ob.Flow}
		if ob.Dialer != nil {
			value := *ob.Dialer
			if ob.Type == model.OutboundReject || ob.Type == "pass" || ob.Type == "reject-drop" {
				c.errorf(doc, base+"/dialer", "outbound.dialer", "reject does not dial a connection")
			}
			if value.RoutingMark < 0 || uint64(value.RoutingMark) > uint64(^uint32(0)) {
				c.errorf(doc, base+"/dialer/routing-mark", "outbound.dialer", "routing-mark must be a uint32")
			}
			if len(value.Interface) > 255 || strings.ContainsAny(value.Interface, "\x00\r\n") {
				c.errorf(doc, base+"/dialer/interface-name", "outbound.dialer", "invalid interface name")
			}
			if !slices.Contains([]string{"", "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"}, value.IPVersion) {
				c.errorf(doc, base+"/dialer/ip-version", "outbound.dialer", "invalid IP version policy")
			}
			out.Dialer = &value
		}
		out.UDPOverTCP, out.UDPOverTCPVersion = ob.UDPOverTCP, ob.UDPOverTCPVersion
		if out.UDPOverTCP && out.UDPOverTCPVersion == 0 {
			out.UDPOverTCPVersion = 1
		}
		if !slices.Contains([]int{0, 1, 2}, out.UDPOverTCPVersion) {
			c.errorf(doc, base+"/udp-over-tcp-version", "outbound.uot", "UoT version must be 1 or 2")
		}
		out.Headers = slices.Clone(ob.Headers)
		for i := range out.Headers {
			h := &out.Headers[i]
			h.Value = c.resolveSecret(fmt.Sprintf("%s/headers/#%d/value", base, i), h.Value)
			if !httpguts.ValidHeaderFieldName(h.Name) || !httpguts.ValidHeaderFieldValue(h.Value) {
				c.errorf(doc, base+"/headers", "outbound.headers", "invalid HTTP header")
			}
		}
		out.UDP = ob.UDP == nil || *ob.UDP
		if ob.Type == model.OutboundHTTP || ob.Type == model.OutboundReject {
			out.UDP = false
		}
		if ob.Multiplex != nil && ob.Multiplex.Enabled && !ob.Multiplex.OnlyTCP {
			out.UDP = true
		}
		if ob.Type != model.OutboundDirect && ob.Type != model.OutboundReject && ob.Type != "pass" && ob.Type != "reject-drop" {
			realmEnabled := ob.Type == "hysteria2" && ob.Protocol != nil && ob.Protocol.Realm != nil && ob.Protocol.Realm.Enabled
			if ob.Server == "" && !realmEnabled {
				c.errorf(doc, base, "outbound.server", "server is required")
			} else if strings.ContainsAny(ob.Server, " /:") && !isIP(ob.Server) {
				c.errorf(doc, base+"/server", "outbound.server", "server must be a host name or an IP address")
			}
			if (ob.Port < 1 || ob.Port > 65535) && !(ob.Type == "hysteria2" && ob.Port == 0 && ob.Protocol != nil && (len(ob.Protocol.ServerPorts) > 0 || realmEnabled)) {
				c.errorf(doc, base+"/port", "outbound.port", "port must be between 1 and 65535")
			}
			out.Server, out.Port = strings.Trim(ob.Server, "[]"), uint16(ob.Port)
		}
		out.Username = c.resolveSecret(base+"/username", ob.Username)
		out.Password = c.resolveSecret(base+"/password", ob.Password)
		out.UUID = c.resolveSecret(base+"/uuid", ob.UUID)
		out.Encryption = c.resolveSecret(base+"/encryption", ob.Encryption)
		switch ob.Type {
		case model.OutboundShadowsocks:
			out.Plugin = c.ssPlugin(base+"/plugin", ob.Plugin)
			if out.Plugin != nil && out.Plugin.Type == "kcptun" {
				out.UDPOverTCP = true
				if out.UDPOverTCPVersion == 0 {
					out.UDPOverTCPVersion = 1
				}
			}
			if !slices.Contains(ShadowsocksMethods, ob.Method) {
				c.errorf(doc, base+"/method", "outbound.method", "unsupported method %q (supported: %s)", ob.Method, strings.Join(ShadowsocksMethods, ", "))
			}
			if out.Password == "" && !c.hasErrorAt(base+"/password") {
				c.errorf(doc, base, "outbound.password", "password is required")
			}
			if strings.HasPrefix(ob.Method, "2022-") && out.Password != "" {
				if _, err := base64.StdEncoding.DecodeString(strings.Split(out.Password, ":")[0]); err != nil {
					c.errorf(doc, base+"/password", "outbound.password", "a 2022 method needs a base64 key as password")
				}
			}
		case model.OutboundSOCKS, model.OutboundHTTP:
			if (out.Username == "") != (out.Password == "") {
				c.errorf(doc, base, "outbound.auth", "set both username and password, or neither")
			}
		case model.OutboundVLESS:
			if _, err := VE.NewClient(out.Encryption); err != nil {
				c.errorf(doc, base+"/encryption", "outbound.encryption", "invalid VLESS encryption configuration")
			}
			if !uuidRE.MatchString(out.UUID) && !c.hasErrorAt(base+"/uuid") {
				c.errorf(doc, base+"/uuid", "outbound.uuid", "uuid is required and must be a UUID")
			}
			if ob.Flow != "" && ob.Flow != "xtls-rprx-vision" {
				c.errorf(doc, base+"/flow", "outbound.flow", "flow must be empty or xtls-rprx-vision")
			}
			if !slices.Contains([]string{"", "xudp", "none", "packetaddr", "packet"}, ob.PacketEncoding) {
				c.errorf(doc, base+"/packet-encoding", "outbound.packet-encoding", "packet-encoding must be xudp, none or packetaddr")
			}
			if out.PacketEncoding == "" {
				out.PacketEncoding = "xudp"
			}
			if out.PacketEncoding == "packet" {
				out.PacketEncoding = "packetaddr"
			}
			if ob.Flow != "" && ob.TLS == nil && (out.Encryption == "" || out.Encryption == "none") {
				c.errorf(doc, base+"/flow", "outbound.flow", "xtls-rprx-vision needs TLS or VLESS encryption")
			}
		}
		if ob.TLS != nil {
			out.TLS = c.tls(base+"/tls", ob)
		}
		c.protocol(base, ob, &out)
		eff.Outbounds = append(eff.Outbounds, out)
	}
	for _, b := range []string{model.OutboundDirect, model.OutboundReject} {
		if !seen[b] {
			eff.Outbounds = append(eff.Outbounds, Outbound{ID: b, Type: b, UDP: b == model.OutboundDirect, Builtin: true})
			eff.setOrigin("/outbounds/"+b, Origin{Layer: LayerDefault})
		}
	}
	for _, action := range []string{"pass", "reject-drop"} {
		if seen[action] {
			continue
		}
		needed := false
		for _, node := range c.profile.Outbounds {
			if node.Dialer != nil && node.Dialer.Proxy == action {
				needed = true
			}
		}
		for _, g := range c.profile.Groups {
			if slices.Contains(g.Members, action) {
				needed = true
			}
		}
		for _, r := range c.profile.Rules {
			if r.Outbound == action {
				needed = true
			}
		}
		for _, block := range c.profile.SubRules {
			for _, r := range block.Rules {
				if r.Outbound == action {
					needed = true
				}
			}
		}
		if needed {
			eff.Outbounds = append(eff.Outbounds, Outbound{ID: action, Type: action, Builtin: true, UDP: true})
		}
	}
	for i := range eff.Outbounds {
		out := &eff.Outbounds[i]
		if out.Dialer == nil || out.Dialer.Proxy == "" {
			out.Fingerprint = outboundFingerprint(*out)
		}
	}
}

func outboundFingerprint(identity Outbound) string {
	identity.Name = "" // display metadata must not rebuild a live outbound
	identity.Fingerprint = ""
	if identity.Multiplex != nil {
		m := *identity.Multiplex
		m.Statistic = false
		identity.Multiplex = &m
	}
	plugin, _ := json.Marshal(identity.Plugin)
	params, _ := json.Marshal(identity.Protocol)
	transport, _ := json.Marshal(identity.Transport)
	headers, _ := json.Marshal(identity.Headers)
	tlsSecrets := ""
	if identity.TLS != nil {
		carrier, _ := json.Marshal(identity.TLS.Carrier)
		tlsSecrets = identity.TLS.Certificate + "\x00" + identity.TLS.PrivateKey + "\x00" + string(carrier)
	}
	return fingerprint(identity, identity.Username, identity.Password, identity.UUID, identity.Encryption, string(plugin), string(params), string(transport), string(headers), tlsSecrets)
}

func (c *compiler) hasErrorAt(path string) bool {
	for _, d := range c.diags {
		if d.Path == path && d.Severity == model.SeverityError {
			return true
		}
	}
	return false
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

func (c *compiler) tls(path string, ob model.Outbound) *TLS {
	const doc = model.DocProfile
	t := ob.TLS
	out := &TLS{Carrier: c.tlsCarrier(path+"/carrier", ob), ECH: t.ECH, CertificatePin: t.CertificatePin, VerifyName: t.VerifyName, Certificate: c.resolveSecret(path+"/certificate", t.Certificate), PrivateKey: c.resolveSecret(path+"/private-key", t.PrivateKey), ServerName: t.ServerName, Insecure: t.Insecure, Fingerprint: t.Fingerprint, ALPN: t.ALPN}
	if ech := t.ECH; ech != nil && ech.Enabled {
		if ech.Config != "" {
			data, err := base64.StdEncoding.DecodeString(ech.Config)
			valid := err == nil && len(data) >= 6 && len(data) <= 65537 && int(binary.BigEndian.Uint16(data)) == len(data)-2
			if valid {
				for rest := data[2:]; len(rest) > 0; {
					if len(rest) < 4 || int(binary.BigEndian.Uint16(rest[2:])) > len(rest)-4 {
						valid = false
						break
					}
					rest = rest[4+int(binary.BigEndian.Uint16(rest[2:])):]
				}
			}
			if !valid {
				c.errorf(doc, path+"/ech/config", "tls.ech", "expected a base64 ECHConfigList with valid framing")
			}
		}
		if strings.ContainsAny(ech.QueryServerName, " /\\\r\n\x00") {
			c.errorf(doc, path+"/ech/query-server-name", "tls.ech", "invalid ECH query server name")
		}
		if t.Reality != nil {
			c.errorf(doc, path+"/ech", "tls.ech", "ECH does not apply to a REALITY handshake")
		}
	}
	if out.Certificate != "" || out.PrivateKey != "" {
		if _, err := tls.X509KeyPair([]byte(out.Certificate), []byte(out.PrivateKey)); err != nil {
			c.errorf(doc, path+"/private-key", "tls.client-certificate", "client certificate and key must be a matching inline PEM pair or secret references")
		}
	}
	if pin := strings.ReplaceAll(strings.TrimSpace(t.CertificatePin), ":", ""); pin != "" {
		if b, err := hex.DecodeString(pin); err != nil || len(b) != 32 {
			c.errorf(doc, path+"/certificate-sha256", "tls.certificate-pin", "expected a full certificate SHA256 hex digest")
		}
	}
	if strings.ContainsAny(t.VerifyName, " /\\\r\n\x00") {
		c.errorf(doc, path+"/verify-name", "tls.verify-name", "invalid certificate verification name")
	}
	if t.Fingerprint != "" && (t.Carrier == nil || t.Carrier.Type == "shadow-tls") && !slices.Contains(Fingerprints, t.Fingerprint) {
		c.errorf(doc, path+"/fingerprint", "tls.fingerprint", "unknown fingerprint %q (supported: %s)", t.Fingerprint, strings.Join(Fingerprints, ", "))
	}
	if t.Reality == nil {
		if out.ServerName == "" && !isIP(ob.Server) {
			out.ServerName = ob.Server
		}
		return out
	}
	if t.CertificatePin != "" || t.VerifyName != "" || out.Certificate != "" || out.PrivateKey != "" {
		c.errorf(doc, path, "tls.reality", "REALITY uses its authenticated handshake rather than ordinary certificate options")
	}
	if ob.Type != model.OutboundVLESS {
		c.errorf(doc, path+"/reality", "tls.reality", "reality is only supported on vless outbounds")
		return out
	}
	r := t.Reality
	if key, err := base64.RawURLEncoding.DecodeString(r.PublicKey); err != nil || len(key) != 32 {
		c.errorf(doc, path+"/reality/public-key", "tls.reality", "public-key must be a 32-byte key in base64url without padding")
	}
	if !shortIDRE.MatchString(r.ShortID) || len(r.ShortID)%2 != 0 {
		c.errorf(doc, path+"/reality/short-id", "tls.reality", "short-id must be an even number of hex digits, at most 16")
	}
	if t.ServerName == "" {
		c.errorf(doc, path+"/server-name", "tls.reality", "reality needs server-name (the site the handshake imitates)")
	}
	if t.Insecure {
		c.errorf(doc, path+"/insecure", "tls.reality", "insecure does not apply to reality")
	}
	if out.Fingerprint == "" {
		out.Fingerprint = "chrome"
		c.warnf(doc, path+"/fingerprint", "tls.fingerprint", "reality needs a ClientHello fingerprint; using chrome")
	}
	out.Reality = &Reality{PublicKey: r.PublicKey, ShortID: r.ShortID, X25519MLKEM768: r.X25519MLKEM768}
	return out
}

func fingerprint(v any, extra ...string) string {
	b, _ := json.Marshal(v)
	h := sha256.New()
	h.Write(b)
	for _, e := range extra {
		h.Write([]byte{0})
		h.Write([]byte(e))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (c *compiler) groups(eff *Effective) {
	const doc = model.DocProfile
	targets := map[string]bool{}
	for _, o := range eff.Outbounds {
		targets[o.ID] = true
	}
	for i := range c.profile.Groups {
		g := &c.profile.Groups[i]
		members := append([]string{}, g.Members...)
		if g.IncludeAll {
			for _, o := range eff.Outbounds {
				if !o.Builtin && !slices.Contains(members, o.ID) {
					if c.scopedIDs[g.ID] {
						owner, _, _ := strings.Cut(g.ID, "/")
						if !strings.HasPrefix(o.ID, owner+"/") {
							continue
						}
					}
					members = append(members, o.ID)
				}
			}
		}
		var include, exclude *regexp.Regexp
		var err error
		if g.Filter != "" {
			include, err = regexp.Compile(g.Filter)
			if err != nil {
				c.errorf(doc, model.JoinPath("/groups", g.ID, "filter"), "group.filter", "invalid filter")
				continue
			}
		}
		if g.ExcludeFilter != "" {
			exclude, err = regexp.Compile(g.ExcludeFilter)
			if err != nil {
				c.errorf(doc, model.JoinPath("/groups", g.ID, "exclude-filter"), "group.filter", "invalid filter")
				continue
			}
		}
		g.Members = nil
		for _, id := range members {
			name := id
			for _, o := range eff.Outbounds {
				if o.ID == id && o.Name != "" {
					name = o.Name
					break
				}
			}
			if include != nil && !include.MatchString(name) || exclude != nil && exclude.MatchString(name) {
				continue
			}
			g.Members = append(g.Members, id)
		}
	}
	seen := map[string]bool{}
	for i, g := range c.profile.Groups {
		base := model.JoinPath("/groups", seg(g.ID, i))
		if !c.checkID(doc, base, g.ID) {
			continue
		}
		if targets[g.ID] || seen[g.ID] {
			c.errorf(doc, base+"/id", "schema.duplicate-id", "id %q is already used by an outbound or group", g.ID)
			continue
		}
		seen[g.ID] = true
	}
	for i, g := range c.profile.Groups {
		base := model.JoinPath("/groups", seg(g.ID, i))
		if g.Type != model.GroupSelect && g.Type != "url-test" && g.Type != "fallback" && g.Type != "load-balance" {
			c.errorf(doc, base+"/type", "group.type", "unsupported group type %q (supported: select, url-test, fallback, load-balance)", g.Type)
			continue
		}
		if len(g.Members) == 0 {
			c.errorf(doc, base+"/members", "group.members", "a group needs at least one member")
			continue
		}
		ok := true
		dup := map[string]bool{}
		for _, m := range g.Members {
			if !targets[m] && !seen[m] {
				c.errorf(doc, base+"/members", "group.member", "unknown member %q", m)
				ok = false
			}
			if dup[m] {
				c.errorf(doc, base+"/members", "group.member", "member %q is listed twice", m)
				ok = false
			}
			dup[m] = true
		}
		if g.Selected != "" && !slices.Contains(g.Members, g.Selected) {
			c.errorf(doc, base+"/selected", "group.selected", "selected %q is not a member", g.Selected)
			ok = false
		}
		if _, err := policy.ParseExpectedStatus(g.ExpectedStatus); err != nil {
			c.errorf(doc, base+"/expected-status", "group.health", "%s", err)
			ok = false
		}
		if g.Type != "select" {
			if g.URL == "" {
				g.URL = "https://www.gstatic.com/generate_204"
			}
			u, err := url.Parse(g.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
				c.errorf(doc, base+"/url", "group.url", "health URL must be HTTP(S)")
				ok = false
			}
			if g.Interval < 0 || g.Interval > 604800 || g.Timeout < 0 || g.Timeout > 60000 || g.Tolerance < 0 {
				c.errorf(doc, base, "group.health", "invalid health-check limits")
				ok = false
			}
			if g.Strategy != "" && g.Strategy != "consistent-hashing" && g.Strategy != "round-robin" {
				c.errorf(doc, base, "group.strategy", "unsupported load-balance strategy")
				ok = false
			}
			lazy := true
			if g.Lazy != nil {
				lazy = *g.Lazy
			}
			eff.AutoGroups = append(eff.AutoGroups, policy.Group{ExpectedStatus: g.ExpectedStatus, ID: g.ID, Type: g.Type, Members: g.Members, Selected: g.Selected, URL: g.URL, Interval: g.Interval, Timeout: g.Timeout, Tolerance: g.Tolerance, Lazy: lazy, Strategy: g.Strategy})
		}
		if g.DisableUDP {
			if eff.GroupUDPDisabled == nil {
				eff.GroupUDPDisabled = map[string]bool{}
			}
			eff.GroupUDPDisabled[g.ID] = true
		}
		if ok {
			if eff.GroupMetadata == nil {
				eff.GroupMetadata = map[string]GroupMetadata{}
			}
			eff.GroupMetadata[g.ID] = GroupMetadata{Name: g.Name, Icon: g.Icon}
			eff.Groups = append(eff.Groups, router.Group{ID: g.ID, Members: g.Members, Selected: g.Selected})
		}
	}
	// Cycles.
	byID := map[string]router.Group{}
	for _, g := range eff.Groups {
		byID[g.ID] = g
	}
	for i, g := range c.profile.Groups {
		if _, ok := byID[g.ID]; !ok {
			continue
		}
		if cycle := findCycle(g.ID, byID); cycle != "" {
			c.errorf(doc, model.JoinPath("/groups", seg(g.ID, i), "members"), "group.cycle", "groups form a cycle: %s", cycle)
			break
		}
	}
}

// findCycle walks every member path from start (not only the selected one:
// a later selection change must not be able to create a loop).
func findCycle(start string, groups map[string]router.Group) string {
	var stack []string
	var visit func(id string) string
	visit = func(id string) string {
		if i := slices.Index(stack, id); i >= 0 {
			return strings.Join(append(stack[i:], id), " -> ")
		}
		g, ok := groups[id]
		if !ok {
			return ""
		}
		stack = append(stack, id)
		for _, m := range g.Members {
			if c := visit(m); c != "" {
				return c
			}
		}
		stack = stack[:len(stack)-1]
		return ""
	}
	return visit(start)
}

func (c *compiler) rules(eff *Effective) {
	rc := c.prepareRuleResources()
	c.validateSubRules(rc, eff)
	c.expandSubRules()
	if eff.Provenance != nil {
		maps.Copy(eff.Provenance, c.origins)
	}
	if c.diags.HasErrors() {
		return
	}
	const doc = model.DocProfile
	targets := map[string]bool{}
	for _, o := range eff.Outbounds {
		targets[o.ID] = true
	}
	for _, g := range c.profile.Groups {
		targets[g.ID] = true
	}
	ids := map[string]bool{}
	catchAll := -1
	h := sha256.New()
	for i, r := range c.profile.Rules {
		base := model.JoinPath("/rules", seg(r.ID, i))
		if r.ID != "" {
			if !idRE.MatchString(r.ID) && !c.scopedIDs[r.ID] {
				c.errorf(doc, base+"/id", "schema.id", "invalid rule id %q", r.ID)
				continue
			}
			if ids[r.ID] {
				c.errorf(doc, base+"/id", "schema.duplicate-id", "duplicate rule id %q", r.ID)
				continue
			}
			ids[r.ID] = true
		}
		if r.Outbound == "" {
			c.errorf(doc, base, "rule.outbound", "outbound is required")
			continue
		}
		if !targets[r.Outbound] {
			c.errorf(doc, base+"/outbound", "rule.outbound", "unknown outbound or group %q", r.Outbound)
			continue
		}
		spec, err := rc.condition(r.Match, 0)
		if err != nil {
			c.errorf(doc, base+"/match", "rule.match", "%s", err)
			continue
		}
		spec.ID, spec.Target = r.ID, r.Outbound
		kind := spec.Kind
		validated, ruleErr := router.CompileRules([]router.RuleSpec{spec})
		if err := ruleErr; err != nil {
			var re *router.RuleError
			msg := err.Error()
			if errors.As(err, &re) {
				msg = re.Err.Error()
				if re.Value != "" {
					msg = fmt.Sprintf("%q: %s", re.Value, msg)
				}
			}
			c.errorf(doc, base+"/match/"+r.Match.Kind, "rule.match", "%s", msg)
			continue
		}
		if catchAll >= 0 {
			c.warnf(doc, base, "rule.unreachable", "unreachable: the match-all rule at position %d always matches first", catchAll)
		}
		if kind == router.KindMatch && catchAll < 0 {
			catchAll = i
		}
		if validated.NeedsProcess() && !c.opts.ProcessLookup {
			c.warnf(doc, base, "rule.process", "this platform cannot identify processes; the rule never matches")
		}
		eff.Rules = append(eff.Rules, spec)
		eff.RuleIDs = append(eff.RuleIDs, r.ID)
		eff.RuleDescriptions = append(eff.RuleDescriptions, rc.ruleDescription(r, spec))
		b, _ := json.Marshal(spec)
		h.Write(b)
	}
	eff.RuleSetSelectors = rc.ruleSetSelectors()
	if catchAll < 0 && len(c.profile.Rules) > 0 && !c.diags.HasErrors() {
		c.warnf(doc, "/rules", "rule.no-final", "no match-all rule; connections no rule matches go direct")
	}
	if len(c.profile.Rules) == 0 {
		eff.setOrigin("/final", Origin{Layer: LayerDefault})
	}
	eff.RulesFingerprint = hex.EncodeToString(h.Sum(nil))[:16]
}

var logLevels = []string{"debug", "info", "warn", "error"}

func (c *compiler) listenersAndLocal(eff *Effective) {
	// Listeners: the local list replaces the profile's as a whole.
	listeners, doc, prefix := c.profile.Listeners, model.DocProfile, "/listeners"
	if c.local.Listeners != nil || hasKey(c.lpos, "/listeners") {
		c.override(eff, "/listeners")
		listeners, doc = c.local.Listeners, model.DocLocal
	}
	seen, addrs := map[string]bool{}, map[netip.AddrPort]string{}
	for i, l := range listeners {
		base := model.JoinPath(prefix, seg(l.ID, i))
		if !c.checkID(doc, base, l.ID) {
			continue
		}
		if seen[l.ID] {
			c.errorf(doc, base+"/id", "schema.duplicate-id", "duplicate listener id %q", l.ID)
			continue
		}
		seen[l.ID] = true
		if l.Type != model.ListenerMixed && l.Type != model.ListenerSOCKS && l.Type != model.ListenerHTTP {
			c.errorf(doc, base+"/type", "listener.type", "unsupported listener type %q (supported: mixed, socks, http)", l.Type)
			continue
		}
		ap, err := netip.ParseAddrPort(l.Listen)
		if err != nil || ap.Port() == 0 {
			c.errorf(doc, base+"/listen", "listener.listen", "listen must be an IP address and a non-zero port, for example 127.0.0.1:7890")
			continue
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if other, dup := addrs[ap]; dup {
			c.errorf(doc, base+"/listen", "listener.listen", "%s is already used by listener %q", ap, other)
			continue
		}
		addrs[ap] = l.ID
		if l.UDP != nil && *l.UDP && l.Type == model.ListenerHTTP {
			c.errorf(doc, base+"/udp", "listener.udp", "http listeners do not carry UDP")
		}
		udp := (l.UDP == nil || *l.UDP) && l.Type != model.ListenerHTTP
		users := c.listenerUsers(doc, base+"/users", l.Users)
		lst := Listener{ID: l.ID, Type: l.Type, Listen: ap, UDP: udp, Users: users}
		lst.Fingerprint = fingerprint(struct {
			Type  string
			UDP   bool
			Users []model.ListenerUser
		}{l.Type, udp, users})
		eff.Listeners = append(eff.Listeners, lst)
	}
	if listeners == nil {
		eff.setOrigin("/listeners", Origin{Layer: LayerDefault})
	}

	eff.LogLevel = "info"
	eff.setOrigin("/log/level", Origin{Layer: LayerDefault})
	if c.profile.Log != nil && c.profile.Log.Level != "" {
		eff.LogLevel = c.profile.Log.Level
		p := c.ppos["/log/level"]
		eff.setOrigin("/log/level", Origin{Layer: LayerProfile, Line: p.Line, Column: p.Column})
	}
	levelDoc := model.DocProfile
	if c.local.Log != nil && c.local.Log.Level != "" {
		c.override(eff, "/log/level")
		eff.LogLevel, levelDoc = c.local.Log.Level, model.DocLocal
	}
	if !slices.Contains(logLevels, eff.LogLevel) {
		c.errorf(levelDoc, "/log/level", "log.level", "log level must be one of %s", strings.Join(logLevels, ", "))
	}
	if c.local.Control != nil {
		c.override(eff, "/control")
		eff.Control = c.local.Control.Listen
	}
}

func hasKey(pos model.Positions, path string) bool {
	_, ok := pos[path]
	return ok
}

// override records that the local layer replaced everything under prefix.
func (c *compiler) override(eff *Effective, prefix string) {
	if eff.Provenance == nil {
		return
	}
	var replaced *Origin
	for p, o := range eff.Provenance {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			if p == prefix {
				o := o
				replaced = &o
			}
			delete(eff.Provenance, p)
		}
	}
	for p, pos := range c.lpos {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			o := Origin{Layer: LayerLocal, Line: pos.Line, Column: pos.Column}
			if p == prefix {
				o.Overrides = replaced
			}
			eff.Provenance[p] = o
		}
	}
}
