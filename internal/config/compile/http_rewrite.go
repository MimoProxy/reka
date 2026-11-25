package compile

import (
	"errors"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
)

var rewriteKinds = []string{"http-rewrites", "header-rewrites", "body-rewrites", "map-local", "scripts"}

// MITM contains the machine's HTTPS decryption settings and flow selectors.
type MITM struct {
	Enabled              bool                   `json:"enabled"`
	CA                   string                 `json:"ca,omitempty"`
	Hostnames            []string               `json:"hostnames"`
	ClientSourceAddress  []string               `json:"client-source-address,omitempty"`
	H2                   bool                   `json:"h2"`
	SkipServerCertVerify bool                   `json:"skip-server-cert-verify"`
	QUICBlock            bool                   `json:"quic-block"`
	ScriptLog            bool                   `json:"script-log"`
	Matcher              *httprewrite.Hostnames `json:"-"`
	ClientSourceMatcher  *ClientSourceMatcher   `json:"-"`
}

func (c *compiler) mitm(eff *Effective) {
	eff.MITM.QUICBlock = true
	// Surge defaults h2 to false. Reka turns it on: apps such as gRPC
	// clients cannot use an HTTP/1.1-only MITM handshake and fall back
	// slowly, and on-device tests kept HTTP/2 MITM within the iOS budget.
	eff.MITM.H2 = true
	settings := c.profile.MITM
	if settings == nil {
		settings = &model.MITM{}
	}
	eff.MITM.Hostnames = settings.Hostnames
	if len(settings.Hostnames) != 0 {
		eff.MITM.Matcher = c.compileMITMHostnames(settings.Hostnames)
	}
	eff.MITM.ClientSourceAddress = settings.ClientSourceAddress
	if len(settings.ClientSourceAddress) != 0 {
		eff.MITM.ClientSourceMatcher = c.compileMITMClientSources(settings.ClientSourceAddress)
	}
	for _, option := range []struct {
		name  string
		value *bool
		dest  *bool
	}{
		{"h2", settings.H2, &eff.MITM.H2},
		{"skip-server-cert-verify", settings.SkipServerCertVerify, &eff.MITM.SkipServerCertVerify},
		{"quic-block", settings.QUICBlock, &eff.MITM.QUICBlock},
	} {
		if option.value != nil {
			*option.dest = *option.value
		} else {
			eff.setOrigin("/mitm/"+option.name, Origin{Layer: LayerDefault})
		}
	}
	eff.setOrigin("/mitm/enabled", Origin{Layer: LayerDefault})
	eff.setOrigin("/mitm/script-log", Origin{Layer: LayerDefault})
	if local := c.local.MITM; local != nil {
		eff.MITM.Enabled, eff.MITM.CA = local.Enabled, local.CA
		eff.MITM.ScriptLog = local.ScriptLog
		for _, path := range []string{"/mitm/enabled", "/mitm/ca", "/mitm/script-log"} {
			if pos, ok := c.lpos[path]; ok {
				eff.setOrigin(path, Origin{Layer: LayerLocal, Document: model.DocLocal, Path: path, Line: pos.Line, Column: pos.Column})
			}
		}
		if local.Enabled || hasKey(c.lpos, "/mitm/ca") {
			if ref := secret.Ref(ca.SecretName); local.CA != ref {
				c.errorf(model.DocLocal, "/mitm/ca", "mitm.ca", "MITM CA requires %s", ref)
			}
		}
	}
}

func (c *compiler) compileMITMHostnames(entries []string) *httprewrite.Hostnames {
	matcher, err := httprewrite.NewHostnames(entries)
	var invalid httprewrite.HostnameErrors
	if errors.As(err, &invalid) {
		for _, issue := range invalid {
			path := model.JoinPath("/mitm/hostnames", "#"+strconv.Itoa(issue.Index))
			c.errorf(model.DocProfile, path, "mitm.hostname", "%v", issue.Err)
		}
	}
	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		if seen[entry] {
			path := model.JoinPath("/mitm/hostnames", "#"+strconv.Itoa(i))
			c.warnf(model.DocProfile, path, "mitm.duplicate-hostname", "duplicate MITM hostname %q", entry)
		}
		seen[entry] = true
	}
	return matcher
}

func (c *compiler) httpRewrites(eff *Effective) {
	p := c.profile
	if len(p.HTTPRewrites)+len(p.HeaderRewrites)+len(p.BodyRewrites)+len(p.MapLocal) == 0 {
		if len(c.moduleDigests) != 0 {
			eff.HTTPRewriteFingerprint = fingerprint(c.moduleDigests)
		}
		return
	}
	paths := make(map[string][]string, len(rewriteKinds))
	seen := make(map[string]bool)
	pathFor := func(kind, id string, i int) string {
		path := model.JoinPath("", kind, seg(id, i))
		paths[kind] = append(paths[kind], path)
		if c.checkID(model.DocProfile, path, id) {
			if seen[path] {
				c.errorf(model.DocProfile, path+"/id", "schema.duplicate-id", "duplicate %s id %q", kind, id)
			}
			seen[path] = true
		}
		return path
	}
	spec := httprewrite.Spec{
		HTTPRewrites:   make([]httprewrite.HTTPRewrite, len(p.HTTPRewrites)),
		HeaderRewrites: make([]httprewrite.HeaderRewrite, len(p.HeaderRewrites)),
		BodyRewrites:   make([]httprewrite.BodyRewrite, len(p.BodyRewrites)),
		MapLocal:       make([]httprewrite.MapLocal, len(p.MapLocal)),
	}
	for i, rule := range p.HTTPRewrites {
		pathFor("http-rewrites", rule.ID, i)
		spec.HTTPRewrites[i] = httprewrite.HTTPRewrite{
			ID: rule.ID, Match: rule.Match, Action: rule.Action, Target: rule.Target, Response: rule.Response,
		}
	}
	for i, rule := range p.HeaderRewrites {
		pathFor("header-rewrites", rule.ID, i)
		spec.HeaderRewrites[i] = httprewrite.HeaderRewrite{
			ID: rule.ID, Phase: rule.Phase, Match: rule.Match, Op: rule.Op, Name: rule.Name, Pattern: rule.Pattern, Value: rule.Value,
		}
	}
	for i, rule := range p.BodyRewrites {
		pathFor("body-rewrites", rule.ID, i)
		body := httprewrite.BodyRewrite{ID: rule.ID, Phase: rule.Phase, Match: rule.Match, JQ: rule.JQ}
		if rule.Replace != nil {
			body.Replace = make([]httprewrite.Replacement, len(rule.Replace))
			for n, pair := range rule.Replace {
				body.Replace[n] = httprewrite.Replacement{Pattern: pair.Pattern, Value: pair.Value}
			}
		}
		spec.BodyRewrites[i] = body
	}
	for i, rule := range p.MapLocal {
		path := pathFor("map-local", rule.ID, i)
		entry := httprewrite.MapLocal{
			ID: rule.ID, Match: rule.Match, DataType: rule.DataType, Data: rule.Data, Hash: rule.Hash, StatusCode: rule.StatusCode,
			Headers: make([]httprewrite.Header, len(rule.Headers)),
		}
		if rule.Download != nil {
			entry.DownloadURL = &rule.Download.URL
		}
		if rule.DataType == nil || *rule.DataType == "file" {
			c.validateMapLocalFile(path, rule)
		}
		for n, header := range rule.Headers {
			entry.Headers[n] = httprewrite.Header{Name: header.Name, Value: header.Value}
		}
		spec.MapLocal[i] = entry
	}
	set, err := httprewrite.New(spec, httprewrite.Options{MaxBodySize: MITMMaxBodySize, ReadResource: c.opts.ReadResource})
	var invalid httprewrite.ValidationErrors
	if errors.As(err, &invalid) {
		for _, issue := range invalid {
			path := paths[issue.Kind][issue.Index]
			if issue.Field != "" {
				path += "/" + issue.Field
			}
			c.errorf(model.DocProfile, path, "rewrite.invalid", "%v", issue.Err)
		}
		return
	}
	if err != nil {
		c.errorf(model.DocProfile, "/http-rewrites", "rewrite.invalid", "%v", err)
		return
	}
	for _, issue := range set.Warnings() {
		c.warnf(model.DocProfile, paths[issue.Kind][issue.Index]+"/"+issue.Field, "rewrite.capture", "%v", issue.Err)
	}
	eff.HTTPRewrite = set
	eff.HTTPRewriteFingerprint = fingerprint(struct {
		HTTP   []model.HTTPRewrite
		Header []model.HeaderRewrite
		Body   []model.BodyRewrite
		Local  []model.MapLocal
	}{p.HTTPRewrites, p.HeaderRewrites, p.BodyRewrites, p.MapLocal}, c.moduleDigests...)
}

func (c *compiler) validateMapLocalFile(path string, rule model.MapLocal) {
	if err := validateDownload(rule.Download); err != nil {
		c.errorf(model.DocProfile, path+"/download", "resource.download", "%v", err)
	}
	if rule.Hash == nil || *rule.Hash == "" {
		return // The engine reports the missing hash.
	}
	if !resource.ValidHash(*rule.Hash) || c.opts.ReadResource == nil {
		c.errorf(model.DocProfile, path+"/hash", "rewrite.resource", "map-local file requires a locked resource hash")
		return
	}
	data, err := c.opts.ReadResource(*rule.Hash)
	if err != nil {
		c.errorf(model.DocProfile, path+"/hash", "rewrite.resource", "read map-local resource: %v", err)
	} else if len(data) > httprewrite.MaxMapLocalSize {
		c.errorf(model.DocProfile, path+"/hash", "rewrite.resource", "map-local file exceeds %d bytes", httprewrite.MaxMapLocalSize)
	} else if resource.Hash(data) != *rule.Hash {
		c.errorf(model.DocProfile, path+"/hash", "rewrite.resource", "map-local resource hash mismatch")
	}
}

// A missing rewrite field has no recorded origin. Locate its containing
// resource and retain the field suffix in the source document's path.
func diagnosticOrigin(origins map[string]Origin, path string) (Origin, bool) {
	for _, kind := range rewriteKinds {
		if strings.HasPrefix(path, "/"+kind+"/") {
			for parent := path; parent != ""; parent = parent[:strings.LastIndexByte(parent, '/')] {
				if o, ok := origins[parent]; ok {
					o.Path += path[len(parent):]
					return o, true
				}
			}
			return Origin{}, false
		}
	}
	return originAt(origins, path)
}
