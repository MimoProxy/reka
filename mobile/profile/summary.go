package profile

import (
	"encoding/json"
	"slices"
	"strconv"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
)

// ModuleSummary describes a declared module, including shadowed device entries.
// Use ModuleReport for the line-by-line report of an effective module.
type ModuleSummary struct {
	ID        string                   `json:"id"`
	Enabled   bool                     `json:"enabled"`
	Origin    string                   `json:"origin"`
	Shadowed  bool                     `json:"shadowed,omitempty"`
	Format    string                   `json:"format,omitempty"`
	Name      string                   `json:"name,omitempty"`
	Desc      string                   `json:"desc,omitempty"`
	Arguments []module.Argument        `json:"arguments,omitempty"`
	Report    *api.ModuleReportSummary `json:"report,omitempty"`
	Hostnames []string                 `json:"hostnames,omitempty"`
}

// MITMSummary shows the effective settings and ordered hostname selectors.
type MITMSummary struct {
	Enabled              bool           `json:"enabled"`
	H2                   bool           `json:"h2"`
	SkipServerCertVerify bool           `json:"skipServerCertVerify"`
	QUICBlock            bool           `json:"quicBlock"`
	Hostnames            []MITMHostname `json:"hostnames"`
}

// MITMHostname identifies the layer and, for a source or module, its ID.
type MITMHostname struct {
	Hostname string `json:"hostname"`
	Layer    string `json:"layer"`
	Source   string `json:"source,omitempty"`
}

func (b *Bundle) describePreparation(eff *compile.Effective, profile *model.Profile, options PrepareOptions, shadowed []ModuleSummary) Summary {
	summary := Describe(eff)
	var hostsByModule map[string][]string
	if hasMITMSettings(eff) {
		settings := eff.MITM
		summary.MITM = &MITMSummary{
			Enabled: settings.Enabled, H2: settings.H2, SkipServerCertVerify: settings.SkipServerCertVerify, QUICBlock: settings.QUICBlock,
			Hostnames: make([]MITMHostname, 0, len(settings.Hostnames)),
		}
		hostsByModule = make(map[string][]string)
		for i, hostname := range settings.Hostnames {
			origin, _ := eff.OriginOf("/mitm/hostnames/#" + strconv.Itoa(i))
			if origin.Layer == "" {
				origin.Layer = compile.LayerProfile
			}
			summary.MITM.Hostnames = append(summary.MITM.Hostnames, MITMHostname{Hostname: hostname, Layer: origin.Layer, Source: origin.Source})
			if origin.Layer == compile.LayerModule {
				hostsByModule[origin.Source] = append(hostsByModule[origin.Source], hostname)
			}
		}
	}
	for _, def := range profile.Modules {
		entry := ModuleSummary{ID: def.ID, Enabled: def.IsEnabled(), Origin: "profile", Format: def.Format}
		if slices.Contains(b.DeviceModules, def.ID) {
			entry.Origin = "device"
		}
		if report, ok := eff.Modules[def.ID]; ok {
			entry.Format, entry.Name, entry.Desc, entry.Arguments = report.Format, report.Name, report.Desc, report.Arguments
			entry.Report = &api.ModuleReportSummary{Partial: report.Partial, CanApply: report.CanApply,
				Rules: report.Rules, Rewrites: report.Rewrites, Hostnames: report.Hostnames}
			entry.Hostnames = hostsByModule[def.ID]
			if len(entry.Hostnames) != report.Hostnames.Imported {
				// An overlay can edit or remove the module's contributed hosts.
				entry.Hostnames = b.moduleHostnames(def)
			}
		} else if path := options.Modules[def.ID]; path != "" {
			if snapshot, err := LoadModuleSnapshot(path); err == nil && snapshot.matches(def) {
				meta, _ := module.InspectWithOptions(snapshot.readRoot(), module.Options{
					Format: snapshot.Source.Module.Format, Arguments: def.Arguments,
				})
				entry.Format, entry.Name, entry.Desc, entry.Arguments = snapshot.Source.Module.Format, meta.Name, meta.Desc, meta.Arguments
			}
		} else if options.Modules == nil && (entry.Origin == "profile" || options.DeviceModules == nil) {
			for _, previous := range b.Summary.Modules {
				if previous.ID == def.ID && !previous.Enabled && !previous.Shadowed &&
					(previous.Origin == entry.Origin || previous.Origin == "" && entry.Origin == "profile") &&
					(def.Format == "" || previous.Format == def.Format) {
					entry.Format, entry.Name, entry.Desc, entry.Arguments = previous.Format, previous.Name, previous.Desc, previous.Arguments
					break
				}
			}
		}
		summary.Modules = append(summary.Modules, entry)
	}
	summary.Modules = append(summary.Modules, shadowed...)
	return summary
}

func hasMITMSettings(eff *compile.Effective) bool {
	if len(eff.MITM.Hostnames) > 0 || eff.MITM.CA != "" {
		return true
	}
	for _, field := range []string{"h2", "skip-server-cert-verify", "quic-block"} {
		if origin, ok := eff.OriginOf("/mitm/" + field); ok && origin.Layer != compile.LayerDefault {
			return true
		}
	}
	return false
}

func (b *Bundle) moduleHostnames(def model.Module) []string {
	var doc sourceDocument
	if json.Unmarshal(b.Sources, &doc) != nil {
		return nil
	}
	for _, value := range doc.Sources {
		var entry sourceResources
		if json.Unmarshal(value, &entry) != nil || entry.ID != def.ID || entry.Module == nil || entry.Lock == nil {
			continue
		}
		converted, _ := module.Convert(b.Resources[entry.Lock.Root], module.Options{
			ID: def.ID, Format: entry.Module.Format, Arguments: def.Arguments,
		})
		var hostnames []string
		for _, list := range [][]module.Hostname{converted.InsertHostnames, converted.AppendHostnames} {
			for _, hostname := range list {
				hostnames = append(hostnames, hostname.Value)
			}
		}
		return hostnames
	}
	return nil
}
