package service

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

type importFailure struct{ report importer.Report }

func (e *importFailure) Error() string {
	return "subscription conversion is incomplete or invalid; review ImportSource diagnostics"
}
func (e *importFailure) diagnostics() model.Diagnostics {
	out := append(model.Diagnostics{}, e.report.Diagnostics...)
	if !out.HasErrors() {
		out = append(out, model.Diagnostic{Severity: model.SeverityError, Code: "import.blocked", Document: e.report.Format, Path: "/", Message: e.Error()})
	}
	return out
}

// PreviewImport converts locally, masks credentials by default, and never
// changes configuration or fetches provider URLs.
func (s *Service) PreviewImport(req importer.Request, reveal bool) importer.Preview {
	result, err := s.convertImport(req)
	if err != nil {
		return importer.Preview{Report: importer.Report{SourceID: req.SourceID, Format: req.Format, Diagnostics: model.Diagnostics{{Severity: model.SeverityError, Code: "import.resource", Document: req.Format, Path: "/", Message: err.Error()}}}}
	}
	return result.Preview(reveal)
}
func (s *Service) mergeImport(sources []byte, req *importer.Request) ([]byte, error) {
	result, err := s.convertImport(*req)
	if err != nil {
		return nil, errf(CodeInvalid, "import resources: %v", err)
	}
	if !result.Report.CanApply {
		return nil, &importFailure{report: result.Report}
	}
	if _, _, ds := model.ParseSources(sources); ds.HasErrors() {
		return nil, errf(CodeInvalid, "sources: %s", ds.Errors().Error())
	}
	doc, ds := model.LoadDoc(model.DocSources, sources)
	if ds.HasErrors() {
		return nil, errf(CodeInvalid, "sources: %s", ds.Errors().Error())
	}
	path := model.JoinPath("/sources", req.SourceID)
	op := model.Op{Op: "set", Path: path, Value: result.Source}
	if doc.Get(path) == nil {
		op.Op, op.Path = "insert", "/sources"
	}
	if err := doc.Apply(op); err != nil {
		return nil, errf(CodeBadRequest, "source import: %v", err)
	}
	return doc.Bytes(), nil
}

func (s *Service) convertImport(req importer.Request) (importer.Result, error) {
	if len(req.ProviderResources) == 0 && len(req.GeodataResources) == 0 {
		return importer.Import(req), nil
	}
	if len(req.ProviderResources) > 1024 || len(req.GeodataResources) > 3 {
		return importer.Result{}, fmt.Errorf("too many import resources")
	}
	providers, err := importer.Providers(req)
	if err != nil {
		return importer.Result{}, err
	}
	aliases, ids, scoped, ambiguous := map[string]string{}, map[string]string{}, map[string]string{}, map[string]bool{}
	for _, provider := range providers {
		ids[provider.ID] = provider.ID
		scoped[provider.Kind+":"+provider.Name] = provider.ID
		scoped[provider.Kind+"-providers/"+provider.Name] = provider.ID
		if old := aliases[provider.Name]; old != "" && old != provider.ID {
			ambiguous[provider.Name] = true
		} else {
			aliases[provider.Name] = provider.ID
		}
	}
	store := resource.At(s.store.Root())
	seen, total := map[string][]byte{}, 0
	read := func(hash string) ([]byte, error) {
		if data, ok := seen[hash]; ok {
			return data, nil
		}
		data, err := store.Read(hash)
		if err != nil {
			return nil, fmt.Errorf("resource is missing or corrupt")
		}
		total += len(data)
		if total > 384<<20 {
			return nil, fmt.Errorf("import resource bundle exceeds 384 MiB")
		}
		seen[hash] = data
		return data, nil
	}
	payloads, geodata := map[string][]byte{}, map[string][]byte{}
	for key, hash := range req.ProviderResources {
		id := ids[key]
		if id == "" {
			id = scoped[key]
		}
		if id == "" && !ambiguous[key] {
			id = aliases[key]
		}
		if id == "" {
			return importer.Result{}, fmt.Errorf("provider resource needs an exact ID or unambiguous name")
		}
		if _, exists := payloads[id]; exists {
			return importer.Result{}, fmt.Errorf("duplicate provider resource")
		}
		data, err := read(hash)
		if err != nil {
			return importer.Result{}, err
		}
		payloads[id] = data
	}
	for key, hash := range req.GeodataResources {
		if key != "geoip" && key != "geosite" && key != "asn" {
			return importer.Result{}, fmt.Errorf("geodata key must be geoip, geosite or asn")
		}
		data, err := read(hash)
		if err != nil {
			return importer.Result{}, err
		}
		geodata[key] = data
	}
	return importer.ImportBundle(req, payloads, geodata), nil
}
