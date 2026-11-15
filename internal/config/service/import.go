package service

import (
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
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
	return importer.Import(req).Preview(reveal)
}
func mergeImport(sources []byte, req *importer.Request) ([]byte, error) {
	result := importer.Import(*req)
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
