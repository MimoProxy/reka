package control

import (
	"context"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/mitm/caops"
)

func isMITMCAMethod(method string) bool {
	switch method {
	case "GenerateMITMCA", "ImportMITMCA", "GetMITMCA", "ExportMITMCA", "DeleteMITMCA":
		return true
	}
	return false
}

func (h *Handler) handleMITMCA(req Request) (any, error) {
	store := h.svc.Secrets()
	if store == nil {
		return nil, &service.Error{Code: CodeInternal, Message: "no secret store"}
	}
	// Keep the existence check and write atomic across control sessions.
	h.mitmCAMu.Lock()
	defer h.mitmCAMu.Unlock()
	switch req.Method {
	case "GenerateMITMCA":
		p, err := decode[api.GenerateMITMCARequest](req.Params)
		if err != nil {
			return nil, err
		}
		return caops.Generate(context.Background(), store, p.Replace)
	case "ImportMITMCA":
		p, err := decode[api.ImportMITMCARequest](req.Params)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "invalid MITM CA import parameters"}
		}
		return caops.Import(context.Background(), store, p)
	case "GetMITMCA":
		return caops.Status(store)
	case "ExportMITMCA":
		p, err := decode[api.ExportMITMCARequest](req.Params)
		if err != nil {
			return nil, err
		}
		return caops.Export(store, p.Format)
	case "DeleteMITMCA":
		return caops.Delete(store)
	}
	return nil, &service.Error{Code: CodeUnknownMethod, Message: "unknown MITM CA method"}
}
