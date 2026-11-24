package control

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
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
		return installMITMCA(store, p.Replace, func() (*ca.Authority, error) {
			return ca.Generate(ca.GenerateOptions{})
		})
	case "ImportMITMCA":
		p, err := decode[api.ImportMITMCARequest](req.Params)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "invalid MITM CA import parameters"}
		}
		return installMITMCA(store, p.Replace, func() (*ca.Authority, error) {
			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.PKCS12))
			if err != nil {
				return nil, &service.Error{Code: service.CodeBadRequest, Message: "pkcs12 must be standard base64"}
			}
			a, err := ca.ImportPKCS12(data, p.Password, time.Now())
			if err != nil {
				return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
			}
			return a, nil
		})
	case "GetMITMCA", "ExportMITMCA":
		var format string
		if req.Method == "ExportMITMCA" {
			p, err := decode[api.ExportMITMCARequest](req.Params)
			if err != nil {
				return nil, err
			}
			format = p.Format
			if format == "" {
				format = "pem"
			}
			if format != "pem" && format != "der" {
				return nil, &service.Error{Code: service.CodeBadRequest, Message: "format must be pem or der"}
			}
		}
		a, err := ca.Load(store)
		if errors.Is(err, ca.ErrNotFound) {
			if req.Method == "GetMITMCA" {
				return api.MITMCAStatus{}, nil
			}
			return nil, &service.Error{Code: service.CodeNotFound, Message: "no MITM CA installed"}
		}
		if err != nil {
			return nil, &service.Error{Code: CodeInternal, Message: "failed to load MITM CA"}
		}
		if req.Method == "GetMITMCA" {
			return mitmCAStatus(a), nil
		}
		result := api.ExportMITMCAResult{Format: format, FingerprintSHA256: a.Info().FingerprintSHA256}
		if format == "der" {
			result.Data = base64.StdEncoding.EncodeToString(a.CertificateDER())
		} else {
			result.Data = string(a.CertificatePEM())
		}
		return result, nil
	case "DeleteMITMCA":
		if err := ca.Delete(store); errors.Is(err, ca.ErrNotFound) {
			return nil, &service.Error{Code: service.CodeNotFound, Message: "no MITM CA installed"}
		} else if err != nil {
			return nil, &service.Error{Code: CodeInternal, Message: "failed to delete MITM CA"}
		}
		return api.DeleteMITMCAResult{Deleted: true}, nil
	}
	return nil, &service.Error{Code: CodeUnknownMethod, Message: "unknown MITM CA method"}
}

func installMITMCA(store secret.Store, replace bool, create func() (*ca.Authority, error)) (api.MITMCAStatus, error) {
	if !replace {
		if _, err := store.Get(ca.SecretName); err == nil {
			return api.MITMCAStatus{}, &service.Error{Code: service.CodeConflict, Message: "MITM CA already installed; use replace:true to replace it"}
		} else if !errors.Is(err, secret.ErrNotFound) {
			return api.MITMCAStatus{}, &service.Error{Code: CodeInternal, Message: "failed to check for a stored MITM CA"}
		}
	}
	a, err := create()
	if err != nil {
		return api.MITMCAStatus{}, err
	}
	if err := ca.Save(store, a); err != nil {
		return api.MITMCAStatus{}, &service.Error{Code: CodeInternal, Message: "failed to save MITM CA"}
	}
	return mitmCAStatus(a), nil
}

func mitmCAStatus(a *ca.Authority) api.MITMCAStatus {
	info := a.Info()
	return api.MITMCAStatus{
		Installed:         true,
		Ref:               secret.Ref(ca.SecretName),
		Subject:           info.Subject,
		FingerprintSHA256: info.FingerprintSHA256,
		SerialNumber:      info.SerialNumber,
		KeyType:           info.KeyType,
		NotBefore:         info.NotBefore,
		NotAfter:          info.NotAfter,
		Expired:           time.Now().After(info.NotAfter),
	}
}
