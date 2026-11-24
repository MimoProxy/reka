// Package caops implements the daemon and mobile app's shared CA operations.
package caops

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
)

func Generate(ctx context.Context, store secret.Store, replace bool) (api.MITMCAStatus, error) {
	return install(ctx, store, replace, func() (*ca.Authority, error) {
		a, err := ca.Generate(ca.GenerateOptions{})
		if err != nil {
			return nil, &api.Error{Code: api.CodeInternal, Message: err.Error()}
		}
		return a, nil
	})
}

func Import(ctx context.Context, store secret.Store, req api.ImportMITMCARequest) (api.MITMCAStatus, error) {
	return install(ctx, store, req.Replace, func() (*ca.Authority, error) {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PKCS12))
		defer clear(data)
		if err != nil {
			return nil, &api.Error{Code: "bad_request", Message: "pkcs12 must be standard base64"}
		}
		a, err := ca.ImportPKCS12(data, req.Password, time.Now())
		if err != nil {
			return nil, &api.Error{Code: "bad_request", Message: err.Error()}
		}
		return a, nil
	})
}

// The caller serializes store access for check-and-install.
func install(ctx context.Context, store secret.Store, replace bool, create func() (*ca.Authority, error)) (api.MITMCAStatus, error) {
	if err := ctx.Err(); err != nil {
		return api.MITMCAStatus{}, err
	}
	if !replace {
		if _, err := store.Get(ca.SecretName); err == nil {
			return api.MITMCAStatus{}, &api.Error{Code: "conflict", Message: "MITM CA already installed; use replace:true to replace it"}
		} else if !errors.Is(err, secret.ErrNotFound) {
			return api.MITMCAStatus{}, &api.Error{Code: api.CodeInternal, Message: "failed to check for a stored MITM CA"}
		}
	}
	if err := ctx.Err(); err != nil {
		return api.MITMCAStatus{}, err
	}
	a, err := create()
	if err != nil {
		return api.MITMCAStatus{}, err
	}
	if err := ctx.Err(); err != nil {
		return api.MITMCAStatus{}, err
	}
	if err := ca.Save(store, a); err != nil {
		return api.MITMCAStatus{}, &api.Error{Code: api.CodeInternal, Message: "failed to save MITM CA"}
	}
	return status(a), nil
}

func Status(store secret.Store) (api.MITMCAStatus, error) {
	a, err := ca.Load(store)
	if errors.Is(err, ca.ErrNotFound) {
		return api.MITMCAStatus{}, nil
	}
	if err != nil {
		return api.MITMCAStatus{}, loadError(err)
	}
	return status(a), nil
}

func status(a *ca.Authority) api.MITMCAStatus {
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

func Export(store secret.Store, format string) (api.ExportMITMCAResult, error) {
	if format == "" {
		format = "pem"
	}
	if format != "pem" && format != "der" {
		return api.ExportMITMCAResult{}, &api.Error{Code: "bad_request", Message: "format must be pem or der"}
	}
	a, err := LoadInstalled(store)
	if err != nil {
		return api.ExportMITMCAResult{}, err
	}
	result := api.ExportMITMCAResult{Format: format, FingerprintSHA256: a.Info().FingerprintSHA256}
	if format == "der" {
		result.Data = base64.StdEncoding.EncodeToString(a.CertificateDER())
	} else {
		result.Data = string(a.CertificatePEM())
	}
	return result, nil
}

func Delete(store secret.Store) (api.DeleteMITMCAResult, error) {
	if err := ca.Delete(store); errors.Is(err, ca.ErrNotFound) {
		return api.DeleteMITMCAResult{}, loadError(err)
	} else if err != nil {
		return api.DeleteMITMCAResult{}, &api.Error{Code: api.CodeInternal, Message: "failed to delete MITM CA"}
	}
	return api.DeleteMITMCAResult{Deleted: true}, nil
}

// LoadInstalled loads the CA and maps failures to errors safe for clients.
func LoadInstalled(store secret.Store) (*ca.Authority, error) {
	a, err := ca.Load(store)
	if err != nil {
		return nil, loadError(err)
	}
	return a, nil
}

func loadError(err error) error {
	if errors.Is(err, ca.ErrNotFound) {
		return &api.Error{Code: "not_found", Message: "no MITM CA installed"}
	}
	return &api.Error{Code: api.CodeInternal, Message: "failed to load MITM CA"}
}
