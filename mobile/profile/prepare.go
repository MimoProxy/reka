package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/subscription"
)

const geodataURL = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"

type resourceLoader func(context.Context, string, string, http.Header) ([]byte, error)

// PrepareFile runs in the foreground app's profile worker, never in the
// extension. Publish the snapshot atomically after validation.
func PrepareFile(ctx context.Context, input, output, geodataCache string) error {
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > model.MaxDocumentSize {
		return errors.New("cannot read profile")
	}
	client := subscription.HTTPClient(nil)
	defer client.CloseIdleConnections()
	load := func(ctx context.Context, name, address string, headers http.Header) ([]byte, error) {
		cachedFile := ""
		if name != "" {
			cachedFile = filepath.Join(geodataCache, name)
			if info, err := os.Stat(cachedFile); err == nil && info.Size() <= 32<<20 && time.Since(info.ModTime()) < 7*24*time.Hour {
				if data, err := os.ReadFile(cachedFile); err == nil && len(data) != 0 {
					return data, nil
				}
			}
		}
		data, err := download(ctx, client, address, headers)
		if err == nil && cachedFile != "" {
			_ = os.MkdirAll(geodataCache, 0700)
			_ = writeAtomic(cachedFile, data)
		}
		return data, err
	}
	bundle, err := prepare(ctx, raw, load)
	if err != nil {
		return err
	}
	data, err := json.Marshal(bundle)
	if err != nil || len(data) > MaxBundleBytes {
		return errors.New("prepared rules and resources exceed the 4 MiB extension configuration budget")
	}
	return writeAtomic(output, data)
}

func prepare(ctx context.Context, raw []byte, load resourceLoader) (*Bundle, error) {
	var document map[string]any
	root, diagnostics := model.ParseNode(model.DocProfile, raw)
	if root != nil && !diagnostics.HasErrors() {
		// The native compiler validates aliases, field types and version before
		// accepting input. Foreign YAML is decoded only by the Clash importer.
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value == "schema-version" {
				if _, _, ds := model.ParseProfile(raw); ds.HasErrors() {
					return nil, diagnosticError("invalid profile", ds)
				}
				if root.Decode(&document) != nil {
					return nil, errors.New("invalid native profile")
				}
				break
			}
		}
	}
	bundle := &Bundle{Version: bundleVersion}
	if document == nil {
		req := importer.Request{SourceID: "ios", Data: string(raw)}
		providers, err := importer.Providers(req)
		if err != nil {
			return nil, errors.New("invalid subscription or provider reference")
		}
		payloads := make(map[string][]byte, len(providers))
		bundle.Resources = make(map[string][]byte)
		total := 0
		for _, provider := range providers {
			data := provider.Inline
			if provider.Type == "http" {
				if provider.Proxy != "" && provider.Proxy != "DIRECT" {
					return nil, errors.New("provider download requires a proxy route")
				}
				data, err = load(ctx, "", provider.URL, provider.Headers)
				if err != nil {
					return nil, fmt.Errorf("could not download %s provider", provider.Kind)
				}
			}
			if importer.ValidateProvider(provider, data) != nil {
				return nil, fmt.Errorf("could not read %s provider payload", provider.Kind)
			}
			total += len(data)
			if total > 32<<20 {
				return nil, errors.New("subscription providers exceed 32 MiB")
			}
			payloads[provider.ID] = data
			if provider.Kind == "rule" {
				bundle.Resources[resource.Hash(data)] = data
			}
		}
		selectors, err := importer.GeodataSelectors(req, payloads)
		if err != nil {
			return nil, errors.New("invalid subscription geodata reference")
		}
		byKind := map[string][]string{}
		for _, selector := range selectors {
			kind, code, _ := strings.Cut(selector, ":")
			byKind[kind] = append(byKind[kind], code)
		}
		geodata := make(map[string][]byte, len(byKind))
		for kind, selectors := range byKind {
			name := kind + ".dat"
			if kind == "asn" {
				name = "GeoLite2-ASN.mmdb"
			}
			data, err := load(ctx, name, geodataURL+name, nil)
			if err == nil && kind != "asn" {
				data, err = rulesdata.SubsetDAT(data, selectors)
			}
			if err != nil {
				return nil, fmt.Errorf("could not load %s rules", kind)
			}
			geodata[kind] = data
			bundle.Resources[resource.Hash(data)] = data
		}
		result := importer.ImportBundle(req, payloads, geodata)
		if !result.Report.CanApply {
			return nil, diagnosticError("subscription contains unsupported settings", result.Report.Diagnostics)
		}
		if json.Unmarshal(result.Source, &document) != nil || document == nil {
			return nil, errors.New("could not convert subscription")
		}
		delete(document, "id")
		document["schema-version"] = model.SchemaVersion
	}

	// The app owns VPN routes and the packet flow. Keep listeners (including
	// DNS listeners) out of the desktop engine's runtime on the phone.
	delete(document, "listeners")
	dns, ok := document["dns"].(map[string]any)
	if !ok {
		dns = map[string]any{
			"nameserver": []string{"1.1.1.1"}, "enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.0/16", "ipv6": true,
		}
		document["dns"] = dns
	}
	delete(dns, "listen")
	if size, ok := dns["cache-size"].(float64); !ok || size == 0 || size > 512 {
		dns["cache-size"] = 512
	}
	if n, ok := dns["max-concurrent-upstreams"].(float64); !ok || n == 0 || n > 2 {
		dns["max-concurrent-upstreams"] = 2
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("could not encode profile")
	}
	bundle.Profile = data
	eff, err := bundle.Compile()
	if err != nil {
		return nil, err
	}
	bundle.Summary = Describe(eff)
	return bundle, nil
}

func download(ctx context.Context, client *http.Client, address string, headers http.Header) ([]byte, error) {
	if !subscription.ValidURL(address) {
		return nil, errors.New("invalid resource URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("invalid resource request")
	}
	if len(headers) > 0 {
		req.Header = headers.Clone()
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("resource request failed")
	}
	defer response.Body.Close()
	const maxBytes = 32 << 20
	if response.StatusCode != http.StatusOK || response.ContentLength > maxBytes {
		return nil, errors.New("resource response rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxBytes {
		return nil, errors.New("resource response exceeds limits")
	}
	return data, nil
}

func writeAtomic(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".reka-profile-*")
	if err != nil {
		return errors.New("could not open profile storage")
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || os.Rename(file.Name(), path) != nil {
		return errors.New("could not save profile snapshot")
	}
	return nil
}
