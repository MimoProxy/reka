package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/secret"
)

var errInvalidSnapshot = errors.New("invalid profile snapshot")

// CompileSnapshot borrows the input only for this call. Resource values are
// indexed in place and decoded only when requested by the compiler.
func CompileSnapshot(data []byte, secrets secret.Store) (*compile.Effective, error) {
	var bundle Bundle
	resources := make(map[string][]byte)
	snapshot := struct {
		*Bundle
		Resources resourceIndex `json:"resources"`
		Summary   struct{}      `json:"summary"`
	}{
		Bundle: &bundle,
		Resources: func(object []byte) error {
			if bytes.Equal(object, []byte("null")) {
				clear(resources)
				return nil
			}
			// Use slices of the caller's input, which outlives UnmarshalJSON.
			start := bytes.Index(data, object)
			if start < 0 {
				return errInvalidSnapshot
			}
			return indexResources(data[start:start+len(object)], resources)
		},
	}
	if len(data) > MaxBundleBytes || json.Unmarshal(data, &snapshot) != nil || bundle.Version != bundleVersion {
		return nil, errInvalidSnapshot
	}
	rawResource := func(hash string) []byte {
		raw := resources[hash]
		if len(raw) > MaxBundleBytes/8 {
			// Clear document parsing allocations before loading a large resource.
			runtime.GC()
		}
		return raw
	}
	read := func(hash string) ([]byte, error) {
		var value []byte
		if raw := rawResource(hash); raw != nil && json.Unmarshal(raw, &value) == nil && value != nil {
			return value, nil
		}
		return nil, bundle.missingResource(hash)
	}
	opts := bundle.compileOptions(read, secrets, false)
	opts.ReadPrecompiledRuleSet = bundle.Precompiled.reader(func(hash string) (*router.PrecompiledRuleSet, []byte) {
		return streamPrecompiledRuleSet(rawResource(hash), hash), nil
	})
	return bundle.compileEffective(opts)
}

// Decode Base64 directly into the matcher reader while verifying the digest.
func streamPrecompiledRuleSet(raw []byte, digest string) *router.PrecompiledRuleSet {
	if len(raw) < 2 || raw[0] != '"' {
		return nil
	}
	encoded := raw[1 : len(raw)-1]
	if bytes.IndexByte(encoded, '\\') >= 0 {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return nil
		}
		encoded = []byte(text)
	}
	hash := sha256.New()
	decoded := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded))
	set := readPrecompiledRuleSet(io.TeeReader(decoded, hash))
	if set == nil || hex.EncodeToString(hash.Sum(nil)) != digest {
		return nil
	}
	return set
}

type resourceIndex func([]byte) error

func (index resourceIndex) UnmarshalJSON(data []byte) error { return index(data) }

// Unmarshal has already checked JSON syntax. Index only the string or null
// members allowed by the snapshot's map[string][]byte resource field.
func indexResources(object []byte, resources map[string][]byte) error {
	if len(object) < 2 || object[0] != '{' {
		return errInvalidSnapshot
	}
	rest := bytes.TrimSpace(object[1 : len(object)-1])
	for len(rest) > 0 {
		var hash string
		end := quotedEnd(rest)
		if end == 0 || json.Unmarshal(rest[:end], &hash) != nil {
			return errInvalidSnapshot
		}
		rest = bytes.TrimSpace(bytes.TrimSpace(rest[end:])[1:]) // Colon.
		end = quotedEnd(rest)
		if bytes.HasPrefix(rest, []byte("null")) {
			end = 4
		}
		if end == 0 {
			return errInvalidSnapshot
		}
		resources[hash] = rest[:end]
		rest = bytes.TrimSpace(rest[end:])
		if len(rest) > 0 {
			rest = bytes.TrimSpace(rest[1:]) // Comma.
		}
	}
	return nil
}

func quotedEnd(data []byte) int {
	if len(data) < 2 || data[0] != '"' {
		return 0
	}
	for i := 1; i < len(data); i++ {
		switch data[i] {
		case '"':
			return i + 1
		case '\\':
			i++
		}
	}
	return 0
}
