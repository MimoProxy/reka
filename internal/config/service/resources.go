package service

import (
	"bytes"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/resource"
)

type resourceUpload struct {
	data    []byte
	size    int
	updated time.Time
}

// StageResource accepts bounded, content-addressed chunks rather than reading
// a privileged daemon's arbitrary local paths. Replayed chunks are idempotent.
func (s *Service) StageResource(req api.StageResourceRequest) (api.StageResourceResult, error) {
	result := api.StageResourceResult{Hash: req.Hash, Size: req.Size}
	if !resource.ValidHash(req.Hash) || req.Size < 0 || req.Size > resource.MaxSize || req.Offset < 0 || len(req.Data) > 1<<20 || req.Offset > req.Size || len(req.Data) > req.Size-req.Offset {
		return result, errf(CodeBadRequest, "invalid resource hash, size, offset or chunk (maximum 1 MiB)")
	}
	s.uploadMu.Lock()
	defer s.uploadMu.Unlock()
	store, err := resource.Open(s.store.Root())
	if err != nil {
		return result, err
	}
	if ready, err := store.Read(req.Hash); err == nil {
		if len(ready) != req.Size {
			return result, errf(CodeBadRequest, "resource size does not match its hash")
		}
		result.Received, result.Ready = len(ready), true
		return result, nil
	}
	if s.uploads == nil {
		s.uploads = map[string]*resourceUpload{}
	}
	now := time.Now()
	for hash, upload := range s.uploads {
		if now.Sub(upload.updated) > 2*time.Minute {
			delete(s.uploads, hash)
		}
	}
	upload := s.uploads[req.Hash]
	if upload == nil {
		if req.Offset != 0 {
			return result, errf(CodeConflict, "resource upload expired or is missing; restart at offset zero")
		}
		if len(s.uploads) >= 4 {
			return result, errf(CodeBlocked, "four resource uploads are already in progress")
		}
		upload = &resourceUpload{size: req.Size, updated: now}
		s.uploads[req.Hash] = upload
	}
	if upload.size != req.Size {
		return result, errf(CodeConflict, "resource upload size changed")
	}
	if req.Offset < len(upload.data) {
		end := req.Offset + len(req.Data)
		if end > len(upload.data) || !bytes.Equal(upload.data[req.Offset:end], req.Data) {
			return result, errf(CodeConflict, "resource chunk conflicts with received bytes")
		}
	} else if req.Offset != len(upload.data) {
		return result, errf(CodeConflict, "resource chunks must be uploaded in order")
	} else {
		upload.data = append(upload.data, req.Data...)
	}
	upload.updated = now
	result.Received = len(upload.data)
	if result.Received != req.Size {
		return result, nil
	}
	delete(s.uploads, req.Hash)
	if resource.Hash(upload.data) != req.Hash {
		return result, errf(CodeInvalid, "uploaded resource SHA-256 does not match")
	}
	if _, err := store.Put(upload.data); err != nil {
		return result, err
	}
	result.Ready = true
	return result, nil
}
