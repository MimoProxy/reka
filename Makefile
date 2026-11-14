# Build tags and linker flags for the locked upstream component set.
# with_gvisor: sing-tun gVisor stack. with_utls: uTLS and REALITY client.
# badlinkname, tfogo_checklinkname0 and -checklinkname=0: required by
# upstream go:linkname usage, same as sing-box release builds.
TAGS    ?= with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
# Desktop builds are pure Go. Android library builds will override this.
export CGO_ENABLED ?= 0

LDFLAGS ?= -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0

GOFLAGS_BUILD = -trimpath -tags "$(TAGS)" -ldflags "$(LDFLAGS) -s -w -buildid="

.PHONY: build test race vet

build:
	go build $(GOFLAGS_BUILD) -o bin/reka ./cmd/reka

test:
	go test -tags "$(TAGS)" -ldflags "$(LDFLAGS)" ./...

# The race detector needs cgo. checkptr is off because sing-vmess's Vision
# reads TLS connection internals through unsafe offsets.
race:
	CGO_ENABLED=1 go test -race -gcflags=all=-d=checkptr=0 -tags "$(TAGS)" -ldflags "$(LDFLAGS)" ./...

vet:
	go vet -tags "$(TAGS)" ./...
