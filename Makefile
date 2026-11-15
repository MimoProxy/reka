# Build tags and linker flags for the locked upstream component set.
# with_gvisor: sing-tun gVisor stack. with_utls: uTLS and REALITY client.
# badlinkname, tfogo_checklinkname0 and -checklinkname=0: required by
# upstream go:linkname usage, same as sing-box release builds.
TAGS    ?= with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal
# Desktop builds are pure Go. Android library builds will override this.
export CGO_ENABLED ?= 0

TEST_TIMEOUT ?= 10m

LDFLAGS ?= -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0

OVERLAY := $(shell python3 tools/build-overlay.py)
GO_OVERLAY = -modfile bin/build.mod -overlay "$(OVERLAY)"

GOFLAGS_BUILD = $(GO_OVERLAY) -trimpath -tags "$(TAGS)" -ldflags "$(LDFLAGS) -s -w -buildid="

# The Android probe and JNI binding need the NDK (mobile/android/build.sh).
PKGS = $(shell go list ./... | grep -v -e /tools/tunprobe-android/ -e /mobile/jni)

.PHONY: build test race vet android

build:
	go build $(GOFLAGS_BUILD) -o bin/reka ./cmd/reka
	go build $(GOFLAGS_BUILD) -o bin/rekactl ./cmd/rekactl

test:
	go test $(GO_OVERLAY) -timeout "$(TEST_TIMEOUT)" -tags "$(TAGS)" -ldflags "$(LDFLAGS)" $(PKGS)

# The race detector needs cgo. checkptr is off because sing-vmess's Vision
# reads TLS connection internals through unsafe offsets.
race:
	CGO_ENABLED=1 go test $(GO_OVERLAY) -race -gcflags=all=-d=checkptr=0 -tags "$(TAGS)" -ldflags "$(LDFLAGS)" $(PKGS)

vet:
	go vet $(GO_OVERLAY) -tags "$(TAGS)" $(PKGS)

android:
	mobile/android/build.sh
