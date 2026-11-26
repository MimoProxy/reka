# Build tags and linker flags for the locked upstream component set.
# with_gvisor: sing-tun gVisor stack. with_utls: uTLS and REALITY client.
# badlinkname, tfogo_checklinkname0 and -checklinkname=0: required by
# upstream go:linkname usage, same as sing-box release builds.
# ts_omit_*: sing-box libbox's Tailscale exclusions plus Peer API.
TAGS    ?= with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal,ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,ts_omit_peerapiserver
# Desktop builds are pure Go. Android library builds will override this.
export CGO_ENABLED ?= 0

TEST_TIMEOUT ?= 10m

LDFLAGS ?= -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0

OVERLAY := $(shell python3 tools/build-overlay.py)
GO_OVERLAY = -modfile bin/build.mod -overlay "$(OVERLAY)"

# -trimpath on every build, test and vet keeps Go's build cache keys free of
# the checkout path, so worktrees and temp copies share one cache instead of
# each adding a full copy of the dependency tree.
GO_COMMON = $(GO_OVERLAY) -trimpath

GOFLAGS_BUILD = $(GO_COMMON) -tags "$(TAGS)" -ldflags "$(LDFLAGS) -s -w -buildid="

# The Android probe and JNI binding need the NDK (mobile/android/build.sh).
PKGS = $(shell go list ./... | grep -v -e /tools/tunprobe-android/ -e /mobile/jni)

.PHONY: build test race vet android dashboard

build:
	go build $(GOFLAGS_BUILD) -o bin/reka ./cmd/reka
	go build $(GOFLAGS_BUILD) -o bin/rekactl ./cmd/rekactl

test:
	go test $(GO_COMMON) -timeout "$(TEST_TIMEOUT)" -tags "$(TAGS)" -ldflags "$(LDFLAGS)" $(PKGS)

# The pinned overlays make Vision and SOCKS UDP race/checkptr-testable.
race:
	CGO_ENABLED=1 go test $(GO_COMMON) -race -tags "$(TAGS)" -ldflags "$(LDFLAGS)" $(PKGS)

vet:
	go vet $(GO_COMMON) -tags "$(TAGS)" $(PKGS)

android:
	mobile/android/build.sh

# A local web page for watching and steering a running kernel.
dashboard:
	go build $(GOFLAGS_BUILD) -o bin/reka-dashboard ./tools/dashboard
