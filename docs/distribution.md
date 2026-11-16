# Distribution and installation

Reka **1.0.0** packages are available from the [GitHub release](https://github.com/MimoProxy/reka/releases/tag/v1.0.0). Reka's releases are unsigned; verify `SHA256SUMS`, `artifacts.json` and the corresponding-source archive. Applications that bundle the kernel, such as Mimo, sign it as part of their own packages. The scripts below support separately authorized signing. Local development packages and workflow artifacts remain staging outputs until published.

```sh
make build
make test
make vet
make race
REKA_VERSION=1.0.0 ANDROID_HOME=/path/to/sdk make android
python3 tools/release.py --version 1.0.0 --android-library bin/android/libreka.so
python3 tools/verify-release.py bin/dist/1.0.0
```

On macOS, add `--macos-pkg` to produce unsigned installer packages as well.

The release builder produces darwin/windows/linux amd64+arm64 archives, an optional Android arm64 library archive, exact corresponding source, linked-module license texts, `MODULES.json`, `BUILD.json`, `SHA256SUMS`, and `artifacts.json`. It never uploads, tags or publishes. Linux executables use `CGO_ENABLED=0`; archive verification checks that they have no ELF interpreter. Android PT_LOAD segments must support 16 KiB alignment; this is a structural check, separate from real-device 16 KiB-page testing.

The corresponding-source archive includes the exact working source, a source-file hash manifest and the upstream module source ZIPs for linked modules under `module-cache/`. Public-module versions and hashes remain pinned in `go.mod`/`go.sum`. The root build may be reproduced with that local module proxy and an installed Go toolchain:

```sh
GOPROXY="file://$(pwd)/module-cache" GOSUMDB=off make build
```

Use `GOSUMDB=off` only with the packaged verified local source set; the pinned `go.sum` still validates module content. Android additionally needs the SDK/NDK. Source archives include code from the current working tree and explicitly report `dirty` and their base commit; a formal release should be built from the reviewed clean release commit. Android `LIBRARY-BUILD.json` binds API version, source revision and SHA-256 to the exact `.so`; the device harness verifies the reported API build version. Dependencies absent from a platform's link graph are not presented as linked.

## macOS service

Unpack the matching architecture archive and run:

```sh
sudo ./packaging/macos/install.sh "$(id -u)"
./rekactl -c "unix:///var/run/reka/$(id -u)/control.sock" status
sudo ./packaging/macos/uninstall.sh "$(id -u)"
```

The installer copies the service into a root-owned directory and creates a per-owner LaunchDaemon. State lives at `/Library/Application Support/Reka/<uid>`, and the runtime socket directory is recreated at boot by launchd's service wrapper. Network mode defaults to off; enable it using the planned local configuration transaction. Uninstallation stops the service and retains state/binary for recovery. It does not erase ownership evidence. Reinstallation refuses to overwrite an existing service.

For an authorized signed release, `packaging/macos/sign-and-notarize.sh` signs both executables with hardened runtime, builds a Developer ID Installer package, submits to notarytool, staples and assesses it. It requires `REKA_SIGN_IDENTITY`, `REKA_INSTALLER_IDENTITY` and an existing `REKA_NOTARY_PROFILE`. No credentials are embedded in the repository. The package installs distribution files; installing/enabling a per-user service remains explicit.

## Windows service

From an elevated PowerShell in the unpacked architecture directory:

```powershell
.\packaging\windows\install.ps1 -OwnerSID 'S-1-5-21-...'
.\rekactl.exe -c pipe://reka-service status
.\packaging\windows\uninstall.ps1
```

Choose the SID of the intended GUI user, not a different account used only to elevate. The service runs under LocalSystem and grants pipe access only to that SID and LocalSystem. Binaries are administrator-writable and user-readable; state under `%ProgramData%\Reka` is restricted to Administrators and LocalSystem. SCM restarts after a crash. Installer parameters allow separate binary/state paths for isolated validation. Uninstallation retains state. Use `-Upgrade` for a service already installed in the selected binary directory; it preserves the service owner, state path and configuration. A different directory, owner or unrecognized service command is refused.

`packaging/windows/reka.iss` builds an unsigned Inno Setup installer from the matching staged directory. Select `TargetArch=x64compatible` or `arm64` to match its executables. Setup stops a recognized service before replacing files, then restarts it with the existing owner and state. A fresh installation defaults to the elevated user's SID; supply `/OWNERSID=S-1-5-21-...` when installing for another GUI user. Setup reports service failures, and uninstall refuses to remove files if service removal fails. State is retained after uninstall.

The `windows installers` workflow builds both architectures and runs fresh-install, configuration-preserving upgrade, owner-change refusal and uninstall checks on native runners. A manual workflow dispatch accepts a `version` input; pull-request checks use `1.0.0-dev`. Windows release checkout preserves exact source bytes. The same checks can be run locally with `tools/windows-installer-runtime.ps1` on a dedicated administrator test machine; it refuses existing Reka state or service. Pass `-Version 1.0.0` to test the formal installer. Workflow definitions alone do not establish that a particular run passed.

For a separately authorized signed distribution, sign both executables before compiling Setup and sign the installer afterwards with `packaging/windows/sign.ps1`. It uses SHA-256, a timestamp and Authenticode verification. Reka's unsigned packages do not require a signing certificate.

Windows uses the unmodified official Wintun 0.14.1 DLL embedded by the locked sing-tun component. `packaging/windows/WINTUN-LICENSE.txt` is the original redistribution license from the [official Wintun distribution](https://www.wintun.net/). Both embedded amd64/arm64 DLLs were byte-compared with the official ZIP (SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`). The signed DLL is not patched or re-signed. This records the selected engineering distribution arrangement; no blanket legal conclusion is inferred from a successful build.

## Build trimming

Default make/release/JNI builds use `reka_minimal` and a generated overlay. Its ECH replacement uses Reka's generation-scoped HTTPS DNS callback and clones TLS configuration per connection, retaining explicit ECH configs, server key parsing and synchronized retry configs. This removes the unused sing-box DNS/router import path. Reka's UDP/TCP DNS exchange uses its own bounded connected-socket implementation, with UDP truncation retry and reply checks. Real TLS/uTLS and Hysteria2/TUIC ECH tests cover successful encrypted handshakes, TCP/UDP and wrong-key rejection.

The generated overlay also corrects the pinned Trojan inbound's authentication-key read to use `io.ReadFull`. Reka uses that inbound for loopback test/tool nodes; a stream read can return a partial key, including data cached during HTTPUpgrade. Deterministic fragmented-key tests cover this correction. The normal proxy client uses the upstream outbound implementation.

Go forbids overlays inside its module cache, so `tools/build-overlay.py` makes an exact generated copy under `bin/upstream`, checks the pinned source hash and full copied tree, and writes a separate `bin/build.mod`. The checked-in module and module cache are unchanged. Upstream changes fail closed and require reviewing this overlay. Normal builds without the overlay remain possible for comparison. The measured size saving is small; do not assume dependency count predicts binary size.

CI runs native tests on six hosted OS/architecture combinations; Android hosted CI only builds the library. The dedicated self-hosted ARM64 Android workflow runs the device harness. Actual run results and pending gates are recorded separately from workflow definitions. Runner labels follow [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The pinned component overlays also synchronize Vision TLS classification and SOCKS UDP remote-address state, retain TLS object pointers through `unsafe.Add`, and validate the expected TLS buffer layout. Vision and SOCKS UDP tests run under the ordinary race detector with checkptr enabled; no corresponding race exemptions remain in the default build. The original sing/sing-vmess copies and module cache are verified unchanged.

The TLS client overlay exposes a scoped configuration hook for whole-certificate
SHA256 pinning and independent certificate verification names. The pinned STD
and uTLS source hashes are checked before applying it. A build without this
hook rejects configurations requiring these checks instead of ignoring them.
Hysteria2's Chrome QUIC TLS path uses its supported peer-certificate callback.

Provider override expressions adapt a standalone GPL-3.0-or-later component
from mihomo v1.19.34; [origin and local changes](../internal/compat/providerexpr/ORIGIN.md)
are shipped with the corresponding source. The runtime, router, refresh service
and configuration transactions remain Reka implementations.

The sing cached-connection overlay serializes access to cached TCP/reader/UDP
prefix buffers without holding a lock during underlying network reads. Closing
a connection cannot release a buffer while it is being consumed. `WriteTo`
also consumes its cached prefix once. Repeated real protocol shutdown and
read/close ownership tests run with the race detector and checkptr enabled.

Windows TFO uses a pinned `tfo-go/v2` overlay for Go 1.27's `net.newFD`
single return value, current poll FD layout and variadic `execIO` pointer
pinning. Runtime version and reflected field-layout checks fail closed before
the internal calls. Real Windows TCP tests exercise TFO, MPTCP and both together;
socket protection remains active. The default dialer also enables MPTCP on both
IPv4 and IPv6 dialers.

The SS2022 overlays publish an immutable request salt before the first physical
write, serialize client read/write state, and close the socket before releasing
the cipher buffers. The test-node server applies the same close/read/write
ownership discipline. A deterministic fast-response test holds the first
write's return until the response has been read; repeated two-hop TCP/UDP and
parent-rotation tests also run under the ordinary race detector.

VLESS encryption adapts a standalone GPL component from the pinned mihomo
reference; [origin, exact source hashes and local changes](../internal/compat/vlessenc/ORIGIN.md)
ship with the source. Standard Go ML-KEM and the existing pinned BLAKE3 library
are checked in both directions against the unmodified reference transport.
Source-hashed VLESS hooks apply encryption after TLS/stream transports; a
test-node inbound hook provides the symmetric peer. Vision obtains this
component's decrypted buffers through a typed interface instead of reflecting
its layout. Ordinary TLS still uses the guarded upstream buffer path.

Security carriers use a scoped TLS factory on the already protected socket.
ShadowTLS vector writes and first-authentication publication are serialized;
the v2 server joins its camouflage writer before handing over the connection.
The v2 client retains the negotiated TLS decoder to discard late encrypted
camouflage records (including HTTP/2 SETTINGS), then preserves the entire first
raw proxy record. TLS alerts and transport failures remain errors, and the
decoder's transition alert is kept off the proxy wire. Standard TLS and uTLS
run against independent original peers, including HTTP/2 and gRPC transports.
The generator pins each changed upstream source hash.
