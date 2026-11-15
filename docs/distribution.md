# Distribution and installation

Current artifacts are **unsigned local staging packages**, version `1.0.0-dev`. They are reviewable build outputs, not a published 1.0 release. Reka's own releases are not code-signed; their integrity comes from `SHA256SUMS`, build metadata and the corresponding source. Applications that bundle the kernel, such as Mimo, sign it as part of their own packages. The signing scripts below support that. Signing identities, notarization credentials, publication and any GitHub release are separate authorized operations.

```sh
make build
make test
make vet
make race
REKA_VERSION=1.0.0-dev ANDROID_HOME=/path/to/sdk make android
python3 tools/release.py --version 1.0.0-dev --android-library bin/android/libreka.so
python3 tools/verify-release.py bin/dist/1.0.0-dev
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

Choose the SID of the intended GUI user, not a different account used only to elevate. The service runs under LocalSystem and grants pipe access only to that SID and LocalSystem. Binaries are administrator-writable and user-readable; state under `%ProgramData%\Reka` is restricted to Administrators and LocalSystem. SCM restarts after a crash. Installer parameters allow separate binary/state paths for isolated validation. Uninstallation retains state. An existing Reka service is never silently replaced.

`packaging/windows/reka.iss` is the Inno Setup definition. Compile it with the matching staged source directory and target architecture (`x64compatible` or `arm64`). Sign both executables before building the installer, and sign the installer afterwards with `packaging/windows/sign.ps1`; it uses SHA-256, a timestamp and Authenticode verification. Signing and an installer build require the corresponding Windows tools and certificate; the ZIP being valid does not imply a signed installer exists.

Windows uses the unmodified official Wintun 0.14.1 DLL embedded by the locked sing-tun component. `packaging/windows/WINTUN-LICENSE.txt` is the original redistribution license from the [official Wintun distribution](https://www.wintun.net/). Both embedded amd64/arm64 DLLs were byte-compared with the official ZIP (SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`). The signed DLL is not patched or re-signed. This records the selected engineering distribution arrangement; no blanket legal conclusion is inferred from a successful build.

## Build trimming

Default make/release/JNI builds use `reka_minimal` and a generated overlay. The overlay replaces only unsupported upstream ECH entry points with explicit errors. It removes the unused sing-box DNS/router import path; Reka's UDP/TCP DNS exchange uses its own bounded connected-socket implementation, with UDP truncation retry and reply checks. Supported protocol and DNS behavior remains covered by the existing tests.

Go forbids overlays inside its module cache, so `tools/build-overlay.py` makes an exact generated copy under `bin/upstream`, checks the pinned source hash and full copied tree, and writes a separate `bin/build.mod`. The checked-in module and module cache are unchanged. Upstream changes fail closed and require reviewing this overlay. Normal builds without the overlay remain possible for comparison. The measured size saving is small; do not assume dependency count predicts binary size.

CI runs native tests on six hosted OS/architecture combinations; Android hosted CI only builds the library. The dedicated self-hosted ARM64 Android workflow runs the device harness. Actual run results and pending gates are recorded separately from workflow definitions. Runner labels follow [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
