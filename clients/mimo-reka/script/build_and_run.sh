#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-run}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$APP_DIR/../.." && pwd)"
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer; fi
export CLANG_MODULE_CACHE_PATH="$APP_DIR/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$APP_DIR/.build/module-cache"
APP_BUNDLE="$APP_DIR/dist/Mimo Reka.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
KERNEL_ARCH="$(uname -m)"
if [[ "$KERNEL_ARCH" == x86_64 ]]; then KERNEL_ARCH=amd64; fi
KERNEL="${REKA_KERNEL_PATH:-$REPO_DIR/bin/releases/1.0.0/reka-1.0.0-darwin-$KERNEL_ARCH/reka}"
VERSION="${MIMO_REKA_VERSION:-0.1.12}"
BUILD_NUMBER="${MIMO_REKA_BUILD:-12}"

case "$MODE" in
  run|--verify|--build-only|--package|--debug|--logs|--telemetry) ;;
  *) echo "usage: $0 [run|--verify|--build-only|--package|--debug|--logs|--telemetry]" >&2; exit 2 ;;
esac

# Only this companion's application identifier is targeted.
if pgrep -x MimoReka >/dev/null 2>&1; then
  /usr/bin/osascript -e 'tell application id "org.mimoproxy.MimoReka" to quit'
  for _ in {1..350}; do
    if ! pgrep -x MimoReka >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  if pgrep -x MimoReka >/dev/null 2>&1; then
    echo "Mimo Reka is still restoring its network state. Wait for it to quit before rebuilding." >&2
    exit 1
  fi
fi

if [[ ! -x "$KERNEL" ]]; then
  echo "Reka 1.0 release binary is missing. Set REKA_KERNEL_PATH to a verified native binary." >&2
  exit 1
fi
xcrun swift build --disable-sandbox --package-path "$APP_DIR" --cache-path "$APP_DIR/.build/cache" -Xswiftc -module-cache-path -Xswiftc "$APP_DIR/.build/module-cache"
BUILD_DIR="$(xcrun swift build --disable-sandbox --package-path "$APP_DIR" --show-bin-path)"
mkdir -p "$APP_CONTENTS/MacOS" "$APP_CONTENTS/Resources/ThirdParty"
cp "$BUILD_DIR/MimoReka" "$APP_CONTENTS/MacOS/MimoReka"
cp "$BUILD_DIR/MimoRekaHost" "$APP_CONTENTS/MacOS/MimoRekaHost"
cp "$KERNEL" "$APP_CONTENTS/Resources/reka"
cp "$APP_DIR/Resources/AppIcon.icns" "$APP_CONTENTS/Resources/AppIcon.icns"
cp "$REPO_DIR/LICENSE" "$APP_CONTENTS/Resources/ThirdParty/Reka-LICENSE"
cp "$APP_DIR/Vendor/Yams/LICENSE" "$APP_CONTENTS/Resources/ThirdParty/Yams-LICENSE"
cp "$APP_DIR/README.md" "$APP_CONTENTS/Resources/README.md"
if [[ -f "$(dirname "$KERNEL")/BUILD.json" ]]; then cp "$(dirname "$KERNEL")/BUILD.json" "$APP_CONTENTS/Resources/reka-release-build.json"; fi
if [[ -d "$(dirname "$KERNEL")/licenses" ]]; then cp -R "$(dirname "$KERNEL")/licenses" "$APP_CONTENTS/Resources/ThirdParty/RekaDependencies"; fi
chmod +x "$APP_CONTENTS/MacOS/MimoReka" "$APP_CONTENTS/MacOS/MimoRekaHost" "$APP_CONTENTS/Resources/reka"
cat > "$APP_CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>MimoReka</string>
<key>CFBundleIdentifier</key><string>org.mimoproxy.MimoReka</string>
<key>CFBundleName</key><string>Mimo Reka</string>
<key>CFBundleDisplayName</key><string>Mimo Reka</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$BUILD_NUMBER</string>
<key>CFBundleDevelopmentRegion</key><string>zh-Hans</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSHumanReadableCopyright</key><string>Mimo Reka contributors · GPL-3.0</string>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - --identifier org.mimoproxy.MimoReka.Core "$APP_CONTENTS/Resources/reka"
/usr/bin/codesign --force --sign - --identifier org.mimoproxy.MimoReka.Host "$APP_CONTENTS/MacOS/MimoRekaHost"
python3 - "$APP_CONTENTS" "$VERSION" "$BUILD_NUMBER" <<'PY'
import hashlib, json, pathlib, sys
contents = pathlib.Path(sys.argv[1])
artifacts = {}
for name in ['Resources/reka', 'MacOS/MimoRekaHost']:
    data = (contents / name).read_bytes()
    artifacts[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
(contents / 'Resources/bundle-build.json').write_text(json.dumps({
    'product': 'Mimo Reka', 'version': sys.argv[2], 'build': sys.argv[3],
    'signing': 'ad-hoc', 'notarized': False, 'embedded_binaries': artifacts,
}, indent=2) + '\n')
PY
/usr/bin/codesign --force --sign - "$APP_BUNDLE"
/usr/bin/codesign --verify --deep --strict "$APP_BUNDLE"
case "$MODE" in
  --build-only) echo "$APP_BUNDLE" ;;
  --package)
    ARCHIVE="$APP_DIR/dist/Mimo-Reka-$VERSION-macOS-$(uname -m).zip"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ARCHIVE"
    /usr/bin/shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
    echo "$ARCHIVE"
    ;;
  --debug) lldb -- "$APP_CONTENTS/MacOS/MimoReka" ;;
  --logs|--telemetry)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/log stream --info --style compact --predicate 'process == "MimoReka"'
    ;;
  --verify)
    /usr/bin/open -n "$APP_BUNDLE"
    sleep 2
    pgrep -x MimoReka >/dev/null
    echo "Mimo Reka is running: $APP_BUNDLE"
    ;;
  *) /usr/bin/open -n "$APP_BUNDLE" ;;
esac
