#!/bin/sh
# Builds the Android TUN probe APK without Gradle: Go c-shared library via
# the NDK, then javac, d8, aapt2, zipalign and apksigner from build-tools.
# Output: bin/reka-tunprobe.apk and bin/libtunprobe.so (repo root).
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
SDK=${ANDROID_HOME:?set ANDROID_HOME}
NDK=${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)
MIN_API=26
OUT=$ROOT/bin/android-build
rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/apk/lib/arm64-v8a"

TAGS=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android$MIN_API-clang"
(cd "$ROOT" && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC" go build -trimpath -buildmode=c-shared \
	-tags "$TAGS" -ldflags "-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" \
	-o "$OUT/apk/lib/arm64-v8a/libtunprobe.so" ./tools/tunprobe-android/go)
rm -f "$OUT/apk/lib/arm64-v8a/libtunprobe.h"

javac --release 11 -nowarn -classpath "$PLATFORM/android.jar" -d "$OUT/classes" $(find java -name '*.java')
"$BT/d8" --release --min-api $MIN_API --lib "$PLATFORM/android.jar" --output "$OUT/apk" $(find "$OUT/classes" -name '*.class')
"$BT/aapt2" link -o "$OUT/base.apk" --manifest AndroidManifest.xml -I "$PLATFORM/android.jar" \
	--min-sdk-version $MIN_API --target-sdk-version 35
(cd "$OUT/apk" && zip -q -r "$OUT/base.apk" classes.dex lib)
"$BT/zipalign" -f -p 4 "$OUT/base.apk" "$OUT/aligned.apk"
"$BT/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android --key-pass pass:android \
	--out "$ROOT/bin/reka-tunprobe.apk" "$OUT/aligned.apk"
cp "$OUT/apk/lib/arm64-v8a/libtunprobe.so" "$ROOT/bin/libtunprobe.so"
ls -l "$ROOT/bin/reka-tunprobe.apk" "$ROOT/bin/libtunprobe.so"
