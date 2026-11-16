#!/bin/sh
# Builds libreka.so (Go c-shared, arm64) with the NDK, and the device test
# app around it, without Gradle: javac, d8, aapt2, zipalign, apksigner.
# Output (repo root): bin/android/libreka.so, bin/android/reka-libtest.apk.
# The published Kotlin wrapper is compiled and exercised by the test app.
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
SDK=${ANDROID_HOME:?set ANDROID_HOME}
NDK=${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)
KOTLIN=${REKA_KOTLIN_HOME:-$(python3 "$ROOT/tools/kotlin-toolchain.py")}
MIN_API=26
VERSION=${REKA_VERSION:-dev}
case "$VERSION" in ''|*[!A-Za-z0-9.+_-]*) echo 'Invalid REKA_VERSION' >&2; exit 1;; esac
OUT=$ROOT/bin/android
BUILD=$OUT/build
rm -rf "$BUILD" && mkdir -p "$BUILD/classes" "$BUILD/apk/lib/arm64-v8a"

TAGS=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal
OVERLAY=$(python3 "$ROOT/tools/build-overlay.py")
HOST_TAG=$(ls "$NDK/toolchains/llvm/prebuilt" | head -1)
CC="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android$MIN_API-clang"
(cd "$ROOT" && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC" go build -modfile "$ROOT/bin/build.mod" -overlay "$OVERLAY" -trimpath -buildmode=c-shared \
	-tags "$TAGS" -ldflags "-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid= -X github.com/MimoProxy/reka/internal/control.Version=$VERSION" \
	-o "$BUILD/apk/lib/arm64-v8a/libreka.so" ./mobile/jni)
rm -f "$BUILD/apk/lib/arm64-v8a/libreka.h"
cp "$BUILD/apk/lib/arm64-v8a/libreka.so" "$OUT/libreka.so"
python3 "$ROOT/tools/android-build-info.py" "$OUT/libreka.so" --version "$VERSION"
cat > "$BUILD/BuildVersion.java" <<EOF
package org.mimoproxy.reka.test;
public final class BuildVersion { public static final String VERSION = "$VERSION"; }
EOF

javac --release 11 -nowarn -classpath "$PLATFORM/android.jar" -d "$BUILD/classes" $(find java -name '*.java') "$BUILD/BuildVersion.java"
"$KOTLIN/bin/kotlinc" -jvm-target 11 -classpath "$PLATFORM/android.jar:$BUILD/classes" -d "$BUILD/classes" $(find kotlin testapp/kotlin -name '*.kt')
javac --release 11 -nowarn -classpath "$PLATFORM/android.jar:$BUILD/classes:$KOTLIN/lib/kotlin-stdlib.jar" -d "$BUILD/classes" $(find testapp/java -name '*.java')
"$BT/d8" --release --min-api $MIN_API --lib "$PLATFORM/android.jar" --output "$BUILD/apk" $(find "$BUILD/classes" -name '*.class') "$KOTLIN/lib/kotlin-stdlib.jar"
"$BT/aapt2" link -o "$BUILD/base.apk" --manifest testapp/AndroidManifest.xml -I "$PLATFORM/android.jar" \
	--min-sdk-version $MIN_API --target-sdk-version 35
(cd "$BUILD/apk" && zip -q -r "$BUILD/base.apk" classes.dex lib)
"$BT/zipalign" -f -p 4 "$BUILD/base.apk" "$BUILD/aligned.apk"
TEST_KEY=${REKA_ANDROID_TEST_KEYSTORE:-$HOME/.android/debug.keystore}
if [ ! -f "$TEST_KEY" ]; then
    TEST_KEY="$OUT/test-debug.keystore"
    if [ ! -f "$TEST_KEY" ]; then
        keytool -genkeypair -noprompt -keystore "$TEST_KEY" -storepass android -keypass android \
            -alias androiddebugkey -dname 'CN=Android Debug,O=Android,C=US' -keyalg RSA -validity 3650
    fi
fi
"$BT/apksigner" sign --ks "$TEST_KEY" --ks-pass pass:android --key-pass pass:android \
	--out "$OUT/reka-libtest.apk" "$BUILD/aligned.apk"
ls -l "$OUT/libreka.so" "$OUT/reka-libtest.apk"
