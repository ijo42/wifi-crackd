#!/usr/bin/env bash
# Dependency-free Android build alternative: JDK 17+, Android SDK platform 35 + build-tools 35.
set -euo pipefail
if [ -n "${JAVA_HOME:-}" ]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${SDK:?Set ANDROID_HOME to the Android SDK directory}"
BT="$SDK/build-tools/35.0.0"
JAR="$SDK/platforms/android-35/android.jar"
OUT="$ROOT/android/app/build/manual"
mkdir -p "$OUT/classes" "$OUT/dex"
rm -f "$OUT/resources.zip" "$OUT/unsigned.apk" "$OUT/aligned.apk"
"$BT/aapt2" compile --dir "$ROOT/android/app/src/main/res" -o "$OUT/resources.zip"
# Gradle supplies namespace; aapt2's standalone linker needs a manifest package instead.
python3 - "$ROOT/android/app/src/main/AndroidManifest.xml" "$OUT/AndroidManifest.xml" <<'PY'
import sys
text=open(sys.argv[1]).read().replace('<manifest ', '<manifest package="org.wifit3.mobile" ',1)
open(sys.argv[2],'w').write(text)
PY
"$BT/aapt2" link -I "$JAR" --manifest "$OUT/AndroidManifest.xml" --min-sdk-version 26 --target-sdk-version 35 --version-code 3 --version-name 0.3.0 -o "$OUT/unsigned.apk" "$OUT/resources.zip"
"${JAVA_HOME:+$JAVA_HOME/bin/}javac" -encoding UTF-8 -source 17 -target 17 -classpath "$JAR" -d "$OUT/classes" "$ROOT"/android/app/src/main/java/org/wifit3/mobile/*.java
"${JAVA_HOME:+$JAVA_HOME/bin/}jar" cf "$OUT/classes.jar" -C "$OUT/classes" .
"$BT/d8" --lib "$JAR" --min-api 26 --output "$OUT/dex" "$OUT/classes.jar"
(cd "$OUT/dex" && zip -q -u "$OUT/unsigned.apk" classes.dex)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
KEY="${DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"
if [ ! -f "$KEY" ]; then
 mkdir -p "$(dirname "$KEY")"
 "${JAVA_HOME:+$JAVA_HOME/bin/}keytool" -genkeypair -keystore "$KEY" -storepass android -keypass android -alias androiddebugkey -dname 'CN=Android Debug,O=Android,C=US' -keyalg RSA -keysize 2048 -validity 10000
fi
"$BT/apksigner" sign --ks "$KEY" --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out "$OUT/wifit3-mobile-debug.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT/wifit3-mobile-debug.apk"
echo "APK: $OUT/wifit3-mobile-debug.apk"
