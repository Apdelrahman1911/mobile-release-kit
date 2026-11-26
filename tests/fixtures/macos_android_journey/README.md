# Disposable Android compile fixture

Synthetic public source only. It requests no network/Store permission at runtime
and contains no credential, upload key, real application identity or user data.
The debug build may generate its normal disposable debug keystore. Keep all
outputs and key material outside the repository; never use it for Store upload.

This fixture was built on macOS arm64 using Java 21, Gradle 8.13, AGP 8.9.2,
Android SDK/build-tools 35. Copy this directory to a fresh private test directory.
Set GRADLE_USER_HOME and ANDROID_USER_HOME to fresh sibling directories,
select the test JDK with JAVA_HOME, and set ANDROID_HOME to an existing SDK.
Do not install or change an SDK from this test. Use one worker:

    "$GRADLE_BIN" --no-daemon --max-workers=1 --console=plain assembleDebug

The gradle.properties file bounds the fixture JVM and worker count. Its one-use
Gradle JVM must settle before fixture cleanup; account for its RSS even if it
changes process group. Compilation outputs are test binaries, never MRK app
releases/installers. No Gradle wrapper binary, generated cache, APK or key is
committed. This standalone build does not establish native MRK tool custody,
helper approval, installed app integration, device behavior or Store readiness.

The saved MRK configuration is Android-only; disabled iOS has only enabled=false.
The Gradle project reads public/version.properties. Its typed-core regression is:

    PYTHONPATH=src:tests:tests/desktop python3.11 -m unittest test_macos_android_journey_fixture

The recorded real build also ran that production transaction on a disposable
copy, then rebuilt and inspected the APK to confirm versionName 2.3.4 and
versionCode 8. The committed source starts at 1.0.0 / 1 so the edit remains
reproducible. Neither identity is a production app or upload credential.
