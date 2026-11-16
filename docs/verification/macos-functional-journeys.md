# macOS functional journey evidence (#62–#64)

All projects and binaries below are disposable fixtures. No installed MRK app,
helper registration, account, device, Store action or repository setting changed.
No MRK release or installer was built, signed or distributed. Test artifacts and
generated debug keys remain outside the source checkout and are not published.

| Issue | Available verification | Remaining gate |
|---|---|---|
| #62 Android | Real Gradle debug compile, typed version edit, rebuilt APK inspection, 180 source/adapter tests | Installed app + protected tool/helper path and complete UI journey |
| #63 iOS | Pending sequential investigation | Signed/account/device acceptance outside this task |
| #64 Store | Pending sequential investigation | Account-backed Store operations outside this task |

## #62 Android

Committed fixture source: `tests/fixtures/macos_android_journey`. Environment:
macOS arm64, ordinary nonroot account; Java 21.0.11, Gradle 8.13, AGP 8.9.2,
existing Android SDK/build-tools 35. Public Gradle/plugin dependencies were
fetched into an isolated cache. No SDK package was installed or updated.
The build has one worker, bounded JVM settings and no persistent Gradle daemon.
The one-use JVM is separately observed because it changes process group; both
fixture JVMs were confirmed gone after builds. Retained subtree monitoring
observed about 606 MiB build RSS, within the local aggregate compiler limit.

1. A fresh fixture compiled with `assembleDebug` (32 tasks, original return 0).
   The generated Android debug identity is disposable and never an upload key.
2. The real registered-root version transaction captured/prepared/applied the
   fixture's `public/version.properties` change to 2.3.4 / 8. Outcome: committed,
   clean journal, settled resources. All unrelated source bytes were unchanged.
3. A fresh one-worker debug compile returned zero after that edit. Actual SDK
   `aapt` inspection confirmed package `org.mrk.fixture`, versionName 2.3.4 and
   versionCode 8. Manifest and DEX entries are present. The private test APK is
   8,726 bytes, SHA256 `5e61e8ac7abac2b086095eb7e8429372a7715810067390b6045c56ad9b51ae06`. It is not distributed.
4. All 180 Android operation/service/protocol/selection/files/tools/bootstrap
   and real version-journey tests pass. The new permanent regression performs
   the typed edit on the same valid Android-only fixture and proves file/resource
   invariants without requiring Gradle, a device or an account.

The test-only Linux xattr seams previously assumed macOS Python supplied
`os.getxattr`; explicit inert patches now create that missing test attribute.
No real Mac xattr check, native profile or tool-registration predicate changed.
The SDK XML-version warning is retained in build evidence; compilation completed.
No installed tool was changed to silence it.

The fixture demonstrates the available compiler/toolchain and core file effect,
not the installed native app's complete Android journey. Open/configure/metadata,
credential import/signing, history/recovery and cancellation still need evidence
through the final installed app. Existing real transaction/recovery tests from
#65 cover their core file effects, not installed UI acceptance. Protected tool
copy/registration and approval are coordinated with #47–#49; their code is intact.
