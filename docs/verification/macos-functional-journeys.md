# macOS functional journey evidence (#62–#64)

All projects and binaries below are disposable fixtures. No installed MRK app,
helper registration, account, device, Store action or repository setting changed.
No MRK release or installer was built, signed or distributed. Test artifacts and
generated debug keys remain outside the source checkout and are not published.

| Issue | Available verification | Remaining gate |
|---|---|---|
| #62 Android | Real Gradle debug compile, typed version edit, rebuilt APK inspection, 180 source/adapter tests | Installed app + protected tool/helper path and complete UI journey |
| #63 iOS | Real unsigned simulator build and Debug archive, core archive inspection, typed version propagation and source/phase tests | Installed app path and signed account-backed archive/export |
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

## #63 iOS

Fixture source: `tests/fixtures/macos_ios_journey`. macOS 27.0 arm64, ordinary
nonroot account, Xcode 27.0 (27A266a), iPhoneSimulator/iPhoneOS SDK 27.0. The
project has no team, provisioning profile, entitlement, external dependency or
script build phase. Code signing is disabled explicitly. All builds use Debug,
one compiler job, private derived data and private result bundles.

- A real arm64 simulator build returned zero, without booting a simulator.
- The actual registered-root typed version transaction committed 2.3.4 / 8,
  cleaned its journal, settled original resources and preserved unrelated source.
- A fresh unsigned Debug archive for the generic iOS SDK returned zero. No
  personal device was selected or required. A current-source simulator rebuild
  also returned zero and contains the edited version.
- The actual core archive/Mach-O inspector accepts the archive with expected
  bundle ID `org.mrk.iosfixture` and version 2.3.4 / 8. No code-signature directory
  is present. The 67,064-byte test executable has SHA256
  `378af37d7d0aadc61d6b3b3eeeb4d5b39c8aace6015e145c606c7dee29c9ccbb`. No archive or app binary is committed/distributed.

The initial archive attempt used a simulator base SDK in the generated test
project and returned 70; correcting the fixture base SDK to iphoneos enables
both generic targets. The final committed fixture is the corrected project.
Raw Xcode logs stay private because tool destination diagnostics can enumerate
machine/device identifiers even for a generic destination; none are copied here.

Candidate/history fixtures incorrectly replaced Darwin CLOCK_UPTIME_RAW with
CLOCK_MONOTONIC while seeding deadlines with monotonic_ns. On this Mac those
clock values differ, so valid fixture requests were refused before their phase
lease was admitted. The test adapter now preserves the real raw clock when
available and supplies the old Linux alias only when absent. Production clocks,
deadlines and admission are unchanged. The producer fixture also now constructs
the real private 0700 output root it replaces, and uses /dev/fd on macOS for
its descriptor-retirement check. Current explicitly supported iOS execution/
reconciliation contexts are tested while cross-platform manifest/namespace
refusals remain intact.

All 63 focused archive/candidate/history and iOS-only project/version tests pass.
The permanent iOS-only regression runs without Xcode or an account.
Signed archive/export, real credential enrollment/assignment, installed-app
review/cancellation/recovery, and device execution remain separate verification.
No Apple account, P12, profile, Store request or installed MRK app was used.
