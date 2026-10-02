# Ordinary macOS application: external UI scenario

This is one **external XCTest UI target**, not a second application engine or an
in-process observer. It does not change the ordinary Rust app, its core,
runtime profile, confirmations, owner or cleanup policy.

## Admitted environment

Only the existing reviewed normal-package job on a **fresh exclusive
GitHub-hosted macOS 26 ARM64 runner** is supported. The same job must first
bind the ordinary Cargo binary, package it, install through the standard
Installer and pass the independent nonroot byte/mode readback. Never point
this scenario at a shared/personal desktop: XCTest launch may terminate an
already-running application. A non-running precondition is mandatory.

The generated XCTest runner is sandboxed. On macOS, `NSHomeDirectory()` then
names its container, not the operating-system account home. Admission uses one
bounded `getpwuid_r` lookup of the original UID and requires the exact nonroot
runner account/home instead; it does not remove the runner sandbox. Both app
launch sites replace the environment with those admitted account values and
the fixed PATH/locale/timezone. They do not copy the runner's sandbox home or
temporary directory; absent TMPDIR leaves normal platform temp selection to
the product. No environment value is published in account diagnostics.

The tiny target has no package dependencies and no app-under-test build target.
It uses ad-hoc local signing for its test runner only; no signing account,
provisioning profile or production credential is needed. The workflow selects
Xcode only for these steps; it does not change the machine-wide developer
directory. Missing Xcode/UI broker/GUI/permission support is a failure, not
permission to modify TCC, Accessibility, Gatekeeper or user credentials.

The selected application URL is fixed:
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
The bundle ID check is a routing check, not a substitute for the original
Installer/readback and normal-binary source receipts.

## Exact scenario and claim

`MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit`:

1. Launch the exact, initially stopped ordinary app once, with an explicit
   credential-free environment and no project or observer arguments.
2. Observe its unique main window, first-party renderer, dashboard heading and
   enabled **Open project folder** control.
3. Use its own **File → Quit** menu. Require the exact native confirmation
   sheet and its unique **Cancel** and **Quit** buttons.
4. Click **Cancel**. Confirm the app and dashboard remain usable; navigate to
   Project settings and back to Dashboard without selecting any project.
5. Use File → Quit again and click the genuine affirmative **Quit** button.
   Wait for the same application proxy to report `notRunning`.

No skip, expected failure, automatic rerun, arbitrary app path, global
keystroke, permission change or live service operation is included.
Framework `terminate()` is failure-only cleanup after this test's own launch;
if cleanup is needed the test fails, even when that cleanup succeeds.
An occupied preexisting app is never assigned to the cleanup slot.

XCTest enforces a **60-second** scenario allowance with timeouts enabled.
The workflow separately bounds runner build and execution; execution has a
three-minute outer step. Apple rounds `executionTimeAllowance` up to whole
minutes, so this is not a falsely claimed precise 90-second timeout.

The original `xcodebuild` test result must succeed, with exactly one total and
passed test and zero failed/skipped tests. The structured UI result and bounded
diagnostics are separate evidence, never a rewritten preview-package receipt.

**Not proved by the first scenario:** original POSIX application exit status, every internal or
external worker/descriptor's finality, Finder/Installer interaction, Gatekeeper
or notarization, Intel/older macOS, project selection, editing, signing, Store
operations, release readiness or complete Desktop feature acceptance.
`cleanExitStatus` remains null and `allWorkerFinality` remains unestablished.

## Resource/evidence handling

Build this small runner once, then use `test-without-building`; batch it with an
actual changed normal-app build rather than rebuilding the whole application
for this scenario alone. Application and harness source commits are both
recorded; this initial integration requires the same commit.

Raw `.xcresult` and full logs stay in this job's task-owned temporary directory.
Only the closed summary and bounded credential-free diagnostic tails enter the
separate engineering evidence artifact. The user-preview package roster stays
exactly `.pkg`, `README.md`, `PREVIEW.json`. Its unexecuted UI fields describe
the package export stage, not a later independent XCTest result.

After a completed accepted test/evidence upload, remove only this task's
DerivedData, result bundle and disposable full logs. Do not stop shared macOS/
Xcode services or delete shared caches. Failure/timeout is not worker-finality
evidence; retain unresolved task outputs until the disposable job is retired.

## Synthetic local-project journey (separate second gate)

Keep the basic launch/Cancel/navigation/Quit method above as the **first gate**.
Build this one tiny XCTest target once, then explicitly select **one**, not
both, of the following methods with the same original test runner:

- `MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEdits`
- `MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages`

The second adds the image segment to the same fixed journey. It requires the
reviewed native public-image adapter, edit profile and common Runtime Book
cleanup correction to be integrated. A missing capability fails the selected
method; it is never skipped or enabled from test input. When the first variant
is selected, images are explicitly **not run**, not passed. Never run the
whole test class implicitly and count both variants as independent coverage.

The external test uses only ordinary accessible controls on the original app:

1. Real native project-folder Cancel, then Go to Folder and genuine Open.
2. Edit candidate branch and add a locale; prove the shared unsaved draft
   survives navigation. Validate, review exactly two destinations, verify
   fresh confirmation gating, save once and explicitly refresh static state.
3. Preview all four workflow callers without writing, then review the separate
   local native plan and confirm once. Compare every complete resulting file.
4. Load one saved locale's public text, edit only its title, validate/review
   all three files, require fresh acknowledgement and typed SAVE, save once,
   and explicitly refresh. Preserve the other locale and both descriptions.
5. Save only two version value spans. Preserve quotes, whitespace, comments,
   mixed CRLF/LF and missing final newline; read saved version again explicitly.
6. Image variant only: genuine native Cancel followed by two-file modifier
   selection. Inspect actual names/digests/header dimensions and target order;
   require fresh local-copy consent. Preserve both sources and other content.
7. Verify the finite final file roster and absence of all twelve fixed
   transaction controls and .git. Use actual File → Quit and the same proxy's
   notRunning, then complete final readback and consuming descriptor closes.

The fixed bundled `Fixtures/normal-project-v1.json` is under64KiB. It
contains only credential-free fixture and expected bytes. Runtime fixture
content is capped at256KiB in one exclusively created, mode0700 directory under
canonical /private/tmp. Private/config/text leaves use0600; two ordinary public
PNG sources use0644. No user project, Git repository, script, build command,
signing input or Store account is used.

Expected complete workflow bytes are frozen from shipped template DATA at tree
`92d912ade95b5a3dcc5104aaea8d0d6db0ffbdcf`,
resource SHA256
`6fa1f3b7dd1907f56af44ccf050458626d702ec0a06e5578a7416986c46ad29a`,
using only the fixed repository Example/mobile-release-kit and forty lowercase
a characters. These are format-only inputs. No production generator/writer is
called as the runtime test oracle; no workflow is dispatched.

The two tiny fixtures are complete distinct1×1 RGB8 PNG files (IHDR, IDAT and
IEND with CRCs). The source policy for Android phoneScreenshots specifies no
minimum dimensions; the local header/dimension rules admit these dimensions.
This is **not Store screenshot acceptance, a full pixel-decoder qualification,
or evidence that the native image test has already executed**.

The journey has one nonrenewable300-second XCTest allowance. Every ordinary
affordance wait is at most5seconds; an active native wait is at most48seconds
(the product's30+8+10 lifecycle window), bounded by the same overall deadline.
Known terminal refusal/Unknown headings end the wait early. The workflow must
also enforce a seven-minute outer original-command ceiling. It must verify
the original exit result plus exactly one selected passed test and zero skips.

Native sheet/menu/Go to Folder accessibility is intentionally an **actual
runner obligation**. Missing/ambiguous controls fail with bounded stage/role
counts. There is no DOM injection, AppleScript, global UI/PID discovery,
coordinate click, preset selected URL, app hook or permission-policy repair.
A broker/query refusal does not justify changing the application speculatively.

Only completed stages print passed markers; the first failing stage is failed
and later stages remain not-run. The markers are not replacements for the
original XCTest result or independent native-owner finality evidence.
Framework terminate remains failure-only even after a partial journey.
Original fixture descriptors are consumed once on success or failure; no
other task's process, directory or shared cache is touched.

Retain the small fixture path with task-local evidence until the disposable job
is retired if all-worker finality is unavailable. Its same-time file content
is bounded; it is not permission to delete a potentially live recovery journal.
Raw screenshots, xcresult and transcripts remain task-local, never preview
assets. Even after a successful UI journey, **cleanExitStatus remains null and
allWorkerFinality remains unestablished**. Signing, release execution,
Store mutation, physical-Mac behavior and whole-product readiness are not
proved by this fixture.
