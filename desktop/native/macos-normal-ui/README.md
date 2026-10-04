# Ordinary macOS application: external UI scenario

This is one external XCTest UI target, not a second engine, application hook
or in-process observer. It uses the unchanged ordinary app's real runtime,
confirmations, owners and cleanup policy.

## Admitted environment and original launch

Only a **fresh exclusive GitHub-hosted macOS26 ARM64 runner** is supported.
The normal route binds its same-build Cargo binary, package, standard Installer
and independent nonroot byte/mode readback. The separately selected reuse route
below binds its older app and current harness independently. Never point either
route at a shared/personal desktop.

Account admission uses one bounded getpwuid_r lookup of the original UID,
requiring matching UID/GID, runner name and /Users/runner account home.
Foundation's sandbox home is diagnostic, not account authority. Both launch
callers share the same owner; no runner TMPDIR/CFFIXED_USER_HOME is forwarded.
Persistent fixture preparation still admits the account before inspecting the
default vault namespace. The account-only native pass is not app qualification.

The fixed outer app is
/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app.
Both its and its nested payload's URL proxies must initially be notRunning,
and the permanent gate must be free. Bundle IDs are routing checks, not
substitutes for Installer/readback/source receipts. No occupied app is adopted.

One NSWorkspace request opens the outer URL with empty arguments, activation
enabled and running-app substitution disabled. The unchanged entry constructs
its clean eight-entry environment. The first callback's NSRunningApplication
is retained before validation. Require its exact payload bundle, executable
and identifier, active/finished/live state, and the same gate busy.
The payload-URL XCUIApplication is monitoring/UI-only, **not a documented
original-PID attachment**. Never launch, activate, open or terminate that proxy.

The tiny target has no app-under-test build target or package dependencies.
Full Xcode is selected only for UI steps, never via a machine-wide switch.
Missing Xcode/UI broker/GUI/permission support fails; it does not authorize TCC,
Accessibility, Gatekeeper, credential or entitlement repairs.

## Exact basic scenario and claim

The old testLaunchCancelAndQuit remains same-build-only:

1. Perform the single ordinary launch and original/payload admission above.
2. Require the unique main window, first-party renderer, dashboard heading and
   enabled Open project folder control.
3. Exercise the real native project picker and Cancel without selecting a project.
4. Use the app's own File → Quit. Require the exact native confirmation and its
   unique Cancel/Quit buttons. Cancel, then prove dashboard responsiveness by
   navigating to Project settings and back without project/Store operations.
5. Use File → Quit again and click the real affirmative Quit. Require payload
   proxy notRunning AND the retained original isTerminated, then the same gate
   free and consuming gate close. Both termination observations share the
   existing ten-second interval.

Only that first original may receive failure-cleanup terminate and, at most
once if necessary, forceTerminate. Boolean request returns are not termination
observations. Any cleanup means a failed scenario; unknown state is retained.
Late callbacks are cleanup-only; duplicate/error/absent/wrong identity latches
failure. There is no proxy/PID/bundle lookup, relaunch or replacement receiver.

A monotonic clock starts before any in-case admission. The existing60s XCTest
allowance and every per-wait maximum remain; all waits consume that same case
budget. Launch/identity is at most15s. All failure cleanup shares at most5s,
capped by the original case end. No helper, callback or restored stage limit
resets it. Every final scenario marker, including extended journeys, requires
original termination and gate acceptance. Build4min/test3min outer ceilings
remain. Apple's whole-minute allowance is not a claimed precise90s timeout.

Original xcodebuild0, exactly one selected passed test and zero failed/skipped/
expected failures are required. A marker, restart or zero-test framework result
is not success. No skip, automatic rerun, app-path switch, global keystroke,
permission change or live service operation is admitted.

**Not proved:** POSIX app exit status, every worker/descriptor's finality,
Finder/Installer UI, Gatekeeper/notarization, Intel/older macOS, real signing,
Store operations, release readiness or complete Desktop feature acceptance.
cleanExitStatus remains null; allWorkerFinality remains unestablished.

## Actual generated runner and evidence

Build this small runner once, then use test-without-building on its exact
generated xctestrun products. macos_normal_ui_runner.py authenticates the
bounded Build/Products roster, retains critical originals, strictly verifies
the actual generated .xctrunner signature and parses its actual entitlements
before any app request. Empty/malformed/unknown inspection or app-sandbox=true/
non-Boolean refuses launch. Absent and explicit false are reported distinctly,
not as proof of no OS restrictions. Project ENABLE_APP_SANDBOX=NO and the old
standalone observer are not substitutes for inspecting this runner.
No re-signing or permission repair is attempted. The same products are checked
before/after the original command; all owned closes must complete.

All five existing normal-workflow selections use this admission and remain
same-build-only. Closed runner receipts accompany their existing UI results.
Raw xcresult/full logs stay task-local; only closed facts and existing bounded
credential-free diagnostic tails enter the engineering artifact. The user
preview still contains only its pkg, README.md and PREVIEW.json; export-stage
unexecuted UI fields are never rewritten into later XCTest receipts.

Only after accepted results/upload may the existing normal job retire its
settled compiler outputs. No shared service/cache is stopped/deleted. Failed,
unknown or possibly-live app/fixture/installation/journal state is retained
until the disposable job is retired.

## Fixed reused-package first-case selection

Only testPackagedEntryLaunchCancelAndQuit selects the private reuse profile.
It shares every basic picker/Cancel/navigation/normal-Quit assertion above.
The old basic method and all extended methods stay same-build-only; there is
no generic environment override for source equality.

The exact verify/desktop-macos-packaged-ui PUSH selects only packaged_ui in
desktop-macos-entry-diagnostic.yml. Both old diagnostic jobs remain confined
to the old push/ref. No direct-entry dependency/rerun, default-branch edit or
generic dispatcher is required.

Reuse application source8b67300f92d2e92cf909a0da12850a678bc2812f,
source run37195548745/attempt1 (.github/workflows/desktop-macos-installed.yml),
artifact11301302356 (56256693 bytes; SHA256
a4dd135994251b3663da354650c7aa3e158134f12c236752f610af6baf75d64b),
and inner package56247938 bytes (SHA256
024523ce33675ecdad8e678b3fe5981f2824ccc26b4477e0bb1f5a6c196ee0ea).
Fresh-only Installer/readback, actual current harness source/roster and actual
runner admission are separate bindings. No app/runtime rebuild, package
mutation or fake same-source receipt is permitted.
Only the external harness is newer: the application remains that exact8b package.
Both basic methods share the same one-shot finite require-site diagnostic; this
packaged-only route keeps its dedicated parser and never widens NORMAL_SELECTIONS.
sameBuildQualified, fullUIQualified, fullM2Qualified and productReady remain false.

Only this new diagnostic UI profile uses /Applications/Xcode.app/Contents/Developer;
old diagnostics retain CommandLineTools. The closed ui-test.json requires
original xcodebuild0, one selected pass without retry, and original+gate terminal
observations. Raw results and possibly-live state stay task-local. This SOURCE
correction neither explains the prior XCTest failure nor claims a native pass,
same-build qualification, POSIX/all-worker finality, full UI/M2 or product readiness.

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
   transaction controls and .git. Use actual File → Quit, require the same
   original terminated, payload proxy notRunning and gate free/closed, then
   complete final readback and consuming descriptor closes before publication.

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
Original-reference terminate/forceTerminate remain failure-only after a partial journey.
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

## Synthetic encrypted-credential journey (separate selection)

Select only
`MRKNormalAppUITests/NormalAppUITests/testSyntheticPersistentCredentials`
after the original installation/readback and basic normal-launch gate. Reuse
the same built runner; unrelated metadata/image journeys are not prerequisites.
This is the **enabled private candidate's acceptance case**, not evidence that
it has already run. The ordinary Mac persistence selector must be enabled in
the actual tested application, with its original Supervisor/document and fixed
helper pins intact. Selected-helper reports describe that different mechanism;
they do not substitute for this ordinary UI journey. Other platform, signed-iOS
and distribution qualification gates are unchanged.

The bundled `Fixtures/normal-persistence-v1.json` has a closed11-file roster,
under11KiB encoded and under8KiB decoded. It contains a saved synthetic iOS
candidate/signing configuration, inert project metadata, a preservation
sentinel, and two original files **outside** the selected project. The P12 and
profile are the existing signature-less DER canary envelopes, not usable Apple
signing assets. Originals are0600, directories0700. The app's real assessment
must say **Configured only**, with native/service checks not run and release
readiness unknown. This journey never archives, signs or accesses a Store.

Through ordinary native pickers and accessible controls, it:

1. Opens uninitialized storage; reviews and explicitly creates the encrypted
   vault. Only then submits the iOS/candidate/build-signing context.
2. Selects each inert original, prepares the actual assessment/save review and
   confirms saving. Saved records must be unassigned and not checked for stored
   use. Each needs its own **Assess and assign → Assign** confirmation.
3. Changes to the admitted Store-only context and back, without any Store
   command. Earlier assignments stay unavailable until explicitly reassigned.
4. Locks, reopens and explicitly unlocks the same store. Reloaded records remain
   unassessed/unassigned until separate new assessments and Bind confirmations.
5. Begins replacement and cancels the native picker. The chosen-file original
   owns a vault lease: its STOP conservatively closes the **whole session**.
   Require known original settlement, no exposed assignments and unchanged
   ciphertext, then reopen/unlock explicitly. Unknown settlement is a failure,
   not permission to continue or silently restore assignments.
6. Replaces only the current P12 revision with the same preserved inert source
   and different fictional fields. Only that ciphertext changes; revision1
   becomes2 and fresh assessment/Bind is required. Separately reviews and
   deletes only the profile, preserving the P12 assignment and unrelated files.
7. Locks, preserves the original mutation receipt, checks files and quits using
   the real File menu. Every mutation requires known-applied/confirmed/known;
   idle status alone does not establish success.

Before **any application launch**, the harness retains NoFollow ancestors and
requires `/Users/runner/Library/Application Support/dev.mobile-release-kit.desktop`
absent, including dangling links and bounded case/normalization collisions.
Existing state is never adopted, erased or repaired. After the app creates its
real store, bounded readback requires0700 directories and0600 single-link,
zero-flags files, no aliases and no unexpected mutation/candidate leaves.
The initialized control roster is `vault-lock` (0bytes),
**`initialization-reservation` (48bytes, permanent)** and `vault-header`
(104bytes), plus at most two `record-<32 lowercase hex>` leaves. The permanent
reservation is an intentional engine invariant, not leftover mutation debris.
Readback is at most64KiB total/32KiB per leaf; unchanged identities/bytes and
absence of known plaintext canaries are accounting, not cryptographic proof.

Passwords are fictional DATA typed into the normal secure field, never read
back or put on the clipboard. No Keychain enumeration/unlock/repair, custom
app-data location, observer argument, DOM injection or permission grant is
used. Native provider refusal ends the case; user consent is not a repair.
Retain the tiny project/store and synthetic protected-key row for disposable
job retirement; never erase possibly-live recovery state. Harness-owned FDs
are consumed once, independently of failed app cleanup.

Use one nonrenewable300-second allowance and a seven-minute workflow ceiling.
Require the original XCTest command to succeed with exactly one passed test,
zero failures/skips, and exact application/harness/helper bindings. Export only
closed stage/count/result facts for this private-input journey, not raw test
logs, screenshots, password keystrokes or xcresult contents. Session reopening
is **not application-restart/upgrade continuity**. Original POSIX exit and all
worker finality remain unavailable to XCTest UI observation; native owners,
helper/provider and filesystem qualification remain separate obligations.
