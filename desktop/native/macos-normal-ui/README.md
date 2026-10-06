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

Reuse application source53850a9fd94768a2521f2634db6121550dbdd71c,
artifact11281078057 (50972943 bytes; SHA256
dfb46e23f7b397facc1a9b69b77d1440960fb846bedc90a573f2410b230255d0),
and inner package50964188 bytes (SHA256
618c873f0b841b54faceae9e5ad1ca073a94215a1a53cee0bf28c3aa17361119).
Fresh-only Installer/readback, actual current harness source/roster and actual
runner admission are separate bindings. No app/runtime rebuild, package
mutation or fake same-source receipt is permitted.

Only this new diagnostic UI profile uses /Applications/Xcode.app/Contents/Developer;
old diagnostics retain CommandLineTools. The closed ui-test.json requires
original xcodebuild0, one selected pass without retry, and original+gate terminal
observations. Raw results and possibly-live state stay task-local. This SOURCE
correction neither explains the prior XCTest failure nor claims a native pass,
same-build qualification, POSIX/all-worker finality, full UI/M2 or product readiness.

## Ordinary project-field Browse candidate

The undelivered candidate enables the existing normal Mac four-field gate and
the separate Android source-folder gate. This is availability for validation,
**not native qualification or delivery**.
The same project-test batch explicitly adds
`MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectPathFields` beside
`testSyntheticProjectLocalEditsAndImages`. It reuses the same admitted runner,
ordinary app launch, original owner and native sheet/quit helpers. The basic
normal launch/Cancel/navigation/Quit gate still runs first.

The new case uses normal-project DATA, not credential/persistence DATA. Four
literal selection-only files join its existing complete bounded fixture inventory;
no extra resource, valid Xcode build, signing input or Store content is implied.
The real Browse sheets select version source, Xcode project, Xcode workspace and
metadata folder. A real file Cancel and folder Cancel preserve the selected values.
Navigation retains all four relative draft values, including both conflicting
Xcode fields. **Review draft changes** must show the retained baseline and invalid
format result. The case never prepares Save, copies files or clears the conflict.
Complete saved fixture bytes/roster must remain unchanged through normal Quit and
consuming fixture closes before its supplementary result markers can be emitted.

Immediately after project registration and before any draft edit, that same case
uses the three public named role groups in Releases for exactly six native actions:
JDK, SDK, Gradle, Cancel on the already-selected JDK, a distinct JDK reselection,
then genuine Open on an owned deep directory followed by backend SourceRefused.
Cancel and refusal must retain the previous role selections. AppKit exclusion,
Cancel, Unknown, timeout or another refusal reason cannot satisfy that last step.
The five extra literal README markers contain no supplier/tool payload and belong
to the same fixture owner, separate from the unchanged four project-field files.
Precreation and postcreation censuses bind22 files and143 directories (root included).
Three anchors yield146 retained fixture FDs,147 with one transient read/enumeration
FD; the test's original gate is separate. The refusal directory has125 relative /
128 absolute normal components and305 path bytes. This is a finite census, not an
OS descriptor-headroom or native timing claim. Existing64-child,32-KiB-leaf and
256-KiB-total DATA limits remain unchanged; the complete DATA total is13,885 bytes.

The runner compares its captured original command output for exactly two selected
starts/passes, two original owner/gate markers, three distinct result markers and
no failure cleanup. The extra Android marker is emitted only after the same final
owner/fixture checks, and admitted only on the same original zero return. The
workflow requires its separate comparison flag plus the original command/receipt closes,
matching720/885-second deadlines and two-pass native summary. Marker text alone
cannot replace original native execution or prove POSIX/all-worker finality.

Exact-source finite-ten AppKit/APFS field acceptance (four selections, two Cancels,
outside/link/kind/root-change refusals) remains separately required before this
profile may be delivered. That fixture's receipt still cannot enable shipping.
Manual relative text entry remains available. The Android ordinary native pass is
also separately mandatory on these exact enabled bytes. Its selection-only scope
does not qualify supplier inspection, protected copying, builds, link/wrong-kind
handling or all-worker finality. The existing300-second case, two-method720-second
command and885-second phase remain unchanged; there is no third case or retry.
No current native pass is claimed.

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
Known terminal refusal/Unknown headings end the wait early. The current workflow
batches the image-inclusive journey with the separate draft-only field case below:
300seconds each, one720-second original-command cap and one885-second admission/
close phase. It requires the original zero, both exact selected passes and zero
failures/skips/expected failures; neither case replaces the other.

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
8. Only after that original app terminates normally, its gate is free and its
   original observation closes successfully, launches the **same installed app
   once more**. Keeps the first owner/gate/Quit facts, fixture originals and exact
   post-delete encrypted-store baseline; does not repeat admission/Initialize.
9. Selects the same project through the native picker and sets the same context
   while storage is closed. Open must show locked with zero visible/assigned
   records. Unlock uses the ordinary provider/helper; waits for the normal UI's
   automatic current-context acknowledgement, without pressing Submit again.
   Requires exactly the replacement P12/revision2, not assessed or assigned, and
   no profile, **before** explicit Assess/Bind. This observes ordinary UI state,
   not an internal pre-context-submission snapshot. Reassesses/binds the survivor,
   locks and genuinely quits the second original, with the store unchanged.
   Only then consumes the fixture originals and accepts both app lifetimes.

Before the **first application launch**, the harness retains NoFollow ancestors and
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
Require the original XCTest command to succeed with exactly one selected
start/pass and zero failures/skips/expected failures, exact application/harness/
helper bindings, and ordered first-lifetime/second-lifetime/final restart markers.
A missing/duplicate marker, framework retry, failure cleanup, stale first owner
or elapsed original deadline cannot become restart success. Both owners remain
checked through final acceptance and teardown. Only the active failed lifetime
may consume the original bounded cleanup allowance; the completed first one is
rechecked without another stop request or fresh cleanup window.

Export only closed stage/count/result facts for this private-input journey, not
raw test logs, screenshots, password keystrokes or xcresult contents. Diagnostic
stages alone are not success authority. Same-process lock/reopen alone is not
an app restart; this selection requires two genuine ordinary lifetimes of the
same installation. It is **not upgrade continuity**: the engineering installer
does not implement occupied-install update/repair/uninstall. Original POSIX exit
and all-worker finality remain unavailable to XCTest UI observation; native
owners, helper/provider and filesystem qualification remain separate obligations.
