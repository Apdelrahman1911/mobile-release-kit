# Essential macOS work ledger

Base: `c52b57a5ef2d877e03be66387301266729aaa36d` on `release/desktop-production`.
Implementation branch: `fix/macos-remaining-essential`, in its own worktree.

All work is local. Application releases, installers, signing, notarization,
publication, release/workflow changes, installed-app modifications and real-user
project interruption tests are excluded. Local compiles use one job and a
3 GiB aggregate compiler RSS cap. Synthetic fixtures and test binaries are allowed.

Current original-issue verdicts, follow-up commits and remaining gates are in
[the reopened status matrix](macos-essential-reopened-status.md), with numeric
receipts in [the reopened checks](macos-essential-reopened-checks.json).
The original #45, #46 and #17 incidents remain unresolved; no claim is made
that all ten assigned issues are fully resolved and verified.

## Ownership boundary

The independent `fix/macos-difficulty5` agent owns #47, #48 and #49. This branch
does not change its checkout, refs, commits, helper shutdown implementation,
installer, updater or their native lifecycle machinery. Findings in those areas
are recorded for coordination. Shared consumer interfaces are preserved.

## Sequential checklist

| Issue | State | Commit | Evidence / remaining verification |
|---|---|---|---|
| #45 workspace failure | DIAGNOSTICS/FALLBACK FIXED; ORIGINAL INCIDENT BLOCKED | `0278652e` | Persistent bounded journal, safe error boundary, helper-state render regressions; 2,463 frontend tests and TypeScript checking pass. Original installed exception remains uncaptured. |
| #46 first connection | STEP DIAGNOSTICS ADDED; ORIGINAL INCIDENT BLOCKED | `1e7c4411` | Two diagnostic tests and the whole-source check pass. No failing native predicate or first-launch race is proven. |
| #17 Git timeout | MACOS INIT DEFECT FIXED; ORIGINAL TIMEOUT BLOCKED | `ff2571cf` | Fixed per-call/phase traces; protected-ancestor regression passes. Broader tests recorded below. |
| #65 interruption integrity | CORE CRASH MATRIX VERIFIED; GUI GATE OPEN | `f20b9463` | Eight real SIGKILL/restart scenarios across four durable boundaries; broader recovery regressions tracked below. |
| #66 performance/memory | SOURCE BASELINE + HOT-PATH FIX VERIFIED; APP GATES OPEN | `4266d1c6` | Reproducible Node/SSR fixture, linear path matching, 10,000 controller cycles; installed one-hour/WebView/helper measurements remain open. |
| #30 macOS security | APP LOCK PATCHED; COORDINATION GATES OPEN | `b8169e10` | Scoped report, 335-command inventory, credential/wire tests; independent helper locks and Tokio pin need coordination. |
| #50 CLI status | INTENDED GATE DOCUMENTED; GUIDANCE FIXED | `ed423ce6` | Exact UI steps, three actual shared Rust formatter tests and 58 frontend access tests pass; signed installed observation remains open. |
| #62 Android journeys | REAL FIXTURE COMPILE + VERSION PROPAGATION PASS; UI GATE OPEN | `1bc113bd` | 180 tests, two disposable Gradle builds, actual typed version edit and APK inspection; protected installed/helper journey remains open. |
| #63 iOS journeys | UNSIGNED REAL FIXTURE/CORE INSPECTION PASS; SIGNED GATE OPEN | `b18af24f` | Simulator build, unsigned Debug archive, typed version propagation; 63 focused tests. |
| #64 Store journeys | FIXED PROVIDER FLAG MISMATCH; ACCOUNT/HOST GATES OPEN | `2e8f6c1d` | 136 network-denied provider contracts, 52 source/owner tests, 52 preparation/recovery tests and 51 frontend tests pass. Protected Xcode qualification refuses this host's writable ancestor. |

## Evidence policy

Local test outputs are retained outside the source checkout. Reports use
repository-relative paths and synthetic identifiers. No raw owner logs, signing
material, real project data or local machine paths are committed. A local test
pass is recorded separately from installed-app or hosted-release acceptance.

## #45 investigation

The retained application observations confirm a workspace error after helper
approval and a successful later normal quit/reopen. They explicitly record
`rawExceptionKnown: false`. The current frontend, rendered with inert native
refusal ports, survives initial render, navigation and focus-return events.
The original installed exception is therefore not yet attributable to a
particular component. Future reproduction needs the persistent diagnostic
record; this task does not modify or reinstall the owner's app.

Implemented a 16-record local WebView journal with fixed failure codes,
component names and connection/focus phase. It excludes raw error messages,
stack URLs, paths and request/project/credential values. Storage failures,
corruption and hostile exception accessors cannot throw a secondary reporting
error. A confirmed secondary defect in the old boundary (reading exception
getters without protection) is covered by the actual boundary fallback render
test. It is not asserted to be the cause of the old installed incident.

The actual helper view renders parsed requires-approval → enabled →
not-registered → unavailable observations without invoking a native operation.
The full frontend suite passes 2,463 tests with Python 3.11 on the subprocess
PATH; TypeScript checking passes. The initial suite attempt selected the
system Python 3.9, below the project's declared >=3.11 requirement, and was
repeated with the supported interpreter. No helper, installer, shutdown or
upgrade implementation was changed.

Remaining #45 gate: obtain a diagnostic from the failing installed workspace
or reproduce it in an authorized test environment. The retained observations
say the raw exception is unknown. No current synthetic render reproduces it.

Reopened #45 investigation does not require the owner to remember the lost
exception. The retained historical system log was inspected privately; the
historical boundary did not retain a React exception. A full mounted-App matrix
now covers historical `ac506bb3` and current source, initially unavailable and
available runtime, event-before-reply and reply-before-event, registration and
already-registered paths, duplicate events, settings/focus return, workspace
loading/navigation and subscription retirement. All sixteen controlled
cases pass. A separate test-only Cocoa/WKWebView host on macOS 27 runs the real
DOM/effects sequence on both trees, with no real helper call or product worker;
both return 0 without a fatal boundary.

The exact historical Python core was also exported read-only and used against
the disposable project. Its capabilities and version payloads match current
core DATA exactly; its snapshot differs only by observation time. The historical
WebView journey passes again with those historical responses. A further native
profile case fills the non-null installation description and project-path
availability, and retains the real `bundled` mode even while capabilities are
unavailable; historical source also passes that sequence. This closes gaps in
the initial preview-derived DTO fixture without asserting native qualification.
The fixed background service is the Android registration helper, not a separate
maintenance helper. No real OS helper approval was reset or requested. The
original failure remains unreproduced, its root cause remains unknown, and #45
is still unresolved. The controlled passes are negative reproduction evidence.

## #46 investigation

The retained first-connection reason maps to `AdmissionFailure::Native` in
`installed_runtime_macos.rs`, returned during the original passive capabilities
inspection. It covers native filesystem/ACL/signature operations, allocation,
manifest reads and decoding. The old evidence contains no exact failing native
predicate. A later successful reload alone does not prove a race or authorize
weakening those predicates.

Each new inspection book now retains a fixed diagnostic phase. On an inspection
failure it emits one fixed step code (admission, record reservation, protected
application, runtime root, manifest open/read/decode, inventory, payload walk or
final validation). No path, native exception text, request or credential enters
the diagnostic. A closed output sink preserves the exact original failure and
introduces no retry. Two isolated Rust tests cover distinct bounded codes and
failure identity with an unavailable diagnostic sink. The full headless source
check passes under the local compiler cap; the final source-check receipt is below.

Remaining #46 gate: a trace from the actual first-launch failure, in an authorized
test installation or the existing app once it contains these diagnostics. No
installed app was changed, and no speculative retry or deadline increase was
implemented. Helper registration/lifecycle code remains owned by #47–#49.

Reopened #46 followed the complete native inspection book. Its protected
application/runtime filesystem and manifest proof does not call the background
helper. Adding a helper-ready wait would therefore be speculative. The fixed
payload check also compares `current_exe()` with the protected installed
executable; an independently compiled test program cannot legitimately qualify
itself as that original installed image. No payload/path/signature predicate was
bypassed. The retained first-launch record still has no exact native errno or
failed predicate. OS provenance/metadata overlap, allocation and interrupted
native IO remain hypotheses, not established causes. Neither arbitrary retries
nor a timeout change were introduced. Original #46 remains unresolved.

## #17 investigation

The historical `GitCli(Checked)` timeout still has no original call return or
first driver exception. The driver caught worker exceptions and retained only
a failure boolean. Added fixed per-call entry/return/exception records with
elapsed/remaining budget, phase waits, worker failure and final thread join.
Arguments, paths, output and exception messages are excluded. An unreturned
call remains in flight; diagnostics never retry, renew the 120-second endpoint,
or invent settlement. Three new actual-driver regressions distinguish response
validation failure from a lost call return and verify a closed trace sink.

Broader portable testing reproduced a separate actual macOS defect:
`git_repository_init.directory` rejected every nonzero Darwin flag while walking
system ancestors. Real `/` and `/Users` carry `SF_NOUNLINK`, so initialization
failed before Git dispatch. The read-only ancestor check now uses the same
fixed protection/display mask as `git_source_flags_macos.rs`, and includes the
exact flags in its revision comparisons. Project/candidate leaves still require
zero flags; mutable flags, unknown flags and nonroot system flags remain refused.
This is not claimed to explain the historical `git-index-cli` timeout.

Initial focused results: 16 driver tests, 27 initialization tests and 2,463
frontend tests pass; three stock-Git initialization tests have explicit
Linux-only guards. Of 88 macOS Git driver/roster tests, 87 pass and the source
projection fixture refuses OS-added extended attributes. No installer/custody
check was weakened to make that fixture pass. Portable real-Git tests use a
physical private temporary namespace, because the system temporary spelling
contains a symlink. Final broader results are recorded before delivery.

Remaining #17 gate: trace the original installed Git journey and complete its
11 native groups after the independent installation prerequisite is resolved.
Those groups require an authorized installed/test application; this task neither
builds a release nor changes the installed app. No timeout increase was made.

Reopened evidence recovered the exact original job log (86,817 bytes), matching
SHA-256 `3d7ee0d62851b4ea90536b95be53f436a7496c6d1f1df79397f516ab15163708`.
The original step measurements include 20.062240s initial read wait, 29.020745s
Prepare and 35.279288s terminal/Apply observation. Checked is pending at the
whole-case deadline with 5.675875s elapsed in that step. The earlier work has
consumed almost all the case budget; the log still contains neither a return
for the pending call nor its first exception. No retained artifacts are listed
for that run. This narrows profiling but does not identify or eliminate the
original cause. The optimized runtime SHA2 dependency was already present at
the failing source; no speculative hashing change or larger timeout was made.

Final #17 checks: the broad corrected-path run exercised 584 tests: 570 passed,
three Linux-only cases skipped, ten initialization tests failed against the
pre-fix module loaded when that long run started, and one fixture failed because
case-insensitive APFS cannot create distinct `main` and `MAIN` files. The ten
initialization failures pass in the fresh affected run. The case-folding fixture
now uses exclusive creation and explicitly skips only the impossible distinct
case collision; its directory-refusal check is a separate test on every host.
The fresh affected run covers initialization, fetch and the real driver code.
The 205-test desktop Git run's ten errors were the same initialization defect;
its affected initialization group also passes after the fix. Full outputs are
retained as separate runs; these are not presented as one post-fix green run.

Final complete source rerun: all 660 Git core and desktop-worker tests complete
in 359.75 seconds: 656 pass, four explicit platform/filesystem cases skip, zero
failures. This supersedes the earlier loaded-module failures for those groups.
An intermediate rerun under physical `/private/tmp` refused 16 upstream cases
because that namespace inherits a different group; the final run uses the
canonical private test directory with the account's original group. No group,
ownership or source check was relaxed. The separately recorded macOS source
projection/extended-attribute qualification and 11 installed groups remain gates.

## #65 interruption integrity

Extended the existing real edit-engine restart fixture with eight self-SIGKILL
scenarios: two saved-text domains (metadata and version) at staged-before-READY,
first completed new-file replacement, durable COMMITTED publication, and partial
journal cleanup. Each signal targets only the disposable test child's own PID.
The original process supervisor must publish finality and retire its creation
and run resources before a fresh recovery process starts or fixtures are removed.
All eight scenarios pass: present files are complete old/new payloads at the
interruption; recovery produces the complete old transaction before commit or
the complete new transaction after commit. Unrelated file bytes and identities
are unchanged. All journals are cleaned after explicit successful recovery.
The existing two-domain abrupt-exit/restart test also passes (20 joined child
invocations across the two restart tests).

Two inert edit-engine input doubles lacked the current `reserved` cleanup field;
updated those fixtures, without changing runtime behavior. A legacy all-write-
boundaries test incorrectly demanded erasing a journal after an uncertain
terminal rename. It now requires complete files, retained journal and truthful
attention, followed by a fresh explicit recovery that restores the exact old
snapshot. No file corruption was found. A confirmed classification defect did surface:
set-order-dependent cleanup checks reported the same replaced journal object
as either `stale_revision` or `filesystem_error`. Completed captured-identity
comparisons now raise a stale conflict consistently during guarded recovery;
actual IO exceptions and every preservation/finality rule are unchanged.

The initial broader Store recovery-settlement fixture failed its upstream
inert Play-preparation protocol before recovery started (18 cases). The #64
clock-domain fixture correction resolves this; all 52 preparation/execution/
reconciliation/recovery tests now pass. An alternate `/private/tmp` run could not create
set-group-ID fixture modes when its inherited group is unavailable to this
account. Final canonical private-namespace results are recorded before delivery.

Remaining #65 gates: installed GUI termination/relaunch, Prepare-and-quit (owned
by the independent shutdown agent), and actual power-loss/filesystem durability
under a hosted RC. Source-level SIGKILL tests are not those acceptance claims.
No real project, installed application or helper was terminated or modified.

Final #65 result: all 146 recovery/configuration/metadata/init tests pass in the
canonical private fixture namespace. The replaced-journal regression also passes
in eight fresh interpreters with `PYTHONHASHSEED=0..7`, covering different set
orders. The two real restart tests cover 20 original child invocations, including
eight SIGKILL/recovery pairs. No project corruption was observed. Store fixture
protocol failures were subsequently resolved under #64 without production clock changes.

Reopened verification adds `test_project_crash_recovery.py`: twelve actual
SIGKILL/fresh-process recovery cases across image import, Android application
identity and iOS bundle identity. Each domain is interrupted before READY,
after the first actual new-file replacement, after COMMITTED, and during backup
cleanup. Twenty-four original child outcomes prove signal/normal returns,
complete result delivery and retired resources before subsequent recovery.
Every present edited file remains a whole old/new payload; explicit recovery
produces the complete pre-commit original or post-commit result, preserves
unrelated file bytes and identities, and leaves no journal. The combined
saved-text, image and identity regression group passes 57 tests in 30.488s.
This extends verified core coverage to five write domains. It found no new
corruption defect and does not prove installed GUI/app-state recovery, physical
power-loss durability or shutdown behavior. Those original acceptance gates
remain open, and no installed application was killed.

## #66 performance and memory

The maximum admitted 512-path review comparison used repeated linear scans.
Three such checks run through prepare/preview validation. A temporary membership
set removes the quadratic scan without changing matching semantics, limits,
reviews, permissions, retained originals or native calls; there is no persistent
project-path cache. Regression coverage includes reordered paths, mismatches,
duplicates, Unicode and the 512/513 admission boundary. All 2,464 frontend tests
and the normal frontend TypeScript/Vite build pass. The existing large-bundle
warning remains; no loading architecture was changed without a runtime profile.

See `macos-essential-performance.md` and its numeric JSON receipt for the
repeatable isolated-source baseline and exact limits. No installed application,
helper, user project, signing identity or account participated. The actual app's
startup/idle WebView memory and one-hour resource behavior remain hardware gates.

## #30 scoped security review

See `../security-review-0.1.4-macos.md`. Fixed the application's vulnerable
ctutils resolution from 0.4.2 to 0.4.4 with a two-field lockfile change. The
independent desktop-image and Android-registration graphs retain their own
locks and require owner-agent coordination; they were not edited. Tokio's
pinned-runtime advisory is also recorded for coordinated update/regression.
No app, helper, installer, Keychain, account, secret value, setting or workflow
was changed. Ninety credential tests pass plus one filesystem-specific skip;
seven native-independent wire tests and targeted frontend security tests pass.
The patched crypto package and current-lock application source compile under
Rust 1.98.1; full #30 production approval is not claimed.

## #50 CLI status

Read access is intentionally explicit. `version`/`capabilities` are offline;
`status` becomes a fixed Info request to the authenticated live-grant service.
The unavailable message now names Project settings, the Advanced CLI/AI panel,
Check access and the one-hour Allow button, with foreground cached history as
an explicit separate option. Live and cached status text now share a pure,
actually used formatter with three passing Rust tests. Fifty-eight frontend
access/permission tests pass. See `../macos-cli-read-access.md` for trace and
steps. No grant, service state, installed app or default permission was changed.
A signed installed transition observation remains a gate; it cannot be supplied
by inert/controller tests. The installed-cli feature source check passes.

## #62 Android journeys

See `macos-functional-journeys.md`. A real Java Android debug fixture builds with
existing public toolchains, including after the actual typed core version edit;
SDK inspection verifies the edited version in the APK. All 180 focused tests
pass. A test-host compatibility defect in inert Linux xattr mocks is corrected.
No MRK release, installed app, protected tool registry or real project was changed.
Full installed UI/native/helper and signed acceptance remain separate gates.

## #63 iOS journeys

See `macos-functional-journeys.md`. The real Xcode simulator and unsigned Debug
archive fixtures both contain the typed-core edited saved version; the actual
core archive/Mach-O inspector accepts the archive. Existing 62 focused tests
pass after fixing test-only raw-clock substitution, private output-root mode,
current action expectations and the Darwin descriptor-directory spelling.
The permanent iOS-only source transaction regression also passes: 63 focused tests total.
No production timeout/permission/native helper behavior changed. Signed export
and installed GUI/account/device verification remain gates.

Whole-source Rust library check: PASS with Rust 1.98.1, locked dependencies,
no default features, one job, peak group RSS 2,812,182,528 bytes (<3 GiB). The
initial one-hour catalogue attempt stopped at its runner deadline and is kept
separate. The current-lock retry completed in 32m29s after cache reuse. Existing
compiler warnings remain. The locked installed-cli feature / `mrk` binary source
check also passes with one job in 4m46s, peak RSS 2,684,518,400 bytes (<3 GiB).
Neither command builds a release, installer or distributable application.

## #64 Store journeys

See `macos-functional-journeys.md`. The real account-backed acceptance remains
blocked by approved candidate/account prerequisites; no account-backed request
or Store mutation was attempted. A source defect independently reproduced:
the Python fixed CLT Git provider rejected every Darwin flag, including the
actual system root's protection flag. Its native provider already permits a
fixed protection/display mask for root-owned directories and compression for
the fixed root-owned executable. The Python layer now matches that exact policy
and additionally compares observed, held and named flags on every check.
Changed allowed flags, held/named disagreement, unknown/mutable flags, writable
modes and wrong owners are refused. No native selection, custody, permission,
mode, identity, finality or timeout check is bypassed.

All 136 credential-free provider contracts pass with socket creation denied.
All 52 source/owner protocol and real temporary version-edit tests pass, including
four new flag regressions. All 52 Store preparation/recovery tests and 51 focused
frontend tests pass. Native raw-clock preservation corrects the Store fixture's
same clock-epoch mismatch found under #63. APFS refuses creating a 1,025-byte
symlink target itself; only that unrepresentable subcase is skipped. Escape,
cycle, malformed-target and the other application refusal tests remain active.

Read-only real `xcrun --run altool --help` passes with original process settlement.
The broader iOS/stage/metadata run is 92 tests: 90 pass, one filesystem skip and
one host-qualification failure; it is not an all-green run.
The protected Xcode resolver's positive qualification is blocked on this host:
the actual `/Applications` directory is root-owned mode 0775, rejected by
`local_store_execute.py::_upload_protected` before pending state or credential
material. Group-writable ancestry is not relaxed. That qualification failure
and coordinated native/tool-selection policy need owner review before installed
Store acceptance. No installed tool permissions or helper code were changed.

## Final source review and integration notes

The full frontend rerun passes 2,464 tests with zero skips, and the normal
TypeScript/Vite build passes. The existing bundle-size warning is retained.
The final Git core/desktop-worker suite passes 656 tests with four explicit skips.
Sanitized counts, original Rust check returns, RSS peaks and private output
hashes are in `macos-essential-checks.json`. Those receipts bind source/test
checks, not an installed acceptance verdict. Raw logs remain private; in
particular, Xcode destination output can contain device identifiers.

This branch contains one local implementation/evidence commit for each of the
ten assigned issues. It has no merge, push, release, installer, workflow trigger,
application-version, repository-setting or installed-app change. No peer agent
was spawned. The other agent's checkout, uncommitted changes and refs were not
modified, and its work was not integrated.

Potential mechanical overlap is `desktop/src-tauri/src/installed_runtime_macos.rs`:
#46 adds a diagnostic field, initialization and failure-step reporting around
the existing inspection path. An eventual integration must preserve the other
agent's lifecycle changes and these original failure semantics. The application
`desktop/src-tauri/Cargo.lock` patch may also meet dependency changes during
integration. No independent helper/image lock was edited.

Coordination findings are the vulnerable independent helper/image locks listed
under #30 and the protected Xcode ancestry gate under #64. Their exact files and
observed refusals are documented, not repaired by changing installer/helper
ownership or writable-directory policy. #47–#49, #26 and #70 remain untouched.
Independent owner/reviewer approval and an authorized integrated installed
candidate are still required; these local results do not close the acceptance
issues or prove the three original installed incidents resolved.
