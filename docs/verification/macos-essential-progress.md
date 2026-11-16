# Essential macOS work ledger

Base: `c52b57a5ef2d877e03be66387301266729aaa36d` on `release/desktop-production`.
Implementation branch: `fix/macos-remaining-essential`, in its own worktree.

All work is local. Application releases, installers, signing, notarization,
publication, release/workflow changes, installed-app modifications and real-user
project interruption tests are excluded. Local compiles use one job and a
3 GiB aggregate compiler RSS cap. Synthetic fixtures and test binaries are allowed.

## Ownership boundary

The independent `fix/macos-difficulty5` agent owns #47, #48 and #49. This branch
does not change its checkout, refs, commits, helper shutdown implementation,
installer, updater or their native lifecycle machinery. Findings in those areas
are recorded for coordination. Shared consumer interfaces are preserved.

## Sequential checklist

| Issue | State | Commit | Evidence / remaining verification |
|---|---|---|---|
| #45 workspace failure | DIAGNOSTICS/FALLBACK FIXED; ORIGINAL INCIDENT BLOCKED | `0278652e` | Persistent bounded journal, safe error boundary, helper-state render regressions; 2,463 frontend tests and TypeScript checking pass. Original installed exception remains uncaptured. |
| #46 first connection | STEP DIAGNOSTICS ADDED; ORIGINAL INCIDENT BLOCKED | `1e7c4411` | Two diagnostic tests pass; whole-source check pending. No failing native predicate or first-launch race is proven. |
| #17 Git timeout | MACOS INIT DEFECT FIXED; ORIGINAL TIMEOUT BLOCKED | `ff2571cf` | Fixed per-call/phase traces; protected-ancestor regression passes. Broader tests recorded below. |
| #65 interruption integrity | CORE CRASH MATRIX VERIFIED; GUI GATE OPEN | `f20b9463` | Eight real SIGKILL/restart scenarios across four durable boundaries; broader recovery regressions tracked below. |
| #66 performance/memory | SOURCE BASELINE + HOT-PATH FIX VERIFIED; APP GATES OPEN | issue commit in branch history | Reproducible Node/SSR fixture, linear path matching, 10,000 controller cycles; installed one-hour/WebView/helper measurements remain open. |
| #30 macOS security | PENDING | — | Credentials/IPC/privilege review; coordinate native helper/installer findings. |
| #50 CLI status | PENDING | — | Diagnose permission refusal and verify enabled path/guidance. |
| #62 Android journeys | PENDING | — | macOS fixtures; no personal device, account or real signing material. |
| #63 iOS journeys | PENDING | — | Test-only unsigned fixtures; account/hardware/signed acceptance gates recorded. |
| #64 Store journeys | PENDING | — | Credential-free contract tests; real accounts are an external gate. |

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
check is also queued under the local compiler cap; its result will be recorded
before delivery.

Remaining #46 gate: a trace from the actual first-launch failure, in an authorized
test installation or the existing app once it contains these diagnostics. No
installed app was changed, and no speculative retry or deadline increase was
implemented. Helper registration/lifecycle code remains owned by #47–#49.

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

The broader Store recovery-settlement fixture currently fails its upstream
inert Play-preparation protocol before recovery starts (18 cases); investigate
that contract under #64. An alternate `/private/tmp` run also cannot create
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
protocol failures remain separately assigned to the conditional #64 review.

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
