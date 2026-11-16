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
| #46 first connection | STEP DIAGNOSTICS ADDED; ORIGINAL INCIDENT BLOCKED | issue commit in branch history | Two diagnostic tests pass; whole-source check pending. No failing native predicate or first-launch race is proven. |
| #17 Git timeout | PENDING | — | Preserve the original 120-second bound; diagnose calls/driver phases. |
| #65 interruption integrity | PENDING | — | Synthetic project fixtures only; installed GUI termination remains an external gate. |
| #66 performance/memory | PENDING | — | Reproducible test-environment measurements; physical Mac gates separated. |
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
