# QA-003 independent capture-handoff amendment review R5-R4

**Verdict: APPROVED for the final revised plan only.** The required terminal
borrowed-cancellation refinement is incorporated. This is not approval of any
implementation, final QA-003 delivery, commit/merge, or production readiness.

## Exact authority and snapshot

Approved `PLAN-CAPTURE-HANDOFF-R5-R4.md` SHA256:
`8ba50a5e7f5a2d61454d6828f0fac13055245a7bd8231e2e96f650325630ea66`.

The original submitted plan hash
`8f423854934cb11e91ca90d1ca9dc8b854609e4a86c8845b3b743c3a556dd7b0`
required the refinement below and is not the approved version. The existing
approved R2/final R3/R4/R5-R2 and online R5-R3 obligations remain in force.

Baseline HEAD `2beb37336fa8002b69f598fe431082606368310d`, tree
`00f3acee00c994e6e81470cc76e42f1f2108fcdb`, version 0.3.0, branch
`fix/qa-003-local-signing-lease`. QA-003 implementation is pending in the working
tree; the R5-R4 correction was not implemented at review close. Companion evidence
records file hashes; no immutable final implementation inventory is claimed.

Re-read the original QA-003 finding, relevant R1 lifetime/cleanup findings, the
approved R5-R2 lifetime/error contract and both versions of this amendment.
Inspected the complete current authentication/capture path, cancellation owner,
cleanup/fork protocol, lifetime exceptions/context aggregation, signing-session
classification, call sites, fixtures and assertion failures. Repository
instructions, SECURITY and applicable signing/provenance/readiness skills were
consulted. This is a narrow plan review, not a fresh entire-repository audit.

## Required refinement independently reproduced

At review baseline `ios_profiles.py:326-327`, authentication's terminal
`cancellation.check()` and return are outside its outer error conversion.
`CleanupScope.__exit__` intentionally checks pending cancellation only for its
own guard (`cancellation.py:208-211`), not for a borrowed guard. Consequently:

1. The actual worker completes, is reaped and its stream closes.
2. The first default signal arrives during actual authentication scratch cleanup.
3. Cleanup finishes under the borrowed guard's short deferral.
4. The terminal check raises a raw `KeyboardInterrupt` outside authentication's
   conversion; real dispatch and containment metadata are absent.

Merely adding a sibling `except KeyboardInterrupt` to the old handler placement
would fix the owning-guard case but miss this borrowed-guard path. The revised
plan explicitly places the terminal check/return within conversion and requires
both owned and borrowed regressions.

Independent probe `plan-review-capture-terminal-r5-r4.py` exercised four cases:
owned/borrowed guard crossed with actual default SIGINT/SIGTERM. It runs the real
authentication caller, scratch/file IO, IPC capture, nested cleanup, process-group
reaping and signal handling. Only the child command is substituted with a
fictional completion-frame emitter that kills its own newly created group. It
uses no profile, native signing command, keychain, application build or Store.

All four cases reproduced a raw cancellation without dispatch metadata. Borrowed
tracebacks end at `ios_profiles.py:326`; owned tracebacks pass through its scope
exit. Every exact worker was reaped/group absent, stream closed and scratch
removed **before fixture fallback**. Borrowed handlers remained owned by the
outer guard until that guard restored them. This proves the current classification
boundary defect, not a resource leak or acceptance of unauthenticated content.
It is a successful pre-correction observation, not a passing fixed-code test.

## Why the final plan is sound

- **The handoff becomes narrow.** The optional private observer runs only after
  `Popen` returned and its resource slot was assigned, inside the existing short
  acquisition deferral. The real authentication callback only records a local
  dispatch flag. It does not issue a command, mutate a journal, introduce a
  Store capability, or claim authenticated native success. Pre-spawn failure
  cannot become dispatched, and a capture-return interruption cannot erase an
  earlier observed spawn. The full capture call is no longer deferred.
- **Cleanup/error authority is retained.** A completed frame is not enough for
  success: original deadline, cancellation, exact process-group, stream, selector
  and scratch obligations remain. Explicit dispatch/containment and prior typed
  context must survive later cleanup/restoration failure. The latter remains a
  fatal `ProcessCleanupError`, not an ordinary interruption or optional absence.
  No retry or foreign/recycled PID/descriptor cleanup authority is added.
- **Borrowing and fork ownership remain intact.** The callback is local state,
  not parent resource authority. Existing child invalidation, late inherited
  handle cleanup, no parent-group signaling and same-thread/actual-owner checks
  still apply. The capture-open/capture-active real-fork fixtures and complete
  lease/profile composition tests must remain. A custom host signal handler is
  not silently converted into toolkit-owned default cancellation.
- **Test strengthening is appropriate.** The inspected 180-test development log
  reports seven failures, not success. One asserts the genuine full-call
  deferral regression. Four selector and two group/stream cases stop at obsolete
  message expectations. Their new assertions must prove the exact structured
  error, dispatch, containment, incomplete cleanup, fatality and redaction plus
  actual resources; broadly catching an exception would not be sufficient.
  A deliberately unresolved selector stays observed as unresolved until fixture
  fallback. Successful fallback cannot retroactively make cleanup complete.
- **No release/Store-state behavior is relaxed.** The proposal is confined to
  internal authentication lifetime reporting and its tests. It changes no CMS
  issuer/profile/entitlement policy, signed artifact identity, manifest/receipt
  chain, schema, source/workflow provenance, Store request or destination. It
  cannot overwrite an unrelated Store release because it introduces no Store
  interaction. Existing no-session quiescence and active-session recovery rules
  remain; a dispatch flag is not durable recovery or Store authority.

## Mandatory implementation checks and regression scope

The revised tests must use actual fictional children for dispatch-to-caller
interruption, first cancellation during owned/borrowed cleanup, and blocked
capture with depth zero. Check both default signal types where the relevant
fixtures support them. Pre-spawn cancellation must prove no spawn/observer call;
post-spawn handoff must prove dispatch true before pending delivery. Capture and
source resource observations must occur before fallback. A cleanup/restoration
error following completion or cancellation must remain fatal and retain the
most conservative explicit earlier containment/dispatch observation. No metadata
may be inferred from an exception string.

Retain exactly-once ambiguous close/reused-descriptor tests, combined group/
stream/scratch/handler tests and callback/fork/lease composition. Existing mock
capture seams may accept the new private optional argument, but real-child
regressions must establish its production handoff behavior. Update the short-write
mock to keep the independent depth-zero/private-source-byte assertions rather
than changing those expectations.

Re-run all seven failing cases and the broad R5 set. Then perform distinct
whole-diff implementation review, the separately approved R6 native-active
matrix and frozen complete source/native/wheel/project gates. This approval
neither replaces R6 nor certifies macOS credentialed compatibility. QA-004,
QA-005, remaining original findings and the mandatory fresh complete audit are
not resolved here. No READY or complete feature report is authorized.

## Executed checks, cleanup and limitations

Executed exit 0:

```sh
PYTHONDONTWRITEBYTECODE=1 .mobile-release/remediation/MRK-002/venv/bin/python -B \
  .mobile-release/remediation/QA-003/plan-review-capture-terminal-r5-r4.py
git diff --check
```

Probe output is in its `.json`, empty stderr in `.err`, exit code in `.exit`.
Source hashes before/after the probe matched. `git diff --check` is only an
interim whitespace check. The author's 180-test failing log was inspected,
**not independently rerun**; no complete suite, package build, signing/native
validation, network or Store rehearsal was executed for this narrow review.

Reviewer changed only ignored QA-003 probe/report/evidence files. All four
reviewer-owned child processes were reaped and group absence checked, temporary
scratch was removed and original signal handlers restored. No build process or
reviewer worker remains. Production, tests, public docs, index/refs and user
AGENTS.md were untouched. AGENTS SHA256 remains
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.
