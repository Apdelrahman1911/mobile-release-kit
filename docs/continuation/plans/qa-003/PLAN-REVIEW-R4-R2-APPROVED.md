# QA-003 independent corrective-plan review — final R4-R2

**Verdict: APPROVED for implementation of final R4-R2.**

This approves the corrective plan, not the implementation, QA-003 closure,
delivery, any complete verification gate, or production readiness. The approved
R2/final R3 requirements remain mandatory. The distinct implementation reviewer
must review the corrected actual diff, including all required adversarial tests.

## Exact approved input and baseline

- Plan: `PLAN-OBSERVER-CLOSE-R4-R2.md`
- SHA256: `a412691b3331308cc53706c8db9e2fb12822af7a8d1fba8e47be04d0c77eee6d`
- HEAD: `2beb37336fa8002b69f598fe431082606368310d`
- Tree: `00f3acee00c994e6e81470cc76e42f1f2108fcdb`
- Branch: `fix/qa-003-local-signing-lease`; version 0.3.0.
- All 40 files still match `implementation-inventory-r1.json`; index unchanged.
  This is a baseline identity check, not whole-diff implementation approval.
- User-owned AGENTS.md unchanged:
  `7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.

The original R4 was not approved. Its retain/early-return omission was raised
independently and corrected explicitly in R4-R2; historical inputs are preserved.

## Independent inspection and reproductions

Re-read the original QA-003 finding and prior approved combined plan. Traced the
actual installer and descriptor helper, its two-level cleanup owner and fork
callbacks, the signing-context caller, real session profile observer/checkpoint
and control writer, admission and recovery consumers, and existing real-filesystem
installer/recovery test assertions. Re-read repository/security instructions and
the focused native-signing, release-provenance and readiness skills.

1. **Fallible retry observer skips stage close.** On unchanged r1, reran the
   independent actual-filesystem probe. After initial `fstat` failure, the retry
   obtains identity and its observer raises. `credentials.py:1073–1084` skips close;
   outer cleanup removes the file but leaves its descriptor open with `nlink=0`.
   Result: `plan-review-observer-close-r4.json`.
2. **Retain early return hides close failure.** Added and ran
   `plan-review-retain-close-r4.py` against unchanged production source. The retained
   normal body succeeds; directory close is attempted once but reports failure.
   `credentials.py:983–984,1022–1029` resumes its pending return and skips the error
   check. Both before-effect failure and actual-close-plus-foreign-FD-reuse report
   success. Retained profile bytes stay intact, and handlers restore. Result:
   `plan-review-retain-close-r4.json`.

Both probes completed with exit 0 because they recorded the negative behavior;
they do **not** demonstrate a passing fix. Each observes real handles before its
exact fixture-owned fallback closes them. No real profile, native command,
keychain, Store operation, application build or background worker was used.

## Why the revised plan is sound

- The retry ownership observation is inside an unconditional descriptor-close
  `finally`. The still-owned slot is cleared before the single close attempt.
  An observer/checkpoint exception can no longer bypass that attempt or authorize
  linking/yielding. OSError, typed validation failure and KeyboardInterrupt are
  explicitly covered.
- The outer owner independently attempts both descriptor and directory closure
  using the existing two-level helper. Failure of one close does not skip the
  other; an ambiguous close cannot be replayed against a recycled foreign handle.
- R4-R2 now **removes retain's early return**. Retention skips file mutation and
  observer work only, not descriptor closure or final failure reporting. The
  explicit retained-success-body tests cover both ambiguous-close outcomes.
  Exceptions from retain/resolved callbacks also cannot stop independent closure.
- Inode/hash authority, write-before-use events, no-clobber installation, borrowed
  cancellation, creator-PID checks and child-only descriptor relinquishment remain
  unchanged. Retaining uncertain files never means retaining installer write
  handles or acquiring deletion authority from a filename.
- There is no change to any Store request, evidence schema, provenance binding,
  credential scope, workflow authority or unrelated release state. This is an
  ownership/failure-composition correction, not a validation weakening.

## Mandatory implementation/test interpretation

The real borrowed-session test must exercise
`SigningSession.profile_event -> checkpoint -> _write`, not a replacement observer
that merely raises. For the planned pending-control/recovery assertion, use a
genuine failed/short/zero control write or equivalent actual protected writer
failure. `_write` has validation **before** its writing try; not every arbitrary
validation exception sets `journal_failed` or leaves a pending file. Do not assume
those states from a mock or manually construct/edit the journal to pass recovery.

Observe actual stage/directory descriptor state, retained committed authority and
pending controls before any fallback. A failed close may genuinely leave an FD
open; report it rather than retrying or falsely declaring closure. Verify blocked
normal admission and production recovery from the actual surviving layout, with
native calls confined to the synthetic model and no new native mutation. Assert
unrelated files/foreign descriptors remain usable and handlers restore.

Existing raw-fork, normal-child-exit/GC and borrowed/default-cancellation suites
remain required. The separate active-native crash-matrix coverage investigation is
**not** closed, waived or replaced by these localized tests. R4 approval does not
approve the current r1 implementation or satisfy that independent requirement.

## Verification and remaining work

Probe commands used the healthy Python with `-I -S -B`; paths, results and SHA256
identities are recorded in `PLAN-REVIEW-R4-R2-EVIDENCE.json`. Hashes identify local
review evidence; they are not authenticated release attestations.

Implementation, distinct full-diff re-review, revised exact inventory/freeze, all
37 required gates and protected per-issue delivery remain mandatory. This reviewer
did not run the complete suite or any credentialed/native/Store rehearsal and
claims no such pass. No public documentation promise needs expanding for this
localized correction; implementation notes must accurately describe its tests.

Only ignored review/evidence files were created. Reviewer-owned temporary trees
and descriptor fallbacks were cleaned after observation; no process remains to
stop. Historical evidence, required deliverables, shared environments/caches and
all source/user changes are preserved. QA-004, MRK-008, MRK-009 and the mandatory
fresh entire-repository audit remain outside and open after this plan approval.
