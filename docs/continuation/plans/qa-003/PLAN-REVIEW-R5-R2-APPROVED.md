# QA-003 independent caller-lifetime plan review R5-R2

**Verdict: APPROVED for implementation of this plan.** No remaining plan-level
blocker was identified. This is not approval of the current implementation,
QA-003 completion, native-active crash verification, commit/merge, or readiness.

## Reviewed authority and snapshot

- Exact plan: `PLAN-CALLER-LIFETIME-R5-R2.md`, SHA256
  `cfd09a088353ba520ee8051bb3dd40b69608e4853b6f5ddbce1e546bc34f7fc0`.
- Baseline HEAD `2beb37336fa8002b69f598fe431082606368310d`, tree
  `00f3acee00c994e6e81470cc76e42f1f2108fcdb`, version 0.3.0,
  branch `fix/qa-003-local-signing-lease`.
- Read with the already-approved R2/final R3 and R4-R2 contracts. R4 descriptor
  corrections are implemented but the combined working-tree change is not
  finally reviewed. R5's behavior remains unimplemented at this review snapshot.
- Re-read the original QA-003 finding, R1 implementation review, previous R5
  refusal/evidence, revised plan and canonical QA-005 finding. Rechecked actual
  owned process/cancellation, signing session, discovery callers, Android
  build/final-copy signing, profile authentication/private consumers, preflight
  phases and error loops, IPA validation/evidence, CLI final preparation and
  Python/Ruby current-upload validator paths. Earlier findings and negative
  reproductions remain historical evidence, not passing regressions.

Review-time source identities and probe hashes are in
`PLAN-REVIEW-R5-R2-EVIDENCE.json`. Reviewer writes are confined to ignored
`.mobile-release/remediation/QA-003/`; no production, test, documentation,
Git index/ref or user-owned AGENTS change was made by this reviewer.

## Reconciliation of the previous mandatory objections

### Structured cleanup failure, not just group containment

Sections A/B distinguish `contained` (owned process-group certainty) from
`cleanup_complete` (all other resource/ownership cleanup). The read-only fatal
predicate and dedicated cleanup exception prevent an optional Git observation
from swallowing a selector, stream, descriptor, scratch or handler failure merely
because the group was reaped. Safely completed nonzero/missing-tool/contained
observation failures remain distinguishable. Cancellation cannot be optional
metadata absence. Independent cleanup obligations and failure reporting remain
mandatory; no signal is authorized against a reused PID or unrelated daemon.

The implementation must apply the approved rule to the in-loop request-pipe
close (`owned_process.py:357-359`), not only final `cleanup()`. Likewise a later
handler/cleanup exception must not reset real dispatch/containment through the
new exception constructor's defaults. These are concrete applications of A's
explicit accuracy and stream-cleanup requirements, not additional plan scope.

### Actual caller and phase propagation

The table in D and explicit phase returns now cover the earlier demonstrated
continuations: doctor/toolchain to application/private work, project-command
loops, effective platform identity loops, Debug-to-Archive, private platform
validation to Firebase/another platform, Store material and build loops.
Sections B/D explicitly address the profile wrapper that erased the original
structured uncertainty. Every relevant consumer must preserve fatality before
ordinary diagnostic conversion; adding a subclass without changing callers is
not sufficient. Secondary ordinary filesystem failures cannot revive work after
a failing prerequisite. Completed invalid profiles remain INVALID rather than
being accepted or bypassed.

Early no-session failures are distinguished from real pending signing intent.
The corrected guidance is owner quiescence, not invented local recovery authority.
An existing active-session ambiguity retains its original journal and recovery
rules. An eventual FAIL report is no longer treated as permission to perform
additional private/application commands beforehand.

### Omitted discovery/Android boundaries

The plan removes unnecessary Git execution from both iOS discovery calls,
Android discovery/materialization and effective identity selection. Required Git
uses the bounded owned runner with scrubbed capabilities, and doctor uses a
single observation. The Android wrapper and build-time final-copy signer preserve
committed version/build inputs, no-daemon behavior, output treatment, timeouts,
credential subset and copy-before-sign order. Independent artifact/Store
validators are not conflated with application build commands.

Real descendant tests must execute these actual caller paths, including the
second discovery after prepare; no test can substitute a fake passing
`run_owned` or selection predicate for the guarantee. First-platform output is
retained without falsely claiming its validation when the second fails.

### QA-005 is explicitly tracked, not silently waived

Section E no longer claims environment fallback proves an observed checkout.
The confirmed source guard defect is separately canonicalized as QA-005 with
required reviewed remediation before final readiness. Keeping that change scoped
separately is technically sound. Workflow-level mitigations do not close it.
There is no request to fold its implementation into this caller-lifetime change.

## Active-session semantics checked independently

A possible concern was that `SigningSession.run` (`local_signing.py:586-637`)
currently clears inflight after `not dispatched and contained`, without a
cleanup-complete predicate. That is not intrinsically a plan defect. A proven
pre-dispatch failure with a confirmed absent group has no possible native effect;
registered independent signing cleanup may proceed while the overall invocation
still fails. Making every such error pending would contradict approved R2/R3.

The new ignored probe `plan-review-session-classification-r5-r3.py` executes the
actual session, pre-dispatch callback, on-disk intent/checkpoints and follow-on
admission. Only its command result is injected as a **planned error-shaped
subclass**; all native observations use the existing credential-free state model.
It does not test an implemented `ProcessCleanupError`, simulate a real kernel
cleanup failure, or establish the missing crash matrix.

Observed four-case result:

| Dispatch | Group contained | Cleanup complete | Actual session result |
| --- | --- | --- | --- |
| No | Yes | No | Inflight cleared; original intent retained until registered cleanup can finish |
| Yes | Yes | No | Inflight/intent retained, unresolved; next dispatch refused |
| No | No | No | Inflight/intent retained, unresolved; next dispatch refused |
| Yes | No | No | Inflight/intent retained, unresolved; next dispatch refused |

The active runner receives the session's exact cancellation guard through
`SigningSession._call` and `_run_private`; `cancellation_owner` therefore borrows
it. The owning-handler-restoration path of `run_owned` is not normally reached
inside that active session. Nevertheless A's dispatch/containment accuracy must
hold for owning standalone callers and nested failures too. Mandatory regression
coverage must prevent later cleanup from losing an uncontained result or enabling
a post-dispatch session to take the pre-dispatch branch.

Probe command (exit 0):

```sh
.mobile-release/remediation/MRK-002/venv/bin/python -I -S -B \
  .mobile-release/remediation/QA-003/plan-review-session-classification-r5-r3.py
```

Probe SHA256 `eebc8d24c1f23da738d2ff7df37292e6631a0b63986f3a890ff0a3152e4752da`;
result SHA256 `8566cad85ab6ccf89781d5a917d6358e264b9902ab9187d2dc0d6ce3c0af519f`.
The initial `...-r5-r2.py` probe failed at import because of its review-script
root calculation; the shell also used a reserved zsh variable. Its original
source, empty result and error explanation are retained and are **not a pass**.

## Required implementation/verification and limits

The approved tests remain mandatory: real owned descendants, failure-before/after
close, handler restoration, combined group/stream/scratch errors, private profile
consumer and Store-call sentinels, every D-table caller, both platform orders,
single-platform/no-build/offline/online, cancellation and actual first-platform
output preservation. Complete existing issuer/DER/entitlement, artifact,
provenance, recovery, credential and workflow contracts must remain intact.
Failure after partial native effects is not permission to repeat setup or upload.

The separate native-active crash/control-I/O matrix (R6) still needs its own
reviewed correction and execution. QA-004, QA-005, MRK-008, MRK-009 and the fresh
all-file/all-release-path audit remain open. This plan does not claim live
credentialed macOS export, Store behavior or publication authorization.

After implementation, bind an updated intended-file inventory, obtain the
DISTINCT full actual-diff implementation review, freeze and execute all mandatory
project gates. No code fix, whole-suite result or readiness status is inferred
from this plan review/probe alone.

No real credentials, profiles, keychains, Store APIs, application builds or native
workers were used. The probe's synthetic filesystem/descriptor resources were
removed after observation; no reviewer background/build process remains. Required
evidence and the shared venv are preserved. AGENTS.md still has SHA256
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.
