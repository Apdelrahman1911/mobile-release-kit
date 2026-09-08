# QA-003 independent R5 caller-lifetime plan review

**Verdict: CHANGES REQUIRED. Do not implement R5 yet.**

The omitted Git/Android command correction is well motivated, but the plan does
not yet close the connected unconfirmed-lifetime propagation paths. Its source
fallback requirement also conflicts with its claimed strict Git authority guard.
R4-R2 remains separately approved; this decision does not revoke that approval.

## Reviewed input and scope

- `PLAN-CALLER-LIFETIME-R5.md`, SHA256
  `572b5c59be67d3b668fb6e68393b68b26db09fa846418335e5095cd09062928b`.
- HEAD `2beb37336fa8002b69f598fe431082606368310d`, tree
  `00f3acee00c994e6e81470cc76e42f1f2108fcdb`, version 0.3.0,
  branch `fix/qa-003-local-signing-lease`.
- Re-read original QA-003 finding and R2/final R3 caller/lifetime requirements.
  Inspected actual discovery, every discovery caller, build and final-copy signing,
  preflight phase/catch/loop graph, private validation/profile authentication,
  owned runner/error types, CLI CI and source mutation guard, workflow source
  staging, existing caller/composition tests and relevant documentation.
- R4 installer implementation proceeded independently during review. R5 behavior
  remained unimplemented. Source identities at review close are recorded in
  `PLAN-REVIEW-R5-EVIDENCE.json`; this is not a frozen whole-diff approval.

Line references below refer to the r1 caller layout unless stated otherwise;
concurrent R4 installer changes shift later credentials.py lines slightly.

## What is technically sound

1. Separate static platform selection from optional Git observation. Both iOS
   discovery calls, Android selection, materialization's module selection and
   effective identity selection need the no-Git mode. Public default discovery
   fields can remain compatible. Reusing doctor's single Git observation avoids
   contradictory duplicate context observations.
2. Needed Git commands require bounded owned execution and a scrubbed environment.
   Optional metadata absence is not clean source provenance. Do not run Git just
   to choose a container while a signing session is active.
3. Move the Android wrapper and **build-time** final-copy jarsigner to the owned
   boundary, preserving scope, committed version overrides, timeouts, output
   treatment and final-copy signing order. The independent final-artifact/Store
   upload validators are distinct and need not be changed for that integration.
4. Stop the platform build loop after a failed build/materialization/cleanup.
   Preserve produced files without claiming validation. This changes local
   continuation only; Store partial success, original-candidate recovery and the
   manual-publication boundary must remain unchanged.

The inspected real fsmonitor/Android reproductions establish why both new runner
boundaries are necessary. This reviewer inspected those source/results but did
not rerun the prior real-worker probes during R5 review. The independent probes
below exercise additional actual caller classification and source guards.

## R5-C1 — Fatal lifetime state must survive every before-active wrapper

**Mandatory correction.** Fixing discovery._run and the final build loop alone
does not establish R5's promised refusal before further private/application work.

Existing paths catch `ProcessError(contained=False)` and keep executing:

| Actual path | Current loss/continuation |
| --- | --- |
| `preflight.py:59–93,874–965` | Toolchain error becomes FAIL; project checks and private validation still execute before the later report gate. |
| `preflight.py:96–203,207–258,261–325,328–337` | Effective Gradle/Xcode errors become ordinary BLOCKED/query error; later query/platform may execute. |
| `preflight.py:700–767` | Failed project check catches ProcessError and explicitly continues with the next application command. |
| `credentials.py:1695–1733` | Private validation catches ProcessError via CredentialError and continues to another platform. |
| `ios_profiles.py:135–144` -> `credentials.py:1462–1470` | Profile reap wrapper erases the containment flag into plain ValidationError; profile validator converts it into ordinary INVALID. Merely adding ProcessError exceptions farther up cannot recover the lost information. |

**Independent evidence:** `plan-review-caller-r5.py/json` injects one structured
uncontained result at the actual command boundary and keeps the real caller
control flow. It observes a later project command after FAIL, actual full public
preflight reaching application/private validation after the unconfirmed Xcode
probe, and another platform's private validator after the first fails uncontained.
The report eventually failing is not equivalent to stopping these operations.

`plan-review-profile-propagation-r5-r2.py/json` separately executes the actual
native-reap conversion and Apple material validator: ProcessError(contained=False)
becomes ValidationError without a containment attribute, then a returned INVALID
finding. No real worker is started by these classification probes. They prove
failure propagation, not an actual kernel inability to kill an owned group.

### Required revision

- Define a structured fatal lifetime/cleanup classification and preserve it through
  profile wrappers, private validators, effective identity queries, project checks,
  doctor, and public preflight. A fatal uncertainty must abort subsequent commands
  and materialization; do not infer safety from a later FAIL report or parse error
  message text to recover classification.
- Keep completed invalid-signature/profile/identity results as ordinary validation
  failures. Do not weaken Apple issuer/content checks, retry ambiguous native work,
  authorize deletion by PID/name, or convert cancellation into optional absence.
- Revisit all broad catches of the selected fatal type, including artifact/CI
  consumers of the same profile wrapper. Verify their complete downstream caller
  behavior rather than simply changing one exception superclass.
- Distinguish an early command-lifetime refusal from busy/pending account admission
  in public errors. No-session early uncertainty requires exact owner quiescence,
  not a fictitious recoverable signing session; actual active-session uncertainty
  must retain its existing original recovery authority.
- Keep the ordinary confirmed cancellation exit 130. A cleanup failure during
  cancellation must remain explicit rather than being silently reclassified as
  harmless metadata absence or successful cleanup.

### Optional Git failure needs more than `contained=True`

`owned_process.py:286–311` can raise ProcessError with contained=True after a
selector/pipe close failure: that flag describes the command **group**, not every
resource obligation. Guard/handler-restoration failures also need not mean an
optional missing Git tool. The revised plan must distinguish genuinely safe
missing-tool/nonzero/contained observation failure from fatal cleanup/ownership
failure. Do not make `if error.contained: return None` the entire policy.

Add tests for this classification, uncontained results at **every** before-active
entry and real public composition, native profile wrapper propagation, no later
platform/query/project/private work, and ordinary contained validation failures
that remain compatible. These are in addition to the planned real-descendant
success/nonzero/timeout/cancellation tests, not a replacement for them.

## R5-C2 — Resolve the Git fallback/authority contradiction

**Confirmed separate source-validation defect**, documented in
`SOURCE-GUARD-FINDING-R5.md`; it is not the original QA-003 concurrency root cause.

R5 requires preserving the current `commit = checked_out_commit or GITHUB_SHA`
policy and also proving unknown/mismatched Git context cannot authorize a Store
request. Those are inconsistent for the current CLI guard.

Independent real-repository probe in `plan-review-caller-r5.py/json` creates two
different committed source trees, checks out B cleanly, supplies GITHUB_SHA=A and
makes only `rev-parse HEAD` unavailable. All other Git reads are real. The actual
GitContext reports A and A's tree, dirty=False; the actual mutation guard accepts
although both actual HEAD and tree differ. No Store call is performed.

The pinned workflow has independent original-checkout verification beforehand;
this is **not** evidence of a complete hosted workflow/publication bypass. It does
disprove the local source guard guarantee and the proposed unconditional R5 test
claim. Do not conflate local guard acceptance with complete release authorization.

Revise the plan to require actual successful checkout observation for authority
consumers, while optionally preserving clearly non-authoritative environment
fallback for display-only discovery. The implementation may use a strict internal
mode or another explicit trustworthy contract; it must not compare an environment
fallback to itself as proof. Cover HEAD unavailable, tree unavailable, dirty
unknown, mismatched environment, clean valid source and original recovery source.
If maintained as a separate issue/commit, keep it an explicit required blocker
with its own reviewed correction and stop claiming it is already enforced by R5.
No weakening of receipt/workflow/source bindings is authorized.

## Other implementation and regression requirements

- The build-loop fail-fast catch must cover actual filesystem/configuration/
  materialization/cleanup errors, not just existing CredentialError/ValidationError.
  Preserve KeyboardInterrupt semantics and never resume another platform after
  incomplete teardown. Pure Python/static diagnostics and required owned cleanup
  are not permission to dispatch another command.
- Preserve Android argv/env/timeout and final-copy ordering under both signed and
  unsigned operation. Do not broaden the environment of Git or private jarsigner.
  Inspect the credentials/discovery import cycle before adding scrubber imports.
- Test no-build, Android-only, both platform orders and actual continuation after a
  successful first platform; no artificial passing artifact result may hide a
  failed transition. Retain current actual guard/recovery/fork behavior.
- Document changed local fail-fast behavior, safe retry versus native uncertainty,
  retained output status and early no-session versus actual session recovery.
  No claim that QA-004's outer cleanup is fixed by stopping later work.

## Evidence, limits and disposition

Commands/outcomes/source and probe SHA256s are in `PLAN-REVIEW-R5-EVIDENCE.json`.
The initial profile-classification probe failed only in its reporting code
(`Finding.check` does not exist); its source/empty result/error explanation are
preserved, and it is **not** labelled passed. Corrected R2 was independently run.

The two successful probe programs report negative production behavior. They are
not passing regression tests or implementation verification. No complete project
suite, native credential rehearsal or Store request was executed in this review.

Only ignored review files were changed. All synchronous fixture Git commands
finished; synthetic temporary trees were removed. No build/daemon/background
worker was started. User AGENTS.md remains
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.

Submit a revised plan addressing these corrections for independent approval before
R5 implementation. The distinct actual-diff review, active-native crash-matrix
requirement, full frozen verification and protected delivery remain mandatory.
No QA-003 closure, QA-004/MRK-008/009 waiver or final READY verdict is granted.
