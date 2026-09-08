# QA-003 R8-R2 — preserve fatal cleanup across recovery and signing owners

## Status, finding and exact scope

PROPOSED R2; supersedes the retained R8 proposal after independent review.
No production implementation changes authorized yet. This corrects
the undelivered QA-003 implementation, not a new accepted limitation. Read the
original `FINDING.md`, `REANALYSIS.md`, approved R5-R2 caller-lifetime plan and
the current code. Baseline HEAD/main2beb37336fa8002b69f598fe431082606368310d,
branchfix/qa-003-local-signing-lease, version0.3.0; previous proposed tree
c6319b556696f89b8cea08fb7d95e1d5f09439df. User AGENTS remains untracked/unchanged.

The R2A final-dispatch wrapper is independently approved ONLY as a wrapper.
Its prepared final verification has executed zero gates and must NOT run against
this rejected product freeze. Preserve the original actual EEXIST gate failure,
wheel, entire forensic installation and diagnostics. Do not adopt their passes.

## Reanalysis and concrete production-boundary evidence

1. `manual-fatal-probe-r1/RESULT.json`, `probe-manual-fatal-r1.py`: actual
   `run_owned` supervisor plus an actual retained kernel selector. Its pre-effect
   close error becomes fatal/dispatched/contained `ProcessCleanupError`, yet
   `recover_signing(manual=True)` catches it as `CredentialError`, reads a manual
   recheck, executes16 further modeled native calls and returns `recovered` with
   the selector still open and original session removed. Child/group is absent.
2. `probe-related-fatal-r8.py`, `related-fatal-r8-baseline.json`: production
   borrowed-profile read has a real retained FD after pre-effect `os.close`
   failure. `cleanup_profile` converts the generic close error into `conflict`;
   recovery performs6 further modeled queries and returns `recovered-with-conflict`
   with the descriptor still open and no pending session, even without a manual
   input read. The borrowed profile itself and native preferences are preserved.
3. Same probe, manual-directory case: real profile-directory close failure is
   caught by manual recovery, which reads once, makes16 additional native model
   calls and returns `recovered` with its directory descriptor still open.
4. Same probe, full signing-context/borrowed-installer case: the actual installer
   cleanup catches its real retained read FD as ordinary `CredentialError`.
   Outer signing cleanup performs6 further model queries, removes the session,
   and raises an ordinary error with no fatal classification. It DOES NOT return
   successful signing. Independent cleanup can be legitimate: the confirmed
   additional defect is the lost fatal classification/finalization, not a claim
   that every subsequent registered cleanup command is inherently unauthorized.

Only fictional native/CMS responses are supplied. Actual journals, files, FDs,
locks and (for the first probe) the owned process run. No Store or real keychain
call occurs. All exact probe-owned handles are closed AFTER observation; scratch
is removed; original negative evidence is retained. Source hashes are in results.

Root cause: errors mix ownership/content conflicts with incomplete resource
lifetimes. `ProcessError` is both `ValidationError` and `CredentialError`, so
broad catches swallow its fatal contract; local/profile FD and cancellation
owners still use generic errors. Aggregators reduce typed failures to booleans,
and exception chaining can hide an earlier fatal result under later cleanup.

## Changes and exact behavior

### A. Shared structured-error classification, not a new runner policy

In `src/mobile_release/owned_process.py`, add a small internal helper built on
the existing `preserve_lifetime_error` traversal. Given an optional exception
and a fixed sanitized fallback message, return the combined `ProcessError`
ONLY when fatal; otherwise return None. Preserve an original ProcessError
object when possible. Walk actual cause/context edges with cycle protection;
OR dispatched, AND contained/cleanup_complete exactly as the existing helper
does. Do not infer lifetime facts from text, generic OSError or a PID. An ordinary
CredentialError remains ordinary unless its explicit chain contains fatal facts.

This centralizes the two kinds of boundary (manual fallback and cleanup
aggregation) without blanket refusal of all CredentialError or ProcessError.
Do not change command IPC, timeouts, process ownership, parent-death cleanup,
environment scrubbing or Store behavior. `SigningSession.run` retains the
approved rule: contained PRE-dispatch failure may discharge in-flight state
and permit already-registered independent cleanup. Post-dispatch/uncontained
failure remains unresolved. No global poison flag or new persisted schema.

### B. Local signing resource owners and recovery

`src/mobile_release/local_signing.py`:

- `_close` reports `ProcessCleanupError`, preserving any active typed lifetime
  facts. Relinquish the slot BEFORE the one close attempt; never retry an
  ambiguous FD, including a freed number reused by another owner.
- Local read/lease cancellation owners use `ProcessCleanupError` for inherited,
  conflicting or failed handler cleanup. Ordinary directory/content/ownership
  validation and failed acquisition remain ordinary errors, not guessed leaks.
- `SigningSession.close` and `SigningLease.close` still attempt EVERY independent
  owned close (including active session, lease and home descriptors) and clear
  their slots exactly once. Aggregate cleanup failure as a structured fatal error,
  retaining earlier dispatched/uncontained facts through nested closes. A later
  ordinary close/restore error must not erase those facts.
- `cleanup_profile` distinguishes fatal snapshot failures BEFORE converting a
  borrowed-profile read error to a conflict. Fatal errors propagate; no new
  snapshot, native command, profile-resolution checkpoint or terminal finalization
  follows that failed read in recovery. Ordinary changed, unreadable, malformed or
  replaced never-owned profiles remain preserved conflicts, as before.
- `recover_signing` classifies the full exception chain BEFORE the manual branch.
  A fatal result is propagated, without checking a recorded worker to excuse it,
  printing the manual prompt, reading input, reloading controls, or retrying
  recovery. Automatic mode also fails. The lease's registered descriptor/signal
  cleanup still runs. Original remaining intent/checkpoints stay recoverable.
- A fatal error on the second manual recheck likewise escapes; no third attempt.
  Ordinary resolvable ownership conflicts retain the same exact TTY/input/lease
  rules. Nonfatal fully-cleaned command failure may retain existing manual owner
  reconciliation semantics; no automatic ambiguous request retry is introduced.
- Errors encountered after terminal controls/session already disappeared cannot
  be rolled back into fictional ownership. Return error, not recovered/absent;
  after the failing invocation ends, fresh status/recovery may legitimately see
  absent. Status cannot return idle successfully if its own close/restore fails.

### C. Profile installer and composed signing teardown

`src/mobile_release/credentials.py`:

- `_close_profile_descriptor` and the installer's cancellation ownership errors
  become typed fatal cleanup errors. Acquisition/content conflicts remain ordinary.
- Remove boolean downgrades of descriptor errors, notably staging-writer close and
  `close_copies`. Always attempt independent raw closes; retain the original fatal
  facts if another close or ordinary cleanup error occurs during unwind.
- Borrowed/owned-profile cleanup catches must propagate fatal lifetime errors
  rather than turn them into replacement/conflict flags. Preserve foreign bytes,
  inode checks and existing safe stage/destination cleanup on ordinary failures.
  When a fatal read occurs, do not retry it or finalize profile resolution; close
  independently held directory/write handles through the existing protected scope.
- At ENTRY to `cleanup_signing`, capture `exc_info()[1]` before any catch or
  cleanup. Initialize a separate cumulative fatal result from that exception;
  explicitly merge EVERY later caught failure into it because a swallowed catch
  will no longer exist in the final exception chain. For a fatal body/entry result
  with `dispatched=True` OR `contained=False`, set `session.unresolved=True` BEFORE
  either native cleanup or `installed_profile.close`, even when in-flight state
  is already None. This conservatively protects an arbitrary internal yielded
  consumer; current production signed build commands themselves use session.run.
  Apply the same quarantine immediately upon a later caught fatal result, before
  the next owner/retention decision. A contained PRE-dispatch fatal (False,True)
  MUST NOT set unresolved: its already-registered independent cleanup remains
  allowed under existing journal/retention guards. Never replay uncertain work.
  ALWAYS close owned raw session descriptors, regardless of any earlier failure.
- Once a fatal failure is known, skip extra profile reconciliation and terminal
  success/finalization in that invocation. Remaining original controls support a
  fresh invocation after exact process/resource quiescence. Merge fatal facts from
  multiple independent failures; a later ordinary conflict, OSError, or handler
  error cannot replace the fatal result. Ordinary conflict cleanup still returns
  its existing failing error and may clear fully resolved ownership.
- Normalize the FINAL propagated exception AFTER the complete protected
  scope/__exit__/handler-restoration envelope, not merely before manual fallback
  or inside the cleanup callback. For the read/lease, profile-installer and
  composed-signing ownership boundaries, an outer try/except around the existing
  inner try/finally scope envelope can preserve a fatal cause/context hidden by
  a later ordinary OSError, CredentialError or KeyboardInterrupt. Keep explicit
  local accumulation for swallowed catches; chain traversal alone is insufficient.
  Preserve existing ordinary optional FileNotFoundError/content-conflict branches
  and pure KeyboardInterrupt when no fatal fact exists. CleanupScope's unconditional
  outer finally and one-claim semantics MUST NOT be removed or bypassed. Do not
  globally alter generic cancellation behavior or QA-004's distinct outer
  materialization scope, and do not falsely claim that issue resolved.

### D. Callers, compatibility and security

Re-read CLI local-signing handler/main, full preflight fail-fast, build materializer,
profile auth/capture owners and fork cleanup consumers. Existing CLI exit2/error
behavior for fatal errors and exit130 for pure cancellation stay intact; there
must be no success JSON after fatal cleanup. Fatal error takes precedence when
cancellation and cleanup failure coexist. No secrets/native output/new saved
paths enter fixed errors or reports. The internal exception remains a compatible
CredentialError/ValidationError. Existing custom-handler/worker-thread semantics
are preserved; owned handler restoration errors are fatal, not ownership takeover.

No Store-facing workflow, schema, receipt, attestation, build identity or evidence
format changes. This affects local account resources and credential-free validators
only; it cannot authorize publication or overwrite unrelated Store state. No real
keychain operations are needed for verification. Python3.11+ POSIX remains baseline.

## Tests: dangerous behavior, independent resource facts and controls

Add focused regression tests (prefer one new `test_local_signing_failures.py`
and shared existing failure helpers only as necessary), extend actual caller/
recovery/error tests, and include the new tests in native/source/wheel gates.
Explicitly add `test_local_signing_failures.py` to
`tests/workflow/run_native_profile_checks.py` PATTERNS and assert that requirement
in `tests/workflow/test_native_profile_ci.py`. Strengthen the existing actual
stage/directory pre-/after-effect close tests in
`tests/unit/test_ios_profile_installation.py:290–420` to assert typed fatal errors;
do not preserve generic downgrade behavior just to match old error-text regexes.
Required cases:

- Actual isolated owned worker with real retained selector pre-effect close
  failure during production manual recovery. Prove group absence AND selector
  still open BEFORE fixture fallback; assert fatal propagation, zero input reads/
  manual prompt, zero subsequent native calls, original remaining intent unchanged,
  pending status and rejected new signing admission. Cover automatic/manual and
  initial observation, journalled observation, and second manual recheck paths.
- Actual borrowed-profile file and profile-directory close failures through the
  recovery entry, not merely injected CredentialError. Verify no successful
  conflict conversion, no terminal completion, unchanged foreign profile/native
  state, original pending recovery and refusal to use a busy account.
- Both pre-effect and after-effect close failures for relevant local/installer
  file/directory/session/lease owners. Reuse the freed FD for a separate synthetic
  sentinel after actual close. Prove no retry/foreign-close; all other independent
  handles close. For the intentionally retained FD, assert identity/liveness before
  exact test-only cleanup. No sweeping numeric-FD cleanup or stale-PID signals.
- Typed chained-error classifier tests, including ordinary controls, cycles,
  dispatched/uncontained/fatal combinations, generic secondary error, cancellation
  context, and multiple independent cleanup failures. Do not mistake group absence
  for complete handle cleanup or turn generic filesystem errors into invented facts.
- Composed signing teardown (owned and borrowed profiles, normal body vs fatal
  body, pre/post dispatch, cleanup failure plus secondary ordinary error) preserves
  fatal output and prevents finalization while honoring registered safe cleanup,
  journal quarantine and foreign-state preservation. Retain the existing explicit
  predispatch-cleanup regression, strengthen if necessary.
- Handler restoration/cancellation combined with another cleanup failure: exact
  original/custom handlers restored/preserved, fatal error rather than success or
  ordinary cancellation; pure cancellation retains130. Inject masking at the
  ACTUAL owning guard's restoration path after a real retained-resource failure
  and invoke the production owner/CLI, not just the classifier with hand-built
  exception chains. Cover ordinary OSError/CredentialError/KeyboardInterrupt
  masking and independent close attempts. All test-only handler
  mutations restored by fixture fallback and no real account inspected.
- Control cases: ordinary unknown stage can be independently resolved through
  locked manual recheck; ordinary borrowed-profile edit remains a conflict without
  deletion; wrong input/EOF/corrupt controls/live recorded group stay refused;
  no third attempt after recheck failure; pure nonfatal/fully-cleaned command errors
  preserve supported explicit recovery. Re-running recovery from a NEW process
  after failed invocation exit must recover the original candidate/session without
  editing its journals, rebuilding or repeating unsafe native mutations. Existing
  persistent crash/cancellation/recovery matrix remains mandatory.
- Actual CLI uses the production recovery path and safe internal home/native seam:
  fatal failure yields exit2 and no recovered JSON; fresh-process recovery is
  repeatable and status idle only after success. No Store-call mock substitutes
  for inspecting the call path; Store functionality is not imported into recovery.

Tests must not hide retained handles by calling real close BEFORE checking the
reported result, nor patch the entire recovery/session at the dangerous boundary.
Use module-local OS seams so faults do not leak into unrelated runner/test IO.

## Documentation and regression risks

Update `docs/local-signing.md` and concise linked troubleshooting/credentials/
CHANGELOG statements only as needed: manual confirmation cannot override fatal
resource or signal-owner uncertainty; end the invocation, establish exact owned
quiescence, then use the SAME remaining session. Registered independent cleanup
is allowed; no ambiguous retry or generic shared-process killing. Account state
conflict is distinct from incomplete invocation lifetime. End-of-terminal failure
can leave no session, but never produces successful cleanup in that invocation.

Risks: disabling necessary independent cleanup, losing earlier uncontained facts
to a later close, masking cancellation, retrying a reused descriptor, accidentally
turning foreign profile conflicts into required deletion, changing normal protocol
IO inventory, or omitting the new tests from installed-wheel/native validation.
Review siblings and complete matrix inventory instead of assuming old counts.

## Verification and delivery

1. Independent plan review must approve before product edits. Preserve original
   failing evidence and record any changed plan assumptions.
2. Implement, run actual focused regressions and original dangerous probes adapted
   to the corrected expectations in NEW evidence files. Record failed development
   runs honestly. Clean only exact owned workers/disposable test outputs.
3. Distinct implementation agent reviews actual diff and full affected owners/
   callers/docs/tests, independently probes failure cases, and approves a new
   issue snapshot. Existing acceptance/freeze is reopened, not inherited blindly.
4. Unused R2 preparation is already superseded: `QA-003-final-r2/SUPERSEDED-R8.json`
   records actual identity/byte/empty-directory checks and removal of only its
   unused owned temp parent/child/marker; zero gates ran and no process was signaled. Keep
   all old failure/forensic evidence and required installations intact. Prepare
   an independently checked fresh runner namespace with the corrected wrapper.
5. Freeze the NEW full proposed source and helper hashes; run ALL58 original gate
   categories from zero, adding/integrating the new regression tests: editable
   install, full Python/workflow tests, all Ruby support/lane/native tests, Supply/
   WIF, Fastfile validation, Bundler install/check, actionlint, dependency pins,
   runtime-dependency/wheel installation and source/wheel native checks, complete
   16-shard source/wheel matrix with actual union, build-output/worker cleanup,
   JDK and diff/freeze checks. No pass adoption or deadline/count reduction.
   Linux CI and protected main CI remain required; local macOS does not prove them.
6. The old spontaneous `state.pending` EEXIST remains unresolved until investigated
   and reconciled; a fresh pass alone is not an explanation or waiver. Any repeated
   failure requires root-cause work, not rerun-until-green.
7. Only complete approved verification authorizes the scoped QA-003 commit and
   normal protected PR/merge, then main CI. Preserve user AGENTS/index/changes.
   Continue QA-004, QA-005, MRK-008, MRK-009, then a genuinely fresh complete audit
   and new-blocker remediation. READY and the final full feature inventory remain
   conditional on the user's complete scope, not this amendment.
