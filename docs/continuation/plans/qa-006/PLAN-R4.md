# QA-006 R4 — primary setup errors and supported indeterminate process states

**PROPOSED; independent plan approval required before source changes.** This
amends approved PLAN-R3-R3, preserving every earlier readiness, deadline,
cancellation, ownership, negative-mutation, CI and full-verification requirement.
Current proposed tree6320d6e4e9d80e33e7db46b4491215d311851496 is not accepted.
These are two corrections within QA-006, not new delivered findings or runtime
Store defects. The delivery denominator stays9/15.

## Reanalysis, root causes and evidence

Re-read original FINDING.md, R3 plan, both complete helpers and all positive
readiness/death/cleanup callers. Distinct review's setup-primary probes show that
`capture_command`, `run`, AND `run_ownership_probe` can fail before `scope.active`.
The failure reaches `ensure` before the outer lifetime sees it. If cleanup then
fails, `Lifetime.cleanup` remembers that second exception first. The original
setup object/message is replaced even though the traps are correctly restored.
R3's active-work/finalization protections do not cover that whole-body gap.

Independent Darwin consultation obtained192 actual `/bin/ps` observations while
holding96 real unreaped child reservations. Eight exact PID/group, exit-zero,
empty-stderr rows contained supported `?E`/`?Es` and were rejected by the actual
Ruby parser. Apple adv_cmds-237 source corroborates the unclassified `?`, exiting
`E` modifier and source-listed `H`; H was not observed. The current boolean
`alive?` is used for BOTH positive readiness and inverted death, so merely widening
the regex would create a new false proof. Root independently replayed all192 rows
and reproduced the primary loss in all three APIs (zero native spawns).

Evidence: implementation-review-r3/, unknown-spawn-consult-r1/CONSULTATION-REPORT.md,
reanalysis-r4/ROOT-REPRODUCTIONS.json and exact scripts/logs. All root/consultation
children joined; root scratch removed only after zero-spawn proof. R3's successful
R2 adverse replays remain development evidence only. The precise historical R1
observation is irretrievably absent from its old log: this supported Darwin defect
does NOT retroactively prove what R1 returned. Preserve that limitation and the
original failure; neither later passes nor this correction reclassifies it PASS.

## Exact change scope

Change only the two new test helpers in the existing six-path QA-006 diff:

- tests/workflow/upload_process_fixture.rb: whole-body error registration,
  validated observation classification, every readiness/death consumer and shared
  regression contracts/static probe dispatch.
- tests/workflow/upload_process_ownership.rb: whole-body registration in
  run_ownership_probe and bounded isolated failure/observation probes.

The two adapter suites already include these shared contracts. Keep their CI
requirements and all existing tests intact. No runtime, Fastlane adapter, Store,
credential, evidence/schema, dependency or packaging changes; no third helper.
No consumer/public documentation change is justified; update helper comments and
retained remediation records to describe exact proof and uncertainty.

## 1. Remember the whole-body primary before cleanup

For each of capture_command/run/run_ownership_probe, catch Exception around its
ENTIRE existing setup plus active body, call that frame's remember(error), then
re-raise before its cleanup ensure. Do not catch only StandardError. In run, keep
bounded diagnostics for StandardError, but remember the primary BEFORE diagnostic
collection/warning can itself fail. Cancellation should not acquire new logging
behavior. Preserve existing scope.active, outer deferral, acquisition ownership,
unknown-state retention and ordered trap restoration. Do NOT move resource
acquisition into an interruptible gap merely to reuse active's exception capture.

Cleanup errors remain separately observable and non-successful. The original
object/message stays authoritative through cleanup and finalization. A setup
failure with no attempted spawn is not UNKNOWN child acquisition. Unknown actual
acquisition/reap continues to forbid signals or scratch deletion.

Add a static isolated setup-failure probe through both adapter contracts. Exercise
all THREE actual APIs: capture stderr-open failure, run input-write failure, and
ownership-probe input-write failure, paired with a distinct real cleanup-method
failure (owned directory removal or preservation warning). Require the precise
setup and cleanup boundaries, original object/message, zero attempted child
spawns, inactive registry/exact restored handlers, and retained diagnostics before
independently removing only the no-child probe's exact scratch. An unexpected
spawn attempt is vetoed and FAILS, never counted as passing fixture cleanup.

## 2. Model process observations explicitly

Keep strict bounded one-row parse, exit status, empty stderr, numeric PID/group
equality and supported status syntax. Add only the documented Darwin primary ?/H;
foreign identity, invalid status, malformed/question-mark suffixes, contradictory
absence, tool failure or diagnostics remain immediate failures.

Classify validated observations as:

- **stopped:** only exact validated absence, or primary Z;
- **live:** existing recognized live primary states without the E exiting modifier;
- **indeterminate:** valid primary ?/H, existing non-live X, or a non-Z E modifier.

Indeterminate proves NEITHER readiness NOR death. Keep observations separate from
OwnedChild acquisition/reap states: no ps row/marker ever authorizes a signal or
converts UNKNOWN ownership into complete. Treat unsupported syntax as failure,
not a catch-all indeterminate observation.

Audit/change every consumer: explicit stopped predicate in dead! and descendant
death polling; explicit live predicate for inherited-pipe and initial readiness.
When event readiness is available but process state is indeterminate, return false
to that existing bounded readiness loop rather than immediately raising or
claiming readiness. Definite stopped still rejects readiness. Malformed/foreign
observations remain fatal. Indeterminate cleanup can be observed again ONLY
within the original fixed monotonic cleanup deadline; never reset deadlines,
retry whole gates, silently increase budgets, or delete evidence on persistent
uncertainty. All real deadline/native-clock and actual pipe-wait oracles stay intact.

## Required observation regressions

- Exact fictionalized ?E/?Es/H/SE rows parse but prove neither live nor stopped;
  S/R establish live, Z/validated absence establish stopped. Reject foreign PID/
  group ?, malformed states, nonzero/contradictory exit and stderr as before.
- Sequence ?E→S→Z must not make cleanup succeed until the definite final state.
  Readiness must deny ?/H/exiting and wait for a definite live observation.
- Persistent valid indeterminate observations expire one fixed real monotonic
  deadline, never become success, and retain diagnostic scratch. Exercise actual
  run with a real static driver/native worker and ONLY parent observation injected;
  do not mock native capture, cancellation, wait/reap or process signals. Record
  retained state BEFORE restoring actual observations and independently proving
  all actual workers dead before exact probe scratch removal. Use original cleanup
  bounds for the full-call case; no new production timeout knob is needed.
- Isolated probes may override only read-only observation seams and expected
  setup/cleanup fault points. Scope all such overrides to fresh Ruby children so
  no monkeypatch/queued signal can contaminate the suite or another test.
- Replay all192 retained Darwin rows through corrected actual parser/classifier;
  the eight ?E/?Es must be indeterminate, not ready/dead. Never query or signal
  historical PIDs during this pure data replay.
- Preserve and rerun all unknown-ownership/primary, actual async/OS signals,
  restoration/finalization, startup/late-record, inherited-pipe, hard-driver EOF,
  real deadline and slow-cleanup/removed-deadline/leader-only mutation contracts.

## Compatibility, risks, failure and recovery

Ruby3.3 on supported Linux/macOS; no runtime or package dependency. Existing Linux
states keep their conservative meaning. The main regression risk is conflating
indeterminate with the complement of live: reject all inverted-live death callsites
in code review and behavior tests. Increased negative-test runtime remains bounded
within existing15/60second fixture/probe bounds and20minute CI job limits.

No unrelated Store state can be touched: probes use fictional inputs and static
interpreters, no application code or Store APIs. Exceptions cannot authorize an
upload. Read-only process classification adds no cleanup signal authority. Catchable
errors preserve the original and explicit cleanup failures; hard driver death still
uses private pipe EOF. Unknown ownership/state remains preserved, not accepted.

## Acceptance and verification

Obtain independent R4 plan approval first. Implement, run both complete adapters
and native CI contracts, reproduce fixed failures/adverse controls, snapshot a NEW
exact tree and obtain DISTINCT actual-diff implementation acceptance. Historical
R2/R3 failures stay preserved. Any new supported objection must be corrected and
reviewed, not excused by passing normal tests.

Only then freeze and execute ALL baseline-applicable local gates from zero:
Python/unit/workflow/native; every Ruby Store/support/upload/native/YAML/WIF;
bundle install/check/Fastlane; actionlint; pins/locks/runtime imports; actual
isolated wheel/bootstrap/native checks; Java21 signing policy; diff/source/mode
reconciliation; scoped owned-worker/build/wheel cleanup. Verification-final-r1
is preparation-only: no freeze/dispatch/gate has executed or may be reused as PASS.
Do not use the old unsafe QA-002 controller's post-reap group signals; the prepared
standalone controller owns its actual unreaped child and has no dependency on
pending QA-003 implementation. Bind verifier inputs/tools/owner identities.

After acceptance and complete gates: scoped commit, protected main PR delivery and
actual main CI. Preserve user AGENTS/QA-003. Then reconcile/review/reverify QA-003
from zero (all58gates/all16source-wheel pairs; old EEXIST still unwaived), finish
remaining findings, fresh comprehensive audit/remediation, justified READY and
the separate complete feature report. Stop/join only task-owned workers; delete
only exact completed disposable outputs after required evidence is preserved.
