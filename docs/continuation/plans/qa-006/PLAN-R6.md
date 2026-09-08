# QA-006 R6 — preserve unexpected native-fixture errors by execution state

**PROPOSED; independent plan approval required before first-party changes.**
This corrects QA006-IR-06 within the existing seven-path QA-006 scope. R5 was
REQUEST_CHANGES, not accepted. QA-007 and ignored-verifier corrections remain
separate; no runtime/Store/package/schema changes belong here.

## Reanalysis and concrete evidence

Read original FINDING.md, approved R5-R2, the complete actual native driver,
Lifetime/OwnedChild, native/runtime and adapter callers, CI routing, native tests
and independent R5 report (SHA256
`68668dafadef9c4a0d4678a840bacce1035e9ed086cd3017053985114e4c78e0`).
The seven-path starting tree is16fb3d7d73171380760ff60d273a86442fc5afbb.

`upload_process_fixture.rb:592-608` consumes every capture exception and uses four
mode names to decide whether to rethrow the original. The nested lifetime still
owns the actual first error, but ordinary-mode unexpected errors become a later
first-close assertion or cleanup error. An IOError is legitimately sanitized by
the production wrapper, yet the fixture retains the actual callback original.
The fixture must preserve that harness error without weakening runtime redaction.

Root independently replayed the exact four reviewer probes in `reanalysis-r6/`:
StandardError/IOError, each with and without a later real-EOF close error. All
four confirm lost final primary identity. All four actual Ruby commands exited0
as reproduction drivers, native workers exited0 through private EOF and joined,
all seven descriptors closed, zero signal requests/forwards; exact scratch was
archived and removed. This confirms a failed-fixture diagnostic defect, NOT a
false upload success, collateral process termination or Store mutation.

## Root correction — no mode-name exception policy

Change only `tests/workflow/upload_process_fixture.rb` and
`tests/workflow/test_native_upload_validation.rb` relative to R5. Retain the other
five issue paths unchanged; preserve accepted R4 ownership/cancellation behavior.

1. Retain the actual nested native `Lifetime` object in the driver when entering
   its already-protected scope, before any native acquisition. Its first `primary`
   remains authoritative even after callback cleanup, Open3 cleanup, trap/queue
   finalization or outer production IOError sanitization. Do not copy only a
   later caught error or introduce a new asynchronous publication window.
2. At capture-result handling, select the earliest real nested-lifetime/callback
   primary before secondary cleanup/assertion results; otherwise use the actual
   capture error. A genuine unexpected error is raised into the existing outer
   lifetime immediately, before any later assertion or cleanup-error promotion.
   Its actual object survives outer teardown and reporting independently of mode.
3. Consume an error as the intentional native test outcome ONLY with actual
   capture entry, exactly one matched first-native-close injection, actual close
   completion, and the same intentional injected object as the nested primary.
   The returned native error must also match: same object/message/status for
   Interrupt/SystemExit, or exact existing redacted ContractError type/message
   for the deliberate native IOError. A matching error string/type without the
   execution/injection identity is insufficient. Missing/unrecognized results
   remain explicit failed fixture results; do not manufacture a passing outcome.
4. Remove the four-name pre-entry rethrow allowlist. Named injected cases and
   unforeseen failures must use the same execution-state/identity rule. Runtime
   capture remains byte-identical, including its existing generic IOError text.
5. Once the expected native outcome has actually been verified, preserve all
   original positive readiness/SIGKILL/reap/death-before-fallback assertions.
   Any real cleanup error still invalidates a positive result and remains visible
   in its separate cleanup diagnostics; it cannot replace an earlier unexpected
   harness primary. The existing outer frame still owns later resource cleanup.
6. Keep result success contingent on complete descriptors, waiter/watchdog/
   injector joins, restored traps/inactive registry, no pending cancellation and
   no cleanup errors. A preserved original error is not a pass or upload authority.

## Regression design and dangerous-boundary coverage

Extend the existing static fixture, not a new unconstrained shell/eval path.
Fixed allowlisted native proof modes map to a small subclass/probe which invokes
the ordinary `native-setup-interrupt` driver. The native driver itself receives
no privileged error-policy mode. Keep native parameters exactly empty and reject
all invalid platform/mode combinations before resource acquisition. Parent driver
ownership/death proof and native fallback remain the existing private EOF protocol.

Exercise actual owner publication (after real write), readiness (after actual
native ready event), and watchdog handoff (after actual Thread registration),
injecting an unexpected StandardError, IOError, Interrupt and SystemExit(41),
each with and without a later real descriptor-close/EOF failure:24 cases.
Where a small watchdog method extraction is necessary to inject after publication,
preserve its existing deferred acquisition/registration and cleanup boundaries.
Use joined Thread#raise for the unexpected Interrupt cases, not a mocked status
or an unrelated process signal. Keep the ordinary expected first-close injection
unreached, and assert that fact in every pre-entry proof.

Add at least one unexpected-primary plus late outer-teardown error control, and
one unforeseen ContractError whose message equals the deliberate IOError text:
the latter must not be consumed based solely on class/message. Use an observer at
the actual final driver result boundary (source-anchor-derived TracePoint or an
equivalently independent exact-object observation) to compare the real outer
exception with the injected original; do not merely assert the driver's own
`harnessPrimaryRetained` boolean. Prove secondary identity/diagnostics separately.

Every acquired worker must genuinely exit through its original private EOF and
be joined; check actual status and ECHILD/death, all acquired descriptors closed,
registered watchdog/injector joined, traps restored, no pending repeat, and zero
historical-PID fallback. No runtime capture entry/first-close false positive is
allowed. Retain StandardError versus runtime-redacted IOError distinctions.

Keep and rerun all existing native positive cases, removed-cleanup mutant, partial
pipes/named setup failures, actual post-reap repeated cancellation, hard driver
loss and input-validation tests. Re-run the original independent four-case proof
with its exact result-boundary observation relocated by the reviewed source
anchor; preserve the original script/results and record that necessary new copy.
Add a negative control restoring only the old blanket-consumption branch in an
isolated source copy: the new identity test must fail, with safe EOF cleanup.

## Security, compatibility, retry and failure behavior

Tests-only Ruby3.3/POSIX Linux/macOS behavior; no consumer interface or dependency
changes. Native argv/environment isolation, Store credential separation, artifact
and receipt validation, all Store state and manual public-release boundary are
untouched. Do not relax the production redaction or cleanup to accommodate tests.

No work/capture/readiness/cleanup deadline is widened or reset. Errors, repeated
cancellation, partial setup and teardown failure retain original ownership rules
and required evidence. Unknown resource state is still retained, never guessed
dead or deleted. New proof cases are deterministic independent processes, not
gate retries. Root/user/source/old failed evidence and both indexes stay intact.

Regression risks: consuming a lookalike but unintended exception; keeping a
secondary instead of the nested frame's first primary; masking expected native
IOError redaction; misclassifying cleanup failure as success; moving the watchdog
registration outside cancellation protection; and proof instrumentation causing
first-close false positives or failing to join its injector. Test these directly.

Only fixture comments and ignored remediation/review documentation need updates;
there is no consumer/lifecycle behavior change. Record R5 rejection and completed
versus unexecuted review checks honestly. The interrupted R5 review's limitations
are not cured merely by rerunning its previously passing tests.

## Approval and verification sequence

Obtain independent exact-plan approval; implement the narrow fix and regressions;
run safe credential-free targeted development; snapshot all152 files/seven issue
paths; obtain DISTINCT actual-diff review and independent ordinary-mode probes.
Do not run full unsafe native runtime paths on the shared host. Complete adapter,
Linux/macOS and full project verification require the separately reviewed safe
isolation/hosted-CI contract; selected tests cannot replace them. Final verifier
VRI-01/VRI-02 and isolation implementation must also be accepted before freeze.

Only all required checks and exact intended scope permit a scoped QA-006 commit,
protected PR delivery to main and actual main CI. Then separate QA-007, QA-003,
QA-004, QA-005, MRK-008/009 and the mandatory new whole-repository audit/remediation
remain, followed by justified READY and the complete technical feature report.
