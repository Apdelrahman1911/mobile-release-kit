# Independent fixture-base R3 plan review

## Decision and scope

**APPROVED_PLAN_ONLY** for the exact frozen `FIXTURE-BASE-PLAN-R4-R3.md` below.
The proposed design addresses the root cause of **VFBP-R2-01** without replacing
its actual control-flow requirement with another disk marker. No additional
confirmed blocking plan defect remained after this independent reconciliation.
This is a plan decision, **not** a finding-implementation acceptance, native pass,
QA-006 delivery, source disposition, commit/push authorization or READY verdict.
The original R1/R2 rejected decisions and failed evidence remain unchanged.

Reviewer: `/root/qa006_inheritance_r3r4_implementation`. The reviewer did not author
this verifier plan. The earlier inheritance implementation package is unrelated
to these review writes and was left untouched. Root must inspect this decision
and separately authorize the next scoped implementation. A later distinct actual
implementation review and separately authorized verification remain mandatory.

Review root (the only helper/plan inputs used here):
`.mobile-release/remediation/QA-006/verifier-correction-r4-r3/fixture-base-plan-snapshot-r3/`.
Names below are relative to that immutable package, not moving original inputs.
No manifest `source.path` or historical `original.path` was followed.

## Exact reviewed inputs

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `BINDINGS.json` | 172705 | `a31c6973122ee8e49f6d799ece55d9d0b8dd6ac4030fd5f826015f00f6909ec5` |
| `FIXTURE-BASE-PLAN-R4-R3.md` | 49638 | `4073504ad2286c2925e510848234549fcb934bb5236e618f3367a035d6a910b0` |
| `FIXTURE-BASE-REANALYSIS-R3.md` | 10521 | `6d0994de457eab0943efea5ea489160cdf02f3653792d25bd78463e591bb2bd8` |
| `COVERAGE.json` | 149392 | `b46af483da897a8831c3d72e853396f4f2519181b0fb78f6fec06fa0af76488e` |
| `STATIC-CHECKS.json` | 2353 | `8639c238cedc01b3a0bac85d4ef6b3fb884e5e1ac99c273a62775f96b700441c` |

All **150** manifest members, totaling **4,997,646 bytes** excluding the manifest,
matched their exact size, SHA256 and original snapshot identity before and after
review. All **139** baseline members additionally matched the copied R2 manifest's
size/hash references. All **36** `.py` members were AST-parsed; that is syntax-only,
not imports, execution or comprehensive semantic coverage. Hash matching proves
integrity against root-approved pins, not source authenticity by itself.

The accompanying `COVERAGE.json` individually classifies every input and records
whole-text, targeted-range, metadata-only or integrity/AST-only credit. It does
not silently assign semantic review to all files. It includes **76 retained
third-party text copies**, with prior detailed member-review conclusions attributed
to R2 rather than claimed as a fresh audit of each third-party member.

## Original findings re-read and checked against callers

### VFBP-R1-01: genuine editable runtime successor

The earlier plan seeded the new fixture `owner/venv` but the mandatory genuine
editable installation changes that same runtime. Source build/egg-info evidence
does not authorize additions to installed pth, console scripts, data or dist-info.
The whole original R1 independent report and R2 plan/member-review were read.

R2's exact original-request-bound SEEDED-to-EDITABLE transition, independent
emitter-derived delta, original-parent capability and joint source/runtime receipt
remain required by R3. The fixture policy is the reviewed CPython3.11 POSIX,
pip24/setuptools79.0.1 tiny src-layout: 1052 seeded regular files/142 directories;
editable adds 12 files/four directories. Its editable source-owned build/egg-info
outputs stay empty; the later genuine wheel build populates them. No generated
runtime is reclassified as pre-existing, no install is skipped, and no namespace
allowlist is made permissive merely to admit the dangerous change. These are
plan/source derivations, not a newly observed installer result.

### VFBP-R2-01: published PASS bytes are not parent finality

The governing original report is `r2-independent-review/PLAN-REVIEW.md` (322 lines,
21199 bytes, SHA256 `49e6aaf5bbb91757aabe1806a17811b0610c943b533a9f5dc1bb80ea654d700c`).
Its actual counterexample remains supported:

1. `baseline-r2/current29/action_io.py:701-720` can perform the real ledger replace
   at line717, then fail on check/fsync/check, directory close or later action exit.
2. `baseline-r2/current29/verify-all.py:181-207` can consequently leave valid-looking
   joint receipt/PASS evidence despite original-parent action failure. Failure
   diagnostic persistence is best-effort, not an independent revocation mechanism.
3. `_run` correctly stops and `main` rejects restart. **No normal failed-controller
   continuation or live Store bypass was demonstrated.** The defect concerns
   later disk-only authority interpretation, not a claim that the current normal
   controller ignores its caught failure.
4. Ordinary collect/load can reach source Git/tool acquisition before the later
   active-ledger check (`bindings.py:741-829,848-1020` and the earlier tool path).
   Checking one more marker at wheel preparation/observer is too late.

This is a static failure-path reproduction, not an executed cancellation/native
test. R3 correctly distinguishes the complete action's original caller-observed
normal return from its final-looking files. The original confirmed defect still
needs actual implementation and regression verification; plan approval alone does
not change its delivered status.

## Design challenge and reconciliation

### 1. Original-parent finality versus live dispatch

Plan `:108-139,166-187` requires registration only after the entire real action
context returns normally, including final checks, revoke/close, applicable handler
restoration and terminal check. A closed ctx or completed os.replace is not enough.
Earlier genuine finality remains immutable after a later failure, but all new live
dispatch is revoked. This avoids both accepting after-effect failure and falsely
making successful historical transitions dependent on every future operation.

Tickets are exact-identity registered against the original session, real action,
case/request/freeze/phase/role/gate and operation. Noneditable prelaunch scopes stay
split: their consumed one-use dispatch reservation is not a revived Action or new
budget. The R2 editable transition alone retains its one unreset action through
real install, independent validation, receipt and ledger save. Terminal all-PASS
inspection cannot create a no-active-gate native exception.

### 2. Earliest admission and no produced-to-generic downgrade

Plan `:189-233` puts descriptor-only admission before ordinary frozen loading,
collect's source snapshot/Git, tool probes, receiver startup and each acquisition.
The original parent validates the base/reservation before actual child Popen; a
child cannot retroactively authorize unsafe interpreter startup. Both capability
and original byte/reference validation are required, not alternatives.

Original registration and the literal stamped copied-source anchor preserve the
produced classification independently of request/config/scope/bootstrap markers.
Deleting or changing a marker, interpreter or request cannot fall into the generic
pre-existing-runner path. Exact FrozenAuthority type/root/action/single-load and
immutable backing checks remain. This does not purport to stop arbitrary out-of-
band same-user execution outside the guarded APIs or defend compromised host memory.

### 3. Actual execs use an independently anchored finite protocol

The baseline controller is source-loaded in the original proof process, but
prepare/cleanup/generated wheel and source-only venv are real exec boundaries.
An opaque Python object alone cannot span those actual children. Plan `:244-373`
therefore uses root-created, no-follow, unlinked regular objects with whole-case
retained inode anchors and fixed header commitments stamped into copied
`action_io.py` before request/freeze. Descriptor numbers merely locate objects;
records, numbers, PID, checksum or copied grant bytes alone are not origin proof.

The actual Popen handle/recipient PID and fresh receiver nonce bind READY, seal and
GO. The sole permitted writer must be fully written, fsynced, read back and closed
before GO. The fixed live issuer pipe is then a revocation channel. Offset-explicit
I/O, strict field widths/reserved zeroes, exact sizes and no arbitrary selectors
avoid an extensible IPC authority surface. Header256+grant2048=2304 bytes fits the
original 4KiB locator cap; READY and GO are each64. Final struct offsets/domain
literals still require actual-code inspection before native verification.

This is explicitly cooperative guarded trusted code, not an OS memory sandbox or
an impossible instantaneous distributed revocation claim. Failure closes issuance;
an already-authorized in-flight acquisition follows the original cooperative
cancellation checks and still-owned handle accounting. Popen ambiguity stays
UNKNOWN, not a fabricated PID/reap or permission to signal an unrelated process.

### 4. Real caller/delegation/profile coverage

| Actual baseline route | Required R3 treatment |
| --- | --- |
| Direct original fixture collection/drift/authority/observation | Explicit original in-process case/session/ticket; no new child |
| Ledger `-c pass` native leaf | Parent admission; no capability FDs to the leaf |
| Worker two-gate path | Exact synthetic-cleanup receiver role |
| Six-gate preparation/lifecycle/VPG | Exact prepare/diff-check/cleanup roles; fault/schema script is its original role |
| Four-gate editable cleanup | Real prepare, generated compound wheel and cleanup; one preallocated wheel-to-source-only-venv delegation |
| Newly named observer positive | Separate declared profile, not inserted into original four-gate/final45 |
| Original final45 Bash wheel route | Unchanged reviewed pre-existing runner; no produced-fixture capability chain |

Plan `:375-441` restricts delegation to one root-preallocated source-venv leaf.
Both ancestor and direct lifetime channels, kernel/header identities, actual parent
PID, request/freeze/gate/generation/command and parent-grant binding remain checked.
The largest profile has six helper slots; no speculative reserve or general relay.
Pip/Git/import/probe/native leaves receive no authority descriptors. The Bash
route has multiple real execs; it must not be silently claimed as covered by one
leaf grant. A genuinely needed missing produced-Bash hop requires revised plan
review, not omission or generic reclassification.

Two author clarifications were checked against the frozen design; no plan edits
were made or treated as authority:

- R2's symbolic `BOUND_VERIFY_FROZEN_DIFF` for source-only base creation must resolve
  to that case's exact `evidence/verify-frozen-diff.py`, adjacent to its stamped
  `action_io.py`, not the original unanchored driver/self.evidence. The existing
  helper-copy/setup ordering is `verify-frozen-diff.py:572-605`. The implementation
  reviewer must verify the actual literal path/source and stamp-before-request/
  freeze order, not merely a similarly named variable or comment.
- A whole-case retained RO inode anchor is not a transferred recipient-reader
  descriptor. Closing transferred duplicates must not close the case-lifetime
  anchor. Ownership tables must distinguish them, pop before one close attempt,
  keep sole-writer close-before-GO and preserve offset-explicit reads/writes.

### 5. Historical snapshot and mutable current ledger

Plan `:450-491` freezes exact pending ledger bytes before the editable attempt.
The current mutable ledger is separately observed and guarded under the original
controller's action-local exclusive writer transaction, outside FrozenAuthority's
immutable backing set. Real current byte/identity comparison, exact post-replace
readback and full action exit stay mandatory. There is no generic unbind/rebind,
second authority reload or hostile-writer kernel-CAS claim.

Historical editable evidence projects its original empty source outputs; later
wheel output creation and cleanup must not make that true history invalid. Current
source/generated outputs and the complete seed/editable startup namespace remain
protected on every real use. Post-replace failure retains candidate evidence but
mints neither transition finality nor further dispatch, even without a diagnostic.

### 6. Read-only inspection is structurally non-upgradable

Plan `:493-521` provides a distinct EvidenceInspection entry/type, sharing real
strict schema/reference/producer/predecessor validators, not native loading or
permission registration. Inspection cannot create FrozenAuthority, ticket, view,
producer, cleanup or completion. No allow_inspection flag weakens ordinary guards.

The actual VPG69 child intentionally rebinds malformed records to reach deep schema
checks. Its genuine successful prefixes, all deep assertions and restored positive
remain required through shared read-only validators. Separate native-entry tests
must also reject those mutations before acquisition. Early capability rejection
must never be relabelled as proof that a deeper original schema assertion ran.

### 7. Budgets, failure and unrelated state

Plan `:523-578` leaves original action120/native30, active-native1, outer900 and all
original byte/name/JSON/graph/token limits intact. Native stdout2MiB/stderr256KiB
is not the gate collector's combined64MiB. Control/grant bytes consume the existing
appropriate collector/action counters while stdout/stderr facts remain accurate.
Original cutoffs propagate; no receiver starts a fresh ancestor900 allowance or
adds handshake workers/actions/time pools. 4GiB free floor/512MiB headroom stay.

This is a credible finite structural plan, **not proven native/quota feasibility**.
If real positives cannot fit, acceptance remains blocked; only a separately
reviewed bounded duplicate-work correction is eligible, not raised caps or skipped
positive cases. No Store-facing implementation or consumer configuration changes
are proposed here, so no new Google/Apple mutation can damage unrelated Store
state. Descriptor/process disposition remains restricted to actually owned
resources, not unrelated tasks, caches, source or retained evidence.

## Required implementation acceptance evidence

The frozen plan's `:625-727` tests are adequate as requirements, subject to proving
they reach the real dangerous paths. The actual-code reviewer and later verifier
must reject superficial mocks or false-positive result labels. In particular:

1. Real successful seed/prepare/editable prefixes must leave actual PASS-looking
   joint/ledger bytes before each independent post-replace check/fsync/readback/
   close/final-action/handler fault; also deny diagnostic persistence. The real
   controller fails, no finality is minted, and every later dangerous entry records
   zero native/target/Git acquisitions. A prefix that failed before publication
   does not count. Exception injection is not claimed as an actual OS kill.
2. Separately fail a later gate/GO/save after genuine transition return: earlier
   historical finality remains, live dispatch does not. No install/reseed/adopt/
   cleanup retry or successful terminal restart is allowed.
3. Exercise real typed/scope/root/phase/route/request/predecessor/replay/downgrade
   attacks, including spliced RUNNING, all-PASS and no diagnostic. Inspect actual
   startup adjacency and parent validation before Popen, not only loader errors.
4. Use the actual receiver/Popen/pass_fds boundary for copied headers/grants in a
   different inode, spoofed FDs/env/PIDs/nonces, wrong modes/aliases/extra endpoints,
   stale roles, missing ancestors and unauthorized/second/deeper delegation.
5. Inject real creation/transfer/Popen-before-and-after/selector/EOF/truncation/
   seal/write/fsync/close/GO/cutoff faults. Verify one-attempt ownership closes,
   unchanged counters, exact output facts, UNKNOWN disposition when warranted,
   no authority FDs in leaf commands and no unrelated resource affected.
6. Progress actual pending-to-editable-PASS-to-wheel-to-cleanup; retain immutable
   pending bytes and historical outputs while rejecting live/same-action reference
   substitution and second authority loads. Probe every inspection upgrade entry
   with zero acquisition and preserve all69 deep-schema assertions independently.
7. Run genuine minimal source-only creation, seed, initial collect/freeze, prepare,
   same-base editable and exact12/four delta, next probe, wheel/venv/install/import,
   observation and guarded cleanup in every original profile and the separately
   named observer profile. Capture original-size timing/byte/descriptor facts.

Unwaived original matrices: **103+62 pure;219 original;30 mapped;5 integration;
143 VPG (69 schema/67 preparation);25 historical mappings;10 controller;24 protocol;
45 real gates/order;13 Ruby files;two separate Bash syntax commands**. These are
future verification obligations, not passes obtained by this review. Original
218PASS/1FAIL/exit1, quota/deadline failures and partial cases remain preserved.

## Commands, coverage limits and resource disposition

Only bounded foreground static utilities used the approved interpreter
`.mobile-release/remediation/MRK-002/venv/bin/python -I -B -S` with non-login shell.
They read named no-follow regular files, hash/parse metadata, AST-parse text and
exclusively write new review records. No helper was imported or executed. The
current R3 commands returned0. An inherited preliminary R2 utility (`c0c957`)
failed with exit1 on an incorrect flat manifest-field assumption before writes;
corrected metadata reads succeeded. That is a preserved utility failure, not a
product/native result. Truncated relevant displays were reread in bounded ranges.

**Zero** installer/build/native/behavioral/project tests, Git/Store calls, process
enumeration/signals, source/index/cache/historical-venv/archive payload reads or
background workers were performed. macOS descriptor behavior, actual output
modes/aliases, cancellation/disposition, genuine positive lifecycle and original
quota fit remain unverified. No new Git snapshot/clean-tree assertion is made.
Generic real-project build-isolated editable/reported setuptools80.9.0 remains
separately unresolved; fixture79.0.1 does not prove that gate and it is not waived.

No task-owned build/background process or disposable build output exists to stop
or delete. Utility descriptors were closed; all prior resources and evidence were
preserved. The new review records are required deliverables and must be retained.
`INITIAL-BINDINGS.json` remains the original in-progress record; this final report,
coverage and decision supersede its status without overwriting its bytes.

## Final reconciliation and next owner

The complete plan, reanalysis, original findings, real affected callers, protocol,
ledger and test/limit contracts were reconciled. No duplicate or unsupported new
product finding is asserted. Approval is narrowly for the frozen design above;
actual missing callers, source/FD custody differences or failed required positive
routes must reopen review rather than inherit this approval by name.

Next: root inspects the pinned decision; only then separately authorizes scoped
implementation, followed by a distinct frozen actual-code review and separately
authorized complete verification. QA-006 remains undelivered. Overall project
status remains **NOT READY** pending its other gates and the mandatory fresh full
repository production-readiness audit/remediation. The complete product feature
report remains conditional on that final audit acceptance. No global completion
percentage is inferred from this bounded plan-review denominator.
