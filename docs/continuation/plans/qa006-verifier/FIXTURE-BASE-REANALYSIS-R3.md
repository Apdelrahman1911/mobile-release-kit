# VFBP-R2-01 — R3 reanalysis and review handoff

## Scope and status

This is **plan authoring only** by `/root/qa006_verifier_r4r4_implementation`.
No R3 fixture-base helper implementation has been made or executed. The new
plan is `FIXTURE-BASE-PLAN-R4-R3.md`; its immutable review snapshot, accompanying
coverage and exact input references will be `fixture-base-plan-snapshot-r3/`.
Only that frozen package, not this moving author workspace, is review authority.

Original independent finding: **VFBP-R2-01**, Medium, a supporting-verifier plan
defect, not a new product/Store issue. Its governing R2 report/decision remain
REQUEST_CHANGES. R1 and all139 R2 members remain unchanged. The original R2
seed/editable derivation is inherited, not represented as an executed installer
or replaced with a relaxed runtime namespace.

## Reproduced reasoning, not a native reproduction

Static inspection confirms the actual counterexample:

1. A genuine editable child can finish successfully; the parent may independently
   validate the exact changed runtime and write/read back the joint completion.
2. `action_io.replace_ledger` can make the prescribed PASS/outputEvidence bytes
   visible at its actual os.replace call, then fail during check/fsync/close,
   later exact readback or the final action boundary.
3. `verify-all._run` catches failure and correctly stops. Its diagnostic is
   best-effort. Restart is rejected. No normal continuation bypass is claimed.
4. An ordinary later disk-only loader cannot distinguish these files from the
   same files after an action that returned successfully. A spliced RUNNING row
   or additional success marker supplies no independent original-parent fact.
5. Actual collect performs source-snapshot/native Git before tool probes; late
   active-ledger checks in wheel preparation/observer cannot protect that first
   acquisition. Admission must happen before load/collect/Git/tool/startup use.

These conclusions are a source trace against the frozen R2 files, **not** an
executed failure-injection/native test. R3's required genuine after-effect tests
remain unexecuted and mandatory after plan/implementation review and separate
execution authorization.

## Why the selected correction is not another marker

R3 separates original parent control-flow finality, revocable live dispatch
authority, immutable historical evidence and bounded current-ledger observation.
The parent stores its successful-return fact only after the real action exits
normally. A later dispatch failure cannot falsify that history, but closes the
session and prevents further dispatch.

In-process callers receive registered identity-bound objects explicitly. Genuine
exec helpers instead receive a finite root-created unlinked kernel capability
through exact pass_fds. Their expected original kernel/header identities are
literal in trusted source emitted before request/freeze, not obtained from
attacker-supplied request metadata. A fresh nonce plus actual Popen/PID/role and
sealed-original-object READY/GO exchange binds one current receiver. This remains
a cooperative trusted-code design, not a same-UID/host-memory sandbox claim.

The original parent controller is source-loaded in the proof process, while
the generated compound wheel and nested source-only venv are real execs. The
plan therefore includes one fixed root-preallocated delegation, not an opaque
in-process object that cannot reach real positive consumers. Fixed descriptor
locators are stamped before route/freeze; no new FD argv/env flags or capability
leak into pip/Git/backend leaves is required.

The existing Bash wheel chain belongs to the original final45/pre-existing
runner route and is explicitly traced. It receives no fixture capability.
Every existing produced profile uses the generated Python route instead. An
undeclared produced-Bash reroute must reject before acquisition; an actually
required extra hop discovered later must return for revised plan review, not
be silently omitted or classified as generic.

## Other cross-component reconciliations

- The pending editable ledger becomes an exclusive exact-byte immutable snapshot.
  The current mutable ledger uses a narrow ctx-local observation/guarded replace/
  readback transaction, never FrozenAuthority same-path rebinding or a second
  authority reload. Post-replace failures retain evidence without minting use.
- The live session/source anchor independently preserves produced classification.
  Changing config/type/request/scope or removing a marker does not select the
  reviewed pre-existing-runner variant.
- Terminal EvidenceInspection is a different non-upgradable type. It shares
  strict schema/predecessor validators, not native loading or authority minting.
- VPG69 deliberately rebinds malformed fixture records to reach deep schema
  assertions. R3 keeps that shared real-validator coverage through read-only
  inspection, separately from native admission rejection. An earlier capability
  denial must not be labelled proof of a deeper original schema assertion.
- Original noneditable split scopes remain split; only the already-proposed R2
  editable transition uses a single action. The fixed protocol consumes existing
  collector/action limits, never a handshake action, new supervisor or reset.
  Original-sized native/macOS/quota feasibility remains explicitly UNVERIFIED.
- Original generic editable source/backend behavior is still unresolved and
  unwaived; its reported setuptools80.9.0/build-isolated path is not the fixed
  fixture79.0.1/no-isolation route. No new generic defect is asserted here.

## Static inspection coverage

The snapshot coverage ledger identifies exact input references and named semantic
ranges. The principal actual paths traced are:

| Immutable R2 area | Verification performed |
| --- | --- |
| R2 plan, member-review, independent R2 report/decision | Finding/recommendation reconciliation; retain original exact namespace and all unexecuted gates |
| action_io Action/context and replace_ledger | Control-flow return versus closed state; post-replace check/fsync/close; immutable reference and cumulative budget rules |
| verify-all run_gates/_run/main | Source-loaded parent, separate scopes, real producer retention, output binding/save, stopping/restart behavior |
| bindings load/check/collect/tool_bindings/FrozenAuthority | Actual earliest Git/native ordering; original references; one action/authority; no inspection upgrade/downgrade |
| owned_outputs receipts/ledger/guards/runtime producers/preparation/cleanup | Exact predecessor chain, source-output lifetime, ordinary loaders, genuine nested venv helper and literal pip leaf argv |
| frozen_diff predecessor/prepare/check/cleanup | Shared descriptor validators versus native consumers, actual active gate checks and destructive path |
| process_gate/native_reader | Real Popen/handle/selector/EOF/close/disposition and original limits; locate protocol integration without extra workers |
| verify-frozen-diff setup/collection/lifecycle/worker/ledger/legacy_cleanup | Complete original profile/caller inventory and emitted source timing; explicit original parent versus exec child boundaries |
| mapped/VPG drivers and VPG schema child | Direct collect/load/check callers; intentional malformed-record tests; genuine successful prefix requirements |
| gate_list/wheel-smoke/finite runner | Original45/Bash path distinction; original finite900 parent and command declarations; original role/deadline scope table |
| Other copied helpers/static records/selected third-party member text | Exact immutable hash binding in R3; prior R2 semantic review inherited only, no claim of fresh whole-file semantic review |

No original cache, historical venv payload, installer archive or runtime binary
was inspected in this R3 task. Existing copied helper files were read as text;
none was imported, compiled or executed. Reading a fixture-capability design or
a source implementation is not a native verification result.

## Authoring command/accounting record

- Foreground `sed`, `nl`, `grep`, `cat` and a max-depth2 named plan-record listing
  were used for static text inspection. Where a tool display truncated a relevant
  section, bounded named ranges were read separately; the coverage record does
  not claim complete semantic reads from a truncated display.
- New Markdown records were authored with apply_patch. An intermediate patch
  attempt failed because its expected text was absent; it made no change. The
  failure was an authoring operation, not a native/helper/test result, and is
  retained here rather than relabelled as a behavioral pass.
- The root-approved static utility interpreter is
  `/ORIGINAL_REPOSITORY/.mobile-release/remediation/MRK-002/venv/bin/python -I -B -S`.
  The new bounded snapshot utility uses only stdlib no-follow file read/hash,
  duplicate-rejecting JSON, finite manifest validation and exclusive record/copy
  writing, with native/network/process operations vetoed. It never imports a
  helper or traverses unknown/cache/venv contents. Its actual outcome/pins are
  recorded in the snapshot manifest and handoff, not assumed before execution.
- Native/behavioral/installer proof runs, helper imports, Git operations, Store
  operations, process enumeration/signals and build workers: **0** in this task.
  The short foreground text/authoring utilities are not claimed as native proof.
  No background process or open descriptor is retained; no build output exists
  to stop/delete. Required new plan/snapshot records are preserved deliverables.

## Authorities withheld and next owner

Root appointed `/root/qa006_inheritance_r3r4_implementation` for independent R3
plan review after the frozen pins are delivered. That reviewer did not author
this verifier plan. Pre-reading/discussion is not approval. Root must confirm
the frozen scope; no author/reviewer obtains implementation or execution
authority from the mere existence of this package.

Still mandatory: independent approved R3 plan; complete scoped implementation;
distinct frozen actual-code review; separately authorized finite full proof
matrix; all original project/final gates; fresh full-repository audit/remediation;
conditional complete feature report. The original218PASS/1FAIL/exit1, quota
failures, partial cases, R1/R2 evidence, held caches/venvs, source/user changes,
AGENTS, Git state and other tasks are preserved. QA-006 remains undelivered and
the project remains **NOT READY**.
