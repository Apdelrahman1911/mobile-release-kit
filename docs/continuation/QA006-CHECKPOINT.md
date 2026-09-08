# QA-006: exact point at which work paused

**The product fixture patch is not accepted or delivered.** Supporting verification
work is also unfinished. Do not start another issue's implementation while losing
this state, and do not confuse static syntax checks with behavioral verification.

## 1. Product R6 patch

Base `2beb37336fa8002b69f598fe431082606368310d`; expected product tree
`6009247f3627c9825e9ad9c790a57876e09f3726`. Exactly these seven paths differ:

```text
.github/workflows/ci.yml
tests/workflow/test_android_upload_validation.rb
tests/workflow/test_ios_upload_validation.rb
tests/workflow/test_native_profile_ci.py
tests/workflow/test_native_upload_validation.rb
tests/workflow/upload_process_fixture.rb
tests/workflow/upload_process_ownership.rb
```

Read `plans/qa-006/PLAN-R6-R2.md`, its inherited plans, the actual seven-path patch,
and `reviews/qa006-implementation-r6.md`. Original approved plan SHA:
`669c9c4398a9c80a52e2f35a02f0c6338341e4a8c171396057b4e70a235f91a1`.

Independent review found no further required source correction in its **completed
safe pre-entry scope**, but withheld acceptance because the plan requires:

- Actual entered distinct-object/same-message IOError proof, not just frame/pre-entry
  execution or a mocked equivalent.
- Identity-only predicate deletion mutation control.
- Original first-close native positives, missing-cleanup mutant, post-reap
  cancellation and hard-driver-loss controls on this exact R6 source.
- Both complete Android and iOS adapter suites; real-time, descendant, mutation,
  and ownership adversarial cases.
- Complete native Linux/macOS, source/wheel and project verification.

Recorded safe independent subset: five methods / 1,946 assertions; 33 instrumented
driver cases, including 28 new pre-entry cases; zero forwarded native signals.
These are not an unmodified full suite or final acceptance. Historical R4/R5
results cannot substitute for R6's missing observations.

## 2. Why verification did not simply continue on the original Mac

The separate QA-007 production capture path may signal an already-released group
identity. Running known unmodified signal-bearing paths on a shared machine was
not accepted. The original agent explored bounded local sandbox/ownership-based
verification instead; those helpers uncovered their own correctness gaps.

The user's immediate push now allows this handoff branch to exist remotely.
An explicitly reviewed disposable-host/hosted-verification plan may be considered
as an alternative to finishing the local-only verifier. It must execute **all**
required cases safely and retain the historical failure ledger; it cannot waive
QA-006, QA-007, or independent approval. The handoff did not dispatch such a run.
Do not reuse original host endpoints, process IDs, capabilities, quotas or success
records on a clone. A new plan must state its exact environment and authorization.

## 3. Paused verifier fixture-base correction

### Underlying supporting defect

VFBP-R2-01: a genuine editable transition can publish PASS-shaped receipt bytes
and then fail before the **original parent action returns successfully**. Later
native use therefore needs live original-parent finality, not disk-shaped success.
The accepted design also keeps strict immutable versus produced bootstrap roots,
early admission, exact source identity, and non-upgradable inspection.

### Plan and review state

`plans/qa006-verifier/FIXTURE-BASE-PLAN-R4-R3.md` is the active amendment, inheriting
R2 and the separate `VERIFIER-CORRECTION-PLAN-R4-R2/R3/R4` documents. Read its
reanalysis and member-derived contract, not just a summary. The R3 independent
decision was **APPROVED_PLAN_ONLY**, not implementation acceptance or execution.

- Original plan SHA: `4073504ad2286c2925e510848234549fcb934bb5236e618f3367a035d6a910b0`.
- Original decision SHA: `bc7dcb38d276893f7c75566471f1ca795eea2303176ef6c0ee510a973fa38873`.
- Earlier R2 review remains useful: it exposed the real after-effect finality
  issue; do not resurrect its rejected disk-only authority.

Required design: live Session/finality; exact dispatch tickets; original-source
anchored unlinked capabilities across real execs; READY/seal/GO; only one allowed
wheel→source-venv delegation; earliest admission before backend/application code;
produced-root tombstones; immutable pending ledger with narrow current transaction;
strict, non-upgradable EvidenceInspection. Anchor descriptors and transferred-reader
descriptors have different custody. Never retry an ambiguous close. Bootstrap must
use the exact case-copy `verify-frozen-diff.py` adjacent to the stamped `action_io.py`.

### Safely paused actual draft

Only two of 38 baseline helper/static/driver files changed before the pause:

| File | Original SHA / bytes | Paused SHA / bytes |
| --- | --- | --- |
| `action_io.py` | `4a6a1bd81642290d47d275681828b9e9a77325282f38d03c7eda3692be81ecf4` / 34,157 | `64ce5f0797e7be98e2ace021521fd7f867795b4a8f23493b651064dab36703b4` / 133,786 |
| `native_reader.py` | `0c2b597db07a00195690598b3a662c8116ad4122b9c88240de3fd7a3b99b965f` / 16,618 | `55c9d3cf40d592c79c9cb0ec016df108b23435e1fd596ba69a50a7e2dc71a59d` / 18,599 |

These hashes identify original local source, **not the sanitized exported bytes**.
Use `EXPORT-MANIFEST.json` for export hashes. The author paused at a completed
write boundary. Draft scaffolding covers factory/session/ticket/lease/protocol/
ledger/finality and initial native collector integration; it is **incomplete and
unreviewed**. Only AST syntax parsing occurred. No current helper import, installer,
native behavior, or regression test was run for this amendment.

Read **all six known concerns and all fourteen unfinished obligations** in
[QA006-VERIFIER-TODOS.md](QA006-VERIFIER-TODOS.md). This includes real missing guards,
not optional cleanup. Do not present the scaffolding as finished implementation.

The source reference set includes:

- 24 baseline non-JSON helpers; overlay only the two draft overrides to understand
  the paused source. Five original local JSON configuration/ownership/acceptance
  records are intentionally excluded, not fabricated as portable authority.
- Nine copied proof drivers and the original 25-mapping oracle
  `prove-corrections-v4.py`, plus `original-verify-frozen-diff.py.txt`.
- Complete inherited plans, genuine minimal/seed/editable contract and current
  independent review. Exact fixture seed is pip 24.0/setuptools 79.0.1 with 1,052
  files/142 directories; editable successor is 12 files/four directories. The
  plan records archive pins/member-derived expectations. Third-party packages
  themselves are not copied into this public handoff.
- Original proof scopes: 103+62 pure; 219 original; 30 mapped; 5 integration;
  143 VPG (69 schema/67 preparation); 25 historical mappings; 10 controller;
  24 protocol; 45 real gates in order; 13 Ruby files; two Bash syntax commands.
  These are separately defined/overlapping obligations, not a sum of new passes.

Original runtime limits remain documented: action 120s/native 30s/one active
native/original outer 900s, 4GiB floor and 512MiB headroom, and all original byte,
name, JSON, graph, tool, inventory/count limits. A clone does not create an old
grant or reset these scopes. Actual-project build-isolated setuptools **80.9.0**
is a separate unresolved compatibility gate, not covered by the fixture 79.0.1.

## 4. Shared-clock correction: approved plan, implementation not begun

The original helper used Python `time.monotonic()` (observed implementation
`mach_absolute_time()`) and Ruby `CLOCK_MONOTONIC` for shared absolute endpoints.
A one-shot bounded scalar sequence Python-before → Ruby → Python-after observed
the later Ruby samples **5.522709291 seconds before** earlier Python samples.
Identically named clock IDs bracketed across languages. This confirms the current
host's mismatched helper contract, not the missing historical Ruby failure sample.

The final independent plan review is approved, superseding the old R18 wording
“under review.” **No clock code fix has been implemented.** Original sources in
`drafts/clock-original/` still have the defect and must not be executed.

Read the complete clock correction plan, its required supplement and review:

- `plans/qa-006/SANDBOX-INHERITANCE-CLOCK-CORRECTION-PLAN-R1.md`.
- `plans/qa-006/CLOCK-CORRECTION-PLAN-SUPPLEMENT-R1.md`.
- `reviews/clock-correction-plan-r1.md`.
- Governing original `SANDBOX-INHERITANCE-CORRECTION-PLAN-R3-R4-R2.md` and
  inherited source/test obligations.

Approved intended change: both language getters explicitly use guarded Darwin
`clock_gettime(CLOCK_UPTIME_RAW)` / ID 8. Reject unsupported platform, missing/wrong
constant, bad sample type/value or API error. No offset, fallback, tolerance,
deadline renewal, historical endpoint adoption, or weakened entry lower bound.
Preserve all original ownership, control, terminal, selector and budget guards.

Critical implementation details already identified:

1. New package/grant/descriptor/evidence identity before any acquisition; consumed
   old grants never authorize corrected helpers. Rebind Ruby BASE and Bash target.
2. Keep `canary.py`, `sender.py`, `python_relay.py`, `reconcile.py` otherwise
   byte-identical in the original-host design. New-host redaction is a separate
   adaptation requiring plan/binding review, not silent equivalence.
3. Keep all 93 Python and 40 Ruby obligations and real ID-sensitive getter/entry
   tests. Ruby positive must call its complete constructor, not allocate-only.
   Python must veto `clock_gettime` before helper definition loading. Preserve
   independent original pure-driver clocks/cutoffs.
4. Fix the old-BASE negative test at original `test_pure.py:2782`: its truncation
   heuristic becomes an invented path under the new package name. Use the explicit
   actual original `sandbox-inheritance-r3-r4` literal; independently expect the
   new literal for all 11 routes/seven Ruby paths.
5. Three required fixtures are read at original Python lines 1571–1572, 2516 and
   2810: legacy snippets and both selector snapshots. Originals stay unchanged
   locally. Public snapshots are sanitized shapes, **not executable substitutes**
   for the approved original bytes. Plan/review the clone's replacement binding.

The original proposed corrected native matrix remains 11 rows, 44 acquisitions/
57 execs, at most six observers (50/63 total), hard 64/96, 30s work+10s disposal,
180s outer, 64KiB streams, 4KiB chunks, 512-byte terminal commit, 2MiB capture/
8MiB evidence. No new query/signal/Store route is implied.

Original consumption is Python **3/4**, Ruby **2/2**, native inheritance **1/1**,
scalar diagnostic **1/1**. The approved plan proposes conditional Python004,
one explicitly additional Ruby and one explicitly additional corrected native
invocation. It grants **none** of them. Distinct exact-code/safety review and
explicit new admission are still needed; do not silently reset consumed quotas.

## 5. Immediate successor choice and eventual completion

Review whether a fresh disposable hosted verification environment can safely
satisfy QA-006's complete remaining matrix now that a handoff branch is authorized.
If not, finish the approved local helper corrections and obtain distinct actual-code
review before any execution. Either route requires a new exact environment/binding
plan; neither can import old live resource authority or claim historical failures
were fixed merely by moving machines.

Then finish independent QA-006 acceptance, complete project verification, scoped
protected delivery and actual main CI. Proceed to QA-007, then rebase/reconcile
QA-003, followed by QA-004, QA-005, MRK-008, MRK-009, the fresh complete audit,
further necessary fixes, and only after READY the full feature report.
