# QA-006 fixture-base bootstrap amendment R4-R2 — independent plan re-review

## Decision and exact reviewed inputs

**REQUEST_CHANGES.** R2 materially addresses the original missing editable-successor
contract, but one blocking supporting-plan issue remains: **VFBP-R2-01**,
post-publication finality. Do not implement this amendment from this review.
This is not a new MRK product finding, Store defect, native proof result or
whole-repository verdict. Original R4-R4/R4-R3 approvals and all outstanding
actual-code, native, full-suite and final-audit gates remain mandatory.

Reviewer: `/root/qa006_verifier_fixture_base_plan_review_r1`.

Reviewed immutable snapshot (paths below use this root unless stated otherwise):
`.mobile-release/remediation/QA-006/verifier-correction-r4-r3/fixture-base-plan-snapshot-r2/`.

- `BINDINGS.json`: 155,874 bytes; SHA256
  `180ff938b59c59f18b14e28b04211bacb7dcafac4bbb53c3150a672986f83d29`.
- `FIXTURE-BASE-PLAN-R4-R2.md`: 35,853 bytes; SHA256
  `33287b70077bc781993d38d094800e74afbedaec2f828535cdc08d051b7de5b4`.
- `FIXTURE-BASE-MEMBER-REVIEW-R2.md`: 17,769 bytes; SHA256
  `21d518d6fb83e6c2fc694fed353c18bbb65c48dfaf8593d3fc5371f1462873d5`.
- All 139 snapshot entries (4,446,810 bytes) independently match their exact
  expected identity, size and SHA256. No moving helper draft is review authority.

`COVERAGE.json` binds every file and distinguishes targeted semantic reads,
complete before/after diffs, retained metadata checks and hash-only coverage.
`STATIC-CHECKS.json` records static outcomes, not behavioral test passes.

## Original finding reconciliation

Preserved R1 review remains **REQUEST_CHANGES**, unmodified: `history/R1-PLAN-REVIEW.md`
SHA256 `26fae4545688aaaf43e284264242071366e745f524dce708b9c07659fb995f15`;
`history/R1-DECISION.json` SHA256
`90773f468b0550872476a52e6a2b7b0d7162a71dfdc1b4e5ffb956601e38c650`.

The R1 root cause was the genuine editable install into the same newly seeded
fixture base, without authority for its installed startup/metadata/console delta.
Current `verify-frozen-diff.py:558-651,1233-1241` still creates that base and declares
that route. `owned_outputs.py:288-319,380-450` currently binds source build/egg-info,
not a full editable runtime. It cannot supply the missing authority by itself.

R2 now specifies immutable original request and seed authority, a fixed genuine
PEP660 successor, independently justified complete delta, original-parent-only
in-progress capability, joint source/runtime receipt, descriptor-only predecessor
validation, unchanged source freeze and later output/cleanup projection. These
are substantive design corrections, not skipping editable or recategorizing the
new base as pre-existing runner TCB. **VFBP-R1-01's omission is addressed in the
proposal; implementation and successful lifecycle proof are still absent.**
The remaining finality defect prevents approval of that proposed transition.

## Independent pinned-source assessment

Member paths in this section are the original member names. Exact retained `.txt`
paths, hashes and reviewed ranges are in `COVERAGE.json`; originals were not imported.

1. Pip24 `cli/main_parser.py:81-105` and `build_env.py:44-57` corroborate the
   `--python` redispatch using target Python plus the bound wheel/pip path and the
   same pip arguments, with only the real pip parent introducing its redispatch
   marker. Parent `-I/-B/-S` flags are not forwarded. `pip/__main__.py` supports
   the wheel-path invocation. A separately observed target PID/exit is not inferred.
2. `distributions/sdist.py:30-67,95-129`, `req_install.py:536-620` and the complete
   editable metadata/build wrappers corroborate the fixed no-build-isolation
   PEP660 route. `commands/install.py:350-495` completes build/hooks before
   `install_given_reqs` mutates installed target files. This does not prove runtime
   environment, modes, aliases, final namespace or timing on the host.
3. `pyproject_hooks/_impl.py:297-330`, pip `base_command.py:135-153`,
   `build_tracker.py:15-51` and `utils/subprocess.py:134-183` support the actual
   `PEP517_BUILD_BACKEND`, `PIP_NO_INPUT` and generated private-TMP tracker additions,
   synchronous wait and no invented hook flags. Native capture must still verify
   the exact original parent dispatch environment and pinned child contract.
4. Setuptools `editable_wheel.py:90-420,558-674`, `build_meta.py:301-483`,
   `dist_info.py` and `install_data.py` corroborate static source/src pth mapping,
   temporary metadata/build roots and noneditable Gemfile installation. For this
   fixed no-isolation synthetic route, empty pre-owned source build/egg-info is a
   justified expectation, not a license for a generic empty-output bypass.
5. `_apply_pyprojecttoml.py:45-119,160-251`, `dist.py:357-531`, `_static.py`,
   `_core_metadata.py:149-337`, `_entry_points.py` and `bdist_wheel.py` corroborate
   static metadata treatment, the license-file dynamic field, fixed entry point,
   WHEEL/licensing behavior and the proposed twelve-file installed delta. The
   plan's exact fixture literals are independently declared, not captured from a
   target or from an expected-value renderer under test.
6. Pip `operations/install/wheel.py:224-710`, distlib `scripts.py:1-357` and
   `util.py:566-590` corroborate scripts, data mapping, generated metadata and
   installed RECORD behavior. Script mode is 0755 under umask077; ordinary
   nonexecutable payload is 0600. Original seed ZIP metadata shows no executable
   member and no `.data` path in either exact wheel. Locale compatibility source
   supports the fixed ASCII-path restriction for Python3.11 pth encoding.
7. Complete retained original RECORD/inspection-metadata agreement covers 524 pip
   and 514 setuptools members. All 76 retained text copies (70 unique members)
   match their original selected-member and RECORD digests where applicable.
   Independent name arithmetic gives 1,052 seeded regular files and 142 directories
   excluding root and platform aliases. Twelve editable files and four new dirs
   are a static expected delta; none of these counts is an installer PASS.
8. The exact `distutils-precedence.pth`, `_distutils_hack/__init__.py`, relevant
   setuptools startup and vendored-wheel emitter source were considered. Their
   binding does not turn an arbitrary pth or new source into trusted startup code.

Unselected 485 pip and 483 setuptools payloads were not read. They are bound through
retained whole-archive input references and complete metadata/RECORD inventories,
not semantically audited. No external package-author signature is established by
this local input binding. Existing source-only venv/activation contracts are
inherited from R4-R4; no archive, runtime-binary, cache or historical-venv payload
was opened in this re-review.

## VFBP-R2-01 — Published PASS-shaped files do not prove parent-observed finality

**Severity:** Medium, blocking supporting-plan correctness/verification reliability.
**Classification:** confirmed missing finality/admission mechanism in a proposed
plan. No live Store defect or executed native reproduction is claimed.

### Affected plan and actual callers

- Plan `FIXTURE-BASE-PLAN-R4-R2.md:123-141,338-395,415-423,503-506` promises that
  failed/cancelled publication leaves the runtime unauthorized even when partial
  success-shaped evidence exists. The proposed later loader uses the actual
  ledger -> joint receipt -> producer/attempt/prepare/seed disk chain.
- `current29/action_io.py:701-720` writes pending ledger, replaces the named final
  ledger at :717, and can fail at the subsequent check/fsync/check (:718-720),
  including directory-close handling after that scope.
- `current29/verify-all.py:99-105,181-207` saves PASS/outputEvidence after joint
  output binding; on exception it changes failure in memory and only best-effort
  writes a separate diagnostic. That diagnostic can also fail or never run after
  termination. The already replaced ledger need not be rewritten as FAIL.
- `current29/owned_outputs.py:323-367,460-470` accepts a completed predecessor via
  ledger/receipt data. Ordinary input loading/guarding has no independently bound
  current-dispatch prerequisite. R2's descriptor-only state selector must change
  this contract; existing predecessor validation is not publication-finality proof.
- `current29/owned_outputs.py:1318-1324` loads/checks frozen inputs before checking
  the active wheel gate. `current29/observe-owned-workers.py:95-100` similarly
  runs check_frozen before prior_workers/active_ledger. `bindings.py:991-1004` calls
  collect, whose `tool_bindings` (:231-288) starts native tools. Therefore putting
  an admission check only at a later active_ledger call is too late.

### Static counterexample and reachability qualification

1. A permitted fixture's genuine editable process succeeds; exact runtime and
   source validation succeeds. The original parent publishes/readbacks a valid
   joint receipt, with its real successful producer and immutable predecessors.
2. The parent builds the prescribed PASS ledger row with the exact outputEvidence
   reference. `replace_ledger` successfully replaces final-verification.json.
3. Inject a failure **after that replacement**, e.g. pending cancellation at :718,
   directory fsync failure at :719, terminal check/close failure, or termination
   before the observing parent finishes this action. Preserve all already written
   valid bytes. Failure diagnostics are absent or cannot be persisted.
4. The original `_run` stops correctly. Nevertheless a new ordinary descriptor
   load can see the same valid source, seed, attempt, joint receipt, real producer,
   log and PASS/outputEvidence bytes as in the successful path. Those disk facts
   alone do not distinguish the original parent's successful transition return
   from step3. The in-progress capability is closed/invalid, and R2 has not
   specified a parent-finality/later-dispatch authority consumed by the new loader.
5. A callable later input consumer must reject before any acquisition. Testing only
   a failure before writing the ledger, or only `_run` returning1, does not exercise
   this after-effect condition. Passing the disk-only state selector would allow
   check_frozen/tool probing before the later active-gate rejection cited above.

**Existing guards that work:** `_run` catches the failure and does not itself
continue the loop (:197-211); `main` rejects restarting any final namespace
(:219-228). No normal continuation of that failed controller was demonstrated.
This finding concerns the plan's stronger reusable-loader/later-consumer authority
claim, including its mandated fresh-action failure-injection guards. It must not
be misreported as a currently demonstrated whole-workflow or Store bypass.

### Expected, impact and root cause

Expected: all post-publication failure/ambiguity scenarios retain evidence but
cannot authorize later native use; successful original transitions remain reusable
without reinstalling. Actual proposed mechanism checks success-shaped disk
relationships without specifying how a later consumer authenticates successful
return through the original parent publication/action boundary. A real child PASS
proves the child, not its parent's later successful accounting persistence.

Impact is potential admission of an incompletely finalized verifier transition,
violating supporting evidence/fail-closed claims and invalidating QA-006 verification
acceptance. This blocks plan approval and eventual supporting-verifier delivery;
it is not independently a candidate/promotion/production-Store block in product
code. The underlying error is conflating visible committed-looking bytes with
parent-observed transition finality.

### Required concrete plan correction

Specify one complete finality and acquisition contract before implementation:

- Separate immutable historical editable candidate/receipt facts from permission
  to use that successor. Only the original trusted controller's successful return
  through the **entire** original transition action may grant the latter.
- Bind subsequent declared gate admission to that parent-observed success and the
  exact original request, source freeze, predecessor, route and actual dispatch.
  The permission cannot be minted from an arbitrary boolean, filename, JSON
  lookalike, unrelated action, merely matching PID or a future success row.
- A fixed active-successor requirement is useful: after the concrete failure the
  ledger has editable PASS but all successors BLOCKED. Check the allowed exact
  current progression descriptor-only **before** load/collect/tool/Git acquisition,
  without recursive load_frozen/active_ledger loops. Define initial SEEDED phases,
  in-progress original capability, later EDITABLE consumers and terminal read-only
  inspection separately.
- A bare next-gate RUNNING predicate is insufficient. The mutable ledger could
  contain a spliced RUNNING row alongside genuine predecessor bytes. Explain the
  binding to original controller-observed progression, for example a factory-
  issued original-parent-held dispatch authority and its explicit trusted
  propagation contract. Do not silently assume that an ordinary disk marker
  proves its writer successfully completed.
- Another success marker only moves the same last-write ambiguity unless it has
  independent caller/finality authority. Absence of a failure diagnostic is not
  success. Do not solve this by making partially published bytes adoptable,
  rewriting original evidence, granting a fresh budget, rerunning installation or
  weakening finality. No alternate correction is approved by this review.

### Required regression evidence

Keep all R2 regressions and add explicit named after-effect cases:

1. Start from genuine prepare/seed/editable successful prefixes. Let ledger
   replacement really occur, then inject each check/fsync/close/readback/terminal
   failure and cancellation boundary. Preserve the valid-looking receipt and
   ledger bytes; also deny failure-diagnostic persistence. Include termination/
   interrupted-publication simulation without granting a later retry.
2. Assert the actual original controller returns failure with truthful accounting,
   no following acquisition, retained output and no install/reseed/cleanup retry.
3. In a fresh authorized test action invoke the **real later admission/guard**,
   including the path preceding check_frozen/tool_bindings. Assert zero target,
   Git or other native acquisition and no reconstructed transition authority.
   Do not count earlier unrelated setup rejection as this result.
4. Mutate only a successor BLOCKED row to plausible RUNNING; try a serialized
   lookalike, wrong/closed parent action, wrong route/predecessor and an extra
   success filename. None may manufacture original-parent dispatch authority.
5. Positive complete original action -> genuine next fixed gate -> wheel/observer/
   cleanup must still work, without losing the exact editable predecessor. Test
   terminal all-gates-PASS read-only inspection separately from new native use;
   no no-active-gate fallback may restore the defect.

## Mandatory clarification — historical pending ledger versus current authority

This is **not a second finding**: R2 :334-337 can be implemented consistently,
but the exact serialization/admission interpretation must be retained in the
revised plan and actual-code review.

The original pending ledger bound by the exclusive attempt is an immutable
historical observation: embed its exact bounded validated contents and digest in
that attempt, or retain an exclusive immutable snapshot. Do not create a forever-
live file reference requiring final-verification.json to remain at those pending
bytes. That file is legitimately replaced on PASS and again by later gates.

`FrozenAuthority.bind/read_record/recheck` (:892-918) forbids contradictory backing
references during an action. Do not mutate those bindings to adopt a replacement,
reload a second authority in the same action, rewrite stable freeze, or skip all
rechecks. Recheck the original pending bytes until the legitimate save boundary;
validate the new save through its exact independent readback/finality path. Later
load uses the **current** actual ledger plus original immutable historical chain.
A historical pending observation never grants current dispatch authority itself.

Tests must advance the ledger through PASS and later gates/cleanup while the
historical observation remains immutable, and reject stale-live reference reuse,
same-action rebinding, changed history, copied pending bytes and fake current state.

## Source-output lifetime, generic scope and intervening drafts

The historical editable receipt must retain its genuine empty source-output
projection without requiring those obsolete contents after a later genuine wheel
build populates egg-info or cleanup removes it (plan :293-316,406-413). Current
source output validation still follows the actual later producer. Mapped SOURCE/src,
seed and complete installed base remain protected before every permitted startup.
The two retained original source caches and all historical53 venv payloads remain
outside read/disposition scope.

Generic non-fixture behavior remains an explicit separate gate, **not a confirmed
additional defect and not waived**. `current29/gate_list.py:34` uses real
`pip install -e .[test]` without the tiny fixture's no-build-isolation policy.
Parent independently reported the real source backend is setuptools80.9.0 rather
than inspected fixture79.0.1. Pinned pip `sdist.py:40-54,103-124` shows isolation can
invoke get_requires_for_build_editable, unlike this no-isolation route. It is
therefore invalid to generalize the tiny fixture's empty-source-root conclusion
to the real generic gate. Its actual source/backend/isolation contract must be
resolved before final acceptance; no actual80.9.0 emitter execution or source
review is claimed here.

All seven intervening R1->R2 draft diffs were considered: collector digest/error/
cancellation/disk handling; explicit collector policies; helper admission and real
offline tiny runtime routing; generated schema/test rows and descendant observation.
Their exact before/after copies are bound in coverage. They are still unaccepted
implementation drafts, not implementation of R2 and not a substitute for the
separately appointed full actual-code review. R1 artifacts and all failed/quota/
partial proof evidence remain unchanged.

## Coverage, verification limits and resource accounting

- The whole R2 plan, member-inspection review, draft reconciliation and preserved
  R1 finding report were read. Relevant actual callers and every intervening diff
  were traced. `COVERAGE.json` lists all139 files, exact reference and method.
- Retained third-party selected text was hashed/cross-correlated completely;
  only named semantic ranges were read. Metadata arithmetic and source reasoning
  do not establish host installation, cancellation, process disposition or quota fit.
- Commands used the approved utility interpreter with `-I -B -S` and foreground
  stdlib-only stdin programs for bounded no-follow read/hash, JSON/CSV comparison,
  static unified diff and exclusive report writing. Static checks succeeded.
  Truncated displays were reread at the relevant named ranges. No helper import,
  proof/test/installer/native target, FFI, Git, Store, process query/signal, source
  cache or historical runtime payload operation ran. No test PASS is claimed.
- Original103+62 pure,219 original,30 mapped,5 integration,143 VPG (69 schema/
  67 preparation),25 historical mappings,10 controller,24 protocol,45 real gates,
  13 Ruby files and **two distinct Bash syntax commands** remain required. The
  previous218PASS/1FAIL/exit1 and JSON/deadline/quota failures are not erased.
- Original120s action/30s native, single active native, all original byte/name/
  graph/record/token limits, outer900s, 4GiB floor and512MiB headroom remain. Actual
  seeded-plus-editable full-lifecycle feasibility is **UNVERIFIED**.
- No build/background worker was started. No process needs stopping and no
  disposable build output was created/deleted. Only this exclusive ignored review
  directory is written; its records are required deliverables. Existing AGENTS,
  product files, helper drafts, frozen inputs, caches and other tasks are unchanged.

## Next steps and authorities withheld

Preserve this R2 plan/review. Revise the finality/dispatch design, retain the
historical-ledger clarification and obtain independent plan approval again. Then
scoped implementation, frozen actual diff, distinct actual-code review, separately
authorized finite native proofs and complete project gates remain mandatory.

This review grants no amendment implementation, execution, acceptance, cache/venv
read or disposition, cleanup, commit/push, delivery or READY authority. Original
R4-R4/R4-R3 scope is not revoked or expanded. QA-006 remains undelivered; a fresh
full-repository audit/remediation and the conditional detailed feature report
are still mandatory. No percentage or bug-free claim is derived from this review.
