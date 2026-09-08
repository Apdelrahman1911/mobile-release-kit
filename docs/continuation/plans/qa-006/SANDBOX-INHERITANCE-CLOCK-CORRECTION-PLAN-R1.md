# QA-006 supporting inheritance helper: one shared clock contract

**PROPOSED PLAN ONLY.** No implementation, pure-driver or native execution is
authorized by this document. Obtain distinct plan review, scoped implementation,
distinct actual-code/safety review and separate root admission for each proposed
verification invocation. This is an ignored verification-helper correction, not
a product Store/CLI finding or a change to QA-006's seven intended source paths.

## 1. Reanalysis and evidence

The original inheritance execution `961634` exited1: three narrow Python-backed
passes, Ruby entry-window failure and seven unexecuted routes. Its actual missing
Ruby sample cannot be reconstructed. The independent result decision under
`sandbox-inheritance-execution-results-review-r1/` remains a reconciled failure;
unknown protocol state and failed scratch remain retained.

A separately reviewed scalar diagnostic ran once (`2a5a0c`, actual exit0), using
exact pinned Python3.11.16 and Ruby3.3.12 in the order Python-before/Ruby/Python-after.
Its raw2411-byte output SHA256 is
`42d7504b1628221a2592949c69f9212227cb920a1e84e7ddc306b7eba270354a`.
`sandbox-inheritance-clock-diagnosis-r1/RESULT.json` SHA256 is
`86aef48b307ba4a8085f5dad8dd91b59eae383e434f3e4b81bcd1514807058d0`.
The independent result decision SHA256 is
`ea2f609dc4741a650bec62a6ff048f166873b01d9c221e56c8b99f4e7ade4262`.

The current Python helper reports `mach_absolute_time()` around120470.645;
later Ruby `CLOCK_MONOTONIC` samples are around120465.122. Minimum observed gap:
5.522709291 seconds. All three explicitly named common clock IDs bracket correctly
across the interpreters. This establishes a **current-host incompatible absolute
clock contract**, not the missing historical value or every platform's behavior.

Affected current code in `sandbox-inheritance-r3-r4/`:

- `runtime.py:21–28`: `now()` uses `time.monotonic()` for every Python original
  endpoint and remaining-time comparison.
- `ruby_relay.rb:45–52,119–142,167–197`: Ruby uses `CLOCK_MONOTONIC` while consuming
  Python-origin start/work/disposition/outer endpoints, including the lower bound.
- Controller, sender, canary and Python relay import the common Python clock;
  query windows, cancellation checks, pipe waits, final publication, disposition
  and terminal acceptance all depend on that same domain.
- `contract.py:238–252` and the reconciler compare recorded entry timestamps
  against unchanged original endpoints. They must not gain tolerances or offset
  compensation. Bash is only the existing precharged exec trampoline: no clock
  sample or local deadline-enforcement claim may be added for it.

The local SDK `_time.h:156–181` declares `CLOCK_MONOTONIC=6`,
`CLOCK_MONOTONIC_RAW=4`, `CLOCK_UPTIME_RAW=8`, and `clock_gettime(clockid_t, ...)`.
Its actual8243-byte hash is
`a3dceadf2c95133018af363187829ca072d85a93d69f9682a2e4fb993902f28d` at
`/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk/usr/include/_time.h`.
Named local clock_gettime man2/man3 pages were unavailable; no manual-page pass
is claimed. Shared API/ID selection, not empirical offset calibration, is the fix.

Root cause: individually monotonic clocks were assumed to share an origin across
languages. Pure fixtures returned one interchangeable synthetic value regardless
of API/clock ID and therefore did not test this assumption.

## 2. Exact behavioral correction

Use **Darwin `clock_gettime(CLOCK_UPTIME_RAW)` (ID8) in both languages**. Every
Python producer/consumer uses the existing common `runtime.now`; every Ruby
consumer uses `InheritanceRelay.clock`. Neither may use `time.monotonic`, ID6,
wall time, an estimated offset, a fallback ID, or a renewed child timeout.

Both functions must fail closed on an unsupported platform, missing constant,
noninteger or unexpected ID, unavailable/failing clock API, non-float,
nonfinite or negative result. No native process/resource acquisition is allowed
after such a failed clock admission. Imports define functions/constants only;
they must not sample a clock or execute a helper route at import time.

This is an explicitly Darwin-only private helper, matching its pinned tools and
sandbox-exec design. It is not a cross-platform public API. Original numeric
budgets and all lower/upper-bound checks remain exact. New endpoints are minted
once from the shared clock in a **new** proof execution; old numeric endpoints
are not translated, adopted, merged or replayed. The current context/frame schema
can remain unchanged: its complete pinned script inventory already binds the
producer/consumer clock implementation. Record the exact clock descriptor in
the new controller baseline and require it in the new root execution grant.

The pure-driver wall budgets are separate, single-language scopes. Preserve
their original retained real measurement functions and60s Python/30s Ruby limits;
do not reinterpret those as inherited cross-language endpoints.

## 3. Files and immutable execution identity

Create only a new ignored `sandbox-inheritance-clock-correction-r1/` package.
Preserve the original96-file R3-R4 package, native/pure results, diagnostic,
failed scratch and all earlier snapshots unchanged. Begin from the exact nine
runtime files and both test drivers in the frozen R3-R4 package; verify their
original bindings before copying. This is not source-worktree adoption.

Changes:

1. `contract.py`: fixed clock descriptor and literal correction-plan/evidence
   bindings, while retaining the original governing plan and every route/budget.
2. `runtime.py`: guarded common Darwin clock implementation and necessary imports.
3. `ruby_relay.rb`: matching guarded clock and **one fixed BASE path rebinding**.
4. `bash_relay.sh`: **only its fixed Ruby target path rebinding**; no new shell
   logic, process, timing claim, command construction or environment behavior.
5. `controller.py`: a new literal root approval location, exact correction-plan,
   failed-result and diagnostic-result bindings, descriptor requirement and
   baseline descriptor. Original source/selector/preservation barriers remain.
6. `test_pure.py`, `test_pure_ruby.rb`: clock-ID-sensitive regression coverage,
   narrow expectation/binding changes and necessary pre-load safety guards.
7. New README, before/final bindings, exact diff, coverage, references, safety and
   verification records. `canary.py`, `sender.py`, `python_relay.py` and
   `reconcile.py` should remain byte-identical unless a demonstrated caller
   dependency requires revising this plan before implementation proceeds.

The new root grant lives only at
`sandbox-inheritance-clock-correction-execution-approval-r1/DECISION.json`.
It must explicitly identify this correction and fresh code/clock/matrix/reference
bindings. The old consumed grant must not authorize the new package. The new
native output remains the private literal `execution-r1/` **under the new BASE**,
whose Ruby/Bash/Python paths must agree completely.

Retain all46 original reference bindings. Add only the new plan/plan-review,
original failed result/outer/independent review and scalar diagnostic result/raw/
outer/independent review needed to explain this correction. Stay within the
existing128-reference/2MiB-member rules; do not relax any selector binding or
follow arbitrary recorded paths. The source152/root-user174/index2 identities
and QA-006 tree stay unchanged. Concurrent ignored verifier changes are separate
and do not authorize source/user drift.

## 4. Security, failure, retries and recovery

No product code, consumer configuration, schemas, Store credentials or Store state
changes. No application build, Store request, Git dispatch, credential access,
network probe, FFI, new signal/query route or arbitrary interpreter selection.
Preserve all native ownership, control-liveness, sandbox, output, immutable
selector, terminal-commit and provenance checks.

Unsupported clock conditions stop, rather than making validation permissive.
Partial capture/clock/entry failure stops subsequent routes, retains raw evidence
and the actual outer failure, and disposes only still-owned resources under the
original limits. Historical finality/unknown flags are not rewritten. There is
no diagnostic repeat, implicit retry, namespace search/adoption, deadline reset,
scratch cleanup, original quota reset or borrowed historical pass.

The old native1/1, Ruby2/2 and scalar diagnostic1/1 are permanently consumed.
Python3/4 remains the original count until its conditional fourth invocation is
separately admitted. Any **additional** Ruby/native authority described below
must be explicitly reviewed and root-admitted for the corrected code. It is not
permission obtained by relabeling the old attempt.

## 5. Required regression tests

Preserve every original93 Python method and40 Ruby case obligation and all
existing dangerous control/EOF/commit/identity/timeout/selector assertions. Freeze
the exact complete new test inventory and report real execution counts; never
substitute a reduced clock-only suite for the existing guards.

Add cases that exercise the real clock/entry functions, replacing only OS leaves:

- Return deliberately incompatible values for ID6 versus ID8. Assert the actual
  corrected getters call ID8, never fall back, and their values pass real original
  entry validation. Reintroducing either legacy getter must fail that regression.
- Drive complete Ruby constructor/entry admission and Python capable entry under
  the existing fictional native world; do not stub the admission predicate or
  common clock. A getter returning one value for every ID is insufficient.
- Reject absent/wrong-type/wrong-value IDs, unsupported platform, API exceptions,
  integer/bool/nonfinite/negative samples, with zero new native acquisitions and
  no alternate getter call. Clock errors must remain visible, not success labels.
- Check exact lower bound and equality-at-work/outer boundaries, original
  disposition/query cutoffs, cancellation/control failure, and no renewed timeout.
- Verify late Ruby and multihop entries still reject; Bash retains its explicit
  no-local-clock claim. Full matrix and native budget constants remain identical.
- Verify new baseline/grant descriptor and exact correction/evidence identities;
  old, missing, mismatched or substituted grants cannot reach acquisition.
- Inspect the entire changed test/loaded-helper pair and transitive definitions.
  Python must veto the new clock_gettime boundary before loading helpers, allowing
  it only through case-local fake leaves. Ruby already vetoes clock_gettime;
  preserve that before-load guard and the no-native/native-attempt ledger.

Preserve independent original pure-driver measurement and output functions.
No fixture may silently exempt an arbitrary native call. New failed/successful
test results must include exact code bindings and genuine outer completion.

## 6. Proposed finite verification sequence (separate live admission required)

1. Static full diff/AST/caller/binding checks; a distinct agent reviews the actual
   complete code and both safety-wrapped test paths, including new clock leaves.
2. Use **only original conditional Python004**, justified by this independently
   demonstrated necessary correction: full old/new tests,60s cooperative scope,
   2MiB aggregate output, original no-native guards. No fifth Python run follows.
3. Propose **one explicitly additional Ruby clock-correction pure invocation**,
   not reuse/reset of exhausted Ruby002: complete old/new exact pair,30s scope,
   2MiB output, pinned Ruby3.3.12/disable-gems and all original denials. Cumulative
   Ruby runs would be3; historical2/2 stays recorded. No further run follows.
4. Reconcile actual raw/outer/source preservation, then distinct final complete
   implementation acceptance. Pure passes are not native feasibility proof.
5. Propose **one explicitly additional corrected native feasibility invocation**
   in the fresh package, after separate root approval. Cumulative inheritance
   invocations would be2, with original1/1 failure retained. Run all11 original
   rows, not only Ruby or the seven previously unexecuted rows. Keep44/57 route
   acquisitions/execs, at most6 observers (50/63), hard64/96;30s work+10s disposal,
   180s total,64KiB streams,4KiB ordinary chunks,512-byte terminal commit,
   2MiB capture and8MiB runtime evidence. No new route/process/query allowance.
6. Root separately rechecks original source/user/index/tool/reference/startup,
   exact new independent reviews, absent namespaces and original counts before
   dispatch. Record genuine raw/outer results and all owned-resource disposition;
   independently reconcile them. Failure is retained with no automatic retry.

The additional invocation proposals are explicit requests for new bounded
correction authority, not a reinterpretation of old quotas or live permission
from this plan. If review/admission rejects them, execution remains blocked; do
not claim acceptance from historical40/93 cases or three narrow native passes.

## 7. Regression risks, documentation and remaining work

Watch for a single unchanged cross-language getter, shared-deadline reset,
startup guard side effects, unit fixtures masking ID selection, altered lifecycle
boundaries, stale BASE/approval paths, changed script/reference selectors, lost
negative/loss routes, accidental native execution during pure preparation and
misreporting old failures as repaired historical evidence.

Update only ignored helper/progress/coverage documents. Explain explicit Darwin
clock selection, no empirical offset conversion, new versus historical proof
identity, actual test outcomes and remaining limitations. No public consumer
documentation/API behavior changes are justified by this helper-only fix.

Stop/join only owned workers; remove only proven disposable owned outputs after
preserving evidence. Required failed scratch, snapshots, toolchains, user-owned
AGENTS.md and pending product changes remain untouched.

QA-006 still needs complete source/native/wheel/hosted gates and protected delivery.
QA-007, QA-003, QA-004, QA-005, MRK-008 and MRK-009 follow. Then perform the **new
whole-repository audit from scratch**, remediate further confirmed blockers,
justify READY, and produce the separate comprehensive feature report. This
supporting plan cannot change the9/16 (56.25%) delivery count or NOT READY verdict.
