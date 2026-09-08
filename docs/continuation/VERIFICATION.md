# Verification ledger: what passed, failed, or was not run

## Status interpretation

This is a sanitized historical ledger, **not raw authenticated execution evidence**.
Historical passes apply only to their named source/tool/environment scope. Raw
local proof remains private and is not available merely by cloning this branch.
Never substitute checksums, syntax parsing, a review, a proposed command, or a
main CI run for a missing test on the pending patch.

## Important retained outcomes

| Check/scope | Actual recorded outcome | What it does not prove |
| --- | --- | --- |
| MRK-001–007, QA-001/002 deliveries | Previously reviewed, verified, protected-main delivery; commit IDs in FINDINGS.md | Fresh full-repository readiness or later compositions |
| QA-002 main CI 33996725809 | Freshly observed completed/success for `2beb373…` during handoff | Passing CI for either pending patch or this handoff branch |
| QA-003 final-r4 on `387856e…` | **25 PASS / 1 FAIL / 32 unexecuted**, controller exit 1 | Complete 58-gate verification |
| QA-003 gate 26 | Ruby iOS upload validation: 13 methods, 86 assertions, one ENOENT error | Exact historical startup-delay cause; original temp data had been removed |
| Older QA-003 wheel attempt | EEXIST retained, cause unresolved | A waived installation defect or a later pass |
| Older process observation | Original raw process output missing; cause UNKNOWN | New process-table facts or cleanup authority |
| QA-006 R6 development | 4 tests / 1,821 assertions; 28/29 new proof cases; missing entered substitution case | Full R6 native/adapter suite |
| QA-006 R6 independent safe scope | 5 methods / 1,946 assertions, 33 instrumented cases, zero forwarded signals | Complete implementation acceptance; entered and mutant cases remained unexecuted |
| Primary sandbox experiment | 32 rows, actual outer exit 0, **PASS_RECORDED_PRIMARY_ONLY** | Inheritance feasibility or general full-suite isolation; authorization consumed |
| Original verifier experiment | **218 PASS / 1 FAIL**, actual exit 1 | Acceptance of old or currently edited verifier |
| Original pure inheritance helper tests | 93 Python / 40 Ruby historical passes, actual outer exit 0 | Corrected-clock tests; existing fake clocks did not expose the cross-language origin error |
| Original native inheritance | **3 narrow passes / 1 Ruby entry-window failure / 7 unexecuted**, outer exit 1 | Eleven-route feasibility; no replay or retry permission follows |
| Finite original custody reconciliation | 13 known acquired processes have actual-parent waits, closed streams and EOF | Clearing original unknownResources flag, deleting failed scratch, or asserting global process absence |
| Scalar clock diagnostic | Once, Python-before/Ruby/Python-after, outer exit 0; 36 samples, three original 5s scopes; mismatch confirmed | Missing historical Ruby sample or retrospective proof of its exact failure cause |
| Scalar diagnostic scope cleanup | Only its new empty HOME/TMP directories removed by exact ownership checks | Cleanup of old failed experiment state |
| Optional archival experiment | Failed on ambiguous xattrs; original failure retained | A usable archive, retry/deletion/retirement authority, or recovered disk space |
| Source-cache relocation | Accepted/consumed scope; original caches retained, zero deletion | Permission to remove shared/required caches |
| Paused verifier R3 draft | AST syntax only for two changed files; **no helper/installer/native/behavior tests** | Functional correctness or independent implementation approval |
| Clock correction | Independent **plan** approval only; implementation not begun | A fixed getter or any corrected-code verification |

The one-shot clock admission initially failed **before dispatch/write** because
a generic 2MiB read cap was smaller than the pinned Python binary. The named-tool
read limit was corrected to its original 32MiB allowance; diagnostic time/output
limits did not increase. Separately, a paused-author static checkpoint utility
first compared access times and stopped before publication; its comparator was
corrected. These are retained utility failures, not passing product tests.

## What was actually checked for this handoff

- Read repository instructions/security and relevant readiness/provenance guidance.
- Independently review the export plan, including source/plan/fixture/oracle closure.
- Safely pause the author; retain its incomplete source and complete TODO list.
- Read and hash all 173 QA-003 and 152 QA-006 product files against the frozen
  selectors. Original user AGENTS and both index hashes matched. No native Git
  ran in the original source worktrees.
- Use a fresh owned public clone; observe exact main SHA/tree, protected branch
  settings, repository visibility, and the specific completed main CI run.
- Produce separate patches from copied source and reconstruct exact expected
  Git trees; both source diffs pass `git diff --check`.
- Regenerate whitespace-safe zero-context transport, then independently exercise
  the documented application flow in two fresh native Git worktrees. Both complete
  150-file baselines matched; resulting trees and every 173/152 file hash/mode
  matched exactly. An earlier manual-index proof setup refused `apply --check`
  with index/worktree mismatch before applying any patch; that attempt is a failed
  transfer check, not a source-test failure or a successful application.
- Export only allowlisted readable references with original/export hash distinction.
  Require distinct final handoff-content review, exact staged scope, static
  integrity/secret/path checks, clean diff, remote ref and clone/readback before
  reporting publication success.

The first staged content check reported extra blank lines at EOF in 13 historical
reference copies. Those export-only endings were normalized and export hashes
regenerated before final review; original records and product patches were untouched.
That initial diagnostic was not counted as a passing `git diff --check`.

**Not executed for this handoff:** package installation/build, Python/Ruby/native
product suites, Store rehearsals, actionlint, Fastlane, Bundler or runtime-dependency
gates. This is a documentation/snapshot checkpoint with unchanged active product
files, not an issue-verification exception. The push trigger is main-only; a handoff
branch with no PR/dispatch is not expected to run CI. No CI absence becomes PASS.

## Complete product gates still required when resuming

Inspect `.github/workflows/ci.yml` and actual tests before running them. Use an
isolated environment proven safe for the relevant process/cancellation cases;
do not run all known unsafe native paths on a shared machine just because these
commands appear in a guide. Do not execute the inert exported verifier scripts.

Core documented commands (after environment and execution-plan admission):

```bash
python3 -m pip install -e '.[test]'
python3 -m unittest discover -s tests -v
bundle install
bundle check
ruby -I. tests/workflow/test_fastlane_support.rb
ruby tests/workflow/test_workflow_yaml.rb
bundle exec ruby tests/workflow/test_supply_wif.rb
bundle exec ruby fastlane/run_lane.rb --validate
python3 -m pip wheel --no-deps --wheel-dir dist .
python3 -m pip check
git diff --check
```

Also run, with actual assertions and native prerequisites rather than silent skips:

- All 13 Ruby files: Fastlane support; native upload capture; Play store and lanes;
  Apple store, lanes, production, production lane and asset upload; iOS/Android
  upload validation; workflow YAML; Supply/WIF. Use the pinned bundle for tests
  which require Fastlane. Preserve both complete adapters and mutation controls.
- Native profile/signing/plist/Mach-O/containment/default-signal gates, including
  `python3 -I tests/workflow/run_native_profile_checks.py` on supported macOS.
- Full workflow contracts and synchronized consumer callers; dependency/action
  SHA validity/pinning, Bundler lock consistency, JDK 21 signature policy.
- Pinned actionlint across reusable and caller workflows. Preserve only the
  existing narrow GitHub context-property compatibility exception, if still
  required by the actual version; do not add broad lint suppressions.
- Build the wheel, install it in a fresh venv, run smoke checks **outside the
  repository** without source-path imports, check CLI entry/resources/templates/
  Fastlane/schemas/profile roots, installed-wheel native/regression cases and no
  runtime dependencies in metadata/import behavior. An editable install is not this.
- All issue-specific malformed/replay/forgery/failure/recovery/concurrency cases
  and protected source/provenance/Store mocks. Never perform live public mutation.
- After QA-003 applies, the whole local-signing native-active/crash/recovery matrix,
  source plus installed wheel and every scenario/partition. A QA-006-only gate list
  must deliberately reject that expanded tree rather than silently omit its matrix.
- Source freeze before/after, explicit complete test-file inventory, independent
  result parsing, scoped worker observations, safe generated-output cleanup, and
  final source/user preservation. Report actual process exits, not receipt shape.
- Required hosted Linux/macOS PR jobs, protected main merge and actual main CI.

Pinned recorded tools: Python 3.11.16 on the original host (package requires
3.11+), Ruby 3.3.12, Bundler 4.0.16, actionlint 1.7.12, applicable JDK 21.
Confirm repository pins before installation. No Python runtime dependencies are
declared; test extras and setuptools build requirements are separate. The active
project build requirement is setuptools 80.9.0; the verifier seed's 79.0.1 is not
a substitute for that installation gate.

The exact old QA-006 45-gate order is readable in
`drafts/verifier/baseline/gate_list.py.txt`; old QA-003 final orchestration is in
`drafts/qa003-verification/`. These are requirement references only. Re-establish
safe current tools, roots, source identity and output ownership before execution.

## Evidence and resource discipline

For every run record exact source tree, argv, environment assumptions, tool versions,
actual outer and inner status, timeouts, assertion counts, skipped/unexecuted cases,
owned-resource custody and limitations. Do not “resume” a consumed result directory
or overwrite failed logs. Source hashes establish integrity; who ran a test and
under what trusted environment is a separate authenticity question.

Join only task-owned workers; do not issue broad `pkill` or delete caches/venvs
just to meet a space target. No old PID, inode, path, or exported ownership record
can authorize cleanup on a new host. Keep required source/evidence; delete only
fresh disposable files whose ownership and irrelevance are established. No Gradle,
application build or Store operation was started by this handoff task.
