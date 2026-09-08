# QA-006 implementation plan — synchronized real Ruby process fixtures

## Root cause, scope and delivery isolation

Read FINDING.md and REANALYSIS.md plus the independently preserved G26-IR-01 report.
Late fixture PID publication is being treated as implicit readiness under the same
short clock used to test runtime timeout behavior. The correction must prove the
intended boundary, not increase production timeouts or skip slow hosts.

Implement in a new main-based worktree/branch at2beb373. Preserve the original
worktree's complete173-file QA-003 tree and untracked user AGENTS.md. Expected files:

1. `tests/workflow/test_ios_upload_validation.rb`.
2. `tests/workflow/test_android_upload_validation.rb`.
3. A shared static `tests/workflow/upload_process_fixture.rb` helper/driver.
4. `.github/workflows/ci.yml`: run both adapter suites on the required macOS job
   with the same pinned Ruby3.3.12/Bundler/lockfile setup already used on Linux.
5. `tests/workflow/test_native_profile_ci.py`: require the non-optional macOS
   Ruby setup/test steps and preserve failed/skipped/cancelled aggregate behavior.

No implementation file, product schema/template, dependency pin or package metadata
changes. Fixture documentation is in the helper/suite comments; no public release
behavior changes to document. Any runtime defect discovered requires its own
evidence/plan rather than silently expanding this test correction.

## Fixture architecture and exact behavioral changes

- Replace both inherited-pipe tests' independently generated shebang/fork/PID-read
  logic with one static fixture, launched through the selected `RbConfig.ruby`.
  Invoke the full real platform current! boundary. A narrow test-only Open3 seam
  must verify the COMPLETE expected synthetic argv and forward actual environment,
  cwd, unsetenv_others, private pgroup, pipe and waiter semantics. It remaps only
  that exact fixture executable; arbitrary launches fail. Keep existing independent
  real no-shell/scrubber/bootstrap/output-bound tests intact.
- Isolate instrumentation in a separate Ruby driver so Open3/IO/clock/constant
  test seams cannot affect another test or background worker. The test runner
  retains and joins its actual driver handle. All inputs are fictional paths and
  hashes under one mode0700 temporary case directory.
- Capture the actual native waiter/PID/PGID before any readiness read. Install
  fixture fallback before assertions. Record progress atomically/boundedly so an
  unready fixture yields a named readiness failure, not an unconditional missing
  file read. Validate each observed child belongs to that exact live private group.
- Use independent fixture control/readiness channels (private pipes or bounded
  atomic records) to establish a real running descendant, reaped leader, and
  inherited stdout/stderr. Require at least one FORWARDED REAL IO.select wait
  with those preconditions and no EOF. Never fabricate events or waiter status.
- Scope a controlled clock ONLY to NativeUploadValidation inside the isolated
  driver. Keep its test deadline unexpired until the required real pipe wait has
  been observed, then advance past the same configured test interval. The outer
  driver/readiness watchdog, sleeps, process inspection, IO.select and all
  cleanup clocks remain real. This avoids charging arbitrary fixture startup or
  post-fork publication time to the boundary test. Preserve the existing separate
  real-time timeout test; additionally assert real elapsed-time enforcement with
  a ready leader under the new bounded harness if useful.
- The descendant holds its inherited pipes until production KILL or an explicit
  test fallback. Give it a private control-read descriptor whose sole writer is
  held by the driver; EOF is a fallback exit request, including driver death.
  Do not pass writer authority into the fixture. A self-limit longer than the
  driver's entire watchdog is a last resort, never part of the passing oracle.
- Before ANY fallback, assert the expected timeout, actual leader reaping,
  positively observed descendant and its non-running state (absence or zombie),
  required pipe waits, and no watchdog intervention. Keep the control writer open
  until these observations are recorded. A previously missing child or later EOF
  fallback cannot manufacture a pass.
- On failure, close the exact control writer to stop fixture descendants; do not
  blindly signal a remembered/reaped child PID. Own driver/native handles from
  real spawn. Bounded failure cleanup may signal only positively owned live groups;
  never signal process-name matches, historical PIDs or other tasks. Preserve
  primary failure and report any cleanup failure, join all waiters/threads/drivers,
  close all pipes and remove only the exact completed case directory.

## Required scenarios and adversarial oracles

On BOTH full Android and iOS adapters:

1. A normal reaped-leader/live-descendant/real-no-EOF wait, followed by production
   timeout and child death before fallback.
2. Deliberate fixture startup delay longer than the logical test deadline; still
   prove the SAME actual descendant boundary, not generic timeout success.
3. Deliberate parent PID-publication delay after a live child exists; late original
   marker publication must not become the cleanup authority or readiness oracle.
4. Readiness never occurs before the independent bound, including before fixture
   PID publication; report the distinct failure and prove early-handle/EOF cleanup.
5. Original real elapsed-time leader deadline, output overflow, stderr redaction,
   no-authority environment, fixed argv and installed/bootstrap contracts rerun.
6. Isolated helper mutations: leader-only KILL must leave an observed live child
   and fail BEFORE fallback; disabled/very-long deadline must trigger an independent
   watchdog/failure within a bounded time. Mutation copies are private, never
   written to production paths or selected by application input. Guard exact
   mutation anchors and record which production source hash was copied.
7. Force fixture assertion/readiness failures and outer driver termination in a
   controlled case; confirm no still-running owned descendant, driver or watchdog.
   EOF/control shutdown and self-limits cannot be counted as runtime containment.

Tests must reject missing readiness, unexpected child/group identity, loss of a
real pipe wait, masked watchdog activity and incomplete cleanup. Failed diagnostic
output should include only synthetic phase/handle/observation data so future
failures are investigable even after temporary-directory removal.

## Compatibility, security, retry and recovery

POSIX Linux/macOS, existing Ruby3.3 and Python3.11+ test toolchains only; no new
dependencies. Production timeout remains3600s. Fixed interpreter/module selection,
Store credential exclusion, group containment, output bounds, artifact signing,
provenance and manual-publication boundaries are unchanged. Synthetic fixture
control descriptors are test-only and never added to production runtime options.

No Store mutation or live credential/keychain/native signing access. Cancellation
of the test controller must close its private control descriptors and safely stop
owned test processes. Every retry gets fresh directories/handles; never reuse
markers or relabel a prior failed final run. Keep original failure evidence and
the separate entire historical EEXIST installation unchanged.

## Regression risks and checks

Clock/IO stubbing could prove only mocks: require full current!, real pipes/waits,
real group signals and pre-fallback observed process state, plus separate real-time
coverage. Broad executable remapping could hide argv drift: exact argv/options
assertions plus untouched real argv/scrubber tests. Cleanup could hide a regression:
write/assert observations before fallback and mutation-test that ordering. PID reuse
could target unrelated processes: prefer lifetime-bound EOF cleanup, use captured
handles and do not signal dead/reaped PID records. Watchdogs could leak or mask
failure: explicit independent bounds, joined workers and intervention-fails-oracle.
CI changes could weaken required status: no permissive conditions or job-gate
removal, and execute aggregate behavior across success/failure/cancel/skip cases.

## Review, full verification and protected delivery

Obtain separate independent PLAN approval before editing first-party files. After
implementation, obtain a DISTINCT agent's actual-diff/behavior review, including
failure/mutation cases. Resolve every supported objection before final acceptance.

Freeze exact separate-worktree commit/tree/file modes/status and toolchain. Run a
new complete baseline-applicable suite from zero: editable[test] install; complete
Python/workflow discovery with required Ruby contracts; all native profile/platform
resource tests; every Ruby support/Store-lane/upload/native/YAML/WIF test; bundle
install/check; Fastlane --validate; actionlint; dependency pins/lockfile and runtime
dependency checks; isolated wheel installation/resources/native-profile smoke;
JDK signature policy; new regressions/mutations; git diff --check and freeze
reconciliation. Do not transplant QA-003-only local-signing matrix tests into this
pre-QA-003 worktree; their absence is explicit applicability, not a skipped gate.
They remain mandatory in QA-003's later complete58-gate run/all16 source-wheel pairs.

Bind all results to this issue's frozen tree; stop acceptance on any failure and
preserve evidence. No concurrent mutation of shared venv/Bundler/build/egg-info;
prefer an isolated test venv and exclusive own build/smoke destinations. Stop/join
only owned workers and remove only exact disposable outputs after preserving proof.

Commit only this issue after approval and complete verified gates; push its branch,
use the protected PR/strict required test status for main (no bypass/force push),
then verify actual main CI. Afterwards reconcile QA-003's preserved55-file diff onto
updated main, independently review any integration deltas, and prepare a NEW full
frozen QA-003 run. Neither final-r4 nor earlier failed namespaces may be reused.
Continue remaining confirmed findings and the mandatory fresh whole-repository
production audit/feature report; QA-006 delivery alone is not READY.
