# QA-006 R3 — correct the deadline oracle and atomic child ownership

**PROPOSED; independent approval required before implementation.** This amends
PLAN-R2.md, not the finding or its tests-only scope. All other R2 requirements
remain mandatory. Current proposed tree bd15428c3aba37a59ca65f6ede127ba4d2cba6a5
is rejected, not accepted because its development tests passed.

## Reanalysis and evidence

Independently re-read FINDING.md, R2 plan/approval, both complete upload suites,
both full platform adapters, NativeUploadValidation.capture, shared fixture,
CI diff and packaging. Only the test fixture is defective; no production change
is justified by either implementation-review objection.

The distinct reviewer recorded REQUEST_CHANGES in implementation-review-r2/:

- **QA006-IR-01**, helper lines377–381,411–412: captureSeconds wraps the complete
  native block, including its ensure/KILL/join. A350ms delay in cleanup lets the
  immediate-deadline mutant satisfy the positive timeout lower bound. Root
  independently reproduced this through BOTH full adapters: incorrect immediate
  deadlines produced kind=pass at .352/.356s, alongside real controls at .560/.558s.
- **QA006-IR-02**, helper lines70–85,175–180,224–227: actual waitpid reap and local
  status publication are separate cancellable operations. A real asynchronous
  Thread#raise in that window leads to KILL(-pid) after actual reap. capture_command
  also replaces Interrupt with ECHILD. Review probes vetoed forwarding stale signals;
  root independently reproduced both original synchronous boundary probes safely.
  Reviewer additionally proved the real asynchronous variant on both helpers.

Root evidence is reanalysis-r3/RESULTS.json, ROOT-REPRODUCTION.log/.exit and
CLEANUP.json. All root/reviewer processes and raisers were joined, native death
was observed, and only their exact synthetic scratch was removed. Failed R2
logs/results remain unchanged. No final verification gate has run for QA-006.

## Exact change scope

R3 changes only tests/workflow/upload_process_fixture.rb within the existing
five-path QA-006 diff. A second small test-only helper is permissible only if
needed to keep isolated cancellation probes readable; it must not enter wheel
resources or runtime imports. Prefer keeping the static helper's probe command
and shared contracts together. No adapter/runtime, Store, schema, credential,
pin, package metadata or public documentation changes. Update fixture comments
and retained remediation evidence to describe actual rather than intended proof.

## 1. Separate deadline decisions from cleanup

- Keep the real-mode module-local clock facade delegating every read to the REAL
  monotonic clock. Record its first and subsequent native read values, without
  altering values, global clocks, sleeps, readiness or watchdogs. The decision
  elapsed value is the last native timeout-check read minus the first native
  deadline-start read. It cannot include later KILL, waitpid, Open3 unwind or IO close.
- Independently observe the real forwarded IO.select on the exact capture pipes
  in ready-leader mode. Require a positive actual no-EOF wait, as well as the
  decision elapsed lower/upper bounds. An immediate mutant cannot pass solely
  through a scheduling gap between two clock instructions. If that boundary
  cannot be observed, fail explicitly; do not manufacture a wait or retry a pass.
- Keep complete captureSeconds as diagnostic data and an independent upper-bound
  check. Do not use it as proof of a positive deadline. Retain readiness, no-fallback,
  no-watchdog, leader reap and death assertions. The controlled orphan clock and
  real inherited-pipe wait remain separate from the real-clock deadline contract.
- Add bounded slow-cleanup modes for the real and immediate deadline cases. In
  the isolated native Process facade, delay only the forwarding of the actual
  KILL by DEADLINE*2; do not change runtime source for that delay. Record before/
  after cleanup timings. Both adapters must accept the correct deadline and reject
  the existing +0 mutant even when total elapsed now exceeds the old lower bound.
- Immediate-mutant assertions must not themselves assume a particular scheduler
  speed: require rejection and absence of a genuine positive deadline wait; report
  the pre-cleanup and total timing separately. Preserve the removed-deadline and
  leader-only mutations, real argv/environment/bootstrap tests and bounded capture.

## 2. Publish actual spawn/reap ownership atomically

- Replace duplicate loose pid/status locals with one small preallocated test-only
  direct-child owner. Construct it before Process.spawn can acquire a child. It
  owns the actual PID and observed status; no detached waiter or marker grants
  authority. Both capture_command and run must use this same owner.
- Use Ruby Thread.handle_interrupt(Exception => :never) around the finite
  spawn/PID publication and nonblocking waitpid/status publication operations.
  Publish ownership/status INSIDE the protected region, not in the caller after
  a helper returns. Restore immediate interruption for normal active waiting/work.
  Protect cleanup dispatch/entry and its bounded body with an outer deferred-
  interrupt scope; do not make the entire driver test uninterruptible.
- Before a stop/signal request, perform the owned nonblocking poll under the same
  protection. A reaped status disables signalling permanently. ECHILD without a
  published status is lost/unknown authority, never permission to signal; latch and
  report it. Preserve a primary cancellation instead of replacing it with ECHILD.
  Report cleanup uncertainty separately and retain unresolved scratch. This also
  protects against synchronous test-injected observation failures: async masking
  must not be falsely claimed to defer an ordinary synchronous raise.
- For a still-unreaped direct child, permit only the exact owned process or private
  group stop, then nonblocking polling to a real cleanup deadline; no unlimited
  waitpid. Handle an already-exited group (ESRCH) by reaping/observation, not by
  repeating a historical signal. No process-name or orphan numeric-PID kill.
- Preserve driver-loss EOF cleanup for every worker phase and existing before-
  fallback death proofs. Native marker PIDs authorize observation only. Cleanup
  of scratch is allowed only after actual owned-child join/native-death proof, or
  after proving that no child was acquired. Cleanup failure cannot return success.

## Required new regression tests

Execute through both existing adapter suites and the shared production callers:

1. Real deadline + bounded slow cleanup passes with positive actual pipe wait and
   pre-cleanup decision time; +0 mutant + identical delay fails the deadline oracle.
   Compare both timings and prove the native child died before harness fallback.
2. Isolated cancellation probe calls actual capture_command and actual run.
   Instrument only real Process.spawn/waitpid boundaries inside that probe, retain
   actual returned handles/status, and deliver Interrupt from a separate joined
   thread after real spawn/before publication and after real reap/before publication.
   Prove the requested boundary was hit. Assert the original Interrupt is preserved,
   every actual acquired child is joined, and no signal is requested after reap.
3. Record and veto ANY attempted stale PID/group signal in the adversarial probe
   before forwarding it. A veto is a test FAILURE, not proof of corrected cleanup.
   Keep all instrumentation isolated in a static child Ruby process, not suite globals.
4. Inject first cancellation at cleanup entry and a repeat during bounded cleanup;
   join all raisers and ensure protected cleanup completes without stale signals.
   Do not use hard SIGKILL as a substitute for catchable cancellation coverage.
5. Inject ECHILD/lost observation while an earlier status is unknown; assert no
   signal authority, non-success, original-error preservation and retained diagnostic.
   Use controlled already-reaped children so this probe cannot leak a real process.
6. Assert bounded stop behavior and no post-reap signalling on normal results,
   parser failures and existing observation timeouts. Re-run delayed/unready,
   driver SIGKILL/EOF, inherited pipes and all mutation cases on both platforms.

Regression probes must prove actual boundary entry, not merely assert a warning
or monkeypatch away the production capture. An injected cleanup delay is an oracle
test; it is not permitted to weaken bounds or change Store validation behavior.

## Compatibility, failures and security

Supported Ruby3.3/POSIX Linux/macOS only; no new dependencies. Blocking acquisition
uses existing explicit executables and private groups. All test inputs remain
fictional. Default/async cancellation is deferred only for ownership and bounded
cleanup; hard driver loss still uses lifetime-bound EOF, never stale PID recovery.
Failure evidence is retained, not counted as a passing production contract. No
Store build, evidence/provenance chain, upload selection, signing policy or unrelated
Store state is touched. The root QA-003 diff/user AGENTS remain preserved throughout.

## Acceptance and verification

Obtain independent R3 plan approval before any edit. Then implement the complete
amendment, run both full Ruby adapter suites/new probes and CI contracts, record
a new exact snapshot, and obtain the DISTINCT implementation reviewer's actual-
diff re-review. Re-run its adversarial probes on the corrected tree where applicable;
preserve old negative evidence and explain any instrumentation-only adjustment.

Only after actual implementation approval, freeze and execute the entire R2
baseline-applicable suite from zero: Python/unit/workflow/native checks; all Ruby
Store/support/upload/native/YAML/WIF tests; bundle install/check/Fastlane; actionlint;
pins/locks/runtime-dependency checks; actual isolated wheel/bootstrap/native checks;
JDK signature policy; diff and source/mode reconciliation. No partial-pass reuse.
The existing verification-final-r1 directory contains PREPARATION ONLY, not a
freeze, dispatch or passed gate. The original preparatory process exit was lost;
later Python3.11/isolated-prefix/pip smoke exited0 and is explicitly recorded.

After every task join only its owned workers and remove only exact completed
disposable outputs. Then scoped commit/protected main delivery and actual main CI.
QA-003 must be reconciled and freshly reverified afterward, including all58 gates
and all16 source/wheel pairs. Its separate historical EEXIST remains unexplained
and unwaived. All remaining findings, the fresh full audit/remediation and eventual
READY-gated comprehensive feature report remain required.

## R3-R1 — required independent plan-review refinements

This revision is PROPOSED pending re-review. It incorporates the reviewer's two
ownership corrections; all preceding scope/oracle/verification requirements remain.

1. Retain the **primary exception object** in a slot outside the outer
   Thread.handle_interrupt(Exception => :never) scope. Capture the first body
   exception inside that scope, perform bounded cleanup under deferral, and catch
   a queued exception delivered as the outer scope exits. A later Interrupt must
   not replace the original object/message. A cleanup error or later cancellation
   is reported separately; neither produces success or hides the initial failure.
   When there was no earlier failure, a pending cancellation remains observable
   only after protected cleanup completes. Repeated-cancellation tests must assert
   original object identity and message, not only the Interrupt class. Join every
   injector before test return so no queued test exception leaks to another case.
2. The preallocated child owner has explicit **unstarted, acquiring, live, reaped,
   unknown** states. Set acquiring before entering Process.spawn; publish the real
   PID/live state inside the same deferred-interrupt region. A synchronous exception
   during native acquisition or its result publication leaves unknown, even if
   the stored PID is nil: lack of a published handle does not prove no child exists.
   Unknown state never authorizes signals, cleanup success or deletion of scratch.
   Only unstarted proves no acquisition was attempted; reaped requires an actual
   published waitpid result. Successful reap/status publication is equally protected;
   any synchronous ambiguous handoff fault or ECHILD without status latches unknown
   and permanently revokes signal authority. Already-published reaped state is terminal.
3. Test normal unstarted/live/reaped transitions, true asynchronous spawn/reap
   handoff cancellation, and synchronous unknown-handoff/ECHILD separately. A
   synchronous raise is NOT evidence about Thread.handle_interrupt's async deferral.
   Unknown-state tests record and veto unsafe signal requests, require preservation
   and non-success, and retain the primary error. If a probe has independently
   captured the true still-unreaped direct child before deliberately withholding
   publication, its bounded emergency stop uses that independently owned handle
   and is reported as probe fallback, never as a successful fixture cleanup oracle.
   Preserve failure diagnostics first and prove all actual workers stopped before
   removing ONLY the probe's completed exact disposable root.

## R3-R2 — real OS signal deferral, not only Thread#raise

PROPOSED pending review. The reviewer's stdlib experiment proves that Ruby3.3.12
**default SIGINT bypasses Thread.handle_interrupt(:never)**. This is not covered
by the earlier Thread#raise probes. Add the following narrow test-only signal
boundary; production/native capture remains unchanged.

- A main-thread-only, reentrant cancellation scope is entered BEFORE any temporary
  directory/file/native child acquisition in capture_command/run. Nested fixture
  calls reuse that scope. Concurrent use from other Ruby threads is rejected before
  acquiring anything; this is not a general process-global signal framework.
- Save the actual original INT/TERM dispositions and install short scoped handlers
  for supported DEFAULT dispositions. These handlers use **Thread.main.raise** to
  enqueue Interrupt or SignalException, never Kernel.raise. Queued delivery respects
  the finite ownership/cleanup Thread.handle_interrupt(:never) regions; normal
  active waits use :immediate. Root's self-only SIGINT AND SIGTERM probes prove
  protected progress/handler restoration precedes queued delivery; see
  reanalysis-r3/QUEUED-SIGNALS.json and queued-signal-semantics.rb. Do not assume this
  solely from the Ruby documentation or a Thread#raise-only test.
- Preserve IGNORE without converting ignored signals into cancellation. During
  handler installation, before the previous policy has been published, record
  bounded pending signal flags and service them only after policy is known. Discard
  pending ignored events, enqueue pending default events. Never allocate a child
  until both policies are established and pending cancellation can be serviced.
- Reject unsupported inherited custom handlers before resource acquisition and
  restore the EXACT prior handlers, including partial installation rollback. Do
  not execute arbitrary saved handlers while ownership is inconsistent. If a real
  signal was deferred while discovering a custom policy, restore first and replay
  that pending signal to this same isolated Ruby process under the original policy;
  no owned resource exists then. Coalesce repeats like ordinary POSIX signal delivery.
- Keep the primary exception slot outside the entire protected scope, including
  trap installation/restoration. Restore original dispositions only AFTER all child,
  file and case-root cleanup or explicit unknown-state preservation has finished.
  Clear the scope registry before restoring external handlers, when no owned work
  remains, and catch any deferred exit exception without replacing the first one.
  When there was no earlier error, a deferred signal is raised after cleanup, never
  converted to success. Custom-handler rejection cannot leave an installed handler.
- Scope cleanup depth prevents a nested capture_command used for process-state
  observation from reopening :immediate while an outer run cleanup is protected.
  This matters for repeat signals/Thread#raise during native-death proof. Ownership
  critical sections remain finite; cleanup observation/stops retain real deadlines.
- Test-only scope precondition: fixture calls execute on the main Ruby thread,
  with DEFAULT or IGNORE INT/TERM handlers (or an already active same-fixture scope).
  No simultaneous third-party signal-handler mutation is supported. If a changed
  handler is encountered during restoration, preserve the observed external handler,
  report a conflict and fail; do not silently install a stale saved policy. This
  restriction is fixture-specific, not a new toolkit/consumer CLI limitation.

Additional mandatory regressions in isolated Ruby probe processes:

1. Actual Process.kill(INT/TERM, Process.pid) at native spawn/PID publication,
   waitpid/status publication, first cleanup entry and repeated/nested cleanup.
   Require the targeted boundary, correct signal exception, actual joined children,
   and ZERO stale signal requests. Native child signals still forward for real;
   intentionally stale requests are vetoed and fail the test.
2. Repeated OS/Thread cancellation preserves the first exception object/message;
   a first signal during cleanup is not delivered until cleanup completes. Exercise
   main helpers, not only the coordinator class.
3. Verify exact DEFAULT/IGNORE/custom handler restoration on success, cancellation,
   partial installation failure and unknown acquisition; a custom handler rejects
   before any Process.spawn. Assert ignored signals remain ignored. Exercise
   changed-handler conflict without overwriting that new handler silently.
4. Preserve the existing hard driver-death EOF tests: catchable-signal coordination
   does not pretend SIGKILL/power loss can execute cleanup. All probes remain
   bounded, credential-free and self/owned-process-only, with joined injector threads.

## R3-R3 — ordered restoration and transition injections

PROPOSED pending final plan recheck. This closes the reviewer's transition-order
requirement without altering the tests-only scope or the preceding invariants.

On the supported DEFAULT/IGNORE path, restore **TERM first** while :never still
protects its deferred-compatible delivery, publish inactive/cleanup-complete scope
bookkeeping and clear the reentrant registry, then restore **INT last**. No resource
cleanup or necessary registry/trap operation may remain after default INT is restored:
its next delivery may be synchronous. The external primary slot catches that final
exception too. Do not publish an unobserved restoration as successful merely because
it was attempted. Actual traps are checked independently by the regression probes.

Install before any resource acquisition under :never, buffer identities until old
policies are known, and retain partial-installation rollback. Unsupported custom
policies are rejected with no acquisition or active registry publication; restore
all already-changed policies before any pending custom-signal replay. During
restoration failures keep attempts for remaining installed traps and report conflict,
never leave cleanup/ownership dependent on a later ordinary application statement.

Add actual self-SIGINT/self-SIGTERM injections at trap installation before/after old
policy publication and ordered TERM/INT restoration, as well as the already required
spawn/reap/cleanup boundaries. Include default, ignored and custom-rejection controls,
check that all expected traps/registry are restored/inactive, and distinguish a
rejected signal-policy conflict from passing normal cancellation/cleanup behavior.
