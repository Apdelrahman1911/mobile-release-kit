# QA-006 R5-R2 — remove stale signal authority from the required native sibling test

**REVISED PROPOSAL; independent R5-R2 plan approval required before first-party edits.** This
explicitly extends QA-006 from six to SEVEN first-party paths. It is the related
fixture-ownership omission QA006-IR-05, not an unrelated product finding. Existing
IR01–04 are independently closed on R4; its six-path acceptance does not authorize
final dispatch while this required sibling remains unsafe. Count stays9/15.

## Reanalysis and root cause

Read original FINDING.md, approved R4-R2, actual native upload runtime, all fixture
owners/callers, both adapter suites, the standalone native suite and both CI jobs.
R4 tree76ee6d092cd256da0fb6228792dff544b68c7aaf is unchanged from its snapshot. In
`tests/workflow/test_native_upload_validation.rb:57–64`, a saved PID is used for
unconditional group KILL after the actual Open3 waiter has joined/reaped. The
three normal cases always reach that stale request. Its watchdog at28–34 also
uses an asynchronously reaped waiter check before a later group signal, leaving
a race; merely adding waiter.alive? to final ensure is not a safe correction.

Independent SIBLING-NATIVE-CLEANUP-FINDING.md and root's byte-identical safe replay
in reanalysis-r5/ show three post-reap requests. Each was vetoed before syscall;
three original production live-child KILLs forwarded and all three workers joined.
No actual PID reuse, collateral kill or Store mutation was demonstrated. Existing
records mention this suite only as a passed ordinary check, not an earlier finding.
The bug is test cleanup authority, not proof of a new runtime upload authorization
bypass. Do not run this unmodified sibling as a final gate until corrected.

## Scope and exact behavior

Retain every approved R4 guarantee and the complete existing adapter tests. Change:

1. `tests/workflow/test_native_upload_validation.rb` (the one additional path):
   replace its inline sleep/PID watchdog/ensure with the common isolated fixture.
   Preserve the actual first-stdin.close injections for Interrupt, SystemExit(23),
   and IOError; exact original object/message for cancellation/SystemExit and
   generic/redacted ContractError for IOError remain mandatory.
2. `tests/workflow/upload_process_fixture.rb`: add fixed native-setup modes and a
   static native-setup driver using the existing parent lifetime/OwnedChild and
   read-only native death proof. Reuse the static EOF-controlled worker as a
   live leader (no fork for this scenario). Dispatch these modes before platform
   adapter logic; they test the shared NativeUploadValidation core, not an app.
3. `.github/workflows/ci.yml` and `tests/workflow/test_native_profile_ci.py`: add
   this shared native suite to the mandatory macOS process-contract step; Linux
   already requires it. Prove actual shell order/failure for all three commands
   and the unchanged required aggregate. Preserve full action SHA/Ruby pins.

The full intended diff remains the existing six paths plus the native sibling;
no runtime/Store/credential/schema/dependency/package files or third helper.
The ownership helper need not change unless a small existing dispatch adaptation
is required; do not refactor unrelated accepted cancellation/observation logic.

### Actual native setup, bounded readiness and EOF-only fallback

Each case runs in a fresh existing static driver child, owned by `run` through
real unshared Process.spawn/waitpid. The driver calls the ACTUAL shared native
capture with constant Ruby/static-worker argv, original pgroup/chdir/environment
contract and real pipes. A module-local Open3 facade forwards the real spawn and
only adds private control-read/event-write FDs and the intended stdin.close fault.
No app code, Python validator, Store credential or Store call can execute.

Before injection, positively observe the worker's structured exact PID/group
ready event and definitely live state under one original READINESS_LIMIT cutoff.
Reuse explicit R4 ready/dead semantics and capped observations; absence/unknown
cannot manufacture readiness. Record actual worker identity before capture. Close
unused exact FDs early so only the driver owns the control writer. The worker
monitors EOF throughout its phase and retains its independent WORKER_LIMIT bound.

The fault is raised synchronously from the FIRST actual stdin.close after its
normal close. An independent driver watchdog can ONLY close that private writer
at CAPTURE_LIMIT; it must NEVER signal the waiter/PID/group. This releases the
worker even if native cleanup regresses and Open3's implicit join would otherwise
hang. Before capture entry/readiness failure, close the writer inside the spawn
callback ensure, BEFORE Open3 can implicitly join. After capture entry, keep it
open until the result/death oracle, with the independently scheduled watchdog as
the bounded fallback. Driver hard death also closes the sole writer by the OS.

No fixture cleanup signal is derived from a marker or Open3 waiter. Parent abort
may still stop ONLY its actual unreaped direct driver via the already accepted
OwnedChild; native-worker fallback is EOF. Stop/join only the exact watchdog and
Open3 waiter and observe the native process definitely stopped. Unknown ownership
or failed readback preserves scratch/diagnostics and fails; never blanket delete.
All catchable exceptional paths close owned pipes independently; no new helper
may reopen a cleanup cancellation window or replace an already established error.

### Oracles, negative mutation and hard driver loss

Positive native cases must establish actual readiness, first-close injection,
actual native capture error, expected error identity/redaction, waiter reaped with
SIGKILL, native death BEFORE fallback, watchdog not used and control writer still
open at the death proof. Record these facts; do not treat any exception/timeout as
proof of correct native cleanup. Any unexpected fault is a distinct failed result.
The driver records bounded sanitized result data and the parent additionally
performs its existing real native death proof before scratch removal.

Add an isolated, anchor-validated native source-copy mutant removing only its
production group KILL (without changing committed runtime). Its actual join must
require the watchdog's private EOF, fail the positive cleanup oracle, record
`setup-fallback` rather than pass, and still end with definite stopped worker and
joined watchdog/waiter. Hash original/mutated source; never substitute a mocked
successful capture or trust a synthetic wait status. The positive cases remain
unmutated real native capture.

Add a hard-driver-loss case at the published native-ready phase, before fault
injection. The existing parent stops its reserved direct driver, then requires
the worker's actual leader-eof.json, definite native death and absence of a final
driver result. Generalize expected EOF filename from actual child presence, not
an assumed mode name, preserving old startup/descendant hard-death cases.

## Tests and documentation

Standalone native suite covers all three original error types, removed-cleanup
negative control and hard-driver EOF. Retain zero-skip actual behavior tests and
preserved source/error/privacy assertions. Independently instrument the corrected
actual execution to prove no post-reap fixture signal requests and no PID/group-
based fallback; do not claim a safety-veto run is an unmodified final-suite pass.
Readiness/cleanup/parser/UNKNOWN and actual cancellation/late-restoration matrix
from R4 must continue unchanged. Run BOTH full adapters plus the native suite,
updated CI contracts and all original/adversarial replays where applicable.

Only helper comments/remediation evidence need documentation: there is no
consumer or release-lifecycle behavior/API change. Record the explicit seven-path
scope and R4 approval versus required R5 acceptance. Preserve original R2/R3/R4
failures, missing historical ps output and separate unexplained QA-003 EEXIST.

## Compatibility, security, retries and verification

Ruby3.3 on supported Linux/macOS. Fork/pipe support already belongs to this POSIX
fixture contract. No credential or unrelated Store state can be touched. Static
isolated drivers prevent monkeypatch/error state leaking between tests. Readiness
and cleanup retain fixed existing limits; no gate retry, timeout widening or
passing watchdog cleanup as production behavior. The main regression risks are
FD ownership/leaked writer, implicit Open3 join ordering, swallowed first error,
hard-termination evidence selection, and weakening original setup assertions.
Test each explicitly. Any observed unknown worker state is retained, not deleted.

Obtain independent R5 plan approval, implement, run development proof, snapshot
all152 first-party files (seven changed paths), and obtain DISTINCT actual-diff
R5 implementation acceptance before final verification. Independently corrected
ignored verifier tooling has a separate approved plan and must pass distinct
actual-diff/proof review too; it does not alter this first-party scope. Then freeze
and run ALL applicable gates from zero, including native sibling and zero-skip
macOS/Python/wheel/native/Java/Ruby/WIF/pinning/actionlint/package gates. No old
final run/partial pass can be adopted. Only complete acceptance permits scoped
commit, protected main PR delivery and actual main CI. Preserve user AGENTS and
pending QA-003. Remaining findings/full fresh audit/READY/feature report are still
mandatory; no additional original finding has been skipped or counted complete.


## R5-R2 — concrete amendment after independent REQUEST_PLAN_REVISION

This section supersedes any less-specific R5 wording above. Original plan/review
remain immutable. Review `plan-review-r5/PLAN-REVIEW-R5.md`, SHA256
`694c022c01c2ef5d56d668b61909c1c19f8a3fe616f902a4811bfe96eda6ff44`, identifies
R5-PLAN-01/02/03. No R5 source has been implemented. This remains the same
seven-path fixture-only fix; a separately investigated runtime concern is not
silently included or counted resolved.

### Native-only identity and static cases (R5-PLAN-03)

Add one fixed `native` fixture platform/entry, distinct from ios/android. An
explicit frozen allowlist covers the three original first-close cases, removed
cleanup mutant, hard-driver loss, partial-pipe failure, owner-publication failure,
malformed-readiness failure, watchdog allocation/publication failures and the
post-reap cancellation case. Native parameters must be exactly empty: trusted
Ruby, native module, static worker and tooling directory are derived solely from
this first-party helper, never fabricated iOS/Android artifact parameters.

Validate platform/mode/parameters BEFORE creating a directory, pipe or child in
both the parent entry and actual driver dispatch. Native modes with ios/android,
platform/ownership modes with native, unknown modes/platforms and nonempty native
parameters fail without a spawn. Keep every existing adapter input contract.
Native dispatch loads only shared native capture, before adapter imports. Native
workers are leaders only; they inherit control-read/event-write, not the writer.

### Whole new driver lifetime (R5-PLAN-01)

Use the accepted `lifetime`/primary cleanup primitives for this new driver, with
separate scopes where expected native failure is deliberately captured. Before
any acquisition, initialize all four pipe-end references, actual native waiter,
stdout/stderr/stdin references, watchdog/injector references, primary/result data
and a bounded resource ledger. Install outer teardown before first IO.pipe.
Finite acquisition+publication (IO.pipe assignment, actual Open3 acquisition into
callback and Thread creation into owned slot) run under deferred asynchronous
cancellation. Reopen active work only after teardown knows acquired references.

Inside the real Open3 callback, register the actual waiter/pipes and establish
its protected ensure FIRST, before owner persistence, closing unused ends,
readiness, first-close hook installation or watchdog setup. The callback cleanup
must close the sole control writer on every failure before native entry and
attempt all remaining descriptor closes independently. It must run BEFORE the
pinned Open3 implicit `parent_io.each(&:close); wait_thr.join`. Bound explicit
waiter joins; if an owned worker is not known stopped, preserve diagnostics and
let the existing parent/worker independent limits contain the failure—never
claim cleanup or signal a historical native group.

Record actual native acquisition before injectable owner-publication failure.
If first owner publication fails, finally publish the captured real identity for
read-only parent death proof after EOF/join. Do not convert this into a pass.
For the sole deliberately pre-spawn partial-pipe case, retain an explicit
no-native-acquisition result (zero attempts, closed actual descriptors) and an
unambiguous no-native-owner marker. Parent acceptance of that marker is restricted
to this fixed fault case plus its matching failed-result evidence; it cannot
stand in for unknown spawn/owner loss in any other case. All unknown identities
still fail and preserve scratch. No marker grants signal authority.

After actual structured readiness + definitely-live observation under the original
absolute readiness cutoff, allocate and register the watchdog under the protected
handoff. Only then enter native active capture. Watchdog only closes the exact
private writer after CAPTURE_LIMIT. Both failure before Thread allocation and
failure after actual thread publication must close EOF inside callback cleanup,
join the acquired watchdog and waiter and leave capture/injection flags false.
Use no `Thread#kill` without joining its exact registered reference afterward.

Install the close hook only within this protected callback. Its normal close
runs first. Injection is armed solely around the real native block and additionally
checks the exact native `stdin.close` call site (locally derived source path and
unique source line/anchor); wrapper/Open3 implicit closes must never set injected.
Disarm in callback ensure before wrapper teardown. Record the actual call-site
match, one injection count, original close completion and real native entry. An
asynchronous handoff failure cannot create a false first-close observation.

Keep `native_error` (the intentional error under test) separate from a harness
primary. Capture the real native error only after its cleanup has run, compare
actual object/message/status for Interrupt/SystemExit, and require the exact
redacted ContractError contract for IOError. A scope must remember an unexpected
body error before cleanup; later FD/watchdog/report errors cannot replace it or
manufacture a passing result. Expected native errors may be consumed only by the
assertion/result channel, never converted into a successful upload. Any cleanup
fault invalidates a positive fixture result and remains visible.

### Required direct boundary matrix (R5-PLAN-02)

The standalone native suite runs these paths through the actual new static driver:

1. Original Interrupt, SystemExit(23), IOError: live worker, actual first native
   stdin.close fault exactly once, native SIGKILL status/reap, death before EOF,
   writer still open, no watchdog, identity/redaction assertions. These remain
   unmodified real production capture calls, not instrumented-positive substitutes.
2. Second-pipe acquisition failure: first real pair acquired/closed, zero native
   attempts, zero injection, original harness error retained, no watchdog/worker.
3. Owner-publication failure after real acquisition and malformed ready event:
   actual worker exits through control EOF, bounded joined waiter, no native
   capture/injection. Preserve exact fault classification and real identity for
   parent observation. Source-independent dummy return statuses are forbidden.
4. Watchdog unavailable before creation and failure immediately after actual
   Thread publication, both after definite worker readiness: EOF before implicit
   Open3 join, actual worker exit0/EOF, joined registered thread if acquired,
   no native capture/first-close false positive, original error retained.
5. Post-reap asynchronous cancellation: the real native block first raises its
   intended Interrupt and its actual waiter is already joined/reaped. Remember
   that primary in the facade/harness scope, then inject a REAL joined Thread#raise
   repeat (and a scoped self-SIGINT in the protected teardown) before result
   publication. Do not inject into production's own earlier ensure. Require the
   expected original native object/message still observed; all acquired IO,
   watchdog/injectors joined/closed; restored traps/inactive scope registry/no
   pending interrupt. The test is successful only in proving retained cancellation
   facts, never by swallowing an unexplained cancellation into native success.
6. Removed-KILL source-copy mutant: native join must require watchdog EOF, actual
   worker exit0 + real leader-eof.json, not SIGKILL; kind setup-fallback, no positive
   death-before-fallback fact. Retain original/mutant hashes/unique mutation anchor.
7. Hard driver death after published live-native readiness, before first-close:
   parent may stop only its reserved direct driver; OS closes sole writer, actual
   worker EOF record and definite death, no final driver result.

Independently instrument the corrected actual native suite/driver signal paths
and veto unknown/post-reap requests before syscall. The check must see actual
production kills in the three positive cases and zero fixture historical-PID
requests, including the post-reap teardown adversary. Never label a safety-veto
probe as an unmodified suite pass. Use actual numerical observations and EOF/
wait statuses for lifecycle proof. Strict malformed/indeterminate/unknown state
remains a failure, never readiness or authorization to dispose live resources.

### Verification and scope reconciliation

Run the whole new native suite and BOTH full adapter suites, zero skips, updated
three-command macOS shell/fail-fast/aggregate contracts, original relevant R4
replays and the safe new signal probe. Recheck all seven intended paths only,
all152 first-party hashes, native/runtime unchanged, both real indexes empty,
root QA-003/user AGENTS untouched. Obtain DISTINCT actual-diff acceptance and
separate ignored-verifier acceptance, then the complete fresh frozen suite and
protected delivery/main CI as previously required. No original failed evidence,
missing historical observation, EEXIST, pending issue or final fresh audit is waived.
