# QA-006 R5 — remove stale signal authority from the required native sibling test

**PROPOSED; independent plan approval required before first-party edits.** This
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
