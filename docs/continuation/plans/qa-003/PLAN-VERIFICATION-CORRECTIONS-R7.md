# QA-003 R7 — bounded proof parsing and owned verification resources

## Reanalysis, evidence and scope

This is a correction to the still-unapproved QA-003 implementation, not a waiver
of a failed gate or a separate Store/lifecycle feature. The original QA-003
finding and approved R4/R5/R6 obligations remain mandatory. No production code
will change in this amendment.

1. Independent R2 review reproduced `proof_paths` exhausting 519 outer entries
   with a 512-artifact limit, and all eight entries of an invalid artifact before
   rejection (`implementation-review-r2/proof-enumeration-*`). `sorted(iterdir())`
   and the inner list comprehension check bounds too late. Moreover, CPython
   3.11 `Path.iterdir` calls eager `os.listdir`; merely wrapping that iterator in
   `islice` would not bound underlying directory enumeration. This violates the
   approved bounded downloaded-proof parser contract. No OOM or provenance
   bypass has been demonstrated.
2. `development-full-r4.log/.exit`: 658 tests, exit 1, 20 failing subcases, all
   init transaction before/after writes at indexes 0–4 (both force settings).
   `boundaries` patches `tx.os.write`, but `tx.os` is Python's shared `os` module.
   R5 correctly moved Git discovery to the owned subprocess runner, adding five
   parent-side IPC writes per init proposal. The old test now injects transaction
   disk faults into unrelated Git request pipes. Optional nonfatal discovery is
   allowed to be unavailable during init; its failure is not a transaction write
   and need not prevent valid configuration creation. Real rollback writes still
   fail correctly. The credential-free actual CLI reproduction
   `reproduce-init-boundary-scope-r7.py` records every caller: the five extra
   writes are `owned_process.run_owned:392`; underlying transaction inventories
   remain 97 (new) and 104 (force) events. A deliberately failed first Git IPC
   write still allows valid init, without source changes or private operations.
3. Independent R2 `harness-descriptor-probe.py` executes an actual fictional
   worker, fails `last-worker.json` persistence, observes its actual group absent,
   then fails the absence observer. `run_worker` places two pipe closes AFTER
   fallible wait/absence cleanup; both descriptors remain open before reviewer
   fallback. The first/second pipe, initial fork and parent peer-end closes also
   occur outside the protected cleanup. Child setup before its task try block can
   unwind back into the launcher after a setup error. These are verification
   harness ownership gaps, not production signing/native corruption. Preserve
   the negative probe/results; no failed cleanup may produce a passing proof.
   Separate plan review then reproduced an immediate watchdog exit 91 while the
   actual worker task runs and `run_worker` returns exit 0/groupAbsent=True:
   readiness merely follows fork and watchdog wait status is ignored. Evidence:
   `plan-review-r7/watchdog-failure-{probe.py,result.json}`. Entire-child `_exit`
   alone does not establish supervision; genuine arming and checked completion
   are also required.

## Exact changes and affected files

- `tests/workflow/local_signing_matrix_contract.py`: use a context-managed
  `os.scandir` iterator, collecting no more than `MAX_PROOFS + 1` outer entries;
  require 1–MAX_PROOFS before sorting the bounded accepted list. Inner artifact
  enumeration collects at most two entries before requiring exactly
  `proof.json`. Close every iterator on success, invalid input or read error.
  Preserve all current symlink/type/name/size/JSON/scope/inventory/attempt/union
  checks and rejection of every invalid later proof before selection.
- `tests/workflow/test_local_signing_matrix.py`: add real filesystem plus
  non-exhaustion tests proving outer rejection at limit+1 and inner rejection at
  two, with a tracked real scandir iterator and a guarded lazy iterator that
  would raise if consumed past the bound. Assert iterator closure and forbid
  eager `listdir` fallback. Cover exact bound, empty/missing/extra entries,
  ordinary valid proofs, and read errors without relaxing other validation.
- `tests/unit/test_init_transaction.py`: scope OS instrumentation to this module
  using a test-only delegating copy/proxy of `os`, replacing `tx.os` rather than
  attributes on the shared module. Capture real OS functions before installing
  wrappers. Keep actual IO/native exclusive rename/fsync and all before/after
  rollback/recovery/intervening-change assertions. No discovery stubbing, no
  monkeypatch of production `run_owned`, no omission based on index/error text,
  no change to expected CLI error for any actual transaction write.
  Add an explicit regression: unrelated real pipe/file IO through `os` is not
  intercepted, real `tx.os` IO is intercepted and faultable, and shared OS
  callables remain unchanged. Exercise actual CLI schedules, including both
  force modes, under the full existing transactional fault matrix.
- `tests/workflow/local_signing_persistent_fixture.py`: begin the parent ownership
  scope BEFORE the first pipe/fork. Keep independently named raw FD slots and
  exact owner PID/child reservation state. After each successful pipe return,
  immediately record both ends; ordinary pre-effect acquisition failures close
  all previously returned ends. Relinquish each slot BEFORE its one close attempt;
  a failed/ambiguous close is reported and never retried against a possibly reused
  descriptor. Protect early parent peer-end closes as well as final handles.
  On every exit, independently attempt launcher-liveness close, exact owned worker
  termination/reap/absence proof, and EVERY remaining FD close using nested
  unconditional cleanup. Wait/absence/one-close failure cannot suppress another
  descriptor's cleanup or become a success result; retain chained error facts.
  Preserve the existing separate watchdog, original deadlines and hard-parent-loss
  behavior. Before each wait, relinquish any assumption that a failed wait did not
  reap its child; reacquire signal authority only on a successful zero-result
  observation. A successful reap or ambiguous wait must never authorize signaling
  a potentially recycled numeric group. On ambiguous wait, use the independent
  launcher-liveness/deadline watchdog and bounded nonblocking reap/absence checks,
  fail with uncertainty if those cannot be confirmed. Do not signal journal PIDs,
  unrelated groups, or unreserved children. Do not remove case files while any
  cleanup predicate remains unconfirmed.
  Wrap the entire forked worker startup/task AND watchdog startup in mandatory
  `os._exit` termination, including setsid/pipe/fork/close/readiness/persistence
  errors. A forked child must never resume or unwind into the outer launcher/test
  runner. The child holds only its inherited copies; it cannot run parent cleanup
  against group zero or another group. Preserve normal task/crash result codes.
  Add a private worker↔watchdog arming pipe, covered by the child ownership/exit
  envelope. The watchdog checks its exact expected group and initializes the
  liveness FD set/deadline (including an initial nonblocking selector validation
  and already-closed-owner check) before sending its one-byte armed acknowledgment.
  The worker must receive that acknowledgment within its existing startup bound
  BEFORE publishing parent readiness or running the task. EOF, malformed/missing
  acknowledgment or pre-arm failure prevents task execution. Startup resources
  unneeded by the watchdog are closed before acknowledgment; post-arm failure
  aborts the owned group, never an unrelated group. Catch unexpected watchdog
  errors/returns and terminate only its verified own worker group, then `_exit`;
  ordinary worker-completion EOF remains the sole successful watchdog exit.
  After the task's normal completion, the worker must observe watchdog exit 0
  rather than discarding wait status. Nonzero/signal/uncertain status makes the
  worker fail even if a task-result file exists; no proof can pass from that file.
  This is trusted fictional-worker supervision, not a guarantee against external
  simultaneous watchdog/launcher compromise or OS failure.
- `tests/unit/test_local_signing_persistent.py`: add real child/pipe regressions
  for owner-record and absence-observer errors (including their combination),
  first/second pipe and initial fork acquisition failure, early/final pipe close
  failures, wait failure before/after a real reap, and child setup/watchdog-fork
  errors. Assert actual original FD identity and group absence BEFORE test
  fallback. For intentionally injected pre-effect close refusal, assert that the
  exact remaining handle is reported/left unresolved without retry; close only
  that known test-owned handle after asserting the failure. For after-effect close
  errors, reuse the freed FD with a separate synthetic sentinel and prove it is
  not closed again. Independent handles must still close in both cases. All error
  paths must fail without an execution proof; child startup errors cannot execute
  the task or return into the parent test. Add genuine pre-arm watchdog abrupt
  exit/missing/malformed acknowledgment, post-arm monitor error and unexpected
  watchdog completion-status tests. The immediate-exit reproduction must now
  prevent task execution; post-arm errors must fail and leave no worker group.
  Existing actual deadline/launcher/outer-owner loss tests must still prove the
  watchdog is actively supervising, not merely that an acknowledgment was emitted.
  Retain existing launcher loss, actual
  crash/recovery inventory and complete matrix coverage.
- `docs/local-signing.md`: correct the scope sentence saying that no workflow
  permissions change. No release-workflow/Store-authorization permission changes
  are made, but CI-only read permissions are added for matrix execution proofs.
  Describe that actual distinction, as requested by independent R2 review.

## Compatibility, security, failures and recovery

Runtime CLI/config/schema/evidence formats and Store operations are unchanged.
The matrix accepts the same valid bounded artifact sets, including old successful
cells from the same run after partial reruns; malformed/excessive sets fail sooner
without wholesale directory materialization. Use existing Python 3.11+ POSIX
baseline. Limits do not change. Do not weaken proof authenticity/scope checks or
accept a directory read error. Close scandir handles deterministically.

Verification pipe/process ownership is test-only. Returned raw descriptors have
one owner and one close attempt; ordinary acquisition failure creates no returned
handle. Injected native effects with unknown ownership are not guessed. A retained
raw-close uncertainty is a failed test, not a cleanup pass. Worker timeouts and
parent-loss watchdogs remain independent of the failing observer. No synchronous
error is allowed to resume a forked child into the suite or declare uncertain
state cleaned. No real keychain/credential/Store work is introduced.

Initialization retains exactly the same production behavior: real filesystem
faults return 2, rollback/recovery semantics and inode preservation stay intact,
and optional Git metadata remains optional. Fatal containment/cleanup failures
must still propagate through production callers (existing R5 tests). This does
not address or waive QA-004 or QA-005.

## Regression risks, documentation and verification

Risks: accidentally eager filesystem enumeration underneath a lazy-looking API;
off-by-one bounds; leaked iterators; bypassed checks through a different entry
type; narrowing init instrumentation so genuine transaction mutations disappear;
changing global monkeypatch interactions in external-edit/crash fixtures;
misidentifying a reaped child as reserved; child-side exception unwinding; or
retrying an ambiguous close against a reused FD. Tests
must prove the precise boundary, not just observe a passing return code. The
test helper's docstring/comments should explain module ownership; the proof
helper should explain Python 3.11's eager Path iterator. Apart from the precise
CI permission scope clarification, no public behavior/documentation change is
needed; retain all negative development and
review evidence and update ignored issue progress/implementation notes.

Before implementation obtain independent plan approval (distinct from the
actual-diff reviewer). After implementation rerun the reviewer's original bounded
enumeration/descriptor probes and the entire init fault/recovery suite, plus
matrix contracts and the new actual pipe/child failure tests. Reconcile event
coverage (97/104 transaction events on this host) and
prove no owned child remains. Refresh intended-file hashes, obtain complete
distinct implementation approval including these changes and ignored final
helpers, then freeze and run ALL final gates: full Python, Ruby/Fastlane/WIF,
source/native/wheel, actionlint/pinning, packaging/dependency checks, all 16
source/wheel exhaustive matrix pairs with complete actual-union reconciliation,
and `git diff --check`. No commit, protected PR/merge or readiness claim before
the existing acceptance requirements are satisfied. Preserve user AGENTS, all
required evidence/wheels/environments and reviewer resources; clean only owned
disposable outputs/finished workers.
