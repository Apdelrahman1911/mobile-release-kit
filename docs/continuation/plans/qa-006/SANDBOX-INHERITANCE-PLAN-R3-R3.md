# QA-006 — inheritance helper correction plan R3-R3

**PROPOSED ONLY. No implementation or native execution is authorized by this
document. Obtain independent plan review, then a distinct actual-code safety
review. This does not close QA-006 or QA-007 or authorize a full-suite launch.**

## Reanalysis and immutable review basis

The original `FINDING.md` is a tests-only readiness/ownership defect. Completing
the R6 fixture verification reaches the separately confirmed QA-007 native
auto-reaper/group-signaling defect. The ignored inheritance experiment exists
only to evaluate a specific host-local signal fence without running that unsafe
runtime on the shared Mac. The accepted primary 32-row experiment remains
consumed; its result is not permission to rerun or to launch the full suite.

Read all nine R3-R2 runtime scripts, the complete 560-line pure test file, the
original finding, R6-R2 plan and the R3-R2 inheritance plan before this proposal.
The independent actual-code review found seven real helper defects, rather than
seven new repository findings. Its source-derived counterexamples have not been
executed as native reproductions. Existing 24 pure passes do not cover them.

Bindings (all relative to this QA-006 evidence directory):

- Existing plan: `SANDBOX-INHERITANCE-PLAN-R3-R2.md`, SHA256
  `78390fbb00444b9faa91c78d04ee9720df417602341606a6f706eb6ccec45cf7`.
- Rejected actual-code report:
  `sandbox-inheritance-implementation-review-r3-r2/IMPLEMENTATION-REVIEW.md`,
  SHA256 `2093a5d30f71214f75e50752f3491dbc2ec189e86dc57fe24619cf75fd6c5f20`.
- Rejected decision SHA256
  `55a4e3082fcbceeb0685b0521e3f9ab6bdb9580222b48ff9e58602b8adcddd7c`.
- Rejected `sandbox-inheritance-implementation-r3-r2/CODE-BINDINGS.json`,
  SHA256 `ec2c8e1d8b38d33e4d06ccad6cd471c8061aea10c44b3fc631107be7f0f1b465`.
- Unchanged eleven-row matrix SHA256
  `5eaae4e81cb621555d117cf86ae808c31a29d75091fa14c68bfc6b5c27216697`.

This is a scoped amendment to the complete R3-R2 plan. Retain that plan and every
old script/package/result/rejection unchanged. All R3-R2 invariants, explicit
native rows, bounds and ownership rules remain mandatory except the precise
exec-only deadline claim corrected below. No old approval is reusable for the
new code. No timer, subprocess, observer, signal, executable or native row is added.

## Scope and compatibility

After plan approval, create a new ignored `sandbox-inheritance-r3-r3/` containing
reviewed copies of `contract.py`, `runtime.py`, `reconcile.py`, `controller.py`,
`sender.py`, `python_relay.py`, `ruby_relay.rb`, `bash_relay.sh`, `canary.py`,
`test_pure.py` and `REFERENCE-BINDINGS.json`. A fixed `test_pure_ruby.rb` is the
only additional test helper; it is not part of the native eleven-route matrix.
Rebind all fixed paths, the new plan hash, script hashes and a fresh
`sandbox-inheritance-implementation-review-r3-r3/DECISION.json` gate. Use a new
exclusive `execution-r1` under the new helper root only after actual-code approval.
Do not create that execution directory while authoring or testing pure controls.

There is no product/API/schema/package/Store change, no source-cache disposition,
and no credential, Git index/ref/object, historical proof or AGENTS modification.
R3-R2's current helpers stay frozen so its results remain reproducible as records.
All new experimental evidence has a new identity; old evidence is never adopted.

## SIIR3R2-01/04 — original observer time and partial-child custody

Root causes: query deadlines exist only in the caller, while the signal guard
uses the longer row deadline; success precedes the work-time check. A returned
Popen handle can also be retained in Registry but lost from the caller's observer
slot if descriptor adoption fails, incorrectly revoking known child custody.

Change `contract.py`, `runtime.py`, `controller.py` and `reconcile.py`:

1. Make a frozen, typed query-window value holding the original admission,
   `admission+2s` work endpoint and `admission+7s` disposition endpoint. Validate it
   against both original row/outer endpoints and bind it to the actual QueryChild
   before dispatch. No caller-supplied replacement timeout is accepted by signaling.
2. Register and publish the actual typed observer slot to its query owner before
   fallible acquisition/adoption. Keep strong references to the returned Popen,
   its actual PID and each returned stream before metadata/capture setup. Distinguish
   capture/setup failure from ownership/wait uncertainty. Missing returned handle,
   invalid actual PID, ECHILD, foreign owner, already reaped or unregistered child
   never acquires signal authority. An fd metadata/Reader failure alone does not
   erase an already known sole-waiter reservation.
3. Check work admission again after all bookkeeping and immediately before Popen.
   Publish any returned handle before a post-return check. A late return is a failed
   query, even if its streams/status subsequently prove completion. Record actual
   returned/first-complete/disposition observation times; never relabel late data.
4. At failure/cancellation, stop ordinary work, drain what can safely be drained,
   and dispose only this actual QueryChild using the unchanged original window.
   Before its original work endpoint, poll without signaling. Within the original
   five-second disposition window, at most one terminal positive-PID KILL is
   permitted only after the actual sole waitpid(WNOHANG) returns exactly `(0,0)`.
   Recheck the original disposition/outer endpoint after that wait and immediately
   before dispatch. Revoke before terminal dispatch/reap. At or past disposition,
   no new wait/query/signal is admitted; retain any unobserved child as unknown.
5. Keep mandatory known-descriptor close attempts independent of capture failures;
   do not let select/read/wait/close exceptions skip other possible disposition or
   overwrite the initial error. Always retain the partial query record and secondary
   errors when serialization remains possible. A cleanup failure cannot erase it
   by escaping a `finally`. No PID from a sender message becomes this handle.
6. Reconcile actual QueryChild timing with its attempt record, queried sender,
   row and immutable query window. Success requires timely actual status plus
   genuine stdout/stderr EOF, all closes and no error. Late, failed, unknown or
   substituted evidence stops the row and all later rows; it is not retryable.
   Only a complete timely query that observes the exact still-present sender can
   use the next already-bounded observation slot, under the original three-query cap.

Use a small query-specific record extension, not optional unconstrained fields
on every child. Update exact schemas/fixtures and all consumers together. An
observed status remains evidence even if it was late; it is not a successful query.

## SIIR3R2-02 — checkpoints at actual dispatch boundaries

Root cause: checks precede potentially blocking emission or setup; Registry also
does not know its owner's control EOF. Later syscall admission can therefore use
stale cancellation/time/control observations.

Give Registry/Emitter a real owner work checkpoint without recursive guard calls.
It checks flag/pending cancellation, the unchanged work and outer endpoints, and
the applicable actual control Reader's EOF/failure. Root has no upstream control;
the sender uses C for loss rows and stdin otherwise; Python/Ruby relays use their
own stdin. Commands already buffered for the correct phase are not mistaken for
EOF. Existing phase-specific unexpected-command validation remains intact.

- Construct literal argv/environment/options, charge the attempt, emit bookkeeping,
  then perform the final owner checkpoint immediately before Popen, Process.spawn,
  fork or Open3 acquisition. Rejected dispatch keeps its spent attempt; no attempt
  is silently erased. Returned handles are still published before any checkpoint.
- Ruby fork's new frame owns its reopened control endpoint, not a stale parent
  Reader/buffer. After stream/group setup and exec-frame emission, check that
  original work/outer window, cancellation and actual control again before exec.
- Guard both literal zero-signal outside probes individually, after marker read
  and before each syscall. Retain the zero-only API; never accept a signal argument.
- Work writes/forwarding/command writes check the owner on each bounded write loop
  and again after a potentially blocking select. Disposition writes use the
  original disposition/outer endpoints without re-admitting ordinary work; pending
  cancellation remains a failure, not a reason to abandon required known custody.
- Recheck time/cancellation/control after potentially fallible sole-wait checks
  before ordinary owned nonzero dispatch as well. No kernel-atomic cancellation
  claim is made; the fix closes explicit blocking intervals in our code.

All affected Python sender/relay, Ruby charge/fork/Open3/spawn/forwarding and
canary work-emission paths must use consistent phase guards. Control-EOF shutdown
records use the disposition path and cannot acquire children or signal.

## SIIR3R2-03 — truthful exec-only trampoline contract

System Bash3.2 cannot demonstrate the carried CLOCK_MONOTONIC pre-exec check with
the available builtins. No alternate Bash was found at the three recorded
Homebrew locations. Do not claim `SECONDS`, wall time, copied timestamps or a
parent check is that guard. Do not add another interpreter/helper or reset time.

Explicitly classify `/usr/bin/sandbox-exec` and the fixed Bash script as **precharged
exec-only trampolines**. They can only exec the fixed next program with the carried
context. They have no child-acquisition, permission-probe or nonzero-signal code.
Their original acquisition/exec transitions remain counted before launch. Bash
continues flag-only cancellation checks before and after its bounded fixed frame.
It carries work/disposition/outer unchanged and never claims a local clock sample.

The next capable Python or Ruby entry must validate the original time window,
cancellation/control and fixed context before any probe or child acquisition.
Retain a typed entry-admission record from that capable interpreter, bound to its
real PID/parent, original context and monotonic sample; require it in final route
reconciliation. A delayed entry cannot create a ready/success proof or re-authorize
work. Recheck after script/policy I/O as well as before the first admitted work.

**Narrow claim:** a delayed exec-only transition itself may occur after a cutoff;
it cannot authorize subsequent work or be accepted as timely inheritance. The
experiment does NOT prove that no OS exec happens after a deadline, preempt an
OS-stalled exec, or contain arbitrary untrusted/native-service execution. A late
or unobserved route remains failed/unknown, stops later rows and prohibits guessed
cleanup. This narrower claim must be explicitly approved independently; it is not
a waiver of a product defect or of the later complete-launch containment review.

## SIIR3R2-05 — publish acquisition custody before metadata

In `Endpoints.pipe`, `Row.input` and Ruby's plain/fork acquisition path, metadata
or temporary-end close can fail before cleanup can use the actual acquired object.

- Publish each actually returned descriptor/stream immediately into a pending
  cleanup scope before fstat, fcntl, flag changes, Reader construction or another
  close. Fresh exclusive acquisition custody is distinct from metadata eligibility
  to send/receive protocol. Metadata failure blocks work, not the one owned close.
- Track close attempts and outcomes; a close error that may already have consumed
  its fd cannot authorize repeated raw-number close or unrelated resource adoption.
  Where a prior identity exists, verify it before close. No later acquisition is
  allowed after a custody/close failure. Preserve ambiguity and secondary errors.
- Move Row.input's entire metadata/write/fsync region inside the descriptor's
  protected cleanup scope. Keep a pending-file record if identity publication
  fails; it is retained, never passed to successful scratch deletion by guesswork.
- Ruby publishes the child input writer, actual PID, all streams and cleanup
  ownership immediately after spawn/fork returns, before temporary endpoint closes.
  On any setup failure, attempt every known control-writer close before waiting.
  One failing temporary close cannot skip the actual child's EOF path or another
  known close. Preserve Open3's distinct actual waiter; relays never gain signals.

Readback, stream/descriptor adoption and metadata injection tests exercise the
actual owner methods. A mocked `cleanup=True` does not prove this correction.

## SIIR3R2-06 — independent EOF and full subtree knowledge

Root cause: generic cleanup drains R but excludes it from `clean`, and row unknown
state derives only from direct children. Observation admission also accepts a
success-shaped final before validating the actual child wait/terminal contract.

Include every supplied independent Reader's genuine EOF and failure state in
Registry's cleanup completion. Closing a reader never sets EOF. Keep direct-child
disposition separate from possible descendant/orphan disposition. Mark a possibly
acquired route subtree as unresolved as soon as acquisition can have occurred;
missing final evidence is unknown, not proof that it never had descendants.

Extract the existing complete pure route/terminal reconciliation into a shared
pre-observation validator. It verifies actual direct relay/outside waits, bound
ready/acquired/loss frames, sender parent change, complete final/owned-inside-child
wait and signals, full streams, independent raw-frame/EOF consistency and exact
context/channel identities, but does NOT fabricate orphan absence or query status.
Only this complete validator admits the first QueryChild. Reject incomplete or
success-shaped malicious data before any observer acquisition. Final reconciliation
reuses it and additionally validates actual bounded observer evidence.

For ordinary routes, complete actual parent waits/terminal chain are necessary
to resolve the subtree. For loss routes, valid final plus real R EOF yields
`awaiting-absence`, not `clean`; only a separately valid scoped absence observation
resolves it. Query admission tests direct cleanup + complete preproof, not a
circular requirement that the orphan is already absent. Row/global unknown state
stays true while the subtree is unresolved, including on failure before handshake,
R read failure, missing final, retained writer, invalid final or missing absence.
No additional diagnostic query or guessed signal is allowed on those failures.

## SIIR3R2-07 — final success after finalization, not before it

Check the original row cutoff after reconciliation and channel finalization and
at its actual successful return. Check original outer cancellation/time after
preservation, budget reconciliation, serialization, file writes/fsync/close and
terminal stdout. Start the one outer epoch once at controller entry; preparation
does not renew it. There are no post-cutoff native observations/signals/launches.

Use first-error retention plus secondary finalization errors, including RESULT,
MANIFEST and scratch-disposition failures. Serialized result files are explicitly
**provisional until actual outer completion is observed**. A successful-looking
file cannot override a nonzero exit, cancellation, late completion or failed
cleanup. Perform no fallible/blocking operation after the last successful-return
decision; where best-effort failure recording is possible it never turns the
status back to success or starts new native work. Preserve all incomplete files.

Restore only owned temporary handlers where applicable, independently attempt
each restoration, and account for restoration failures before the terminal gate.
Do not manufacture an orphan exit status: loss sender still uses one final frame
immediately followed by its own exit; root still needs actual R EOF and absence.
Late transmission cannot be accepted by root's original row/outer completion gate.
Ordinary relay/sender terminal writes also must not return success after observed
late/cancelled finalization. The actual tool exit remains a separate observation.

Deadlines are cooperative admission/completion bounds, not guaranteed preemption
of a blocking OS filesystem/exec call. A late return fails and forbids further
work; no new deadline, kill-by-name or unsafe cleanup is introduced to conceal it.

## Required regressions and finite verification

Preserve all original 24 pure tests (adapting shapes for corrected real contracts)
and implement every control in the rejected review's `PURE-REGRESSION-REQUESTS.md`:

1. Original query 109/111/116 against row140: delayed return, late successful EOF,
   early/late KILL, clock jump inside wait, no reset, reaped/ECHILD/foreign handle.
2. Actual acquire with returned fake-backed Popen followed by every fd identity /
   stdout Reader / stderr Reader failure; preserve that same QueryChild and real
   cleanup methods, not a successful mock. Inject secondary read/select/wait/close
   failures; retain exact original and partial records. No returned handle means
   no invented custody. All signals in these tests are fake/vetoed before syscall.
3. Cancel/expiry/control EOF during attempt emit; no Popen/spawn/fork/Open3/exec
   after that boundary, charges retained. Inject marker and between-probe changes.
   Backpressured writes must stop ordinary work without extending time.
4. Static fixed Bash/sandbox transition classification and actual pure capable-
   entry guard tests. Late/fabricated entry records reject route acceptance;
   the unchanged eleven routes and 44/57 acquisition/exec totals still reconcile.
5. Pipe metadata/flag failure for each fresh fd, input fstat/write/fsync/close
   failure, substituted identity and ambiguous close. Ruby temporary-close error
   must close its known child writer before the first actual fake wait.
6. Real cleanup with reaped children and open/failed/partial R. Full final/child-
   wait/parent/channel/signal mutations reject before query. All ordinary/loss
   missing-subtree states remain unknown; reader close never becomes EOF.
7. Advance/cancel within preservation, reconciliation, evidence writes, terminal
   output and handler restoration. Double-fault finalization preserves the first
   error. Actual main/run return must be nonzero; provisional success is not proof.

Preparation is separate from native feasibility. Use the pinned isolated Python
`-I -B`, at most four new pure invocations, each with an original60s cooperative
test cutoff, 2MiB captured output and no source/cache/native operations. Install
fail-closed guards for Popen/fork/exec/wait/kill, sockets, FFI, signal mutation and
native process queries before loading definitions. Fake handles, clocks, select,
descriptor calls and writes invoke actual helper control flow; no real synthetic
child or real signal is allowed. Retain every failed run; never renew an invocation
or silently exceed this continuation ceiling. Finite cases, not stress loops.

Add actual-code Ruby unit controls using the fixed `test_pure_ruby.rb`: intercept
all spawn/fork/exec/Open3/wait/signal/trap/pipe APIs before loading the relay module;
all streams/statuses/clocks are fictional. No relay main entry or process creation.
Before executing that test file, obtain a static safety approval of its exact
bytes from a distinct reviewer. At most two pinned Ruby `--disable-gems` invocations,
30s cooperative bound and 2MiB output each, into fresh retained result files.
Do not count those invocations as inheritance/OS behavior or change native caps.
If any route reaches a real native boundary, stop and retain failure. Need for
additional invocations requires explicit bounded review, not a quota reset.

After pure results and implementation snapshot, a distinct actual-code reviewer
must examine every changed and sibling route and the full native matrix again.
Only its new exact single-execution decision can permit the unchanged native
experiment: 11 rows, 44 acquisitions/57 explicit execs; at most6 bounded observers,
maximum50/63, hard64/96; 30s work+10s disposition per row, original180s outer,
64KiB/stream, 4KiB chunks, 2MiB aggregate captures, 8MiB new native evidence.
No new native timing/fault rows, Bash syntax child, version probe or helper are
implied. Stop on first failure/unknown; later rows stay UNEXECUTED. Independent
result reconciliation and separate complete-launch approval remain subsequent.

## Regression risks, documentation, recovery and remaining gates

Main risks: retaining fd authority too broadly; accidentally accepting capture
failure as PID uncertainty or vice versa; recursive work guards; consuming a
phase command as EOF; returning early before close attempts; breaking Open3's
ordinary parent-exit exception; a circular orphan-admission gate; record-shape
drift; losing an earlier error under finalization; falsely claiming a Bash clock
guarantee; and success-shaped stale files. Direct controls above cover each.

Update ignored implementation/coverage/resource/progress documents with the
revised claim, actual results and remaining limits. Consumer docs do not change.
Failures retain original evidence and incomplete namespaces; no implicit restart,
adoption, rollback, new observer, cleanup signal or source edit. Stop/join only
actually owned workers under their existing custody; remove only inventoried
owned scratch after required bytes and complete disposition are preserved.

Full project Python/Ruby/native/workflow/Supply/WIF/Fastlane/actionlint/Bundler/
pinning/source-wheel/runtime-dependency checks, exact QA-006 acceptance, protected
delivery and main CI remain required. This helper correction does not claim any
of them passed. QA-007, QA-003, QA-004, QA-005, MRK-008 and MRK-009 still need their
individual full workflows. Then perform the mandatory fresh first-pass-style
whole-repository audit, fix new confirmed blockers through the same process,
repeat to justified READY, and produce the separate complete feature inventory.

**Authoring outcome:** plan only; prior helpers and all implementation files
unchanged. No native experiment, build/background worker, Store action, cleanup,
commit or push was performed by writing this proposal.
