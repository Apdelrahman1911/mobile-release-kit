# QA-006 — sole-owner macOS signal-fence feasibility plan R2-R3

**PROPOSED; independent approval required before implementation.** After that,
a different reviewer must approve the actual experiment's safety before it is
run. No first-party code, full native/adapter suite, final verifier, Store, VM,
commit or push is authorized by this proposal.

## Findings and revised scope

This new exact revision preserves R2-R2 (SHA256
`b5fa3d648cde5d9154bbecf87b4051aa3d1b65d1f15363bf650d6a1630a2889e`)
and its independent REQUEST_REVISION report (SHA256
`f9bc6e98a111d6340390d00c9c875e06bdc04a1ddaede9aecd9c587c5688aa83`).
SFPR-04 cancellation/cutoff handoff design is independently resolved. SFPR-05
requires an explicit case/launch/time matrix rather than the impossible inferred
32-launch allocation. This exact revision provides that immutable table and
clarifies dispatch linearization, both levels of sole-waiter custody, and halting
on unknown resource state. It is still a proposal, not experiment authorization.

Preserve R1 and its independent REQUEST_REVISION report
`plan-review-sandbox-feasibility-r1/PLAN-REVIEW.md`, SHA256
`216be3783e17b262bd4c24aa8488c97071b5a8cce1c6f1b0316e9bddb6de399f`.
SFPR-01 is real: a separate owner can die or reap while a surviving sender has
a queued numeric signal target. EOF, a controller flag or a timeout does not
revoke that sender's authority. No experiment has been implemented or run.

Remove that architecture rather than adding a timing delay. This revision is
an explicitly **narrower primary feasibility phase**, not a replacement for all
R1 containment obligations. It asks whether this host's real kernel enforces
the proposed signal policy for a sender that itself exclusively owns every
recipient. Ruby/Open3, inherited multi-hop sender chains, native-tool/service
compatibility and the full-run launch contract remain **UNEXECUTED/REQUIRED**.
They cannot be passed or waived by this phase. The later phase needs its own
safe design and review; no remote numeric-target handoff is implicitly approved.

## Components and exact policy

Add only a new ignored `QA-006/sandbox-feasibility-r2/` preparation namespace:
a fixed Python outer controller, fixed pre-exec owner/post-exec sender, static
Python canary, a small shared bounded protocol module, policy/marker files and
bounded evidence. There are no authored
threads, Ruby/Open3 waiters or other automatic target reapers in this phase.

Use exactly the R1 candidate, substituting only a canonical owned marker path:

```scheme
(version 1)
(allow default)
(deny signal (require-not (target same-sandbox)))
(deny file-read-data (literal "<owned-domain-marker-path>"))
```

No import, policy broadening, silent fallback, shell, eval, service launcher,
network, keychain or production capture invocation. Use pinned absolute Python
and `/usr/bin/sandbox-exec` with explicit argv/clean nonsecret environment. Bind
OS version, actual executable leaves, installed interface references, profile,
script and fixture hashes. The current Python3.11.16 exposes `waitpid` but not
`waitid`; do not invent WNOWAIT support or change interpreters silently.

Apple documents parent-child inheritance but marks these policy interfaces
private/unstable. This experiment measures behavior; profile text is not proof.
The allow-default policy is only a candidate signal fence, **not** filesystem,
credential or network isolation. Existing path/environment protections remain.

## Authority: the actual sender is the sole kernel waiter

The outer controller owns one invocation at a time. It starts the pre-exec owner
in a new session and retains its real child handle. All targeted groups differ
from the owner's group and from the outer controller/tooling group.

1. Before activating any sandbox, the pre-exec owner creates outside canaries
   using actual direct-child acquisitions and `process_group=0`. Each leader
   remains its unreaped child. It may also create a direct child that activates
   a separately declared profile for domain-equivalence cases. Actual ready
   records must show the acquired child's PID, UID, parent and intended PGID.
2. The same owner `execve`s `/usr/bin/sandbox-exec -f <profile> <python> -I -B
   <static-sender> ...`. Preserve only fixed control/event descriptors and an
   inherited read-only carrier pipe containing its actual acquisition registry,
   creator PID, per-case nonce and descriptor identities. This is an in-process
   exec transition, **not** ownership delegation to another sender.
3. The post-exec sender must have the exact creator PID and the controller's
   retained child identity. All carried descriptors must match their recorded
   pipe identities/directions. If sandbox-exec forks or changes that PID rather
   than execing, fail before signaling. No alternate launcher is selected.
4. For *each* carried target, actual `os.waitpid(pid, os.WNOHANG)` must return
   `(0, 0)` before first use. That kernel result proves a live direct child
   under this actual waiter, not merely a PID written in a file. ECHILD, a
   returned status, unexpected PID, exception or ambiguous acquisition revokes
   dispatch. Record any returned status as a real reap and never signal it.
5. After activation, the sender may create inside canaries as its own actual
   direct children. Register handles/descriptors before any fallible publication.
   For mixed groups, an inside child joins the already-owned outside leader's
   private PGID in the same session; require its actual membership acknowledgment.
   It must not create unrelated recipients or target its own/supervisor group.
6. Immediately before every positive-PID or negative-PGID signal, recheck the
   actual target/leader direct-child reservation using the sole-waiter rule.
   A group additionally requires the complete registry of exclusively owned
   member canaries and acknowledged membership. Never derive signal authority
   from process observation, signal0, files, messages from another owner, or a
   historical status. Forbid PID/PGID0/1, minus1 and all unknown identities.
7. Between a successful live check and the signal, there is **no other waiter**.
   A child may die, but remains an unreaped reservation. SIGCHLD must use normal
   waitable/default semantics, never SIG_IGN/SA_NOCLDWAIT; do not introduce
   `Popen.poll` elsewhere, detached waiters, wait-all calls or threads. After the
   final dispatch decision for an identity, revoke it before an actual reap.
8. The sole sender may perform sequential SIGUSR1 observations before a single
   terminal KILL. No further signal is permitted after terminal dispatch or
   revocation, including fallback cleanup. Every group leader remains unreaped
   until *all* dispatch to that group is irrevocably closed. A per-member reap
   cannot accidentally release a later-used group reservation.

If the sender dies, the only process capable of sending its registry's signals
dies too. The outer controller never receives authority to use those numeric
targets and never signals orphaned children/groups. This removes R1's separate
sender/owner expiry race even if the sandbox provides no restriction at all.
Preserve proof of the exec PID/parenthood and actual wait calls; a nonce alone
cannot establish this kernel relationship.

## Descriptor, cancellation and resource lifecycle

Each canary has a private stdin/control reader and sole writer in its owner.
`close_fds=True` and individually allowed descriptors prevent writer inheritance
by sibling/inside canaries. Before the owner's exec, only its required pipe
ends are made inheritable; after exec reset CLOEXEC before new acquisitions.
EOF makes a canary exit normally. Every canary also has a30s fixed self-expiry;
expiry never proves that it joined and never authorizes a historical signal.
No cleanup operation depends on sandbox-denied signal success.

Install INT/TERM flag-only handlers before acquisition. Preserve cancellation
across exec explicitly; Python memory alone is not a handoff:

- After pre-exec acquisition/readiness and before the final cancellation check,
  block INT and TERM using the actual `signal.pthread_sigmask`. Save the original
  mask, require the expected initial signal policy, and recheck the prior handler
  flag. If already cancelled, disable dispatch and clean up without exec.
- Keep both signals blocked through carrier serialization/publication and the
  exact exec call. Carry the prior flag, original case start/work cutoff and
  allowed restore mask alongside the actual acquisition registry. Do not clear
  cancellation, create a fresh30s cutoff, or silently drop pending signals.
- Exec preserves the blocked mask even while Python handlers reset. The new
  sender installs flag-only handlers before unblocking or dispatch/acquisition.
  It validates that INT/TERM really remain blocked, the carried flag/mask and
  original cutoff are valid, and its real PID/child/descriptor custody matches.
  Observe `sigpending`; any carried or pending cancellation disables dispatch.
  Restore only the validated original mask, then immediately recheck delivered
  flags and time. A signal arriving during restoration still makes this case
  fail. Late complete-looking evidence cannot override cancellation.
- A failed exec remains in the same owner. It records the original failure,
  disables all dispatch, and keeps cancellation handling/masking valid through
  private-EOF/actual-wait cleanup. Owned descriptor closes must run in finally
  even when cancellation/deadline checks fail; never skip close at a checkpoint.
  Restore the original mask/handlers only after owned cleanup, checking for late
  cancellation. If any ownership/state remains unknown, retain failure evidence.
- The outer controller may inject INT/TERM only into its own still-unreaped
  sender invocation. A bounded phase/ack protocol makes pre-block, after-block,
  pending-across-exec, after-handler-install and restoration cases reproducible.
  Parent injections never target canary IDs or an already reaped sender.
  Target signals still occur exclusively in the sole-waiter sender.

Cancellation or any failure disables all new signal dispatch, closes only known
control writers and joins actual directly owned children. Keep the original
error, real wait/EOF outcomes and cleanup failures separate. No rescue may
return success after timeout, cancellation, missing/changed carrier or ambiguous
ownership. SIGKILL of the sole sender remains uncatchable but cannot leave a
separate dispatcher using that sender's target registry.

Use one30s work cutoff per case,10s additional EOF/join allowance after failure,
and one180s experiment cutoff; do not reset on phase or retry. At most one sender
and four canaries are active. The fixed table below permits65 actual process
acquisitions; the immutable safety caps are96 process-acquisition attempts and
128 explicit exec transitions, including failed attempts. No case retries or
extra unlisted acquisitions are allowed; caps cannot be widened after a failure. Workers self-expire30s
after their own start; if a later-stage timeout leaves their state unknown,
retain evidence rather than guessing cleanup. Bound chunks to4KiB, each stream
to64KiB, aggregate output to2MiB and new files to8MiB. Use selectors/nonblocking
control/read/write and fail closed on oversized/duplicate/wrong-nonce/malformed
messages. Record actual command, byte/cutoff state and exits, not just a footer.

## Cases and noncircular proof oracles

All recipient identities come from the sender's own current reservations. No
actual PID reuse, foreign process, broad process scan/kill or runtime monkeypatch
is allowed. All signals remain safe for other tasks even if the policy is inert.

1. **Activation.** The marker exists with ordinary readable permissions in a
   canonical private root. A matched unsandboxed read of the *same* file/bytes
   must succeed under the same UID/argv context; the fenced read must return
   actual EACCES/EPERM, not ENOENT or an arbitrary setup error. Require an ordinary
   successful owned control handshake as well. Missing/wrong-marker controls
   must fail the oracle, never count as active enforcement.
2. **Invalid activation.** A no-fence control invokes the exact child and
   observes its earliest unconditional sentinel before other initialization.
   An intentionally invalid profile must return nonzero without that sentinel;
   missing output or a generic child crash is insufficient. This case acquires
   no canaries. There is no unsandboxed fallback after invalid activation.
3. **Inside and outside direct children.** For both PID and PGID, same-domain
   inside canaries must acknowledge sequential SIGUSR1 and die from the one
   intended KILL. Pre-activation outside canaries must not receive either signal.
   Require EPERM/access denial, unchanged counter and a fresh control response
   after each negative attempt. Outside canaries must still be able to read the
   marker, distinguishing their real domain from a retroactively inherited one.
4. **Effective domain identity.** Pre-create canaries under independently
   activated identical and different-enforced-marker profiles. Measure actual
   allowed/denied delivery to each from the now-sandboxed same owner. Require
   different effective domains to reject cross-signaling. Record identical-
   profile equivalence as an observation, not a pre-assumed answer or general
   invocation-isolation guarantee. All these targets remain its own children.
5. **Mixed group per-member proof.** In a target group containing an outside
   reserved leader and same-domain inside member, SIGUSR1/KILL must reach only
   the inside member. Repeat with a different-effective-policy outside leader.
   Keep the leader reserved throughout. Inspect each actual receipt/status;
   a successful group return cannot imply that excluded members were protected.
6. **Absent-fence control.** Under an explicitly declared no-signal-fence
   policy, the same owned outside-style canaries must receive the signals and
   cause the isolation oracle to reject that environment. This is expected
   control rejection, not authorization for unsandboxed project testing.
7. **Lifecycle controls.** Cancel before signal dispatch and after readiness,
   before the final exec block/check, while blocked just before exec, pending
   across actual exec, after new handler installation and at mask restoration.
   Preserve the original cutoff and assert that delaying across exec cannot
   reset it. These are real own-sender injections with zero subsequent canary
   dispatch, not a mocked cancellation flag. Inject malformed readiness and
   an early actual canary exit. Require zero
   subsequent dispatch, real ECHILD/reaped revocation where applicable, private
   EOF/join cleanup, and no false success. Inject a pre-exec launch failure:
   close/join owned children without historical-PID signals. Cases that never
   reached valid readiness cannot satisfy any delivery or containment oracle.

Install/unblock SIGUSR1 handlers before ready. Use sequential command IDs and
fresh counter responses after each signal; do not infer denial from missing
output, signal coalescing or signal0. Actual KILL status is observed only after
all dispatch for that identity/group is revoked. KILL-denied canaries must
answer a fresh request before EOF exit. A helper can report an expected failure
as a successful *negative test*, but retain its raw failed operation separately.


## R2-R3 exact custody and dispatch contracts

Before acquisition BOTH the outer controller and each owner explicitly call
`signal.signal(SIGCHLD, SIG_DFL)` to establish normal waitable delivery (clear
SIG_IGN/SA_NOCLDWAIT), not merely display `getsignal`. The post-exec owner repeats
that operation before any further acquisition. Reconcile the installed interpreter
implementation/system contract and prove actual waits in the early-exit control.
Retain every Popen object strongly until all signal authority for that child/group
is irrevocably revoked; do not invoke poll/wait, drop a handle, or allow subprocess
`__del__`/`_active` cleanup during the signal-authority window. A direct wait that
returns a status records that real reap, marks the retained handle's returncode,
and revokes all authority before any later path can reach dispatch. No threads,
wait-all calls or detached waiters exist. Across exec only same-process direct
children/descriptors carry forward; new actual `waitpid(WNOHANG)==0` checks remain
mandatory. The outer controller follows the same rule for cancellation injection
into its sole sender; it never dispatches to canary IDs/groups.

Dispatch has one explicit authorization point immediately before the native
signal call. Block INT/TERM, check prior flags and actual pending signals, verify
the original cutoff and the direct-child reservation, then authorize that one
bounded call. An already-authorized syscall can race a newly arriving external
cancellation; do not claim to retract a syscall atomically with arbitrary external
signal delivery. After restoration/flag observation, cancellation revokes every
later dispatch. Cancellation tests pause at named phase/ack barriers BEFORE the
next authorization point, inject into the actual still-unreaped sender, and require
zero subsequent canary dispatch. The pending-through-exec row deliberately queues
cancellation with the mask blocked after the final pre-exec checkpoint, then proves
it remains pending at post-exec entry. It cannot become a passing operation.

Both levels disable future dispatch before cleanup. All owned writer closes occur
in finally even after expiry/cancellation. EOF/actual wait are the only canary
cleanup; neither layer signals historic IDs or orphan groups. Halt ALL remaining
rows on unresolved sender/canary state. Closing an outer control pipe is not proof
that grandchildren joined. A missing final owner cleanup report is unknown unless
this row acquired no canaries and actual owner reap proves that bounded no-child
path. Never infer quiescence from30s self-expiry or start another sender afterward.
Known clean expected-negative rows may proceed; unexpected execution/ownership/
policy failures stop further rows and preserve raw evidence and unexecuted entries.

## Immutable row and resource ledger (SFPR-05)

The reviewed code must contain exactly this ordered row list. `S` is one actual
outer-owned sender acquisition (pre/post exec retains that same PID). `C` is the
number of actual direct-child canary acquisitions by that sender. All are retained
sole-waiter objects/records. Each row has one30s work cutoff and at most10s EOF/join
cleanup, both bounded by the original180s overall experiment cutoff. There is no
per-phase deadline reset. Do not start a row unless at least40s remain globally;
otherwise record a failed incomplete experiment and remaining rows UNEXECUTED.
The cutoff-carry row reserves its actual30s elapsed work, not a mocked clock.

| Row | Exact case | S | C | Required observation |
| --- | --- | -: | -: | --- |
| 01 | plain-activation | 1 | 1 | No-sandbox exact post child sentinel; same existing marker readable; actual canary handshake and EOF/join |
| 02 | invalid-profile | 1 | 0 | Actual sandbox launch nonzero; proven-working exact post sentinel absent; no fallback/no canaries |
| 03 | missing-marker | 1 | 0 | Actual ENOENT rejected by activation oracle; raw failed operation retained |
| 04 | wrong-marker | 1 | 0 | Existing alternate marker read succeeds and fails expected-denial oracle, not a false fence pass |
| 05 | fence-pid | 1 | 2 | Outside PID USR1/KILL denied and fresh response; inside PID sequential USR1 delivery and actual KILL |
| 06 | fence-pgid | 1 | 2 | Same proof for private standalone PGIDs, each with actual reserved leader |
| 07 | identical-domain-pid | 1 | 1 | Pre-created independently identical-policy child; actual allowed/denied equivalence recorded, never presumed |
| 08 | identical-domain-pgid | 1 | 1 | Same independent-domain observation for PGID |
| 09 | different-domain-pid | 1 | 1 | Pre-created different-marker-policy child must reject cross-domain PID signals and remain responsive |
| 10 | different-domain-pgid | 1 | 1 | Same different-domain denial for PGID |
| 11 | mixed-plain-leader | 1 | 2 | Outside reserved leader and inside member: member USR1/KILL only; per-member receipts/status |
| 12 | mixed-different-leader | 1 | 2 | Different-policy outside leader and inside member: same per-member proof |
| 13 | no-fence-pid | 1 | 1 | Real outside-style PID USR1/KILL succeeds and isolation oracle rejects this environment |
| 14 | no-fence-pgid | 1 | 1 | Equivalent required negative fence control for PGID |
| 15 | cancel-ready-int | 1 | 1 | INT after real pre-exec readiness; observed prior flag; no exec/canary dispatch |
| 16 | cancel-ready-term | 1 | 1 | Same ready boundary with TERM |
| 17 | cancel-preblock-int | 1 | 1 | INT immediately before final mask/block/check; handled flag not lost |
| 18 | cancel-preblock-term | 1 | 1 | Same preblock boundary with TERM |
| 19 | cancel-blocked-int | 1 | 1 | INT after block, before final pending check; actual pending observed, no exec/dispatch |
| 20 | cancel-blocked-term | 1 | 1 | Same blocked boundary with TERM |
| 21 | cancel-exec-int | 1 | 1 | INT queued after last pre-exec check and carried pending across actual exec; same PID/cutoff/mask, no dispatch |
| 22 | cancel-exec-term | 1 | 1 | Same actual exec handoff with TERM |
| 23 | cancel-handler-int | 1 | 1 | INT after new handlers installed, before unblocking; actual pending/flag, no dispatch |
| 24 | cancel-handler-term | 1 | 1 | Same installed-handler boundary with TERM |
| 25 | cancel-restore-int | 1 | 1 | INT queued at restoration barrier; real unblocking delivers flag before dispatch |
| 26 | cancel-restore-term | 1 | 1 | Same restoration boundary with TERM |
| 27 | cancel-predispatch-int | 1 | 1 | INT after valid restore immediately before authorization; no target dispatch |
| 28 | cancel-predispatch-term | 1 | 1 | Same predispatch boundary with TERM |
| 29 | cutoff-carry | 1 | 1 | Real hold across exec reaches original30s cutoff; no fresh deadline or dispatch; failed raw outcome |
| 30 | malformed-ready | 1 | 1 | Wrong-nonce/invalid readiness rejected before dispatch; actual owned EOF/join |
| 31 | early-child-exit | 1 | 1 | Real child exit/reap revokes identity; actual returned status/ECHILD; zero target signals |
| 32 | exec-failure | 1 | 1 | Real nonexistent executable exec fails after acquisition with mask held; original error/EOF/waits/restoration retained |
| **Sum** | **32 fixed invocations, no retries** | **32** | **33** | **65 process acquisitions maximum; fixed96-attempt cap includes failed acquisition attempts** |

USR1 attempts are sequential with fresh command IDs/counter responses; record both
USR1 and KILL outcomes on each relevant target. For same-policy independent domains,
allow and deny are both empirical classifications only when actual per-signal errno,
response/status and activation proof agree. Inconsistent/unknown results fail.
Outside/different-domain/fenced mixed leaders MUST be denied, not classified away.
No-fence rows have an exact expected negative oracle rather than accepting arbitrary
errors. Their raw isolation evaluation remains FAIL while the expected-negative
regression envelope can PASS. Invalid/missing/wrong/negative lifecycle controls
likewise require their specific actual outcome plus complete cleanup, never just
some nonzero exit.

Canary configurations are static table entries: ordinary ready, wrong-nonce ready,
ready-then-exit. Rows with no canaries use the exact early post sentinel/read oracle
and must not acquire one incidentally. Rows29/31 still carry an actual child across
exec where specified; all direct-child reaps are retained. The invalid-profile row
is deliberately early so unsupported sandbox grammar stops applicability assessment
without a general fallback; expected syntactic rejection itself is not evidence
that the valid profile works. No signal occurs until real activation is proved.

Fixed protocol limits from above apply to carrier and raw output as well as normal
control messages. Partial/duplicate/oversized events fail closed. Every actual
acquisition/exec attempt records its immutable row/role before fallible publication;
full stdout/stderr and real exit status remain separate from summary/oracle fields.
Environment is a declared clean allowlist; no environment dump, user credential
read, network or application/production capture is involved. On partial acquisition
before exec, the same owner retains cleanup duties; no later row shares resources.

## Verification sequence and remaining obligations

Obtain independent exact-plan approval; implement the small static experiment;
obtain distinct actual-code safety review before execution; run the reviewed
experiment once in a new owned namespace; independently reconcile raw evidence.
Policy/script corrections require a new reviewed revision, not a permissive retry.
This is preparatory verification, not a project/full-gate execution.

Preserve all original R1 requirements in a coverage table: inherited fork/exec/
grandchild senders, actual Ruby/Open3 acquisition/waiter lifecycle, changed
sessions, post-interpreter-exit descendants, native tool/service compatibility,
full source/wheel runner confinement, cancellation/hard-loss cleanup, and hosted
Linux/macOS gates. They remain unverified and require safe follow-up design.
Do not signal those auto-reaped intermediate nodes or claim this direct-child
phase exercises them. SFPR-02 is resolved here by explicit exclusion and role
clarity, not by deleting its future obligation or replacing Open3 behavior.

Retain script/profile/marker/raw/result/ownership hashes and cleanup manifests.
Remove only this experiment's exclusively owned inventoried scratch after actual
joins and evidence retention; preserve unknown worker/state evidence. No source,
AGENTS, shared cache, existing venv/worktree, old failure or other task resource
may be modified/deleted. No build processes are needed.

Even complete phase success authorizes neither full suites nor closing QA-006
or QA-007. Obtain a separate reviewed complete-isolation launch contract first.
If denied/ambiguous, keep NOT READY and the unanswered hosted authorization
or a reviewed VM alternative. All original remediation, final comprehensive
audit, further confirmed fixes, protected delivery and feature report remain.

**Authoring outcome:** this new ignored proposal only; no implementation,
sandbox/process experiment, signal, build, VM, Store mutation, commit or push.
