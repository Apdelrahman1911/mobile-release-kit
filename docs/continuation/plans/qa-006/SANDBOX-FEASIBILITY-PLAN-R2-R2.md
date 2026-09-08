# QA-006 — sole-owner macOS signal-fence feasibility plan R2-R2

**PROPOSED; independent approval required before implementation.** After that,
a different reviewer must approve the actual experiment's safety before it is
run. No first-party code, full native/adapter suite, final verifier, Store, VM,
commit or push is authorized by this proposal.

## Findings and revised scope

This new exact revision preserves the original R2 proposal (SHA256
`daade4a2cfa41d37c4a5e85c28aed62b23049fbf7027dd27ff4748f18da67bc4`).
Its independent review identified a consumed pre-exec INT/TERM flag that could
be lost when exec replaces Python memory. A default-handler interval does not
cover that already handled cancellation. This revision transfers both prior
cancellation and the original monotonic deadline without an unmasked exec gap;
independent exact approval is still required. No original proposal is edited.

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
Python canary, policy/marker files and bounded evidence. There are no authored
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
and four canaries are active, at most32 total launches. Workers self-expire30s
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
