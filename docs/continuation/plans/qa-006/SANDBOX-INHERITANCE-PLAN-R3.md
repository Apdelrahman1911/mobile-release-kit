# QA-006 — inherited signal-fence feasibility plan R3

**PROPOSED; independent plan review and a distinct actual-code safety review
are required before execution.** No first-party change, production capture,
full suite, Store operation, commit, push or general launch authority follows.

## Evidence, root cause and scope

QA-006's remaining real native/adapter checks reach the unchanged QA-007 runtime
ownership defect. Native capture can request a group KILL after Open3's detached
waiter has released its numeric identity. Such paths must not run unrestricted
on this shared Mac. The tests-only R6 fix is still INCOMPLETE_VERIFICATION.

The primary experiment ran once under independently approved code:32 cases,
9 positive plus23 exact expected-negative, actual outer exit0. Its original
nonzero signals targeted only each sender's own still-reserved direct children.
It measured actual PID/PGID denial outside the sender's sandbox, same-domain
delivery, mixed-group handling, cancellation and exec continuity on this host.
Independent recorded-results decision SHA256:
`2951408891c3f1a92d2f5524cbf91f716e322b4059b59e802d468c34628c030c`.
That authorization is consumed; this proposal does not rerun it.

Still missing are real fork/exec, Python, Ruby/Open3 and multi-hop inheritance,
session changes, and survival of the restriction after an intermediate parent
dies. R3 measures those particular boundaries with fixed synthetic programs.
It does NOT execute the unsafe production capture, rely on a guessed PID,
or recreate R1's unsafe delegation of nonzero signals to another owner.

The installed sandbox documentation describes inheritance but calls the policy
private/deprecated. Retain exact host, interpreter, shell, Open3, interface,
policy and script hashes. Host-specific observations are not a platform-wide
guarantee. The allow-default policy is not credential/filesystem/network isolation.

## Central safety change: outside probes cannot stop a process

An inherited sender cannot be the kernel parent of a pre-existing outside
recipient. Therefore **no inherited sender receives authority for a nonzero
signal to such a recipient**. Use two deliberately separate operations:

1. `query_external`: a fixed syscall with signal number **zero**, for one
   root-owned outside canary's positive PID and its private negative PGID.
   Zero checks permission/existence; it does not deliver a stop/termination
   signal. This function has no caller-supplied signal argument, fallback or
   route to a nonzero operation. An outside scalar ID is never an owned-child
   object. No result of this query authorizes later signaling or cleanup.
2. `exercise_owned`: real USR1 then terminal KILL to a canary acquired directly
   by this same final sender. Use its actual handle and sole-waiter reservation,
   not the external ID or a readiness message. All final senders are single-
   threaded Python; they do not detach, auto-reap or signal historical IDs.

The outside canary is a real direct child of the root controller, in its own
group and outside the sandbox, with the same UID. Root keeps it unreaped and
observes its actual control responses before/after permission queries. It is
stopped only through its original private EOF, then actually waited. If root
dies unexpectedly, the remaining sender possesses only a zero-signal query;
it cannot damage a recycled recipient. A nonce is a protocol binding, not PID
authority. Never use zero,minus1,PID1,unknown groups or process-name targets.

This phase explicitly measures **permission probes**, not inherited KILL
delivery against an outside recipient. The separate complete-launch review
must assess the combination of primary nonzero-signal evidence, actual policy
inheritance, marker denial and these permission probes. It must not silently
equate signal0 with every nonzero delivery path. If this evidence is insufficient
or the kernel exempts signal0, retain an INCONCLUSIVE/FAIL outcome and pursue a
separately reviewed stronger isolation option; do not broaden the profile.

## Fixed policy and noncircular oracles

Use the primary policy bytes with only the current owned literal substituted:

```scheme
(version 1)
(allow default)
(deny signal (require-not (target same-sandbox)))
(deny file-read-data (literal "<owned-marker>"))
```

The two declared no-fence controls omit only the signal rule, retaining the
same marker-read rule. No other permissive retry or fallback is permitted.

- Before launch, root and its outside canary must read the actual ordinary-
  permission marker bytes successfully. Each inherited final sender must fail
  that read with actual EACCES/EPERM, not ENOENT or an arbitrary exception.
- A fenced final sender must receive EPERM from both zero-signal permission
  queries, while root proves the exact outside canary is still responsive in
  its original private group and can still read the marker.
- A no-fence sender must succeed at the same queries; the isolation oracle must
  reject that environment. Marker denial alone cannot count as a signal fence.
- The sender's own positive-control child must receive real USR1 by PID and PGID
  with distinct acknowledgments, then the one intended group KILL with an actual
  signaled wait status. EOF fallback cannot satisfy the production-like oracle.
- Root/relay/sender identity, session/group changes, actual parent exit/wait,
  stream EOF, byte limits and retained statuses must agree with the chosen row.
  Do not accept an output footer in place of actual outer completion/cleanup.

All nonzero targets are registered actual directly owned children. Immediately
before a nonzero signal the sole waiter must observe waitpid(WNOHANG)==(0,0),
with no intervening automatic/other reaper. Death after that check leaves an
unreaped reservation. Revoke dispatch before reaping; terminal signal permits
no later nonzero fallback. Parent-controlled EOF and fixed expiry remain the
independent containment path if any assertion fails.

## Exact finite route matrix

Every row creates one outside root-owned canary and one final-sender-owned
positive-control canary. All argv/programs/modes come from this fixed table;
there is no arbitrary command, shell expression or environment input.

| Row | Actual inherited route / loss boundary | Process acquisitions |
| --- | --- | ---: |
| direct | sandbox-exec → Python sender | 3 |
| python-child | sandbox-exec → Python relay → Popen sender | 4 |
| python-new-session | same, actual start_new_session=True for sender | 4 |
| ruby-spawn | sandbox-exec → Ruby relay → Process.spawn sender | 4 |
| ruby-fork-exec | sandbox-exec → Ruby relay → actual fork/exec sender | 4 |
| ruby-open3 | sandbox-exec → Ruby relay → Open3.popen3(pgroup:true) sender | 4 |
| multi-hop | sandbox-exec → Python relay → fixed Bash exec relay → Ruby/Open3 → sender | 5 |
| parent-exit | Ruby/Open3 sender proceeds after its relay's actual normal exit | 4 |
| parent-kill | Ruby/Open3 sender proceeds after root kills/reaps only its own live relay | 4 |
| no-fence-direct | Direct route under declared no-signal-rule policy; expected oracle rejection | 3 |
| no-fence-multi-hop | Complete multi-hop under same declared control; expected oracle rejection | 5 |
| **Total** | **11 immutable rows; no retry** | **44** |

For the two parent-loss rows, root retains its actual direct Ruby-relay handle;
it alone waits or sends a terminal positive-PID KILL to that still-reserved
handle. It never signals the grandchild sender or the relay's historical group.
The sender has a private root-control reader carried through explicit descriptor
allowlists, so relay death does not close root's sole control writer. Open3 stdin
is not misrepresented as that independent control. The sender must observe its
actual parent change before querying/creating the positive-control child.

Root cannot waitpid an orphaned sender. Record that limitation accurately:
require its final complete child-wait report, real EOF, and bounded read-only
absence observation of its previously recorded exact PID. Use only explicit
`/bin/ps -p <that PID> -o pid=,ppid=,pgid=,stat=`; no command lines, environment,
whole-system scan, signal0-as-cleanup or guessed-ID stop. At most three2s queries
per parent-loss row. An extant/reused/ambiguous row blocks completion and retains
evidence; do not call it a successful direct wait or signal it.

The44 route acquisitions plus at most6 observation queries fit a hard64 total
acquisition-attempt cap. Failed attempts count before dispatch. Charge every
explicit exec transition separately under a hard96 cap, including sandbox,
fixed Bash/Ruby exec and failed exec attempts. Actual-code review must reconcile
the exact per-route acquisition/exec ledger before approving execution; no
unlisted helper/tool/version subprocess is allowed inside this run.

## Owned lifecycle, limits and failure handling

Use new ignored `QA-006/sandbox-inheritance-r3/` only: fixed Python controller,
protocol/canary/sender, Python/Ruby/Bash relays, policy/marker files and bounded
raw results. Reuse reviewed ideas, not an old run's authority/resources; preserve
all primary scripts, snapshots and raw outputs. The outside canary writer is
never inherited by relays/sender/inside canary. Explicit pass-fd allowlists and
CLOEXEC protect every other descriptor; no sibling can keep a control writer alive.

Install flag-only INT/TERM handlers before acquisition. Publish each returned
handle/descriptor before a fallible checkpoint, do not asynchronously raise
through acquisition, and stop dispatching on cancellation. Relays must drain
both output streams concurrently, retain actual Open3/Process::Status values,
and close their sole owned control channels before bounded joining. No Ruby
Thread object, waiter.pid or file record grants additional signaling authority.
Root control EOF/cancellation makes senders stop work, close controls and reap
their own positive children. Relays never send group KILL as fallback.

One carried30s work deadline per row,10s additional owned disposition allowance,
one180s outer cutoff,64KiB per output stream,4KiB chunks,2MiB aggregate captures
and8MiB new evidence. No phase/exec resets a deadline. Workers self-expire within
the original row window. At most five owned descendant processes are live in
the largest route (plus the controller); queries occur after route disposition.
Stop on first unmatched failure, missed limit or unknown resource; later rows
remain UNEXECUTED. Retain the original error, secondary close/wait errors and
actual partial acquisition/accounting separately. No guessed cleanup syscall.

Preparation/static proofs must reject malformed/duplicate/wrong-nonce records,
unauthorized external nonzero dispatch, wrong ownership object, reaped identity,
bad argv/route/policy hashes, exceeded time/count/byte limits and wrong expected
control outcomes. Actual-code safety review must inspect entry, publication,
EOF, cancellation, implicit Open3 join and hard-parent-loss windows. If it needs
additional runtime failure-injection rows, revise this explicit matrix/caps
before execution rather than making ad-hoc calls afterward.

No network, Store/credential/keychain access, application check, build process,
service launcher, AppleScript/XPC/daemon or production capture call is part of
this phase. Supply fixed nonsecret environment, private HOME/TMPDIR, pinned
absolute tool leaves and explicit argv. No final-verifier import or mutation.

## Review, cleanup and subsequent work

1. Independently approve or correct this exact plan before implementation.
2. Implement only the ignored fixed scripts; syntax/pure checks are not execution
   authorization. Have a different agent review the actual scripts and finite
   matrix before any native launch or permission/signal probe.
3. After approval, execute once into a fresh exclusive result directory and retain
   actual commands, OS/tool/script/policy/input hashes, every syscall result,
   control response, wait/EOF/absence observation, raw streams and outer exit.
4. Independently reconcile results. Claim only what actually ran; distinguish
   expected no-fence rejection, denied zero-signal probes, positive local signals
   and non-direct orphan observations. No primary rerun or full-suite approval.
5. Close/join only owned workers. Archive required input bytes and disposition
   records before removing exclusively owned inventoried scratch. Preserve any
   ambiguous resource, source/user/index/AGENTS bytes, existing evidence and
   other-task caches/worktrees. No process-name or bulk cleanup.

Even successful R3 leaves the complete source/wheel/native-tool/service launch
contract, comprehensive wrapper failure/cancellation behavior and hosted checks
outstanding. Ignored-verifier R4-R2 acceptance is a separate prerequisite.
QA-006/QA-007 still require their complete fixes/reviews/tests/protected delivery;
all remaining findings, the fresh whole-repository audit and feature report remain.

**Authoring outcome:** proposal only. No implementation, worker/native launch,
signal/permission probe, source edit, Store action, commit or push occurred.
