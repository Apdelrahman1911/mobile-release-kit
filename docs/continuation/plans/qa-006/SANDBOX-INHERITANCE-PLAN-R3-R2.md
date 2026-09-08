# QA-006 — inherited signal-fence feasibility plan R3-R2

**PROPOSED; independent plan review and a distinct actual-code safety review
are required before execution.** No first-party change, production capture,
full suite, Store operation, commit, push or general launch authority follows.

## Revision and review basis

This complete revision preserves R3 and the independent REQUEST_REVISION at
`sandbox-inheritance-plan-review-r3/PLAN-REVIEW.md` (decision SHA256
`467874b00597fd6946b7172dfa36eac6491558a1c66e54a085b103d3433a5a56`).
It resolves SIPR3-01 with explicit no-block normal Open3 parent exit; SIPR3-02
with independent return-channel custody and actual EOF; and SIPR3-03 with a
separately owned bounded observer lifecycle and original-budget admission.
Neither the old review nor this proposal grants execution authority.

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
dies. R3-R2 measures those particular boundaries with fixed synthetic programs.
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

### Open3 status ownership and deliberate parent loss (SIPR3-01)

The ordinary `ruby-open3`, `multi-hop` and `no-fence-multi-hop` rows use real
block-form `Open3.popen3`, nonblocking concurrent stdout/stderr draining and the
actual detached waiter's terminal `Process::Status`. Their relay must return
through Open3's real ensure/join. They cannot claim a complete row before that
wait completes. No detached waiter or remembered sender ID is signal authority.

`parent-exit` uses the real **no-block** `Open3.popen3` form. After the private
handoff below and actual sender stdout/stderr EOF, the relay calls ordinary
`exit(0)` while the sender remains at its parent-loss barrier. It deliberately
does not call waiter.join/value first and does not use `exit!`. Root records the
actual relay exit0; no relay-side sender wait/status or join is claimed. Normal
interpreter termination, rather than return from an Open3 block, is the boundary
being measured. If actual ordinary exit cannot satisfy the deadline, the row
fails; there is no alternate termination fallback credited as parent-exit.

`parent-kill` may retain block form and its normal waiter, but stays at its
loss-ready barrier. Root alone sends the one deliberate positive-PID KILL to its
actual, direct, still-reserved Ruby-relay handle and actually reaps that relay.
The resulting missing relay-side sender wait is intentional and recorded, not
misreported as an ordinary Open3 join. Root never signals the orphaned sender,
the relay's historical group, or any sender ID received through the protocol.

Both loss rows require root's actual relay wait before the final sender is
released, and the sender must independently observe its real parent PID change
from the initially bound relay identity before performing any probes or creating
its positive-control child. That sender still genuinely waits for its own child.

### Independent parent-loss descriptor custody (SIPR3-02)

Root creates two private pipes **before** acquiring the relay: `C` carries
root-to-sender commands; `R` carries sender-to-root acknowledgments/results.
These are not Open3 stdin/stdout/stderr. Endpoints have one fixed direction and
nonce/row binding; only explicit fd-number remapping is permitted, never a path
or arbitrary fd supplied by a worker. The relay receives only the endpoints it
must pass once to the final sender. `close_others`/pass-fd lists and CLOEXEC must
be explicit at every spawn/exec; no positive canary inherits either endpoint.

| Phase/owner | `C` reader | `C` writer | `R` reader | `R` writer |
| --- | --- | --- | --- | --- |
| Root before relay acquisition | pending handoff | root only | root only | pending handoff |
| Relay after actual acquisition | pass once | absent | absent | pass once |
| Root after relay handle publication | closed | root only | root only | closed |
| Sender after real Open3 acquisition | sender only | absent | absent | sender only |
| Relay after sender handle publication | closed | absent | absent | closed |
| Sender's positive-control canary | absent | absent | absent | absent |
| Relay exited/killed | absent | absent | absent | absent |
| Sender terminal disposition | closed | absent | absent | closed after final frame |

All temporary duplicates are registered immediately and closed even if the next
handshake fails. A completed handoff is required before root requests deliberate
relay loss. The relay writes its actual Open3 acquisition PID plus its own
identity to root through its ordinary captured stream. The sender independently
writes its self/initial-parent identity and the exact expected descriptor roles
through `R`. Root compares both nonce-bound records to its real relay handle,
then acknowledges through `C`. A message alone never establishes signal custody.

The loss-row sender writes every protocol/final-wait record through `R`, never
through Open3 stdout/stderr. Before declaring loss-ready it flushes/closes its
ordinary stdout/stderr, and the relay drains both to **actual EOF** and records
that fact before exit or root-authorized kill. No post-parent-death write uses
the relay-owned readers. Root multiplexes `R` and all ordinary relay streams
under the same capture/deadline limits; each stream has its own real EOF bit.
A missing channel, extra inherited writer, stale/duplicate frame, identity
mismatch, EOF without a complete final report, or complete report without EOF
fails the row. EOF is never synthesized by closing root's own reader.

Root retains the sole `C` writer until it has observed the relay's actual exit
and released the sender. Early root cancellation closes that writer; the sender
uses real EOF and the carried expiry to stop and reap its own child. Sender
failure closes `R`; root cannot turn such EOF into success or guessed-PID cleanup.
The result frame must contain the sender's actual terminal child-wait status,
complete signal/marker results and original deadline/row identity. Real `R` EOF
and the scoped orphan observation below are additional conjunctive requirements.

### Bounded read-only orphan observation (SIPR3-03)

Root cannot waitpid an orphaned sender. Record that limitation accurately. After
its complete final report and real independent-result EOF, require bounded
read-only **absence**, not a fabricated direct wait, for the exact sender PID
already bound by both handshakes. Invoke only explicit
`/bin/ps -p <that PID> -o pid=,ppid=,pgid=,stat=`. No command lines, environment,
whole-system scan, signal0-as-cleanup or guessed-ID stop is allowed. At most
three observations per loss row; an extant/reused/ambiguous row cannot be counted
as absent. Preserve actual stdout/stderr/status and distinguish documented empty
selection from parser, execution or permission failure.

Each observer is a new actual direct `QueryChild` of root, with a separate typed
handle, private captured streams, DEVNULL stdin and no relay/control descriptors.
Root is its sole waiter with normal SIGCHLD semantics; no detach/auto-reaper or
Popen finalizer may release its identity independently. **QueryChild PID** and
**queried orphan PID** are different roles and cannot be converted/interchanged.
Charge acquisition and exec before dispatch, publish the returned child handle
before any fallible checkpoint and concurrently drain both bounded streams.
A successful query requires its actual wait/status plus stream EOF.

An observer has a fixed2s work bound and a reserved5s failure-disposition bound,
both inside the original row disposition/outer cutoff. At timeout, root may send
exactly one terminal positive-PID KILL **only to its actual QueryChild**, and
only after its sole waitpid(WNOHANG) returns(0,0). If that call instead reaps a
status or reports ECHILD/uncertainty, revoke all nonzero authority immediately;
never use the historical number. Revoke before actual reap or terminal dispatch,
record the outcome, and finish actual wait/EOF within the reserved5s. No second
nonzero fallback, group signal, observer retry after timeout/failure, or signal
to the queried orphan is permitted. Unknown observer disposition blocks the row
and all following rows; retain errors and evidence rather than guessing cleanup.

A successful query that still observes the exact PID may be repeated only within
the three-query ceiling and if another complete2s+5s interval can still fit the
unchanged disposition deadline. A new query is not a new deadline. Reused or
ambiguous identities fail, not retry. Inadequate time/count/byte reserve rejects
acquisition; retain the unresolved observation honestly. No extra process query
is authorized merely to explain failure.

The44 route acquisitions plus at most6 observation queries fit a hard64 total
acquisition-attempt cap. Failed attempts count before dispatch. Charge every
explicit exec transition separately under a hard96 cap, including sandbox,
fixed Bash/Ruby exec and failed exec attempts. Actual-code review must reconcile
the exact per-route acquisition/exec ledger before approving execution; no
unlisted helper/tool/version subprocess is allowed inside this run.

## Owned lifecycle, limits and failure handling

Use new ignored `QA-006/sandbox-inheritance-r3-r2/` only: fixed Python controller,
protocol/canary/sender, Python/Ruby/Bash relays, policy/marker files and bounded
raw results. Reuse reviewed ideas, not an old run's authority/resources; preserve
all primary scripts, snapshots and raw outputs. The outside canary writer is
never inherited by relays/sender/inside canary. Explicit pass-fd allowlists and
CLOEXEC protect every other descriptor; no sibling can keep a control writer alive.

Install flag-only INT/TERM handlers before acquisition. Publish each returned
handle/descriptor before a fallible checkpoint, do not asynchronously raise
through acquisition, and stop dispatching on cancellation. Ordinary relays must drain
both output streams concurrently, retain actual Open3/Process::Status values,
and close their sole owned control channels before bounded joining. The two
deliberate parent-loss exceptions above do not claim a missing sender join or
status, and their independent result/EOF protocol remains mandatory. No Ruby
Thread object, waiter.pid or file record grants additional signaling authority.
Root control EOF/cancellation makes senders stop work, close controls and reap
their own positive children. Relays never send group KILL as fallback.

One carried30s work deadline per row,10s additional owned disposition allowance,
one180s outer cutoff,64KiB per output stream (including independent `R`),4KiB
chunks,2MiB aggregate captures and8MiB new evidence. Before a row is admitted,
its **full40s** interval must fit the remaining original outer cutoff. Carry
both row endpoints unchanged through every fork/exec; no phase, parent loss,
retry, signal or query renews either deadline. Reject a next row without its
full reserve, leaving it and later rows UNEXECUTED. All synthetic workers
self-expire within their original row work window; `/bin/ps` is explicitly not
such a worker and uses the separately owned disposition above. Parent/child
cleanup uses the original reserved disposition interval, never a new timeout.
At most five owned descendant processes are live in the largest route (plus the
controller); queries occur after route disposition. A query requires its full
7s reserve inside both the original disposition endpoint and outer cutoff,
before charging/acquisition. Failed admission stops; there is no after-cutoff
command, observation, or unbounded wait.
Stop on first unmatched failure, missed limit or unknown resource; later rows
remain UNEXECUTED. Retain the original error, secondary close/wait errors and
actual partial acquisition/accounting separately. No guessed cleanup syscall.

Preparation/static proofs must reject malformed/duplicate/wrong-nonce records,
unauthorized external nonzero dispatch, wrong ownership object, reaped identity,
bad argv/route/policy hashes, exceeded time/count/byte limits and wrong expected
control outcomes. Include no-block versus block parent-loss state, missing/wrong
independent channels, retained extra writers, duplicate/incomplete final frames,
EOF without genuine child-wait evidence, wrong sender/parent identity, expired
row/query admission, observer timeout, reaped/unknown observer handles, and
QueryChild/queried-orphan role confusion. Check every count before dispatch;
reported success never restores spent admission or released signal authority. Actual-code safety review must inspect entry, publication,
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

Even successful R3-R2 leaves the complete source/wheel/native-tool/service launch
contract, comprehensive wrapper failure/cancellation behavior and hosted checks
outstanding. Ignored-verifier R4-R2 acceptance is a separate prerequisite.
QA-006/QA-007 still require their complete fixes/reviews/tests/protected delivery;
all remaining findings, the fresh whole-repository audit and feature report remain.

**Authoring outcome:** proposal only. No implementation, worker/native launch,
signal/permission probe, source edit, Store action, commit or push occurred.
