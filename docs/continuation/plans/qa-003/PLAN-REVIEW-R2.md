# QA-003 independent plan review — R2

**Verdict: REQUIRES CHANGES; not yet implementation authorization.**

Reviewed complete R2 SHA256
`606890bf83d2276d62c5f25a149052550e37a378f6f82b5f9d4be17725582466`
on unchanged main `2beb37336fa8002b69f598fe431082606368310d` /
tree `00f3acee00c994e6e81470cc76e42f1f2108fcdb`.
R2 makes substantial technically sound progress. The remaining corrections below
must be incorporated before approval, not left for unreviewed implementation.

## R1 reconciliation

- **Account scope / real busy entry:** outer signed-iOS-build preflight admission,
  explicit lease borrowing and single-active-context constraint address R1's
  late-admission flaw. Android-only, read-only signing and Store paths retain
  their existing scope.
- **Native DB identity:** immutable owned directory versus checkpointed mutable
  DB identity, source-backed rename/.fl modeling, and preservation of unknown
  staging address the original inode simplification.
- **Worker design:** trusted isolated bootstrap, pre-request PID handoff, bounded
  request/output, complete terminal framing and exact reaped/absent group proof
  are sound. Scope still needs the remaining real preflight callers below.
- **Recovery:** immutable intent, conditional cleanup, explicit owner confirmation
  and locked manual recheck are a practical foundation. Clearance and interrupted
  control teardown still have contradictory/underspecified cases below.
- **Platform:** reviewed actual credential-free Darwin ABI probe/result. C and
  ctypes agree on 2168-byte statfs, flags64/type-name72; explicit fstatfs64 works
  on the tested APFS host. This does not claim private keychain/native signing was
  tested. Initial failed symbol probe is honestly retained.

## Mandatory R2 corrections

### R2-M1 — foreign preexisting profile edits must not permanently prevent clearance

The R2 requirements “preexisting profiles must remain byte/inode-identical” and
clearance only with “recorded unchanged preexisting resources” are incorrect for
resources the session never owned.

Actual current installer reproduction
`plan-review-reused-profile-r2.json` used a synthetic existing profile, entered
the real installer, atomically replaced it with the same bytes at a new inode,
then exited. The replacement was correctly preserved. Recreating the old bytes
cannot restore the deleted original inode.

A session must preserve this external edit, report a conflict and withhold any
claimed successful unchanged signing state, but it cannot demand the impossible
old inode as a prerequisite for finishing all genuinely owned cleanup. Once
owned DB/stages/links/workers/native references are confirmed resolved, safely
finalize with the explicit conflict result; a subsequent new session may snapshot
the new user state. Apply the distinction consistently to preexisting removal,
different-byte replacement and a demonstrably replaced owned destination where
the toolkit's original inode/link is no longer there. Same-inode content changes
and unproven stage ownership still need conservative resolution; do not use this
correction to delete a replacement or silently adopt it.

Add real production-cleanup/recovery tests for all those states, including fresh
admission after conflict cleanup and complete preservation of external bytes/mode.

### R2-M2 — specify recoverable control-file teardown and partial checkpoint handling

R2 promises recovery from every normal crash point, but “remove controls LAST”
does not define which controls, in what order, or the classifier after each
unlink/fsync. Ordinary interrupted state.pending writes can be malformed; they
must not automatically fall into “corrupt/unknown intent → fresh OS account.”
A crash during final control removal can also leave an intent/state/empty-directory
combination not covered by a safe, recheckable transition.

Provide a concrete state/control cleanup order and a table for every cut point:

- partial intent.pending before immutable intent;
- valid immutable intent with missing initial state;
- previous valid state plus complete/incomplete state.pending;
- post-effect checkpoint failure retaining old inflight state;
- interruption before/after each state/pending/intent unlink and directory removal;
- cancellation/fsync/close failure during finalization and during manual recovery.

Specify which record is authoritative, how a known pending stage may safely be
removed without adopting its partial bytes, and how ownership is proven where a
durable inode checkpoint could not yet exist. Controls must not be removed while
any unfinished worker/resource/reference needs their authority. Conversely, a
fully cleaned session must not become permanently unrecoverable merely because
its final bookkeeping was interrupted. “No immutable intent implies no shared
mutation was ever authorized” is not literally true after successful cleanup
starts removing that intent; make the terminal distinction explicit.

Use actual on-disk interrupted layouts and the production recover interface in
tests, not only a modeled refusal predicate. Deliberately corrupted committed
authority remains distinct from routine interrupted staging.

### R2-M3 — propagate ownership across the entire broadened consumer, including fork cleanup

R2 now holds one default cancellation owner across full preflight. Artifact
validation later reaches `ios._profile_payload` → `load_authenticated_profile`
after materialized signing has ended, and early credential validation also calls
load directly. Merely adding optional kwargs to signing's direct calls is not
sufficient: every no-argument profile owner entered under this root must borrow
the exact active owner rather than create a default-only guard. Explicitly update
the safe default and/or complete caller propagation, and test the entire real
consumer path with actual cleanup-entry/acquisition signals.

A fork hook that only closes inherited lease FDs is insufficient. Independent
actual-installer probe `plan-review-fork-profile-r2.json` forks inside an active
profile context and calls its inherited __exit__ in the child: the parent-required
profile is deleted while the parent is still active. The child was reaped and all
fixture resources removed. This is source-backed, not a mocked lease assertion.

PID ownership must protect the actual signing/installer/observer/native-process
cleanup callbacks. Inherited child cleanup may close its duplicate FDs but must
not unlink parent profiles/scratch, alter parent journal, restore global native
preferences or kill a parent's worker group. It must never LOCK_UN a shared
flock description. Test inherited context exits, native/checkpoint callbacks,
child admission and continued parent use together, not only FD-hook behavior.

### R2-M4 — finish the synchronous command map and validate complete native observations

Containing only credentials._run_private and ios._run_checked misses the first
preparation and other application code executed by signed preflight:

- `preflight.py:274–299`: effective identity invokes ios.prepareCommand before
  materialized signing;
- `preflight.py:153,222`: effective Gradle/Xcode identity native commands;
- `preflight.py:747`: project checks.

A descendant from the first preparation can survive its direct parent and run
into a later signing context. Route these applicable synchronous callers through
the same bounded ownership/cancellation runner. Map which operations occur before
a durable signing session and which require its observer, so initial default/
search snapshot reads do not create a circular “need intent to read baseline
needed for intent” dependency. There must be no unjournaled command dispatch once
shared signing resources become active.

Preserve every caller's timeout, output/return-code/error contract and Store/
application credential boundary. Verify success, failure, timeout and cancellation
with actual startup-synchronized descendants at these real entry points. Do not
claim unrelated artifact/native Store validators were changed if they were not.

Also require empty stderr for native default/search observations: pinned
keychain_list.c:52–61 prints SecKeychainGetPath failure to stderr from a void
callback without necessarily changing the command return status. rc==0 plus a
parseable partial stdout list is not proof of the complete search list. Add a
returncode-zero/partial-stdout/stderr-error test and require zero mutations.

Clarify synchronous service compatibility: standard Gradle/Xcode clients may use
shared idle services without authorizing the toolkit to kill them. The prohibited
case is application work continuing to use signing resources after its client
claims completion, not the mere existence of a standard idle daemon. Ambiguous
in-session service completion still retains recovery, requiring truthful owner
quiescence confirmation. Document the limit without silently withdrawing the
supported KMP flow.

## Independent evidence / limitations

Read the revised process-descendant reproduction and its startup-synchronized
results: both existing runners time out while their actual owned descendant
continues writing. The script's exact stop files/reap checks and temporary cleanup
are explicit. No claim of real native Store/keychain execution was made.

New reviewer probes used only actual temporary profile filesystem operations and
one exact owned fork child. The child is reaped; temporary trees and retained FDs
are gone. No real credential, user keychain/profile, application build or Store
was accessed. No production, tests, docs, index or refs were edited. AGENTS.md is
unchanged and remains the sole untracked user file.

A focused textual supplement resolving M1–M4 can be reviewed next. Original R1
approval requirements remain in force where retained by R2. Distinct whole-diff
implementation review, full frozen verification, scoped protected delivery and
the later entire-repository audit are still mandatory. No readiness waiver.
