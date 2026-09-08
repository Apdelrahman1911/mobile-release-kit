# QA-003 implementation plan — R2 (PROPOSED; no implementation authorization)

Supersedes R1. Preserve its sound invariants/tests except where explicitly replaced
below. Inputs: original FINDING.md; R1 independent review (bf90b03e...); current
2beb373/tree00f3acee; current-source overlap and process-descendant reproductions.
No production file has changed. No Store operation or real credential inspection.

## Root cause and scope

Per-invocation cleanup is not a lease over account-global signing preferences and
profile users. Also, direct-process exit does not end an owned descendant's use.
Fix the entire cooperating signing lifetime, not only an installer syscall.
Implement a private account lease, write-before-use recovery protocol, observed
conditional cleanup and contained synchronous commands. Keep all issuer, expiry,
fingerprint, artifact, Store, receipt and provenance validations unchanged.

The process probe actually synchronized child startup before timeout in BOTH
`credentials._run_private` and `ios._run_checked`; both returned an error while
the child continued updating its fictional heartbeat. Both children then exited
on their exact owned stop files, before fixture deletion. This is a connected
lease-lifetime problem to fix here, not a new accepted exception.

## 1. Account admission at the actual consumer

New `local_signing.py` implements `SigningLease` and `local_signing_lease(...)`.
Default production admission is macOS, non-root, equal real/effective UID, real
password-database home, no conflicting HOME override. Native subprocess HOME is
explicitly that canonical account home. No CLI override of account/lease paths.
Existing private `home=` is retained only as a synthetic-testing seam; it cannot
be selected by consumer configuration or environment.

Use a persistent `<account-home>/.mobile-release-signing/` private directory as
the flock inode; never remove/recreate it in normal operation or recovery. Open
home and children descriptor-relatively, no-follow, validate owned directory/mode,
identity and namespace; exclusive nonblocking flock. Validate before/after acquire
and before mutations. Bound directory enumeration and reject unsafe/unknown state.
No PID takeover, no busy waiting. Supported production storage is local APFS/HFS+;
a Darwin `fstatfs` call through the fixed system library checks MNT_LOCAL and type.
`statvfs` DOES NOT expose MNT_LOCAL (confirmed by SDK header), so don't guess its
flags. Probe ABI/sizeof/offsets against a tiny credential-free C helper in native
and wheel tests; unsupported platform/filesystem/ABI fails before native work.
Flock behavior is tested with real same-process, thread and separate-process FDs.

For `preflight(mode='signing', run_builds=True)` selecting enabled iOS, acquire
one lease at the OUTER public entry before calling the existing cheaper/private
validation or project/native commands. Rename the existing body to an internal
helper; pass the lease explicitly through materialization/signing and iOS build.
A busy/pending session returns a fixed actionable FAIL report without running
profile authentication, P12 extraction, project checks or builds. Do not acquire
this global lease for Android-only, offline, Store-only or signing --skip-builds:
those paths do not install/global-activate signing state. Retain their validation.
Direct `_temporary_apple_signing_environment` acquires its own lease when none was
explicitly supplied; an active lease permits only one signing context, preventing
nested borrowing of an installed profile. Borrowed contexts never release their
outer holder's FD. Actual preflight busy regression must prove the boundary.

FDs are noninheritable, but raw fork is separate: maintain a private weak set of
live leases, register an after-fork-child hook that relinquishes/closes the child's
inherited descriptors WITHOUT LOCK_UN, clears child ownership and never restores
parent preferences. Every method also rejects PID/thread ownership mismatch.
Test the parent remains locked and a surviving fork child cannot retain/adopt the
lease after the parent ends. No unrelated process is signalled.

## 2. Cancellation and process execution

Keep the existing CleanupScope two-level try/with/finally and claimed-once close
rules. Add `borrow_or_create_cancellation` that recognizes only exact installed
bound DefaultCancellation methods from this module, same thread/PID, consistent
owners. It either borrows that actual guard or returns a fresh default-only guard.
Never borrow a custom handler or a main-thread owner into a worker thread. Mixed
owners fail before resources. The full lease owner installs/owns its guard; nested
profile readers/authenticators/installers/process runners explicitly borrow it.
Extend read_profile_bytes/authenticate_cms/decode/load with optional cancellation
while preserving standalone behavior. No generator-wide deferral; a cancelled
setup must never yield into a build. This is NOT a claim QA-004 is closed: its
outer scratch/client-file ownership and independent restoration still need their
own complete remediation/review after this issue.

New internal `owned_process.py` supplies bounded synchronous process execution for
`_run_private` and `_run_checked`. Use trusted `sys.executable -I -S -B` bootstrap
with an explicit toolkit source path, not application imports, and a fresh session/
process group. Command/request is bounded private stdin IPC, never printed or put
in supervisor argv; native env/cwd are explicit and restricted as currently scoped.
This helper introduces no Store credential capability or third-party dependency.
Before sending the request, an optional session observer persists the worker group
PID under the already durable inflight operation. A child cannot start the actual
command until that handoff succeeds. No lease FD is inherited across exec.

The fixed supervisor independently checks actual parent identity/liveness and a
monotonic deadline during request IO, command execution and result emission. Native
command/descendants inherit its group. Input/output use nonblocking bounded IO:
<=2MiB request, <=2MiB combined native stdout/stderr (discard output in build mode),
finite timeouts/cleanup, a complete framed private terminal result carrying native
exit code and bounded bytes. Stop collection on overflow, not after unbounded PIPE
buffering. At direct-command termination emit a complete result only after exact
checks, and unconditionally SIGKILL its OWN group (including itself) in finally,
like the reviewed profile supervisor. Parent accepts only complete frame, expected
supervisor terminal signal, deadline, reaped leader and observed group absence.
On timeout/cancellation/IO/spawn/output failure, parent attempts exact group cleanup
and confirms absence with a finite ESRCH/reaped-leader protocol. No broad pkill,
no securityd/Xcode service/Gradle/shared-worker termination. Frame authenticity is
private trusted-child IPC, not Store evidence or crypto authority.

Return terminal native nonzero exits distinctly from missing/ambiguous completion.
Ordinary failures with complete terminal results allow safe reconciliation; absent
completion retains inflight state. No nonzero readback or current snapshot is proof
that an ambiguous asynchronous native request ended. Signing observers journal
before all credential-native and prepare/archive/export commands while active;
record operation kind and worker before command dispatch, clear inflight only after
confirmed process/group completion and its valid observed resource checkpoint.
No blind retry of a native mutation. Read-only queries may be retried on a fresh
recovery invocation, not replayed within failed cleanup.

Catchable signal at/after a completed mutation defers through durable ownership
checkpoint, then cancels setup/body and performs normal cleanup. Signals inside a
long-running native call are interruptible: actual owned workers are reaped; if
native completion is ambiguous, preserve the session/profile/keychain for explicit
recovery. Cancellation between commands, at file acquisition, handoff, normal body
and cleanup entry/dispatch continues to clean normally. Do not quarantine every
ordinary signal. A native command that may have queued work in an OS-owned service
requires owner-confirmed quiescence after ambiguous completion; no group mechanism
claims to kill or control that service. Detached application background daemons/
setsid escapes and hostile same-UID peers are outside the supported synchronous
build contract and are explicitly prohibited, not claimed contained.

## 3. Durable session model (replaces R1's underspecified single mutable record)

All writes/cleanup hold the account lock. Private on-disk layout:

```
.mobile-release-signing/                 # persistent lease inode, never delete
  session-<32 lowercase hex>/            # one owned session, mode0700
    intent.json                         # immutable committed write-before-use intent
    intent.pending                      # exclusive staging, never authoritative
    state.json                          # latest mutable observed checkpoint
    state.pending                       # exclusive update staging
    keychain/                           # owned mode0700 immutable directory identity
      signing.keychain-db               # native-mutable database identity
      .fl<8 uppercase hex>              # exact source-derived native local lock name
```

Allocate/register every handle and ownership before use with the shared guard.
Capture session/keychain directory identity; commit immutable intent before ANY
profile or keychain mutation. Intent includes exact schema/version/UID/home/lease
and directory identities/session token, baseline full default/search, UUID/profile
SHA256, baseline existing profile identity+hash or absence, reserved random profile
stage name. No P12/key/profile/certificate bytes, passwords or tester/Store values.
Paths are derived from validated token/home/UUID, never arbitrary path strings read
from a journal. One session per account; unknown entries block admission/recovery.

State has strict bounded known fields/revision/session binding, profile stage/link
identity and observed completion, DB/lock identities, last observed complete native
preferences, explicitly attempted activation targets, inflight operation/worker
and cleanup progress. Reject duplicate keys, types including bool-as-int, unknown
fields/version, sizes/counts, identity/path mismatches, symlinks/hardlink controls.
Before each syscall/native dispatch persist the intended transition. For profile
installation add an optional observer and reserved stage name: persist stage intent
before exclusive open, stage inode after fstat and before bytes/link, link intent
before link, installed identity before unlinking its stage. Existing standalone
installer behavior remains protected. Reused preexisting profiles are never owned.

Use exclusive0600 staging, bounded raw full writes, fsync(file), inode-checked atomic
rename under the lease, fsync(parent). Immutable intent never overwritten. A failed
write/checkpoint never authorizes the next effect. Keep surviving previous state
and pending file; do not adopt partial bytes, replace unknown journal stages or
blindly retry ambiguous descriptor close. In-memory known identities may permit
safe cleanup after a failed checkpoint, but leave controls pending unless complete
safe cleanup and final control removal can be confirmed. Clear controls LAST.

Phases/transitions:

| Observed state | Permitted action |
| --- | --- |
| no session | admit a new signed operation |
| session/keychain directories before intent commit | no shared mutation authorized; explicit recovery can remove only verified empty directories and their bounded owned intent staging |
| committed intent, no resource/checkpoint | no shared mutation until initial state committed; recovery uses intent and absent resources, never a new baseline |
| profile installation / native operation inflight | fail new admission; reconcile only under original intent; ambiguous workers/identities require protected manual resolution |
| valid active checkpoint | same holder may build; cleanup/recovery conditional on live identity/current preferences |
| owned resources removed/detached and full observations verified | remove exact owned controls then empty directories, confirm absence and release lock |
| interrupted cleanup/recovery | retain original intent and resume its same predicates, never reconstruct a new session from current state |
| malformed/unknown/replaced namespace | fixed conflict; no native mutation, recursive deletion or force reset |

## 4. Native transitions and observed complete-state cleanup

Read default/search via bounded owned runner, strict full-line quoted parser.
Preserve literal spaces, backslashes and non-ASCII; reject embedded quotes/control,
duplicates, ambiguous lines, nonabsolute paths, counts and lengths. Require one
nonempty default; allow an empty search list (cleanup must support `-s` with zero
paths). Bound failures do not mutate native state. Snapshot both before intent.

Model native DB as mutable inside an immutable owned directory, not one permanent
inode. Completed create/settings/unlock/import/partition-list and active owned build
commands may advance the DB inode via native atomic temp-file+rename. Validate full
BEFORE inventory and directory identity; after terminal completion accept only the
expected regular same-UID/no-hardlink DB and source-derived local .fl file, record
new identities durably, then continue. Unexpected extra native staging on failure
is preserved/pending, not recursively deleted. Existing DB disappearance/replacement
OUTSIDE an authorized operation window is a conflict: no refreshed ownership over
it. The native .fl name is `.fl` + uppercase first4 bytes SHA1 of the database leaf
filename per pinned AtomicFile.cpp; this is filename compatibility, not security
SHA1. Its exact observed identity is tracked; normal delete should remove it.
Native import tests MUST perform real rename replacement, not only in-place writes.

Corrected source attribution: pinned StorageManager.shouldAddToSearchList119–134
currently restricts create-side automatic insertion to login/System. Nonce-path
implicit insertion is a conservative compatibility case, not proven observation.
Still defend against it: after create accept only unchanged complete baseline or
a list with precisely the owned path added without dropping/reordering originals;
nonempty default must remain baseline. Native delete also removes references.

Before each activation compare complete current state to the last expected state,
record target before dispatch, and read back both fields afterward. Retain current
supported isolated active list `[owned keychain]` plus owned default for Xcode.
No conflicting state or failed/ambiguous command may yield a build.

Cleanup only after active owned process completion or explicit recovery predicates:
- If default still points to owned verified path, restore original default;
  preserve any foreign default and report conflict.
- If search still equals this session's exact attempted active `[owned]` target,
  restore original search. Otherwise remove only the owned entry, preserve every
  foreign entry/order and do NOT resurrect historical user-removed entries.
  Recognize baseline/creation-only states without falsely claiming activation.
- Re-read both before each mutation, validate expected full after-state. Changes
  observed during cleanup conflict; don't overwrite a snapshot known stale.
- Only after verified detached preferences and owned current DB identity, invoke
  delete-keychain. Require actual DB absence and complete post-delete settings
  equality. Remove only a residual recorded .fl inode if needed and no native
  worker remains; preserve every unknown file. Never delete a substituted DB.
- Close the installed profile owner independently when processes are known stopped;
  its exact bytes/inode rules and preexisting reuse semantics remain required.
  Preserve uncertain active resources instead of calling their automatic context
  cleanup prematurely. Add an explicit installer retain/quarantine observer path
  for truly unresolved signing consumers; ordinary cancellation still removes it.
- Final errors identify busy/pending/conflict/unconfirmed cleanup without secrets;
  no observed conflict becomes success even if independent cleanup completes.

No API provides CAS across unrelated apps: flock serializes toolkit peers, not
uncooperating native apps. Preserve observed edits, document the unavoidable
read/write race with outside same-UID programs; never use that caveat to excuse
proven toolkit overlap or full-state regressions.

## 5. Concrete owner recovery interface and clearance authority

Add top-level `mobile-release local-signing status` and
`mobile-release local-signing recover --session <32hex> --confirm
account-signing-is-idle-and-restore-owned-state` (actual shell command is one line).
No config, credential, alternate home/root, Store call, build, retry-upload, generic
force/reset or delete-by-PID option. Both validate the real account and acquire the
same lock. Status emits only sanitized session ID/phase/disposition/counts, not
original keychain paths, raw profile data or private credentials; journal stays
local/private and excluded from release reports. Busy status reports busy safely.
Recovery requires exact confirmation/session ID and preserves original intent.

Before ANY recovery mutation require lock, valid owned intent/namespace and process
quiescence: a recorded exact worker PGID must be absent (ESRCH); an existing/recycled
PGID or permission uncertainty rejects, never authorizes killing it. A state with
no durable worker PID could not dispatch a command: supervisor request comes only
after that checkpoint. If intent/state consistency can't prove this, require
protected owner resolution, not that inference. Native asynchronous OS-service
completion after an ambiguous command cannot be proved by PGID; the exact explicit
owner confirmation asserts all signing/build operations are now idle. Explain how
to terminate the owner's exact build normally, wait for its service work, and retry;
never instruct pkill securityd/Gradle/shared services. This confirmation is not inode
ownership: automated deletion still requires the checks below.

With complete known resource identities, run the SAME idempotent conditional
cleanup, no password needed for deleting the owned keychain. It can resume after
cancel/failure between every step: absent resources are acceptable only when that
step's original-owned identity is recorded, not by adopting a foreign replacement.
Preexisting profiles must remain byte/inode-identical; owned stage/link must match
recorded inode+hash. Unknown/newly replaced resources are preserved and reported.

Precisely unsupported automatic cases and owner completion procedure:
- Missing immutable intent: protocol never authorized shared mutation. Recovery
  may remove only same-UID0700 empty recorded session/keychain directories and
  a bounded0600 single-link intent.pending, with no committed state/other entry
  and no current default/search reference anywhere under that session path.
  Unknown content/layout is preserved. Tests cover before/after mkdir/fstat/stage/
  rename; a session with committed intent is never routed through this branch.
- Failed native transaction/checkpoint left DB identity unknown/different, an
  unrecognized native staging file, or an incomplete profile-stage identity: do
  NOT native-delete/adopt the file or remove a global preference pointing to it.
  Status/recovery names the **resource category** requiring owner resolution. The
  documentation directs the owner, under this same live lock via a protected
  `local-signing recover ... --manual` session, to inspect the exact private paths
  locally, retain/move unfamiliar files, restore/detach only this session's native
  preferences using Keychain Access, and remove/move only independently identified
  abandoned resources. `--manual` opens no shell and runs no arbitrary command:
  it prints local-only owned paths and waits for an exact `recheck <session>` line
  on a TTY (no environment auto-confirm); lock remains held during owner work.
  On recheck perform the same bounded validation. No journal editor/delete request
  is ever a clearance criterion. Unknown paths remain refusal; controls clear only
  when no session native files/default/search references remain and profiles are
  either recorded unchanged preexisting resources or recorded owned resources
  absent after owner resolution. An unknown profile-stage identity may be resolved
  by its exact reserved stage+destination both absent, never by digest adoption.
- Corrupt/unknown intent/foreign nonempty session directory: no automatic or manual
  command mutation; retain evidence and have the owner use an isolated fresh OS
  account/runner pending toolkit-supported forensic recovery. This is data damage/
  unsupported format, not the normal crash cases above; don't say deletion is safe.

`--manual` is optional exceptional recovery, not required for successful native
signing/catchable cleanup. In unattended/non-TTY execution it refuses. Its terminal
input contains only a fixed token, no shell evaluation. Recovery cancellation holds
cleanup ownership, leaves pending state, releases only its own lease and never
half-clears controls. No generic `rm -rf` command in docs. Tests drive the underlying
recheck context with a synthetic TTY seam and genuinely execute all predicates,
including a second process being refused throughout manual inspection.

## 6. Tests, compatibility and delivery

Retain R1 behavioral list, PLUS explicit critical cases:
- full CLI preflight same-account busy before native/authentication, independent
  projects/UUIDs, reverse exit, process/thread/fork, no-build/Android/Store exclusions;
- real DB rename and .fl lifecycle, terminal failures after effect, extra staging,
  journal after-rename/fsync faults, substitutions outside native windows;
- production recovery from every phase, including no intent, stage/link crash,
  active checkpoint, native failure, cleanup failure/cancellation; recheck under
  held lock after exact owner resolution; wrong token/confirmation/TTY/namespace;
- real supervised descendants using startup rendezvous, normal parent exit,
  timeout, signal, parent hard-kill, surviving pipe writers, overflow, truncated/
  forged private frames, cleanup permission faults; assert dead-before-fallback;
- actual signals across lease/profile/capture/materialization consumer handoff,
  acquired FDs, mutation/checkpoint, cleanup dispatch/entry, partial install and
  handler restore; same active borrowed guard, custom/thread semantics retained;
- full before/after preferences (all unrelated entries/order/default), bounded
  parser and unavailable native commands, partial side effects and no false success;
- Darwin filesystem ABI/actual lock tests required in source and installed wheel.

Expected components: new local_signing.py and owned_process.py; credentials.py,
ios_profiles.py, cancellation.py, preflight.py, ios.py, cli.py; tests/synthetic native
helper and process/signal fixtures; required native/wheel gate list; new recovery
document and relevant credential/security/profile-authority/troubleshooting/CLI/
upgrade/changelog guidance. No Store schema/manifest/receipt or workflow authority
change; caller workflow permissions stay identical. Worker-request IPC isn't public
evidence. No Python runtime dependency. Existing command interfaces remain intact;
new busy/pending errors intentionally replace unsafe concurrency.

This revision must be independently approved before production editing. Implement
only approved complete behavior, then distinct implementation review and correction
loop. Freeze exact tree; run all existing35 gates plus new regression/native/wheel
coverage, preserve original failed evidence, clean only owned workers/disposable
outputs. One scoped commit/protected PR/normal merge/main CI, not a bypass. Then
QA-004, MRK-008, MRK-009, fresh all-file/all-path audit and any new defects through
the same workflow. Only a passing final audit permits READY and feature report.
