# QA-003 R3 focused supplement — PROPOSED

Read with PLAN-R2 (606890bf...). This overrides its contradictory/underspecified
clauses identified by independent R2 review (ece2fb02...). R1/R2 sound requirements
remain. No production implementation before independent approval of this combined
plan. Main2beb373/tree00f3acee; original finding and all prior reviews preserved.

## M1. Ownership, not historical equality, determines final clearance

A reused preexisting profile is NEVER owned. If changed/deleted/replaced externally,
preserve its current bytes/mode/absence, fail the affected signing attempt with an
explicit conflict, and still finish all independently safe OWNED cleanup. Never
require restoration of its historical inode as a clearance condition. Once owned
workers, native DB/stages/links/references are resolved, finalize with conflict;
a later fresh session snapshots current user state. Recovery has the same rule.

For an actually installed destination, demonstrably different current inode means
the original path was replaced: preserve that foreign replacement, report conflict,
and remove only any other still-owned stage/link. Do not delete/reinstate/adopt the
replacement. Once remaining owned resources are resolved, this also permits final
conflict clearance. In-place modification of the owned inode is different: preserve
it and require owner resolution because the owned file is still present but its
expected bytes no longer match. Unknown ownership at a stage/link cut point stays
pending; exact reserved paths being absent is a valid manual-recheck disposition,
not a reason to guess a new inode. Normal identical borrowing remains successful.

Tests: real inode replacement with same and changed bytes; deletion of preexisting
file; replacement of installed owned path; same-inode edits; preserve exact foreign
mode/bytes and confirm new admission after conflict-clearance. Include normal
cleanup AND production recovery, not only the installer standalone helper.

## M2. Complete recoverable control protocol and every finalization cut point

### Ownership of protocol metadata versus resources

The protected mode0700 session directory is a reserved protocol-metadata namespace
owned under the account lease, not a consumer directory. The known pending control
slots (`intent.pending`, `state.pending`, `completed.pending`) are expressly reserved
before opening them. They may be interrupted at zero bytes/before inode checkpoint.
Their ONLY authority is immutable directory ownership, exact reserved name, bounded
same-UID0600 regular single-link metadata slot and protocol state; partial content
is NEVER mutation/cleanup authority. Explicit recovery may discard such a slot only
in the phases below. Unknown names, special files, links, unsafe modes or a replaced
session directory are conflicts. No namespace-wide recursive cleanup. Slots outside
this owned protocol namespace (native DB/sidecar/profile staging) still require
recorded identity and their stronger rules; name resemblance is NOT ownership.

A deliberate same-UID edit inside a private reserved metadata slot cannot be
cryptographically distinguished from an interrupted writer. This is a cooperating
local protocol, not a hostile same-UID sandbox. Do not edit/store files there; no
existing consumer/user file is assigned as a control slot. Committed intent/state
must still pass strict complete structural/binding validation; corruption of those
committed authorities is not silently treated as an interrupted stage. Confirmation
is not authentication, and an adjacent checksum is not independent authenticity.

### Authoritative states and pending files

1. Before intent commit, only newly allocated session/keychain directories and the
   private `intent.pending` slot may exist. No shared profile/native mutation can
   have been dispatched. If the immutable intent is absent AND no completion/state
   authority exists, recovery may clean this exact empty-directory/preparation
   layout after verifying no default/search reference under it. Reject native files,
   state/completion controls, unsafe stage or any other entry in this branch.
2. Commit immutable intent via fsync+rename+parent fsync; never overwrite it. Write
   initial state before shared work. With valid intent but missing state and absent
   completion, only an initial state.pending and empty native directory are valid:
   no native/profile dispatch is allowed before committed initial state. If those
   resource predicates fail, preserve for owner resolution rather than dispatch.
3. With valid committed state, it remains the sole checkpoint authority when a
   partial/complete state.pending exists. Do not adopt staged bytes as a completed
   mutation. Recovery uses original inflight/ownership predicates and manual
   resolution if needed. Once those predicates authorize the next recovery step,
   remove only the validated reserved state.pending slot before staging its next
   checkpoint. Complete/partial staged updates never become an unrecoverable format
   error merely because bytes were interrupted. A current holder can use its actual
   captured ownership to clean safely after a failed write; no next action proceeds
   after a failed pre-dispatch checkpoint.
4. A failed post-effect checkpoint preserves the old inflight state and recorded
   worker group. Absence of that group plus explicit native-service quiescence does
   not create new inode authority. Complete known identities allow normal cleanup;
   changed/unknown resource identities use the locked manual resolution/recheck.
5. Deliberately corrupt committed intent/state or future unknown version remains a
   separate refusal; atomic interrupted stage/rename/fsync paths yield old-or-new
   complete authority and are NOT routed into that exceptional corruption case.

### Terminal completion and unlink order

Add immutable `completed.json` plus its reserved stage. It is written ONLY after
all owned process/resource cleanup and full native detach/readback have succeeded
(or safely completed with an explicit foreign conflict). It is self-contained:
strict version/session/UID/home/lease/session/keychain directory bindings, a complete
validated copy of original intent, final owned-resource dispositions and whether
this completed with conflict. Its copy must equal intent while both exist. This is
a local protocol terminal record, not public release/provenance evidence.

After completion is durably committed, NEVER restore historical preferences again.
Every resumed terminal cleanup rechecks: no worker group remains, no native DB/
sidecar/staging under the reserved directory, no current preference pointing into
that session, and no remaining original-owned stage/link. Preserve all later user
preference/profile edits; if a new unknown owned-path resource appears, stop.

Under that terminal authority, remove in this exact resumable order:

1. validated reserved `state.pending`, `state.json`, `intent.pending`, and any
   uncommitted `completed.pending` (with fsync after mutation; retained complete
   marker stays authoritative);
2. the exact owned EMPTY keychain directory (already-missing is a terminal no-op);
3. `intent.json` only after all resources and earlier controls are confirmed gone;
4. `completed.json` only when it is the sole remaining entry and terminal predicates
   still hold; then fsync;
5. the now-empty owned session directory; then fsync lease directory and close FDs.
   The persistent lease directory is never removed or recreated.

Classifier at every cut point:

| Remaining on disk | Authority/action |
| --- | --- |
| before/partial intent stage | bounded preparation cleanup above; no native/profile mutation |
| intent + missing initial state + partial stage | initial-state predicates; resume cleanup, not fresh baseline |
| intent + old state + any state.pending prefix | old committed state; reconcile original inflight operation |
| intent/state + partial completed.pending | completion not committed; original state/intent cleanup predicates remain; discard only its validated metadata slot after safe resource reconciliation |
| valid completed + any earlier controls | complete marker; terminal-only rechecks/removals, never restore/dispatch native setup |
| valid completed + no intent/state/native directory | same terminal marker independently sufficient; no corruption/missing-intent error |
| no controls + empty session | resources were never authorized OR terminally removed; only empty-directory removal after no-native-reference check, no historical restoration |
| session absent | no-op; a new signing session may start |
| unknown/replaced/corrupt committed authority | preserve/refuse; do not label this a normal staging failure |

Cancellation/fsync/close faults during any step leave one of those states. Clear
FD ownership BEFORE close, never retry a possibly closed/reused descriptor. A failed
fsync never authorizes the next effect; recovery evaluates whichever complete layout
actually remains. Rerunning recovery makes progress without rebuilding or needing
the random keychain password. Unknown user resources are never deleted to finish
bookkeeping. Manual recheck also uses these same transitions, not a journal-reset
shortcut; cancelling manual recovery leaves all remaining authority intact.

Tests must inject real file-operation cuts before/after EVERY open/write/fsync/
rename/unlink/rmdir boundary, including zero/partial state.pending and completed
writes, replay those actual on-disk layouts through the production recovery API,
and assert no remaining owned resource/reference is stranded or foreign one erased.
Include complete-marker-only and final-empty-directory layouts, corruption cases,
wrong confirmation/token, interrupted recovery and renewed same-account admission.

## M3. Entire borrowed/fork cleanup ownership, not only lease descriptors

Every no-explicit-guard profile owner uses the exact borrow-or-create helper by
default (read, authenticate, capture, installation, plus signed context/process
owners). Thus early credential validation and later ios._profile_payload/load under
outer preflight share its actual guard. Explicit kwargs remain supported for known
parent/child handoffs; no blind independently installed default-only inner guard.
Inspect actual installed bound method/function identity, owner PID and main thread;
foreign callbacks/mixed toolkit owners are not borrowing authority. Custom-handler
and worker-thread semantics remain default-only and unchanged.

Add creating-PID checks to the ACTUAL signing, installer, lease/journal observer and
owned-process cleanup callbacks. After raw fork, inherited cleanup must not unlink
parent profile/native files, change preferences/journal, release a shared flock via
LOCK_UN or kill the parent's worker. Child may close its inherited duplicate FDs
once. Profile read/authentication/capture resources additionally must not kill parent
workers or delete parent's scratch on inherited exit/finalization: detach any
inherited TemporaryDirectory finalizer in the child where needed, rather than
letting GC masquerade as safe cleanup. All new generic process resources are owned
by the exact creating PID too. At-fork closes lease copies and invalidates admission;
subsequent independent child admission borrows no parent cancellation authority.

Existing outer materialize scratch/client owner is still QA-004 and is not claimed
fixed by these inner changes. Its additional inherited-fork behavior is a caller
obligation to reanalyze there, not permission for a new QA-003-owned resource to
lack its PID guard. Actual preflight/lease/profile/worker composition tests cover
this issue's owners; QA-004 will cover the full independent outer owner next.

Tests use actual forked inherited signing/installer/observer/process exits with
parent resources still active, plus real INT/TERM at early and late profile-read/
CMS cleanup acquisition/dispatch under actual outer preflight. Verify parent use,
continued lock, no foreign syscall, descriptor state and exact child reap BEFORE
fixture fallback. Retain independent reproductions and required native/wheel gates.

## M4. Complete synchronous caller and observation map

| Caller | Shared signing resources active? | Required runner/observer |
| --- | --- | --- |
| early full preflight doctor/Xcode-version, project checks, effective Gradle identity, first ios.prepareCommand/showBuildSettings | no; outer account lease already held | bounded owned runner borrowing guard; no session journal or signing mutation |
| credential-material validation/authentication before session | no; outer account lease held | bounded owned private runner / existing isolated CMS runner; actual guard borrowed |
| initial authenticated-profile/baseline default+search observations | no resources yet; account lease held | bounded read-only runner; no intent needed to read baseline; failed/partial query performs zero mutations |
| after initial committed intent/state: profile stages, native create/import/settings/unlock/partition-list/activation and subsequent queries | yes/intended; original session authority exists | session observer persists inflight + worker PID before request dispatch; terminal/group/resource checkpoint before continuation |
| ios.prepareCommand, archive, export inside active signing | yes | same owned runner + explicit signing observer; no unjournaled dispatch |
| post-signing artifact project checks/identity/native queries under outer preflight | signing resources already cleaned; lease still held | bounded owned preflight runner; profile API defaults borrow root guard; no new signing session mutation |
| Android-only/offline/read-only signing/Store-only | no account-signing mutation | no new account lease; shared runner upgrades retain each caller's scope, otherwise unchanged |

Replace preflight's synchronous subprocess.run sites (including version probe and
application/identity commands) with the helper as well as credentials._run_private
and ios._run_checked. Preserve timeout and typed error/result behavior, explicit
env/cwd and credential scoping. Bounded capture must accommodate real build-setting
JSON: expose a validated per-call cap (e.g.16MiB for build-setting/Gradle captures,
2MiB for private credential/native preference tools); no silent truncation. Build/
prepare/project-check output remains discarded, not read into an unbounded buffer.
Independent Android final-artifact/Store upload validators are NOT changed here.
Their authority/no-application-code boundaries remain enforced by existing tests.

For active-session queries, worker journaling is needed for lifetime but a read-only
command does not authorize a DB inode transition. Whitelist exact mutating kinds:
creation/settings/unlock/import/partition-list/owned build calls. Preference writes
have their own full before/after targets; don't accidentally treat all commands as
blanket identity-refresh authority. Completed native nonzero responses may require
reconciliation but never allow setup to continue. Before any command request is
sent, check pending cancellation after recorded worker handoff: cancelled acquisition
must not accidentally start work. Distinguish proved not-dispatched startup failure
from ambiguous after-dispatch failure, so ordinary pre-dispatch cancellation need
not quarantine resources that were not used.

Native observations require rc==0 AND EMPTY stderr AND complete bounded literal
stdout; security's per-entry display callback may otherwise return a partial list
with error stderr but global rc==0. Tests assert zero mutation on that exact case.
Round-trip empty list with `list-keychains -d user -s` (source explicitly supports
zero arguments) and all literal spaces/backslashes/non-ASCII paths; reject ambiguous
quotes/control, duplicates, unexpected stderr and missing default. No guessing.

Standard synchronous Gradle/Xcode clients may use shared idle services. Their mere
existence is not failure and gives no authority to stop them. The unsupported case
is application work continuing to use signing resources after its client reports
completion, or hostile process-group escape. Complete terminal synchronous-client
results plus owned-group absence end that command; ambiguous in-session OS-service
completion requires explicit quiescence/recovery. Normal KMP/Gradle --no-daemon
flows remain supported. Never claim the toolkit contains/kills securityd, shared
XCBuildService or other tasks' Gradle daemons.

Add real startup-synchronized descendants at these preflight entry points, success/
failure/timeout/cancellation, and prove they are gone before the later signing
context. Existing contract/permissions and the full35+ verification gates remain.
Independent approval of R2 plus this supplement precedes implementation; distinct
actual-diff review, protected delivery and remaining issues/fresh audit still follow.

## Normative cancellation/fork clarification requested in R3 review

- A guard restores a signal ONLY if that signal still has its exact bound owned
  handler. It preserves and reports an intervening foreign handler; it cannot
  overwrite somebody else's newly installed callback. Preexisting custom TERM
  alongside toolkit-owned INT stays custom. Mixed toolkit owners are rejected.
- Forked children relinquish only inherited resource ownership first (close their
  duplicate FDs once, invalidate inherited lease/journal/process authority, detach
  parent-owned scratch finalizers), then reset ONLY exact inherited toolkit-owned
  handlers to their saved originals, once. Child cleanup cannot perform a second
  parent-handler restoration. Independent child admission then creates/owns its
  own guard instead of borrowing the parent's. If child cleanup is unresolved,
  fail new child admission rather than pretending ownership was transferred.
- Resource bookkeeping/at-fork hooks are registered before acquisition and contain
  only explicit child-safe callbacks, not arbitrary parent cleanup. A PID-aware
  scratch owner/finalizer may replace bare TemporaryDirectory where necessary so
  even a constructor/handoff fork cannot create a child finalizer that deletes the
  parent's path. Parent process-death/GC cleanup behavior stays unchanged.
- Real fork tests include normal child interpreter shutdown and deliberate GC
  WITHOUT explicitly exiting inherited contexts, not just os._exit or __exit__.
  Keep the parent-required profile/scratch/native resources alive and unchanged;
  reap the exact child and prove resource state before fixture fallback. Also
  test a new independent child lease after parent completion, and intervening
  foreign handler preservation/reporting in the actual broadened consumer.
