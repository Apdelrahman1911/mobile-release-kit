# Local Git writes: closed native integration packet

Implementation packet, **not an available route or a native receipt**. The
accepted Python worker is `5d0b48fa` (Root `7fcde2ec` + `54701894`); this native
successor is source-only and awaits distinct implementation review and Root's
actual graph/tests. The patch is generated against Root's pinned `fa5ffac7` baseline,
with exact before/after hashes in the task's `native-hooks-manifest.json`.
Root owns every shared hook. Existing GitRead/GitHub and process owners remain
authoritative. Branch/remote operations are deferred.

## 1. Scope and source

Stage/unstage 1–64 explicitly selected regular paths; commit the **whole reviewed
staged set**, with a retained message and author. Ordinary full `.git` directories
only. Preserve unrelated index/worktree changes. Refuse required hooks/signing,
filters, conflicts/active operations, ignored/unobserved staging, sensitive
content, linked worktrees, sparse/partial/external-object layouts. No remote,
network, reset, force, hook execution, arbitrary argv or tool/path endpoint.

The new Python facet delegates to the original `git_service` transaction through
one default-preserving `_index_transaction` hook. Initial config-only/no-includes
and all candidate/read commands use the existing frozen GitRead view. Only the
exact attached-ref expected-old CAS uses original config, with `config.lock`
held and the exact original no-includes policy rechecked. Current original refs
are compared before frozen HEAD reads. A positive exact CAS alone permits the
selected copied ref to refresh. Content-addressed loose-object additions have
finite parent checks, not a claim of exhaustive object inventory/hostile ABA
protection. Preparing is persisted **before** candidate object/lock effects.

Use the same protected fixed Apple CLT Git provider, installed Book, SourceBook,
Account/SnapshotBook, Supervisor and `run_owned` C/A/W. Add only a closed GitLocal
profile/domain and child facets. Neither GitRead status nor a tool/version DTO is
mutation authority. No PATH/Xcode fallback or a second subprocess owner.

## 2. Human review and five public commands

All commands are main-window strict bounded RAW, under currentDocument:

* `git_local_prepare`: projectId, expectedDocumentRevision, exact action
  (`stage|unstage|commit`), expected Git revision, sorted selected paths (empty for
  commit), message/author only for commit. At most96KiB. Starts one read-only
  prepare ticket. Status eventually contains reviewId and bounded review DATA.
* `git_local_apply`: projectId, expectedDocumentRevision, reviewId only, <=1KiB.
  One-use explicit confirmation of the retained full private request/review.
* `git_local_discard`: reviewId only; memory-only when no apply is admitted.
* `git_local_status`: `{}`; memory only; never initialize Store or replay work.
* `git_local_cancel`: operationId only; STOP remains usable during cleanup.

A ready review retains no child, source/runtime Arc or Git lock. Retain only
bounded immutable request/review DATA and original document/project comparison
stamps. Apply makes a fresh actual core plan under the new real owner and checks
its full digest against that review; no deserialized `GitPlan` is accepted. No
new request starts implicitly from status, attach, a promise timeout or a review.

Prepare uses the same facet to produce its selected diff before retiring,
avoiding a second read admission while preparing. SetupUI's separately reviewed
`dca78037` controller/component and Root hooks consume these exact five RAW
commands; this packet does not replace that work. Only genuine joined Prepare
can supply `Status.review`; discard/context change may remove it while retaining
the historical terminal. Public operation context remains
`document-${request.expectedDocumentRevision}`, including Apply; the publisher's
new internal input epoch is not substituted for that correlation value. A
successful native handoff or core result alone cannot supply settled status.
Diff/path sensitivity checks are bounded heuristics, not proof that arbitrary
repository content contains no secrets.

## 3. Same Document and genuine mutation publisher

Reserve `android_registration_control.reserve(General,false)` **before taking
Doc**, as the original ControlSlot requires. Under that same Doc, consume the
one review, retain Apply + actual Publisher + SavedEditStamp, and invalidate only
dependent memory DATA. There is no fallible operation after ticket insertion.
The first registered blocking job calls that same `Publisher::accept` **off
Doc**: Host invalidation can wait for real IO. Only its actual returned join is
rematched under Doc to capture the post-epoch/stamp, then begin the Host ticket.
An error/unwind after entering accept is not a pre-admission refusal or retry.
The sole-publisher `git_local_epoch` accessor uses the unchanged exact original
`tool_source_epoch` check; ordinary `epoch()` is not relaxed.

Apply retains the publisher until all native/process and final Store jobs return.
Never hold Doc or SavedEditGuard across Store, filesystem, child IO or await.
Reacquire the genuine guard under Doc and match the retained
stamp/project/generation/root/revision before GO, candidate ACK, and final
acceptance. Reciprocal GitLocal checks precede existing edit/publisher effects
and peer admission. Status and STOP never reinitialize or repeat work.

The same Supervisor original owns one 45s work /55s hard tuple from admission,
including source discovery, Store jobs, all Git commands and finalization.
First failure uses the earlier failure+10s or original hard endpoint. No phase,
command, callback or status poll renews these clocks.

## 4. One bounded operation row in the existing Store

Consume Root/service's `Namespace::GitOperations` and
`enable_git_operations(&NativeUse)->Snapshot` on the same PrivateStateDirectory
Book. Ordinary reads/status never enable it. Explicit first Apply may enable
under its same retained publisher/NativeUse; no extra DB, generic CAS endpoint or
process-independent journal owner.

The persisted projectId is the **service's stable ProjectBinding ID** from the
same original NativeStateReady, not a runtime/renderer alias. Its full canonical
root/device/inode must match the genuine registration. If Host is dormant,
explicit Apply alone reserves the fixed native app_local_data_dir and complete
native project roster through `reserve_native_state_location` (TRY only), then
retains the actual `begin_native_state_until(original,work_end)` ticket. Existing
`prepare_native_state(ticket,path)` runs as an original retained async startup
job outside Doc; after its actual join, the fixed borrowed-ticket
`finish_native_state_retained` rematches the same NativeProject/current
SavedEditStamp under Doc. The existing consuming API delegates to exactly that
unchanged TRY/pending/epoch body. GitLocal retains the original ticket Arc on
every failed handoff; it releases this route only after positive Ready adoption.
The body can clear pending before a later check fails, so neither an error nor
a cancellation Conflict proves successful cleanup. One exact-ticket STOP error
is retained Unknown, never a newer ticket or a repeated cancellation. Subsequent
checks call the
original `native_state_current`, not a copied readiness bit. `begin_use` runs in
the retained IO job afterward. No agent-read grant/listener or Initialize widget.

Root supplied Host hooks (actual qualification remains Root scheduled): clamp
the original native ticket's startup endpoint to min(existing Host30s, original
Apply work endpoint), and `cancel_native_state_ticket(&ticket)` supplies TRY
STOP invalidation that cannot retire a newer ticket. Keep all pre-existing Host
source-exclusion/startup/unknown ownership. An unavailable Host/native location
refuses Apply instead of treating the journal as empty.

Schema1: <=32 sorted project rows, total canonical bytes<=128KiB. One
row per project, not an accumulating operation history. Each row contains only
projectId, operationId, action, reviewDigest, expectedRevision, expectedIndex,
expectedRef/Head, optional candidateIndex/Head, phase and fixed terminal outcome.
No diffs, message, author, token, tool/root path or source file bytes. Replace a
prior row only if its actual recorded result was fully settled without recovery;
pending, unknown and recovery-required rows fence a new Apply. A decoded row is
never a replay/consent/native-finality capability.

`operationId` text is Supervisor-local, not globally unique across application
restarts. A fresh explicit reviewed admission may replace a known Finished row
even if its text repeats, but never a pending/recovery row. Each transition still
binds the stable service project, exact retained snapshot/revision, and same live
Original/NativeUse/full review. Public history consumers must retain their actual
service-instance/request context; old ID text is not a new operation identity.

There is **one row, not one write**: Preparing before GO; amend that same row with
the exact candidate before publication; final outcome after real original joins.
Each transition uses retained previous Store Snapshot revision and exact CAS ACK,
with no automatic logical retry. Unknown ACK/adoption leaves the adapter latched.
A restart exposes pending recovery only. Matching Git readback cannot settle a
lost original producer or authorize another mutation.

## 5. Finite frames, jobs and publication boundary

Private `mrk-git-local/1` request (<=96KiB): fixed phase Prepare/Apply, operationId,
native context/source snapshot, original endpoints, retained action/draft, and
reviewDigest on Apply. Same held SavedCommandInput and engine: READY<=512B, exact
GO. Prepare has one terminal; Apply may emit **one CANDIDATE<=4KiB** then one
terminal<=2MiB. No caller command/env, generic input RPC or retry frame.

CANDIDATE contains only exact operation/request/review digest and core
PublicationIntent (expected index/ref/head + candidate index or commit OID).
The original stdout reader validates it before notification to the same
Supervisor driver. Its retained stdin writer sends one exact ACK (digest + Store
revision) only after the matching Store job actually returned and the original
Doc/consent check passes. Python's one-attempt handoff keeps STOP/parent custody
live while waiting. It rechecks the actual owner after ACK and immediately before
index rename or expected-old ref CAS. Lost/duplicate/wrong/late ACK never sends
publication. The ACK is internal comparison DATA, not a public grant.

Eight finite job slots live in this original `Resources`, following the existing
VersionAllocation pattern: register handle + one-shot release before any IO;
borrow the actual handle across join outside Doc/Host/Store locks; retain
late/unknown jobs. Fixed phases: Publisher accept, Host startup, open NativeUse +
explicit enable/read, Preparing CAS, candidate CAS (optional), terminal CAS,
retire NativeUse, Publisher finish. The existing management observer invokes
terminal CAS only after original process/source/driver/watchdog returns. Its
private joined witness is not a self-join of that observer or the later CAS/use
retirement. NativeUse retirement is a separate actual job after terminal CAS.
No unregistered job or dropped timeout handle can release the reservation. Job
STOP does not pretend a running fsync has stopped. An unjoined/failed final job
keeps the publisher/use/resources pending even if Git's candidate is observed.

The private writer distinguishes a fully returned request/GO (and any entered
ACK) followed by an original STOP and known input close from a partial/ambiguous
write. Its one-attempt stopped-control evidence permits only a validated
cancelled/timed-out, nonpublication terminal, still requiring actual successful
child wait, both EOFs and every IO join before original source/runtime close.
Generic false-complete or terminal DATA alone remains Unknown; STOP cannot turn
a successful-looking child result into native success.

Native postchecking retains the original old index FD through its sole close.
For a positive stage/unstage publication only, a separate successor slot must
match this acknowledged candidate digest and actual publication receipt. The old
FD's dev/inode/mode/uid/gid/size/mtime/content remain exact; only unlink link-count
and ctime may differ as required by that proven own replacement. A commit leaves
the index exact and accepts only the approved attached ref successor. Old slots
and their identities are never reset or discarded. Unknown work cannot acquire
this exception. Fixed no-follow ref-parent traversal stays in the SourceBook.

## 6. Ownership, hooks and evidence

New native owned files are `git_local_protocol{,_tests}.rs`,
`git_local_state{,_tests}.rs`, `supervisor_git_local{,_jobs,_tests}.rs`,
`asset_session_git_local{,_unavailable}.rs`, `git_local_sources_macos{,_tests}.rs`,
`git_local_runtime_macos.rs`, and `application_service_git_local_tests.rs`.
Linux keeps the real Store type graph but cannot admit this Mac profile; other
platforms use a closed unavailable Doc cut with no Store/process construction.

`git-local-native-hooks-2026-10-20.patch` is the sole native Root hook artifact:

* `supervisor.rs`: exact profile, slots, finite dialogue, original management
  finalization, no generic runner or private DATA in `ReadOutcome`/Debug.
* `asset_session.rs`: child/state, currentness, memory census, reciprocal gates,
  context invalidation and original retirement. No new global coordinator.
* `saved_command_android_registration.rs`: sole-publisher comparison only.
* `application_service_host.rs`: borrowed-ticket wrapper + test child only.
* `runtime.rs`, `installed_runtime_macos.rs`, `asset_source{,_macos}.rs`,
  `git_read_protocol.rs`, `lib.rs`: exact child graph/profile, six existing DATA
  validator visibilities, no GitRead policy/authority changes.
* `shell.rs`, `build.rs`, `capabilities/main.json`: five main-window RAW handlers
  and exact matching allowlist rows; only native app_local_data_dir, no IPC path.
* `tests/installed_shell_observation.rs`: the same two module declarations as
  the library (journal Linux/Mac-gated); no observer role or roster redesign.
* `prepare_runtime.py`, `stage_macos_installed.py`: add **only**
  `git_local_bootstrap.py` to CURRENT roster; keep legacy/new key/Apple/version
  entries and derived capacity. Original installed Book refuses a missing fixed
  entry. Normal compose-store-runtime recomposes core/bootstrap with the existing
  signed Python/Store supplier; no supplier rebuild or re-signing is requested.

Working reservations include 12MiB dialogue/result overlap, separate original
runtime/source/Store backing, and 1MiB retained review backing (four bounded path
sets plus diff and structural slack). GitLocal alone uses independent fixed
partitions: the unchanged full code reserve is 128MiB, actual retained Document
backing is at most 16MiB, and future writer non-code backing is at most 16MiB;
the checked full admission total is at most 160MiB. The original capacity-based
Document/artifact/GitHub census includes the old read, joined preparer and review
before admission; no presumed disposal earns credit. The existing census feeds
that full total to the same admission check. History/Read/Store quotas are
unchanged. This is bounded owned backing, not a process RSS or authority claim.
Service's existing `GitOperations` upgrade and SetupUI's App/bridge are consumed,
not reauthored. No shared source is edited in this lane.

### Evidence and remaining checks

* Accepted worker: nine fake-owner tests +13 codec tests. They prove no native
  receipt, not an installed Mac or Store/process dialogue.
* Accepted controlled Linux Git fixture: **4/4 PASS, 116.702s, exit0**. Fresh
  UID65534 private source projection/HOME/tmp; fixed `/usr/bin/git`, no remote,
  user repo, credentials or hooks; original `run_owned` C/A/W, 120s/160-call/5s
  bounds and one45s Prepare+Apply. Caller joined, successful projection removed.
  Earlier failed runs/evidence remain; this is not native/Mac qualification.
* New Rust tests are **defined, not executed**: nine protocol, nine journal DATA,
  eight in-memory pipe/clock, two Mac source comparison predicates, three actual
  idle Host/Doc/Publisher memory/lock tests. These never create a Git child, Store
  or positive native capability. Source formatter parsing is not typechecking.
* Root must apply/review the actual graph, compile Linux + shipping Mac, run the
  selected DATA/lock tests, and qualify the genuine native source/runtime/Host
  and controlled Git/ACK/STOP/cleanup composition. No installed availability,
  publisher/NativeUse finality or old-index-FD close is inferred from a parser,
  candidate digest, ref readback or these source-level tests.
