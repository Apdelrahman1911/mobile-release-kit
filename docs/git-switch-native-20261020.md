# Content-only local branch switch: native composition

This is a fixed extension of the **existing GitLocal** request, SourceBook,
Supervisor, saved-edit publisher and GitOperations Store row. It introduces no
new process runner, transport, session, grant, journal, timer or command. Rename,
remote operations and general checkout remain outside this increment.

Prerequisites are the accepted switch core/identity hook (`d9f5f338`, integrated
as `98fdfc84`) and worker5/two parent hooks (`fa61c249`, integrated as `5169bab4`).
Their prior28 passive,4 disposable Linux Git and16 passive worker results are
reused for those scopes only. They are not native qualification.

## Closed wire and current original

- Existing five RAW GitLocal commands remain unchanged. Prepare accepts the
  exact new `{kind:"branch-switch",expectedRevision,expectedReferenceRevision,
  name}` action. No force, executable, path, author, target OID, command, stash
  or serialized plan is accepted. Apply still consumes only the retained native
  review ID with original project/document revision and explicit consent.
- The existing Prepare owner returns a bounded content-only review, not a
  fabricated diff or a new file observation. It binds original HEAD/branch,
  index, complete local reference revision, target ref/OID, at most8 changed
  regular-file comparisons, bounded log policy and the core review digest.
  Same-tree switches remain real HEAD/log/index changes, not synthetic success.
- Public context stays `document-<request expectedDocumentRevision>`. The
  original publisher/Host jobs use their existing internal post-epoch stamp;
  no public revision is advanced from a write result.
- Only original native Apply source capture constructs the private `switch`
  input. Prepare uses null. It contains the held target-lock identity and
  parent before/after comparison, old HEAD-log and changed-file snapshots. It
  is not deserializable native custody and is never a renderer parameter.
- The same original Preparing CAS precedes source/lock effects and GO; the
  same candidate ACK precedes checkout/publication. Existing Source/Doc/STOP
  rematches,45/55 endpoints, first-failure cutoff and all actual joins remain.

## Actual source and exact successor

`git_switch_sources_macos.rs` is a child of the existing GitLocalSources. Its
source descriptors are in the **same SourceBook**. No old FD is replaced,
forgotten or inferred closed because a named file changed.

The existing fixed Apple CLT executable and original project/config/index/
object custody stay unchanged. Existing physical target-reference parents,
loose target (or exact held packed-refs), changed file parents/old files and
HEAD-log parent/old file are admitted before GO. Only the same bounded normal
full `.git` layout accepted by the core is supported. There is no resolver,
directory creation, Xcode/PATH fallback or policy bypass.

Darwin replacement creation inherits the held destination parent's group.
Original changed files/HEAD/index/log with a different group are refused as an
unsupported layout **before GO**, not silently chowned. Every returned
successor still matches the original uid/gid/mode and exact candidate bytes;
new HEAD-log mode is0600. Existing hooks/signing/conversions/LFS/submodules and
other core refusals are unchanged. Private umask probing is still the core's
pre-effect operation; no global mask is changed.

The native owner creates the exact target `.lock` once with O_EXCL/O_NOFOLLOW,
retains the returned FD before any subsequent check, and checks empty0600,
held/named identity and the exact held parent transition. The Python worker
only compares this lock. It cannot create, close or unlink it.

Only the existing Supervisor's private publication witness—after original
child success, both EOFs, IO joins and the actual candidate ACK job—can admit
the returned checkout and metadata prefix. Its original request/review/native
projection must match exactly. Generic index/ref receipts cannot authorize a
switch. The actual worker's positive C/A/W and fsync/close receipts remain the
source of its fixed phase; shaped candidate/result DATA alone does not suffice.

Returned changed files and the positive prefix `logs/HEAD → HEAD → index` get
**separate** held descriptors. Each replaced original FD is still read and
hashed; only that exact original's nlink0/ctime transition is tolerated, with
unchanged inode, uid/gid/mode, size, mtime and bytes. Named successors must have
the exact candidate hash. Config/tool/target ref and all unaffected originals
remain strict. A switch return/rematch ambiguity promotes even an earlier
SourceChanged label to CleanupUnknown so it cannot release the lock as a
harmless refusal. The original first-failure clocks are not replaced.

## Last target-lock retirement

Switch-only original settlement order is:

1. The existing source post/positive-successor rematch, after process/pipe joins.
2. The **same** runtime's `settle_originals`, with SourceBook/target lock held.
   Unknown runtime closure retains the source original and lock, not success.
3. The same account/ACL settlement and one reverse close attempt for all other
   SourceBook slots. Target lock and its held parent are excluded until every
   other close is known. A close failure is reported to the existing owner's
   failure/cleanup clock immediately; it creates no new deadline.
4. Exact held lock/parent check; latch the sole unlink attempt; unlink only
   this owned name via that parent FD; check unchanged parent common identity,
   exact absence and repeated parent metadata. Only then close the lock FD and
   parent once. Uncertain unlink/postcheck/close is retained and never retried.

The parent SourceBook hook extracts its unchanged close-slot body; old callers
keep their original reverse close loop and behavior. Old Git actions keep
their original settlement order. Ordinary Git lock coordination is not atomic
protection against arbitrary external editors or hostile namespace/ABA edits;
the core's immediate destination/ancestry and preserved-name checks remain.

Management driver/watchdog joins and the final Store CAS are **later** original
steps. None is inferred from a target read, publication prefix or source close.
NativeUse and publisher retirement still join separately. There is no self-join.

## Same durable row, including manual recovery detail

Only explicit Switch Apply's Preparing CAS upgrades the existing operation
envelope to schema3. Canonical schema1/2 reads do not rewrite or initialize it;
other projects' pending rows remain exact. Later branch creation cannot
downgrade it. No pending/Unknown/RecoveryRequired row becomes replaceable.

The switch portion stores the approved ref/OID/file/log comparisons and the
same row's one candidate index/HEAD/log/footprint amendment. It stores no file
bodies, reflog text, committer identity, executable, credential or private path.

When a genuine positive publication and all original pre-final-CAS joins are
known, that **same GitLocalNativeJoined** witness carries bounded historical
`effectPhase` and at most5 exact relative candidate paths. Only the existing
final CAS stores this detail. A schema3 successful switch requires its known
`index-returned` phase and no retained candidates. Partial known phases remain
RecoveryRequired, never retry or rollback permission. Negative/missing evidence
does not invent a "nothing happened" phase. If final CAS/ACK is unknown, the
original fence remains; the app does not claim detail was persisted.

On restart this is manual recovery information, not a reconstruction of native
authority or an automatic repair engine. Preserve originals/candidates and use
the original status/STOP controls. Do not remove lock files to enable a retry.

## Exact Root hooks and verification limits

`git-switch-native-hooks-20261020.patch` has8 targets:

1. `git_local_protocol.rs`: exact tagged action/review/intent, private source
   projection, four publication phases, bounded result validation.
2. `git_local_state.rs`: closed schema3 same-row candidate/final data, unchanged
   existing Store/NativeUse/CAS owner.
3. `git_branch_state_tests.rs`: reject future schema4 instead of now-supported3.
4. `supervisor_git_local.rs`: original private source/publication binding,
   switch-only close ordering, same joined final-detail witness.
5. `git_local_sources_macos.rs`: fixed child admission/post/close integration.
6. `asset_source_macos.rs`: unchanged one-attempt close-slot extraction.
7–8. `lib.rs` and the real `installed_shell_observation.rs` module graph.

No bootstrap/runtime role or supplier change: the current GitLocal core package
contains the new leaves and still requires actual installed source binding.
No availability/qualification flag is changed. Renderer integration is a
separate successor using the same controllers and RAW commands.

Six new Rust leaves define22 tests:17 portable codec/journal/private-correlation
DATA tests and5 Mac-gated source comparison/one-attempt-state DATA tests. They
cover exact shapes, same-tree review, source/ACK/phase binding, partial paths,
schema1/2 preservation, pending/recovery fences, historical final detail,
original group policy and absorbing ambiguous lock cleanup. **All are unrun**
until Root's coordinated actual graph batch. Source parsing of14 changed/new
Rust files passed; this is not Rust typechecking or native lifecycle evidence.
Actual Mac source/lock/ACL/runtime/Store/STOP/HTTP-free operation qualification
and integrated renderer typechecking remain Root-owned.
