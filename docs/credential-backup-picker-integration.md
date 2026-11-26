# Credential backup — original pickers and private destination pair

## Status and scope

This is **internal source, not an enabled or natively qualified feature**.
It extends the [source-reviewed Scope A parent](credential-backup-native-integration.md)
(`a60527e3`). Only the earlier codec/reference slice has Root's genuine
19-test/full-crate result. Scope A/B graph compilation, the new focused tests,
and real macOS picker/filesystem/installed behavior remain pending. No owner
credential, signing account, or native key generation was used for development.

Scope B adds two original native picker phases and a concrete private export
writer, not another service, worker framework, generic file endpoint or callback
sink. Existing document, native context, vault qualification, same-key/store,
bounded memory, STOP and original-join gates remain. Linux persistence stays
disabled. No public IPC, GUI control or CLI route is registered by these files.

## Intended explicit user flow

* **Back up this credential:** select a folder for the encrypted backup, then a
  different folder for its recovery-code file. Keep the recovery code separately
  and safely: both files are required to recover without this Mac or Keychain.
* **Restore a backup:** select the encrypted backup, then its matching
  recovery-code file. Successful authentication creates a **new** vault record;
  assessment and assignment are separate explicit operations. Existing signers
  and assignments are never replaced by restore.

Neither action happens during a wizard refresh, readiness read or app startup.
The two folders must have distinct native identities and satisfy the existing
protected ancestry/private-file policy; renderer/CLI paths are not accepted.
The recovery code is a random 256-bit key in the codec's exact 79-byte format,
not a password. No clipboard, ordinary stdout, public JSON or secret preview is
used. The existing authenticated-encryption format and crypto dependencies are
unchanged.

## Same original through both phases

`credential_backup_selection.rs` is a child of `asset_session_vault.rs`.
`OriginalWork::new_credential_backup` reserves the primary and second genuine
`GuiCall` before the existing coordinator GO, retaining the second in an
install-once `OnceLock`. No call can be reset or replaced. The closed native
purposes are encrypted input, recovery-code input, encrypted destination and
recovery destination. They do not reuse JKS/public-image/ordinary-file grants.

`shell_macos_dialog.rs` uses its existing native construct/poll/close/release
loop and awaited original dispatch receivers. Production `OriginalPanel`
matching now requires the actual call pointer, original owner and exact closed
kind/phase, not just an operation number. Existing observation roles do not
acquire authority for the new purposes. The first selected path moves from the
actual call into the same original's private progress cell only after that
loop returns. Both original loops must return before a sealed `SelectedPair`
can exist. It exposes no path getter or receipt constructor.

Backup Accept callbacks record the actual response time but **do not** start or
renew an IO clock or assessment review clock. After both real selector joins,
the current document gate starts one existing `WORK` deadline, once. No private
input read, recovery-key allocation or output creation precedes this transition.
STOP wakes both originals. A fixed coordinator no-GO exit can record no-object
only for the genuinely undispatched second phase; an entered unknown selector
is retained, not reset by the next phase or a wrapper result.

Before allocating the picker owner, the native entry reuses Root's read-only
`lookup_memory::retained_document_bytes(&document.inner, state)` and
`installation_memory::additional_document_bytes(document, state)`, then adds a
derived bound for the original/slot/source/two-call/path/native controls against
the actual vault caps. These are Root's existing accepted helpers, not copies
in this lane. After both joins, **the real** `pending_slot_bytes` census and the
additional saved-lane/evidence/maintenance/Inner accounting run again before
`Child::Backup` GO. The original second call and all retained path capacities
are counted; unsettled/unknown calls do not become settled census evidence.

## Concrete export custody

`credential_backup_destinations_macos.rs` is a closed child of the real macOS
`SourceBook`. Its constructor retains path DATA only and performs no IO.
The same original vault child retains it before GO, then:

1. Acquires and compares the full current project/vault exclusion roster and
   both native destination ancestry chains with existing no-follow/physical
   alias rules. It checks distinct device/inode parents, protected filesystem,
   owner/mode/flags and native ACL policy. Both destinations stay outside every
   registered project and the current vault.
2. Obtains a fresh OS-random **public filename ID** and checks all four final and
   pending names absent. Fixed names are `mrk-backup-<id>.mrkbackup` and
   `mrk-recovery-<id>.mrkcode`, with `.pending` staging counterparts. No caller
   filename, overwrite, chmod-to-relax, deletion, collision retry or adoption.
3. Creates and retains both original `O_EXCL|O_NOFOLLOW|O_CLOEXEC` private files
   before recovery-key/backup generation. Both must be empty regular files,
   current-UID, mode 0600, single-link, with empty ACL, no xattrs and safe flags.
   Failed admission closes all independently acquired originals once and keeps
   partial/unknown effects; it never proceeds to generate a code.
4. Authenticates the current vault record using the complete `StoredRef` and
   original read witness. The reviewed codec output is retained on the same
   `Work` **before** fallible record/root/current-key postchecks. Production
   export without this concrete destination is refused before crypto.
5. Borrows the retained output through the sole concrete
   `ExportedBackup::publish_to(&mut BackupDestinations, &Arc<OriginalWork>)`
   method. There is no generic callback or public byte getter. It writes and
   full-syncs the code first, then the encrypted backup, checking exact bytes
   and EOF through a zeroizing buffer. It publishes the code with the existing
   native `RENAME_EXCL`, syncs its parent, then publishes/syncs the encrypted
   backup. Both original names, bytes, private metadata and ancestry are
   rechecked. File/ACL/directory original closes are attempted independently.
6. Returns only an internal candidate. After actual child **and** coordinator
   joins, the parent rematches the same current key/store, complete record
   reference and native document generation/context. Only that publisher can
   mark delivery and authorize existing off-lock memory disposal. A phase,
   hash, file existence, close flag or child body return is not delivery.

The pair is **not atomically published**. On partial publication, failed sync,
changed paths, cancellation or uncertain close, output and original effects
remain retained. Unknown effects prevent normal retry/disposal/closed reporting,
even if producer quiescence is known. Files are not automatically removed.
In particular, STOP after an acknowledged rename but before directory sync
leaves that sync genuinely `NotStarted`; the unsynced publication still requires
recovery and cannot authorize private-output disposal or a fabricated sync entry.
There is no after-restart adoption/recovery claim. Independently recoverable
backup means the authenticated pair needs no original vault/keychain to import;
it does not mean an interrupted pair write is automatically repaired.

The native snapshot's original first-failure `Instant` is forwarded to existing
`Work.fail` and original STOP/wake before cleanup. The writer uses the existing
cleanup ceiling; neither failure nor a later cleanup return restarts it.
Unknown effects remain distinct from StoreBook mutation outcomes.

## Import and retirement remain Scope A originals

The sealed input pair is handed to the existing `BackupSources`, retained on
the same original before capture. Recovery bytes, partial reads and EOF sentinel
are zeroizing from the first read. Exact bounds, full physical exclusions,
original identities, ACLs, terminal comparisons and one-use closes precede
authentication/parse. The retained random new record ID and `Mutation::New`
with no previous reference are unchanged.

Only an actual New store mutation updates the remembered outcome, before
readback. Capture/authentication failure cannot replay the store's previous
operation outcome. Restore does not return private plaintext, restore a saved
Bind, overwrite an existing row or auto-assign.

The Scope A Work/Retirement private-data-empty fence and preserved failed
original-join checks remain intact. Cleanup-only returned receipts cannot
rehabilitate a prior failed original. Successful delivery adds a narrowly gated
disposal reason; otherwise explicit existing discard/lock is still required,
and unknown custody/effects refuse it. Refund/empty credit follows the actual
off-lock drain, not a public completion projection.

## Exact Root-owned hooks

`credential-backup-picker-hooks.patch` is deliberately **unapplied here**. It
targets the lane's central source after Scope A's eight-hunk parent patch.
Root must preserve its other integrated additions when applying these changes:

* `asset_session.rs`: install-once second selector; STOP and original resource
  settlement; actual-call response/path/presentation/failure routing; no backup
  per-Accept deadline renewal; real second-selector census; fixed genuine no-GO
  exits. Preserve the Scope A private-empty, allocation and retirement hooks.
* `shell.rs`: macOS-only reexport of `run_owned_backup_dialog`.
* `desktop/native/macos-installed-native/src/lib.rs`: four closed `PanelKind`
  variants/codes 17–20 and corresponding pure classifier test cases. Existing
  installed observer decoding/qualification is not extended.
* `asset_session_installation_memory.rs`: count the retained second selector
  and backup custody in its existing known original-owner census.

The two generic read-only census helpers named above must already exist in
Root's graph; this patch deliberately does not duplicate their traversal.
No manifest, lockfile, provider gate or public schema changes are proposed.

The concrete native-only entry methods are:

```text
DocumentBinding::choose_credential_backup_export(app, context_revision, RecordRef)
DocumentBinding::choose_credential_backup_import(app, context_revision)
```

Both return the existing safe `AssetStatus`. They reserve one genuine
`Job::BackupPick`, use the existing current-context/durable gate and coordinator,
then enter the existing fixed child after both selector joins. No public caller
may synthesize `SelectedPair`, destination custody, source capture or finality.
Actual GUI/CLI authorization and native qualification remain integration work;
do not connect a permissive generic path adapter or advertise availability.

## Focused regressions and evidence limits

Written but **not run** for this Scope B graph:

* Five portable selector DATA tests: distinct pre-GO originals; pointer/purpose
  binding; retained first path and one clock; unknown entered second phase;
  genuine no-GO cleanup; actual second-call/path census and unknown refusal.
* Two additional portable native-child predicate tests: preserved original
  first timestamp/cleanup ceiling; joined/result-shaped DATA without a concrete
  sink never delivers. The ten earlier portable Scope A tests remain.
* Five macOS-only destination DATA tests: closed fixed names; effects versus
  close/delivery; ordinary-owner paths cannot acquire a sink; retained unknown
  effects and the bounded control quote; a renamed-but-unsynced directory never
  claims sync entry or permits disposal. One additional macOS parent test
  proves both closed-but-unknown and renamed-but-unsynced pair effects cannot
  be discarded or report empty.
  The two prior macOS native-child and two source DATA tests remain.
* Two macOS shell DATA tests: actual-call/kind binding and unknown outcome not
  consuming the original selected path. The existing native pure response
  classifier receives all four purpose codes, without constructing panels.

Source parser and patch/diff checks are not these tests. Root owns the exact
integrated compiler/test runs. Native panel cancellation/join uncertainty,
ACL/no-follow/alias cases, code/backup readback, partial publish/sync/close
failure, store postchecks, process interruption and installed authorization need
their real admitted macOS owners; no fake native or extracted codec harness
substitutes. JKS/Apple key generation, CSR, live provisioning/signing and Store
operations remain outside this slice and unavailable.
