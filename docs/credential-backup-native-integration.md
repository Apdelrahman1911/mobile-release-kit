# Private credential-backup adapter — integration boundary

This is **not an enabled or natively qualified export/import feature**. The
previous codec/reference slice (`d6abb5b5`) passed Root's actual no-default crate
compile and 19 focused Rust tests. The two new native child modules described
here have only passed Rust parser/format and diff checks. Their focused tests
and the actual macOS/native graph are pending. No real signing key was used.

## What the new code does

`credential_backup_native.rs` is a child of the existing
`asset_session_vault.rs`, not another service/worker. Preparation retains opaque
custody in the same `OriginalWork` before GO. Its fixed native child borrows the
same original `StoreBook` and authenticated `VaultKey` as ordinary vault work.

* Export compares the complete `StoredRef` (vault + generation + record + random
  revision ID + counter + original read witness), authenticates the small
  descriptor, quotes the complete record before reading, authenticates that
  record, and calls the reviewed random-code backup codec. It retains the output
  **before** record/root postchecks or a late interruption. The only successful
  local phase is `PendingPrivateSink`: still undelivered, not an export receipt.
* Import retains its one random new record ID before any source capture/mutation.
  `credential_backup_sources_macos.rs` uses a separate original `SourceBook`
  because the ordinary vault-exclusion book is one-shot. Both selected files,
  the full native project/vault roster, physical input identities, private ACLs,
  exact size/EOF, terminal comparisons and original one-use closes are checked.
  Both buffers, including partial code and the EOF sentinel, are zeroizing from
  the first native read. The recovery code is exactly 79 bytes; no trimming,
  password mode, ambient lookup, callback result or FileKind substitution.
* Authentication uses the existing AEAD codec before private payload parsing.
  The input and an in-place transition debit remain in the original custody.
  The write is fixed `Mutation::New`, previous revision `None`, expected witness
  `None`. It uses the actual store mutation/intent path, remembers its outcome
  before any readback failure, and authenticates the new descriptor afterward.
  It never replaces a record, restores an old ID/approval, assesses or binds.
* A fixed `OriginalWork::credential_backup_failed(reason)` retains the first
  actual failure timestamp in existing vault work and requests original STOP/
  wake **before independent closes**. It takes no document lock, supplies no
  output/receipt and never extends a deadline. The caller holds no vault-work
  lock while capturing; the child holds only the separate store/custody locks.

Opaque private output has no production byte getter or generic delivery
callback. The old two codec extraction helpers are now `cfg(test)` only.

## Required Root-owned integration

These are source hooks, **not permission to register an IPC command**. All
existing document, exact context/generation, cancellation, memory, provider and
native qualification gates remain. In particular Linux persistence stays off.

1. Module graph:
   * `asset_session_vault.rs`: declare
     `#[path = "credential_backup_native.rs"] mod backup_native;` on the parent's
     existing target profile.
   * `asset_source_macos.rs`: declare the `backup_sources` child at
     `credential_backup_sources_macos.rs` and reexport `BackupSources` crate-only.
     `asset_source.rs` reexports that type under the same macOS LP64/ARM64+x64 cfg.
2. Original custody: add `backup: backup_native::Work` to vault `Work`. Its
   `settled()` must also require `backup.native_settled()`. Add its actual
   `retained_bytes()` to the existing owner census. Failed/poisoned census is no
   credit. The quote separately reserves 1 MiB of native roster/control storage
   plus the existing 8 MiB parser arena; actual ciphertext/plaintext capacities
   are counted as well. Source control is derived from the existing finite
   descriptor, component, alias and path limits, not an unbounded allocation.
3. Closed dispatch: add `Child::Backup(backup_native::Request)` (large work).
   It calls `backup_native::execute(owner, &mut actual_book, request)` from the
   existing parent store-lock/child path. Its mutation classification is
   `request.mutation()`, so existing `remember`/failure reporting still runs.
   Add `ChildResult::BackupPrepared`, shell-only `Job::Backup(Request)` and its
   delegation to `backup_native::run` through the existing coordinator path.
4. Separate operations: `PrepareBackupExport` and `ImportBackup`, not ordinary
   `Commit`/`Save` or a fake file kind. Preparation functions expect the genuine
   newly reserved vault slot with current context, same key/store and roster.
   Import preparation reserves the existing row/inventory cells before IO.
   After successful installation and before GO, Root marks the import slot/
   session mutating and supplies the ordinary initial NotStarted/NotRun/Pending
   outcome. Preserve the original operation after STOP; import failures must
   enter the existing interrupted/read-only/relock path.
5. Post-join publication: add `Staged::BackupPending { generation }` with no
   dynamic public data. Only after original child/coordinator joins and existing
   current gates may `backup_native::pending_publication(&work, &session)` project
   pending/undelivered. Never mark it completed/delivered or grant a sink.
   `Staged::Mutated` admits `ImportBackup` only in a **separate New-only arm**:
   no old row/target, counter 1, capacity, existing known-applied/confirmed/known
   checks, and `backup_native::new_publication(&work.backup, identity, record,
   row)`. It uses ordinary `publish_saved_revision`; separate assess/Bind remains.
6. Disposal is different from producer quiescence. `blocks_reuse()` remains true
   while private input/output is held, even if the child joined. Ordinary idle,
   context/reset, owner replacement and allocation admission cannot drop or
   bypass it. An original cleanup-only `Release` may still close its existing
   store; it must not become a new backup/import attempt. Before an explicit
   undelivered discard or an accepted New publication is disposed, use
   `backup_native::retirement_ready(owner)` **without holding vault work**.
   It requires actual original normal joins, source/store quiescence and no
   unknown effect/durability/cleanup. Move the same Work into a new vault
   `Retired::backup` field via the existing retirement owner. Include its memory
   in `Retired::empty/data_bytes`, restore it on a failed retirement transition,
   and refund only after the actual off-lock drain. Unknown preserves custody;
   neither `PendingPrivateSink` nor a public result supplies disposal authority.

## Still required before routes can exist

**Import selection:** two real, purpose-specific native picker phases and both
original selector owners must be retained/bound to this exact document and
operation before capture. `BackupSources::new([PathBuf; 2])` validates DATA only;
it is deliberately not picker authorization. The existing one-`GuiCall` owner
cannot simply be reset/reused for two dialogs. Do not accept renderer/CLI paths,
construct a picker receipt or reuse public-image/JKS selection authority.

**Export delivery:** a concrete retained two-destination private native sink is
not implemented. It must choose separate destinations before export creation,
own no-clobber/no-follow physical destination custody and original writes/
flushes/closes, and preserve partial/unknown delivery. The code and encrypted
backup must remain separately recoverable without the original vault/Keychain.
No clipboard, generic stdout/JSON, byte getter or `FnOnce` sink is an alternative.
Until that owner is implemented/reviewed, reject the public export action before
`prepare_export`; creating an undeliverable candidate is not feature activation.

No new Apple signing-key kind, CSR primitive, OpenSSL/keytool role or credential
generation operation is enabled by these files.

## Focused regressions pending Root's real graph

The native child contains five synthetic tests: complete random revision/read
witness comparisons; actual codec output held/charged after failure; running
producer vs undelivered custody and dishonest phase/effect DATA; checked memory
quotes; and original first-failure/STOP without deadline renewal or fake joins.
The macOS source child contains two pre-native DATA refusal tests (exact code/
backup bounds and malformed/same paths). These are not macOS IO qualification.

Actual source capture/ACL/replacement/EOF/close-unknown tests, original picker
retention, store mutation interrupted before/after readback, and private sink
delivery require their real native owners and Root's scheduled native run. No
extracted fake cipher/Fields/native harness or full suite is substituted.
