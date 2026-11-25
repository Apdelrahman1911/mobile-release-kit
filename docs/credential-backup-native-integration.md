# Private credential-backup adapter — integration boundary

This document records the **Scope A checkpoint** (`cd7ac643`, `a60527e3`).
The subsequent concrete picker/private-sink source and its additional unapplied
Root hooks are described in [Scope B](credential-backup-picker-integration.md).
That addition does not turn either checkpoint into native qualification.

This is **not an enabled or natively qualified export/import feature**. The
previous codec/reference slice (`d6abb5b5`) passed Root's actual no-default crate
compile and 19 focused Rust tests. The source-reviewed native children
(`cd7ac643`) and these narrow parent hooks have only passed Rust parser and diff
checks. Their focused tests and the actual macOS/native graph are pending. No
real signing key was used.

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

## Narrow parent integration and remaining Root-owned patch

These are source hooks, **not permission to register an IPC command**. All
existing document, exact context/generation, cancellation, memory, provider and
native qualification gates remain. In particular Linux persistence stays off.

The following parent/source hooks are implemented in this worktree under
Root's narrow file-ownership transfer. The separate
`credential-backup-parent-hooks.patch` contains only the still-required
`asset_session.rs` changes; it is **not applied** here because Root owns that
file. Both pieces are required for the actual graph to compile and its census/
admission tests to mean anything. Neither piece registers a public route.

1. Module graph:
   * `asset_session_vault.rs` declares
     `#[path = "credential_backup_native.rs"] mod backup_native;` on the parent's
     existing target profile.
   * `asset_source_macos.rs` declares the `backup_sources` child at
     `credential_backup_sources_macos.rs` and reexports `BackupSources` crate-only.
     `asset_source.rs` reexports it under the same macOS LP64/ARM64+x64 cfg.
2. Original custody: vault `Work` retains `backup: backup_native::Work`. Its
   `settled()` also requires `backup.native_settled()`. The Root-owned patch adds
   its actual `retained_bytes()` to the owner census. Failed/poisoned census is no
   credit. The quote separately reserves 1 MiB of native roster/control storage
   plus the existing 8 MiB parser arena; actual ciphertext/plaintext capacities
   are counted as well. Source control is derived from the existing finite
   descriptor, component, alias and path limits, not an unbounded allocation.
3. Closed dispatch: `Child::Backup(backup_native::Request)` is large work.
   It calls `backup_native::execute(owner, &mut actual_book, request)` from the
   existing parent store-lock/child path. **Do not classify this entire child
   as a mutation in the parent's final `remember`:** the store retains a prior
   operation's outcome until the actual new `mutate` begins. Capture/auth/STOP
   before that point must not replay that outcome. The backup import itself
   remembers only the actual fixed New call, immediately before readback;
   the parent still records first failures. `ChildResult::BackupPrepared` and
   shell-only `Job::Backup(Request)` use the existing coordinator path. The
   Root patch admits only this exact retained, still-unentered Request through
   the private-data allocation fence; unrelated child jobs remain blocked.
4. Separate operations: `PrepareBackupExport` and `ImportBackup`, not ordinary
   `Commit`/`Save` or a fake file kind. Preparation functions expect the genuine
   newly reserved vault slot with current context, same key/store and roster.
   Import preparation reserves the existing row/inventory cells before IO.
   After the original selection/preparation, `backup_native::run` calls the
   parent's fixed `begin_backup_import` while holding the genuine current
   document gate, before this same child's GO. It marks the slot/session
   mutating and supplies the initial NotStarted/NotRun/Pending outcome; there
   is no second installation. Original operations survive STOP; import
   failures enter the existing interrupted/read-only/relock path.
5. Post-join publication: `Staged::BackupPending { generation }` has no
   dynamic public data. Only after original child/coordinator joins and existing
   current gates may `backup_native::pending_publication(&work, &session)` project
   pending/undelivered. Its slot stays Selected, not Idle/completed/delivered,
   with no preview, token, assessment or renewed review clock. It grants no sink.
   `Staged::Mutated` admits `ImportBackup` only in a **separate New-only arm**:
   no old row/target, counter 1, capacity, existing known-applied/confirmed/known
   checks, same current key/store, and
   `backup_native::new_publication(&work.backup, identity, record,
   row)`. It uses ordinary `publish_saved_revision`; separate assess/Bind remains.
6. Disposal is different from producer quiescence. `blocks_reuse()` remains true
   while private input/output is held, even if the child joined. Ordinary idle,
   context/reset, owner replacement and allocation admission cannot drop or
   bypass it. The Root patch adds the census, idle/allocation fences and fixed
   Discard/Lock marker; a generic STOP/status/discard flag is not consent.
   The actual private-data-empty gate checks both the current Work and the
   original off-lock Retirement holding (failed locks mean not empty), so
   session lock/quit cannot report closed over quiescent retained backup data.
   An original cleanup-only `Release` may still close its existing
   store; it must not become a new backup/import attempt. Before an explicit
   undelivered discard or an accepted New publication is disposed, use
   `backup_native::retirement_ready(owner)` **without holding vault work**.
   It requires actual original normal joins, including the prior coordinator
   and failed-child history preserved across a cleanup-only continuation;
   current cleanup Returned cannot rehabilitate a failed original. It also
   requires source/store quiescence and no
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

The native child contains ten portable synthetic tests: complete random revision/read
witness comparisons; actual codec output held/charged after failure; running
producer vs undelivered custody and dishonest phase/effect DATA; checked memory
quotes; original first-failure/STOP without deadline renewal; actual parent
census across same-Arc retirement/restore/off-lock disposal; explicit discard
refusing failed joins or unknown outcomes; and closed Request allocation
admission versus other work; actual private-empty/quit predicates across retained
Work, off-lock holding and genuine DATA disposal; and preserved failed original
joins despite current cleanup Returned. Synthetic join values in these predicate tests
are explicitly DATA, never native finality. Of two additional macOS-only tests,
one uses actual parent dispatch but refuses before any native acquisition,
proving an unentered import cannot overwrite its initial intent with another
store outcome; the other checks unknown-import custody against the actual
private-empty/quit predicates. The macOS source child contains two pre-native DATA refusal tests
(exact code/backup bounds and malformed/same paths). None is macOS IO
qualification.

Actual source capture/ACL/replacement/EOF/close-unknown tests, original picker
retention, store mutation interrupted before/after readback, and private sink
delivery require their real native owners and Root's scheduled native run. No
extracted fake cipher/Fields/native harness or full suite is substituted.
