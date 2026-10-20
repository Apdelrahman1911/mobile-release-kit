# Pending Apple Distribution key — local storage/helper slice

## Status and scope

This packet is **source for an unfinished native feature**, not evidence of key
generation, usable signing, a delivered CSR or backup, or certificate issuance.
All local helper tests replace cryptography/process/file effects with synthetic
objects. The actual Rust codec tests have not run yet. No availability flag,
ordinary credential purpose, picker role, Store grant, or release rule changes.

The native flow is deliberately two separate original operations:

1. Explicit local preparation: retain the real Apple SavedSession, Asset vault
   owner, reserved NEW identity and durable pre-generation intent; generate once;
   save the private material; authenticate and compare the whole NEW readback;
   acknowledge `keySaved` durably; finish all original jobs and private disposal.
2. Separately approved certificate work: acquire a fresh current stored-key loan,
   verify its private key/CSR/public key again, and only then disclose the public
   CSR under the original certificate-request permission.

An interrupted or unknown first operation must not create a second key. A record
ID, CSR hash, helper return, encoded ACK digest, or listed descriptor cannot
replace these native facts. Restoring a backup creates a different NEW reference;
it never restores the old intent's ACK, assignment, or issuance permission.

## Implemented leaves in this packet

- `fastlane/apple_distribution_key.rb`: one fixed local RSA-2048/e65537
  generation and SHA-256 CSR using bundled Ruby's maintained OpenSSL APIs. The
  subject is a fixed product string, not a project/account label. It emits one
  private binary frame, never JSON/control output, a public CSR, or a key file.
- `fastlane/apple_distribution_key_verify.rb`: verification only, without a
  generator fallback. It reads the exact original FiniteScratch file, checks
  restrictive descriptor identity/size/EOF/close, validates canonical PKCS#8,
  canonical CSR/signature and full SPKI equality, and signs/verifies one fixed
  non-account challenge. Its output contains only the original public CSR/SPKI.
- `_desktop_apple_distribution_key.py`: fixed child of the existing
  `AppleProvisioningRun`, using its actual StoreRuntime, cancellation, command
  and FiniteScratch. It retains the original command outcome slot **before
  acquisition/GO**. A late STOP that prevents `CompletedProcess` return cannot
  discard the original raw capture. Unknown original joins leave that capture
  rooted and unparsed. No second process/input owner, HTTP client, journal,
  deadline, generic bytes callback, or generated-key disposal method is added.
- `credential_apple_distribution_key_fields.rs`: private zeroizing scalar
  storage and fixed binary/canonical Base64/PEM framing. This is encoding DATA,
  not cryptographic verification or custody. Full readback equality compares
  every retained scalar, not only a public hash.
- `vault_crypto_apple_distribution_key.rs`: fixed NEW-only reservation bound to
  the actual VaultKey allocation, vault identity, fresh record and random
  revision/counter1. A sealing attempt consumes that reservation even on error.
  It uses the existing descriptor/payload AEAD, not a new cipher or secret.

The three private scalar names are `privateKeyPkcs8Base64`, `csrPem`, and
`publicKeySpkiBase64`. Maximum raw lengths are 3072/4096/1024 bytes; their maximum
stored text lengths are 4096/4096/1368 bytes. The private frame ceiling is 8233
bytes. The original native census must charge actual raw, encoded, parser and
transport capacities together before GO; the new constants do not refund the
parent's original backing. Owned Rust buffers use the existing zeroization
patterns. No promise is made to erase Ruby/OpenSSL/GC, allocator history, swap or
process memory.

## Closed stored-only kind and independent recovery

`AppleDistributionKey` / `apple-distribution-key` is an **encrypted storage and
list-only kind**. It is absent from ordinary `kind()`, `enabled()`, FileKind,
manual `ASSET_KINDS`, assessment and Bind. Its descriptor requires exactly three
present scalars, no file and no label. It lists as unassigned/not-checked without
scalar values. `Payload::usable_source` is false; ordinary prepare and generic
removal explicitly refuse it. Existing descriptor/record spellings and cipher
domains are unchanged. Unknown newer kinds fail without modifying their bytes.

The existing independent encrypted backup format can carry this descriptor and
payload. The existing native import remains NEW-only and must authenticate and
compare its entire readback. Cleanup owns the separately reviewed correction to
`credential_backup_native::import_new`, which previously read only a descriptor:
its `ImportedBackup::matches_authenticated_readback` / BackupSources wrapper is
a **required native restore dependency**, not an already-passed test in this
packet. No backup file, recovery code or native picker was produced here.

After restore the fixed verifier must inspect the actual new stored-key loan.
Public-key equality is necessary for explicit journal/certificate reconciliation
but does not revive an old grant. Pending records cannot silently become P8,
P12, profiles or usable signing credentials, and generic deletion cannot discard
an unresolved key intent.

## Root-only hook packet

`apple-distribution-key-storage-hooks-20261020.patch` has 13 targets, projected
against Root `d86ddc92b25c93dc0edf2dcda37dfe1d73317786`. The source lane remains
based on `3f0e73df4124467be4d63a8c6615168ead2070a0`:

1. `asset_commands.rs`: private fields child, stored-only kind/field roster and
   authenticated stored-fields decoder; ordinary field admission unchanged.
2. `vault_format.rs`: strict stored descriptor encoding/decoding.
3. `vault_crypto.rs`: fixed reservation child, reserved revision seam and
   authenticated payload decoding. Root must preserve the specialist's separate
   `AppleProfile` reserved-kind arm when composing its packet; neither arm may
   permit arbitrary caller-selected reserved kinds.
4. `asset_session.rs`: unusable ordinary source and closed session-kind gate.
5. `asset_session_vault.rs`: honest descriptor row and prepare/removal refusal.
6. `assetSessionTypes.ts`: descriptor-only `StoredAssetKind`, not `AssetKind`.
7. `assetSessionProtocol.ts`: encrypted/unassigned/not-checked/null-label only.
8. `CredentialSession.tsx`: one explanatory row using existing backup control;
   ordinary assess/removal disabled, no new wizard or creation button.
9. `_command_process.py`: fixed key-only original outcome-slot binding at the
   end of `_Outer.__init__`, after backing initialization and before acquisition.
10. `build_inputs.py`: one finite verifier layout/filename/8233-byte bound.
11–13. `tooling.py`, `pyproject.toml`, `macos_store_runtime.rs`: literal generator
   and verifier helper rosters. Existing Ruby/Bundle executable roles and the
   complete signed runtime inventory remain unchanged. No dependency changes.

Preserve later Provisioning context, backup-integrity and profile changes. There
are no applied edits to these shared files in this lane.

## Remaining actual parent integration

The new helper is not reachable through existing Bundle/Profile modes. Apple
owns the same SavedSession/journal-v3 extension with closed modes `key-prepare`,
`key-recover`, `certificate-review`, `certificate-create`, and
`certificate-reconcile`. Its fixed child hooks must:

- Retain this `AppleDistributionKeyWork` and constructor/output reserves before
  private input, scratch or command acquisition; bind its exact scratch;
  call `admit_command` only for the fixed helper/environment/limits.
- Mint and durably record the original reservation, then consume the genuine
  pending ACK before local helper GO. A digest merely compares that ACK.
- Supply `distribution_key_material(operation)` as the same retained tuple of
  three native fields for reuse; no P8/Signing loan or renderer scalar input.
- Use a distinct retained generated-key receive/trailer and keySaved ACK. Do
  **not** reuse profile's empty-on-failure trailer or infer never-generated from
  save-not-started. Possible/partial output remains private and recovery-required.
- Use the actual `AppleProvisioningClock` minted by that same SavedSession,
  retaining its original endpoints/minimum first failure. No Asset default10s
  clock or renewed late-operation budget.

The separately authored but **unwired/unreviewed** native leaves
`credential_apple_distribution_key_native.rs` and
`credential_apple_distribution_key_store.rs` are not part of this finite packet.
They propose the actual Asset OriginalWork/StoreBook destination and fresh loan,
with NEW/full-readback/physical-witness/retirement checks. They depend on Apple's
genuine `AppleKeyPendingAck`, `AppleKeySavePermit`, `AppleKeySavedAck`,
`AppleKeyNeverGeneratedJoined` and `AppleKeyUseJoined` types and require a later
combined actual review. No placeholder token or fake acknowledgement may enable
them. P12 association, release signing, native backup, UI/resume and installed
Mac qualification remain unfinished.

## Focused evidence

- `ruby tests/workflow/test_apple_distribution_key.rb`: **9/9**, 95 assertions,
  zero skips (synthetic OpenSSL/file objects only). Syntax checks of all three
  Ruby files passed.
- `PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -q
  tests.unit.test_desktop_apple_distribution_key`: **10/10**, zero skips.
  Every would-run command/scratch is substituted. Late-STOP and unknown-original
  branch observations are expressly DATA, not native finality receipts.
- Nine actual Rust codec/fields tests are authored but **UNRUN**, including
  independent re-seal to another vault/new reference and unchanged old descriptor
  bytes. Rustfmt syntax checking is not compilation. Six more native-leaf tests
  belong to the unwired follow-on, also unrun.

Logs are retained only in the lane's `.task-apple-key-results/`; no private
material, Store response or native account was used. Root schedules the real
combined graph and any eventual narrowly approved Mac verification.
