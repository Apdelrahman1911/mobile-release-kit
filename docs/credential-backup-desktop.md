# Desktop encrypted-backup entry

This is the bounded Desktop wiring slice above the original backup picker and
private pair sink. **Backup/restore remain unavailable pending focused native
Mac verification.** Existing vault availability does not enable this new route.
Key generation, Apple CSR creation and installed CLI backup are not added here.

## Two explicit actions

- **Back up…** beside an encrypted stored item sends only
  `vault_backup_export({contextRevision, record:{recordId, expectedRevision}})`.
- **Restore a backup…** sends only `vault_backup_import({contextRevision})`.

The native dialogs choose both inputs or both destination folders. The renderer
never receives paths, file bytes, private keys or the recovery code. Restoring
uses the existing New-only store path; no replace, assessment, assignment or key
generation is performed automatically. The page explains the separate recovery
code and preserves an already-open private-input form instead of discarding it.
Detailed native status and the existing platform limitations are disclosures,
not another wizard.

The existing `AssetSessionController` retains the original operation identity,
current project/draft/context, synchronous busy state and cancellation. The new
actions also match the exact committed display snapshot before and after
`syncProject`. Only that command's own reply identifies its operation. An event,
poll, record count, storage effect or idle phase cannot substitute for it.

## Root-only integration patch

Apply `credential-backup-desktop-hooks.patch` to the integration tree, not this
lane's older central files. It changes exactly twelve shared files:

- `assetSessionTypes.ts`, `assetSessionProtocol.ts`, `assetSessionController.ts`,
  `bridge.ts`, `preview.ts`;
- `asset_commands.rs`, `asset_session.rs`, `asset_session_vault.rs`,
  `credential_backup_selection.rs`, `shell.rs`, `build.rs`, `capabilities/main.json`.

New native children are `credential_backup_commands.rs` under `asset_commands`
and `credential_backup_desktop.rs` under the existing vault owner. Commands use
the existing main-window/body checks and exact `DocumentBinding`, not a renderer
project path, generic filesystem call or new native lifetime. Both entry methods
and status use the same backup qualification predicate, which is initially
closed even on an otherwise vault-qualified Mac.

Wire additions are backward-compatible optional `backup:{available,reason}` and
`operation.backupDelivered:true`. Missing backup capability means unavailable;
the marker is omitted unless the current original really published the pair.
The existing publisher alone sets `backup_export_published`. Beside it, a fixed
nonsecret `(context revision, full StoredRef/read witness)` stamp survives the
ordinary working-reference retirement. Current projection checks the exact
context, vault/registry generation, record random revision and witness, original
joins, private retirement and absence of failure. The stamp grants no material
loan or disposal permission and retains no secret payload. Existing size-derived
memory accounting and backup disposal rules are unchanged.

## Verification and remaining qualification

The focused `desktop/tests/credential-backup.test.mjs` run uses exact copies of
the real Root frontend plus the unapplied patch, not extracted controller or
protocol substitutes. Sixteen DATA/promise tests passed with no skips. They
cover closed request shapes, old-host unavailability, current marker meaning,
fixed bridge/preview behavior, stale view/project/record, duplicate clicks,
cross-feature busy state, missing/overtaking own replies, unknown settlement,
explicit original cancellation and no automatic assessment/Bind. The task-owned
source projection was removed after the original Node process joined.

Two new Rust children passed rustfmt parsing only. Their three command-admission
and four actual-state projection/retirement regression tests have **not** run
in this lane. Root must compile the real combined graph and run these filters:

```
asset_commands::backup::tests
asset_session::vault::backup_desktop::tests
```

Root's earlier 17 portable Scope B tests passed; that is not native backup
qualification. Still needed: shared TypeScript check; actual Mac shell/native
compilation; original two-picker/window/cancellation and one-IO-clock cases;
private source/destination exclusions and no-clobber custody; both file and
directory sync/close outcomes (including rename-before-dirsync STOP); authenticated
New-only restore and preserved uncertain outcomes. Use synthetic private fixture
material only. No native gate, installed feature, live key generation or account
operation is qualified by this source or the Node tests.
