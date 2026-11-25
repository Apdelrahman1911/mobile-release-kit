# Apple provisioning: delegate one actual Desktop-prepared step

## Scope and limits

This is an IDs-only installed CLI facade over the existing Apple Saved/Asset
owners. It does **not** implement CLI Prepare, unattended setup, new account or
credential discovery, a replacement executor, or a new Apple transport. The
normal Desktop **Start** remains the primary action. Optional delegation is
under a collapsed **Advanced** section, with a separate unchecked consent for
the exact mode and original Prepared.

The fifteen closed modes are:

| Family | Modes |
| --- | --- |
| Bundle ID | `review`, `register`, `reconcile` |
| Profile | `profile-review`, `profile-reuse`, `profile-create`, `profile-reconcile` |
| Distribution key | `key-review`, `key-prepare` |
| Certificate | `certificate-review`, `certificate-create`, `certificate-reconcile` |
| P12 | `p12-review`, `p12-reuse`, `p12-save` |

`key-recover` remains refused by the existing native Context. There is no P12
reconciliation mode. Existing reconciliation is GET-only comparison of retained
history, not a reset of Pending/Unknown or permission to issue again. The
original reuse-first and account-wide journal gates remain unchanged.

These are supported *routes*, not a claim that native availability is enabled
or that every mode is qualified on a particular host. Existing qualification,
runtime, saved-source, current account and credential gates still apply. Runtime
installation, project Read access, actual Desktop Prepare, Keychain/system
prompts, credential selection, Assess/Assign and backup remain explicit Desktop
steps. There are no private key, CSR, password, certificate DER, token, path or
provider parameters in the CLI.

## Public entrypoints

```text
mrk apple-provisioning-submit PROJECT INSTANCE GRANT REVIEW --reviewed [--json]
mrk apple-provisioning-status PROJECT INSTANCE REQUEST [--json]
mrk apple-provisioning-cancel PROJECT INSTANCE REQUEST [--json]
```

Submit generates and prints its request address **before** transport. Duplicate
submission of that same request returns its original row, not another Start.
A lost acknowledgment retains the original IDs for Status/Cancel; never submit
a replacement. The shared catalogue lists the retained address, not a new grant
or proof that work finished after a restart.

The four MAIN-only RAW calls are `agent_apple_provisioning_access`,
`allow_agent_apple_provisioning`, `revoke_agent_apple_provisioning`, and
`agent_apple_provisioning_request_status`. Allow names the exact native
operation/generation/status revision, mode, nonce and fixed mode-specific
consent version. It does not deserialize an Input or construct a Prepared.

The service report is bounded redacted DATA: original disposition/reason,
decision, optional comparison/attempt/certificate ID/public fingerprint, and
an optional authenticated **record-at-completion** full reference. It never
reports that a saved record is assigned, signing-ready, backed up or still
current. A completed P12 `blocked` decision can legitimately have no saved
record. Unknown results have no positive report or saved-reference projection.

## Original lifecycle and authority

1. Native Desktop Prepare retains the actual Input, prior review and material.
   MAIN Allow performs two actual Doc/Edit/source rematches around the existing
   off-Doc Host/Read checks. It binds a one-use link in that original Intent
   before any prior review is consumed or the Prepared is taken. Ordinary GUI
   Start cannot consume the delegated original.
2. The same service receives a small Submit and records server `submitted_at`
   before its service lock or queue wait. Its retained Desktop relay claims the
   original Entry once, attaches the exact native link, consumes the original
   service saved observation through the existing writer, and enters the same
   native Start. No worker, NativeUse or window is manufactured.
3. Start still checks current Input/material/registration/census under the same
   Doc/Edit guard. Saved admission precedes actual Asset attachment. A failure
   after Saved admission retains that original and stops/drops the same GO;
   returned error is not interpreted as pre-admission or retry permission.
   Asset GO then SavedAdmitted release stay off Doc/Edit, in the original order.
4. Pre-admission expires at the minimum of the actual Prepared expiry and the
   original Read grant end. It is not retirement evidence. Native Apple
   1200/1210-second work/hard clocks start at the original Submit timestamp;
   original first-F settlement limits remain. Read revoke/expiry and context
   change feed the existing watchdog select slot even after STOP, without a
   new task or a new deadline. A normal Apple pipe-stop is not cancellation.
5. Only the existing Saved reconciliation callback, after genuine manager,
   final CAS, NativeUse, Asset/private retirement and Apple review retirement,
   supplies native completion. A small cached callback handles an original
   that retires before late link attachment. Status, a terminal DTO, OS exit,
   permission expiry or cancellation cannot produce this proof.
6. Service publication additionally requires the actual relay/admission caller
   return and the original service-history writer acknowledgment. Native
   retirement never awaits service history. Dropped/failed returns, conflicting
   native identities or unknown cleanup remain absorbing Unknown. The same
   request is independently queryable even after a later permission exists.
7. Revoke before the first Allow cut tombstones only that nonce in the same
   finite spent-consent book. Consumed permission cannot be replaced merely
   because it expired or was withdrawn: the active/Unknown Entry and original
   cleanup still fence reuse. A returned exact withdrawal is required by the UI
   before offering another permission.

The frontend models a **delegated origin**, not a fabricated GUI Start return.
Follow-on review data needs a returned Allow, exact service final query, and a
separate actual read of the same native owner, with the original conservative
delegation-time freshness anchor. Event-only terminal data and delayed status
receipt time cannot advance the flow. A reentrant peer veto before Allow was
ever invoked cancels/reads the actual unused Prepared instead of inventing a
return or restoring its Start button. An attempted/lost Allow remains Unknown.

## Fixed resource and integration boundaries

* One 32-row inbox and one 32-nonce book, not a pool per mode; one current or
  consumed permission. Request <=1 KiB, native service status <=8 KiB, redacted
  report <=4 KiB; renderer Access decoder <=16 KiB. All schemas reject extra
  fields and malformed original IDs.
* `DOCUMENT_BACKING = 32 * 24 KiB + 8 * (3 * 8 KiB + 1 KiB) + 128 KiB`
  (**1,122,304 bytes**) is a new named debit inside the existing 64 MiB Doc.
  It covers retained small scopes/rows/links, reply copies, nonce and history
  scratch. Existing native source/material/review/journal/capture charges and
  the mode-bound future quote are unchanged. There is no cap increase.
* Catalogue discovery grows from 288 to **320** addresses: two original detail
  inboxes plus eight distinct 32-row metadata namespaces. Play Cleanup remains
  namespace 6; Apple is namespace 7. The existing 64 KiB catalogue output bound,
  generic IPC caps and catalogue backing formula remain enforced. The full
  eight-family encoder and per-family overflow tests are extended in-place.
* Existing history-only service front refuses all three live Apple methods.
  Standalone installed CLI, library and installed-observer roots each declare
  the portable wire/inbox modules. The same shell relay handles Apple alongside
  the old families; there is no parallel transport or observer owner.

## Packet and evidence

Author worktree is `apple-provisioning-cli` at
`be431fb981a5dd0f80c40912b2d2cef1055fb9d2` (includes the accepted P12 startup
presence correction). The **23-target** detached hook is composed against
Root `5e2352ad9e9b04f38cc79fefa57a8d20ace602d2`:
`docs/apple-provisioning-cli-hooks-20261021.patch`.

Fourteen owned source/test leaves plus this guide and the hook form the
sixteen-file packet. Exact source inventory, hashes and before/after pairs are
in `.task-apple-cli/frozen.json` and `.task-apple-cli/parents/`. Only three
shared targets differ between author HEAD and Root: catalogue data/application
and installed CLI. Their current Root changes, including truthful CLI help and
Play Cleanup discovery, are preserved; no stale whole-file replacement is
required. Root applies the hook, not the author worktree's shared Git diff.

Author evidence (no provider or native execution):

* **148 Node tests passed**, 17 new plus 131 affected existing Apple tests;
  `.task-apple-cli/frontend-final-v2.log` (5.321 s).
* Whole composed frontend TypeScript check passed;
  `.task-apple-cli/typescript-final.log`. The exact temporary dependency link
  was removed after both returned.
* **26 Rust files syntax-parsed only**, `.task-apple-cli/rust-syntax.log`.
  **28 new Rust tests are UNCOMPILED/UNRUN**. They exercise actual bounded
  Inbox/Control/caller/history methods, native projection/cached-link methods,
  nonce guards, actual default Doc plus two inert profile payload metadata
  charges, CLI codec and the history-only front. No test constructs NativeUse
  or native private-retirement authority. Exact selectors are in
  `.task-apple-cli/rust-selectors.txt`.
* Existing catalogue encoder/fullness/source-limit and capability tests are
  changed in their actual original modules, not replaced by a new harness.
  They are also UNRUN here; Root owns the combined graph and native batch.
* Complete 23 before->patch->after and reverse source equality, current Root
  apply-check, and whitespace checks pass. Earlier Node/TS failures and the
  corrected replay-directory setup error remain under `.task-apple-cli/`;
  no test result was inferred from those failures.

Still required: independent actual source review, combined library/installed
CLI/observer compilation and focused Rust execution; then an appropriately
qualified installed Mac journey with a genuine already-prepared original,
ordinary Read, explicit Advanced Allow, CLI Submit/Status/Cancel, real native
and relay/history retirement, and unchanged credential/runtime/quit behavior.
No live Apple provider calls, real key/certificate/P12 operations, shipping
availability, headless parity, Git or Store qualification are claimed here.
