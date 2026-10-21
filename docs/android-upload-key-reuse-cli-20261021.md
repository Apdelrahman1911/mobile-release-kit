# Android stored-key Prepare delegation

Source-only handoff, 2026-10-21. Versions independently accepted PLAN
`36d37b101e77ed0489f62927a3e1d8ced9dc64c3157ecfb9a725ba4e60aacc12`;
Root approved implementation. Distinct actual review is required before integration.

## Scope and actual flow

Same UploadKey family, one permission, **32 total retained rows**, existing four
ID-only CLI commands and three MAIN commands. Add only explicit
`prepare-existing {recordId,expectedRevision}` / consent
`agent-android-upload-key-prepare-once-v1`. The record is chosen in Desktop, not
CLI argv. Only a nonpending encrypted Android key is eligible. Existing four
actions, their consents, native qualification and cancellation stay unchanged.

The two actual Allow cuts and consume rematch the original full StoredRef,
context, vault/key, registered source/root/Edit and READ. The new selection
retains no payload. The original `prepare_stored_vault` installs its same Load
Job with the same Entry/NativeLink attached **before allowance/install/GO**.
Review expiry is clipped to the original permission/READ, not renewed.

The original `Document.prepared` waiter is named `PreparedReply`, preserving its
ordinary return/error/polling semantics. Its closed delegated arm checks the
actual slot/link and records a compact stamp only after the genuine Load and
assessment, normal coordinator/child returns, current full reference, permitted
assessment and unexpired Bind preview. It does **not** create a full second
AssetStatus snapshot, task or native owner. The same relay retains that waiter
and Claim. `review-ready` waits for native proof, caller return and relay join;
it means a returned Load/assessment with a live preview, **not** private payload
drain, assignment, save or signing readiness. Unknown/loss/STOP never retries.

Only MAIN Access may project the optional seven-field `prepared` comparison.
The Inbox/CLI scope still omits it; request status has no preview token or key
bytes. A predeclared private attempt in the actual Asset controller plus the
original returned Allow is necessary. After the stamp, any already-running
Asset read is first joined; then **one genuinely later existing Asset status
read** must match. Events, remount, status alone and a coalesced old read cannot
create origin. Source/API/entry/peer ABA and post-notification changes refuse.
The ordinary IntentPhase/review is correlated only at that last cut. The returned
stamp's ceiling is anchored to its SAME Allow/Check Work.startedAt, intersected
with the original attempt/prior ceilings; reply or subscriber delay cannot
extend a READ-clipped review. Null, nonfinite and expired ceilings refuse.

User then inspects that ordinary review, successfully withdraws the consumed
permission, and separately allows `bind-reviewed`. No automatic Bind, second
Prepare, generation, picker, password, NEW, backup or remembered assignment.
Withdrawal after correlation preserves only the ordinary current review;
withdrawal/lost Allow cannot clear Unknown or manufacture a native join.

## Packet and integration

Donor `automation-20261019/upload-key-reuse-cli` at
`f6b8b885584e2706466b5fd55a9c260350f3b519`.
Canonical composition now uses Root
`95ef8c970f7081e085f3853fd29d6e000a099a8f`, retaining accepted memory base
`8f4c0206cfddb3d4ce2800a46055633a92188463` and the separately accepted Load-reader
correction on both sides of the vault hook. All 17 current parent images match.
Original v1 on Root `4cac1c9255576540902d993d18eeb35680c619f7` is preserved in
`.task-upload-key-reuse/frozen-v1`. No Root or actual central donor file was edited.

Exactly **18 domain source/test files + this guide + detached six-target patch**.
Exact roster/tree/hashes: `.task-upload-key-reuse/frozen.json`.
Complete current parents: `.task-upload-key-reuse/composed/{before,after}`.
`source-root.patch` beside them is the incremental 18-file domain patch against
those current parents; the ordinary branch diff additionally retains the
already accepted C debit transfer in `service_upload_key_requests.rs`.

Root-only `android-upload-key-reuse-cli-hooks-20261021.patch` targets:
`asset_session.rs`, `asset_session_vault.rs`, `installed_cli.rs`,
`assetSessionController.ts`, `App.tsx`, `desktop/package.json`.
Hook SHA-256: `f3f0c0138bfea19a16cdc8d57ac7b724d2f963d7ab946e2684cc8d08d348180b`.
No workflow, encoder, worker count, permission endpoint or transport limit change.

## Complete bounded storage

`Entry`, `Row`, `Book`, NativeScope and their 32-row limit are unchanged; the
new action uses those same rows. C's actual **eight-total IPC** quote is preserved:
`IPC_WORKER_BACKING = 4096 + 1024 + 2*4096 = 13312`, one term in existing
`application_service::ipc_response_memory`, not another eight-worker debit.
Its actual Request/Response layout calculation includes the new optional Access
field; its fixed maximum remains fail-closed. CLI still emits no prepared stamp.

The one live native Proof's `size_of<Self>` includes Selection/Reply/OnceLocks.
Its extra debit reserves **before attachment** the original Weak allocation body
and header (`size_of<OriginalWork> + 2*word`) plus the one exact 32-byte token.
All old context/Store/key weak bodies remain charged. The original Call's
measured layout includes the optional GO, same Claim and named PreparedReply.
Its task-cell/oneshot accounting is unchanged; it adds the one boxed Sleep and
both actual poll/ready result-cell layouts. The delegated None result allocates
no record list or assessment clone. Existing two 4KiB MAIN reply scratch debits
remain. Original loaded material is charged by the same Slot/source census,
never by every historical row. No cap is raised or existing debit discarded.

Actual combined 64MiB fit/layout and native operation remain **unexecuted** here.

## Evidence and required follow-up

In `.task-upload-key-reuse/results`:
- `node-v1.log`: retained initial failure (stamp needed 35 bounded nodes, old
  Access decoder allowed 32); exact original source retained beside the log.
- `node-v2.log`: **15 new actual-controller/pure-parser tests PASS**, 0.27s.
- `node-affected-v1.log`: **138 existing affected tests PASS**, 0.87s, covering
  original Asset, upload-key, backup and their permission controllers.
- `tsc-v1.log/.exit`: whole composed frontend **PASS**, 19.317s. Original caller
  joined, own projection/dependency link removed, cache untouched; minimum
  available RAM 7,843,725,312 bytes. Cleanup and source hashes retained.
- `rust-syntax-final.log`: original 16 Rust paths parse via rustfmt only, not
  compiled; this successor changes no authored Rust.
- `stamp-before.log` / `stamp-after.log`: one focused actual-controller test
  reproduces the expired-review promotion in v1, then **PASS** in 0.184s after
  correction. It covers both delayed Allow and later Check plus a genuinely
  later Asset read returned after the original shortened end. Prior 153 Node
  passes and whole TS are reused; no broad rerun. Private callback argument only,
  no public/native DTO or interface change. Exact delta: `review-expiry.patch`.

**Nine new Rust DATA tests are authored, UNRUN.** Exact selectors in
`rust-selectors.txt`; one strengthened existing MAIN grammar selector and the
affected actual common-IPC layout selector in `rust-affected-selectors.txt`.
Six pure protocol/Inbox/CLI tests, one inert named-future layout test, two
in-memory selected-reference/Weak tests. No FS/process/native/crypto/keychain
test effect. The two selected-reference tests need debug test + the actual
Linux x86_64 GNU or Mac64 vault cfg; no desktop-shell feature is otherwise needed.
Existing configured lib/installed-CLI/observer graphs must compile these hooks.

**Separate reader dependency:** Root
`95ef8c970f7081e085f3853fd29d6e000a099a8f` integrates the independently reviewed
ordinary `Child::Load` full-witness/allowance preallocation correction for the
same Linux/Mac Store/PRE/POST/close path. This packet preserves those bytes and
does not author or qualify that fix. Relevant compiled/native checks remain
pending. Backend cold-reopen tests are not CLI or real-picker proof; all existing
unavailable/unqualified paths and shipping flags remain unchanged.
