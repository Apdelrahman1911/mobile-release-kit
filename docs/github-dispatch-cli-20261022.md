# Existing GitHub workflow / first-counter CLI delegation

Implementation of accepted plan `98e61c453cac269f184c5827ed09623323565791e5a98d484df7fc6fc2bccaac`. Donor base: `546209847d9c787cd7db7b886b08c63cc4582ed7`. This is a source-review packet, **not native/provider qualification**.

## Delivered scope

The existing three ID-only CLI verbs and GH9/shared32 Inbox now reach twelve additional, separately approved actions:

| Kind prefix | Actions | Actual existing owner |
| --- | --- | --- |
| Preflight | Prepare, Dispatch, Pending, Observe (fixed Track or Reconcile) | original Preflight / selected Connection |
| Release | Prepare, Dispatch, Pending, Observe (fixed Track or Reconcile) | original Release / selected Connection |
| Counter / Publication | CounterPrepare, CounterCreate, PublicationPending, CounterReconcile | original Publication / CounterStateProof |

Release retains Android/iOS × candidate/external-testing/production-submit and valid recovery forms. Preflight Dispatch may run project code, download dependencies and consume hosted resources. Release Dispatch may sign/upload/promote/submit. Prepare does **not** dispatch. CounterCreate remains first creation only; it cannot overwrite/enroll/reset/allocate. Counter Prepare may enter the original private local state-location facet. The existing warnings and separate, exact one-use mutation confirmations remain visible.

Old seven selections, consent strings and CLI Submit/Query bytes remain compatible. Ordinary five-file Setup Prepare remains Desktop-owned; its already-supported Publish/Reconcile and generic Pending loader are preserved. No new transport, endpoint, permission namespace, workflow, automatic polling/retry/dispatch, remote-run cancellation, resolver or Store action.

## Critical actual ownership cuts

* The new CLI-safe protocol/requests are children of the existing service modules. Native capture is a child of the original Connection/Asset state. All three crate roots (lib, `installed_cli_main.rs`, installed observer) were source-checked; no new root declaration is needed. No new Tauri handler/AppManifest/ACL: the existing four MAIN handlers are reused.
* MAIN selection captures the real private native arguments, account/repository/root/Edit/credential end and controller revision. Release confirmation and Counter purpose/state proof are checked by the original native commands. Counter app-data comes only from the original shell application path, not CLI input.
* The existing permission epoch is compared at both Doc cuts and consumed **immediately before the first fallible Inbox install**, not after native install. Error/unknown cannot reuse N. Revoke still stops originals on overflow; no Doc/Book is held over Service IO.
* Before spawning, the optional service Entry is on the original gate and Supervisor. GO does not manufacture provider success. Original workflow 10+2 seconds and Publication 60-second policy are unchanged, including earliest READ/STOP polling through cleanup.
* A generated private Consent/record has a distinct `Weak<Entry>` producer, not the consumer `Weak<NativeScope>`. Its positive query requires matching native return, original relay return and latest history ACK. New permission/READ/source gates provide later authority; a completed producer is not revalidated as a still-live consumer. Cancelling that completed request does not revoke a separately captured successor.
* Workflow record witnesses retain the actual accepted full native rows and original moved Edit stamp, operation, digest, context and end. Public compact Pending data is not a native intent or retry permission. Publication uses its original PendingRead and a Counter-only selector; Setup selection is unchanged.
* Actual Connection acceptance/control/currentness/retirement precedes native service publication. Native, relay and history returns stay separate. Known NeverAdmitted is not fabricated native retirement. Unknown and earliest failure remain absorbing.
* Existing controllers distinguish CLI origin from a GUI call. An event cannot fabricate the original GUI Promise return. A matching service terminal followed by a separately joined native Status/Check is required before adopting the real review/record. A new mutation needs a new joined permission Check and ACK; failed/lost Allow is not rearmed.

## Retained representation / limits

The GH retained debit remains **786432 bytes**, one shared32 pool. Each row owns at most one Activity **or** Dispatch snapshot. New compact snapshots use fixed binary digests/IDs and scalar fields; actual Vec capacities, enum padding and Arc headers must fit the same4096-byte snapshot envelope. Full64-record Pending output is represented or refused, never truncated. Full native input/Prepared/journal copies stay charged to their original Connection/Publication state.

CLI remains1024 bytes. Only the new Prepare MAIN input uses the closed4096-byte decoder; old variants remain1024. New native input/root/context physical capacities are checked before retention. The existing ancillary call allowance is explicitly named `MAIN_CALL_BACKING = 2*ROW_BACKING + 16KiB = 48KiB` (not an additional debit). Its checked native phase sums five bounded root allocations, three input allocations, two account/context groups, raw MAIN bytes, a complete unused scope, actual Review/NativeProject/RegisteredRoot/Allow/Edit-stamp ABI cells, and fixed validation/control backing. Current-root comparison copies are dropped before installing the scope. Full actual ABI and default-Doc admission remain **unrun** and must pass; no assumed spare capacity or removed originals.

Shared IPC remains the same eight-worker mixed quote with the existing Metadata lease. New output remains within the already-reserved8192-byte typed MAIN/CLI projection; no per-family eight-worker charge or frame-limit increase.

## Packet / integration

* New leaves: ten Rust files (including three focused test siblings), one TS helper, one Node test leaf; accepted plan, this guide and the Root-only hook patch are the three documentation files.
* `docs/github-dispatch-cli-hooks-20261022.patch`: **43 existing-file deltas only**. Complete current before/after images and hashes are under `.task-github-dispatch-cli/current-parents/`. They were composed without conflict against actual Root HEAD324ada plus staged tree8238df7c; donor images remain separately preserved under `parents/`.
* Root must integrate only these deltas, preserving unrelated concurrent work. No shared working file was edited by this author. The manifest, exact staged tree/diff, owned hashes, full parent pins and evidence hashes are in `.task-github-dispatch-cli/frozen.json`.
* `rust-new-selectors.txt` contains18 new methods; `rust-affected-selectors.txt` names the directly affected old checks for Root's deduplicated batch. All Rust tests remain **UNRUN**. New tests use in-memory unentered owners/real comparison methods; no provider/native/files/socket effects or invented native admission proof.

## Actual bounded author evidence

* Node v3: **111 PASS, 0 failed/skipped**,1.326s; **107 distinct test bodies +4 imported-file sentinels** (17 new,90 old). Existing nonroot/networkless projection,384MiB heap, original caller joined and exact scratch removed. Node v1/v2 failures are preserved: old event-only finality test expectations and wrong Counter fixture field/marker were corrected, not hidden as product/native success.
* One corrected whole composed TypeScript noEmit: **PASS**,20.282s, minimum available memory8,000,794,624 bytes.768MiB heap, original caller joined, owned projection/dependency link removed. Initial v1 unused-import/narrowing diagnostics are preserved; fixes were type-only, so no duplicate Node rerun. Actual Root324ada frontend composition and every input are recorded, not attributed to the donor alone.
*36 Rust source files syntax-parsed only; no Cargo/typecheck/test/native claim. Three-root child-module reachability is source-only evidence. Initial ad-hoc graph checker wrongly treated Publication's existing child as a root; no source or compiler defect was inferred.
* No Python engine/HTTP policy changes, provider calls, native dispatch, Git writes, builds, availability flags or CI executions were performed for this packet. Independent ACTUAL review and Root's combined compiled/native accounting gates remain required.
