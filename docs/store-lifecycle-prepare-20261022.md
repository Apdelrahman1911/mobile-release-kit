# Remaining Store lifecycle: genuine CLI preparation

Base `324ada874bb5ef3213c60ea339e31590d8e45b8e`. SetupUI independently
accepted plan `../store-lifecycle-prepare-plan/plan.md`, SHA-256
`a018265d5c52ab5c3da7a420627f6f16140d02089ec51a9ceed6aca6b1750c0a`.
Root reviews this implementation. No native/provider action or qualification
is claimed by this packet.

## Closed increment

Eight additional selections reuse the existing `store-prepare` / `store-start`
commands and original Store owners:

* Android/iOS external-testing Execute;
* Android/iOS production-submit Execute;
* Android/iOS current-internal Reconcile;
* Android recovery settlement;
* iOS external readiness.

The old thirteen encodings and consents remain unchanged. New selections use
the existing pure release Review through one present-only `release` field;
`release:null`, missing inner nullable fields, mixed selection arms and
unsupported modes refuse. Candidate/stage receipt UUIDs remain historical IDs,
not the new native Prepared ID or its separate native authorization.

`Input::Execute` and new `Input::Reconcile` use the original parsers, current
Context/material, native domains, budgets and decoders. Execute's actual Start
still borrows `ExecuteMemoryAdmission` from the same locked Document and
material; Reconcile uses its original budget and cannot receive that loan.
iOS later/readiness selection retains only three fixed actual RecordKey + Weak
Payload identities. Existing contact/demo/commitment policy and full material
census still apply. No private values are copied to CLI DATA.

The original optional Prepared attachment, post-commit construction fact,
Prepare and Start caller returns, native retirement and history ACK are
unchanged. The ordinary Reconcile frontdoor now checks the same original
linked-origin guard before its destructive `context_changed` tail. Losing GUI
or foreign Start cannot consume/retire the linked Prepared. Shared permission
revision is still obtained by explicit Check before acknowledgement; Prepare
has no Store HTTP and never authorizes Start. Start requires another fresh
Check/acknowledgement and its exact mode consent. Status/receipt/checkpoint is
not a join, previous-finality proof or permission to retry.

The renderer uses the actual existing stage Execute and Reconcile factories.
Android current/settlement takes the same matching-project AndroidBuildProject
application observation as ordinary Android Reconcile, **not** a tool loan;
only old Android candidate upload needs tools. Other six new selections use the
existing platform-neutral saved project observation. The App peer comparison
now has four explicit native domains, including exact recovery-settle Context;
it still cannot clear an original GUI Promise or manufacture a GUI Attempt.
The phase preview names source/lineage/credential references and the distinct
promotion, draft/manual submission, temporary Play edit and local-checkpoint
effects. Old evidence and uncertain cleanup remain retained.

No generic later/production Reconcile, paired Execute/Reconcile, iOS recovery
settlement, Android readiness, new upload/build transformation, edit discovery,
new transport/owner, automatic operation/retry or availability flag is added.

## Backing and tests

Unchanged: Store32 and all retained failure rows, shared eight IPC workers,
2MiB Store backing including the full History512KiB term, RAW/Status8KiB,
128 nodes/depth8, native fixed128KiB (96KiB Doc +32KiB Saved), original clocks,
READ/earliest-F and source/caller/cleanup gates. The extended tests include
largest Selection/Basis and report capacities, actual largest Input cells and
parsed maximum-length source/name + three supplemental references. Material
payloads stay in the original full census. Existing complete formula remains
`32*(3*8192) + 8*(4096+2*8192) + 163840 + 131072 +
3*128*512 + 8192 + 524288 = 1974272 <= 2097152`;
its typed cell/heap sub-bounds still must pass in the real target build. This is
not a claim of measured default-Document, runtime layout or native fit.

Actual author evidence: **32 unique Node tests passed**, zero failures/skips,
1.461s, using the existing nonroot/networkless bounded Node route. Six new
cases cover real factories, old/new grammar, original receipt semantics,
separate effects/Start, real two-controller caller retention and foreign peer
refusal. The original caller returned; exact task projection was retired.
Existing frontend bytes are unchanged since that run. No full TypeScript,
Cargo, Rust tests, native or provider execution was performed for this packet.

Seven new Rust tests and nine affected selectors are in
`.task-store-lifecycle-prepare/test-selectors.json`; **all are unrun** here.
They exercise original decoders, actual Entry/Book/Saved unentered DATA
fixtures, both return orders, failed history, lost callers, full 32 rows,
fixed-three original payload comparisons, capacity refusal and real CLI codec.
They do not fabricate material admission or native retirement. Rust source
syntax was parsed only, without compilation. Root's independent Mac-discovered
candidate fixture correction is included verbatim: four literal wire
limitations replace the illegal private `execute_wire::LIMITATIONS` reference;
no production constant visibility changed.

## Integration boundary

Eight owned implementation/test files plus this guide and the detached patch
are staged. Exact source/parent/evidence pins are in
`.task-store-lifecycle-prepare/frozen.json`. Apply the six-parent patch once:

1. `saved_command_agent_store_release.rs`: sibling-visible existing `details`;
2. `asset_session_store_reconcile.rs`: early original-link guard;
3. `App.tsx`: matching Android observation and explicit Reconcile peer;
4. `installed_cli.rs`: truthful closed21 discovery/help;
5. `installed_cli_store_prepare_tests.rs`: exact catalogue/receipt codec cases;
6. `service_local_history_tests.rs`: neutral `release:None` field.

Before/after images are exact base324; preserve newer Backup/Candidate/History
and other Root hooks by surgical composition, never whole-parent overwrite.
History Prepare's independent new Selection fixture also needs `release:None`.
No new module or command/ACL is introduced, so lib, mrk and the independent
installed-shell module catalogue need no added declaration. Root batches
actual compilation and native qualification separately.
