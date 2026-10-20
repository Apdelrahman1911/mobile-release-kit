# Shared Android + iOS version inventory and allocation

## Product path

Manual versioning remains the default. For one saved version source shared by
both apps, this packet adds the missing **single original paired Store check**:

1. In Credentials, explicitly choose **Use shared-version credentials**. Assess
   and assign the Google service-account JSON and ASC P8/Key ID/Issuer ID in
   that same context. Neither assignment is inferred from a preference.
2. Review the shared Store check and separately authorize Apple reads and the
   temporary Google Play edit. Apple runs first; an incomplete/unsupported or
   failed Apple inventory means **no Play edit is opened**.
3. A complete, joined, still-current pair can feed the existing version review
   and Reserve action, using the existing enrolled GitHub counter. Its actual
   source, material, account and clocks remain native gates.
4. Reserve retains the same candidate, durable pending/ACK/CAS and recovery
   behavior. Open the existing saved-version preview and explicitly Apply.
   No new writer, counter, service, executor or automatic retry is added.

This is current visible inventory, **not atomic/all-history proof**. Play may
invalidate another editor's in-progress edit for the app/account; creation and
deletion are actual remote mutations even though the edit is never committed.
Failure or cancellation can leave an edit until Google expires it. Both keys,
both inventories and confirmed exact deletion are required; there is no
single-platform, old-receipt, local-max or no-Store fallback. External uploaders
can still conflict. Shared automatic build values use the supported Android/iOS
intersection **1–9,999**; manual ranges are unchanged.

## Original context, transport and material

The only new native context is `Both / VersionInventory / Local / Candidate`,
wire `both / version-inventory / local / candidate`, with both draft platforms
enabled. It admits only GSA and P8. Existing Full/Store/signing/provisioning/
GitHub contexts, vault target gates and assessment grammar are not widened.
Each ordinary assessment still sends its real single-platform core request:
Google `Android/Store`, P8 `Ios/Store`, both local candidate. The actual native
Slot/assignment retains the same original Both context, not a relabelled result.
The frontend explicitly checks this closed projection.

The same `SelectedStoreMaterial` holds GSA plus supplemental slot zero P8;
the remaining slots must be empty. `iosRecord` names the second exact revision
and is forbidden on old requests. The fixed private input has four roles in
order: Google JSON ≤16KiB, P8 ≤16KiB, Key ID 10 bytes, Issuer ID 36 bytes. No
renderer path, raw key accessor, provider selector or second context is added.
The old single-Google callback refuses this paired material.

The existing StorePreflight owner, installed runtime, input, invocation,
cancellation ledger and C/A/W paths own **13 commands**:

| Indices | Actual existing calls |
| --- | --- |
| 0 | P8 validation under the original Store runtime |
| 1–5 | Existing finite bundled-tool probes |
| 6 | Existing bounded iOS current-inventory reader |
| 7–11 | Existing finite bundled-tool probes |
| 12 | Existing bounded Play current-inventory reader |

The two readers are sequential. Existing raw response, pagination, app binding,
filter-before-every-send, single-token/no-refresh/no-retry and exact insert-ID
then DELETE rules remain unchanged. Each query remains within its original
≤60-second command bound (Play's original 50+10 contraction); the same outer
1200/1210-second owner applies. No clock or cleanup owner is renewed between
providers. Five original finite scratch scopes replace the single query's four;
there is no final public readback file.

One public result (≤16KiB) contains the old Android and iOS summaries under
`currentVersions.{android,ios}`. Partial results can be displayed but cannot
mint a paired observation. Existing per-provider ≤1MiB raw / ≤2MiB private
framing stays sequential and separate from the public bound. Material copies
and command/control storage are not a CPython/RSS guarantee.

The original Document census counts both retained Payloads once. Additional
paired input reservation is a checked finite 149,184 bytes on 64-bit targets:
two four-part vectors, the original 1KiB header and reused eleven-row stack,
four complete 32,814-byte material copies, and 16KiB extra control/scratch.
Existing runtime/code reserves are unchanged. The weak result witness retains
both payload identities and the original NativeContext; revoking either
assignment, changing context/source, losing a join or exceeding the earliest
clock invalidates the entire pair.

## Same allocator, explicit v4

`require-current-shared-inventory` is schema/protocol v4. It requires exactly
`[android, ios]` and the ordered two original observation DATA records with
the same identity, context digest and earliest native timestamp. Existing
v1/v2/v3 domains, row bytes, replay and checkpoints are not reinterpreted.
Appending v4 upgrades only the envelope; older clients must refuse it.

The existing policy takes the maximum current/saved/ledger build floor and iOS
marketing floor, then applies the selected build/patch/minor/major rule under
the original central conditional append. Local arithmetic is not distributed
authority. Fixed repository/ledger enrollment, immutable repository identity,
branch protection/trust and append-only checkpoint rules remain prerequisites.
The native Reserve path remains branch-only; generic core exact branch/tag
policy support is unchanged, not a new native tag route.

The existing state port chooses/retains the same candidate, persists Pending
before the sole PUT, retains lost-ACK uncertainty, and durably acknowledges
reused data. Reconciliation cannot renumber. A later floor consuming a reserved
number refuses the current edit instead of allocating again. The native v4
adapter validates shape/binding only; Python is still the sole policy proposer.

Reserve keeps its original 60/70-second clock, ConnectionState, NativeUse,
state jobs and source owner. Its SourceBook really closes. The existing
consume-once Edit handoff contains both observations; Edit reacquires its own
existing GitReadSources and retains its live original source/flock during the
same RELEASE_VERSION transaction. No closed metadata becomes access, no own
publisher exemption grows, and preview/Apply remain separate explicit actions.

## Deliverables / integration

Author branch `task/automation-version-paired-20261020`, based on `4f6cf94b`, in
the reused `version-enrollment` worktree. Other branches/evidence are untouched.

Owned production leaves:

- `paired_store_versions.py`, plus actual `version_policy.py` and
  `version_allocation.py` amendments.
- Rust children `asset_session_paired_versions.rs`,
  `asset_session_paired_store_material.rs`, `paired_store_versions.rs`,
  `version_allocation_paired_inventory.rs`.
- `pairedStoreVersions.ts`, `components/PairedStoreVersions.tsx`.
- Focused Python/Node tests below.

Apply **both** accompanying shared patches atomically with these leaves:

- `version-paired-native-hooks-20261020.patch`: 29 paths, consisting of 16
  Rust parent hooks, 11 existing frontend files, one existing Node regression
  and the ordinary package test-list entry. Base snapshots are Root
  `aff7efd4`; the added iOS component/test-list snapshots are current
  `4f795bf4`. Both single-platform result components discriminate the new union
  without a cast. No App/shell/service/permission or root-module addition is
  needed: all four Rust leaves are children of existing compiled modules.
- `version-paired-python-hooks-20261020.patch`: nine original Python files at
  `4f6cf94b`: Store input/protocol/runner, credentials, Android reader, Apple raw
  reader, allocation protocol/runtime and reserved Edit borrower. The actual
  own-worktree files, not replacement logic, were tested. These nine copies
  are deliberately not committed as whole shared files.

Both patches pass read-only `git apply --check` against current Root
`4f795bf4`. Root must preserve any later CLI Reserve linkage in
`asset_session_version_reserve.rs`; this packet changes only its review
template's platform tuple. CLI Reserve3 is independently plan-approved and
owned by Root, not implemented here. Hosted headless CI still needs genuine
source/account/material producers; sharing a ledger does not grant them.

No Ruby or gem dependencies changed. Existing provider Ruby files are reused;
this packet does not require a new gem assembly. Fresh full app/runtime
composition and actual installed/native validation remain required.

## Focused evidence and limits

All commands used original joined callers, no background test jobs remain.

- `PYTHONPATH=src:tests/unit python3 -B -m unittest
  tests.unit.test_paired_store_versions`: **11 PASS**, 1.348s. One initial
  fixture-isolation failure was corrected by clearing only that fixture's
  settled synthetic retained source, not changing product cleanup.
- Affected explicit old modules `test_version_policy`, `test_version_allocation`,
  `test_ios_store_versions`, `test_android_store_versions`,
  `test_android_store_versions_owner`, `test_desktop_store_preflight`,
  `test_desktop_version_allocation_runtime`, `test_reserved_version_edit`:
  **107 PASS**, 3.461s. All commands/provider responses mocked; only owned
  temporary Source/Init/flock/version-file work is real.
- Exact frontend hook projection + new unchanged test file via Node
  `--experimental-strip-types --test --test-isolation=none --test-concurrency=1`:
  **11 new PASS**, 236.681ms; affected Android/iOS/Reserve tests **37 PASS**,
  287.891ms. No DOM, native port, key or external action. Projection copies the
  exact packet and ordinary dependencies, not shadow policy/controller code.
- Four new Rust files and 16 projected parents pass rustfmt syntax parsing;
  **five new Rust tests and one extended actual-terminal test are UNRUN**.
  GSA admission remains Mac-only: the portable fixture tests original weak
  custody/closed projection, and cannot enable a Linux credential route.
- Task-local logs and exact projection manifest remain under
  `.task-paired-version-hooks/`. No native process/provider/GitHub/Play
  mutation, Cargo, full TS/React build, signing or installed qualification was
  run by this lane. Source review and Root's combined graph tests are pending.

Material new cases: v1→v2→v3→v4 immutable replay; four increments/9999 boundary;
one earliest pair clock; marketing-only iOS; APK/current-track floors; first
reader failure with zero Play insertion; failed DELETE; same original four
roles/13 commands; either assignment/context ABA; source drift; real temporary
Reserve→preview→Apply→restart/same-candidate with exactly one fake PUT;
post-notification Prepare/Start vetoes; lost ACK retains original controls.
