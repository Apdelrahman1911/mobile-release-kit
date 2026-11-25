# Android upload-key CLI delegation — source handoff (2026-10-21)

## Boundary and status

This packet adds a closed installed-CLI facade for **one explicitly reviewed
Android upload-key action** in the running Desktop. It reuses the existing
ApplicationService, Asset session, upload-key producer, encrypted vault and
Shell relay. It adds no crypto, native runner, general credential service,
headless window, workflow, provider request or availability flag.

The two choices are deliberately separate:

* `generate-new`: Desktop has already completed the real setup/tool check. The
  user separately confirms a new application with no existing upload key and
  allows one generation into the current encrypted vault. The result is
  **saved, unassigned**, never an automatic Bind.
* `bind-reviewed`: Desktop has already loaded and assessed one existing
  encrypted Android key to its current Bind preview. The user delegates that
  exact preview once. The result is assignment in this Desktop session, not
  remember-assignment, independent backup or release readiness.

Backup/export/import, picker permissions, no-GO acknowledgment, regeneration,
recovery reconciliation and remember-assignment remain explicit existing
Desktop actions. Full headless credential service is not implemented. Existing
shipping qualification still applies; source integration alone cannot make
generation available.

**Executed:** whole projected frontend TypeScript check and 108 inert Node
cases (14 new + 94 existing affected) before the narrow review corrections;
the corrected controller's complete 16-case suite also passes, including two
new regression groups. **Not executed:** all 21 new Rust cases, Rust
compilation, installed CLI IPC, native generation/Bind/cancellation,
Keychain, JKS, backup or Mac observation. Rust syntax is not compilation.

## Commands and authority

The same bundled `mrk` and existing IPC expose only:

```text
mrk upload-key-scope PROJECT_ID [--json]
mrk upload-key-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID --reviewed [--json]
mrk upload-key-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk upload-key-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

There are no path, key, password, tool, field, record-selection or command
arguments. Submit allocates and prints its original request ID before any
connection/send. Exact duplicates observe that row; changed duplicates and a
different project, service instance or grant cannot replay it. Unknown/lost
responses print only original Status/Stop addresses. `mrk requests` adds only
the bounded `android-upload-key` family and original request IDs.

CLI read access alone is insufficient. Three fixed MAIN adapters are added:
`agent_upload_key_access`, `allow_agent_upload_key`,
`revoke_agent_upload_key`. Allow receives an explicit tagged selection, the
exact current Asset context/status revisions, a client-created consent nonce
and the corresponding `agent-android-upload-key-{generate,bind}-once-v1`
consent. The generation declaration is
`new-application-no-existing-upload-key`. The Bind choice contains only its
existing preview operation/token, not a caller-supplied stored reference.

Native Allow captures the actual PreparedSetup or preview's **same
Arc<OriginalWork>**, exact full StoredRef/review endpoint, NativeContext,
vault key/StoreBook, project/root and SavedEditStamp. Weak references are
comparison links, not authority reconstructed from status. Two Doc cuts
surround the existing off-Doc Host/Service lookup; both rematch the original
source. The grant end is at most 300 seconds from the first cut and is also
bounded by the original Read permission and, for Bind, its original preview
end. Status, Check and reconnect cannot renew it.

The consent nonce is retained before the off-Doc call. Exact Revoke also
tombstones that nonce if it overtakes Allow **before its first Doc cut**,
using the same finite 32-consent set. A full set refuses an unseen nonce rather
than acknowledging off; re-revoking a recorded nonce still works. Revoke can
veto a pending/lost Allow, but cannot withdraw a replacement consent. Frontend
lost Allow remains Unknown even if its original permission is subsequently revoked.
The controller retains original Promise/API/epoch and rechecks current source,
peer and selection after synchronous notifications immediately before invoke.
Actual consumed Access is not a saved/assigned result.
After consumption, a fresh review still requires the original permission's
explicit returned Revoke before the frontend offers another Allow. A zero
countdown or Check cannot release that gate, and withdrawal does not prove
that the prior request completed or clear Unknown.

## Original producer, assignment and retirement

`credential_upload_key_controls.rs` remains the only Consent constructor.
The delegated call goes through its ordinary qualification and original
`PreparedSetup.attempted` CAS. The native producer still reclassifies existing
rows/preferences and performs the same `reserve_generation` CAS under its
actual NativeUse before RNG. Any existing key, reservation, pending/unknown
state or stale source refuses; no replacement/fallback is introduced.

The Bind wrapper consumes only the exact delegated preview before its original
`consume_preview` and native Check. The same kind, full reference, usable
assessment, context and real BoundLoan publication remain required. Ordinary
GUI Create/Bind cannot consume a concurrently delegated grant. Existing
Release-only cleanup remains allowed; no general stopped/private-data bypass
is added.

One fixed continuation in the existing Shell RelayBook retains the Claim and
actual caller before GO. The service row/link exists before an attempted
native preparation; any resulting SavedCommand preparation IDs are retained.
The actual Asset OriginalWork is linked before install opens GO. An attempted
preparation that fails before install is Unknown, not a fabricated no-GO proof.
Only a never-entered request can settle as preclaim refusal/cancellation.

Public terminal publication requires all three original facts:

1. the actual initiating Document caller returned;
2. the actual Asset/native retirement was captured before Slot replacement;
3. the Shell continuation's original JoinHandle returned normally.

Generate success calls the existing strict `stored_marker`: actual NEW/full
readback, durable producer journal, publication, same context/reference and
actual native/Asset/Store/private retirement. Bind success requires the real
current BoundLoan plus normal child/coordinator receipts, not merely
`resources_settled`. The fixed retirement witness is not Deserialize; IPC
cannot mint it. Later context withdrawal cannot reinterpret an already
latched historical result.

Revoke/read loss/context loss/quit forward the first original STOP. Existing
generation 180/190-second and Bind/cleanup endpoints are unchanged; an
admitted operation does not get a new five-minute work clock. Cancelled
generation cannot acquire the Android success/saved marker. Unknown joins,
poison, missing originals and loss remain absorbing and block replacement or
exit. The existing Quit original continues native reconciliation; the same
exit observer joins the retained continuation before the final `can_exit`.

## Finite memory, not a new cap

`service_upload_key_requests::DOCUMENT_BACKING` explicitly reserves 32 rows,
32 consent tombstones, their Entry/Scope/Lease/Read allocations and Arc headers,
one unsubmitted grant and fixed native-link cells. Each row budgets all
simultaneous input/status/query/full-reference/preparation string copies
(21 × 32 bytes), not just one semantic reference. Runtime IDs remain ≤64 bytes.
No row retains private payload, vault key, tool body or complete AssetStatus.

The existing eight IPC workers are unchanged. Their additional decoded and
encoded upload-key term is
`8 × (REQUEST_BYTES + RAW_LIMIT + 2 × VIEW_LIMIT)` = **106,496 bytes** with
the current 4-KiB request, 1-KiB command and 4-KiB view limits. This is not eight
new workers. The existing 64-KiB request catalogue accounts the extra 32 IDs
and simultaneous copies without changing its frame limit.

Native grant/Proof accounting includes weak allocation tombstones and owned
token/root/runtime strings. Existing actual shared material/Arc accounting is
retained. The same Shell continuation has a named concrete Future, a fixed
Tokio-1.48.0 task-cell layout/alignment quote and one oneshot allocation; the
source formula charges those rather than using RSS or an unexplained partition.
Two bounded native DTO conversion/reply buffers are also named. No existing
debit is removed and no new 16-MiB pool is invented.

The combined Document-capacity issue identified by Root/Cleanup is separate.
This source packet does **not** prove combined admission fits or widen the
existing Document reservation. Root must compose its independently reviewed
budget correction and run actual census checks; a capacity refusal must not be
reported as successful feature execution.

## Source packet and Root-only hooks

Own 13 source/test leaves: nine Rust (`service_upload_key_protocol`,
`service_upload_key_requests{,_tests}`, `credential_upload_key_delegation`,
`asset_session_agent_upload_key{,_relay}`,
`application_service_upload_key_requests`, `installed_cli_upload_key{,_tests}`),
three TS/component leaves (`agentUploadKeyAccess`, its Controller and
`components/AgentUploadKeyAccess`) and `agent-upload-key-access.test.mjs`.
This guide plus `android-upload-key-cli-hooks-20261021.patch` make 15 paths.

The detached patch has 21 shared targets, never applied in this worktree:

* `desktop/package.json`, `src/{App,bridge,types}.ts[x]`,
  `src/pages/Credentials.tsx`;
* `desktop/src-tauri/{build.rs,capabilities/main.json}`;
* `src/{application_service,application_service_request_catalogue,
  asset_session,asset_session_vault,credential_upload_key,
  credential_upload_key_controls,installed_cli,installed_cli_main,lib,
  service_protocol,service_request_catalogue,shell}.rs`;
* test-fixture-only `src/{android_build_wiring_tests,
  asset_session_installation_memory}.rs`: three cfg-matching empty State
  initializers, no grant or native proof.

Original authored parents remain in `.task-upload-key-cli/parents`.
`composed-v1` contains the actual TypeScript-tested Root78c union.
`composed-v2/{before,after}` preserves the first frozen 19 complete parent pairs from
Root78c working source, including its independently staged Device/Apple and
32-KiB catalogue-stdout fixes. Only the package test-list adjacency conflicted
in this last refresh; both existing test literals are preserved. The final
hook does not own or overwrite those Root changes. `composed-v3` preserves all
19 byte-for-byte and adds only the two fixture paths. `review-before` retains
the entire previous frozen packet; the successor delta identifies both
production corrections, regressions and the default-only fixtures. Final
manifest holds exact source/index/tree/diff and before/after hashes.

## Verification and exact pending Rust selection

Evidence in `.task-upload-key-cli/results` is preserved, including the first
Rust syntax refusal and its corrected closing delimiter:

* `node-own-v1.log`: 14 unique new inert cases PASS, 172.43205 ms.
* `tsc-v1.log`/`.exit`: whole projected frontend `--noEmit`, exit 0.
* `node-composed-v1.log`: 108 PASS, zero skips/failures, 422.122731 ms
  (new 14 plus existing asset-session/credential-upload-key 94).
* `node-review-v1.log`: corrected complete 16-case suite PASS, zero skips or
  failures, 237.795873 ms. New groups exercise exact pre-Allow withdrawal with
  delayed conflict/lost replies, and consumed permission A followed by an
  actual fresh Asset Prepare B, blocked until A's exact returned withdrawal.
* `frontend-projection-v1.json` and `frontend-cleanup-v1.json`: original source
  hashes, all callers joined, scratch/link removed, cache untouched;
  17.778525 seconds total and minimum available RAM 7,922,327,552 bytes.
* `rust-syntax-final.{log,json}`: 9 owned + 13 shared Rust files parsed by
  rustfmt before review, no module traversal/compilation/test execution.
* `rust-syntax-review-v1.{log,json}`: corrected native State/Doc source and
  both added fixture paths parsed, all exit 0; still not compilation.

The last Device/Apple parent composition and review correction are **not**
claimed as another whole-frontend execution. Only the affected controller
suite was rerun; unchanged 94-case and whole-TS evidence is retained as prior
evidence, not relabeled as a final-source run.

Exact 21 Rust names are retained in `.task-upload-key-cli/rust-selectors.txt`
and `.json`, derived from the actual declarations under these module paths:

| Selector prefix | Count | Effects when eventually run |
| --- | ---: | --- |
| `service_upload_key_protocol::tests` | 2 | Closed serde/data only |
| `service_upload_key_requests::tests` | 9 | Actual in-memory Inbox/Entry/Claim; inert callbacks, not native receipts |
| `asset_session::agent_upload_key::tests` | 3 | Strict MAIN decoder and actual State nonce/capacity predicates; no native grant |
| `application_service::upload_key::tests` | 2 | Existing private Service/Store temporary fixture; no socket/daemon/key/native operation |
| `installed_cli::upload_key::tests` | 5 | Actual collector/codec/formatter/catalogue; no IPC or native execution |

They use existing `cfg(test)`/Unix module routes. Mac and Linux original module
graphs, not a synthetic copied Cargo crate, must compile/run them. The two
Service fixtures create disposable private state through the existing fixture
owner and drop Service/Store before fixture cleanup. The other 19 have no
filesystem, process, tool or provider effects. All 21 remain **UNRUN** here.

The existing installed JKS RoundTrip and ColdReopen cases can later substitute
one genuine CLI Submit for their current Generate/Bind calls, preserving the
same single synthetic key and original 495/480-second case bounds. That needs
a separately reviewed fixed observer sibling and actual runtime evidence;
this packet does not generalize the existing local-check CliCaller, dispatch
native cases, or claim installed/backup/restart qualification.
