# Installed CLI: historical Android tool catalogue

Scope: `mrk android-tools PROJECT_ID [--json]` reads one bounded, volatile
observation from the running Desktop's existing catalogue owner. It does not
inspect, recover, select, acquire or validate tools. It does not execute project
code or grant a build, and does not access credentials.

## Actual producer and authorization

The existing retained shell relay already calls
`DocumentBinding::android_toolchain_catalog_status`, which reconciles the SAME
`SavedCommandOwner` catalogue originals. The new hook forwards that exact
returned `Status` **after** its Document/registry guards are released. No socket
handler calls a Document/native method and no extra observer, timer or task is
introduced.

`ApplicationHost::publish_android_tools_catalogue` TRY-checks that the existing
service is initialized in Ready/Listening, then drops Control before projection.
A dormant host remains dormant. One memory-only `ObservationSlot` Arc is shared
with that SAME `ApplicationService`; the normal standalone `open(store)` API is
preserved. The fixed alternate constructor shares DATA backing, not another
service or writer. Relay loss and accepted Host retirement directly hide the
cell without waiting behind Host/Service storage IO. An initialized native state
does not thereby gain a listener, read grant or execution permission.

`android-tools.observation` is a closed `ProjectQuery` in the existing protocol.
Normal private AF_UNIX peer/capability checks, current service instance, original
grant ID and expiry remain mandatory. Dispatch requires the requested project's
current native runtime alias and keeps the exact grant/alias guard through the
bounded copy. The original store/grant pre-send check remains; this one read
also repeats its exact project scope/current-alias check before transport send.
No execution/request consent is borrowed or created.

## DATA and limitations

Human **and** JSON results explicitly say this is a historical Desktop catalogue
observation, not revalidated now, and `projectCompatibility` is `not-checked`.
It is not a project-specific dependency/Gradle compatibility check.

The only projected facts are original status revision/catalogue generation,
closed availability/phase/reason, row count, and optionally the observed selected
instance plus six bounded version labels. Selection is copied only from a
matching validated `VerifiedThisSession` row with the exact complete original
comparison (including native UID and hashes). Those comparison fields are then
**discarded**, not exposed as a reusable receipt. Unknown removes any selected
summary. Metadata-only recovery rows never become a selected/reusable tool.

No path, UID, record/inventory/provider hash, operation ID, source nominee,
credential, raw issue or private native object reaches the result. Even a
reported selected copy is not current-tool, project-readiness, build, native
qualification or release authority. A missing observation differs from an empty
catalogue; invalid/contradictory DATA or lost relay yields unavailable, never an
invented empty/ready result.

The cell is not persisted. Restart restores neither the observation nor any
grant/alias. Identical revisions deduplicate; older revisions do not overwrite
newer ones. Conflicting same-revision data, backwards catalogue generation and
unknown-to-known substitution fence only this optional view until a new host.
No cache result can clear original native uncertainty. A TRY-busy publication
may be skipped, which is why the view never promises currentness.

Bounds: native rows retain the existing 32-row limit; projection retains at most
one selected instance and six ASCII labels of at most128 bytes. The whole view
fits2048 bytes. A conservative16KiB fixed DATA backing charge covers the cell,
relay projection and eight possible typed replies; original native Status and
framed IPC buffers retain their separate existing charges. This is not an RSS
cap. No namespace, migration, fsync, durable operation/history row or secondary
persistent writer is added.

## Root integration packet

Base: `5dbd047fc8d603b51b7433a7a4576de2665c96e7`.
Own new source: `service_android_tools.rs` and
`application_service_android_tools.rs`, both under `desktop/src-tauri/src`.
`service-android-tools-hooks-20261020.patch` changes exactly ten existing paths:

1. `application_service.rs`: same-service cell, authenticated read arm, stop
   barrier, two existing-framework Service/Store tests.
2. `application_service_host.rs`: closed child, shared cell during actual open,
   memory-only retirement and corresponding original fixture initialization.
3. `service_protocol.rs`: one read method/result and closed result validation.
4. `installed_cli.rs`: parser/help/static capabilities/human output and one test.
5. `asset_session.rs`: fixed census charge and original relay-loss invalidation.
6. `shell.rs`: forward the already returned catalogue Status, independently of
   renderer revision deduplication.
7. `lib.rs`: portable DATA declaration.
8. `installed_cli_main.rs`: same portable declaration, no Desktop/native import.
9. `tests/installed_shell_observation.rs`: same current portable graph declaration.
10. `installed_cli_ipc.rs`: exact project/alias pre-send recheck for this read;
    extend the existing real-socket test for unobserved and then synthetic
    observed DATA through the actual authenticated route.

No frontend, new GUI command/permission, native execution owner, source reader,
qualification flag or runtime package changes are part of this packet.

## Focused verification (Root scheduling)

Authored, **not executed in this lane**:

- `service_android_tools::tests::` — four bounded DATA/cell cases.
- `application_service_host::android_tools::tests::` — five typed projection,
  dormant/TRY-lock and actual shared Store/Service fixture cases.
- `application_service::tests::android_tools_read_keeps_scope_alias_revoke_and_store_checks`
- `application_service::tests::android_tools_restart_does_not_restore_observations_or_access`
- `installed_cli::tests::android_tools_is_a_closed_historical_read_with_no_action_parameters`

Also run the affected existing selectors:

- `installed_cli_ipc::tests::real_socket_two_clients_share_completed_observations_and_history`
- `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`

These are12 new tests plus2 existing affected tests. Their synthetic catalogue
DATA and real private Store/socket fixtures do not qualify a Mac tool operation,
installed GUI journey, foreign-UID authentication or selected-tool compatibility.
The actual integrated library/thin CLI graph remains a separate Root obligation.
The earlier seven IPC tests passed locally in Root before this extension; actual
Darwin execution of that seven-test packet remains separately unverified.
