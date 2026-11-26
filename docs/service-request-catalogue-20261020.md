# Installed CLI: discover retained requests

`mrk requests PROJECT_ID [--json]` lists the running Desktop's retained
local-check, Android-build and iOS-archive request IDs. It uses the existing
authenticated socket and project read grant. It cannot create, prepare, start,
cancel or replay work. Identity requests and other native operations are not
part of these two inboxes; `mrk operations PROJECT_ID` remains separate saved
operation history.

## Same originals, bounded observation

The service reads the existing local-check inbox (32 entries) and shared
Android/iOS build inbox (32 entries **combined**). No new inbox, owner, relay,
timer, persistent namespace or writer is added. Android/iOS share their existing
request-ID namespace; local checks retain their independent namespace.

Each row copies only its request ID, expected observation revision, fixed
family/request phase, build Start phase, and optional original operation ID,
owner generation, status revision, reported state/settlement and history flag.
The new getters share the existing status phase conversions but do not clone
or expose Report/Review, config/version/tool bindings, paths or credentials.
Existing queued-expiry housekeeping is unchanged. There is no claim, link
construction, permission renewal, native callback or project-filesystem read.

The exact service/grant guard is held through all bounded memory copies. The
request's project must still have a current native runtime alias; entries for
other projects are excluded before projection. Before socket send, the same
project/grant/alias predicate is checked again. Store, grant, native-history
fence and inbox/entry-lock failures remain errors, **never** an empty list.
The existing store check is reused; no additional filesystem owner is created.

The response states `current-host-retained-requests`, `per-request-not-atomic`
and `doNotReplay: true`. Native updates can advance while entries are sampled;
this is not an atomic cross-operation snapshot or native finality receipt.
Unknown settlement is copied unchanged, and history availability cannot repair
it. Empty after restart does not prove an earlier operation settled or permit
reexecution. A reconnect can recover the same retained IDs after a lost reply;
human output supplies only the existing status/cancel command forms.

There are at most64 rows, with fixed enums and32-character IDs. The bounded
projection fits64KiB. The original Document census adds named backing for the
same eight IPC workers' typed views, encoded output, finite borrowed-entry
vectors and scalar scratch. Existing inbox, native owner and framed IPC charges
remain separate; this is not an RSS cap. No report backing is copied here.

## Root hook packet

Base: `576fbaced727abb37fe01827cbd49f65338c90d8`.
Own leaves: `service_request_catalogue.rs` (portable DATA) and
`application_service_request_catalogue.rs` (existing Service child), under
`desktop/src-tauri/src`. The hook patch changes exactly ten existing paths:

1. `agent_local_checks.rs`: compact metadata getter; share unchanged phase map.
2. `agent_build_requests.rs`: same getter and unchanged phase/Start maps.
3. `application_service.rs`: child and fixed authenticated dispatch arm.
4. `service_protocol.rs`: closed `request.list` and validated response.
5. `installed_cli.rs`: parser, help, human/static capability output and one test.
6. `installed_cli_ipc.rs`: project presend check and existing real-socket case.
7. `asset_session.rs`: named bounded reply-backing charge only.
8. `lib.rs`: portable module declaration.
9. `installed_cli_main.rs`: same client-only declaration.
10. `tests/installed_shell_observation.rs`: same manual graph declaration.

No Host/Document admission, native runtime, GUI command/permission, frontend,
read-grant scope, execution grant, original lifecycle or history writer changes.

## Focused verification (Root scheduling)

Authored, **not executed in this lane**:

- `service_request_catalogue::tests::` —4 DATA cases: closed redaction, shared
  capacity/ID namespace and full-row bounds, unknown/history, restart/no replay.
- `application_service::request_catalogue::tests::` —6 existing real
  Store/Service fixture cases: lost reply/reconnect, both build families without
  Start/review exposure, admission/native unknown, project/alias/revoke,
  expiry/fence errors, actual store restart with retained historical uncertainty.
- `installed_cli::tests::requests_is_discovery_only_and_rejects_action_parameters_and_foreign_instance`

Also run the two affected existing cases:

- `installed_cli_ipc::tests::real_socket_two_clients_share_completed_observations_and_history`
- `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`

The extracted phase maps should retain the existing local/Android/iOS tests;
targeted regression selectors are:

- `agent_local_checks::tests::identical_reconnect_is_observation_not_second_execution_even_after_revoke`
- `agent_local_checks::tests::expiry_is_fixed_and_cancel_is_not_native_settlement`
- `agent_local_checks::tests::native_unknown_absorbs_later_terminal_and_history_never_changes_it`
- `agent_android_build::tests::prepare_returns_original_ids_without_start_or_a_go_claim`
- `agent_android_build::tests::lost_prepare_return_keeps_bound_request_and_cannot_authorize_a_retry`
- `agent_android_build::tests::cancellation_before_prepare_consumes_permission_but_does_not_invent_native_ids`
- `agent_build_requests::tests::same_ios_start_link_is_one_use_and_foreign_family_never_consumes_it`
- `agent_build_requests::tests::ios_unknown_absorbs_and_lost_ack_blocks_both_families_without_native_receipt`

Author source checks: both new leaves and all ten projected Rust files parse;
the exact patch applies to its stated base; whitespace is clean. These are not
compiler or test results. The test links/scopes are explicitly inert DATA, not
native admission, execution or join proof. Root must compile the actual library
and thin CLI and run the selected tests. Mac peer authentication, installed GUI
consent and actual local-check/build/archive execution retain their separate
qualification requirements; this discovery slice does not qualify them.
