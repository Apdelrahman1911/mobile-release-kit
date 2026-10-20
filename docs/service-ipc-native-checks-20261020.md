# Existing Mac library: real local IPC checks

Apply `service-ipc-native-hooks-20261020.patch` in Root integration. Base
`1f0fb33c`; exactly two existing files change, with no production Rust change.
The previous Android/iOS source branches and untracked evidence are preserved.

## Scope

Two existing IPC tests are extended:

- Poll and cancel a `ServerHandle::shutdown` observer after STOP, retain the
  original accept/worker handles, then await that same shutdown and check its
  cached result and removed original endpoint. No replacement task or join
  receipt is fabricated.
- Shut down, close and reopen the same actual reference store. A new service
  has a different instance/capability, rejects the old handshake and restores
  neither runtime alias nor read grant. Re-registering the actual held fixture
  root preserves its stable project ID; explicit read-Allow permits a new
  connection to its still-stale saved DATA. Capabilities remain zeroizing and
  never appear in assertion diagnostics.

The existing `app-typecheck` branch runs seven exact IPC library selectors
after its unchanged DATA checks. It creates a short, private, task-owned HOME
under the original runner HOME, uses the existing Cargo cache/toolchain, and
checks the actual byte length before running. With hosted `/Users/runner`,
the longest generated socket path is 93 bytes, below Darwin's 104-byte limit.
The real directory owner still checks all ancestry/permissions; no `/tmp`
fallback or weakened path/socket policy is added. Cleanup removes only the
empty task-owned HOME; unexpected retained files fail cleanup and are not
recursively removed. Each existing fixture owns its synthetic reference files.

Exact selectors, all under `installed_cli_ipc::tests::`:

1. `real_socket_two_clients_share_completed_observations_and_history`
2. `stalled_client_and_disconnect_do_not_block_other_client_or_shutdown`
3. `private_capability_wrong_instance_and_revoked_access_are_rejected`
4. `replaced_endpoint_is_retained_and_state_cannot_close_before_join`
5. `stale_descriptor_and_symlink_are_not_an_auto_cleanup_authority`
6. `client_handshake_timeout_closes_original_and_preserves_unknown_close`
7. `poisoned_revoke_still_stops_and_joins_original_workers_once`

Use the actual no-default library and `--exact --test-threads=1`; require seven
passes and zero ignored. Root runs the seven locally before the separately
approved Mac invocation. No broader suite, service daemon, dependency, native
qualification flag, installer, signing or notarization pipeline is added.

## Evidence boundary

This exercises production AF_UNIX, both peer-UID checks for the actual same-user
peers, binary capability/framing/reconnect and real original socket/task closure.
It does **not** test a foreign-UID peer, an installed CLI subprocess/bootstrap,
real GUI approval, native SourceBook admission, or a project operation's STOP or
finality. Snapshot/history fixtures are redacted DATA, not executed operations.
The genuine Desktop/manual safe-project runbook remains required for native
local checks, Android builds and iOS archives.

Author checks are syntax, exact patch applicability and whitespace only; no
Cargo, test, Mac or native operation has been executed in this lane.
