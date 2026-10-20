# Installed CLI: historical repository summary

`mrk repository PROJECT_ID [--json]` reads bounded Git-observation DATA from
the running Desktop. It uses the existing authenticated socket and explicit
project read grant. It does not execute Git, inspect files, fetch, start a
native owner, or authorize a mutation/build/release.

## Original producer and honest scope

The **same retained Desktop relay** calls a memory-only Document observer.
That observer uses the existing GitRead reconciliation: only the original
ticket's known settled receipt, after its native/management joins, becomes a
`Finished` projection. Pending work is not completion; unknown/lost native
state retires the optional projection. The original operation/history outcome
is never changed by this observer.
Not-yet-bound startup, a pending quit confirmation, and ordinary asset disposal
only skip capture; they do not permanently lose historical facts. Actual
document loss, unknown/exhausted/stopping state or relay loss still retires it.

Only an actual completed `Observe` is projected. The existing strict GitRead
validator checks the borrowed result. Public output contains the original
`git-read-N` ID, attached/detached/unborn mode, changed/index/worktree/untracked/
conflict counts, closed tracking state and available ahead/behind counts, and
restriction count. Index/worktree counts can overlap. No source paths, branch
or remote names, refs, commit identities/messages, diffs, tool paths, hashes or
credentials are exported. Two private revision digests detect contradictory
copies of the same original; they are not exposed or treated as authority.

Every response explicitly says `historical-not-revalidated` and
`local-refs-no-fetch`, including in normal human output. Complete ahead/behind
means the original **local-ref** comparison completed, not that a remote is
current. Zero counts never grant permission or prove the checkout remains
clean. A later Diff/History/Branches action does not manufacture a new Observe.
No capture after restart is unobserved, not a fabricated empty repository.

The genuine Document is held through its current registry-generation/root
lookup and the Host's **TRY-only**, exact native-registration/document-identity
comparison. There is no Service mutex or filesystem IO in this publication
path. The Host must already contain its original Service; the tap cannot open
a dormant Host or a listener, renew a grant, or register a project.

The shared volatile cell has at most64 rows, matching the existing project
bound. Each row retains its private original runtime/root/device/inode/
registration comparison and latest captured original ID. Source/registration
replacement cannot adopt or repair an old row; unavailable/contradictory copies
of the same ID never revive it. Loss/unknown retirement is absorbing for this
Host. A fresh Host starts with no captured rows. This small slice does not
provide registration migration, complete Git history, a currentness probe, or
all native Git mutation commands.

Queries hold the existing Service/grant guard through the small DATA copy,
require a current runtime alias and match the row's root/device/inode to the
saved project binding. Cross-project or rebound aliases cannot borrow a row.
The transport repeats the existing project/grant/alias check immediately
before sending. Store/grant/history-fence failures remain errors, not empty
success. No query calls a Document/Host/native tool or writes a namespace.

The original Document census adds one named reservation (<1MiB) for the finite
rows, existing strict validator's borrowed-key sets, one small projection and
eight typed/encoded replies. Original Git result and framed-transport charges
are unchanged and separate. This is not an RSS claim.

## Exact Root hook packet

Base: `f0acfece0fa34874a94d0a6c47fa3beb771b5640` (exact three-way refresh after
the accepted identity-action integration; both relay guards/actions and the
original eleven-word CLI collector are preserved).
Owned leaves under `desktop/src-tauri/src`:

- `service_repository_summary.rs`: portable closed DATA and volatile cell;
- `application_service_repository_summary.rs`: Host child, native projection;
- `asset_session_repository_summary.rs`: same-Document relay tap.

`service-repository-summary-hooks-20261020.patch` changes exactly ten existing
paths: ApplicationService, ApplicationHost, asset_session, shell's existing
relay, service_protocol, installed_cli, installed_cli_ipc, lib,
installed_cli_main, and the installed_shell_observation manual module roster.
The new relay-loss guard is on the same retained relay, including unpolled/drop
loss; it adds no task, timer, supervisor or finality source. Existing Service
constructors remain source-compatible and create no second Service/writer.

## Focused checks (Root scheduling; not executed by author)

Sixteen new Rust cases:

- `service_repository_summary::tests::` —5: closed redaction/bounds, source and
  alias isolation, same-ID conflict/late copies, loss/poison/capacity/restart,
  incompatible counts/tracking/IDs;
- `application_service_host::repository_summary::tests::` —5: original result
  projection/redaction, nonfinal/malformed refusal, unborn/detached/incomplete
  tracking, dormant/held Host guard, actual shared Store/Service with a held
  Service mutex/no writes and foreign-document refusal;
- `asset_session::repository_summary::tests::` —2: saved context cannot rematch
  another document/registry revision; real default lifetime then Bind and
  transient quit/disposal only skip, while actual loss/unknown stays distinct;
- `application_service::tests::repository_read_preserves_scope_binding_revoke_and_no_store_write`;
- `application_service::tests::repository_read_cannot_attach_an_old_row_to_a_rebound_alias_and_unknown_is_not_empty`;
- `application_service::tests::repository_restart_retains_project_identity_but_restores_neither_observation_nor_grant`;
- `installed_cli::tests::repository_is_a_closed_historical_query_without_git_action_parameters`.

Two affected existing cases:

- `installed_cli_ipc::tests::real_socket_two_clients_share_completed_observations_and_history`;
- `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`.

The fixtures are bounded DATA and existing private Store/socket fixtures, not
native Git/picker/GUI qualification. No author Cargo, test, native process,
provider or live project execution. Root must compile the actual library and
thin CLI and run these cases. Actual installed Mac auth/GUI/relay/Git execution
remains a separate verification requirement; full CLI mutation parity is
unfinished.
