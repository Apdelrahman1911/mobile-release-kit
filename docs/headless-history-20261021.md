# Explicit foreground cached-history host

Source implementation only; no installed/native qualification is claimed.
Plan reviewed independently by Versions; Root authorized implementation.

## User-visible scope

The **existing signed `mrk` executable** gains one explicit entry on macOS
64-bit arm64/x64:

```text
mrk serve-history --project ABSOLUTE_PATH --allow-history-read-seconds 1..3600
```

It stays in the foreground until Ctrl-C, SIGTERM, or the original consent
deadline. It serves exactly `status`, `projects`, `observe`, `operations`, and
`operation` through the existing client/IPC. All loaded observations remain
stale. No fresh discovery, project scripts, credentials, edits, builds, signing,
provider requests, background startup, hidden window, or fabricated Document.
Other CLI calls remain Desktop-dependent and are refused by this host **before
every special dispatcher route**, including Play cleanup and scope discovery.

Startup may initialize the existing private service layout/register a stable
project ID. It never writes project files. It uses the actual native UID/home,
not an environment-selected server directory. The normal client is unchanged.

The same Store/flock/socket is exclusive. An active Desktop host or other
foreground host causes refusal; no PID-based takeover, deletion, automatic
retry, fence reset, or restored grant. Close this host before enabling Desktop
state/agent access. A Desktop which already encountered a sticky startup Busy
may need to be reopened. This is **not** seamless headless/GUI synchronization;
fresh shared reads, editing and execution remain unfinished product scope.

## Original ownership and bounds

* A new private History origin factors the **existing** Host storage startup;
  the Document origin retains its original checks and registration map.
* Actual PRE `SourceBook`/`ProjectProbe` supplies the single root, followed by
  the existing application-directory exclusion, original Store open/flock,
  Service registration and IPC listener. An independently retained POST book
  rechecks the same root against the actual held application directory before
  any read grant. Saved path/identity DATA is never a live source witness.
* The foreground retains the same startup task and Host before native entry,
  awaits its actual return, then retains/joins the one grant-publication task.
  There is no JoinHandle abort/detach or timeout-as-join inference.
* Startup and grant publication share exact `min(T+30s, T+N)`; access ends at
  exact `T+N`, not receipt/lock-release time. Signal/expiry stops an atomic
  original lease before blocking cleanup. Publication checks it after lock/IO
  waits, including after the original permission publication. A late startup
  check stops that whole lease, so an intermediate grant cannot remain usable.
* Only this explicit entry uses a fixed two-worker runtime. The calling
  `block_on` thread polls signals/deadlines while the retained workers own
  synchronous startup/publication. Kernel/runtime stalls are not claimed to be
  preemptible; original handles are still awaited, not abandoned at a deadline.
* Same listener, eight-client bound, 4-KiB request, 256-KiB response, 5s server /
  8s client limits; same 1-MiB-per-namespace Store checks. Three existing source
  books keep their descriptor/name/ancestry bounds plus a checked 1-MiB retained
  source/control allowance. This is bounded backing, not an RSS estimate.
* Shutdown fences reads, retires the actual source books, joins the existing
  listener/client originals and closes the same Service/Store/endpoint. Unknown
  effects/close/join facts remain absorbing; a clean later call cannot erase them.

## Integration packet

Five new Rust leaves and this guide are independent of the eight shared targets
in `headless-history-hooks-20261021.patch`. Original worktree base is `1bb85938`;
the hook before-images are actual Root `49fb7a55bba8145f5a31ef83dac75e05f7b9de83`,
preserving its installed observer and Play-cleanup additions. No Root files were
edited. Exact before/after copies and pins are under `.task-headless-history/`.

No new binary, installer/packaging roster or workflow. `installed-cli` enables
the already-locked Tokio signal feature; the default client runtime stays
unchanged. The main entry alone selects the library Host for `serve-history`.
Actual signed CLI linking, size guards and macOS signal/startup behavior still
need the normal Root build/qualification path.

The capabilities JSON remains subject to the **unchanged 12-KiB limit**. Source
literal expansion found current Root+history at 12,760 bytes (Root alone 12,566).
Root assigned the existing combined description-only compression to Project;
that separate correction must be composed before claiming capabilities work.
This packet does not widen the limit or independently compress other command descriptions.

## Focused tests — all authored, UNRUN

Seven portable tests (Linux/macOS library graph):

```text
application_service::history_policy::tests::original_history_lease_never_renews_or_rearms
application_service::history_policy::service_tests::history_allowlist_precedes_every_dispatch_family_and_service_lock
application_service::history_policy::service_tests::history_reload_is_stale_and_never_restores_alias_grant_or_execution
application_service::history_policy::service_tests::history_stop_overtakes_blocked_grant_publication_without_timer_renewal
application_service_host::headless::tests::history_startup_deadline_and_stop_refuse_before_source_without_rearming
installed_history_service::tests::serve_history_requires_exact_foreground_consent_and_bounded_native_path
service_protocol::tests::service_info_accepts_only_desktop_or_foreground_history_tuple
```

Three Mac64 arm64/x64 tests use real supported APFS SourceBooks/Store/IPC; no
unsupported-filesystem skip and no fake Document, grant or close witness:

```text
application_service_host::headless::tests::macos::history_native_original_sources_join_before_grant_and_restart_does_not_restore_it
application_service_host::headless::tests::macos::history_concurrent_host_is_busy_and_cannot_take_over_or_delete_original_endpoint
application_service_host::headless::tests::macos::history_stopped_joined_startup_grants_nothing_and_saved_path_cannot_adopt_replacement
```

Use the existing short private HOME/APFS test convention. Tests retain their
task-owned fixture on failure; removal happens only after genuine close/join
checks. They do not qualify the installed entry/account lookup/signal loop.
The existing `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`
also gains history metadata assertions and needs the combined size correction.

Author checks: Rust parser/format checks, TOML parsing, whitespace and hook
application only. No Cargo, test execution, native/provider operations or new
CI dispatch. End-to-end foreground service qualification remains pending.
