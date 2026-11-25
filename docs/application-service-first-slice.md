# Shared application service: first executable slice

This slice is a **read-only client of the original running Desktop**, not a
replacement release engine or a newly qualified headless native role. It shares
saved, redacted observations and published operation history through a real Unix
socket. It does not grant edits, builds, credential use, signing or publishing.
`SECURITY.md` and all existing native qualification gates still apply.

## Actual module/API contract

The host uses these six source files without copying their test bodies:

- `service_protocol.rs`: finite version-1 data protocol; no executable/path RPC.
- `application_state_store.rs`: one original locked private directory, three
  fixed reference-only namespaces and durable compare-and-replace.
- `application_service.rs`: stable project preferences, runtime aliases, saved
  observations, explicit expiring read consent, and operation-status **data**.
- `installed_cli_ipc.rs`: authenticated bounded Unix transport and original
  listener/worker ownership.
- `installed_cli.rs`: fixed CLI verbs and bounded structured output.
- `installed_cli_main.rs`: client-only executable entry; no native engine owner.

Native host construction, on its **existing** async runtime:

```rust,ignore
let location = app.path().app_local_data_dir()?; // native Tauri resolution only
let store = Arc::new(PrivateStateDirectory::open(&location)?);
let service = Arc::new(ApplicationService::open(store.clone())?);
let server = installed_cli_ipc::start(service.clone()).await?;
```

Map failures to fixed public codes, not formatted filesystem errors. Preserve
the original `StateError` internally: its effect, durability and cleanup are
independent. A later successful directory close does not erase an earlier
unknown outcome. A construction failure is not permission to reset files.

### Root-owned central integration edits

These are required integration hooks, not edits to the central files in this
lane and not a claim that packaging or a platform qualification has passed.

1. Declare `service_protocol` and the new host/transport modules in `lib.rs`;
   gate POSIX storage/IPC to Linux/macOS. The separate Cargo `[[bin]]` entry is
   `name = "mrk", path = "src/installed_cli_main.rs"`. Its source does not import
   DesktopBridge, a WebView, helpers, Python or any native execution role.
   Keep existing image/installer/helper feature isolation; do not select another
   role just to make this client build. Installation/signing is separate work.
2. Add a retained host book to `ShellState`: the store and service `Arc`s and an
   async-mutex-protected **original** `ServerHandle`. Use the same native app-data
   resolver already used by `vault_open` (`shell.rs` at the base's line 1822).
   Its fixed `service-v1` child is separate from the encrypted vault.
3. After the genuine native picker/`document.project_result(...)` settles, acquire
   `bridge.native_project(runtime_id)` **under the real DocumentBinding admission
   mutex and registry-result gate**, as existing native owners do. The native
   `RegisteredRoot` supplies `path` and POSIX device/inode. Call:

   ```rust,ignore
   let binding = service.register_native(runtime_id, &root.path, dev, inode)?;
   // Later native preference consumers only:
   let binding = service.native_binding(runtime_id)?;
   ```

   Do not accept those root facts from JSON, call the registry outside its
   original admission, or turn saved preferences into a new registration.
   `project-N` remains the bridge's runtime ID. `binding.project_id` is a separate
   persistent, nonzero lowercase-hex32 ID, not a UUID-v4 promise. Same path with a
   different identity, or the same identity at a different path, is a migration
   conflict; it never creates an automatic empty credential slot.
4. In `project_snapshot`, retain the runtime ID before passing it to the existing
   `bridge.project_snapshot(&document, ...)`. **Only after its actual successful
   passive response**, call `publish_passive_snapshot(runtime_id, &value)`.
   This checks the original response's root, passive scope and assurance fields,
   then copies only bounded configuration state/length/hash, partial-discovery
   flag and issue count. It never saves config data, issue text, account identity
   or credential values. Identical already-fresh facts cause no revision/fsync;
   stale-to-fresh publication still persists. Persistence failure must not rewrite
   the independent core action's success/finality as a different action outcome.
5. On a known saved-file change or save intent, call
   `invalidate_native(runtime_id)` and retain the existing domain revocations of
   reviews, candidates and credential assessments. The service method invalidates
   **data only**; it cannot substitute for those original domain owners. GUI
   drafts remain local and must never be silently overwritten.
6. Add once-per-session, explicit Settings consent scoped to selected native
   registrations. The real window gate validates a closed request, then calls
   `allow_agent_read(Vec<Id>, Duration)`. Maximum lifetime is 3600 seconds, minimum
   nonzero, at most 64 projects; expiry uses the owner's monotonic clock. A new
   grant revokes all earlier connected sessions. `revoke_agent_read()` denies
   immediately; keeping the original listener until shutdown is fine. Both
   `read_access_status()` and `allow_agent_read(...)` return camelCase:

   ```text
   { enabled: bool, remainingMs: u64, projectIds: [stable-id] }
   ```

   The renderer cannot supply a capability, instance/client/session identity,
   arbitrary lifetime clock, path, executable, namespace or filesystem content.
7. At the actual exit observer, before setting `exit_ready`/`app.exit`, borrow
   the retained handle and await `server.shutdown(&mut self)`. It always requests
   stop and joins even when revoking a poisoned service fails. It consumes the
   original listener and every original client worker; results are cached only
   after that join. Then attempt `service.stop()` and `store.close()`, preserving
   all prior failures. Do not take the server handle out before awaiting: a
   cancelled observer must not detach the only join handle. `stop`, a dropped
   connection, an absent PID and `Drop` are **not** settlement receipts.

`publish_operation(runtime_id, operation_id, action, state, settlement)` is a
native-only data publisher for genuine original outcomes. It starts no work.
Unknown state or settlement cannot become a settled success for the same ID.
Recovery belongs to the original owner and a distinct observation. Empty history
means no original outcomes have been published, not a complete historical audit.

## Shared private reference storage

```rust,ignore
enum Namespace { Projects, CredentialReferences, VersionAllocations }
struct Revision(u64);
struct Snapshot { revision: Revision, bytes: Vec<u8> }
PrivateStateDirectory::open(native_app_data: &Path) -> Result<Self, StateError>;
store.read(namespace) -> Result<Snapshot, StateError>;
store.replace(namespace, expected_revision, bytes) -> Result<Snapshot, StateError>;
store.excludes_project(native_device, native_inode) -> Result<(), StateError>;
store.close() -> Result<(), StateError>;
```

These are **internal Rust methods**, never a generic renderer or socket endpoint.
All three required namespaces are reserved on first initialization, with revision
zero and empty payload. The exact required set is fixed. After establishment,
missing files are recovery-required, including at revision zero. A parent
reservation binds the original child directory so a replaced/missing whole child
cannot silently initialize empty. This is not protection against wholesale
deletion of all app data or a compromised same-user account.

Reads bound the file size before allocation and hold private, no-follow,
owner/mode/identity checks through the original close. Write admission verifies
the original lock and namespace record. A stale expected revision alone refuses
without poisoning; failed custody/read/close does poison the current store.
Replacement writes/fsyncs a fixed intent and candidate, checks the originals,
renames once, fsyncs the directory, verifies the candidate's exact publication,
removes only the original intent and fsyncs again. Unknown rename/sync/cleanup
retains its fence. No PID-based repair or retry is performed. A successful
Snapshot is a durable reference-state replacement, **not native operation
finality**. Error outcomes retain `effect`, `durability`, `cleanup` separately.

Credential assignment preferences use exact
`{vaultId,generationId,recordId,revisionId,revisionCounter}` references. All four
IDs are nonzero, distinct native-vault IDs; the counter is positive. Preferences
never authenticate stored payload, restore an old Bind, or authorize use.

The version allocation owner uses only the future fixed internal pair
`read_version_allocations()` / `replace_version_allocations(expected, payload)`.
Its Python `NativeAllocationJournal` expects `{revision,payload}` and a successful
write acknowledgement with `effect=committed,durability=durable,cleanup=settled`.
Those literals may be added **only after this original store returns success**.
The finite owner adapter is not installed by this read-only socket. Do not expose
arbitrary namespace/byte calls to clients or claim a memory journal is durable.
The stable registered project ID is installation-local. A shared Git allocation
ledger's project/repository/ledger/genesis identity is a separate authority;
multi-host use needs explicit native enrollment linking them, never normalization
or automatic rebinding to each installation's new local ID.

## Transport/client boundary

The installed client bootstrap resolves the fixed native app-data convention:
macOS `HOME/Library/Application Support/dev.mobile-release-kit.desktop`, Linux
`XDG_DATA_HOME` (otherwise `HOME/.local/share`) plus the same fixed application ID.
No CLI option selects an endpoint. The checked private directory holds a fresh
per-host random capability in a mode-0600 binary descriptor; both peers check
the other UID. Capability bytes are zeroizing and never enter argv, environment,
JSON, logs or public status. This assumes a trusted OS/current ordinary account,
not hostile same-UID process isolation.

Socket basename `s`; descriptor `agent.connection`. Real pathname sockets are
used, no HTTP, TCP, abstract namespace or temporary/PID fallback. Paths too long
for Darwin's 104-byte address fail closed. At most eight clients, one framed
request per connection, 4096-byte request, 256-KiB response, nesting at most 16,
five-second original server deadline and eight-second client deadline. A stalled
client does not block other accepts or shutdown. The client retains its acquired
stream outside its cancellable exchange, then attempts that original close once;
unconfirmed close or connect-constructor cleanup yields unknown, not success.
Clean initial absence of both endpoint names means open Desktop/enable access;
partial absence or any drift after acquisition is not automatic cleanup authority.

```text
mrk status [--json]
mrk projects [--json]
mrk observe PROJECT_ID [--json]
mrk operations PROJECT_ID [--json]
mrk operation PROJECT_ID OPERATION_ID [--json]
```

Responses contain saved observations, freshness, published states and private
host-minted correlation IDs. They do not execute a snapshot/build, validate a
release, read credential values or prove native completion. Remembered projects
and history become stale on restart; runtime aliases and consent never restore.

## Dependency-aware route to full shared mutation parity

1. Reuse actual `config_edit.py` and `release_version_edit.py` prepare/apply cores
   and original `InitRootLease`/`InitWorkspace` custody and root `flock`. Do not
   create a competing lockfile or replace the current filesystem owner. Existing
   Python CLI initialization must continue sharing that actual project lock.
2. Refactor only the admission seam of the existing native EditOwner/document
   lifecycle to accept a genuine service-session witness alongside a genuine GUI
   witness. Never invent a window or deserialize a witness. A separately
   qualified headless host is later work, not enabled by this read-only CLI.
3. Admit each fixed prepare/apply/status/cancel operation through one project
   mutation coordinator and existing account/tool leases. Keep full native
   checkout revisions separate from common saved-observation revisions. Plans are
   one-use original private objects/tokens, not caller-supplied inventory/path
   authority. Root identity, cancellation and scoped action authorization are
   checked again immediately before actual publication.
4. Use the same Git owner and native expected index/ref checks, project-identity
   closed transactions and durable version-allocation adapter. External Git is
   detected, not presumed to obey MRK's lock. Unknown publication stays pending
   for original-owner reconciliation; no response-shaped message settles it.
5. Wire reference-only assignment preferences to actual authenticated vault
   payload, current assessment and explicit Bind. Then connect existing build,
   release and Store owners without relaxing native image/platform qualification.
   Publish their history only from actual outcomes; retain reservation/floor
   history across identity edits and preserve GUI drafts on external change.
6. Test the same operation through GUI and installed CLI with shared saved state,
   overlapping admission, stale plans, cancellation, restart and unknown recovery.
   Signed installation, real Mac/Linux qualification and full mutation parity
   remain separate required acceptance, not results of the focused Rust tests.

## Focused verification scope

The task-local `.task-test-harness` imports these exact source files via `#[path]`
and pins the repository's public dependency versions. Tests use synthetic private
directories and real local Unix sockets; no credential/provider/build commands or
package installs. They cover bounded decoding, namespaces/CAS/missing state,
rename fences, poisoned preflight, stable aliases/restart/scope, absorbing unknown
status, redaction/no-op observations, authentication, concurrent clients,
disconnect/stall, endpoint replacement, close uncertainty and joined shutdown
despite poisoned grant state. `mrk --help` and no-host JSON smoke exercise the
separate binary. They do **not** qualify a deployed installer or original native
mutation role. Exact run results are handed off separately; no synthetic PASS is
represented as live Store or signed-Mac evidence.
