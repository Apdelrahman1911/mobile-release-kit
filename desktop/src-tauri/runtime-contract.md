# Desktop Rust bridge and runtime contract

This is a passive foundation plus independently gated configuration-edit and
GitHub read-only source implementations, not a shipping standalone runtime, Windows native release
backend, or replacement for the audited CLI's ownership services.

## Current executable scope

The installed read-only/preparation renderer commands are `app_info`, `choose_project`,
`project_snapshot {projectId}`, `catalog`, `validate_config {draft}`,
`suggest_config {hints}`, `preview_config {base, draft}`,
`environment_requirements {draft, platform, operation}`,
`propose_github_setup {draft, toolingRepository, toolingSha, suppliedSnapshot}`,
`release_version_observe {projectId}`,
`metadata_text_observe {projectId, platform, locale}`, and
`metadata_text_validate {platform, fields}`.
Evidence has separate lifecycle commands: `artifact_evidence_choose {}`,
`artifact_evidence_status {}`, `artifact_evidence_observe {selectionId}`, and
`artifact_evidence_cancel {operationId, selectionId}`. Cancellation addresses
the original owner; it is not another passive core method.
Snapshot and draft validation return the core result without inventing verified
facts or saving files. Project IDs refer to Rust-held native picker selections;
renderer-provided roots/executables/command lines/method names are not admitted.
There are also five finite configuration-edit commands and four fixed GitHub
connection commands, described below. Configuration, local workflow Apply and
public metadata text editing have separate sealed installed Linux profiles;
the remote GitHub connection qualification gate remains disabled. Installed
metadata integration is source-authored, awaiting independent native evidence.
There are no generic shell,
filesystem, opener, build, Store, credential, or recovery commands/plugins.
The sole local webview denies remote/new-window navigation.
The CSP allows only local assets and Tauri IPC, not project-provided web content.

**The general packaged resolver remains disabled.** A valid manifest and its
compile-time digests alone do not authorize later path consumption. A separate
fixed Linux x86-64 installed-A profile now connects the normal
`desktop-shell,custom-protocol` build to the original installed-runtime owner.
Every request must retain its inspection, transfer, final claim, process owner
and finality checks; byte hashes alone are not custody. The fixed target,
manifest/protocol and platform checks remain mandatory, without an environment
or renderer override. Other platforms/profiles do not gain production launch.

That installed profile admits exactly `capabilities`, `catalog`,
`project.snapshot`, `config.validate`, `config.suggest`, `config.preview`,
`environment.requirements`, `github.setup.propose`, `release.version.observe`,
`metadata.text.observe`, `metadata.text.validate` and `artifacts.candidate.observe`.
The native bridge intersects core availability with this allowlist. A separate
project-only gate uses the existing document/picker/source/registry chain, not
the closed credential/asset-session grant. `app_info.projectSelection` is
bounded availability DATA, not live admission; absent/malformed data disables
the UI action. Snapshots are bounded named observations, not selection-to-query
custody, saved-base authority or an atomic project snapshot. Draft edits alone
do not save; the separate native review/confirmation flow is required.
The two guidance methods use the current draft: prerequisites do not inspect
installed tools, and workflow proposals do not observe or modify a repository,
resolve a remote ref, contact GitHub or grant Apply authority.
Version and public-text reads use the saved configuration, never unsaved drafts.
Candidate inspection has a separate evidence registry and native folder picker;
its gate intersects installed project-selection availability with the exact
candidate passive method, while retaining the original shared lifecycle gates.
It never grants private-asset authority or replaces the source project. Its
three document checks prove consistency only, not artifact bytes, authenticated
provenance, Store state, source correspondence, readiness or recovery authority.
Configuration saving separately uses the existing `EditOwner`, a sealed
configuration-only installed-A selector and its own original runtime ledger.
Passive queries never grant write authority. Inspection and acquisition workers
are registered before effects; the final one-use claim is serialized against
the same original session/document, STOP and deadlines. Custody remains retained
through review and Apply, and settles only after original borrowers/child IO
return; its original settlement worker must also join before final success.
Installed-shell/project/guidance/Save and the read-only batch's native acceptance
are still pending. These changes
do not qualify a standalone installer, general Linux, macOS or Windows. There
is no source, PATH, ambient-Python, browser-preview or synthetic-result fallback.
`inspect_bundle_for_packaging` is explicitly **unqualified preparation work**;
its result contains no executable/core/bootstrap paths and active app commands
never reach it. Its current pathname-based reads are not a safe execution admission
backend and are not authorized native tests.

Only `--features development-runtime` **with debug assertions enabled** compiles
the development selection branch. The build script additionally requires the
debug Cargo profile, so enabling debug assertions in a release profile cannot
admit this feature. A release build with that feature is a compile error.
Developers explicitly configure absolute `MRK_DESKTOP_DEV_PYTHON` and
`MRK_DESKTOP_DEV_CORE` paths. The latter is an intentionally trusted development
package directory or ZIP; the bootstrap is the compile-source fixed
`desktop/engine_bootstrap.py`. These inputs are never accepted from the renderer,
project configuration, PATH search, or a failed production launch. Development
paths and sources must be developer-controlled/quiescent. This route does not
claim a production protected bundle or hostile same-user filesystem protection.

## Packaged preparation shape (not launch authorization)

Future explicitly reviewed packaging maps its prepared directory to
`resource_dir/runtime`. Source `tauri.conf.json` intentionally has no required
runtime resource directory and `bundle.active=false`. It does not depend on
ignored generated files in a clean checkout. The fixed intended payload names:

- `manifest.json` (excluded from its own inventory);
- `engine_bootstrap.py`;
- `config_edit_bootstrap.py` (a separately gated configuration-only entry point);
- `github_connection_bootstrap.py` (the separately gated read-only GitHub entry);
- `github-ca.pem` (fixed nonempty CA payload, at most512KiB; no OS trust fallback);
- `core.zip`;
- `python/bin/python3` on Unix, or `python/python.exe` on Windows;
- the explicitly inventoried interpreter/stdlib payload.

The offline CPython payload transformer is publisher preparation, not runtime
admission. Its production notice/static-link anchors remain absent and its
public entry point refuses before parsing/writing. The new Linux original-
descriptor inspection module is also not an executable runtime constructor or
launch path. Its Ubuntu 24.04 / x86_64 GNU / same-root ext4/XFS ABI selector
recognizes GA6.8 and the source-reviewed exact `6.17.0-1022-azure` kernel, not
arbitrary newer kernels. Native observations and installed-runtime qualification
remain separate requirements. Adding these source modules does not enable either
the packaged-runtime or native-save gate.

Manifest exact keys:
`schemaVersion:1`, `protocol:1`, `coreVersion:"0.3.0"`, `target`, `coreSha256`,
`protocolSha256`, `inventorySha256`, `files:[{path,sha256,size}]`.
`target` is the exact Cargo target triple. `protocolSha256` hashes the exact
`src/mobile_release/_desktop_engine.py` stored inside the core ZIP.
`coreSha256` must equal the core ZIP inventory digest. The inventory includes
all three fixed bootstraps and the fixed CA; their bytes and the complete core
ZIP are bound by the compiled manifest digest. The new engine/transport sources
are in that complete ZIP. `protocolSha256` retains its passive-engine meaning;
there is no separately inferred CA anchor or runtime trust environment override.
Including these payloads does not qualify an owner, CA, TLS profile or execution.
The file list is strictly
sorted by ASCII relative path. Inventory SHA-256 hashes compact UTF-8 JSON of
that array, object keys ordered `path,sha256,size` (Python `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`). Hashes are lowercase 64-hex.

No links, reparse entries, case collisions, Windows reserved names, trailing-dot
names, absolute paths, backslashes, traversal, unknown/empty directories, or
uninventoried payload files are supported. Payload components use ASCII letters,
digits, `.`, `_`, `-`, `+`; component depth <=16. Ceilings: manifest 1 MiB,
2048 files, 8192 filesystem entries, 512 MiB/file, 1 GiB total. The file-count
ceiling leaves room under the shared 20,000-key/value-node JSON limit; the actual
manifest must also satisfy the independent byte and depth limits.

The separately reviewed build supplies **both**
`MRK_BUNDLED_RUNTIME_MANIFEST_SHA256` and `MRK_BUNDLED_PROTOCOL_SHA256` as explicit
compile-time inputs. `build.rs` validates/embeds them and Cargo's `TARGET`; it
never generates an inventory, hashes an adjacent untrusted manifest into an
anchor, downloads a runtime, or reads these environment variables at app runtime.
These bindings and `desktop/tools/prepare_runtime.py` are preparation assets,
not a bypass of M1's production execution gate.

Publisher preparation admits every fixed source bootstrap and the bounded,
nonempty `desktop/github-ca.pem` before its first output write. The checkout does
not carry a placeholder CA: missing trust intentionally refuses preparation,
preserving publisher inputs. CA bytes are opaque inventory inputs; preparation
does not acquire a bundle, load TLS, validate certificate chains or grant trust.
Payload/entry reservations include all three bootstraps, core ZIP, CA and final
manifest. Inert preparation fixtures contain explicitly non-certificate data,
not a substitute trust store or native qualification.

## Separately gated GitHub read-only profile

The fixed command names are `github_connection_status`,
`github_connection_connect_token`, `github_connection_refresh`, and
`github_connection_disconnect`. The public DTO/event remains the closed G1
status graph, not private helper controls or raw headers. The native session gate
and `runtime::GITHUB_TLS_PROFILE_QUALIFIED` remain false. A handler registration,
passing passive query, valid manifest or developer-selected interpreter is not
activation, token interoperability or TLS/exit evidence.

`resolve_github_readonly` refuses its closed profile gate before filesystem or
native work. Its strictly latent positive branch is Linux x86_64 GNU only,
`development-runtime` plus debug assertions. That branch requires the complete
inventory bound by the **existing explicit compiled manifest/protocol anchors**
and exact development Python/core selections equal to the inventoried bundle
`python/bin/python3` and `core.zip`. It selects the fixed bundled
`github_connection_bootstrap.py` and runtime-directory cwd; `github-ca.pem` is
that bootstrap's fixed sibling, never a supplied argument or ambient trust
path. The inventory remains a preparation check, not a new custody constructor
or authority to open the false gate. Production and other-target branches refuse.

The private synchronous `Supervisor::start_github_readonly` uses the same two
permits, original10s operation and immutable2s cleanup allowance, owner roster,
driver/watchdog/final observer as passive reads. It does not wrap a lazy query
future in another task. Its ticket exposes only the original operation ID,
fixed cancellation and a safe-data mailbox: Pending, RetainedUnknown, or
Settled with typed outcome, original `settled_at` and monotonic `was_unknown`.
Stop, ticket drop, output readiness and an early unknown notification are not
settlement. Only original `Owner::retire`, after actual native/management checks
and releasing bookkeeping locks, seals final receipt data. Status/relay reads
never renew that time. There is no document callback under supervisor locks.

The one private request is at most8KiB including newline. Its dedicated encoder
does not create a serializable/debuggable/clonable credential DTO or request
Value. The actual IPC Value path validates the tiny borrowed command shape and
encoded-size ceiling before copying a token; it does not claim to recover
lexical duplicate keys already consumed by Tauri. Private byte framing remains
strict and duplicate-free. The GitHub stdout frame is at most64KiB including
newline,2000 nodes/depth12, using closed typed facts/control rather than the
passive generic result; stderr remains separately bounded/discarded at64KiB.

Private controls have exact reason, required nullable canonical expiry, required nullable
integer cooldown1..604800 and mandatory `cooldownBlocked`. Rate limiting must
supply a known/default delay or a known-overflow block. `response-invalid` may
retain independently justified cooldown; all other reasons require null/false.
Unknown/malformed control data cannot create a grant or a new block. A null new
hint does not clear the existing outside-token deadline/block. A recognized
known long/unrepresentable delay blocks the original document, never clamps to
the credential's60-minute ceiling. Canonical expiry syntax is reserved private
data support only: the live helper currently emits null and refuses a present
unsupported expiration header instead of guessing GitHub's wire grammar.
Response-invalid retires credential use while preserving original settlement
custody and independently justified cooldowns. None of this qualifies an actual
token, socket, CA, installed runtime or native document lifecycle.

The dedicated `desktop-github-connection-native.yml` workflow has verified the
original Linux headless owner/document fixture at commit
`d84a15db77e4776c5d89e23b87b868e21fb3a314` (run `35299903903`, attempt 1).
Its 23 cases are 17 owner cases and 6 controlled document cases; all original
owners settled and its finite compiler/fixture cleanup completed. Scheduling
controls establish retained-error and late-settlement behavior, not genuine
stuck native syscalls. The fixture's supplied frames establish neither real
TLS/GitHub authentication nor native WebView callbacks. This result does not
qualify macOS/Windows GitHub behavior, packaged runtime custody, credential
persistence or production activation; both qualification gates remain false.

## Passive protocol and original child owner

Only `capabilities`, `catalog`, `project.snapshot`, `config.validate`,
`config.suggest`, `config.preview`, and `github.setup.propose` can be requested. Suggestions and previews
are bounded in-memory preparation, never saving or filesystem revision authority;
see `docs/desktop-configuration-preview.md` and `docs/desktop-github-setup.md`.
The GitHub command admits a complete closed typed object, including explicit
null for an absent supplied snapshot. It can neither select a repository path
nor authenticate, write, apply, fetch a template or dispatch a workflow.
One fresh selected Python process
gets `-I -S -B`, a fixed bootstrap,
trusted core resource, fixed trusted cwd, and an environment cleared to constant
LANG/LC_ALL (plus absolute SystemRoot on Windows). No project cwd, PYTHONPATH,
site/user-site, credential, loader-variable or PATH route is forwarded. The
reviewed API import graph cannot spawn descendants; this owner must never be
reused for buildful/stateful methods without a new ownership review.

Request exactly `{protocol:1,id,method,params}`; success exactly
`{protocol:1,id,ok:true,result}`; service rejection exactly
`{protocol:1,id,ok:false,error:{code,message,retryable:false}}`, exit zero.
Transport/startup failure is nonzero, never a provisional success. The byte
stream is one UTF-8 JSON object plus newline and EOF, with no extra frames or
leading/trailing whitespace. Duplicate keys, nonfinite numbers, wrong identity,
unknown envelope/error fields, invalid types, and truncation reject. IDs and
error codes use 1–64 ASCII alphanumeric/underscore/hyphen characters; error
messages have 1–1600 UTF-8 bytes and no ASCII controls (U+0000–001F/007F). Limits are 1 MiB request,
4 MiB response, 64 KiB diagnostics, root depth 0 through depth 32, and 20,000
nodes **including object keys**, and at most 32 nested containers (an empty
33rd container is also rejected). Raw diagnostics/requests never reach UI errors.

A try-acquired two-slot semaphore rejects excess work with Busy. Independent
owner and watchdog tasks are registered before awaiting the UI reply. The
startup-inclusive endpoint is 10 seconds, including runtime inspection and
blocking spawn acquisition. A failure latches the first error, permanently sets
the stop channel even before subscribers exist, and starts one nonrenewable
2-second cleanup allowance. Only the exact retained unreaped Child can receive
one stop request; no discovered PID/process-group signal, kill-on-drop, broad
reaper, or renderer-triggered command exists. Writer and both readers run
concurrently; the writer closes stdin, and overflow latches failure while the
reader drains/discards bounded data to real EOF.

Success requires original wait/reap, both EOFs, successful request closure,
settled IO handles, a successful process exit and the correlated valid response.
The result is never accepted on stdout text alone. Unknown startup/wait/IO/close
settlement disables future queries and retains the owner/resources/permit;
watchdog timeout does not abort/drop the owner. Existing work can settle later,
but uncertainty cannot become a successful request and the disabled latch stays
set. A window/renderer abandoning its reply cannot drop owner tasks. Shutdown
requests stop, observes existing allowances without renewing them, and prevents
exit when settlement is unconfirmed. Before requesting shutdown, an unconditional
native OK/Cancel confirmation explains that foundation drafts are in memory only
and quitting discards them. Cancel clears the quit-pending flag without stopping
any owner. Project selection is refused while that prompt/quit is pending; no
renderer dirty-state assertion grants shutdown authority. An open native picker
must first be selected/cancelled rather than abandoned by closing the event loop.
The native confirmation/picker/close behavior remains unverified until actual
disposable-hosted shell qualification.

### Staged Windows static reader (disabled)

The Python original-parent reader is source-stage only; its public activation
constant remains false pending independent ABI and six-group native qualification.
The initial profile is native x64/ordinary local NTFS, with bounded drive or
verbatim-drive roots, no reparse/case-sensitive ancestry, exact long-name vetoes
and access/sharing refusal. A single captured native volume root and subsequent
one-component `NtCreateFile` opens relative to retained original parents use
`OBJ_DONT_REPARSE`; no full-path/file-ID reopen or weaker-sharing fallback exists.
Share-read-only does not exclude attribute-only mutation. Metadata equality is
not atomicity, private ownership or proof against mapped writes/ABA.

The picker still retains a path, not selection-to-request handle custody. The
existing command, SnapshotResult and original-child 10s + one 2s owner are
unchanged. The reader has one cooperative 5s budget, not kernel-call cancellation.
Unknown/pending native completion pins its arena/parents and nonreturningly
fail-stops the child; termination is not an adapter CloseHandle receipt or proof
of original Rust IO settlement. Portable methods and POSIX imports never load
the lazy Windows bindings. Added Python leaves change the whole core ZIP binding
on every platform. No Job Object/build owner, Save or production-runtime gate is
activated by this source or its inert tests.

## Dependency and check boundary

Direct crates and toolchain are exact-pinned; Cargo.lock records the complete
optional/platform graph. Default features are empty; `desktop-shell` adds Tauri,
rfd and tauri-build. Headless check does not require GTK/WebKit. `build.rs` uses
only std bookkeeping in a headless build, but serde/tokio proc macros and
transitive build scripts still require independent source/execution review.
Optional tauri-build generates allow/deny permissions for only the thirteen named
commands. The main local capability grants their allow permissions plus event
listen/unlisten, not renderer event emission or general filesystem access.

In-memory protocol, path-name and stop-latch unit tests contain no child, native
SDK, filesystem fixtures, network, or app launch. They do not establish native
IPC, timeout behavior, original process finality or platform readiness. Cargo
compilation/test, native query/fault tests, shell launch, packaging and installers
must follow the independent check plan; real supervisor/native work stays on
reviewed disposable hosted runners. No test or compilation is implied by source
authoring or Cargo lockfile generation.

## Separately gated finite configuration edit

The native edit owner is separate from passive queries. Its fixed renderer
commands consume complete closed argument objects; extra keys and raw bodies
reject rather than becoming alternate authority:

| Command | Arguments |
| --- | --- |
| `open_config_edit` | `{projectId}` |
| `prepare_config_edit` | `{sessionId, revision, expectedBase, draft, draftRevision, baselineGeneration}` |
| `apply_config_edit` | `{sessionId, planToken}` |
| `close_config_edit` | `{sessionId}` |
| `config_edit_status` | `{}` |

Each returns the same versioned, bounded status as `config-edit-state`. The
renderer subscribes before reading initial status and orders observations by
native revision, not arrival time. Events are best-effort observations, not
authority. Missing invoke results never authorize a retry of Open/Prepare/Apply.
The registry retains the original operation independently of renderer promises.

One original native document owns at most one edit session. Reload, subsequent
navigation, destruction or observed web-content-process termination permanently
invalidates that document under the same registry lock used for admission.
Only the original finished-load event, after native crash observation is
installed, can bind it. Document loss requests STOP; later documents can read
status but cannot Close/Prepare/Apply or acquire a replacement generation.
Already accepted Apply may commit, and its actual outcome must be preserved.
Native lifecycle behavior is a separate qualification from pure state tests.

The dedicated child captures the selected original root once, prepares once,
then applies or discards once. No project scripts, SDK, Git, credentials or Store
calls run. Only `release/mobile-release.json`, root `.gitignore`, and (if absent)
the `release` directory may be part of the reviewed transaction. The original
lease uses short common-lock scopes, never a lock across human review. Both
initialization and build-input pending namespaces are checked. Original bytes,
inodes and ancestor bindings cannot be replaced by renderer snapshots; a complete
no-op preserves bytes and identity. See the exact [core adapter contract](../../docs/desktop-configuration-edit.md).
Selection itself retains a pathname. Open establishes fresh lease custody over
the project then at that displayed path; Prepare/Apply use the same lease. This
does not claim continuous picker-to-Save inode custody.

Active phases have 30-second deadlines, human review an absolute 15-minute
lifetime, and cleanup one 10-second allowance. The sole stdin writer's EOF is
cooperative STOP, not rollback or child-finality proof. Known core effect,
journal state, resource settlement and primary reason remain independent of the
native wait/EOF/close/join facts. Success requires all applicable original facts;
Unknown is absorbing and retains owners instead of dropping them to manufacture
completion. A settled recovery-required journal blocks its project, even after
another project's terminal result replaces the last status.

Confirmed quit starts both passive and edit shutdowns and waits for both; a
failure in one never skips the other. The status relay is joined before normal
exit. An uncertain owner prevents normal exit; no PID discovery, broad process
cleanup or assumed rollback is provided. Unsaved newer renderer drafts are not
replaced by an older successful save, and native quit confirmation remains
independent of renderer state.

`NATIVE_EDIT_QUALIFIED` stays false. The exact installed Linux configuration,
workflow and metadata profiles add separate original-owned routes; the general
resolver remains closed. Metadata reuses the original slots and settlement,
requires registered-root ownership at the same serialized final claim as
workflow, and supplies the closed `metadata_text` bootstrap argument before
that claim. The metadata preparation phase participates in interruption and
absorbing Unknown handling; no new ledger or fallback owner is introduced.
The observer-only metadata finality accessor returns only the exact settled
original session from the existing tagged terminal record, never another
domain's last result. A discarded first Review must settle before a later
Review replaces that record. The new installed Save case requires exact
plan/readback and independent filesystem postconditions; source and inert
checks do not establish installed qualification.
The ignored hosted fixture has only a private
test-build authorization after its fixed environment/source/root checks; it
cannot enable production constructors. Core inert tests, three initial actual-
owner cases, compilation, or a passing negative fault assertion alone cannot
qualify saving, native document lifecycle, Windows custody or installed runtimes.


## Separate saved-version VALUE profile (closed)

The existing `EditOwner`, native document/root registration, lifecycle and
installed-runtime slots carry a fourth fixed edit domain, `release_version`.
Its closed renderer commands are `release_version_edit_open {projectId}`,
`release_version_edit_prepare {sessionId, revision, expectedBaseline, intent,
values, draftRevision, baselineGeneration}`, `release_version_edit_apply
{sessionId, planToken}`, `release_version_edit_close {sessionId}` and
`release_version_edit_status {}`. The event is `release-version-edit-status`;
the private child uses `mrk-release-version/1` and the fixed `release_version`
bootstrap argument. No generic passive API mutation or path/key/policy override
is added; `release.version.observe` schema 2 is unchanged.

Open captures the saved config-derived source through the original concrete
lease-bound `VersionTargets`. Only that one source is writable; config and ignore
are read-only dependencies. Prepare validates the two proposed strings through
shared core policy and changes only admitted inner value spans. Explicit true
absence alone permits two-line LF Create. Review contains full original/after
text and native byte hashes, action/mode/ancestor/separator facts. The original
lease/revision and one-use Prepare/Apply remain mandatory; no auto-rebase,
serializer, CLI fallback or second transaction/cancellation engine is introduced.

`NATIVE_RELEASE_VERSION_EDIT_QUALIFIED` is independently **false** and the new
`ReleaseVersionInstalledProfile::SOURCE_BINDING` is **None**. Both must be
separately reviewed; neither the old installed A payload, a metadata profile nor
a configuration/workflow fixture permit can select this writer. A new core ZIP,
exact source/member inventory and manifest/compiler binding are required before
authorizing original-owner Linux filesystem/UI/process/finality observations.
The thin version slots preserve the same ledger and finality rather than
constructing replacement owners. Uncertain outcomes retain the original evidence
and block retries, including after late settlement. Windows, macOS writes,
persisted recovery and shipping remain unqualified.

See the [ordinary UI and byte-preservation contract](../../docs/desktop-release-version-edit.md)
for synchronous lifecycle retirement, explicit reload/discard, ten-rule version
prerequisites and the unchanged positive seven-rule metadata proof.
