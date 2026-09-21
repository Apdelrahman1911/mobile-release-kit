# Desktop Rust bridge and runtime contract

This is a passive foundation plus independently gated configuration-edit and
GitHub read-only source implementations, not a shipping standalone runtime, Windows native release
backend, or replacement for the audited CLI's ownership services.

## Current executable scope

The eight passive renderer commands are `app_info`, `choose_project`,
`project_snapshot {projectId}`, `catalog`, `validate_config {draft}`,
`suggest_config {hints}`, `preview_config {base, draft}`, and
`propose_github_setup {draft, toolingRepository, toolingSha, suppliedSnapshot}`.
Snapshot and draft validation return the core result without inventing verified
facts or saving files. Project IDs refer to Rust-held native picker selections;
renderer-provided roots/executables/command lines/method names are not admitted.
There are also five closed configuration-edit commands and four fixed GitHub
connection commands, described below; their native qualification gates remain
disabled. There are no generic shell,
filesystem, opener, build, Store, credential, or recovery commands/plugins.
The sole local webview denies remote/new-window navigation.
The CSP allows only local assets and Tauri IPC, not project-provided web content.

**Production runtime execution is disabled, even when both compile-time hashes
are provided and a manifest is valid.** A digest binds bytes at inspection, not
later path consumption. M1 does not yet supply an immutable runtime namespace,
nonblocking component-bound no-follow readers, original consumption custody,
platform file/handle identity, installation/update lease, or native qualification.
Both the resolver and spawn function deny production launch. There is no switch
or runtime environment override that enables it. `app_info` remains usable and
reports unavailable, with null capabilities; it never falls back to source,
PATH, an ambient Python, browser preview, or synthetic successful core output.
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
launch path. Its initial Ubuntu 24.04 / GA6.8 / x86_64 GNU / same-root ext4/XFS
scope requires separate native qualification. Adding these source modules does
not enable either the packaged-runtime or native-save gate.

### Windows embedded passive payload (source admitted, native unverified)

The separate `windows-payload-v1` hosted lane stages only the exact official
CPython3.14.7 AMD64 embedded ZIP, SHA256
`d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15`.
It retains all37 unmodified supplier files, including unused PE images and the
catalog, with the unchanged80-byte `python314._pth` (only `python314.zip` and
`.` active). Whole-ZIP admission is the accepted official HTTPS/release-digest
basis, not verified Sigstore/catalog/PE signing or redistribution clearance.
`prepare_windows_embedded_payload.py` requires the independently reviewed complete
240822-byte recipient notice, SHA256
`6c814672403bec2064b22e54dbd028b055e0cacdc6837557a66cd5c0a04af360`, before output.
Missing or changed text still refuses; a source pin is not recipient assent,
Microsoft onward-distributor compliance or binary-delivery approval. The fixed
CA and its three target-neutral notices are exact copies of the previously
accepted certifi2026.7.22/Mozilla input; no Windows TLS claim follows.

After those gates and separate command admission, the existing `prepare_runtime`
produces all six bootstraps/core/CA and unchanged manifest v1. Its sole shared
reader amendment corrects CPython3.14 Windows pathname/fstat comparisons:
normalize only named executable-suffix0111, compare common identity/birthtime,
and retain complete same-API mode/ctime/birthtime/attribute/reparse stamps.
The original POSIX comparison is unchanged; an inert mocked-reader regression
is not real Windows proof. Two opaque headless debug
test-only selections re-inspect that compile-anchored inventory inside the
original passive inspection/endpoint: copied engine, or one compile-bound fixed
probe. The eleven-case batch comprises copied capabilities/catalog/probe, the
same calls with inert hostile cwd/parent environment canaries, and five separate
extra-startup-file prelaunch refusals. Only the exact known refusal extra is
removed, after positive original no-spawn/settlement; no general repair occurs.
The probe measures a bounded current-process loaded-image roster against exact
payload hashes or a finite named System32/API-set policy. Static PE imports and
this prospective policy are not a measured complete dynamic closure.

The fixed-ref Windows2025/X64 first-attempt workflow has five closed phases:
prepare/acquire/compile/windows-payload/retain. One locked headless `--no-run`
artifact is invoked directly once, never rebuilt by a Cargo native command.
Only a non-deletion push to `verify/desktop-windows-payload` with actual event
after equal to the source SHA, or an exact-SHA dispatch on that ref, is admitted.
Python and the compiled Rust test independently recheck the source/workflow/run
binding. Pre-push review establishes the candidate; the ref is not approval.
The native batch allowance is120s; original10s work/2s cleanup stay unchanged.
First unresolved ownership retains the original case and stops successors.
Only bounded existing bindings/frames/receipts are uploaded; no payload or
compiler binary upload is provided. The30min workflow limit is disposal only.
Source authoring, inert DATA and native RESULT acceptance are separate gates;
none has been substituted for native payload evidence. Installed custody,
Windows product builds, W1–W6 transfer, Save/GUI/Quit, TLS/Stores/installers and
production execution remain independently disabled/unqualified.

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

`NATIVE_EDIT_QUALIFIED` stays false. The ignored hosted fixture has only a private
test-build authorization after its fixed environment/source/root checks; it
cannot enable production constructors. Core inert tests, three initial actual-
owner cases, compilation, or a passing negative fault assertion alone cannot
qualify saving, native document lifecycle, Windows custody or installed runtimes.
