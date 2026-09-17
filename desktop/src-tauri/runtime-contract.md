# Desktop M1 Rust bridge and runtime contract

This is a read-only foundation, not a shipping standalone runtime, Windows native
release backend, or replacement for the audited CLI's ownership services.

## Current executable scope

The seven renderer commands are `app_info`, `choose_project`,
`project_snapshot {projectId}`, `catalog`, `validate_config {draft}`,
`suggest_config {hints}`, and `preview_config {base, draft}`.
Snapshot and draft validation return the core result without inventing verified
facts or saving files. Project IDs refer to Rust-held native picker selections;
renderer-provided roots/executables/command lines/method names are not admitted.
There are no shell, filesystem, opener, build, Store, credential, or recovery
commands/plugins. The sole local webview denies remote/new-window navigation.
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
its result contains no executable/core/bootstrap paths and app commands never
call it. Its current pathname-based reads are not a safe execution admission
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
- `core.zip`;
- `python/bin/python3` on Unix, or `python/python.exe` on Windows;
- the explicitly inventoried interpreter/stdlib payload.

Manifest exact keys:
`schemaVersion:1`, `protocol:1`, `coreVersion:"0.3.0"`, `target`, `coreSha256`,
`protocolSha256`, `inventorySha256`, `files:[{path,sha256,size}]`.
`target` is the exact Cargo target triple. `protocolSha256` hashes the exact
`src/mobile_release/_desktop_engine.py` stored inside the core ZIP.
`coreSha256` must equal the core ZIP inventory digest. The file list is strictly
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

## Passive protocol and original child owner

Only `capabilities`, `catalog`, `project.snapshot`, `config.validate`,
`config.suggest`, and `config.preview` can be requested. Suggestions and previews
are bounded in-memory preparation, never saving or filesystem revision authority;
see `docs/desktop-configuration-preview.md`. One fresh selected Python process
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

## Dependency and check boundary

Direct crates and toolchain are exact-pinned; Cargo.lock records the complete
optional/platform graph. Default features are empty; `desktop-shell` adds Tauri,
rfd and tauri-build. Headless check does not require GTK/WebKit. `build.rs` uses
only std bookkeeping in a headless build, but serde/tokio proc macros and
transitive build scripts still require independent source/execution review.
Optional tauri-build generates allow/deny permissions for only the seven named
commands, and the main local capability grants exactly their allow permissions.

In-memory protocol, path-name and stop-latch unit tests contain no child, native
SDK, filesystem fixtures, network, or app launch. They do not establish native
IPC, timeout behavior, original process finality or platform readiness. Cargo
compilation/test, native query/fault tests, shell launch, packaging and installers
must follow the independent check plan; real supervisor/native work stays on
reviewed disposable hosted runners. No test or compilation is implied by source
authoring or Cargo lockfile generation.
