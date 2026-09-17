# Mobile Release Kit Desktop

## Status and scope

The desktop application is **under development**. This branch introduces the
passive foundation and gated configuration-save implementation, not a production release or a complete alternative to the
CLI yet. A visible screen is not proof that its future operations are available.
Unimplemented operations are explicitly disabled.

The intended application uses **Tauri 2 / Rust → application services → the
existing Mobile Release Kit core → platform and Store integrations**, with a
React/TypeScript local UI. Python remains responsible for release policy rather
than duplicating it in JavaScript or Rust. The CLI remains supported.

The production distribution must include its Python engine and non-SDK helpers.
An absent or invalid bundled runtime is an error, not permission to use an
arbitrary system Python. **Production engine launch is currently gated off even
if a manifest is supplied:** manifest hashing alone does not hold filesystem
custody through later executable/import opens. The reviewed native bundle
admission implementation and its platform evidence are still required. The
foundation's engine integration is available only to an explicit trusted
development build. Android still needs a compatible JDK/Android SDK and
project Gradle wrapper. iOS native work requires macOS/Xcode locally or on a
protected hosted macOS runner. The desktop does not make these SDK requirements
disappear. No complete installer or clean-machine qualification is claimed here.

## Foundation capabilities

| Surface | Foundation behavior | What this does not prove |
| --- | --- | --- |
| Project selection | Native directory selection, bound to a Rust-owned project ID | Trust in project scripts or repository contents |
| Static snapshot | Bounded recognized text-file hints and configuration observations on supported POSIX filesystems | An atomic snapshot, Git source authority, successful build, signing or Store state |
| Configuration | Guided in-memory drafts with core-owned schema/policy validation and contextual help | Saving a file, checking path existence, approving an app identity or release readiness |
| Configuration save implementation (disabled) | Separate native owner, exact two-file preview/apply contract, guided confirmation and original-outcome handling | Enabled saving, native window/process qualification, general project initialization or Windows file transactions |
| GitHub setup proposal | Guided toolkit pin inputs, core-generated read-only workflow previews, contextual help and environment/credential-name checklist | GitHub login/contact, repository observation, compatibility verification, file writes, secret provisioning or workflow dispatch |
| Environment | Static capability and missing-feature explanations | Running the full doctor, SDK version probes or native admission |
| Credentials, metadata, releases, artifacts, recovery | Guided navigation and honest unavailable states | Stored credentials, completed operations, authenticated evidence or “no recovery needed” |

Windows can use the portable passive services. Its original-parent static reader
is staged in source but **disabled pending independent ABI/native W1–W6
qualification**. The initial target is native x64 Windows on ordinary local NTFS:
bounded ordinary or verbatim drive paths, exact long-name/case observations,
accessible non-reparse directories and single-link files. Unsupported roots,
case-sensitive directories, sharing conflicts or insufficient access refuse;
there is no POSIX, full-path or weaker-sharing fallback.

Acquisition uses documented `NtCreateFile`, one captured volume root, then one
component relative to each retained original parent with `OBJ_DONT_REPARSE`.
Name/metadata equality only vetoes admission; share-read-only does not prevent
attribute-only reparse/case changes. Partial results remain non-atomic static
observations, not ACL ownership or selection-to-request custody. Windows native
build/process ownership, configuration Save and packaged-runtime custody are
separate closed gates; this reader does not implement or enable them.

The UI distinguishes *configured*, *format-valid*, *observed hint*, *unknown*,
*partial*, *stale*, *unavailable*, *native-verified*, and *service-verified*.
`identityStatus=approved` is a user's policy value, not a successful service
check. A core report without failures does not itself prove release readiness.
Draft validation does not save or execute configured commands. Draft edits must
not silently disappear during refresh or project changes.

Help is supplied next to relevant fields and explains what a value means, why it
is needed, where to find it, its format, conditional requiredness, and incorrect
value consequences. Project-provided help/schema URLs are not fetched. Private
credentials must never be entered in general configuration fields.

## Passive engine interface

`mobile_release.api.execute(method, params)` is a dependency-light data interface,
not a wrapper around `argparse`, printed reports or CLI output. The closed initial
methods are:

- `capabilities`, `{}` — implemented services and unavailable actions.
- `catalog`, `{}` — packaged schema, field help and credential/metadata guidance.
- `project.snapshot`, `{root, configPath?}` — static observations of one explicit
  selected root; the desktop supplies the root, not the renderer.
- `config.validate`, `{draft}` — pure shape/policy checks of a JSON object.
- `config.suggest`, `{hints}` — closed in-memory hints to an explicitly unverified
  draft, with default/example provenance and no invented detected platform.
- `config.preview`, `{base, draft}` — bounded, redacted known-field changes and
  shared-policy field context; no filesystem revision, save token or writes.
- `github.setup.propose`, `{draft, toolingRepository, toolingSha, suppliedSnapshot}`
  — four core-generated workflow proposals and desired setup guidance, with no
  repository observation or Apply authority. `suppliedSnapshot` is explicitly
  null or caller-supplied digest/size assertions, never an observed file tree.

Exact additive preparation contracts, limits and the static-hint projection are
documented in [desktop configuration preview](desktop-configuration-preview.md).
The GitHub wire contract and its deliberately non-mutating scope are documented
in [GitHub setup proposals](desktop-github-setup.md).

Configuration saving does **not** expand this passive method list. Its separate
finite owner and core transaction contract are documented in
[configuration editing](desktop-configuration-edit.md) and the
[Rust bridge contract](../desktop/src-tauri/runtime-contract.md#separately-gated-finite-configuration-edit).
The new guided Save flow remains unavailable until native and runtime
qualification gates are satisfied. Preparing an unchanged configuration can
still require an explicit ignore-file update; only a native reviewed plan can
declare a complete no-op. Known committed files, cleanup status and recovery
requirements are shown separately, never collapsed into a generic “Saved.”

These methods do not run Git, Gradle, Xcode, project hooks, native validation,
credential acquisition, signing, Store requests or report-writing code. Do not
call `preflight.doctor`, `Report.emit`, or Git-enabled discovery from them. The
static reader prunes private, generated, dependency and transaction trees before
walking them. It uses anchored no-follow descriptor reads with traversal/read
budgets and explicit partial/error results. It does not infer an enclosing
repository above the selected directory or read arbitrary file contents for the
renderer.

The transport is private and one-shot. Each request is one strict UTF-8 JSON
object followed immediately by a newline and EOF:

```json
{"protocol":1,"id":"request-1","method":"capabilities","params":{}}
```

A success has exactly `protocol`, `id`, `ok: true`, and `result`. A service
rejection has exactly `protocol`, `id`, `ok: false`, and
`error: {code, message, retryable: false}`. Both can exit zero after successful
transport cleanup; the caller must check `ok`, not just the exit code. Startup,
framing, unexpected service, write and close failures exit nonzero. Raw inputs
and tracebacks are not diagnostics.

Limits are 1 MiB request, 4 MiB response, 64 KiB diagnostics, 32 nesting levels and
20,000 JSON values. Duplicate keys, non-finite numbers, invalid Unicode, extra
fields/frames, unknown methods, mismatched IDs and truncated input reject. Input
and output protocol descriptors are private/non-inheritable; ordinary stdin is
detached and OS stdout redirected before service imports.

Rust owns each original child while concurrently writing input and draining both
outputs. Queries have a startup-inclusive 10-second endpoint and at most one
2-second cleanup allowance. A success frame is provisional until original wait,
both EOFs and IO settlement. Timeout/cleanup errors cannot become success. At
most two queries can run; excess calls reject rather than accumulate. Renderer
abandonment does not abandon a process owner. Unknown finality prevents reuse.
This direct-child design **must not** be reused for builds, native validation,
signing or other descendant-producing/stateful work without the separately
reviewed ownership/cancellation backend.

## Runtime and UI trust boundaries

Only fixed packaged executable/bootstrap/core resources are valid in production.
The manifest is bound to a trusted compiled digest, exact target/protocol/core
version and payload digests; an arbitrary self-described adjacent manifest is
not authority. Python launches with `-I -S -B`, a trusted working directory and
an allowlisted environment. No `PYTHONPATH`, site hooks, project cwd, credential
environment, tool search, or implicit development fallback is allowed.

Developer runtime selection requires an explicit debug-only build feature and
explicit developer-owned paths. It cannot be enabled by project configuration,
renderer arguments or a production environment variable. Missing production
resources remain *unavailable*.

`desktop/tools/prepare_runtime.py` is offline publisher preparation, not a
runtime installer or admission bypass. It accepts only an explicitly prepared
public Python payload, creates a deterministic core ZIP and complete bounded
manifest without replacing existing files, and emits
`prepared-not-native-verified`. Publisher acquisition must separately verify the
runtime's provenance, platform, licenses and redistribution terms. Neither this
script nor matching manifest digests qualify executable custody; production
launch stays disabled until that separate implementation is accepted.

### Standalone runtime preparation (publisher work, not user setup)

The intended installed application will include its engine; users will not be
asked to install Python. The following source work is **not yet a working
standalone distribution**:

- `desktop/tools/prepare_cpython_payload.py` implements a bounded, offline
  transformation of the pinned Linux x86_64 CPython payload. It treats archives
  as data, never executes them, preserves required notices, rejects path and
  inventory conflicts, and leaves interrupted output explicitly incomplete.
  Its production entry point currently refuses before reading inputs: the
  accepted notice inventory and original static-link provenance anchors are
  still missing. Caller-supplied approval flags cannot replace those anchors.
- `prepare_runtime.py` includes both the passive and configuration bootstraps
  plus the core ZIP in the complete inventory. Preparing these files does not
  authorize either entry point to run.
- The Linux installed-runtime inspection module has a deliberately narrow
  first scope: Ubuntu 24.04 x86_64 GNU, GA Linux 6.8, and a single original local
  ext4/XFS root mount with protected immutable installation names. It retains
  original descriptor custody, refuses unknown namespace/mount/permission
  observations, and records explicit close results. It is **not connected to
  engine launch** and cannot manufacture an executable qualified runtime.

Supply provenance, accepted redistribution notices, real native custody,
loader/import behavior, installer publication and clean-install checks remain
separate requirements. Other Linux environments and the macOS/Windows installed
runtime backends still need their own implementation and native evidence.
An unavailable runtime is an actionable limitation, never a fallback to a
project-selected executable or the user's ambient Python installation.

The renderer receives typed commands, not general filesystem or shell access.
Native selection and root binding stay in Rust. UI content is local, with a
restrictive CSP; project strings are text rather than HTML. No remote fonts,
remote navigation or arbitrary schema/help downloads are required. Browser
preview is an explicit `VITE_MRK_BROWSER_PREVIEW=1` development build, prominently
labelled with inert example data. A bridge error must never activate preview.

## Verification and resource rules

Read [repository verification](verification.md) first. The historical native/
process suites and CI controller must not run on a shared VPS. Desktop filenames
do not make unsafe tests safe.

Foundation checks have a narrower independently reviewed allowlist: explicit
in-memory protocol/API tests, finite inert snapshot fixtures, TypeScript checks,
and pure UI-state tests. Inspect actual imports/scripts first; never discover the
historical test tree as a shortcut. Installing frontend dependencies must disable
lifecycle scripts, and use the committed lockfile. Vite and Cargo build checks
need the actual dependency/build-script and resource-plan review. Pure tests do
not establish native process custody, native dialog behavior or installer support.

Use disposable GitHub-hosted platform runners for genuine supervisor, Tauri,
Windows/macOS and packaging tests after local detectable failures are resolved.
Use credential-free synthetic inputs and verification-only workflows. Never run
a release workflow or contact a live Store merely to test the desktop. Keep
protected PR delivery and actual-main verification separate from feature-branch
checks.

Keep build outputs/cache roots task-owned, serialize memory-intensive compiles,
and record concise source-bound results. Close only owned finished workers and
delete only known disposable task outputs after each run. Do not remove shared
caches, required dependencies, other worktrees, credentials, or release evidence.

## Remaining product milestones

1. Safe Windows filesystem/process ownership; secure OS-keyring-backed vault,
   native asset selection/import and validation; transactional file preview/apply.
2. Local preflight, native builds/signing/artifact validation, metadata editing,
   progress/cancellation, authentic history and session-bound recovery.
3. GitHub App device login (advanced token fallback), repository/environment/
   secret/workflow plans and safe reconciliation, hosted non-publishing checks,
   guarded release dispatch, build-once promotion and authenticated evidence.
4. Bundled runtimes/helpers, signed cross-platform installers/updates, supported
   native and clean-machine verification, independent acceptance, protected
   delivery and actual-main CI.

All Store mutations remain protected GitHub operations with explicit preview and
confirmation. GitHub App registration, signing identities and private consumer/
Store qualification are genuine external inputs, not reasons to fake a successful
flow. No automatic public release is in scope.
