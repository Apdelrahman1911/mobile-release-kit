# Mobile Release Kit Desktop

## Status and scope

The desktop application is **under development**. This branch introduces the
passive foundation and gated typed-edit implementations, not a production
release or a complete alternative to the CLI yet. A visible screen is not proof
that its future operations are available.
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
| Public locale text | Saved-config-derived named observations, in-memory drafts, shared core validation and contextual help | Private review/TestFlight access, whole-metadata validation, translation, Store acceptance or writes |
| Public locale text save implementation (disabled) | Separate metadata domain, complete one-locale file review and original one-use typed Save | Enabled saving, native transaction/process qualification, screenshot editing, locale deletion or packaged-runtime readiness |
| Pure credential assessment (internal only) | Core policy over explicitly supplied scalars and finite file observations, with a private result-sanitizing adapter | Renderer secret entry, file acquisition/parser qualification, password verification, native custody, storage or assignment |
| Environment requirements | Current-draft prerequisites, fixed baseline guidance and missing-feature explanations | Observing installed tools, running doctor or native admission |
| Build-tool diagnostics implementation (disabled) | Explicit, cancellable version observations through a separate native owner and the ordinary core command owner | Enabled diagnostics, complete SDK checks, native document/runtime qualification or release readiness |
| Credentials, releases, artifacts, recovery | Guided navigation and honest unavailable states | Stored credentials, completed operations, authenticated evidence or “no recovery needed” |

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
- `environment.requirements`, `{draft, platform, operation}` — current supplied
  draft guidance for `android|ios` and `build|artifact-validation`. Expected pins
  and practical help are core-owned; tool presence/version/readiness stay unknown.
  The actual core host is distinct from the selected release platform. Disabled
  draft platforms return no applicable rows. There is no filesystem/tool probe,
  credential lookup, native execution or network access in this method.
- `github.setup.propose`, `{draft, toolingRepository, toolingSha, suppliedSnapshot}`
  — four core-generated workflow proposals and desired setup guidance, with no
  repository observation or Apply authority. `suppliedSnapshot` is explicitly
  null or caller-supplied digest/size assertions, never an observed file tree.
- `metadata.text.observe`, `{root, platform, locale}` — all-or-error observation
  of the complete public-text roster for one saved, enabled platform/locale;
  native project selection supplies the root, never renderer paths. Available
  only with the supported POSIX named reader, not the staged Windows reader.
- `metadata.text.validate`, `{platform, fields}` — pure shared generic text
  policy, Unicode character counts and fixed non-reflective issues; no IO,
  observation, native revision or Save permission.
- `credentials.assess`, `{schemaVersion, policyVersion, context, input}` — pure
  assessment of supplied scalars and closed mechanical observations, not a
  credential reader. This does not add a renderer command or enable the vault.

Exact additive preparation contracts, limits and the static-hint projection are
documented in [desktop configuration preview](desktop-configuration-preview.md).
The GitHub wire contract and its deliberately non-mutating scope are documented
in [GitHub setup proposals](desktop-github-setup.md).
The public-text scope, separate configuration prerequisite, raw-byte semantics
and gated typed Save are documented in
[guided metadata text](desktop-metadata-text.md).

Typed saving does **not** expand this passive method list. Configuration's separate
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

Environment requirements narrow the whole response envelope, including its
newline, to 65,536 bytes; draft input is at most 512 KiB. Fixed errors never echo
malformed field names, draft values or exception messages. Project, draft,
baseline, activity and connection generations bind UI responses; changes
invalidate synchronously, including switching away and back. Earlier requirements
are explicitly stale, not evidence for the current selection. A deliberate
browser fixture remains labelled as example data across connection changes.
No native doctor or release gate is enabled.

General limits are 1 MiB request, 4 MiB response, 64 KiB diagnostics, 32 nesting levels and
20,000 JSON values. Duplicate keys, non-finite numbers, invalid Unicode, extra
fields/frames, unknown methods, mismatched IDs and truncated input reject. Input
and output protocol descriptors are private/non-inheritable; ordinary stdin is
detached and OS stdout redirected before service imports.
Metadata text narrows its passive result/native status to 2 MiB and a complete
prepared view to 768 KiB; oversize data is refused rather than truncated.

Rust owns each original child while concurrently writing input and draining both
outputs. Queries have a startup-inclusive 10-second endpoint and at most one
2-second cleanup allowance. A success frame is provisional until original wait,
both EOFs and IO settlement. Timeout/cleanup errors cannot become success. At
most two queries can run; excess calls reject rather than accumulate. Renderer
abandonment does not abandon a process owner. Unknown finality prevents reuse.
This direct-child design **must not** be reused for builds, native validation,
signing or other descendant-producing/stateful work without the separately
reviewed ownership/cancellation backend.

### Build-tool diagnostics (separate, qualification-gated operation)

The Environment page separates **requirements** from **observed checks**.
Requirements use the current configuration draft; they do not inspect the host.
The explicit **Check build tools** action has a separate native capability gate.
It never runs automatically when a project opens, reconnects, or changes. At this
source milestone that gate remains closed: source implementation and pure tests
do not qualify a host, runtime, or native document lifecycle.

Once that exact profile is qualified, the first diagnostic scope is deliberately
small:

| Target and host | Allowed observations | Still not checked |
| --- | --- | --- |
| Android on qualified GNU/Linux or macOS | Git, Java runtime and Java compiler versions | Gradle/AGP compatibility, SDK packages, signing tools, project commands |
| iOS on qualified macOS | Selected developer installation, Git, and complete Xcode version/build against core policy | Signing, profiles, schemes, archives, Store access |
| iOS on Linux; Windows; artifact-validation diagnostics | Explicit host/scope unavailable result | No fallback execution or cross-platform claim |

Linux uses only the admitted system Git and the matching Java alternatives pair
under `/usr/lib/jvm`. macOS uses the existing selected developer installation and
at most one admissible system-installed JDK pair. No PATH search, custom-location
fallback, installation launcher, license acceptance, or tool-selection change is
performed. Missing **in the supported lookup** does not mean missing everywhere
on the computer. The UI explains these distinctions and the next manual setup
step rather than displaying raw tool output or internal paths.

The command environment starts empty with only fixed locale/system search
settings (and the admitted developer directory for Xcode). It excludes project
hooks, home configuration, JVM options, credentials, proxies and loader settings;
the current working directory is the qualified neutral runtime directory, not the
project. Installed tools are administratively trusted software. This is not a
malware sandbox, immutable executable-handle proof, or promise that system tools
cannot update their own caches.

One native operation reserves a **six-second work deadline** and a **ten-second
finality deadline**, both from original admission, including startup. Each command
has at most three seconds within that shared reservation and a combined 16-KiB
stdout/stderr bound. A slow installation can therefore time out even when it
would work with a longer interactive command. There is no automatic retry or
renewed cleanup allowance. An ambiguous ordinary command failure is reported as
incomplete, not guessed to be a timeout, missing tool or invalid version.

The native operation—not the page promise—owns startup, the original child,
request pipe, output readers and their final joins. Cancel, document/context loss
and confirmed Quit request the original operation to stop. Losing a Start reply
requires checking its existing status, never starting a replacement. A terminal
core frame is provisional until original resources settle; unknown cleanup keeps
the active operation reserved and blocks conflicting work/normal exit. Earlier
results remain visibly stale after their project/draft/baseline context changes.

**Complete** means the finite check list completed, not that every tool matched
policy. Version mismatch, unavailable selection, failed command, cancellation,
timeout and unknown finality remain distinct. No project, repository, credential,
signing, network or Store operation is requested. Builds, full doctor, Windows
ownership, native UI qualification and standalone distribution remain separate
milestones; no production constructor is enabled by this implementation.

### Supplied-input credential assessment (no renderer routing)

The R1 pure contract uses exactly:

```text
{schemaVersion:1, policyVersion:"credential-policy-v1",
 context:{draft:object, platform:"android"|"ios"|"project",
          stage:"candidate"|"external-testing"|"production", purpose:"full"|"signing"|"store"},
 input:{kind:Kind, fields:Fields, observation:Observation}}
```

Every declared member is required, including explicit null scalar/observation
members. Extras, wrong exact JSON types, bool-as-int, contradictory tags and
`stage:"all"` refuse. The draft keeps the existing configuration schema: core
independently bounds, serializes and parses it without reading a project. It
does not reuse potentially reflective `config.validate` issues. No selected
paths, bytes/Base64, filenames, labels, project IDs, digests or native claims
are accepted outside that unchanged draft schema.

| Kind | Platform | Exact scalar fields | Allowed observed formats |
| --- | --- | --- | --- |
| `android-keystore` | android | `storePassword`, `keyAlias`, `keyPassword` | JKS, PKCS#12 |
| `android-firebase` | android | none (`{}`) | Firebase JSON projection |
| `apple-p12` | ios | `password` | PKCS#12 |
| `apple-profile` | ios | none (`{}`) | CMS SignedData |
| `asc-p8` | ios | `keyId`, `issuerId` | unencrypted PKCS#8 |
| `ios-firebase` | ios | none (`{}`) | Firebase plist projection |
| `google-wif` | android | `provider`, `serviceAccount` | none; observation must be null |
| `project-read-token` | project | `token` | none; observation must be null |

Scalars are null or UTF-8 strings, at most 4,096 decoded bytes each and 65,536
bytes in aggregate. Null/empty means missing. Nonempty NUL-containing values
fail value admission, not password verification. Whitespace is not trimmed;
shared core identifier rules remain unchanged, as do all CLI readers and bool
policy seams. The closed union currently has at most three scalar companions.

File observation null means no submitted selection. Common nonnull variants are
`{status:"unavailable",reason}` with `not-run`, `incomplete`, `unsupported-format`,
`unsupported-variant`, `material-limit` or `parser-limit`, and
`{status:"rejected",reason}` with `empty-file`, `suffix-conflict` or
`malformed-container`. These are not IO/picker/custody failure reports.

Observed variants all require `status:"observed"`, a positive exact integer
`byteCount` within the canonical core material limit (4 or 32 MiB), and exactly:

| Format | Additional members |
| --- | --- |
| `jks` | `version:1|2` |
| `pkcs12` | `version:3`, `authSafe:"data"|"signed-data"` |
| `cms-signed-data` | `encoding:"der"` |
| `pkcs8` | `encoding:"pem"|"der"`, `algorithm:"ec"|"rsa"|"other"`, `curve:"p256"|"other"|null` |
| `firebase-json` | `document:AndroidProjection` |
| `firebase-plist` | `encoding:"xml"|"binary"`, `document:IosProjection` |

Non-EC PKCS#8 requires curve null. EC other/null curves are representable but
fail the core EC/P-256 predicate. These tags assert only their named envelope
scope, never key usability, parser/platform qualification or password validity.

```text
AndroidProjection = {root:"object"|"other", clients:null|Client[]}
Client = null|{clientInfo:null|{androidClientInfo:null|{packageName:null|string}}}
IosProjection = {root:"dictionary"|"other", bundleId:null|string}
```

Root other requires the other member null. Null represents an absent/wrong-type
node; all clients and their order must be preserved, including malformed ones.
There are at most 256 clients and 1,024 UTF-8 bytes per projected string. Core
reconstructs minimal decoded documents and uses the shared Firebase shape/match
predicate: every Android client must have required objects and a nonempty
package name, with at least one exact applicationId match; iOS needs a string
BUNDLE_ID with an exact bundleId match. Empty Android arrays/iOS strings are
complete shapes without a match. Shape failure is not identity mismatch.
Duplicate/trailing-input/entity/parser/allocation checks remain native R5 work.

Observation JSON is at most 64 KiB, 4,096 nodes and depth 8. Draft JSON remains
at most 512 KiB. The existing actual envelope limit (1 MiB including newline,
depth 32 and 20,000 nodes including keys) still wins; direct pure calls also
bound exact JSON params. Escaping counts toward encoded bounds. No truncation,
sampling, dropping malformed clients or deduplication makes an input fit.

The existing requirement selector remains the sole stage/purpose/platform and
service-flag authority. It is intersected with the selected guide's canonical
kind/field associations, in guide order. Project-token assessment explicitly
uses `project` and an empty release-platform selection; its existing candidate
full/signing/source-flag rule is unchanged. Applicability reason precedence is
`wrong-platform`, `platform-disabled`, `not-required`, then `selected`. A partial
kind association is unavailable rather than a guessed policy.

The result has only `schemaVersion`, `policyVersion`, `kind`, finite
`context:{platform,stage,purpose}`, `applicability:{state,reason}`, `state`,
`fields`, `identity` and `assurance`. Every field has constant guide `id` and
canonical `requirement`, `presence:"missing"|"supplied"`, `state`, at most one
issue code and at most three ordered, nonduplicate `{scope,outcome}` checks.
There are 1–4 fields and a separate 16-KiB result bound. No raw values, draft,
IDs, paths, sizes, counts, hashes, lengths/prefixes or free-text details return.
Presence describes the submitted value/assertion, not actual file existence.

- Not applicable: all fields and aggregate `not-applicable`, no checks/issues.
- Missing: `missing`/`required-missing`; unavailable observation: `unknown` with
  its reason; rejected observation: `invalid` with only its limited file reason.
- Recognized JKS/PFX/CMS/P8 envelopes are at most `configured`. Each file is
  assessed independently of scalar companions: a missing/invalid password or
  identifier never becomes a file/password failure.
- Scalars use `value-admission` and, for alias/ASC/WIF identifiers only,
  `identifier-format` with actual `passed`/`failed` outcomes over supplied data.
- File rejection checks (`file-nonempty`, `suffix-consistency`, `container-parse`)
  are `asserted-fail`; observed envelope/document checks are `asserted-pass`.
  Pure P8 `ec-p256-identifiers` and Firebase `firebase-shape`/
  `application-identity` checks use `passed`/`failed`, not native assurance.
- Only a matching Firebase projection is `format-valid`, in the supplied-data
  document/identity scope. Shape failure is `firebase-shape`/`not-assessed`;
  complete-shape mismatch is `identity-mismatch`/`mismatch`.
- Aggregate precedence after applicability is invalid, missing, unknown, then
  configured (format-valid for matching Firebase). Other field facts are kept;
  neither unknown nor stale is retrospectively called invalid.

Assessment assurance is separate from the passive catalogue's
`credentialsRead:false` contract:

```text
{basis:"supplied-input-only", scalarValuesProcessed:bool, fileObservationsProcessed:bool,
 selectedFilesRead:false, keyringAccessed:false, storageWritesPerformed:false,
 projectCodeExecuted:false, sourceCustody:"not-established", nativeValidation:"not-run",
 serviceValidation:"not-run", releaseReadiness:"unknown"}
```

The processed booleans mean any string (even empty) and any nonnull observation
was admitted and processed. A direct caller can fabricate observations, not
native custody. No result means stored, assigned, password-verified or ready.

Expected refusals are `retryable:false` and use only these fixed messages:

| Code | Message |
| --- | --- |
| `assessment_invalid_request` | The assessment request has an unsupported shape or value type. |
| `assessment_limit` | The assessment request exceeds a supported interface bound. |
| `assessment_version` | This assessment schema version is unavailable. |
| `assessment_policy_stale` | Credential policy changed; prepare the context again. |
| `assessment_context_invalid` | The submitted draft is not valid for assessment. |
| `assessment_unavailable` | Credential assessment is unavailable; no credential was verified. |

Policy version must first be a 1–64-byte ASCII letters/digits/`._-` token; a
different well-shaped token is stale, not an invalid credential. Unexpected
dependency exceptions use the engine's constant failure path, never reflective
config/parser or arbitrary ApiError messages.

The private Rust adapter admits/rebuilds closed types, validates result context,
kind, version, field/check/aggregate invariants and the 16-KiB cap, and discards
raw engine error messages. Only these six codes and fixed owner `busy`,
`shutting_down`, `query_timeout` and `cleanup_unknown` survive; other errors
become `assessment_unavailable`. Actual native context changes must eventually
use local `assessment_context_stale` / `Assessment context changed; prepare
again.`, not a core-supplied stale flag. No native binding is implemented here.
Future routing must retain and recheck the exact live document, serialized draft,
context, policy, kind and original selection/record revision after core success.

There is no `credentials_assess` renderer invoke or generic method selector.
The existing Supervisor, two slots/no queue, 10-second endpoint, single 2-second
cleanup allowance, original-child/write/EOF/reap/join settlement, retained
unknown and production/platform gates are unchanged. Request, serialization,
Python/Rust and owner buffers create copies; unknown cleanup can retain them.
No zeroization, crash/swap/OS-memory erasure, payload logging/cache/storage or
earlier resource release is promised. Native custody/parsers, credential entry,
vault lifecycle/backends and feature activation remain separate prerequisites.

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

### Build-tool diagnostics verification profile

The dedicated `desktop-environment-diagnostics-native.yml` profile is headless:
one compilation and one fixed test entry on each of GNU/Linux x64 and macOS
arm64. It does not launch the desktop, install an application, invoke project
build scripts, contact a Store or change the selected tools. Linux compilation
and inert checks run locally first; hosted Linux is used for the original
process-lifecycle exercises that must not run on a shared development machine.

Receipts distinguish actual installed-tool observations, source/core-ZIP
bootstrap coverage, and explicitly injected cancellation, output-limit and
delayed-finality cases. The latter exercise the real owners but are not evidence
of installed tool versions or actual OS faults. A missing prerequisite leaves
dependent checks unexecuted; it is not replaced with a fake successful tool.
Terminal output alone never proves that the original processes, readers and
closes settled. Unknown resource custody prevents another case from starting.

This profile cannot enable diagnostics in a production constructor. Native
window/document behavior, installed runtime custody, Windows support and
standalone packages remain separate qualification requirements. Passing its
workflow is not a claim that the Desktop application is complete.

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
