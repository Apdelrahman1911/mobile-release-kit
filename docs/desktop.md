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
arbitrary system Python. The general bundled-runtime resolver remains closed:
manifest hashing alone does not hold filesystem custody through later opens.
There is now a separate, fixed Linux installed-runtime path for the normal
shell, with per-request original custody and finality. Its current scope is
capabilities/help, native project selection, a static project snapshot, and
in-memory configuration suggestion, validation and redacted review, plus
draft-based Environment prerequisites and read-only GitHub workflow proposals,
saved release-version reads, public locale-text observation/validation, and a
separate candidate-document inspector.
Prerequisites do not inspect tools; proposals do not read or write repository
files, verify remote refs or contact GitHub. The installed-shell and
project/draft/guidance native checks are still pending; this is not general Linux
or production qualification. A separate configuration-only installed Save route
now uses the existing edit owner, full two-file review, explicit confirmation and
original runtime settlement. Its installed native check is also pending.
A separately sealed workflow profile now connects the existing GitHub review
and confirmation UI to that same installed edit owner. It can create absent
callers or preserve exact originals, never save the configuration draft. This
is **prepared source, not installed workflow qualification**; the installed
check and independent original-finality review are still required.
A third sealed profile connects public locale-text Review/Save to the same
installed owner. It requires the registered project root, a complete file
preview, acknowledgment and typed `SAVE`; it never saves the configuration
draft. Its new sixth installed `metadata-save` case and independent integration
verification are still pending. This is prepared implementation, not a native
or production-readiness claim.
Credentials, tools, network and Store actions remain unavailable on that path. Trusted development builds
remain a separate explicit mode, never a fallback. Android still needs a compatible JDK/Android SDK and
project Gradle wrapper. iOS native work requires macOS/Xcode locally or on a
protected hosted macOS runner. The desktop does not make these SDK requirements
disappear. No complete installer or clean-machine qualification is claimed here.

## Foundation capabilities

This table describes implemented surfaces, not a grant to execute them. The
installed path above admits its twelve passive core methods, separate
project/evidence-folder pickers and separately sealed configuration/workflow/metadata edit profiles; the UI shows an explicit
reason for unavailable actions.
Choosing a project does not enable the credential/asset session. Draft changes
stay in memory until a separately reviewed and confirmed native Save.

| Surface | Foundation behavior | What this does not prove |
| --- | --- | --- |
| Project selection | Native directory selection, bound to a Rust-owned project ID | Trust in project scripts or repository contents |
| Static snapshot | Bounded recognized text-file hints and configuration observations on supported POSIX filesystems | An atomic snapshot, Git source authority, successful build, signing or Store state |
| Saved release version | Explicit Dashboard read of the saved configuration's version file, using the same parser and version/build policy as core builds | A version from an unsaved draft, Git commit proof, artifact comparison, full preflight or release readiness |
| Configuration | Guided in-memory drafts with core-owned schema/policy validation and contextual help | Saving a file, checking path existence, approving an app identity or release readiness |
| Configuration save implementation (installed verification pending) | Existing separate native owner, fixed Linux installed profile, exact two-file preview/apply contract, guided confirmation and original-outcome handling | General packaged/native qualification, project initialization, workflow or metadata Save, or Windows file transactions |
| GitHub setup proposal | Guided toolkit pin inputs, core-generated read-only workflow previews, contextual help and environment/credential-name checklist | GitHub login/contact, repository observation, compatibility verification, file writes, secret provisioning or workflow dispatch |
| Local workflow Apply implementation (installed verification pending) | Existing four-caller review, complete text, separate confirmation and one-use Apply through the original shared edit owner; create absent or preserve exact bytes | Configuration Save, overwrite/pin upgrades, remote setup, Mac/Windows workflow writes, or completed installed qualification |
| Public locale text | Saved-config-derived named observations, in-memory drafts, shared core validation and contextual help | Private review/TestFlight access, whole-metadata validation, translation, Store acceptance or writes |
| Public locale text save implementation (installed verification pending) | Separate fixed Linux metadata profile, complete one-locale file review and original one-use typed Save; close retains the draft | Completed installed qualification, Mac/Windows writes, screenshot editing, locale deletion or packaged-runtime readiness |
| Pure credential assessment (internal only) | Core policy over explicitly supplied scalars and finite file observations, with a private result-sanitizing adapter | Renderer secret entry, file acquisition/parser qualification, password verification, native custody, storage or assignment |
| Environment requirements | Current-draft prerequisites, fixed baseline guidance and missing-feature explanations | Observing installed tools, running doctor or native admission |
| Build-tool diagnostics implementation (disabled) | Explicit, cancellable version observations through a separate native owner and the ordinary core command owner | Enabled diagnostics, complete SDK checks, native document/runtime qualification or release readiness |
| Saved Android offline checks implementation (disabled) | Saved-input consent, the existing shared offline core policy and original cancellation/finality ownership; core builds disabled | Enabled execution, a sandbox, no-network/no-write behavior, native/runtime qualification or release readiness |
| Saved Android build implementation (disabled) | Guided saved-input review, one explicit app/variant, build progress/cancellation and captured AAB observations through the existing core | Enabled execution, fresh-source provenance, verified signing, a release candidate, qualified tools or Store approval |
| Candidate evidence inspector (installed verification pending) | Separate evidence-folder picker, three fixed candidate documents, core-owned format/self-digest/binding checks and a guided documents-only summary | Artifact-byte inspection, authenticated provenance, source-project comparison, Store state, release readiness or safe recovery |
| Credentials, releases, recovery | Guided navigation and honest unavailable states | Stored credentials, completed operations, authenticated evidence or “no recovery needed” |

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

Recovery also lists the three file-edit controllers' retained per-project alerts
from the current app session, including alerts older than the latest result.
This is not persistent history, journal inspection or a recovery action. Loaded
projects can be opened through ordinary navigation without discarding drafts;
unloaded-project alerts stay visible. Public-text alerts retain no locale or file
outcome. An empty list never establishes clean state or permission to retry, and
existing original/uncertain-operation status controls remain unchanged.

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
- `release.version.observe`, `{root}` — bounded observation of fixed saved
  `release/mobile-release.json` and only its admitted `version.source`. Rust
  supplies the registered root via `release_version_observe({projectId})`;
  renderer paths, alternate configs, key/platform overrides and drafts are not
  accepted. This uses the existing POSIX named reader, not staged Windows support.
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
- `artifacts.candidate.observe`, `{root, expectedRoot}` — private, bounded
  observation of `candidate-manifest.json`, `candidate-receipt.json` and
  `operation/candidate-operation-intent.json`. Native supplies the separately
  selected evidence root and its original device/inode/mode/UID/GID; renderer
  requests contain only the opaque selection ID. Reuses the existing provenance
  validators for document consistency, without opening artifact payloads,
  following document-directed paths, contacting services or changing files.
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
Saved-only consent, trusted project-code effects and the separate closed execution
gate are documented in [saved offline checks (Android)](desktop-offline-preflight.md).
The separate build flow and its artifact/safety limits are documented in
[saved Android build and inspection](desktop-android-build.md).

The Artifacts screen always labels its result **“Local document consistency;
provenance and artifact bytes unverified.”** Choosing evidence never replaces the
source project, discards a draft or changes GitHub context. The separate original
operation ID permits exact cancellation and status recovery after a lost reply;
“Stopping” is not proof of settlement, and cleanup-unknown remains blocking.
Earlier observations are shown only as stale. The inspector now has a separate
fixed installed Linux profile, without granting private-asset authority. Its
installed native verification is pending; preview/development builds and older
native fixtures cannot run it. macOS/Windows evidence adapters and general
production runtime admission remain outstanding.

Typed saving does **not** expand this passive method list. Configuration's separate
finite owner and core transaction contract are documented in
[configuration editing](desktop-configuration-edit.md) and the
[Rust bridge contract](../desktop/src-tauri/runtime-contract.md#separately-gated-finite-configuration-edit).
The guided Save flow is available only through its narrow profile and original
native admission; installed verification is not yet complete. Preparing an unchanged configuration can
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

### Read the saved release version

Dashboard's **Read saved version** action displays the normalized marketing name
and build number from the saved configuration's source. The shared core parser
handles KEY=VALUE lines, comments, quotes and duplicate/unsafe-value refusal;
the shared release policy applies the stricter marketing form whenever saved
configuration enables iOS and requires a canonical build number in
1..2,100,000,000. No project script, Git command, native tool, credential lookup,
report writer or network service is used. An unsaved draft is explicitly **not
applied** and is never overwritten by the read.

Configuration is capped at 512 KiB and the version file at 64 KiB. Saved source
paths must be bounded nonprivate relative paths (512 UTF-8 bytes, 12 components),
with no links or portable aliases. The existing named reader holds original
parents, checks file identities and absences, and settles original cleanup.
Ordinary missing/invalid outcomes are retained until those contexts finish;
change/limit findings supersede them and uncertain cleanup cannot become success.
The version-2 result returns the admitted relative source, selected normalized
name/build, and `savedConfig` / `savedVersion` comparisons. Each comparison has
an exact positive byte count and 64-character lowercase SHA-256 digest of the
original UTF-8 file bytes, not reserialized JSON, normalized lines or parsed
version values. File text, other keys and raw parser/filesystem errors are not
returned. Version-1 results are refused; explicitly read again rather than
inventing missing hashes. The 8-KiB params and 4-KiB result DTO caps are separate
from unchanged finite RPC framing limits.

Observations are single-request, non-atomic and may become stale. Refresh, picker,
service and save intents retire old UI requests synchronously; failed refresh,
cancelled selection, unchanged/stale saves and recovery attention cannot reattach
a late result. Both byte comparisons are retained or retired with the whole
observation; they are not file custody, build consent or release-readiness evidence.
This read does not match a build Prepare snapshot or implement a build Start
recheck. Retry is explicit, and retiring a UI result does not cancel or
claim settlement of its native owner. Browser preview never fabricates a read.
This saved-version method is included in the installed twelve-method passive
profile, with installed native verification pending. Windows observation remains unavailable. The card reports real
runtime/platform unavailability rather than using ambient Python.

This is build-input preparation, **not offline preflight**. Even core preflight
with `--offline --skip-builds` may perform Git/discovery, project checks and native
commands. No build, version bump, artifact inspection/authentication/comparison,
signing or release operation is added; **Release readiness remains Not assessed**.

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

### Prepare this release's inputs (draft guidance only)

Credentials offers **Show current draft requirements** using the existing passive
`config.validate` method. It sends a clone of the current in-memory configuration,
including unsaved changes; it does not inspect credentials or saved files. The
core already returns all-stage, full-purpose requirements. Candidate/internal,
external testing and production preparation are presentation filters only, with
Android, iOS and project-level rows grouped without a second policy table.

Each row says **Required by this draft; presence not checked.** File/scalar
companions and alternatives come from the returned descriptors. Existing core
asset/catalogue help explains what an input is, how/where to obtain it, its format
and failure guidance. **Open guide** selects existing reference content; it never
starts an importer or changes private-session context. Unmatched families remain
visible, with bounded catalogue help or an explicit unavailable-help message.
No requirements for one stage does not mean inputs are present or a release is
ready. Browser preview cannot fabricate a current-draft core result.

Rows and requests retire synchronously on refresh attempts, project/picker and
draft changes, reconnect at its start, help replacement/failure, and save or
recovery events—even when draft revision does not change. Pending/failed refresh
never restores old rows; stage changes cannot reveal them. Only the still-current
original request may publish, and retired replies cannot clear a newer request.
This is UI retirement, not cancellation or finality of the passive supervisor.
A failed project refresh leaves any later explicit guidance limited to the
retained draft; separate native recovery attention remains blocking.

The renderer admits bounded requirement/help DTOs and schema-policy assurance,
not credential-validation claims. Invalid-draft and transport errors use fixed
safe messages instead of reflective core errors. No secrets, possession flags,
file paths or private values are collected or retained by this pane. Existing
session acquisition/assessment/storage/assignment gates are unchanged; native
qualification, unsupported pickers, persistent vault storage, protected service
checks and releases are not enabled by guidance or pure frontend tests.

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
- The Linux installed-runtime inspection module retains original descriptor
  custody, refuses unknown namespace/mount/permission observations and records
  consuming close results. Separate fixed installed-A selectors connect the
  twelve-method passive profile and configuration edit owner on the exact
  reviewed Linux x86_64 GNU host profile (including its pinned kernel). This is
  not general Ubuntu/Linux qualification or permission to use an arbitrary
  manifest, host or engine; installed shell/Save verification remains pending.

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

The prepared installed workflow route is limited to the normal
`desktop-shell` profile on Linux x86_64 GNU, with the existing A runtime and
exact Ubuntu/platform/custody checks, including kernel `6.17.0-1022-azure`.
It does not enable a global edit flag or a development/publisher fallback.
The existing installed-shell observer has a separate fifth `workflow-apply`
case: mixed preserve/create, a changed-pin conflict without a token, explicit
unchanged confirmation, and native Quit with a pending review. Its original
45-second, 128-evaluation and 2048-byte receipt limits remain unchanged.
Source, compilation or prior headless checks do not establish that this path
works in an installed window. The full Desktop remains incomplete.

The separate sixth `metadata-save` case uses the actual editor and two explicit
Reviews: close the first without applying, retain the text, then reopen and
acknowledge/type `SAVE` for one Apply. It requires genuine original session,
plan, revision, runtime/child/stream finality and fresh Load correspondence.
Independent post-exit inventories require one replacement, one new text file,
and preservation of the title, unrelated sentinel, configuration and inputs.
The same 45-second/128-evaluation/2048-byte receipt limits apply. This case is
source-authored and awaiting installed verification; no Store is contacted.

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
