# Guided public metadata text

## Status: source implementation, Save still gated

The narrow desktop path is **configure locale → load public text → edit and
validate → review exact files → confirm typed Save**. This is an app-managed
preview/save implementation, not a manual-copy substitute. The metadata writer,
native qualification and packaged-runtime gates remain closed. A visible
editor, source-authored inert tests, another edit domain's evidence or a browser
preview does not enable or qualify Save. No test execution or native/Store
readiness is asserted by this document.

The separate metadata writer gate targets Linux x86_64 GNU with strong original
root registration. It does not inherit configuration/workflow fixture
permission and does not enable Windows or macOS mutation. Passive observation
uses only the supported POSIX named reader; the staged Windows snapshot reader
does not enable it. Pure validation is portable. Browser preview may display
the shipped help, but refuses actual file observation, core validation and Save
rather than returning successful fixtures.

## One enabled platform and one saved locale

The existing Metadata configuration editor controls `metadata.root`, Android
locales and iOS locales. Save root/locale/platform configuration separately
before loading public text. A text save neither saves nor discards a
configuration draft; a configuration save neither saves nor discards text.

Only `release/mobile-release.json` determines the public target roster. One
text operation contains every required field, in this order:

| Platform | Canonical field IDs |
| --- | --- |
| Android | `title.txt`, `short_description.txt`, `full_description.txt` |
| iOS | `description.txt`, `keywords.txt`, `privacy_url.txt`, `support_url.txt`, `release_notes.txt` |

Each destination is exactly
`<saved metadata.root>/<platform>/<saved locale>/<field ID>`. The renderer
cannot submit filenames, `metadataRoot`, config paths or absolute roots as
target authority. Paths are bounded to 512 UTF-8 bytes and 12 components;
private, hidden, generated, reserved, unsafe and portable-alias paths refuse.

This does **not** edit private review/demo/TestFlight material, credentials,
optional iOS/category text, screenshots, historical Android changelogs or
build-selected Android release notes. There is no rename, deletion,
translation, whole-tree scan, preflight, archive, Store sync or release action.
Removing a locale from configuration leaves existing files intact. Success for
one selected locale says nothing about other locales, assets or hidden junk.

## Load and validate are passive

Native `metadata_text_observe({projectId,platform,locale})` resolves the selected
root and calls Python `metadata.text.observe({root,platform,locale})`. The core
reads the fixed saved config and only the derived three or five public text
leaves. It does not read `.gitignore`, enumerate other locales, call CLI
discovery or execute project code.

Observation is all-or-error. A missing known text file is an explicit absent
row; an unsafe, unreadable, changed, oversized or invalid-UTF-8 file is never
treated as absence. Original root/parent/file facts are rechecked and original
descriptor cleanup must settle before success. Immediate sibling-name checks
are only for portable-alias rejection and remain bounded. Selected objects
must be ordinary and share the captured root's device and owner; ownership
facts are retained through recheck. The result is still
`single-request-non-atomic`, not an atomic snapshot or a native write revision.

Raw UTF-8 text, raw byte lengths and SHA-256 digests are returned only for safe
selected public files. A secret-pattern match in config or selected text
withholds the whole result, including text and digests. The heuristic does not
prove arbitrary prose secret-free: never place credentials in public copy.
Errors use a closed constant-message vocabulary, not raw inputs, paths,
configuration, exceptions or terminal transcripts. No raw-text logging,
telemetry or on-disk draft persistence is introduced.

Native `metadata_text_validate({platform,fields})` calls the pure Python
`metadata.text.validate` service. It accepts the complete canonical field/text
bundle and returns per-field counts, limits, fixed issues and format-only
assurance. JavaScript and Rust check the structure, not a second release policy.
The core owns empty/NUL/placeholder/secret/URL/length rules. URL fields require
absolute credential-free HTTPS URLs without queries or fragments.

Generic validation uses a **validation-only** universal-newline view: CRLF and
lone CR become LF, then trailing LF characters are excluded from the Unicode
character count. Counts are Python Unicode code points, not JavaScript UTF-16
units. Original and replacement bytes remain independent: no trimming, BOM
removal or newline normalization is performed on Save. Browser textarea edits
may normalize line endings; the exact proposed bytes and newline-style-set
change are therefore included in Review. Android's separate raw CR/LF
500-character build release-note policy is unchanged and outside this editor.

## Drafts, help and reconciliation

The UI distinguishes configured, observed/missing, unsaved, format-valid,
stale, saved and recovery-required/unknown states. A format-valid result is not
Store approval. The shipped `metadata-text-help-v1.json` supplies accessible
requiredness, what/why/where/format/failure help for every field and each of
Load, Validate, Review, Save and Discard. Missing help is additive-unavailable,
not a reason to fetch project-provided guidance or weaken policy.

Raw originals are kept separately from textarea drafts. Async results bind to
the selected project, saved config context, platform/locale, observation and
baseline generation, request and draft revision. Refresh, switching project or
locale, and removing a configured locale do not overwrite or silently evict
drafts; old-context drafts remain explicit. The workspace cache holds at most
32 locale bundles and 8 MiB of text. Capacity refuses a new admission and asks
for explicit discard; it never automatically evicts unsaved work.

Changing text/selection/config context retires pre-Apply authority. Closing a
review keeps drafts. Text dirtiness participates in project/close warnings.
If a save was already submitted, newer drafts remain separate from that
original operation. A lost mutation reply observes the original owner; it does
not automatically retry or open a replacement writer.

## Read-only dependencies and complete typed Review

The original registered-root lease captures saved config and `.gitignore`,
derives an immutable metadata target descriptor once, then captures target
originals/absences and parent facts. Config and ignore are **read-only
dependencies**, never metadata writable entries. Dependency-only parents are
not part of target-directory staging or creation.

Before Open, `.gitignore` must conservatively cover the fixed private rules:

```text
.mobile-release/
.mobile-release-init-prepare/
.mobile-release-init/
.mobile-release-init-cleanup/
.mobile-release-metadata-text-prepare/
.mobile-release-metadata-text/
.mobile-release-metadata-text-cleanup/
```

Missing or ambiguous coverage, including conflicting negations, requires a
separate reviewed configuration save. That configuration operation still has
exactly two writable destinations: `release/mobile-release.json` and
`.gitignore`. Only its fixed ignore vocabulary expands; metadata never writes
ignore rules or bypasses their proof.

Prepare accepts the original revision, complete field/text bundle and expected
baseline. Baseline config and per-file digest/length/absence assertions detect
changes that preceded Open; they cannot reconstruct native authority or select
new paths. Core validation must accept every field. Changed dependencies,
parents, targets or namespace refuse the whole bundle without a plan token.
There is no force, automatic rebase or replacement checkout.

Review freezes every canonical destination and its `create`, `replace` or
`preserve` action, original/after raw text, byte lengths and digests,
newline-style changes and observed-absent target ancestors. Preserve means
exact byte equality, retaining existing bytes, mode and inode. Replacement uses
the existing supported mode policy. No dependency, other locale, asset,
version, `.git` or index is a write target. There are no deletes.

## Original one-use Apply and recovery boundaries

The separate commands `metadata_text_edit_open`, `_prepare`, `_apply`, `_close`
and `_status` share the existing global original edit owner and document
admission with configuration/workflows. The event is `metadata-text-edit-status`;
the child protocol is fixed `mrk-metadata-text/1` with bootstrap selector
`metadata_text`. Prepare cannot retarget Open, and Apply contains only the
original session/plan token. Tokens are consumed before acquisition. There is
no writer on the passive supervisor or general filesystem/shell bridge.

Apply rechecks the same original root, dependencies, parents and targets, and
uses short lock scopes, exclusive staging/install, fsync and original cleanup.
Editing/review holds no project lock. All-preserve still confirms and rechecks
the original baseline, then returns unchanged without creating a journal.
Multi-file installation is recoverable, not instantaneously atomic or a
containment boundary against hostile same-UID code.

Metadata state names are selected **before the first mkdir**:

```text
.mobile-release-metadata-text-prepare
.mobile-release-metadata-text
.mobile-release-metadata-text-cleanup
```

The legacy three-state list/recovery dispatch remains separate. All domains
reserve both sets and refuse foreign states/aliases before opening or adopting
them, including an empty metadata preparation or one containing only
`header.tmp`. Metadata cleanup requires original domain/header/plan/control/
inventory authority. Incomplete or uncertain preparation is retained. There
is no generic persisted/crash metadata recovery, automatic journal deletion,
`init --recover` fallback or mutation retry.

One original rollback or committed-cleanup attempt is allowed. Known committed
effect, journal cleanup and resource settlement are separate facts; cleanup
uncertainty cannot erase a known commit. Only the exact submitted plan with
ordinary settled native/core finality advances the matching text baseline.
Unknown/recovery-required state blocks further edit domains rather than
displaying an unsupported “Saved” or “nothing to recover” claim.

## Bounds and qualification

Each text/original is at most 32 KiB UTF-8. Config is at most 512 KiB and the
native-only ignore dependency at most 1 MiB. Five originals plus five
replacements total at most 320 KiB; dependency/control material has separate
bounds. Requests are at most 1 MiB, passive results/native status 2 MiB,
complete prepared views 768 KiB and terminal frames 16 KiB. Complete oversize
objects refuse, never truncate a review. Existing traversal/cleanup ceilings,
the five-second cooperative reader budget and ten-second passive endpoint are
retained. These budgets do not enlarge Store character limits.

Focused Python/renderer/Rust test sources cover pure policy and framing,
original target/dependency binding, exact projections, isolated metadata state,
one-use/stale/finality handling and help. Execution requires separate exact
command admission. Real Save enablement additionally requires independent
exact-source native original-owner/direct-child, filesystem replacement/fault,
cancellation/STOP/settlement and installed-resource qualification. None is
inferred from source review, inert checks or another domain's qualification.
