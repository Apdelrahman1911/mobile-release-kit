# Saved release-version VALUE editing

## Status: source implementation, writer closed

This is an app-managed **Open → edit two values → Review → confirm Save**
implementation, including an explicit **Create version file** path for a source
observed absent. It is not a manual-copy or CLI substitute. The separate
`NATIVE_RELEASE_VERSION_EDIT_QUALIFIED` gate is **false** and
`ReleaseVersionInstalledProfile::SOURCE_BINDING` is **None**. No native writer,
platform, recovery or shipping qualification is asserted here.

The existing **Read saved version** action and `release.version.observe`
schema 2 remain read-only and unchanged. Successful Read is not permission to
write. Browser preview never fabricates a load, absent file, save or capability.
Another edit domain's runtime/fixture/evidence cannot enable this writer.

## Ordinary application flow

1. Select a native project. Save a format-valid `release/mobile-release.json`
   in Settings, including the intended `version.source`, `nameKey`,
   `buildKey` and iOS enabled state. Unsaved Settings remain an independent
   draft: opening or saving values neither applies nor overwrites them.
2. Use **Settings → Prepare save review** to review any missing conservative
   ignore rules. Configuration still writes only its fixed config and ignore
   destinations. The version editor never repairs `.gitignore`.
3. When the separately qualified writer is available, select **Open saved
   version editor** on Dashboard. It loads the original saved-config-derived
   source and keeps one original native lease. The UI displays the admitted
   source, keys, original values, iOS policy and saved byte comparisons.
4. Edit the marketing-version and build **strings**, then **Validate and review
   values**. Only a true captured absence offers **Validate and review
   creation**; blank fields in that case are not detected values.
5. Inspect the complete original/after text, action, destination, UTF-8 byte
   counts, native SHA-256 digests, requested/preserved mode, exact missing
   directories, separator styles and final-newline presence. Check the review
   acknowledgement and type **SAVE** in the confirmation dialog. The dialog
   binds the exact session, one-use plan, draft revision and baseline generation.
6. Keep the original status until its actual result and native cleanup settle.
   Read saved version again explicitly before preparing fresh build consent.

No account, JDK/SDK/Xcode, project script or terminal step is needed for this
ordinary flow once its writer is qualified. Save does not rebuild an application,
change Gradle/Xcode projects, edit Git/index/workflows/metadata, acquire secrets,
contact a Store, or establish artifact agreement or release readiness.

## Exact bytes and refusal rules

The shared `config.parse_key_value_text` parses the **whole** UTF-8 source.
A writer-specific span locator then admits exactly one selected name and build
assignment, each with an unambiguous nonempty ASCII atom. Matching outer quotes
are allowed, but inline annotations, escaping, ambiguous/missing/duplicate
selected keys or case-fold aliases are not guessed or normalized. Malformed
unrelated lines also refuse the edit. Whole-file sensitive text and unsafe
selected paths are withheld.

For Edit, only those two inner value byte spans change. Everything else is
preserved: unrelated keys, comments, indentation, spaces around `=`, quote
style, ordering, every separator and final-newline presence. No whole-file
serializer is used. All separators already supported by the Python parser,
including its additional Unicode/control line separators, retain their bytes;
this does not broaden the shared Ruby parser corpus.

An unambiguous policy-invalid original such as build `0` or marketing name
`bad` can Open and be corrected. Original atoms can exceed proposed-value
bounds within the source-file cap; they are not silently clipped. Empty,
malformed, unreadable, linked, ambiguous or withheld sources **are not absence**
and cannot enter Create.

For Create, the only output is exactly:

```text
<saved nameKey>=<reviewed name string>
<saved buildKey>=<reviewed build string>
```

Those are two UTF-8/LF lines with a final LF. Only the captured absent source and
its captured missing ancestor suffix may be created. New file mode requests
0644 and directories 0755, subject to the native umask. Edit preserves the
admitted original mode. Exact same-value Edit uses no payload and rechecks the
original file and dependencies rather than writing a replacement.

Proposals require a 1–64-byte ASCII name and 1–10 ASCII-digit build string.
Nothing is trimmed, coerced or automatically incremented. The same
`release_version_from_values` policy used by existing builds decides validity,
including iOS's stricter marketing form and canonical build range
1..2,100,000,000. Renderer/Rust bounds are not a second policy implementation.

Limits: saved configuration 512 KiB, source 64 KiB, ignore file 1 MiB; public
source path 512 UTF-8 bytes and at most 12 components. Request, Opened, full
Review and response/status caps are respectively 16 KiB, 512 KiB, 1 MiB and
2 MiB. Complete bounded text is selectable/scrollable, never truncated into an
apparently complete review.

## One original authority and read-only dependencies

The concrete noncopyable `VersionTargets` is created once by the original
`InitRootLease`, not by deserializing a path or baseline. It binds exactly one
source derived from the captured saved configuration. Config and `.gitignore`
are read-only dependencies; their original-only parent facts never become
write targets or new directories. File identities, absences, modes and parent
bindings are retained in the original `RootedRevision`.

Capture, Prepare and Apply use that same lease with short scopes of the existing
root lock; no lock spans human review. Prepare consumes the checkout once,
including malformed/stale requests. Apply consumes the plan once. A changed
original, dependency or parent refuses; no new observation silently replaces
the expected baseline. Renderer digest/length/absence comparisons are DATA,
not a replacement for native custody.

The existing `init_transaction` engine, rename/fsync/rollback and cleanup
machinery are reused. The closed profile `release_version` selects:

```text
.mobile-release-version-prepare
.mobile-release-version
.mobile-release-version-cleanup
```

These join the shared pending-state vocabulary, not the legacy initialization
`STATE_NAMES`. Foreign domains refuse them even before the first complete
header. Version editing does not recover another profile's journal.

Configuration and version prerequisites use all **ten** fixed ignore lines:
the existing evidence/init/metadata seven followed by those three version
directories with trailing slashes. Exact positive root-prefixed or unprefixed
rules count; a later syntactic negation invalidates an earlier proof.
Configuration can conservatively append missing rules, but not override
ambiguous negation intent. Metadata explicitly retains its original
**seven-rule** proof and remains positively usable with seven-only coverage.
The build-input proof remains its original single evidence-directory rule.

## Draft lifecycle, uncertainty and recovery

App-retained drafts are bounded to 16 projects and stay in memory only. Closing
keeps the draft; confirmed Discard resets its values to the retained original
without reading a file. **Reload saved values and discard this draft** is the
only explicit rebase. Reopening for another Review must first match the
retained original; mismatch closes the fresh session and marks the old draft
stale instead of authorizing the new source.

Before Apply, selection (including away-and-back or cancelled selection),
refresh (including failed/no-op reducer results), configuration intent/outcome,
draft/review changes, navigation, reconnect and shutdown retire the old review
synchronously, before reducer/effect early returns. Late replies may settle the
original owner but cannot revive its confirmation.

After Apply is claimed, newer draft values or navigation do not erase the
submitted outcome or retarget its operation. A normal final result advances a
baseline only for the still-matching submitted draft/context. Otherwise the
newer draft is retained and marked stale, with the exact older outcome visible.
Every save intent and outcome, including unchanged/stale/unknown, invalidates
the passive read epoch and saved-input/Android/offline consent. No new read,
preflight, build readiness or cancellation success is fabricated.

The shared Rust `EditOwner` retains one domain-tagged session per native
document. Its existing 30-second active phases, absolute 15-minute review,
10-second finalization and original process/IO/task/descriptor settlement apply.
Known committed effect, journal state and native cleanup are separate facts.
Unknown is absorbing; late evidence can refine the original outcome, not enable
retry or turn a late join into normal success. Missing invoke replies trigger
one original-status observation, never mutation resubmission.

Desktop version recovery is **unavailable**. Never commit/upload/delete its
private transaction state or rerun a save to clear it. Preserve the original
operation, report a sanitized blocker and obtain separately authorized recovery.
Legacy `init --recover` and other edit domains must refuse version state;
they are not a recovery fallback.

## Required distinct verification

Pure span/facade/custody-seam tests, DTO/controller promise tests and Rust DATA
tests do not establish filesystem, UI, process or finality behavior. A future
admission needs a **new** source-bound core ZIP, exact member inventory,
bootstrap/manifest/compiler binding and separate version-writer profile review.
The old installed A payload and metadata/configuration positives cannot be
borrowed. Only then can separately authorized original-owner Linux
filesystem/UI/process/finality cases be collected. Windows, macOS writer
qualification, persisted recovery and shipping remain closed.
