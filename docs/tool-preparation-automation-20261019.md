# Tool preparation: implementation and integration handoff

## Scope and evidence

This slice plans reuse and exposes beginner-facing, manual/resume guidance. It
does not download, install, accept licenses, lend tools, change project pins,
relax a native profile, or establish release readiness. The existing Environment
page **already consumes** the new guidance through its retained diagnostics
controller. Its original Start/Cancel/Status and global recovery controls remain.

Implemented:

- `mobile_release.tool_requirements.observe_tool_requirements`: bounded passive
  source hints, no IO, Gradle/Xcode/dependency resolution or project execution.
- `tool_preparation.rs`: reuse-first decisions and exact-context resume checks.
- `tool_preparation_adapters.rs`: original catalog, source, registration, service
  and diagnostics owner DATA; no renderer-supplied native status or executable.
- `tool_preparation_protocol.rs`: narrow request, closed source response, view.
- `toolPreparation{Types,Protocol,Controller,Guidance}.ts`: closed DATA parsing,
  recheck-before-click, fixed existing-controller adapters, manual instructions.
- `ToolPreparationGuide.tsx`: optional app-retained planner view for central
  integration. `EnvironmentDiagnostics.tsx` already has the useful fallback.

Focused local verification (synthetic DATA, **not** installed/native acceptance):

- Python `test_tool_requirements.py`: **9 passed**.
- Node `desktop/tests/tool-preparation.test.mjs`: **11 passed**.
- Existing focused `environment-diagnostics.test.mjs`: **18 passed** (29 combined).
- Direct std-only Rust `tool_preparation.rs`: **9 passed**, no dependencies built.
- `git diff --check`: passed.
- Added 5 native-adapter DATA tests and 3 wire DATA tests for Root's scheduled
  native compilation. These have **not yet been compiled or run** in this lane.
- Frontend typecheck remains Root-scheduled; this worktree has no node_modules.

One Node assertion initially matched `ready` inside `already`; word boundaries
fixed that test. Independent Root review required a separate actual in-flight
promise guard: invalidation/project switching now retires only presentation,
never permitting a new read while the original read/forwarded action is pending.
The focused regression covers both kinds of pending work. Compact title is now
“Build-tool check.” No download or native work was performed by these tests.

## Root-only wiring

Do not use a path nomination, renderer status object or ordinary version probe
as an installed-tool lease. Protected execution remains with its existing owner.

1. Add normal module declarations for `tool_preparation`,
   `tool_preparation_adapters`, `tool_preparation_protocol`.
2. The read-only route accepts only:
   `{schemaVersion:1, projectId, expectedObservationRevision}`. Parse with
   `tool_preparation_protocol::request`. Native supplies the actual client/session,
   current host, original saved project and observation revision. No client host,
   policies, selections, pins, paths, installer options or consent is accepted.
3. Collect an already-owned, **bounded** source snapshot and saved-config digest.
   Pass its fixed source text map to Python `observe_tool_requirements`, using
   the actual selected Android application build file, not an arbitrary module.
   Decode that response with `tool_preparation_protocol::requirements`.
   This is not yet a registered public core method in this lane.
4. Bind `Context` to project, native session, observation revision, complete saved
   config digest, returned source fingerprint and current native host. A revision
   represents a current census; re-reading unchanged DATA must not manufacture a
   new revision. New source, config, selection or connection invalidates it.
5. Pass statuses obtained from the **original** owners to
   `android_observation(&saved_prepare, &catalog, &sources, &registration, &service)`
   or `ios_observation(&expected_diagnostics_context, &diagnostics_status)`.
   Root must snapshot/recheck all owner generations before publishing; do not
   promote a mixture of observations across a project switch or an active owner.
   The Android supplier getter reads only an already-warm checked cache; it must
   not initialize supplier work under Document/Registry locks.
6. `prepare(context, &requirements, &observation)` returns guidance. Its
   `action_still_current` guard compares full Context plus all nine generation /
   revision fields. `resume` requires a fresh revision of the same source,
   configuration, session and host, then plans again. It never repeats a write.
7. Expose `toolPreparationPlan` in the central Desktop API/bridge only when the
   original native snapshot route exists. Otherwise leave the optional planner
   view hidden; do not fabricate a positive preview/native response. The already
   wired Environment diagnostics fallback still works independently.

### Source snapshot roster

Maximum 9 entries, each <=512 KiB, total <=2 MiB; exact bytes and missing entries
are fingerprinted. Fixed root inputs: `build.gradle`, `build.gradle.kts`,
`settings.gradle`, `settings.gradle.kts`, `gradle.properties`,
`gradle/libs.versions.toml`, `gradle/wrapper/gradle-wrapper.properties`, plus the
selected application build file and its `.gradle`/`.gradle.kts` sibling. The
selected path must have bounded conventional relative components. Both siblings,
dynamic/conflicting hints, external build logic and incomplete census stay unknown.
`complete` is a native snapshot fact, never a UI checkbox. Unknown files or read
failures must not be presented as missing files in a complete census. The caller
must invalidate on source changes beyond a previously missing file as well.

Even fully literal hints are `unverified-static-source-hints`, **not effective
Gradle values**. This parser intentionally does not resolve custom plugins,
settings overrides, convention builds or dependencies. Normal build validation
still owns compatibility and execution. A wrapper URL without an exact checksum
does not produce a resolved preparation plan.

### Existing frontend adapters

Retain one `ToolPreparationController` in App, subscribe normally, invalidate on
the saved observation, existing tool events, connection changes and navigation
context loss. Do not dispose an original native owner when this view disappears.

Callbacks are deliberately fixed:

| Callback | Existing control to invoke/show |
|---|---|
| `refreshRegisteredTools` | existing explicit catalog refresh |
| `chooseRegisteredCopy(comparison)` | existing catalog selection, never a path |
| `chooseSource(jdk/sdk/gradle)` | existing native folder picker |
| `showSourceInspection` | source Inspect/Review/explicit protected-copy approval |
| `showToolService` | existing Check/Request registration/Settings approval UI |
| `showRecovery` | original status/cancel/recovery, preserve retained files |
| `showXcodeChecks`, `showXcodeInstructions` | Environment diagnostics/prerequisites |
| `showProjectRequirements`, `showBuild` | existing project/build navigation |

Refresh does not execute any of those callbacks. Continue re-reads and compares
the full decision before forwarding one explicit click. Forwarded means neither
installed nor settled. Service registration and copy approval are never invoked
automatically by this controller. In particular the Java 21 workflow example is
not an override for the checked macOS supplier's Temurin 17 profile.

## macOS 27 Xcode companion: reuse the completed ARM package

The source in this base already has `min="26.0"` without a `before="27"` ceiling,
and the shared native OS-version correction. **No new XML, native OS gate,
allowlist or workflow edit is necessary for this lane.** The owner now reports
the main app working on macOS 27. That is not Xcode-companion, SDK, archive,
signing or upload verification. The older Intel companion remains 26-only.

The corrected ARM companion has since passed signing/notarization, first/repeat
installation and both managed-tool admission tests on macOS 26: source
`bf9d397b`, run `39301915324`, attempt 1. Reuse
[artifact 12211884317](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/39301915324/artifacts/12211884317),
confirmed available on October 22 and expiring November 2, 2026, 18:31:42 UTC.
See `desktop-macos-manual-test-guide.md` for installation prerequisites and the
remaining macOS 27 verification limitation. Do not rebuild merely for reassurance.

If a replacement is actually needed, Root can reuse the existing
`.github/workflows/desktop-macos-installed.yml` job:

- event: `workflow_dispatch`;
- exact existing ref: `refs/heads/verify/desktop-macos-xcode-setup`;
- input `operation=xcode-setup-companion`;
- input `target=aarch64-apple-darwin` for the owner's Apple Silicon Mac;
- source/workflow SHA must be the same exact reviewed commit at that ref;
- preserve the branch allowlist in the workflow and
  `desktop/tools/macos_android_helper_package.py` (`XCODE_SETUP_REF`).

Only Root may coordinate routing reviewed source to that branch and dispatch.
No push, dispatch, installer or download was performed by this lane. Intel is a
separate explicit target, not implied by an ARM result. No app/Store supplier
runtime rebuild is required just to replace this standalone companion.

The existing job compiles the current app-native test binary and standalone
`--no-default-features --features macos-xcode-setup --bin mrk-macos-xcode-setup`,
signs the helper, builds/signs/notarizes the PKG, and uploads it. **Upload is not
the acceptance point**: the subsequent Installer first/repeat qualification and
both native tests must pass before giving that artifact to the owner:

- `installed_runtime::ios_upload_tools_tests::ios_managed_archive_actual_tools_pre_post_and_positive_consume`
- `installed_runtime::ios_upload_tools_tests::ios_upload_actual_selected_tools_pre_post_and_positive_consume`

`desktop/tools/macos_xcode_native_admission.sh verify` requires exactly 2 passed,
0 failed, 0 ignored. These actual selected-tool admission tests do not launch
Xcode/build/archive/export. The existing runner is macOS 26, not proof of macOS
27 operation; record the actual source/run/attempt/artifact and host separately.

Manual prerequisites remain exact Xcode **26.3 / 17C529** from the shared core
policy, Apple license/first launch/iOS platform completion by the user, original
`/Applications/Xcode.app` preserved, separate protected
`/Library/MobileReleaseKitDeveloper/Xcode.app`, enough space for another full
logical copy plus reserve, no global `xcode-select` workaround, and no old remover
or force deletion. Re-run only the same matching package where its authenticated
unfinished state permits; completed copies are not silently replaced.

## Following slice (separate approval)

Verified cache-first/missing-only vendor acquisition and strict extraction,
followed by the ordinary explicit native picker and existing protected-copy
review/approval. This is a **staged download/picker step**, not full automatic
setup. A download receipt cannot forge the picker OriginalWork retained by
SourceSnapshot. Native origin-role integration and targeted repair remain later
reviewed work. No HTTP, extraction or filesystem acquisition implementation is
approved by the existence of the read-only planning API.
