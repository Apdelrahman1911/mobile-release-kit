# iOS app-target source hints

## Scope and integration

Seven owned files; shared sources are changed only by the accompanying
`ios-app-target-hints-20261020.patch` (three targets). Authoring base:
`4f28cbdd`, branch `task/automation-project-target-hints-20261020` in the
preserved `project` worktree. Root independently approved this plan and owns
actual integration/review.

This removes the need to type a conventional app target name from memory.
The existing passive saved-project check lists literal application-target
names. An explicit choice fills the **local** iOS target field; the manual
field always remains. Nothing chooses the first target, changes saved
settings, opens an edit, or applies an ID automatically.

Mandatory Root hooks:

1. `src/mobile_release/discovery.py`: `parse_project_sources` uses the same
   admitted source/directory inventory to append optional `ios.appTargets`.
   There is no additional reader, executable, discovery pass or bootstrap.
2. `src/mobile_release/api/_setup_analysis.py`: admit that closed optional
   field using the leaf validator. All existing setup selectors and limits
   remain unchanged; hints do not become setup/release authority.
3. `desktop/src/App.tsx`: replace only the existing manual target presentation
   with the new controlled field. Capture the original rendered session,
   service/identity binding and existing intent epoch. On explicit choice,
   recheck them and the reciprocal gate both before and after the original
   `retireIdentity`; then update only the existing per-project local map.
   The original manual setter, ProjectIdentity editor and native calls remain.

The new module is included by ordinary Python package collection. No runtime
profile, Rust/native owner, wire command, permission or manifest is added.
Root may add the focused Node filename to its existing test command roster;
this packet does not edit the manifest.

## Bounded source data, not build truth

`project_target_hints.ios_app_target_hints(sources, projects)` reuses the
actual `project_identity_ios._Project` parser. Only root-declared
`PBXNativeTarget` objects with the literal application product type are
listed. Test/framework/aggregate targets, products and scheme names are not
app suggestions. All root target names participate in duplicate/ID-alias
checks, matching the original identity selection semantics.

The bounds are 16 Xcode projects, 512 KiB per existing source, 128 root target
references and 32 app names per project. The existing strict PBX parser,
passive inventory's aggregate source/time bounds and output limiter remain.
Malformed, generated-marker, ambiguous or over-limit projects have no
partial name list. An unsupported row has only a closed diagnostic code and
source line, never raw build settings, scripts or exceptions.

The optional snapshot shape is:

```text
ios.appTargets = [
  {project: "iosApp/Reader.xcodeproj",
   source: "iosApp/Reader.xcodeproj/project.pbxproj",
   targets: [{name: "Reader", line: 9}]}
]
```

A refused row has `targets: []` plus `diagnostic: {code, line}`. Successful
rows omit the diagnostic: the original snapshot deliberately drops null
members when bounding output. No truncation is treated as a valid target.

The frontend requires the same saved-config comparison and selected root,
nonpartial original snapshot, exact saved `.xcodeproj`, no pending/failed
refresh and no source/save-recovery invalidation. Workspace-based selections
remain manual/unsupported for this editor; a workspace is never removed or
inferred to be a project. Schemes never choose targets. A same-byte replacement
snapshot or API/project/epoch ABA invalidates an old click. A blocked native
context disables the choice; the handler repeats the checks for races.

These remain **names from the last file check**, not an atomic source view or
resolved build settings. The original identity Open/Preview/Apply still
rechecks complete source controls, exact target/config/scheme closure,
published-identity continuity, immutable review and transactional recovery.
Namespace, source packages, reservations and unrelated source are untouched.

## Focused author evidence

The two Python hook targets were applied only to a task-owned public-source
projection. The App hook was not installed or executed by this lane.

```sh
PYTHONPATH=.task-ios-target-hints/projection/src python3 -B -m unittest -v \
  tests.unit.test_project_target_hints tests.desktop.test_setup_analysis

/opt/node/current/bin/node --experimental-strip-types --test \
  --test-isolation=none --test-concurrency=1 \
  desktop/tests/ios-app-target-hints.test.mjs
```

- Python: **17 passed**, zero skips, 0.053 s (9 new and 8 existing passive
  setup tests). Includes the actual finite `project_snapshot` filesystem
  reader and setup projection with synthetic project files; project execution
  is forbidden. The first run caught the null-member omission at this real
  seam; the optional diagnostic shape above fixes it, not the shared limiter.
- Node: **12 passed**, zero skips, 145.569 ms. Uses the actual workspace reducer,
  bounded parser and local-choice helper. Tests malformed/oversized data,
  saved-vs-draft selection, partial/recovery refusals, same-byte refresh,
  single-use choice and reentrant API/session/gate/epoch invalidation.
- The three-file patch applies to both the author base and current Root
  `9a723876` with Root's existing working changes. No tracked shared file in
  the author worktree was edited.

Original test callers returned. Logs (including the initial failed assertion)
are retained under `.task-ios-target-hints/results/`; finite fixture directories
were removed by their original test scopes. The public Python projection is
disposable author output, not runtime evidence.

No Cargo, real build/tool/provider operation, native invocation, credentials,
React render, TypeScript graph check, Mac qualification or UI automation was
performed. Root still owns typecheck, application wiring and actual installed
functional verification; passive suggestions do not qualify source editing.
