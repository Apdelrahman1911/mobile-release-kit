# Guided dashboard integration

This is a presentation layer over the existing controllers, not a new release
engine or a readiness authority. The owner reported the current app works on
macOS 27; that report is not qualification of every native operation.

## Required App wiring (Root-owned)

Pass the two existing states alongside the unchanged Dashboard panel slots:

```tsx
<Dashboard
  initializationState={initializationState}
  versionEditState={versionEditState}
  // Existing props, initializationPanel and versionEditor unchanged.
/>
```

These states keep active work, failed results and recovery visible. Do not
replace them with a generic `busy` flag or hide original global operation
controls. Both panel slots remain mounted exactly once inside native details
elements; a disclosure change neither resets a form nor cancels a task.

Dashboard imports its own scoped `components/setupOverview.css`. It needs no
new route, bridge, package, global stylesheet or backend change. Root may use
plain navigation labels while preserving the existing Page IDs and `navigate`
retirement behavior. GitHub, Store delivery, metadata, artifact inspection and
recovery remain discoverable task links; only technical detail is collapsed.

## Optional domain observations

`checks?: readonly SetupCheckObservation[]` is an **internal UI projection**.
Root maps actual tool/signing controllers to it only after those controllers
accept the current native observation and bind it to the selected project,
saved configuration, applicable platform/activity and service generation.
The selector additionally matches project ID, observation generation, baseline
generation and draft revision. Stale, foreign, duplicate or missing projections
are unchecked. Supply at most one current item per stage.

`checked` means the particular setup check, **not** release readiness. Tool
catalogues, picked paths, version/format checks, stored credential descriptors,
reservation previews and unconfirmed native replies cannot qualify it. Use
plain, public, nonsecret summary text. When a native domain has no currently
qualified adapter, omit the item; do not simulate completion.

`activities?: readonly SetupActivity[]` accepts public negative/progress
observations from original operation owners. `unknown` means unknown original
finality, not an unperformed check. Retain recovery/unknown until the same
owner/domain actually resolves it. Ordinary old or foreign check failures are
not owned activities. The current-project guide is separate from foreign
unfinished work; App must retain the latter's original global controls.

The guide can only choose a folder, request an existing read, reveal a panel or
navigate. Its final next step is **Review a local build**, never Start/Apply.
All native prerequisite checks and sensitive confirmations remain authoritative.
The saved release version is an accepted saved-file read, not a draft value,
allocated reservation, Store latest version, or build approval.

## Focused verification

```sh
cd desktop
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 tests/setup-overview.test.mjs
```

The focused tests cover project/version freshness, missing versus partial
observations, draft preservation, inert preview, resume, cancellation/recovery
priority, foreign work separation, and disclosure-state rules. They are pure
presentation fixtures, not DOM/native/platform/provider acceptance. Root owns
the integrated frontend typecheck/build and the owner’s actual UX trial.
