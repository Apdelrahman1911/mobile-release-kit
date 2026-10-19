# Guided project settings — integration checklist

## Actual delivered scope

- `DraftEditor.tsx` now uses `GuidedConfigurationFields` for its normal settings
  layout, with App & platforms, Version & build, Project defaults, and Signing &
  Store groups. There is no new route, App prop, API, schema or save method.
- All 41 real bundled catalogue fields are retained once. Custom commands,
  schema fields, and future catalogue additions remain in Advanced. Help,
  values, unknown/invalid shapes, native browsing callbacks, and explicit unset
  behavior still come from the original `DraftField`.
- Groups and search hide DOM wrappers, not field components. Stable path keys
  preserve mounted controls. An active native file picker keeps its field
  visible and pauses group/search navigation. The small metadata-only form also
  retains its existing three fields across search changes.
- A visible, direct group link exposes required/conflicting/unknown Advanced
  fields. Advanced stays open for current field attention, matching search
  results, or a picker there. A background review never moves keyboard focus.
- “Check what’s needed” calls the existing `onReview`, under its existing reason
  and pending checks. No mount, stage change, search, refresh, or suggestion
  automatically checks, adopts values, approves an identity, or saves anything.
- The existing suggestion/provenance/adoption flow, draft retention warnings,
  errors, save/discard/review/validation footer, removed-field undo controls,
  original review, and native ownership/recovery controls remain outside the
  new grouping. No native owner or confirmation dialog is duplicated.
- The default banner uses ordinary saved/unsaved wording. Baseline and
  two-destination details are collapsed; external-file changes remain a visible
  keep-editing or explicit reload choice. “Review & save…” is only a new label
  for the original native review callback, not a direct-save shortcut.

## What the numbers mean

`guidedConfiguration.ts` uses only an existing current pure core review bound to
the selected project session, draft revision, and baseline generation. Its
descriptor-safe bounded presentation check requires complete catalogue field
coverage and the existing read-only assurance. It does not derive policy from
labels/help or declare which values should be required itself.

- Required but absent, forbidden but present, and unknown field contexts count
  as attention. A present empty/invalid value is **not** known valid.
- Current validation failure and partial comparisons remain explicit issues,
  even when the field-presence count is zero.
- A pending, failed, stale, foreign, incomplete, or malformed review has unknown
  counts, never “zero missing” or “completed.” Example mode makes no real-project
  observation claim.
- Neither format-valid data nor all four visited groups establishes a saved
  configuration, native rename, current saved version, tool/signing compatibility,
  Store eligibility, or build/release readiness. Original owners still recheck.

## Existing policy limitation — intentionally not changed

Configuration v1 still requires the shared version/source/metadata/service/check
structure, enabled-platform identities and declared identity policy. An approved
identity adds its actual signing/delivery requirements. Later groups are not all
optional; incomplete configurations are not partially saved. A truly staged
persisted schema requires a separately reviewed shared-core/schema change, not
UI defaults or bypassing the existing native save owner.

## Verification and remaining checks

Focused command from `desktop/`:

```sh
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 tests/guided-configuration.test.mjs
```

Result: **15/15 passed**, 174.212762 ms. `git diff --check` passed. Tests use the
actual field-help resource and existing workspace reducer/project-path binding
helpers, including stale-review-no-zero-attention and
pending-picker-stage-switch-no-state-loss. Test observations are inert DATA,
not a native/Store/installed-UI pass. No dependency install or full build ran.

Root accepted distinct source review of grouping, context, retained controls,
and save/recovery ownership, with the small default-copy correction now applied.
Root still must perform its shared integrated TypeScript / frontend build. This
slice needs no additional App wiring. Root may add the new
focused test file to the existing package test command; this lane did not edit
the manifest. Real macOS UX and native picker behavior remain owner testing,
not established by these pure tests.
