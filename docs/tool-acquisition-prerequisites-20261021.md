# Resume tool setup after a missing prerequisite

Source-only successor to the existing discovery, missing-only acquisition and
protected registration path. No new owner, command, clock, budget, qualification
flag, automatic download, registration or approval.

## Root composition

Owned leaves:
- `desktop/src-tauri/src/tool_acquisition_prerequisite.rs`
- `desktop/src/toolAcquisitionPrerequisite.ts`

Apply `tool-acquisition-prerequisite-hooks-20261021.patch` (10 existing targets).
It applies to author base `3a8ad7eed59638ad540c070222a6ad584081c811` and was
checked against Root `f37f4240d7384004505384539841b348b00d30b4`.
The patch does not contain the separately accepted three-transition native
observer reorder, which Root has already integrated. Service-only observation,
all original source operation IDs and deadlines stay unchanged.

## Exact boundaries

- Only Document **Prepare**, before `owner.prepare`, can return
  `tool_acquisition_catalog_required` or
  `tool_acquisition_saved_inputs_required`. Existing Start and generic errors
  are unchanged. A failed, busy, unknown, unqualified or exhausted original is
  not reclassified as a missing prerequisite.
- Catalogue diagnostics require pristine never-entered state or the actual
  positive joined catalogue original, including its existing `CatalogChanged`
  retirement. Existing `CatalogLoan` remains the only successful route. The
  original source/registration checks and retained-owner census still refuse
  uncertainty; no fake empty catalogue or selected tuple is constructed.
- Saved-input diagnostics come only from the existing saved-lane match in
  Prepare. Drop the Edit guard and recheck the original admission gate first.
  No renderer snapshot is promoted to a returned `SavedObservationLane`.
- The UI records the exact rejected Prepare call. It releases that UI pending
  attempt only after the original Promise returns and a new read returns the
  **same complete status, revision and previous identity**, with unchanged
  original API/project/saved/known-tools witness and epoch. This is known
  nonentry, not `terminalRead`, a native completion, or a reusable intent.
  Events, pre-return reads, lost responses, changed status, ABA, reentrancy and
  post-admission errors cannot satisfy it. An older terminal remains history.
- Once that refused call is confirmed not entered, later peer status changes
  are handled normally; they cannot revive the old attempt. The user explicitly
  uses existing catalogue Recover/Choose or saved-input Read, then explicitly
  checks required tools again. Existing folder choices stay selected. No action
  is automatically repeated and download/copy consent remains separate.

## Focused evidence and limits

- Actual composed Node: **63 passed, 0 failed, 0 skipped** (12 new + 51 affected)
  in the two existing `tool-acquisition-controller.test.mjs` and
  `tool-acquisition-source-picker.test.mjs` suites. The new paired-controller
  case uses the existing Android and saved-input reader with inert ports.
- Whole composed Root `f37f4240` frontend + these hooks: `tsc --noEmit` exit 0,
  using the existing dependency tree, with the exact temporary link removed.
- Five Rust sources parsed with rustfmt. **No Rust compile/test or native
  execution here.** No download, vendor tool, service or installation ran.
- Logs and exact before/after sources are retained in `.task-tools-resume`.
  The first Node run exposed a test-only null-prototype comparison; it retained
  the actual immutable parsed value thereafter. The first noEmit projection
  lacked seven public JSON inputs and contained Root's already-fixed unrelated
  version-editor null guard. Both failed logs are retained; final source checks
  above are the successful ones.

New portable Rust selectors (unrun):

```text
tool_acquisition_protocol::prerequisite::tests::prerequisite_errors_are_closed_nonretryable_hints_not_generic_failures
saved_command_owner::tool_acquisition::tests::unqualified_prepare_census_is_not_a_resumable_missing_prerequisite
saved_command_owner::android_catalog::frozen_row_data_tests::missing_catalogue_hint_needs_pristine_state_or_actual_positive_originals
```

One extended existing unsupported-target negative (unrun):

```text
saved_command_owner::android_catalog::tests::catalog_unknown_and_earlier_failure_retain_the_original_slot_without_a_build_session
```

Native missing-only acquire/Register/reuse and cancellation/drift qualification
still use the existing installed tool observer. This UI correction is not that
qualification and does not change its availability.
