# Required release and review notes

**Phase A portable SOURCE only. Not integrated, executed, qualified or delivered.**
The existing public metadata editor and native owner files are unchanged.

## What this preparation adds

* A closed five-choice notes model: exact saved-build/default Play notes per
  saved Android locale; fixed iOS beta review, App Review and TestFlight notes.
* One pure note-policy helper reused by the future editor and saved-note API.
  Play policy still comes from `validate_android_release_note`; Apple preflight
  comes from `check_metadata_text`. Exact/fallback selection is presence-based.
* A pure config/version-derived one-target selection. It is DATA, not authority.
  No file reads, native capability, writer, credential or Store access is added.
* Separate direct private Load/Prepare DTOs and a **content/digest-free** routine
  status contract. Native/core must construct this projection before emission.
* A transient selected-form controller, strict response checks, field-specific
  beginner help, and a React form using existing application presentation pieces.
* Focused pure policy/contract/form-state regression SOURCE, not execution proof.

The controller emits typed intents to the application layer, not terminal or
filesystem commands. It owns no worker, subprocess, timer, FD, Store session or
cleanup capability. `snapshot`/its local UI subscription contain the explicitly
selected editor's private content; they are NOT native routine events and must
never be routed to generic logs/history/telemetry/evidence.

## Existing Store semantics kept

Android: 500 raw Unicode characters including whitespace, bounded UTF-8 <=2000
bytes; no trimming/newline rewriting. Any exact file's presence prevents default
fallback, including an invalid exact file. An observed error/nonregular path may
never be converted into `None`/absence. The saved version source determines the
exact build. Only original source captures may later authorize a write.

Apple review notes: current core has no per-field character limit; `null` means
that, not unlimited Store acceptance. The local editor cap is 32 KiB. These files
are ordinary repository text, not a vault for review contact/demo credentials.
Those separate credential inputs are not completed by this feature.

TestFlight: current generic preflight character policy plus the Fastfile's
64 KiB original-byte bound, nonempty Ruby-strip view, <=4000 stripped characters.
Ruby strips ASCII NUL/tab/line whitespace/space, not Python's full Unicode
whitespace set. Outbound Pilot sanitization remains in Fastlane. Raw bytes still
bind intent; the editor never saves sanitized output automatically.

## Phase B is still REQUIRED, not optional follow-up

1. Bind these selections inside the existing original metadata-text owner and
   transaction; keep public text's two fixed dependencies and payload limits
   unchanged. Only a sealed notes descriptor may hold additional read-only
   version and exact/default-counterpart dependencies. Recheck them on Apply;
   never rebind a target after a version change. Root reviews that shared seam.
2. Implement registered, selected-window direct observation/Prepare transport,
   original owner dispatch and strict Rust protocol types, without private text
   or digests in routine status/events/lastTerminal/history. The Python routine
   constructor is not evidence that an unimplemented native publisher uses it.
3. Add the closed API method/help registrations and have saved-note validation
   call `check_required_note`. Its public report must emit only fixed issue/state
   information, never note bytes, hashes, counts or outbound summaries.
4. Connect the form with selected-project/saved-locale choices and real shared
   owner availability/finality. Reconcile a refused/unknown Prepare against its
   ORIGINAL native operation; the form never invents a session/cleanup proof.
   Invalidate its context when configuration/service/project observations change.
   Preserve the already implemented all-public-locales check and draft caches.
5. Implement the genuine native .txt picker/read contract on supported platforms:
   one bounded regular UTF-8 source, original identity/change/cleanup checks,
   immediate shared-policy validation, no original modification. The form only
   renders Select text file when this genuine capability is available. A typed
   import fixture or callback is NOT proof of an implemented picker.
6. Native private response publication, stale-version/source races, transaction
   failure/rollback/cleanup integration and picker behavior still need actual
   source-bound Linux/Windows/macOS verification and independent acceptance.
   The pure tests here cannot substitute for those checks.

Save is unavailable until both the direct original prepared view and matching
content-free owner status have been accepted; it is one-use. Final success needs
normal core outcome and native finality, not a button response. A completed Save
requires a new actual Load before another edit; routine events cannot manufacture
a new private content baseline. A changed draft/context cannot reuse a preview.
No live Store mutation or public release is needed to verify this feature.
