# Project identity — original native route

Depends on accepted core `3b76faf84acf52f9e14313c3bc0bac5cf0917bd3` and the
accepted UI `5245cb3d` + `cc41d312`. Root owns central integration and native
qualification. This packet adds only two isolated Rust modules and a proposed
seven-file central patch; it does not modify those central files here.

## Required patch

`PROJECT-IDENTITY-NATIVE-WIRING-2026-10-19.patch` applies against this worktree's
unchanged central sources. Root must preserve adjacent integration changes when
applying it. All hunks are required:

- Register the two crate modules and the Document child.
- Permit only the closed `ProjectIdentity` registered-root domain. Before the
  common publisher accepts/context invalidates, call the original Execute and
  Reconcile `ensure_idle()` under the same Document mutex. This lets an already
  Ready positive original retire and retain its continuity veto. Pending Store
  work/reviews refuse; identity editing must not cancel them to become available.
- Charge `identity_continuity_document_backing_bytes()` **once** in the existing
  global Document census, including when Store owners are idle. Do not separately
  double-charge this reservation in each active Store envelope.
- Install three bridge forwards, five raw commands, their generated permissions,
  and the existing EditOwner revision-driven event relay.
- Close/refuse the new domain in three exhaustive legacy hosted-test matches.
  These branches do not enable any identity development/hosted fixture.

## Five fixed IPC actions

All requests are original UTF-8 JSON bytes (`Uint8Array`), not Tauri parsed JSON.
The bound is 16 KiB. Duplicate keys, extra fields, malformed values, and arbitrary
paths/continuity fail closed. The event is `project-identity-state-changed`.

| Action | Body |
| --- | --- |
| `project_identity_open` | `{intent:'edit', projectId, selection:{platform, target, project}}` or `{intent:'recover', projectId}` |
| `project_identity_prepare` | `{intent:'edit', sessionId, revision, desiredIdentity, identityIntent:'preserve'\|'new-application'}` or `{intent:'recover', sessionId, revision}` |
| `project_identity_apply` | `{intent:'edit'\|'recover', sessionId, revision, planToken}` |
| `project_identity_close` | `{sessionId}` |
| `project_identity_status` | `{}` |

Android's `project` is explicitly `null`; iOS supplies the recognized relative
`.xcodeproj`. Actual saved source/target checks remain in the core. Every reply
is the existing `IdentityStatus` from the same EditOwner; a reply is not finality.

Open obtains an entropy-only ticket outside the Document lock, then binds the
actual native continuity under its registered publisher. Prepare/Apply obtain
the selected platform from retained private native Details and repeat both
typed original Store veto getters against the same registered project/root.
Missing facts mean **Unknown**, never Store absence. Either getter's failure
refuses. New Existing knowledge retires a stale Unknown review and asks for a
fresh read; nothing is automatically reopened or applied. The core's saved
identity status/App Store ID veto remains independent. Recovery checks both
platform vetoes but can only finish/roll back its original verified descriptor;
it is not a new application-identity edit.

Malformed Prepare/Apply retire only the original pre-Apply review. Close uses
the original STOP and stays available during Quit, without a new root lookup.
Unknown/pending/committed-with-cleanup-pending outcomes retain their original
resources, journal and incompatible-plan invalidation requirements.

## Frontend integration contract

The accepted `IdentityNativePort` needs synchronous admission into its original
native controller, retaining that controller's actual promise/busy state. Do
not return `true` from an unowned fire-and-forget bridge call. The adapter strips
UI selection continuity, maps UI `intent` to `identityIntent` at Prepare, and
uses the captured original mode for Apply. Root retires local consent before
project/source/API/draft/selection intents, including no-op/ABA changes. Native
checkout continuity can update the UI context; renderer Unknown cannot grant
permission. Commit/uncertainty invalidates incompatible plans/assignments and
candidate identities, never reservations, build floors, old IDs or history.

## Evidence and remaining qualification

- Earlier accepted slice: 17 focused Python protocol/actual core engine fixture
  tests passed (author 0.617 s, independent reviewer 0.608 s). No Python changes
  in this packet. Core identity's earlier 59 tests remain unchanged.
- This packet adds four pure raw-command tests and two pure veto-combination
  tests. They do not fake original native joins or access a project/provider.
- Author checks: rustfmt syntax parsing of both new modules; patch applicability
  against the exact seven original sources; syntax parsing of patched Rust
  copies. No Cargo, TypeScript, native process, installed Mac, Store or artifact
  qualification is claimed. Root owns the coordinated compile/test batch.
- Useful Root test filters: `project_identity_commands::tests`,
  `asset_session::project_identity::tests`, `project_identity_edit_protocol::tests`,
  `edit_owner::identity_owner_tests`, and
  `saved_command_owner::identity_continuity::tests`. Include development-runtime
  **compilation only** for the legacy exhaustive arms; no hosted fixture run.
- Root still supplies the genuine UI native port, common context/retirement
  wiring, installed runtime packaging/source-hash checks and actual Mac route
  verification. Unsupported platforms never fall back to development/runtime
  Python or another edit profile.
