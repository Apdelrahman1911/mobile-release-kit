# Apple retained-memory census (A+B+C, piece B)

This is the bounded census change approved by Root and independently
PLAN-reviewed by Credentials. It does not qualify Apple execution or alter
the journal, credential limits, clocks, consent, cleanup or Store provider.
Root composes this with Service's report backing (A) and Git's shared IPC pool
(C); **B alone is not a claim that every Apple mode fits.**

## Actual ownership and arithmetic

`SavedCommandOwner::apple_retained_census` takes only the SAME Registry's TRY
lock. It never invokes `inner.lock`, reconcile, status, expiry or publication.
It retains at most two distinct `Arc<Input>` roots: the prior exclusive review
and current Prepared/Session Intent. The five consumed-review fields alias
that prior input. Existing `retire_review` clears all five slots before its
exclusive result, and `invalidate_review` clears all. Extra distinct roots,
malformed overlap, disabled/unknown or failed locks refuse, never count zero.
Expiry or a project change does not discard retained bytes from this census.

An active Session without `current` temporarily refuses another admission.
With `Some(current)`, the original profile/key parent must match that exact
Asset through its existing clock and original Arc, and the SAME Input must
retain that Asset on the correct side. KeyRecover uses the actual key parent,
not a hand-maintained mode exception. Registry and Input snapshot guards are
released before the existing Source/vault traversal. This adds no restriction
to read/status/cancel/retirement: those paths do not call this census.

The existing `lookup_memory::Census` now visits these roots before ordinary
Document records. Its SAME bounded `Seen` sets account SelectedStoreMaterial,
NativeContext/draft, P8/supplemental payloads, profile/key Sources, selected P12,
inventory, vault key/Store, original Asset SourceBook/retirement, and Ready.
Identical Ready/material/payload allocations are counted once; a distinct old
Ready or material wrapper is still counted. The current Asset path borrows
the caller's original SourceBook and Retirement instead of re-locking them.
Other retained Assets still require the old positive quiescence checks.

Selected-P12 census uses a separate lossless `Result<Option<Arc<_>>, Reason>`
getter. A failed TRY lock is not absent P12. Its ordinary producer getter and
retirement behavior are unchanged. `supplemental_frame_bytes` remains charged
only at the original NEW-operation admission, not as old retained payload.

Both occurrences of the guessed `6 * 1024 * 1024` are replaced with the named
`memory::CONTROL_BYTES`: actual fixed snapshot/guard/Arc cells, const-checked
at <=32KiB. The active expression still subtracts the same retained expression,
so **future F is unchanged**. The old review's actual graph is now in D;
there is no active six-MiB fallback or absent-material zero shortcut.
The existing Input128KiB, Store, recovery, eight STATE_LIMIT, two ROWS*ROW_LIMIT,
eleven ROW_LIMIT, private/wire/runtime and 64MiB/96MiB bounds remain intact.

## Delivery

Six new Rust leaves (only the first two contain shipping code):

- `desktop/src-tauri/src/saved_command_apple_memory.rs`
- `desktop/src-tauri/src/asset_session/lookup_memory/apple_memory.rs`
- `desktop/src-tauri/src/saved_command_apple_memory_tests.rs`
- `desktop/src-tauri/src/asset_session/lookup_memory/apple_memory_tests.rs`
- `desktop/src-tauri/src/asset_session_apple_memory_fixture.rs`
- `desktop/src-tauri/src/asset_session_apple_material_memory_fixture.rs`

Root applies `docs/apple-retained-memory-hooks-20261021.patch` once. Its 14
targets are: `asset_session.rs`, `asset_session_apple_provisioning.rs`,
`asset_session_apple_provisioning_saved.rs`, `asset_session_store_material.rs`,
`application_state_store.rs`, `application_service_upload_key.rs`,
`credential_apple_p12_source.rs`, `saved_command_apple_provisioning.rs`,
`saved_command_apple_signing.rs`, `saved_command_apple_key.rs`, and the existing
four profile/key/certificate/P12 `saved_command_apple_*_review.rs` files.
No shared tracked source was edited in this lane.

Captured before/after files are in `.task-apple-retained-memory/{before,after}`.
Base9a93 lane is preserved; shared images include Root024c KeyRecovery.
The patch apply-check passed on Rootf6b8. Two full before images have later
Root changes (`asset_session.rs`, `saved_command_apple_key_review.rs`); apply
the additive patch, **not wholesale after-file replacement**. This preserves
KeyRecovery/VersionPrepare and allows the disjoint C census hunk to compose.

## Focused proof and limits

Eleven new Rust tests are listed with exact selectors/cfg in
`.task-apple-retained-memory/selectors.json`. All are **UNRUN** here.

- Same Registry empty, contention, poison and revision nonmutation.
- Prepared/current plus prior consumed review are two exact Arc roots; the
  registry can be re-locked while the returned snapshot remains held.
- Actual parent attachment matches only the same Asset, including KeyRecover;
  foreign Asset/no-current/mismatched Input refuse without STOP or poison.
- Third distinct root refuses and the fixed quote keeps the old buffers.
- Real max-sized retained P8/P12/context allocations survive current-selection
  replacement; an additional actual overbound allocation is refused.
- Ready/payload/context identity dedup and distinct-wrapper extra charge.
- Live/pending callbacks traverse with the original SourceBook/Retirement
  guards held; a contended vault refuses; original unreturned review refuses.
- Input and selected-P12 real None versus contention/poison are distinct.

The cfg(test) constructors are inert original-object fixtures, not grants:
the saved lane stays RESERVED; StateDirectory has no file/FD; Input.current
and Ready.begin_use explicitly refuse. Parent attachment never sends GO,
creates a process or writes a returned/settled receipt. No test constructor
is compiled into production. Tests do not generate or inspect real credentials.

Author verification: six owned rustfmt checks and 14 shared rustfmt parse-only
checks passed; whitespace and current-Root patch checks passed. Records are
under `.task-apple-retained-memory/evidence`. No Cargo, native, provider, CLI,
FS fixture, process custody or full-fit result is claimed. Root must run the
combined A+B+C graph, all five previously failed contracts and these changed
memory paths on the actual macOS layout. Existing historical/actual-fit and
overbound test assertions were not removed or weakened.
