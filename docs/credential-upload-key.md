# Explicit Android upload-key generation: native vault parent

## Status

This is the credentials half of the reviewed generation plan. It is source
implementation, **not a qualified or delivered key-generation feature**.
`NATIVE_UPLOAD_KEY_QUALIFIED` remains false. No native tool, signing key,
certificate, account, provider, network request or private vault was used for
this work. The existing backup slice is unchanged.

The Project lane owns the closed `GenerateUploadKey` facet of the actual
`SavedCommandOwner`, its original protected-tool lease, private binary
transport, scratch/JKS validation, and producer/native/tool-tail joins. This
lane owns the durable reservation, private random scalar fields, actual
`OriginalWork`/vault child, authenticated NEW save/readback, and reference
publication. There is no second supervisor or generic process/result callback.

## Concrete flow

1. The future explicit, confirmed-new-app Desktop command calls
   `DocumentBinding::generate_confirmed_new_upload_key` with the original
   application service, bridge's `upload_key` owner, actual catalogue loan,
   current context revision and native availability. It accepts no renderer
   path, tool command, password, private bytes, fingerprint or generated key.
   Ordinary setup observations use `Continuity::Unknown`; rerunning setup
   cannot assert this confirmation.
2. Reuse-first classification must return `OfferGeneration`. Any existing
   Android key, remembered choice, pending reservation, corrupt/unknown journal,
   changed physical project, or different vault/record prevents generation.
   The same native saved-observation lane and Edit stamp supply configuration
   size/hash, draft hash and app identity. Stable project ID and current native
   runtime alias are not interchangeable.
3. The actual native preparation supplies its original random operation ID.
   The only busy-gate exception is a private, still-Prepared companion belonging
   to this exact bridge owner, root, context, saved lane and expiry. Equal IDs,
   a replacement preparation, Active, STOP, Unknown and other busy owners are
   not exceptions. No saved-lane invalidation/publisher acceptance is invented.
4. The same vault `OriginalWork` retains the preparation, custody and one
   admission/work/hard clock before releasing its original coordinator. The
   durable reference-store reservation is published before private CSPRNG or
   native GO. One OS CSPRNG call supplies two independent 256-bit passwords;
   they remain in the existing zeroizing `Fields`, with the fixed `upload`
   alias. Random failure is refusal, not a retry/fixed-secret fallback.
5. The original native writer calls the one-use `UploadKeyGoGate` off Document
   and native registry locks. It rechecks the actual durable reservation, same
   vault/key/book/context, saved/Edit witness and actual measured native/tool/
   Document census. Only then can the original private writer consume
   `PreparedGenerationGo` and the child-scoped password input. Uncertain sends
   do not create another GO, operation ID or record.
6. The retained `UploadKeyRun` must finish its actual original producer and
   native/tool-tail joins. Only its private candidate can seal through the
   existing vault key. `Child::GenerateUploadKey` borrows the SAME `StoreBook`,
   rechecks the physical exclusion roster, and performs exactly `New` with
   `expected = None`. It remembers **this** mutation outcome immediately after
   `mutate`, before any later failure. Authentication/capture failures cannot
   replay the store's prior mutation outcome.
7. The child reads the complete saved record from the same store, authenticates
   it with the same key, checks exact record/random revision/counter/file length,
   compares every private Field and the complete JKS against the retained native
   candidate, and rechecks root and read witness. Known applied + confirmed
   durability + known cleanup and the actual returned child are required before
   `record_saved`. A public descriptor/process exit/fingerprint is insufficient.
8. The existing post-join publisher rechecks NEW-only context/full reference and
   the actual journal revision, publishes the row **unassigned**, and retains
   only volatile certificate provenance tied to this full `StoredRef`, app
   identity and original key/book. Expected/persisted hashes are constraints,
   never observed signer evidence. Reopen/replacement cannot restore this
   observation. Ordinary assessment and explicit Bind remain separate.
9. Only actual successful publication plus original joins can mint the private
   `UploadKeyDisposal` consumed by the native original. The same off-lock
   Retirement retains/counts everything through concrete private disposal.
   Unknown save/readback/journal/publication/disposal retains originals and
   blocks reuse/empty/exit; no regenerate, overwrite, automatic cleanup retry
   or automatic Bind/backup follows.

## Clock and memory boundaries

- One immutable T/W/H tuple is retained by the actual vault original and native
  original: 180 seconds work, 190 seconds hard finality. Later-delivered earlier
  first-F and native cleanup endpoints only contract it. Existing ordinary
  `Work.fail` keeps its original reason/time and other roles are unchanged.
- `native_cleanup_at(reason, Option<Instant>, Instant)` preserves a real native
  cutoff even when first-F is unknown. It never substitutes status-now for F,
  calls back into native, or echoes inverse-mapped native time as a new local
  STOP. Optional explanatory books use try-locks; clock and STOP latch even
  when those books cannot be borrowed. A genuinely earlier parent failure still
  reaches the same native original once. Cached release endpoints are also
  capped by this generation clock.
- Generic `set_endpoint(None)`, normal transport STOP, status, `record_saved`
  and a publication-shaped marker cannot retire the clock. Endpoint becomes
  absent only after the actual same-original private disposal and all source/
  coordinator/child/native joins; immutable bounds/failure facts remain.
- Pre-inspection admission counts existing Document/catalogue/picker originals
  and concrete constructor backing, and retains the existing separate 128MiB
  installed-code inspector reservation with `installed_control_fits(total, 1)`.
  This does not enlarge or become credit against the 64/96MiB vault caps.
  Project's sequential M2/runtime inspection enforces that same partition.
- READY and pre-NEW use the SAME original's measured native census, not the
  constructor quote; unknown/in-progress measurement refuses GO. Source/GUI/
  keyring/retirement, saved/evidence/maintenance and actual Arc backing remain
  counted. Fixed crypto work is 1MiB, sufficient for the protocol's 64KiB JKS
  plus the unchanged codec's 512KiB control, scalar/descriptor/framing bounds.
  All existing vault limits remain unchanged.

## Root hooks

`credential-upload-key-root-hooks.patch` records the independently reviewed
five-central-file delta. Root has composed it with the current integration,
preserving Git, version-source and Apple hooks as well as the tool picker.
It is a historical integration aid, not a patch to reapply to this checkout.

| Shared file | Narrow addition |
| --- | --- |
| `asset_commands.rs` | private scalar child/reexport |
| `asset_session_vault.rs` | existing Work/Retired/Slot/Child/Job, NEW publisher, generation-only cleanup cap, exact preparation gate, three test-fixture visibilities |
| `asset_session.rs` | original clock, private-empty/disposal/census/child admission, actual bridge lifecycle/busy checks and prepared-only exception |
| `asset_session_installation_memory.rs` | actual retained generation/clock backing in the existing census |
| `bridge.rs` | same `SavedCommandOwner::generate_upload_key` field/constructor and idle checks |

The Project packet supplies `android_upload_key_protocol`, the SavedCommand
owner/private reader/native lease/role/helper changes, and the original
saved-observation child/reexport. Neither packet alone is a complete graph.
The private scalar and upload-parent children need no new top-level lib module.

The native entry still needs the separately reviewed Desktop command/status/
controller/button wiring and real native qualification. Do not infer generation
availability from the existing installed vault or tool capability. Backup has
its own current-original operation and separate qualification; generation
success never means a backup was delivered.

## Focused evidence / limitations

All fifteen new Rust regressions **passed in Root's integrated Linux graph**.
They use synthetic private/scalar/file/receipt DATA only:

- three scalar/real-vault-codec tests: distinct fixed entropy, error/no retry,
  maximum-size synthetic file under the fixed allowance, full Field equality;
- nine parent/provenance/clock tests: original/min/capped clocks, inverse native
  cutoff/no echo/unknown F, cached release contraction, readback vs journal vs
  publication/disposal, marker-only actual retirement, first failure/no retry,
  full random revision/read witness, current key/book, separate inspector cap;
- three tests using the existing actual Bind/retirement fixtures: remembered
  reference survives retirement through the current BoundLoan; equal counter/
  changed random revision/context/duplicate loan refuses; missing assessment or
  unknown/failed original cannot become a durable assignment.

The combined library compiled and all 65 selected Rust checks passed. Two
test-only compilation mistakes were corrected without changing the production
credential logic. Linux no-default checks do not qualify shell-gated methods, original macOS
private process/input/output custody, generated JKS operation, native dialogs,
signing, App Store/Play behavior, or installed Desktop availability.
