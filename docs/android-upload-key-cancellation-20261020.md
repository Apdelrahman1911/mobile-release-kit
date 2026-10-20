# Android upload-key cancellation: cleanup, not generation success

Source packet based on `ce47c609`. The two new children and the companion
six-file hook patch are one implementation. Root applies the shared hooks;
this lane has not edited their production parents.

## Fixed scope

The successful `Published`/`UploadKeyDisposal` path is unchanged. A separate,
non-Clone cleanup disposition can release private memory for **the same original
explicitly UserCancelled operation** in only these cases:

1. **Known no private GO:** the original outer request was sent and closed, the
   retained private writer never claimed or sent GO, and the real binary reader
   observed READY followed by the exact empty Cancelled terminal and EOF. The
   original native preparation, parent, reservation, and clock must still match.
   Missing writer/READY/terminal, partial GO, failed native startup/acquisition,
   or unknown cleanup cannot use this case.
2. **Authenticated durable NEW:** the original successful producer remains held;
   its JKS and every private field were compared against the real authenticated
   NEW readback. The full vault/record/revision and physical read witness, public
   certificate hash, and known-applied/confirmed/known outcome are retained by an
   `AuthenticatedNew` captured only at that actual check. A descriptor, counter,
   expected fingerprint, or successful write alone is insufficient.

Both cases require the existing producer/observer/driver/manager/M2/SH-close
originals, the original Asset source/control/child/coordinator joins, and the
same StoreBook's actual release. A returned current cleanup cannot rehabilitate
an earlier failed original join. Nothing creates a candidate, publishes a
successful generation, assigns a key, or clears existing Unknown.

## Actual ordering and hook sites

`saved_command_upload_key_cancellation.rs` is a child of the existing private
binary receiver. Its `NoGoCloseDisposition` explains only an intentional refusal
of the private frame. It is retained before, and rechecked at, both existing
native-settlement gates:

- `saved_command_owner::native_consumers_returned`;
- `saved_command_owner::observe_final`, before the original SH close.

Their other startup, process wait, pipe close/EOF, accepted terminal, task-join,
and native-finality checks remain. The exception is GenerateUploadKey-only.
The actual private-writer error site forwards an already retained same-parent
UserCancelled cause/time if that exact writer remains unclaimed; otherwise it
keeps the existing CommandIncomplete failure. No existing native first cause is
overwritten, no Document/Store IO runs under the native Registry, and no new
producer or clock is introduced.

`credential_upload_key_cancellation.rs` owns the parent half:

- A **report-only** pending-cleanup predicate prevents the old unconditional
  failed-generation-to-Unknown projection for the two proven cases. It does not
  grant retirement or clear a prior Unknown. Before any Asset store child, a
  noGO original may have the genuine New/no-handle child receipt; after Release
  is claimed, and for durable NEW, an actual Returned receipt is required.
- After the same coordinator's actual Release child, off Document/Work/native
  locks, preparation checks the original NativeUse and reads the durable journal.
  It accepts only the exact retained reservation or the exact already-acknowledged
  RecordSaved revision/full reference. It never writes, resets, retries, or
  adopts a journal. Failed/lost checks are retained and re-reported as Unknown.
- Only all-joined parent retirement moves the same Holding and a one-use
  `UploadKeyCancellationDisposal` into the existing charged Retirement. The native
  Session retains and consumes that proof before clearing its own private
  receiver, writer and candidate. No raw material or general disposal callback
  crosses this boundary.
- The separate `retire_use_cancelled` claims the same NativeUse retirement once,
  calls its actual Store owner, retains a successful returned-token fact, and
  rechecks the original cleanup cutoff **after** the potentially blocking return.
  Only then may actual private Holding disposal retire the clock. A late/unknown
  result keeps remaining custody and cannot retry or become successful.

The immutable original 180/190-second tuple and minimum original first-F/cleanup
endpoint are preserved. Cancellation uses the existing cleanup window, not a
new work interval. First reason, failed clock, and stopped status remain recorded
even after known cleanup; `completed` means no original deadline obligation
remains, not that a key was successfully published.

Shared patch targets, and only their narrow associated hooks:

1. `asset_session.rs`: private proof reexport.
2. `asset_session_vault.rs`: report predicate; post-Release preparation on the
   original coordinator/cleanup continuation; separate cancelled retirement.
3. `credential_upload_key.rs`: child/state fields, actual authenticated-readback
   capture, and separate private-disposal dispatch.
4. `saved_command_owner.rs`: private proof reexport, fixed writer-cause forwarding,
   and the two original pre-close checks above.
5. `saved_command_upload_key.rs`: child reexports and retained cancellation state.
6. `saved_command_upload_key_private.rs`: child declaration.

New retained state is inline in the already size-counted Work/Holding/Progress/
native Session, with only references to already charged original allocations.
No alternate allocation owner or private-data-empty shortcut is added.

## What the user can recover

Cancelling does **not** delete or replace a signing key.

- Known noGO leaves the durable reservation. There is no key to reuse, and the
  current wizard must not generate another key automatically. **Explicit
  abandon/resume of that reservation is still missing.**
- Durable NEW leaves the encrypted record and its reservation or acknowledged
  RecordSaved entry. The existing reopen/Load/Assess path can inspect a saved
  record; this cleanup does not grant Bind or repair the setup journal.
  **Explicit reconciliation of an interrupted generation intent is still
  missing.** A second Create, reassignment, or backup is not implied.
- Cancellation before the retained READY/private-writer boundary, after partial
  GO, before full authenticated NEW readback, or with any unknown original is
  outside these cleanup dispositions. Existing recovery/unknown retention is
  preserved rather than pretending a key was never created.

## Evidence and remaining verification

This packet's tests are inert original-clock/reference/receipt and private-binary
predicate tests. They never create a key, launch a process, open a native vault,
or manufacture successful native joins. Rustfmt parsing and patch applicability
are source checks, **not** compilation or execution. The new Rust tests remain
unrun until Root's actual combined graph batch.

Root should filter the two new test prefixes in that real graph:

- `asset_session::vault::assignment_native::upload_key::cancellation::tests::`
- `saved_command_owner::upload_key::private::cancellation::tests::`

The prior positive installed roundtrip fixture is separately source-reviewed.
Its two STOP probes remain diagnostic-only until their observation expectations
are separately amended and this production fix is verified. No guaranteed-green
STOP run or normal-cancellation qualification is claimed here.

Actual Mac verification still needs Root's current retained signed runtime and
package route, genuine protected JDK/catalogue selection, original saved-project
input, and the isolated existing installed-vault/Host fixture roots. Do not use
ambient keytool or activate the historical Aqua supplier matrix. No new harness,
AX/UI selectors, real user credential/account operation, or shipping availability
change is part of this patch. `NATIVE_UPLOAD_KEY_QUALIFIED` stays false.
