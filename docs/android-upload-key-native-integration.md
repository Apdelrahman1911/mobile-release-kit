# Android upload-key native/helper handoff

This is the native producer half of the approved generation slice. It is **not
enabled or native-qualified** by these source changes or synthetic tests.
Credentials owns the companion vault parent, durable reservation, authenticated
New save/readback, `record_saved`, assignment and UI. Root composes the shared
hooks and runs compilation/native qualification.

## Original ownership and admission

- `saved_command_upload_key.rs` is a child of the existing `SavedCommandOwner`,
  not another process supervisor. `GenerateUploadKey` uses the original driver,
  manager, watchdog, child and pipe joins. Its M2 observations and one moved SH
  close tail use the existing `saved_command_android_leased` settlement path.
- `prepare_upload_key` retains the actual tool-catalogue loan, returned saved
  observation, registered root and native context. Existing random operation
  and owner-generation IDs are used unchanged; AssetSlot numbers are not IDs.
- The parent-only prepared admission exception is
  `UploadKeyPreparation::admission_current(&SavedCommandOwner, now)`: exact owner
  and Prepared allocation, full context/root, current saved/tool originals,
  positive expiry, healthy registry and **no Active operation**. `current()` is
  not a busy-gate exception.
- `UploadKeySavedInput` retains the SAME returned `SavedObservationLane` and
  native context Arcs. Capture/recheck uses the existing borrowed Edit stamp,
  registration/root and input epoch under the original Document gate. A
  replacement lane with equal bytes is not the original. Worker `current()` is
  only a finite atomic/epoch veto, not another Document reader.
- `start_upload_key` returns the actual `UploadKeyRun` and original release
  sender. Credentials retains the Run before releasing it. Its actual
  `UploadKeyGoGate` retains the durable generation reservation and original
  vault Work, saved context, key, store and preparation. The private writer
  calls this fixed gate once; reservation-current IO is outside Document and
  native Registry locks. The gate rematches the same Document/saved stamp and
  complete census before returning the non-Clone, once-consumed GO token.
- One admitted tuple is used throughout: T, T+180s work, T+190s hard. Vault New,
  full readback and journal publication spend its remaining work, not a fresh
  ten-second operation. Generation-only hooks forward genuine first failure
  before the old native clamp. The same M2 ControlData supplies its min original
  cleanup cutoff; an absent native first-F stays absent. The parent records
  native provenance and does not echo inverse-mapped time as a new local STOP.
  Optional parent Work/Progress updates are try-lock-only; STOP/clock latching
  has no callback into a native owner or IO.

## Fixed producer/private handoff

Only the protected, fully inspected original JDK `bin/keytool` is used. The
fixed commands are `-genkeypair -noprompt` (JKS, alias `upload`, RSA3072,
SHA256withRSA, validity10000, fixed public DN), then `-exportcert` to DER stdout.
Both use separate `-storepass:env` and `-keypass:env` names. JVM limits, home,
scratch, capture bounds and arguments are fixed. No shell, build, arbitrary
flags, imported key, ambient password or parent environment modification exists.

The helper reuses `run_owned` C/A/W ownership and checks the sole fixed
`release/mobile-release.json` before READY and before/after both commands:
actual full root, held no-follow file, raw hash/length, parsed canonical saved
draft and enabled Android application-identity digest. No build is executed.
Independent original file/directory closes must all actually return settled.

The app exclusively creates a0700 scratch directory and a held0600 JKS inode.
Before keytool it writes an authenticated standard empty JKSv2 using the
specified password UTF-16BE / `Mighty Aphrodite` SHA-1 integrity recipe. Only
that original inode may change. Replaced output or foreign entries refuse and
are retained; cleanup uses the finite original inventory, not recursive delete.

JKS/password bytes never pass through a public JSON decoder, String, status or
event. The original stdout reader branches to a dedicated private binary
reader. Its96KiB zeroizing backing is retained before the first read/GO, with
64KiB JKS and16KiB DER limits plus a bounded private overrun-drain region.
Malformed, partial, oversized or trailing output cannot become public frames.
Only fixed accepted/terminal metadata is reduced by the existing owner.

`GeneratedUploadCandidate` is non-Clone/non-Serde and stays in that same
Session. `UploadKeyRun::wait_candidate` requires original native/driver/manager/
watchdog/IO/tail settlement, not a process exit or terminal frame. It exposes
only fixed `seal_new`, full authenticated-readback comparison and public
certificate digest after that readback. Sealing binds the actual vault key,
reserved record and newly sealed random revision; it is once-only.

`dispose_private(UploadKeyDisposal)` accepts only Credentials' actual
post-publication/record_saved/all-join proof. The proof is retained before
consumption, and private backing/GO/fields are actually cleared before
`private_disposed` becomes true. Run Drop or producer settlement is not private
disposal. Unknown outcomes retain the originals and cannot replay generation.

## Memory partitions

- Fixed private/control quote: `upload_key_document_backing_bytes`; preparation
  adds its actual retained saved/context/root strings and original references.
- `preparation.tools().census()` visits the SAME existing catalogue and picker
  originals through `execute_owner_census`, not selected-path DATA.
- Existing installed-inspector **128MiB CONTROL_LIMIT** remains reserved while
  native graphs can grow. Generation alone uses the existing bounded typed M2
  parser at16MiB and the same policy validator. Its pre-inspection quote counts
  actual row sizes, temporary trees/sets/native frames and existing query/cache
  reservations. Runtime inspection starts only after pricing the held M2 graph
  plus the existing runtime tree/parser planner. No new pool or relaxed cap.
- Quiescent inspected/spawned graphs publish an actual atomic charge. Zero,
  in-progress, failed, missing or over-limit measurements are unavailable, not
  empty. After native settlement, the same returned observation graph supplies
  the charge. A Document census never waits for a native book performing IO.
- Credentials keeps the128MiB reservation separate from vault credit and uses
  the existing `installed_control_fits(total,1)` partition check before native
  start. READY/pre-New require the actual Run + catalogue/picker/Document census
  against the unchanged vault64/96MiB limits.

## Mandatory Root composition

`android-upload-key-root-hooks.patch` was produced against current integration
source (HEAD12616a1a plus its current shared changes), not blindly against this
worktree's older2c492e47 base. Apply/rebase its22 exact source targets; preserve
adjacent lanes. The patch installs:

1. Same SavedCommandOwner domain, clocks, private I/O branch, native resources,
   original-failure/cutoff forwarding and final joined candidate publication.
2. Existing catalogue loan and M2 observation/tail delegation; generation-only
   tool/runtime inspection accounting and original held-keytool binding.
3. Closed native preparation role5 and query role4, exact180/190 clock, only
   ReadIntent1/Finish2. Objective-C's exact whitelist adds preparation **5 only**;
   it does not change the unrelated preexisting LocalStoreExecute4 issue.
4. Installed runtime profile/bootstrap and current preparation/staging roster
   (no historical-roster change), fixed Python saved-input/process dispatch.
5. Saved-observation child and protocol declaration; inert legacy fixtures
   explicitly refuse generation instead of being reclassified as native tests.

Credentials' companion patch supplies Bridge/Document lifetime, original vault
clock/admission, reciprocal busy gates, complete census, gate/proof reexports,
actual New/None readback/journal and retirement. Neither packet alone is an
enabled route. The existing native qualification gate must remain false until
Root's actual supported-Mac checks pass.

## Verification and remaining limits

Actual focused synthetic command (from this worktree):

```sh
PYTHONPATH=src:tests/unit python3 -B -m unittest -q test_desktop_upload_key
```

22 tests pass. They use only synthetic protocol/container bytes and disposable
local fixture files: exact commands/env, private framing bounds, JKS integrity,
wrong password/alias/extra entry refusal, original EXCL inode and foreign-entry
preservation, saved raw/canonical/app equality, links/replacement/post-read drift
and original-close uncertainty. They do **not** run the helper process or JDK.

12 new inline Rust tests are authored but **unrun**: five protocol/peak/charge
checks, four prepared-identity/expiry/active/clock checks, two retained private
backing/digest checks and one same-bytes replacement-lane check. The Root patch
adds one pure native query-role test and extends the existing preparation-role
roundtrip table. Rustfmt/AST checks are syntax only, not compilation.

Root still must compile the combined graph and run its affected tests. Actual
Mac qualification must verify the nominated JDK writes the authenticated empty
JKS **in place**; inode replacement refuses, never weakens custody. Generation
and certificate export are not a jarsigner usability test, trusted certificate
assessment, Play upload-key replacement, assignment, backup or Store readiness.
No real key, native process, Store action, install or remote operation was run
by this lane.
