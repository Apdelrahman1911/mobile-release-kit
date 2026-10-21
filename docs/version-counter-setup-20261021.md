# First shared version counter — source packet

This adds **Create a first shared counter** beside the existing shared-counter
enrollment panel. It uses the existing publication controller, seven commands,
Connection, worker, native state service and publication journal. It does not add
an allocator, credential, transport, permission, workflow or native test mode.

## User path and limits

1. Read the project's saved inputs and connect the selected GitHub account and
   repository. The source must be an existing remote branch/commit, not the fixed
   counter branch. An empty repository must have its source committed/pushed first.
2. Explicitly choose counter setup and request a review. The review binds the
   current saved configuration/version, actual account/repository IDs, native
   project binding, one native ledger UUID and the canonical empty ledger.
3. Separately confirm first-time creation and invoke Create once. The same
   retained review, original source and consent govern all three writes.
4. A positive result means **counter observed**, not protected, enrolled,
   reserved or Store-ready. Configure supported classic branch protection manually
   (enforce administrators; prohibit force pushes and deletions), then explicitly
   use the existing enrollment Review/Connect actions. Enrollment freshly checks
   both the exact ledger and supported protection.

The initial version is saved DATA, **not a verified Store floor**. Unsupported
manual version names refuse rather than normalize or reset to zero. An already
published app must reconcile its Store history/floors before reserving versions.
Creation requires the selected token's actual repository Contents read/write;
reading classic protection may separately require Administration:read. No scope
escalation or admin mutation is performed. Creating a ref may trigger repository
automation. Cancellation does not undo GitHub objects or the ref.

Any existing counter ref, known local authority or previous counter-create
journal record blocks new creation. The complete existing 64-record journal is
checked by immutable repository ID and original native project binding, not just
the current marker, account or display alias. Missing remote history does not
clear a prior record. A fresh computer cannot prove that a privileged actor never
deleted an earlier orphan counter; the first-time review discloses this limit.
There is no global-history claim, reset, deletion, retry or alternate branch.

## Original custody and fixed operations

- Optional `purpose: "version-counter"` selects a closed publication facet.
  Omitting it preserves the existing five-file setup-PR request. Counter
  target/review/summary/result types are separate; a ledger is never represented
  as a five-file review or a protection receipt.
- SavedInputBinding supplies the actual returned saved-input observation. Native
  root/registration, saved stamp, input epoch and configuration/version bytes must
  remain current. Genesis project ID comes from the actual NativeStateLease,
  never a renderer field or nonexistent configuration property.
- The read-only state child uses the existing VersionAllocations namespace,
  Snapshot/parser, Host and NativeUse. It retains the entire returned original
  before the 256 KiB / 4096-node / depth-20 parser, including oversized refusals.
  No fake protected Authority, state write or enrollment is created. Publish
  obtains a new original read and matches the reviewed raw bytes, revision and
  native binding before GO.
- Host/load/recheck/retire jobs belong to the same admitted publication Owner.
  READY-to-GO prerequisites consume its original clock. Three fixed job slots are
  retained before entry; failed or lost jobs/leases do not become settled by Drop.
  A review/result is usable only after this original's actual driver/watchdog,
  native jobs and NativeUse retirement. Doc-lock callbacks do not perform IO.
- Prepare uses at most 8 GETs. Create uses exactly the fixed 20-call maximum:
  initial user/repo/source-ref/source-commit/counter-absence (5); tree POST plus
  root/release/blob readback (4); root-commit POST/readback (2); source/absence
  checks (2); create-only ref POST (1); ref/commit readback (2); final
  user/repo/source/ref checks (4). Each of the three POSTs requires its own
  durable claim in the original journal. Results are recorded only after phase
  readback. The tree contains only the fixed canonical ledger, the commit has no
  parents, and the ref is exactly `refs/heads/mrk-version-allocations`.
- Reconcile uses at most 12 GETs of the original known identities; it never
  searches for unacknowledged objects or resumes a send. Lost ACK, STOP, source
  drift, journal failure and consuming-close failure retain original uncertainty.

The original 24-request / 60-second work / 2-second first-F cleanup, 4 MiB HTTP
aggregate, 384 KiB review, 512 KiB reply and 8 MiB retained-publication limits are
unchanged. The native facet charges a 6 MiB quote inside that partition, including
full possible Store originals, parser/copies and retained jobs, plus actual held
source/target/prior-proof capacities; the complete Document census still applies.

**Explicit approved source-reader amendment:** ordinary callers retain 128
cumulative opens. The counter purpose derives `128 + 65 * (2 + d)` from the
internally held configuration depth, `1 <= d <= 32` (maximum 2338). Every original
alias/edge check still runs; there is no cached proof or skipped census. The 40
live-FD, 4096 aggregate-entry, 4 MiB read, 64-checkpoint, deadline and close limits
are unchanged. The regression retains the actual old-cap 13/20 failure and
checks all 20 calls with the scoped allowance. This supersedes only the original
plan's assumption that 128 cumulative opens sufficed.

## Packet and integration

Author worktree base: `dbb77ef69ada612979204b2deea56f41ef2f40d2`.
The twenty detached before-images match Root
`5e2352ad9e9b04f38cc79fefa57a8d20ace602d2`; current App/Store composition and package
test entries are preserved. No Root source/index was edited.

New production leaves:

- `src/mobile_release/version_counter_setup.py`
- `desktop/src-tauri/src/version_counter_setup_protocol.rs`
- `desktop/src-tauri/src/version_counter_setup_state_native.rs`
- `desktop/src-tauri/src/asset_session_version_counter_setup.rs`
- `desktop/src/versionCounterSetup.ts`
- `desktop/src/components/VersionCounterSetup.tsx`

New tests: `tests/unit/test_version_counter_setup.py`,
`tests/unit/test_version_counter_setup_publication.py`, and
`desktop/tests/version-counter-setup.test.mjs`. Together with this guide and
`version-counter-setup-hooks-20261021.patch`, these are the eleven owned paths.

The hook patch changes only the twenty paths in
`.task-version-counter/hooks/targets.txt`; full originals/successors are retained
in `hooks/before` and `hooks/after`. All new Rust modules are children of roots
already present in both library and explicit installed observer crates. The
transport-only installed CLI gets no new native dependency. The existing bounded
Python runtime source roster already includes new `mobile_release` leaves.
No build/supplier/workflow/capability hook is needed.

## Authored checks (not native/provider qualification)

- **45 unique Python PASS:** 12 new pure policy, 8 new actual publication/source
  runtime tests with inert HTTP/storage ports and task-owned files, and 25 affected
  existing publication/transport/source tests. No nonroot journal fixture was run
  as root and no existing test was weakened. Latest logs:
  `python-policy-v3.log`, `python-runtime-v5.log`, `python-affected-v1.log`.
- **22 unique Node PASS:** 12 new actual shared-controller/strict DTO/bridge/UI
  tests and 10 unchanged publication-controller tests. `node-counter-v2.log`
  retains a test-only object-versus-bytes assertion failure; only that assertion
  was corrected to match the actual structuredClone bridge and its one test
  rerun (`node-bridge-correction.log`). The other 21 passes were reused.
- **Whole frontend TypeScript 5.9.3 noEmit PASS**, exit 0, 20.046 seconds, using
  existing dependencies, a bounded networkless public-source projection and
  768 MiB V8. Source pins are `typescript-sources.json`; the caller joined and its
  projection/link were removed. The later disjoint App/package current-context
  union was source-inspected, not a second TypeScript run.
- Three new Rust leaves and nine modified Rust parents parsed with Rust 1.98
  rustfmt; **no Cargo compile or Rust test execution**. Six new DATA tests
  (protocol/state, no native calls) are listed in `rust-selectors.txt`. Modified
  existing publication fixture expectations also remain unexecuted.

Evidence is in `.task-version-counter/results`; earlier failed fixtures, the
real cumulative-open exhaustion and initial missing-public-JSON test preparation
failure remain recorded. No provider/authentication, native filesystem/service,
installed observer, real repository write, protection, enrollment or CI execution
was performed. Those original integration/qualification steps remain required.
No availability flag was enabled. Distinct actual source review is separate.
