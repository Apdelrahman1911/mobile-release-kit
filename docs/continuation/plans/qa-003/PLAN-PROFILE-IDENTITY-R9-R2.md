# QA-003 R9 revision 2 — bind profile observations to the files used and removed

## Finding, scope and reanalysis

PROPOSED REVISION 2; no runtime implementation is authorized until independent
plan approval. Supersedes the initial R9 plan, retained unchanged. Addresses
independent plan review R9-PR-01/-02 in plan-review-profile-r9/PLAN-REVIEW-R1.md.
This is a correction of the undelivered QA-003 implementation, not a waived
limitation or another delivered finding. Original QA-003/FINDING.md requires
preserving other tasks' profiles. Independent R8 review found QA003-IR8-01:
owned cleanup discards the relationship between the observed bytes and inode.
The original finding, R8 fatal-lifetime plans, both complete owners, every
`_profile_snapshot` / `_read_regular_at` caller, profile events, recovery,
CLI, signing materialization, crash fixtures and documented limits were reread.

Baseline HEAD/main2beb37336fa8002b69f598fe431082606368310d, version0.3.0,
branchfix/qa-003-local-signing-lease. Runtime still equals R8 proposed tree
f8f489a20ad852c8e649ea9e2eee09f8679f179a. Since that snapshot, one previously
required compound-content regression was added:20 failure methods now PASS in
development (5.046s). The prior689-test full pass applies to the OLD test tree,
not future R9 acceptance. User AGENTS/index are unchanged; no QA-003 commit.

### Confirmed behavior and actual production boundaries

- `local_signing.py:779–796`: after the real ownership stat, a profile is moved
  aside and replaced with a different inode containing the same bytes. The real
  `_profile_snapshot` RETURNS that foreign identity, but cleanup checks only
  SHA256, unlinks the foreign file, clears the original session and CLI returns
  exit0/recovered. Applies to owned destination AND reserved stage.
- If the file disappears at the same boundary, `_profile_snapshot` returns None;
  indexing it raises uncaught TypeError through actual CLI recovery. Remaining
  controls survive; no deletion/success occurs. Missing owned files are already
  supported elsewhere as safely absent, so this is not an unsupported scenario.
- `credentials.py:1005–1023`: normal full Apple signing teardown repeats the
  original-stat/bytes-only-read pattern. An actual foreign same-byte file is
  read and deleted; the composing owner returns normally/idle. This is reachable
  outside recovery. Its raw reader discards the observed stat entirely.
- `credentials.py:1060–1072,1113–1121`: initial-existing and real link-EEXIST paths
  read authenticated bytes from inodeA, then independently stat and record inodeB
  alongside A's authenticated hash. A modeled replacement at actual read-close
  admits the signing body with DIFFERENT unvalidated on-disk bytes. Full outer
  cleanup later detects the conflict and fails; no successful Store release or
  bypass of final artifact validation is claimed.
- Safe controls at the initial-stat→open boundary: borrowed recovery preserves
  disappearance/replacement as a conflict; full borrowed cleanup detects it via
  the outer owner; ordinary installer absence safely cleans. These controls do
  NOT prove terminal post-close handling. Preserve these safe specific paths.
- R9-PR-01: actual terminal borrowed recovery reads original inodeA, closes it,
  then observes replacementB in the subsequent owned-loop stat but ignores that
  observation because no deletion identity exists. CLI returns0/recovered and
  discards controls instead of reporting conflict; B itself survives.
- R9-PR-02: same-inode chmod after the initial owned stat and before actual read
  is not seen by internal before/after read comparisons. Current recovery deletes
  the changed file and reports success. The caller must also compare its initial
  stat with the actual snapshot, not just compare inode/hash.
- Root independently replayed all3 new boundary/control cases byte-identically
  in reanalysis-profile-r9-r2/ (ROOT-REPRODUCTION.json). The stable-hardlink control
  shows that our own link/unlink changes ctime/nlink: compare fresh observations
  WITHIN each operation, never saved pre-link or pre-own-unlink metadata. Native
  commands are fictional; real files/read-close/CLI/journals execute. No scratch
  or worker remains. These are negative evidence, not product passes.

Independent evidence: `implementation-review-r8/owned-profile-race-probe.py`,
`owned-profile-race-negative-baseline/RESULT.json`,
`profile-identity-siblings-probe.py`, `profile-identity-siblings/RESULT.json`.
Root replayed the byte-identical nine-case sibling probe in NEW
`reanalysis-profile-r9/` (exit0 means negative cases reproduced, NOT product PASS).
Real files, inodes, hardlinks, descriptors, journals, CLI and owning contexts run;
only native/CMS seams are fictional. Original inodes were moved, not recycled.
All exact owned scratch was removed after observations. No Store, real keychain,
credential or background process was used. The reviewer tool failed while
finishing its prose report; its earlier findings/results remain evidence, NOT
an implementation approval. Root has read and replayed the results independently.

Root cause: content validation and deletion/reuse authority come from different
observations. Equal bytes are not ownership; an old pathname stat does not bind
the subsequently opened file. Newly observed missing/foreign state is ignored.

## A. Keep coherent bounded file snapshots

Change only `local_signing.py` and `credentials.py` runtime code unless review
establishes another directly affected consumer.

- Add a small internal stat-comparison helper in local_signing, reused by
  credentials (which already imports local_signing). Compare device, inode,
  regular-file mode, link count, UID/GID, size, mtime_ns and ctime_ns. Exclude atime:
  our own read may change it. No new dependency, native command or public API.
- `_read_regular` keeps its current `(bytes, stat_result) | None` contract and
  bounds, but validates all coherent stat fields before/after the descriptor read
  AND at the no-follow pathname observation, not just pathname device/inode.
  Its optional-absence catch remains inside the body, outside cleanup/restoration.
- `_read_regular_at` returns `(bytes, stat_result)` rather than bytes alone. It is
  private and has exactly one runtime caller, the installer's snapshot wrapper.
  Prove bounded regular-file content, stable descriptor state and no-follow
  pathname agreement before returning. Preserve its exact descriptor ownership,
  independent finally-close and direct typed fatal error behavior. No additional
  cancellation owner is inserted into this raw-reader boundary.
- Keep persisted profile evidence exactly `{identity, sha256}`. Local metadata
  comparisons are ephemeral; do not add stat timestamps or new fields to intent,
  state, completed markers, release schemas or authenticated Store evidence.

## B. Installer admission and cleanup consume the SAME observation

Retain the existing read-local `snapshot_failed` rule and direct ProcessError
classification. A real fatal snapshot still stops reads/mutations/resolution;
an ordinary error inherited from a contained predispatch body does not falsely
poison an otherwise safe cleanup. All independent raw closes still run once.

1. Initial-existing path: compare captured bytes to authenticated content and
   recheck the current no-follow pathname against the captured stat. Only then
   record the borrowed identity FROM THAT SNAPSHOT, not from a new independent
   stat. A changed/missing pathname fails setup before signing admission and
   never registers the replacement as authenticated borrowed state.
2. Real EEXIST path: similarly bind matching content, observed inode and current
   pathname before recording reused/linked state. Determine whether the link is
   original-owned from snapshot identity, not an unrelated later stat. Preserve
   the original writer/stage identity. Do not adopt a same-byte foreign inode as
   owned, or an unvalidated replacement as borrowed.
3. After existing setup/stage-removal and before yield, take one bounded final
   destination snapshot. Require authenticated bytes and the already recorded
   owned/borrowed identity; recheck current stat against that snapshot. This also
   rejects observed replacements during successful-link/stage-removal setup.
   Do not silently reselect a new identity. No new persisted phase is required.
4. Borrowed cleanup keeps the initial identity short-circuit (do not open a known
   foreign/special replacement). If read, compare its returned identity AND bytes
   to the recorded borrowed observation, then recheck current stat. Any mismatch
   is a preserved cleanup conflict, never resolved success.
5. Owned destination cleanup requires original ownership stat, returned snapshot
   identity, authenticated bytes and final no-follow stat agreement before unlink.
   Compare the full initial ownership stat with the read snapshot too: a changed
   mode/nlink/UID/GID/size/time between stat and read is a preserved conflict even
   when the read itself is coherent and the inode/hash still match. Use fresh
   metadata for this operation, never metadata saved before our own link/unlink.
   Missing destination retains the current safe-absence behavior. Changed content,
   type, metadata or identity is preserved and reports cleanup failure. Never
   allow equal bytes alone to authorize deletion of the observed foreign inode.
6. Stage cleanup retains its separate original-writer-inode authority and partial
   write cleanup semantics; it does not require a successful full-content write
   to clean an owned partial stage. Never overwrite or adopt an unknown stage.
   Check related stage and post-link transitions for observations that would
   contradict the pinned identity; preserve existing no-clobber link behavior.
   Compare fresh stage pathname observations around its conditional unlink,
   without rejecting legitimate partial writes based on an earlier writer stat.

Use fixed sanitized errors. Preserve original exception/fatal aggregation,
handler restoration and registered independent cleanup. Do not change R8's
safe contained-predispatch vs dispatched/uncontained quarantine distinction.

## C. Recovery validates both observed ownership and bytes

In `SigningSession.cleanup_profile`, ALL profile roles consume the full bounded
`_read_regular` `(bytes, stat)` observation (or a helper retaining it), not only
an evidence projection. Retain original persisted authority and handle these
caller boundaries explicitly:

- Borrowed recovery, INCLUDING `terminal=True`, first rejects missing/known
  foreign/special files without opening them. If read, compare bytes/hash and
  returned inode with the original borrowed authority, compare its full initial
  pathname stat with the read stat, and AFTER raw close compare the full returned
  stat with a new no-follow pathname observation. Any mismatch/absence/error is
  a preserved conflict (except a fatal lifetime error, which remains fatal).
- Do not leave a later ignored observation of a borrowed destination in the
  owned-resource loop. Reorder/reuse observations so that the last destination
  observation, including terminal recovery, is validated as borrowed when no
  owned identity exists. No successful recovery JSON after a contradiction has
  actually been observed. Original preexisting `info["before"]` can coexist with
  a later installer-owned replacement: still report lost preexisting state while
  removing ONLY the independently proven owned file. Do not skip that case.
- Keep regular/terminal borrowed disappearance a conflict, not safe-owned absence.
  Terminal cleanup must not erase original journal authority when a fatal reader
  failure occurs. Safe foreign conflicts may clear it with CLI1 as before.

For each original-owned stage and destination:
- Compare full INITIAL ownership stat with the returned snapshot stat, as well
  as original recorded inode identity. Metadata changed in this interval must
  not be ignored merely because the actual read saw a stable file. An in-place
  metadata change is a controlled preserved error, not unlink authority. Never
  compare stale metadata across our own hardlink/stage-removal operations; obtain
  fresh before/read/after state for each stage and then destination separately.

- A None/missing result is safely absent, just like the initial missing stat.
  No TypeError, invented identity, forced upload/build, or unnecessary manual
  edit of original controls. Missing stage and destination are both supported.
- A snapshot identity differing from original ownership is a conflict BEFORE
  hash comparison or mutation, even if all bytes match. Preserve it. A foreign
  destination may complete recovery as `recovered-with-conflict`/CLI1; an unknown
  reserved stage keeps original pending authority and requires existing manual
  owner reconciliation. Do not remove controls that still guard an unknown stage.
- Original identity with changed bytes or metadata is not deletable in that
  invocation. Preserve it and fail in a controlled CredentialError; ordinary
  filesystem/read errors keep remaining recovery state. A fresh invocation can
  re-observe unchanged original identity/hash after exact owner quiescence.
- Recheck no-follow pathname stat against the full read snapshot immediately
  before unlink. Missing is safe; foreign destination/stage distinctions remain.
  Do not claim an atomic compare-and-unlink API: the per-account toolkit lease
  serializes cooperating users, not hostile/non-cooperating same-UID writes
  after the final check. The correction MUST reject every contradiction actually
  observed; that explicit host limitation is not permission to ignore one.
- Terminal mode still rejects any original-owned resource reappearance and never
  deletes it. Fatal read/close/handler errors still bypass manual retry and any
  terminal finalization in the failed invocation. Preserve finalization when a
  file had already been safely removed before an interruption.

## Tests and regression risks

Add credential-free real-filesystem regression coverage, preferably a new
`tests/unit/test_local_signing_profile_identity.py`, plus minimal existing-test
adjustments for the intentional internal tuple return / extra final snapshot.
No whole-owner mock substitutes for filesystem, journals, cleanup or CLI.

- Actual remove, same-byte different-inode and different-byte replacements
  between original stat and actual snapshot open, during read completion, and
  after read-close/before final pathname validation. Move originals aside so
  different-inode assertions cannot depend on inode recycling. Track actual read
  FD identity and every unlink target identity; assert foreign files/bytes/modes
  survive BEFORE fixture fallback.
- Exercise normal composed signing teardown AND actual CLI recovery, owned
  stage/destination and borrowed roles, automatic/manual entry and terminal
  controls. Verify expected exit/status/no-success JSON, no stray TypeError,
  original intent/checkpoint preservation when pending, and unchanged unrelated
  native preferences. Unknown stages stay pending; destination conflicts remain
  reportable without deleting unrelated state. Reproduce R9-PR-01 with an actual
  completed marker produced by interrupted terminal teardown, swapping at the raw
  close in that LAST borrowed recovery; require CLI1/conflict, never CLI0/recovered.
  Also test borrowed disappearance and same-inode metadata change at that cut.
- Fresh-process recovery against unchanged original remaining controls, no new
  identity/source/version/candidate, correct repeated absent/recovered behavior.
  Where an unknown stage must be moved manually, fixture action must be labelled
  external owner reconciliation, never production force-reset or guessed unlink.
- Initial-existing and actual link-EEXIST admission swaps, same/different bytes,
  plus successful-link/stage-removal swaps. Body/native create/import/build
  sentinels must remain untouched after the rejected admission. Never assert only
  that eventual cleanup fails after dangerous admission already happened.
- Stable original-owned, stable identical borrowed (including hardlinked files),
  ordinary owned disappearance, same-inode chmod between initial owned stat and
  read on BOTH recovery/normal cleanup, post-read chmod, changed content, stable
  hardlink controls and fresh snapshots after our own unlink. Test inode metadata
  comparison fields individually without relying on timestamp clock resolution.
  Retain partial-write stage cleanup and same/different UUID controls. Verify no retries on ambiguous descriptor close, independent
  handles closed and R8 fatal precedence, including the new pre-yield snapshot.
- Keep the20-method R8 regression module and its newly added compound-content
  linked/body controls. Register the new identity module in native PATTERNS and
  assert required source/installed-wheel/CI routing. Test discovery, local-signing
  glob and complete crash-matrix definitions must include it automatically.
- Rerun the original negative probes to NEW corrected-expectation evidence with
  real IO intact. Keep old negative results, runtime hashes and all failures.

Main risks: confusing identical bytes with ownership, false conflict on our own
hardlink/unlink metadata changes, blocking safe partial-stage cleanup, treating
missing files as fresh authority, swallowing fatal cleanup, premature resolved
events, recording a replacement's inode with another file's hash, changing an
implicit snapshot-count test rather than preserving its dangerous boundary, and
stale native/matrix inventory. Extra reads may add crash cuts: enumerate actual
inventory, never assume the old count or lower coverage to keep it fast.

## Compatibility, documentation and verification

No CLI option, journal/release schema, Store API, workflow authorization, signing
identity, Python minimum or package runtime dependency changes. Existing valid
local sessions remain recoverable; stable owned/borrowed setups must still work.
QA-004 outer materialization and QA-005 source guard remain separately open.
This fix cannot mutate unrelated Store state because no Store code is changed
or invoked. It blocks QA-003 delivery/reliable local signing until verified.

Update `docs/local-signing.md`, concise `docs/credentials.md` / troubleshooting
and CHANGELOG where needed: bytes plus observed inode authorize use/removal;
unknown stages vs foreign destinations, safe absence, fail-before-admission,
and explicit remaining non-cooperating host limits. Do not advertise an atomic
filesystem transaction or revise public Store/exact-build guarantees.

1. Independent plan approval BEFORE runtime edits; revise/re-review if needed.
2. Implement approved correction/tests/docs; run focused cases and original
   probes safely. Preserve negative/intermediate evidence; clean exact scratch.
3. A distinct implementation reviewer reads the actual full issue/delta and
   independently exercises ownership/fatal/recovery cases; no old R8 approval
   is adopted (there was none). Bind a new complete proposed tree and reviews.
4. r3 was never frozen/dispatched. After its runtime rejection root verified
   marker and both recorded inodes/modes, then removed only its empty tmp and
   owned parent/marker. `QA-003-final-r3/SUPERSEDED-R9.json` records0gates and
   preserves all preparation bytes. Do not run stale r2 or r3 wrappers. Prepare
   a NEW independently reviewed final namespace only AFTER R9 implementation
   acceptance, with reviewed helper semantics unchanged and a new source freeze.
5. Run ALL58 categories from zero, including complete Python/workflow suite,
   Ruby support/lane/Store contracts, Supply/WIF, Fastlane validation, actionlint,
   Bundler/pins/runtime-dependencies, new installed wheel/resources/bootstrap/
   native checks, every16 source+wheel crash pair and actual full union, JDK21,
   exact owned cleanup, diff and freeze equality. No old pass adoption or bounds
   reduction. Hosted protected PR/main CI remains mandatory after local gates.
6. Preserve the original unexplained EEXIST FAIL, wheel, entire forensic install
   and diagnostics; this identity fix is NOT its established cause. Investigate
   any recurrence, not rerun-until-green. No READY claim from tests alone.
7. Only approved complete verification authorizes one scoped QA-003 commit and
   normal protected PR/merge to main, without bypass. Then QA-004, QA-005,
   MRK-008, MRK-009, fresh entire-repository/all-release-path audit and additional
   confirmed-blocker remediation, conditional READY and the full feature report.
