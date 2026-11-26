# Explicit future-tag version reservations

Implementation packet for the accepted plan `a61ed90a768a3c93775649fd753aa38a1f2b0182fb701255eaf3223821f4b409`.
This is **branch-triggered** version automation with an explicitly selected future
tag, not support for running the version-changing build from an existing tag.
Native/provider behavior is not qualified by this source packet.

## User path and authority

1. In the existing Version Reservation panel, select the genuine branch source B
   and optionally enable a literal future full tag T. The policy matches T, not
   the version-like text inside T. Existing Store observations/floors, native
   review, original source owner, one-use Reserve and separate editor stay intact.
   A reservation is not a created tag or permission to create one.
2. Use the existing explicit editor, commit and push operations to produce F.
   F must have B as its sole parent and exactly the permitted version-file change,
   mode, configuration and reservation trailer. Other edits require a new valid
   reservation workflow, not a relaxed proof or moved tag.
3. The existing hosted Play-cleanup section now also offers **Future version tag**.
   Select the candidate UUID, reservation-row SHA256 and final commit SHA. Review
   displays T, actual reserved version/build, B/F, branch and repository. Explicit
   unchecked consent authorizes only this fixed hosted dispatch. Existing account,
   source, review expiry, original calls, STOP and post-notification checks apply.
4. Alternatively allow that same exact native review for an agent, then use:

   ```text
   mrk version-tag-submit PROJECT_ID SERVICE_INSTANCE CONSENT_ID --reviewed [--json]
   mrk version-tag-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
   mrk version-tag-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
   ```

   CLI takes IDs only, requires current READ plus the separate Desktop grant and
   uses the existing shared dispatch Inbox/NativeLink. It has no headless owner,
   arbitrary workflow/ref/command input, token, or old-cleanup grant fallback.
   The request ID is retained before send. Identical retry discovers the same
   entry; neither lost ACK nor Unknown authorizes another send.
5. GitHub's existing generated candidate caller exposes these fixed operations:

   ```text
   reserve-future-tag:ios:refs/tags/T
   reserve-future-tag:android:temporary-play-edit:refs/tags/T
   reserve-future-tag:both:temporary-play-edit:refs/tags/T
   bind-version-tag:PLATFORM:CANDIDATE_UUID:ROW_SHA256:FINAL_COMMIT_SHA
   ```

   Select the corresponding operation/platform and actual configured branch.
   The bind job requires actual dispatch HEAD F; advanced HEAD, SHA/tag dispatch
   substitution or unrelated legacy/recovery markers refuse. Same protected
   `version_reserve` job and App token, no additional job/Store credentials/Ruby
   setup for binding. The created lightweight tag may trigger other automation
   in the user's repository; review discloses that effect.

Workflow dispatch's empty 204 remains **acknowledged-unconfirmed**, not a run ID,
tag receipt or build. Explicit Pending discovery may omit selection only for
the typed read-only VersionTag listing. Prepare/Dispatch/Observe require the full
selection. Later exact tag/ledger observations are not a replayed creation receipt
and never clear original Unknown. Existing `mrk requests` uses the SAME Cleanup
namespace 6 and 32 rows with typed `version-tag-status` routing, one enumeration.
Current Root's separate Apple namespace 7 and total 320 remain intact.

## Same counter, immutable binding, old compatibility

New requests add a required non-null `futureTag`; actual SourceBinding remains
branch/B and inventory policy remains 2/3/4. Wire/hash generation 5 is separate
from that policy. Ledger v5 has required bounded `tagBindings`; each claim binds
candidate, exact row hash, F/tree, attempt and original hosted run/attempt.
Old v1–v4 canonical bytes and digests are unchanged. No read migration, blanket
schema acceptance, recycling, eviction or lost-old-row upgrade is introduced.

Only actual tagged append upgrades the ledger; subsequent writes preserve the
whole v5 ledger. All allocation/enrollment adapters parse the exact schema-5
envelope, including required `tagBindings`. Genesis/emptyLedgerV1, hosted full
Play record/ciphertext/claim, iOS-only progress and old current-source rules stay
unchanged. Binding writes only the same protected allocation ledger.

Fresh bind first reads and proves full B→F, then CAS-publishes its immutable
claim and reads back the complete returned claim. Before the one create-ref POST
the counter must still equal that exact fully read commit, not merely descend
from it. Final read validates the full preserved ledger prefix and selected
claim. The stable local exclusion key is repository + full authority + candidate;
F/T/row are compared body fields, not a way to mint a second key.

An existing tag, including an annotated tag or T already at F without this
claim, is a fresh-operation collision. Loaded claims are GET-only, even when T
is absent. No force/PATCH/DELETE/reset/adoption/retry, including after lost claim
or POST ACK. Existing privileged-repository-history limitations are not removed.
CI retains branch F, sole-parent/full-delta/trailer/source/provenance checks and
adds exact v5 claim plus two fresh lightweight T→F reads before build admission.

Every collaborator and the pinned reusable-workflow consumer must use compatible
v5 tooling before the first tagged reservation. Older tooling must refuse v5.
The canonical Desktop generator, template and before-image compatibility helper
are updated together: exactly one immediately prior candidate is accepted only
as BEFORE, with existing coordinates/SHA rendering and full-byte CAS. Current
AFTER/Release matching stays strict; user edits and older unknown callers conflict.
No setup/source pin is silently upgraded by reserving or binding a tag.

## Bounds and packaging

- Existing 128 KiB ledger, 64 rows/bindings, 16 KiB Pending and original native
  backing remain. No new Doc owner, native service namespace, transport or grant.
- Same source work clock 60 seconds plus 3 seconds cleanup. **Bind-only 16 Git**:
  actual CA3 + full CI proof10 + pre-POST HEAD1 + final HEAD/tree2. Ordinary
  CI/Reserve retain 12; no restarted clock/counter or omitted CA read.
- **Bind-only 25 HTTP**: repo, protection, counter, ancestry, ledger, run, branch,
  B, F, tag, counter, repo, claim PUT, full claim read, ancestry, branch, tag,
  exact claim counter, sole tag POST, tag, counter, ancestry, full ledger, repo,
  branch. Loaded-claim path is shorter and has no write.
- New reservation adds one absence GET (native 10, hosted iOS38/Android45);
  old ordinary 9/37/44 remain. New CI10 HTTP, old CI8; all old work limits remain.
- Native hosted-dispatch Prepared4 KiB/Initial8 KiB/response192 KiB and existing
  public-work partition remain; same <=120-second consent and READ watchdog.
  Added bounded DATA stays within existing maximum reservations; no final-status
  or message-as-join credit. Local catalogue keeps its existing 32 KiB-only cap.
- New Python modules are included by existing `src` package discovery; there is
  no new runtime dependency. Existing canonical JSON package data and template
  collection apply. Observer fixture constants were recomputed through the actual
  generator: resource `a3ed1b9d5b0df42d0f921e09c0fded2c392568e96ec100628c35e319785d5191`,
  candidate 4079 bytes at `example/toolkit`/`a`×40; other lengths remain
  1479/3079/3816. This corrects comparison DATA, not native qualification.

## Delivery and evidence

Owned worktree base d2be161d; deliver **16 new paths** (14 code/test leaves,
this guide and `future-version-tag-hooks-20261021.patch`). Shared parents are
NOT edited/staged in the worktree. The patch contains **50 targets** with exact
captured before/after copies under `.task-future-tag-hooks`. Final before-images
match current Root76c62c52, preserving Store/Apple/counter setup and other panels.
The frozen manifest records every source, image and evidence hash. Root applies
the accepted patch once; future context conflicts require semantic union.

Retained author evidence, not native/provider claims:

- **107 distinct Python tests passed** using actual allocation/hosted/CI/dispatch
  and canonical generators with existing fake providers/owned test fixtures,
  nonroot/networkless. See `passed-python-selectors.txt` and core/host/ci/dispatch/
  callers logs. 33 are new; old allocation/transport/hosted/CI/enrollment/cleanup
  and four actual canonical/adapter methods provide compatibility coverage.
- **50 Node tests passed** (8 new + 27 Cleanup + 15 Reserve), actual controllers
  with inert ports; `node-v1b`. Corrected whole composed strict TS **PASS** on
  Root1fae plus hooks; `ts-v2`, original caller34956 joined0. Subsequent final
  merges only preserve newer Root context/add CLI metadata and test selection;
  they are not a new full-TS claim.
- Two meaningful new workflow DATA methods individually passed in
  `workflow-v1-diagnostic`. The following redundant new canonical-equality case
  stalled; original bounded calls exited137 and are retained. Its internal cause
  remains unestablished, not a product failure/pass. Root approved removing only
  that redundant method because the four actual Python generator/adapter passes
  cover those bytes/pins. **No successful whole Ruby-suite exit is claimed.**
  Existing affected YAML compatibility hooks remain for Root's bounded batch.
- Initial loader/fixture/HTTP-test mistakes and TS unknown-type diagnostic are
  retained, with corrected affected subsets; no product relaxation was used.
  The genuine schema5 enrollment adapter omission was corrected and its nine
  existing methods passed. The validated Prepared cast fixes only TS narrowing.
- Review corrections: absolute-end UUID/version parsing has two targeted Node
  methods passing; the existing History cleanup Query fixture explicitly retains
  `Purpose::PlayCleanup`. No production History or quota change.
- Final AST19 and Rust22 syntax checks pass, **not Rust compilation/tests**.
  Eleven new Rust methods are listed in `rust-selectors.txt`: ten inert DATA /
  original Inbox checks; one existing real private StateStore fixture with no
  native process/provider. Original affected service tests remain unchanged in
  behavior. Root must run the actual library and installed-CLI module graphs.
- Every test caller joined. Exact task-owned source projections, HOME/TMP and
  node_modules links were retired after inode/hash rematch; useful logs and
  original failures remain. No caches/dependencies/private origins were changed.

Actual installed/native Reserve, hosted workflow, tag creation, CI consumer,
Store access and provider cleanup were **not executed**. No nomination,
availability flag, release readiness or shipping qualification is added.
