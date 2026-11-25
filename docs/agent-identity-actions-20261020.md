# Exact CLI identity edits through the original Desktop owner

This packet adds a one-use delegation to an **already opened** CLI identity
proposal. It does not add a headless editor, native availability flag, process,
queue, database, source parser, history writer, or general project-write grant.
The old proposal/read permissions alone still cannot Apply.

## User path and exact interfaces

1. Existing `identity-request` submits the desired ID and target. The existing
   Desktop proposal Review opens that target through `ProjectIdentity` and
   seeds the immutable desired ID into the existing editor; no retyping.
2. Read the actual supported source. For a new identity, explicitly acknowledge
   that it is a different app, not an update. Review the old/new ID and named
   controlling locations, then **Allow this exact change once**. Ordinary local
   preview/Apply remains an alternative until delegation is claimed.
3. Use these fixed commands; `--json` is optional and last:

   ```text
   mrk identity-prepare PROJECT_ID SERVICE_INSTANCE INTENT_ID --json
   mrk identity-status PROJECT_ID SERVICE_INSTANCE INTENT_ID --json
   mrk identity-start PROJECT_ID SERVICE_INSTANCE INTENT_ID SESSION_ID OWNER_GENERATION REVISION PLAN_TOKEN --reviewed --json
   mrk identity-cancel PROJECT_ID SERVICE_INSTANCE INTENT_ID --json
   ```

   Start uses the **returned original** session, generation, revision and plan.
   Prepare cannot change the proposal. Repeated exact requests only inspect the
   same consumed slot; they never send again. The CLI prints the original query
   and Stop correlation before its mutating IPC call. There is no second GUI
   Apply. Status may be pending, refused, unconfirmed, recovery-required or
   settled; a Stop acknowledgement is not completed cleanup.

The three local-main-window RAW commands are `allow_agent_identity_action`,
`agent_identity_action_status` and `revoke_agent_identity_action`. Allow accepts
only `{intentId,sessionId,revision,acknowledgeNewApplication,consentVersion}`;
the other two accept `{intentId}`. The fixed consent version is
`agent-exact-opened-identity-edit-v1`. No caller root, continuity or replacement
ID is accepted. The existing exact Tauri AppManifest/main capability receives
only these three commands. Unknown/unsupported platforms still refuse.

## Native ownership and failure boundaries

- The same existing 32-entry `agent_identity_requests::Inbox` owns at most one
  optional Action per retained Entry. IDs are the original native Session and
  owner generation, never the IPC transport request ID. No tombstone is evicted
  or restored/replayed at launch. An action has exactly one Prepare and Start
  claim; failed/unreturned claimed admission remains consumed.
- Native Allow checks the same registered root/Document/private Link, actual
  opened checkout, exact proposal and explicit new-app acknowledgement. It
  captures original Session identity and registry revision. Host/service/read
  grant comparisons occur **outside Doc/Edit locks**, then the same original
  Document/root/Session/revision/continuity are rechecked before granting.
  Expiry is the minimum of original proposal Review, original Edit review and
  fifteen minutes; no read or new IPC connection renews it.
- The existing shell relay claims the bounded request, rechecks the original
  Host registration and actual current native continuity, then enters private
  facets of the **same** `prepare_domain`/`apply_domain` claims. Both slots are
  consumed before the original command send. Ordinary GUI endpoints cannot
  consume a delegated claim. They retain their old behavior without delegation.
- Exact-action Revoke has an Entry-local first-cancel latch, including before
  Allow returns. It does not revoke a shared proposal lease or cancel a later
  intent. Original Link identity selects the native Stop target. The original
  STOP watch and expiry evaluator preserve the earlier cancellation/cleanup
  endpoint; no new timer or finality owner is introduced.
- Native changed/retirement hooks publish bounded DATA using the already
  reviewed identity-history mapper. Only original `observe_final`, after its
  actual joins, permits settled status. Core terminal frames, Close, lost Weak
  links and command acknowledgements cannot manufacture settlement. Unknown,
  effect/journal uncertainty and recovery remain distinct. History still uses
  its original off-lock publisher and may be absent; query it separately.
- The saved observation is intentionally invalidated by the original Open.
  This does not turn a stale cache into source authority: Prepare/Apply retain
  the original native checkout and existing transactional currentness checks.
  Source/target drift, unsupported layouts and published-identity vetoes still
  refuse. Namespace/package refactoring and version-reservation recycling stay
  excluded. Recovery remains the original descriptor-bound Desktop route.
- The frontend retains the original API methods and every original Allow,
  status and Revoke Promise. Revoke may overlap pending Allow. Context/ABA/draft
  changes retire consent before handoff; stale replies cannot revive it. A
  passive expected-change binding lets the existing native controller display
  externally initiated Prepare/Apply, but grants no native authority. Actual
  original Apply publication invalidates saved inputs once before its callback;
  that reentrant invalidation must not cancel the just-admitted Apply.

## Root composition

`agent-identity-actions-root-hooks-20261020.patch` is against captured Root
`5169bab4bb14d617e05382cf6a3589491e909de9`, refreshed from the author's
`5dbd047fc8d603b51b7433a7a4576de2665c96e7` base. Apply once, not to the old base.
It touches exactly 16 existing paths: Inbox, identity Link, history mapper
visibility, EditOwner, Document identity child, ApplicationService, service
protocol, installed CLI, shell, build.rs, main capability, and the five existing
frontend files `projectIdentityNative`, `ProjectIdentityEditor`, `App`, `types`,
`bridge`. Current Android-tools/request-discovery routes remain present. All
new Rust modules are children of existing roster modules; no observer/thin-CLI
root declaration is needed. Shared files were not edited in the author's WT.

The existing Document census charges another 3 MiB for the fixed 32 Action
rows plus sixteen bounded public comparison/IPC copies; the whole Inbox quote
is 3,637,248 bytes, below 4 MiB. A public Action status is at most 64 KiB,
65 safe relative locations of at most 512 bytes, 2 MiB coordinate limits,
and closed scalar shapes. This is owned backing, not RSS. Existing 16 MiB
Document admission and separate runtime reservations are not enlarged.

## Focused evidence and remaining work

- Actual source-projection Node run: **38 passed, zero failed/skipped**
  (13 new action tests plus 25 original identity/proposal controller tests).
  Command: `node --experimental-strip-types --test --test-isolation=none
  --test-concurrency=1 desktop/tests/agent-identity-actions.test.mjs
  desktop/tests/project-identity-native.test.mjs
  desktop/tests/agent-identity-requests.test.mjs`. Synthetic DATA/deferred
  Promises only, not native Sessions, files, processes or finality receipts.
- Current Root frontend typegraph plus this packet: `tsc --noEmit` passed.
  Initial projection-only missing JSON imports are retained separately; seven
  existing public resources supplied the corrected projection, no source fix.
- Six new and ten complete projected shared Rust files parse with rustfmt.
  **Twenty new Rust tests are authored but uncompiled/unrun.** Root batch
  selectors: `agent_identity_requests::actions::tests::` (11),
  `edit_owner::agent_identity::actions::tests::` (3),
  `asset_session::agent_identity::actions::tests::` (2),
  `application_service::identity_actions::tests::` (1),
  `installed_cli::identity_actions::tests::` (3). The original bounded CLI
  collector is exercised before child parsing: nine/ten-word Start survives,
  an eleventh argument refuses rather than truncating into an accepted prefix.
  Recheck existing Inbox and
  installed-CLI capability tests after the census/catalog additions.
- No Cargo, native execution, CI, credentials, provider work, downloads or
  availability changes. Root must compile the combined graph/thin CLI and
  verify the actual installed proposal→Allow→Prepare→Start/status/Stop route.
  The existing native identity four-case run does not by itself qualify this
  new CLI delegation. Recovery is not a CLI journal-reset endpoint.
