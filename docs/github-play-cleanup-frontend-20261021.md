# Previous Google Play draft cleanup — frontend

This packet adds the **Clean up a previous Google Play draft** panel to the
existing GitHub page. The native Connection/Setup owner selects the genuine
retained candidate; the renderer never supplies a target, edit ID, encrypted
capsule, credential or workflow input. Backend integration and qualification
remain separate prerequisites. No native or provider operation was run here.

## Original requests and approval

- Explicit **Review previous Google Play draft** invokes Prepare. A terminal
  event cannot grant approval before that original invocation returns. The
  returned review must still match the same API, selected ProjectSession,
  Connection/account/repository and epoch. Dirty, stale, recovering or busy
  source states remain blocked.
- The unchecked approval separately permits **Request draft cleanup** or
  **Allow this cleanup once in CLI**. Both recheck the captured source, native
  revisions, peer gates, approval and original expiry after synchronous view
  callbacks and immediately before invocation. Neither is an automatic action.
- Allow retains its original Promise. Its native return is the snapshot copied
  under the same Doc lock at permission installation. A newer CLI Dispatch event
  may arrive first; the older Allow reply cannot restore consumed permission.
  Only the joined original Allow exposes the native project/service/consent IDs
  for the fixed CLI command. The app cannot also Start a delegated review.
- Native countdown DATA can change without a revision bump. At the same revision
  every other field must still match exactly, and the view retains the minimum
  remaining time actually observed. A delayed Allow or Status reply cannot renew
  permission. The original native expiry and all unknown-state rules are intact.
- Status, Cancel, Discard and subscriptions retain their original calls through
  navigation, disposal, late events and replies. Generic/lost/malformed mutation
  acknowledgements remain absorbing unknown. A later Status may recover only
  the exact original Stop or consent-withdrawal address, not approval or success.
  Explicit successful withdrawal does not clear a lost Allow or its unknown.
- Only source-confirmed pre-admission command rejection codes release an
  unadmitted Prepare/Pending/Observe/Start attempt; they never remint its review.
  This exception never applies to Allow, event reasons, synchronous throws or
  missing Promises. Known refused Close requires an explicit subsequent Check;
  it is not silently repeated.

GitHub acknowledgement means **acknowledged-unconfirmed**, not deletion or a
workflow run ID. Later journal observations remain separate DATA, even when a
row disappears. History is explicitly read and each Observe click retains its
exact returned row/context across callbacks. No replay, claim reset, release
permission or automatic retry is added. The branch-change and irreversible-send
warnings remain visible next to approval; technical review details are folded.

## Integration

Own source: `githubPlayCleanupProtocol.ts`, `githubPlayCleanupController.ts`,
`components/GitHubPlayCleanup.tsx`, `tests/github-play-cleanup.test.mjs`.
`github-play-cleanup-frontend-hooks-20261021.patch` contains only:

1. App original-controller lifecycle, reciprocal peer gates and mounted panel.
2. The existing native bridge factory and closed event literal.
3. Optional `DesktopApi.githubPlayCleanup` port.
4. One `GitHubTaskSection.id` literal for the existing page slot.
5. The literal test entry in the existing package command.

The hook parents match integration `e1c15300`; its frontend bytes are unchanged
from tested `609606c1`. No shared source was edited in either worktree.

Matching backend source is Service's `service-android-build` worktree:
`github_play_cleanup_protocol.rs`, `service_play_cleanup_protocol.rs`,
`github_play_cleanup_session.rs` and `asset_session_github_play_cleanup.rs`.
The eight matching closed cleanup routes are Status, Prepare, Start, Pending,
Observe, Allow agent, Discard and Cancel; event `github-play-cleanup-status`.
Status requires nullable `agentAccess`, paired only with the same delegated
consent. The backend owner confirmed both the Doc-locked Allow response and the
pre-admission rejection cut. Native source is still separately under authoring
and review; this UI cannot make it qualified or available.

## Verification

All tests are complete TypeScript modules, actual composed bridge/reducer and
inert deferred ports, never network, native services, Google Play or DOM tests.

- **27 unique new cases passed cumulatively**: the original 24 comprise an
  initial run of 23 passed/1 failed solely because
  a strict fixture assertion compared the safe parser's null-prototype object
  with a plain object. The assertion now compares copied DATA; the exact one
  affected case then passed, including its remaining withdrawal assertions.
  No production parser relaxation. Both logs are retained.
- Distinct review found the native same-revision countdown contract. Two new
  controller regressions reproduced healthy Check/event and delayed Allow replies
  becoming unknown under the old equality check. The narrow minimum-retention
  fix passes all **three** focused cases, including valid-shaped contradictory
  identity, enabled, expiry and availability DATA plus absorbing unknown.
  Original 24 cases were not broadly rerun; before/after evidence is retained.
- Whole composed frontend `tsc --noEmit --pretty false`: **exit 0**. The first
  check found only the omitted event and page-slot type literals; both exact
  literals were added to the detached hooks, then the full check passed. The
  full composed check also passed after the countdown correction.
- The existing shared dependencies were reused with a private temporary symlink,
  768 MiB Node heap and 120-second enclosing command. All original callers
  returned. The disposable source projection is removed after verification;
  source, hook before/after copies and concise success/failure logs remain in
  `.task-play-cleanup-ui`.

Commands used `/opt/node/current/bin/node`, `NODE_DISABLE_COMPILE_CACHE=1`:
`--experimental-strip-types --test --test-isolation=none --test-concurrency=1
tests/github-play-cleanup.test.mjs`, then the exact failed test-name filter;
`node_modules/typescript/bin/tsc --noEmit --pretty false`.

No Rust build, native integration, installed application, workflow dispatch,
real credential, provider or cleanup-success claim is made by this packet.
