# Initial Identity proposal permission: original Check revision

This is the bounded implementation of independently accepted plan
`60c88c178d7306e15d51a7db4fff6306e583131ec2ee720079bdd47356b167e2`.
It fixes an initial Allow arriving after a completed Revoke, including before
the first service link. It does not grant or perform an app-ID edit.

## Original ordering, not another permission owner

Only MAIN `agent_identity_status {}` gains canonical decimal
`permissionRevision`, read with its existing status under the same Document
guard. Initial MAIN Allow requires that exact `expectedPermissionRevision`.
It consumes the existing counter under the first Doc guard, before startup,
project or off-Doc service admission, then checks the consumed successor at
the original final Doc cut. Failed admission never restores the old revision.
MAX-1/MAX cannot admit Allow; Revoke still runs its original STOP, including
at saturation or without a service. Ordinary Review context is non-consuming.

The other GUI replies remain the original three-field DATA. CLI wire, seven
commands/ACLs, existing Inbox32, 15-minute lease, exact-change action approval,
EditOwner, source checks, history and native finality are unchanged. Shell
already serializes the returned MAIN value; no shell or CLI hook is needed.

App keeps its existing normal/revoke Promise slots. A genuinely returned,
current Check enables an unchecked acknowledgement of that exact immutable
witness. Later Check (even equal revision), Allow, Revoke, Decline and context
invalidation clear it. The new pure leaf only matches/acknowledges/consumes
that DATA; it cannot invoke, subscribe, allocate an execution owner or retry.
App retains the original API before publication and checks project, service,
API, context epoch and peers again before invoke. Revoke targets the retained
permission original first, otherwise the pending original/fallback: a Check
on a replacement service cannot steal the old permission's STOP target.
Lost/malformed Allow or failed Revoke stays uncertain until the original
Revoke is confirmed and the retained normal caller returns. No automatic
query, rearm, revoke or edit is added.

No new native counter, pool or Doc field is introduced. The Check wrapper
serializes a u64 without a retained String. Existing 4KiB request and 64KiB
GUI parser limits stay; parsing does not copy the entire status graph twice.
The one small witness and its ACK share references, not cloned proposals.

## Integration packet

The one new production leaf is `desktop/src/agentIdentityPermission.ts`.
Apply `docs/identity-permission-revision-hooks-20261021.patch` centrally to
these five existing paths, preserving later independent integration hunks:

1. `desktop/src-tauri/src/asset_session_agent_identity.rs`
2. `desktop/src/projectIdentityNative.ts`
3. `desktop/src/App.tsx`
4. `desktop/tests/agent-identity-requests.test.mjs`
5. `desktop/tests/catalog.test.mjs`

The fifth hook is Root-approved fixture maintenance: pass revision `"0"`,
then collect only the ten explicitly emitted commands' exact ACL grants,
asserting all ten are present and unique. Later IdentityAction/upload-key
recovery grants remain untouched; the global ACL checks remain unchanged.
The new MAIN request/reply contract must be integrated with both callers;
there is deliberately no missing-revision compatibility fallback.

Exact before/after and owned pins are in
`.task-identity-permission/frozen.json`; the approved plan and original
images are retained there. No shared working source was edited by the author.

## Evidence and limits

- Existing identity Node file: **12 PASS**, 171.661251ms, caller `c5c0b0`
  returned 0. Includes four new strict Check/witness tests and original
  deferred API/identity controller behavior.
- Only the named ten-command catalogue case: **1 PASS**, 447.447163ms,
  caller `519372` returned 0; no unrelated catalogue cases run.
- Both ran in the existing nonroot/networkless route, clean environment,
  Node heap limit 384MiB and 120s bound. Exact public projection394 files and
  11 source directories were verified unchanged and retired after both
  callers joined; HOME/TMP were empty. Logs/exits/cleanup are under
  `.task-identity-permission/evidence/`.
- Rust syntax-only parsing passed. Seven selected native-module tests
  (four new, three existing) are listed with source pin in
  `.task-identity-permission/rust-selectors.json`: **UNRUN**. They exercise
  DATA and actual refused dormant Document calls, not a successful invented
  window, Host, grant, active EditOwner or native settlement.
- Exact current Root five-before match, forward apply-check and strict
  source whitespace checks passed. Root owns distinct actual review and
  the next combined noEmit/native compilation.

No author whole-TypeScript check, Rust compilation/test execution, React
mount, installed CLI/native journey or provider operation is claimed.
