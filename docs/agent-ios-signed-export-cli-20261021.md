# One approved iOS signed export through the installed CLI

This is the signed-export variant of the existing Desktop-bound iOS archive
permission, not a headless signer, another executor, or a new signing service.
Root reviewed this plan; the common Build permission/return/READ correction is
owned separately by Credentials. Source acceptance and actual native
qualification remain separate.

## User path and limits

1. In the original Desktop, select the registered project and read its current
   saved configuration/version. Select **Signed export**, without **Keep
   candidate**. Assign the existing Apple Distribution P12/password, profile,
   and any required Firebase/read-token inputs in the existing Asset session.
2. Refresh the iOS agent permission. Separately acknowledge the displayed
   signing, account/Keychain/profile, project-code, and cleanup effects, then
   Allow. This sends the genuine MAIN consent
   `agent-saved-ios-signed-export-v1` plus the exact returned
   `expectedPermissionRevision`. Ordinary GUI v2 consent is not synthesized.
3. Use the unchanged `ios-archive-prepare PROJECT_ID OBSERVATION_REVISION`
   command, review the returned exact mode/saved pair/team/fingerprint, then
   issue its existing, separate IDs-only `ios-archive-start` once. The same
   `ios-archive-status` and `ios-archive-cancel` retain that original request.
   Lost acknowledgements do not authorize another attempt.

Only `ios-unsigned-archive` and `ios-signed-export` are supported here.
Candidate creation, signing-input checks, recovery, credential values, paths,
commands, tool selection, and mode overrides cannot enter these four CLI
verbs. Recovery remains the existing separate Desktop route. There is no
Store upload, release approval, candidate provenance, or artifact digest in
this result. The signed result exposes only the already-validated original
IPA byte count and pairing counts; the normal Desktop retains its original
native operation and STOP controls.

## Original authority and lifecycle

* `asset_session_agent_ios_archive` still uses the real MAIN Document,
  registered root, saved-reader binding, and Edit stamp. Both Doc cuts compare
  the user-captured permission revision; only successful Inbox/Doc install
  advances it. Revoke advances even before the first Allow and still attempts
  the original STOP at counter exhaustion.
* The new `ios_signing::agent::Pin` contains only exact weak native-context and
  payload pins plus bounded record keys. It neither retains credential bodies
  per history row nor creates an Asset context. Currentness requires the same
  assigned records, context, platform, root/registration and payload Arcs.
* The original `IOSSigningMaterial` is freshly borrowed from those existing
  assignments at genuine Prepare. It is retained by the SAME Saved
  Prepared/Session and rechecked at Start; this does not reopen material by
  filename or turn renderer policy into a loan. The native adapter admits
  exactly export, never the broader native `signed()` union.
* The original Saved owner, account lease, private input framing and native
  5400/5520/5530 clocks remain unchanged. The common signed-only READ control
  retains the SAME service `Grant.reserve_read`, rematches it off Doc before
  admission, and samples its earliest revoke/expiry in the existing Saved
  watchdog/STOP path, even after Start consumption or renderer/relay loss.
* The common Build32 pool still has one lease. Real Prepare/Start caller
  return, native retirement and the same history ACK precede usable Prepared,
  known final and released occupancy. Unknown is absorbing and immediately
  visible; neither a complete core terminal nor public IDs prove native joins.

## Closed representation and memory

`agent_ios_signed_export.rs` is DATA-only, so the installed transport CLI does
not import the native signing owner. Old unsigned objects omit the new optional
fields; explicit null is rejected. Signed Review requires its exact mode and
bounded team/fingerprint/optional-input booleans. A signed report is legal only
for its original signed Review and native export scope.

The added weak binding counts vector/string capacities and the inline
NativeContext/Payload Arc allocations that Weak retains after strong values
drop. Approval counts the retained compact policy, one overlapping context
policy, and its public summary. Their checked sum must fit the common named
2 KiB per-binding reservation **before** grant publication. The existing
Build 32-row/16 KiB row, 64 KiB ancillary, 8 KiB status and 688128-byte fixed
backing limits are not raised. Credentials' shared quote names the simultaneous
Android/iOS binding slots; actual compiled layout assertions are still pending.

## Source ownership and composition

New owned leaves:

* `desktop/src-tauri/src/agent_ios_signed_export.rs`
* `desktop/src-tauri/src/saved_command_agent_ios_signed_export.rs`
* `desktop/src-tauri/src/asset_session_agent_ios_signing.rs`

The detached hook patch is `agent-ios-signed-export-cli-hooks-20261021.patch`.
It changes only the existing iOS native/protocol/CLI adapters and their tests,
the existing permission wrapper/panel, and its one App prop. No new command,
pool, Doc field, watchdog, native capability flag, or package test framework is
introduced. Existing test scripts already include both iOS Node files.

Required common dependency is Credentials' `android-signed-cli` A+B+READ
packet: `MainAccess`/canonical full-u64 revision helpers; BuildPermission's
retained actual returned revision; signed-only `NativeScope.read` and
`build_point_with_read`/`matches_read`; original caller/history publication
barrier; signed ancillary accounting. The sibling iOS recovery packet is a
later additive integration, not an optional-config relaxation in these saved
build types. Root owns all shared-file union.

## Verification and remaining work

Author evidence is retained under `.task-ios-signed-cli/evidence`:

* **21 distinct Node cases passed**: existing+new permission12, and nine
  selected signed/raw/current-controller cases. Real controllers and fixed
  APIs were used with inert promises/DATA; no native or provider was called.
* First controller run had one new assertion mismatch solely because the
  safe copier intentionally returns null-prototype objects. The existing
  `clone` helper corrected that assertion; only that one case was rerun and
  passed. Original failure and all source pins are retained.
* Both callers ran nonroot/networkless with a clean environment, bounded
  standard Node runner and no dependency install. Original callers joined;
  exact public projections and empty HOME/TMP were removed.
* **Composed whole TypeScript noEmit passed** on actual Root
  `164567583e4a05876983bb7b0b825e33dc1924f0` including its working LocalChecks
  correction, these six frontend hooks, and Credentials' six frontend hooks
  plus two new helpers. Actual caller 62378 returned zero; the exact public
  379-file projection, own dependency link and empty HOME/TMP were removed.
  Shared dependencies and all eight Credentials source pins were unchanged.
* Rust syntax parsing passed for the three new leaves and nine Rust hook
  after-images. This is not Rust type checking or test execution.
* `.task-ios-signed-cli/rust-selectors.json` records 21 focused new/affected
  Rust cases, including ten new tests. They are **UNRUN**. Twenty use pure or
  deliberately unqualified native DATA; one reuses the existing real private
  StateStore fixture and original Service writer, without a native build.

Root will compile the real library and installed CLI together. Actual signed export,
Mac/Xcode qualification, account custody and cleanup need the original native
journey with valid externally supplied Apple Distribution material; none is
established by these tests. No key/certificate/account was created or probed.
