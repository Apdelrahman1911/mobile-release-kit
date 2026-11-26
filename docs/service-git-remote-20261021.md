# One delegated Fetch or normal Push on the existing Git service

Source-only handoff, 2026-10-21. This adds a closed Remote facade, not another
native Git owner, account/session, service, relay, journal, command runner or
network credential path. Native availability/nomination remains unchanged.
No real Git, provider, credential, native process, Cargo build or CI run was
performed by this author for this packet.

## User path and scope

The running Desktop must already hold the actual current project, completed
Git **Observe**, selected Connection/account/repository and supported native
runtime. In the existing Git area, the user selects either the existing Fetch
draft or the attached branch's current, nonzero Push target, then checks a
separate unchecked approval and explicitly allows that exact action once.
Opening the panel, reading status, a read grant or a CLI request cannot grant it.

The same read-authorized installed CLI exposes only:

```
mrk git-remote-scope PROJECT_ID [--json]
mrk git-remote-prepare PROJECT_ID SERVICE_INSTANCE GRANT_ID [--json]
mrk git-remote-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID PREPARE_OPERATION_ID REVIEW_ID [--json]
mrk git-remote-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk git-remote-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

Prepare creates its request ID before the existing send and asks the original
native owner for a review; it does not Apply. Start consumes that exact original
review once. Equal-tip Fetch remains Close/cancel-only. A duplicate exact
request discovers the same entry; a lost reply is not a no-send receipt.
`mrk requests` discovers Remote IDs in the **same** Git catalogue namespace.
Status/cancel keep the existing read authorization even after write consent
expires; neither renews consent or any original clock.

Fetch updates only the originally reviewed remote-tracking reference. Push
means the existing normal Push: attached branch, complete cached tracking,
behind=0, ahead=1..64, nonzero unequal old/new SHA1 OIDs, then the original
complete native outgoing-history review. No force, new branch/zero target,
upstream change, arbitrary URL, path, token, command, account choice, headless
window or remote retry is admitted. Service's separately planned new-branch
Push is deliberately outside this facade.

There is no new CLI Activity/reconcile command. The exact known terminal effect
and finite retained diagnostic names are historical DATA, not permission to
open/delete paths, clear a pending fence, or repeat an unknown send. Fresh
Activity remains a separate explicit ordinary Desktop read; it cannot settle
this request. The complete application and installed CLI must be upgraded
together; unsupported response families fail closed without fallback/replay.

## Same-original authority and return cuts

* One `Family::Remote` shares the existing 32 rows, one grant and one active
  intent with Index/Commit/Repository. Old local grants cannot select Fetch or
  Push. The five requests carry IDs only; the Desktop captures the actual
  Observe witness, registered root/Edit stamp and immutable Connection Pins.
* Exactly three MAIN-window RAW commands are added to the existing handler,
  AppManifest and local-main ACL: `agent_git_remote_access`,
  `allow_agent_git_remote`, `revoke_agent_git_remote`. Allow is bounded to 8KiB;
  read/revoke use the existing 1KiB empty decoder. The installed fixture still
  refuses these commands. Consent is `agent-git-fetch-once-v1` or
  `agent-git-push-once-v1`, not local Git consent.
* Allow rematches the actual Observe/root/Edit/account/repository/session at
  both Doc cuts around the existing off-Doc Host/service checks. Actual native
  Prepare/Apply still select and rematch their own Pins and source gates.
  Status revisions cannot replace the retained credential endpoint. The
  existing 15-minute grant and original review maximum of 300 seconds remain;
  each real native operation retains its existing 45/55/first-failure clocks.
* For Remote only, arming the original `NativeLink` reserves one phase on the
  same row. Public Ready/final settlement and corresponding settled history
  wait for **all three** original returns: native receipt, `Claim::returned`,
  and the actual same-ticket Doc `Connection.finish`. This includes failed,
  cancelled, removed/no review and expiry paths. Exact never-armed/no-hold
  refusal retains the previous local behavior.
* Reconcile forms its private candidate while the original hold gate still
  exists, calls the existing Fetch/Push finish, then uses the existing
  `*_prepared_current` checks after hold removal. A returned finish is not
  sufficient if the same Connection became unknown/exhausted. Known expiry
  can suppress Ready without rewriting the actual historical outcome.
  Candidate ID, source, document, registration, account, original caller and
  request phase are compared again; a contradictory effect stays Unknown.
* An armed Apply has its own return tuple. Dropping its consumed Prepare
  review cannot retire the Apply. No ordinary local finality rule changes.
  In the new Remote mapping only, a transport-valid terminal whose validated
  mutation says `failed` is Failed, never Succeeded merely because protocol
  transport completed. Existing recovery-required and Unknown remain sticky.
* The same finite permission controller retains issued Allow/read/revoke
  promises across selection, account, API, epoch and ABA changes. Synchronous
  notifications are rechecked before invocation. Pending or unknown originals
  remain visible; one-way status metadata is not an Apply or cleanup receipt.

## Public shape and bounded retained storage

The public selection is the exact closed Fetch/Push action plus bounded
account ID/login/repository ID/coordinate and a domain-separated comparison
digest. No token, source body or native review capability is returned.
`Status` has required fields `{progress, result}`; `result` must be null unless
it agrees with the original known settled Apply ID/action/outcome. The review
has only its original ID/revisions/digest and a fixed preview. Push's full
commit list stays in the native owner; public count+digest do not claim secret
safety or a full object proof.

The existing document census reserves 24KiB per same Git row for simultaneous
selection/private-public-pending review summaries and terminal effect copies,
plus the existing one-scope backing and same eight IPC reply reservations.
The Doc component additionally names the bounded retained/rematch Connection
Pins and fixed mutation-projection scratch. No uncharged parallel inbox or
32-fold native full-review/path-list copy is added. Responses remain at the
existing 8KiB status bound (including envelope); overflow refuses, never
truncates. CLI whole-capabilities retains its existing 12KiB bound and names
the Remote argument pattern by reference to the same five Repository shapes.
These are application capacity reservations, not a claim about total RSS.

## Exact ownership / composition

New production Rust leaves:

* `service_git_remote_protocol.rs`
* `service_git_remote_requests.rs`
* `service_git_remote_document.rs`
* `service_git_remote_native.rs`
* `service_git_remote_application.rs`
* `installed_cli_git_remote.rs`

Three separate new Rust test children accompany Requests/Application/CLI.
New frontend leaves are `service_git_remote_permission.ts`,
`components/ServiceGitRemoteAccess.tsx` and
`tests/service-git-remote-permission.test.mjs`. Together with this guide and
`service-git-remote-hooks-20261021.patch`, these are the only owned 14 paths.

All existing files are **patch-only**, never modified in the author worktree.
The detached hook covers the existing Family/union/inbox, Doc adapter,
service dispatcher/codec/catalogue, CLI routes/declarations, original
GitLocal reconcile and selected Connection liveness checks, literal RAW/ACL,
and App/bridge/types/package integration. No workflow or qualification change.
Complete parent before/after copies and source/evidence pins are retained in
`.task-git-remote/`; the frozen manifest records the final integration base and
exact 26 hook targets. The original e4d parent copies remain preserved.

## Verification and remaining work

Actual complete-module inert Node batch: **78/78 PASS, 0 skipped**, including
8 new Remote permission tests and 70 existing Index/Commit/Repository,
Fetch/Push controller tests, 968.024725ms. These use actual controllers/codecs
with inert promises only; no filesystem, native, Git, provider or DOM work.
Log: `.task-git-remote/logs/node-affected-v2.log` (exit0).
The earlier new-only eight passed unchanged apart from a later defensive
comparison refusal now included in the final batch.

Whole composed TypeScript: **PASS**, 16.830895s, max child RSS718696KiB,
768MiB V8 cap. This was current e419 source + this hook + complete real JSON
resources + new leaves, using the existing pinned dependencies with a
temporary projection-only link removed after return. Log:
`.task-git-remote/logs/frontend-ts-v3.log` (exit0). Historical unsuccessful
attempts are retained: missing `/usr/bin/time` (no TS execution), then missing
seven repository JSON resources in the first projection (no product error).
No casts, `any`, installs or production weakening were used to obtain PASS.

Rust: nine new leaves plus 21 shared parents passed **syntax-only rustfmt**.
**22 newly authored Rust tests are UNRUN / uncompiled here**. Exact filters:

| Selector | New tests | Effects when Root runs it |
|---|---:|---|
| `service_git_remote_protocol::tests` | 4 | DATA only |
| `service_git_requests::remote_requests::tests` | 8 | Real Inbox/Entry/Claim/Link with inert callback DATA; no native proof |
| `asset_session::agent_git_index::remote::tests` | 2 | DATA-only Observe shape / strict RAW consent |
| `application_service::git_index::remote::tests` | 2 | Existing exclusive temporary State Store/Service fixtures; filesystem IO, no Git/native/network |
| `installed_cli::git_index::remote_tests` | 4 | Actual collector/codec/formatter on inert bytes |
| `github_connection_session::fetch::tests::remote_delegation_current_uses_original_pins_and_never_renews_expiry` | 1 | Existing inert Connection fixture |
| `github_connection_session::push::tests::remote_delegation_current_uses_original_pins_and_never_renews_expiry` | 1 | Existing inert Connection fixture |

The tests distinguish both caller-return orders, failed/cancelled/no-review
paths, expiry/withdrawal, consumed Prepare vs Apply, missing finish/lost ACK,
foreign review and contradictory effect, old local finality, read-only versus
explicit grants, cross-family/project/session refusal and complete CLI bounds.
No test constructs a real native receipt, token hold or source proof. Root
must compile the actual library/installed CLI/shipping/observer graph and run
the selected tests in its existing batch. Genuine installed/native Remote
operation, account/transport/current-source behavior and Mac qualification
remain unexecuted; source/UI tests do not enable them.
