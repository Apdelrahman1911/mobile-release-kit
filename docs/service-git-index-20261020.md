# Shared CLI Stage / Unstage — source integration

Scope: **Stage or Unstage the exact Desktop-selected paths, once**. This is not
commit, branch, push, credential, signing or general Git/CLI parity. The running
Desktop, its separately enabled project read access, and the original qualified
Git runtime remain required. No native availability flag is changed.

## Actual path

1. Use the existing Desktop Git **Check changes**. The existing GitRead admission
   optionally retains its native root, registration, Document identity, saved-edit
   stamp and input epoch. Only its successful, settled Observe reconciliation can
   retain the comparison witness. A failed/Diff/history/public DTO cannot recreate
   it; optional capture failure does not change ordinary read behavior.
2. Select 1–64 paths and explicitly Allow Stage or Unstage. The three new main-only
   permission commands use the same real Webview/Document checks. Allow rechecks
   the original Observe/root/stamp/epoch and exact changed rows, obtains the SAME
   already-started Host/Service off Doc/Edit, then rematches under Doc/Edit. No
   service/native startup, source probe, directory or persistent namespace is added.
3. `mrk git-index-scope PROJECT --json` displays that exact selection and its
   service instance/grant. `git-index-prepare PROJECT INSTANCE GRANT --json` creates
   a client request ID before transport. One in-memory entry consumes the grant;
   identical retries only observe it, and changed bodies conflict.
4. The SAME retained relay claims the entry and calls the SAME GitLocal Prepare.
   A private original link is armed with the original Supervisor ID under its
   owners lock, before insertion/spawn. The native reader, expected repository
   revision, selected paths and fixed original runtime checks are unchanged.
5. Only native reconciliation after the actual Prepare receipt joins can publish
   a usable review. Status returns its opaque review ID, index/review hashes,
   document/registration revision and native Prepare ID. The CLI never receives
   a native ReadyReview, diff, commit draft, source content or raw journal.
6. `git-index-start PROJECT INSTANCE REQUEST PREPARE_OPERATION REVIEW --json`
   requests the separate Apply. The shared original Apply requires the exact
   request/lease/phase link, original ReadyReview/action/stamp/root/expiry, and its
   own Publisher epoch. GUI None-origin cannot apply that review, while ordinary
   GUI reviews keep their prior behavior. GUI status/STOP/discard remain usable.
   The real Apply ID is separately armed before insertion/spawn. No caller path,
   executable, arbitrary arguments, tool choice or publication receipt is accepted.
7. The existing Preparing/candidate durable ACKs, index publication, original
   provider/source/runtime/IO/driver/watchdog/observer joins, final CAS and NativeUse
   retirement are unchanged. Only the original final receipt updates the entry.
   An armed error/unreturned claim is Unknown, not a negative admission or replay
   invitation. Recovery-required remains occupied even when native jobs are settled.

## Revocation, history and restart

The default-off grant expires after 15 minutes; it is never renewed by Prepare,
query or reconnect. Both native phases keep their original 45/55-second bounds.
Expiry prevents new entry and use of a completed review; it does not install a
new clock on an already armed native phase. Explicit revoke, context loss, quit or
original Cancel uses the first retained STOP time and the SAME owner. Cancellation
or review removal never settles an armed Apply. The native publisher's existing
joined post-epoch exception is preserved, not widened into a currentness waiver.
The relay's advisory watcher checks original Document/root/stamp, link/revoke and
control Unknown before any epoch sample. Its own retained publisher lock,
accept-before-join and finished-before-receipt cuts defer only that sample; they
do not imply external drift, authorize work or settle the operation. Actual
native claims remain strict, and joined/stable epochs must still match exactly.

`git-index-status` and `git-index-cancel` take the exact project, service instance
and client request ID and still require ordinary live authenticated project read
access. Execution-grant expiry is not a read-authentication bypass. GUI Stop does
not need that read grant. Restore read access in the original Desktop to query an
old request; do not create a replacement because an acknowledgement was lost.

The same service history writer uses the client request ID and fixed GitStage or
GitUnstage action. History is DATA, never a native finality receipt. Failure/loss of
its original publication fences service history. The same relay is joined and
drained before Host close. Native originals remain independently authoritative.
Restart restores neither grants, aliases, inbox entries nor native review owners;
old durable Git pending/unknown rows still fence the original core. There is no
adopt/reset/retry endpoint. Existing `requests` discovery remains explicitly its
local-check/Android/iOS scope; retain the returned Git request ID.

## Bounds and custody

There is one active selected pathset and at most 32 metadata tombstones. Settled
entries drop path custody; Unknown/recovery entries are not evicted. The retained
old/new handoff, native comparison witnesses, GUI decode and eight existing IPC
workers' simultaneous typed/encoded copies are charged to the existing document
census. Native Git action/review/runtime/source budgets remain separate and
unchanged; existing admission can refuse capacity. These quotes are not RSS proof.

Paths are sorted exact UTF-8, at most 64 × 1024 bytes, with the existing closed
relative-path vocabulary. The exact action/repository revision/path list is hashed.
The scope response, **including escaped JSON and service envelope**, must fit
128 KiB; metadata status must fit 8 KiB. A fixed serde counter validates before
encoding allocation. Requests keep the existing 4096-byte frame. There is no
32-times-path/diff cache. CLI output contains approved paths and fixed status only,
not credentials, source lines, diffs, author data or provider responses.

Stage may invoke configured clean filters: the UI explicitly warns about project
code, filesystem and network effects. Consent is not an assertion of harmlessness.

## Root hook packet

`service-git-index-hooks-20261020.patch` is against integration
`649ee310f16ab32317f590b256c827ef7ffcf68f`, with 17 existing targets:

- `service_protocol`, `application_service`, `installed_cli`, `installed_cli_main`,
  `installed_cli_ipc`, `lib`: fixed DTO/inbox/client routes and pre-send checks.
- `asset_session`, `asset_session_git_read`, `asset_session_git_local`, `supervisor`,
  `supervisor_git_local`: optional original Observe witness, exact common native
  admission/arm/reconcile/retirement, census and STOP, without a second runner.
- `shell`: three permission commands and additions to the SAME relay/final drain.
- `tests/installed_shell_observation`, `build.rs`, `capabilities/main.json`:
  exact module/command rosters, retaining unsupported-platform refusals.
- `bridge.ts`, `App.tsx`: the native permission adapter and simple Git-page panel.

The original CLI collector, five native Git commands, saved/publication owners,
Git core, fixed runtime profiles and all qualification switches stay unchanged.

## Evidence and pending verification

Author ran only the inspected nine new Node DATA/promise cases:

```
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/service-git-permission.test.mjs
```

**9 passed, 0 failed/skipped**, caller exit 0. No native calls or DOM qualification.
Rustfmt parsed the owned Rust and all 14 complete projected Rust parents; capability
JSON and exact hook apply were checked. These are not compiler/test results.

**26 Rust cases are authored but UNCOMPILED/UNRUN**, for Root's existing graph:

| Exact module filter | Cases | Scope |
| --- | ---: | --- |
| `service_git_protocol::tests::` | 4 | Closed scope/frame/hash/escaped bound |
| `service_git_requests::tests::` | 10 | One-use, reconnect, claim loss, phase IDs, native receipt vs Ready, STOP/expiry/unknown, tombstones/history |
| `application_service::git_index::tests::` | 2 | Existing real private Store fixture, project grant/reconnect/current alias and pre-send check; no Git |
| `asset_session::agent_git_index::tests::` | 3 | Failed/non-Observe eligibility, strict consent, dormant/non-main no-start |
| `asset_session::git_local::agent_tests::` | 3 | Shared Apply rejects foreign origin; original publisher lock/join/finish versus real drift/poison |
| `installed_cli::git_index::tests::` | 4 | Actual outer collector, uncertain receipt, response pairing, bounded capabilities |

Also reuse the existing `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals` regression when Root compiles.
Actual integrated Rust/CLI/TS, macOS owner execution and installed GUI consent
remain required. No native Git command, build, credential/provider/Store action,
CI dispatch or qualification was performed by the author in this task.
