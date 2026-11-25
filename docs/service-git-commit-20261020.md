# Shared CLI: one Desktop-approved whole-index Commit

## Scope and original ownership

This adds five named `git-commit-*` commands to the running Desktop's existing
authenticated CLI transport. It is not a new Git runner, journal, service,
credential permission, or full Git/CLI parity. Stage/Unstage keep their original
wire names and behavior. Branch writes, fetch/push, hooks, signing and credential
access are not included; native availability flags are unchanged.

Desktop must already hold the genuine, successful, settled GitRead Observe.
The real main-window Allow copies the current message and author from the
existing Git draft once. The native path rematches that Observe's retained
root/registration/Doc revision/SavedEditStamp/control epoch, not a renderer
observation or historical repository summary. It derives **all staged paths**
from that original observation; untracked, ignored and unstaged rows are not
staged by Commit. Conflicted, failed, non-Observe, empty or overbound results
refuse. The original GitLocal Prepare independently re-reads its own sources.

There is still ONE `service_git_requests::Inbox`, lease, occupied request and
32-total metadata tombstones. Its closed Index/Commit discriminator is checked
before CLI lookup, consumption or per-request STOP. Index read/prepare/start/status/cancel cannot
adopt a Commit row, and vice versa. Only an explicit Allow can replace another
family's unused grant; occupied/unknown work cannot be replaced. There is one
bounded private Commit draft in the active scope (plus the old handoff stack),
not 32 drafts. The same existing document quote adds two fixed draft backings;
native action/review and eight simultaneous public IPC representations remain
in their existing charged owners. The private draft never enters an IPC reply,
history, public native projection, log, error or CLI input.

The two native main-window Stop buttons intentionally revoke the SAME shared
permission and stop its occupied task, including the other family. Their one
revoke epoch also fences an in-flight sibling Allow; no per-family renewal can
revive it after Stop. This GUI emergency revocation is distinct from CLI Cancel,
which must match its exact family and request before any STOP. Neither path
retimes a retained first failure or supplies native cleanup/finality.

The private scope reaches the SAME original `NativeLink`, owners-lock arm before
spawn, Prepare/ReadyReview, publisher, Apply, terminal joins, final CAS and
NativeUse retirement. Prepare and Apply retain separate genuine operation IDs.
The original Action constructor binds the exact message, author and revision;
reconcile additionally matches the actual whole-index review paths to the
approved scope. GUI None-origin cannot consume this agent-linked review.
The existing advisory publisher watcher, strict admission/currentness checks,
STOP/first-failure, 45/55-second native clocks and finality are unchanged.

The 15-minute permission is authorization to enter Prepare/Start, never a new
runtime clock. Status/STOP still require normal authenticated project read
access but not a renewed write grant. Caller loss, uncertainty or host restart
never grants replay; no persisted row recreates an original review or join.

## User flow

1. In the running Desktop, enable existing scoped agent read access and perform
   the existing Git check. Review the whole staged index and enter the commit
   message and author in the existing fields.
2. Explicitly allow one agent Commit. This is separate from Stage/Unstage or
   read access and uses `agent-local-git-commit-once-v1`.
3. `mrk git-commit-scope PROJECT_ID --json` returns the approved paths and grant
   IDs, never the message or author. Scope/status queries start no native work.
4. `mrk git-commit-prepare PROJECT_ID SERVICE_INSTANCE GRANT_ID --json` creates
   one client-generated request ID before transport. It invokes the same native
   Prepare only; poll that request until its actual joined review is available.
5. `mrk git-commit-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID PREPARE_OPERATION_ID REVIEW_ID --json`
   consumes that exact native review once. It does not redo the action in GUI.
6. Use `git-commit-status` or `git-commit-cancel` with the same project, instance
   and request ID. An uncertain reply exposes those IDs, never a replacement
   command. Restore read access if needed; restart is not replay permission.

The existing Git panel can observe/stop/close; its common guard rejects GUI
Apply of an agent-linked review. Public status/history are observations, not
cleanup receipts. The public CLI report does not invent a commit OID or other
provenance absent from the existing request projection.

## Root integration packet

Apply `service-git-commit-hooks-20261020.patch` after the new leaves. It has
27 existing targets and was refreshed by ordinary conflict-free three-way
composition against Root `d5e83ceff083e925f68986e7342cb016a403b5dd`:

The 27th target adds only this packet's Node test to the explicit package roster
from Root `b20beca2872efce4b0bb1ed09e0eb266f32f470b`. The review correction also
clarifies the copied draft/shared GUI Stop and tests that existing Stop behavior;
it changes no native runtime logic or permission semantics.

- Existing protocol/inbox/Doc/Service/GitLocal/CLI children use closed family
  helpers; no second execution owner or new Document field is introduced.
- Existing application dispatcher and final pre-send guard add five finite
  routes. The guard remains held through memory-only inbox access and checks the
  same current project alias/read grant before response.
- `lib.rs`, thin CLI and the existing nonshipping observer declare the portable
  DATA module. Native-only leaves are children of their actual original owners.
- Shell/build command catalogue/main capability add exactly three local native
  GUI permission commands. They use the original main-window guard and bounded
  RAW input, not a new execution endpoint or fabricated window.
- Existing permission promise controller is parameterized only by its bounded
  result type. Reentrant Revoke, retained original API, pending Allow and
  saturated epoch behavior is unchanged. Commit uses the same existing draft.
- Four original Rust fixture/helper files gain neutral private-draft fields,
  one exhaustive Index refusal and a test-only shared observation constructor.

All shared source is PATCH ONLY. Before/after source pins and complete copies
are in `.task-service-git-commit-hooks/refresh-v1`; Root owns composition and
actual integration.

## Evidence and remaining checks

- **18 Node tests PASS**, 0 skipped (9 new + all 9 affected original permission
  tests), 134.806 ms; original caller returned 0.
- **Full strict frontend source projection PASS** at the Root above, using its
  existing pinned dependencies and actual 284 source/JSON files. Original TSC
  caller returned 0. The first projection lacked seven original JSON inputs and
  used the earlier, already Root-corrected LocalStore field; that failure log is
  preserved. No product workaround was added.
- **23 new Rust tests authored, UNCOMPILED/UNRUN**. Eleven new Rust files and
  twenty projected Rust targets syntax-parsed; this is not typechecking.
- Temporary frontend files and the sole dependency link were retired by their
  exact known inventory after the callers returned. Logs/hashes and shared
  caches remain; no installation, Cargo, native Git, credential or provider work
  was executed in this lane.

Root's focused actual graph batch should include these new groups:

```
service_git_commit_protocol::tests::                   (4)
service_git_requests::commit::tests::                  (8)
git_local_protocol::service_commit::tests::            (1)
asset_session::agent_git_index::commit::tests::        (4)
application_service::git_index::commit::tests::        (2)
installed_cli::git_index::commit_tests::               (4)
```

Rerun the affected existing Index groups once with that graph: protocol (4),
inbox (10), Doc (4), native guard/watcher (3), service (2), CLI (4): **27**.
Also check actual thin-CLI help/capabilities (existing 12 KiB limit unchanged)
and real framing. No new native/installed qualification is claimed here.
The existing short manual CLI/native runbook applies: genuine Desktop consent,
same original owner, status/STOP and shared history; Mac execution remains
Root-scheduled, not a new harness or CI pipeline in this packet.
