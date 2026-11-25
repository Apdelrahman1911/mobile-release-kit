# Existing iOS recovery through the installed CLI

This adds a closed `local-ios-recovery` selection to the **same** iOS Build
grant, 32 retained requests, native Saved owner and four
`ios-archive-{prepare,start,status,cancel}` commands. It does not add a recovery
engine, a headless service, a signing capability or a new native nomination.

## User boundary

Use **Advanced — CLI delegation** on the existing iOS recovery page. Select
Inspect, Account, or Project and explicitly allow that one action. The CLI
receives only the existing project/revision and original request/operation IDs.
Prepare does not execute recovery; Start is separate and one-use. After a
completed inspection, check the permission state before choosing a restoration.
Each restoration needs its own confirmation and the original native inspection.
A pending/manual/conflict report is not a restoration permit. Unknown or lost
replies require observing the same IDs, not retrying with a new request.

Recovery needs no saved configuration. Ordinary archive/export still requires
its exact saved inputs and, where applicable, original signing material. Manual
recovery, candidate operations, credential arguments, automatic follow-on, and
provider/Store actions remain excluded. Existing normal Desktop controls remain.

## Original ownership

- `NativeInput::Saved | Recovery` and distinct Review/Operation/report branches
  keep configless admission from weakening either saved build mode.
- MAIN matches the displayed inspection operation/generation against the actual
  weak `IOSRecoveryObservation` **before** deriving the eligible session. Native
  source matching and the existing consume-once registry still authorize Start.
- Allow, CLI Prepare/Start, relay admission and response pre-send retain the
  original project/root/revision and READ identity. Start consumes the existing
  shared observation; status/reconnect never refreshes it.
- The original common commit installs the link before usable publication.
  Native retirement, the actual Prepare/Start caller returns, and the exact
  history-writer acknowledgment remain separate. Native status is not a join.
  Dropped callers, failed history and native Unknown are absorbing.
- Existing 300-second intent and recovery 120/240/250-second endpoints, original
  earliest failure and READ watchdog slot are unchanged. No clock is renewed.
- Approval retains weak sources, not a second Session/private graph. Typed
  variant/weak-holder/returned-marker charges remain inside the existing
  16-KiB row, 64-KiB ancillary and 688,128-byte common Build quote. The shared
  eight IPC workers and all other retained obligations remain unchanged.

## Source packet

Own leaves:

- `desktop/src-tauri/src/agent_ios_recovery.rs`
- `desktop/src-tauri/src/agent_ios_recovery_requests_tests.rs`
- `desktop/src-tauri/src/saved_command_agent_ios_recovery.rs`
- `desktop/src-tauri/src/asset_session_agent_ios_recovery.rs`
- `desktop/src/agentIOSRecovery.ts`
- `desktop/src/components/AgentIOSRecoveryAccess.tsx`
- `desktop/tests/agent-ios-recovery.test.mjs`

The isolated checkout is based on `658d8cbd`. The detached
`agent-ios-recovery-cli-hooks-20261021.patch` is composed over Root tree
`6b354f8f`, preserving accepted signed Android/common A+B/READ and signed iOS.
Its 29 target images are retained under `.task-ios-recovery-cli/parents`;
`frozen.json` pins the exact owned bytes, target pairs and evidence. New Rust
modules are children of already-declared protocol/native roots, including the
installed CLI and installed-observer graphs. No new RAW handler is introduced.

## Evidence and remaining execution

- 12 new original-controller/strict-parser tests passed.
- 32 existing Android/iOS permission and 39 existing iOS tests passed: **83
  unique Node tests**. The first affected invocation retained a loader failure
  for seven absent public JSON inputs; only that unentered 39-case file was
  rerun after supplying exact source inputs. Earlier evidence remains retained.
- One bounded composed whole TypeScript no-emit check passed. Its original
  caller joined and exact disposable source/dependency link were removed.
- Rust syntax parses only. **15 new Rust tests are uncompiled/unrun**: 14 DATA
  cases and one existing task-owned private Service/state-file fixture. The
  latter uses the real history writer, not a native recovery engine. Explicit
  constructor/predicate DATA in other tests is not a native join receipt.
- Exact new/affected selectors and effects are in the task's `selectors.json`.
  Root must compile and run these in the existing graph, including real typed
  capacity assertions. Native recovery/CLI/runtime qualification is still
  unverified; no synthetic data or source review enables it.

No native, provider, signing, credential, CI, Cargo or network operation was run
by this author for this packet. No background task remains.
