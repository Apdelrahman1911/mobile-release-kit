# Apple CLI: one genuine Desktop-selected Prepare

Author lane: `apple-prepare-cli`, base
`8f4c0206cfddb3d4ce2800a46055633a92188463`.
Plan v2 was independently reviewed by Project (`bd5d6a6d`); implementation
requires Tools' distinct actual review and Root integration. This packet does
not nominate or qualify a runtime.

## Scope

The collapsed Advanced control allows an explicit, unchecked, Prepare-only
approval for the current Desktop selection. The new command is:

```
mrk apple-provisioning-prepare PROJECT_ID SERVICE_INSTANCE GRANT_ID SCOPE_ID --reviewed [--json]
```

Only scalar addresses cross IPC. Desktop still selects the actual credentials,
target and prior reference. The same fifteen existing CLI modes are supported;
KeyRecover remains Desktop-only and there is no P12 reconcile mode. The existing
Start/status/cancel commands remain separate. Prepare never means Start, save,
assignment or signing readiness. Assess/Bind, encrypted backup/restore, account
setup, Keychain and file-picker boundaries remain their ordinary explicit routes.

## Original ownership and publication cuts

* `service_apple_provisioning_requests::preparation` uses the original Book's
  `Start | Prepare` union, total32, one lease and existing nonce/tombstone bound.
  The ordinary eight IPC workers remain common; no second pool or executor.
* MAIN Allow makes two original Doc/Edit/source/READ checks. The scope retains
  bounded public metadata and Weak material/prior-review comparisons, not a
  second private payload owner. A submitted request binds its original receipt
  to `min(receipt + 30s, scope/prior expiry, Read.end)`.
* The existing MAIN `prepare_apple_provisioning` command has a fixed IDs-only
  delegated branch. The original controller retains its actual promise. No
  relay worker invokes a renderer API or reconstructs a Context from CLI input.
* Same Host acquisition and Saved Prepare are used. The actual common Prepared
  commit installs the typed Apple Intent and Prepare Entry **before** the
  original bump/snapshot. It is not usable until construction, the original RAW
  return, and the service history return have all occurred. A terminal event or
  status value supplies none of those return facts.
* The original Host ticket remains retained through finish, including bind or
  return failure. Only an actual pre-Host/pre-Prepared refusal can close as a
  known refusal. Entered Host, lost return, failed finish or history loss stays
  Unknown; no new attempt is inferred from a returned error.
* Prepare history uses its own request ID and ObserveProject record. The new
  Prepared operation ID remains available to the separately approved Start.
  The original300s Prepared/prior-review expiry is never renewed by observation.
* Exact same-original handoff covers Doc and Inbox occupancy gates. GUI Start
  claims before the existing prior-review consumption/take. CLI Start needs a
  separate nonce/binding/consent. Failed installation stays consumed; late old
  Cancel/READ withdrawal cannot cancel an already handed-off successor.
* Prepare STOP records the earliest original failure. Scope notifications and
  Unknown/retired updates are transition-only, so repeated retained-stop polling
  cannot self-wake the existing Document relay indefinitely. Unknown remains
  absorbing; none of these controls is retirement evidence.

The UI deliberately models a delegated Prepare origin, not a fabricated GUI
StartJoined. After the real return/history cuts it performs the ordinary native
status read and permits only the same original unpublished-to-usable transition.
Listeners, current API/session/project, ABA and original expiry are rechecked.

## Source packet and composition

Nine new source/test leaves: five Rust files named `*apple*prepare*.rs`,
`agentApplePreparation.ts`, `agentApplePreparationController.ts`,
`components/AgentApplePreparationAccess.tsx`, and
`tests/agent-apple-preparation.test.mjs` (exact paths in the freeze manifest).
This guide plus `apple-cli-prepare-hooks-20261021.patch` completes the owned11.

The detached patch has29 existing targets. Its exact current before/after pairs
are in `.task-apple-prepare/parents/`; the baseline is Root21cbb9f9.
Current Image/Upload additions, truthful CLI help/catalogue and accepted memory
A/B/C are preserved. Only two conflicts needed additive union: package test list
and the CLI human-response match. The observer test root explicitly declares
the new pure protocol; the new response uses per-project IPC pre-send checks.
No new RAW handler/capability name, nomination, memory quota or global debit.

The changed old Apple accounting assertion retains32 row debits and128KiB
ancillary; accepted memory B already moved IPC-only allocations to the common
eight-worker pool. New tests measure actual row/call/context representations
against those existing bounds. Those Rust measurements are **not yet run**, so
this is not a whole-Document fit or native-admission claim.

## Focused evidence and limits

Retained `.task-apple-prepare/` logs:

* New controller/protocol tests: **19/19 PASS** (`node-final.log`,0.609s), using
  the actual existing controller plus inert fixed ports/reducer-style sources.
* Affected existing frontend cases: **135 unique resolved**. First134 passed;
  one stale expectation incorrectly rejected the already-supported Desktop
  KeyRecover Start. Only that case was corrected and rerun (1PASS). Unknown
  consent remains rejected; CLI KeyRecover was not enabled.
* Composed frontend TypeScript: PASS18s, before the final conservative expiry
  boolean conjunct. It is not represented as a byte-identical final-source
  check; Root will check its combined frontend once. Final19 Node cases include
  the expiry behavior.
*27 Rust files parse with rustfmt only. **No Cargo or Rust tests executed.**
  Exact20 new and affected selectors/effects are recorded in the task manifest.
  They use in-memory original methods and constructor-only fixtures; no Host,
  filesystem/private key, provider, NativeUse or native join is fabricated.
  The shared writer/material lifetime fixture explicitly cannot grant source
  admission. Real Host/worker/Asset/NativeUse/IPC runtime behavior remains unrun.
* First failed Node fixtures and the stale affected assertion are retained, not
  overwritten. Test/TS callers joined; only the proven task-owned public-source
  scratch/link were removed. Shared dependencies were unchanged.

No native/provider/account operations, CI dispatch, signer build, credentials or
private output were used. Existing production availability and supported trust
boundaries are unchanged. Source acceptance and component/unit checks are not
end-to-end Apple issuance or headless qualification.
