# Bundle-ID registration: original native composition

This packet extends the **existing SavedCommandOwner Session**, installed
StoreRuntimeSlots and selected-P8 writer. It adds no runner, HTTP client,
credential kind, certificate/profile issuance, implicit state startup or CLI
grant. The Root-only patch is based on integration `0356f163` plus Root's
upload-key accounting reexport cfg; it preserves the already integrated
Android upload-key hooks. Shared files are not edited
in the Apple worktree.

## Required original bindings

The four raw commands are `prepare_apple_provisioning`,
`start_apple_provisioning`, `apple_provisioning_status` and
`cancel_apple_provisioning`. Context includes the selected saved app/config/
version and credential revision, bounded explicit display name, mode and
nullable review/reconciliation reference. No public path, account override,
P8, response body, journal record or native receipt is accepted.

Prepare/Start keep the SAME Document, registered root, original saved lane and
SavedEditGuard, selected native P8 context/payload/full RecordKey and explicit
NativeStateReady Arc. Start rematches the retained private input; it drops
Document/Edit guards before releasing the existing GO. Only the actual P8
issuer UUID is hashed into the account fence. Key ID/project/seedId are not
account or team proof.

**Root prerequisite:** publish `DocumentState.apple_provisioning_ready` only
at the genuine explicit grantless native-state startup completion, after the
original probe/Store/registration jobs join and the same native project,
root, source epoch and saved-input revision rematch. Existing
`Host::native_state_current` remains authoritative; stale state refuses.
There is no fallback to Allow, `allow_agent_read`, opening an endpoint, or
starting a dormant Host during a read. This publication/UI is not fabricated
by this packet. Store v1 needs the separately reviewed explicit upgrade;
unavailable is not an empty account roster.

## Closed flow

* **Review** uses its own consent, original native state read and fixed
  selected-key GET. A reusable returned Bundle ID needs no POST. Not-returned
  means this key's exact response only, not global availability. Only actual
  positive original retirement can retain one private review token for the
  same selection (original observation tick + 300 seconds, never refreshed).
* **Register** consumes that review and separate `local-ios-bundle-register-v1`
  consent, requires the explicit new-app declaration/unverified saved identity,
  and repeats the original private Execute/Reconcile continuity veto. Unknown
  continuity does not itself assert absence. The fixed worker GETs again.
  A register plan must receive the actual same-account durable Pending ACK
  before its sole POST. The exact operation/generation, raw request hash,
  nonce, canonical plan/update and namespace revision bind each ACK.
* **Reconcile** selects the exact prior account row and makes only a fixed GET.
  It reports same/different/unattributed/not-returned comparison, never retries,
  adopts a restored NativeUse/reservation, clears unknown native settlement or
  manufactures signing readiness.

The existing worker remains seven commands for Review/Reconcile, at most nine
for Register (one POST and at most one GET readback). It keeps original
source/material POST, private scratch and process C/A/W rules. Release Access
context/consent and its two-frame decoder are not widened.

## Journal and finality cut points

The actual Session retains seven fixed serial original job slots:
Initialize+account-read; Pending reserve; up to two attempt updates; at most
one proved-no-ACK audit; native-settlement CAS; NativeUse retirement. Each
blocking job is registered before GO, runs off Document/Edit/Host/Service
guards, and is awaited through its **same** JoinHandle. STOP never takes its
private journal mutex. No timeout abort, detached replacement or retry exists.

W/H stay 1200/1210 seconds. Runtime/provider probes and journal calls have a
60-second cap (P8 validation remains 30). While an original syscall is blocked,
the existing owner observes the earlier cap/F and continues retaining/joining
that syscall. New audit effects are limited by `min(W, F+10)`; original cleanup
uses the existing hard-finality rules. A delayed result cannot renew any clock.

`AppleProvisioningNativeJoined` is minted only after actual worker/provider/
source/material-consumer, pipe, driver, manager and pre-final-CAS job joins.
It precedes the last journal CAS; later material retirement/watchdog edges
cannot be a circular prerequisite. The distinct `AppleProvisioningAllJobsJoined`
requires all journal jobs, including that final CAS (or known not-entered),
and seals the writer roster. It permits only the original NativeUse retirement
call; that **separate retained retirement job must also return and join** before
the final observer/watchdog can finish. Neither fact has a public/test factory,
serde/Clone/Drop settlement, or restoration from JSON.

Lost/partial first ACK remains irreversibly armed. Only a never-entered first
ACK plus genuine known worker joins and the exact original returned reservation
can record no-send. A child terminal never clears native settlement; failed,
unknown or lost native jobs keep the original account row/token fenced. After
F, only already-armed final audit records may be acknowledged; the intermediate
response ACK that permits the readback GET still requires current work.

## Central patch / limits

The 20-file patch adds the closed SavedOwner variants and original start/
writer/decoder/closure hooks; two narrow original saved/material child imports;
the actual Bridge owner and reciprocal Document busy/lost/context/shutdown/
exit hooks; four raw shell commands and the existing single event relay;
fixed runtime/bootstrap and packaging roster additions. Original Android
defaults/tests get only the required additional inert field/exhaustive arm.
The independent Tool Acquisition and Local History Document gates each also
include Apple in their existing disabled/stopping/busy lists; they do not rely
on the separate common Store gate for reverse-direction exclusion.

The retained review/status/input reservation is charged **once** in every
Document census; the active quote subtracts it. The active quote covers the
1 MiB namespace, 32 x 16 KiB rows, concurrent bounded decode/encode/readback,
seven retained job/ACK slots and wire buffers. Request/response/IPC/ACK bounds
are 64 KiB/128 KiB/8 KiB/2 KiB, with at most three events. These are finite
representation bounds, not SDK/native/allocator/process RSS claims.

## Evidence and remaining gates

* New source: 18 Rust tests authored (10 codec, 5 original memory/clock/
  projection, 2 target/issuer, 1 original saved comparison), **not run here**.
  They construct only DATA, not fake current key loans, native Store tokens,
  native joined receipts or installed permits. Root owns actual graph batches.
  The original inert Session regression exercises common Cancel/context-loss/
  shutdown `stop_locked`, both native cutoff watches, delayed earlier/later F,
  and the W cap; it does not use a fabricated native completion.
  A second original-Document regression verifies both independent public peer
  gates preserve real Apple Shutdown and missing-original Unknown before the
  Linux unsupported-platform refusal; no native availability is simulated.
* All eight complete new/changed Rust modules syntax-parse with rustfmt;
  bootstrap AST parses. The complete patched shared Rust/Python/JSON/TOML
  sources also parse. Patch application to task-only source copies produced
  byte-identical complete files; `git apply --check` passes against Root.
  Syntax and patch application are not compilation or native qualification.
* Accepted Worker15 is unchanged: Root's integrated 15 tests passed in
  `verification/apple-worker-integration-v1.log` (1.943s, exit 0), using inert
  provider/ACK/C-A-W fixtures. Prior accepted core73/Ruby12 evidence is reused.
* Root still owns actual central composition, Rust/Mac graph, explicit state
  startup/UI, installed bootstrap/manifest/package and original native
  qualification. No installer, host process, key/account/Apple call, live
  registration, certificate, profile or signing acceptance was performed.
