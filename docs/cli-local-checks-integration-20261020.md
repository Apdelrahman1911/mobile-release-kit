# Named CLI local-project checks

Source packet checked against integration `6690d445` (original hooks composed
on `ce47c609`; fixed observer and three GUI permission declarations added during review). Apply
`cli-local-checks-hooks-20261020.patch` only in the central integration lane.
The ten new implementation/test files do not replace any existing owner.

## User-visible contract

The running Desktop is required. Agent read access **does not** authorize
execution. The real main Desktop window can separately allow **one saved
Android local-project check**, for one selected project and saved observation,
for at most 15 minutes. The grant is default-off, consumed once, and never
restored after restart. Revoke is independent of a pending Allow/inspection.

Configured project checks can execute programs, read account files, modify
files, build, or use the network. This is not a sandbox. The MRK action does
not request toolkit builds, signing credentials, Store operations, artifact
validation, or release readiness. Existing local-check/release defaults and
runtime qualification gates remain unchanged.

```
mrk local-check PROJECT_ID OBSERVATION_REVISION [--json]
mrk local-check-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk local-check-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

The client generates and flushes the public instance/request correlation
before sending an action. An uncertain send preserves that same tuple in
the result; it never automatically retries. A new socket/client can query or
request STOP using the original tuple without another execution grant. Read
access is still required. CLI exit zero acknowledges a request or completed
report, **not** passing checks or release approval.

## Exact owner handoff

1. `ApplicationService` retains a bounded memory-only inbox on the existing
   instance. IPC submit/query/cancel hold the same current read-grant guard
   through the inbox action; revoke cannot linearize inside a guard gap.
   The inbox checks the separate exact native grant. Requests contain only
   IDs and an observation revision, never executable/path/configuration data.
2. Genuine `DocumentBinding` Allow captures the selected registered root,
   original document identity, input epoch, and `SavedEditStamp`. Service/Host
   calls occur off Doc/Edit locks; their return is rematched under the same
   Doc against the original stamp, registration, and revoke epoch. Ordinary
   status never opens a dormant Host or enables access.
3. Submit wakes the existing retained native relay via the original Doc watch.
   The relay compares the saved observation, marks it stale through the same
   Projects writer **off Doc/Edit**, then rechecks all native peer/currentness
   gates under Doc/Edit before the original preflight Prepare/Start. A
   preclaim refusal may conservatively leave the observation stale.
4. `saved_command_agent_local_checks.rs` is a child of the existing
   `SavedCommandOwner`, not an executor. During the same Prepare it links the
   genuine operation ID/generation before Prepared publication. All Start
   paths use the common exact retained-entry/context guard **before take**.
   Ordinary GUI Start cannot adopt an agent-bound Prepared. The existing
   `Admitted` release sends original GO only after Doc/Edit unlock.
5. The existing Session retains the link and its original STOP sender. Revoke,
   request cancellation, and fixed lease expiry stop that original without
   waiting for Service IO or the UI relay. The existing watchdog samples the
   same lease expiry/first STOP; native spawn/transfer keep their existing
   final `advance_locked`/currentness checks. No clock renewal or extra
   observer/task is introduced.
6. Progress is copied by the original registry bump. Final status is copied
   only after actual positive watchdog/reconcile retirement and original
   material/worker/native joins. Helper terminal JSON, observer return alone,
   socket exit, missing weak handles, and history never grant settlement.

## Correlation, history, and failure

There is one outstanding native request and at most 32 non-evicting per-launch
request rows. Exact same body/ID observes the original; another body with the
same ID conflicts. A consumed permission cannot authorize another request.
An admitted or unconfirmed original never becomes a false preclaim refusal.
Dropped admission, failed binding, and uncertain native finality retain the
request and prevent replay. Only the original positive retirement releases
active occupancy; its launch tombstone remains.

The same relay calls existing require-new `begin_operation`, then
`publish_operation`, with the genuine original ID and `LocalProjectChecks`
action. It holds no Doc/Edit lock while writing. Latest native data and an
in-flight history claim remain separate; an unreturned/failed ACK is retained
and fences saved reads. `historyAvailable` means the current status revision
was acknowledged, not that native resources settled. A panic guard fences
history without rewriting the original core outcome.

Final drain runs only after native domain owners and the same relay joined,
before existing Host shutdown. It closes/revokes the inbox and flushes; it
never executes a remaining queued request to empty the queue. A history
failure does not skip Host cleanup. Restart restores only existing stale
operation observations, never an execution grant, request, native owner, or
authority to clear unknown cleanup. There is no adopt/retry/recovery execution
endpoint in this slice.

## GUI observation and compatibility

An optional native-only `agentLocalCheck` marker is added to the existing
offline Projection, not worker Context/Terminal or public Start input. The
same GUI controller may display and STOP it only after its previous original
is terminal and no actual GUI submission remains pending. One bounded held
event can be reconsidered when that same pending invocation returns. This
does not call Prepare/Start, create another observer, or clear Unknown.

The GUI's existing behavior after a genuine cancelled operation is unchanged,
including a lost earlier Prepare reply. Pending-invocation tracking gates only
unsolicited agent display adoption. Same-ID marker substitution is rejected.
The App-owned permission controller samples saved selection at event time,
survives panel hiding, and retains the original connection for Revoke.

Static capabilities separate direct mutation commands (unsupported) from this
explicitly authorized named project-code execution. ServiceInfo says read
permission does not authorize execution. The thin CLI imports only portable
DATA/inbox/protocol modules, not DocumentBinding or native owner code.

## Packet and verification

The 25 Root hooks cover Service/IPC protocol and CLI declarations, existing
SavedCommandOwner/facade/Projection, Doc/relay/exit/census, native-only GUI
handlers, existing frontend API/parser/controller/App, the test list, and
literal-field additions in five existing fixture files, plus the fixed portable
module declaration in the existing installed-shell observation executable, plus
exactly three command names/generated permissions in build.rs/main capability.
No new namespace,
filesystem owner, process adapter, general shell/executable endpoint, dependency,
or feature flag. The three new GUI permission endpoints use the existing
main-window/local-only capability; execution enters the original offline owner.

Executed in the isolated task-owned source projection:

```
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  .task-local-check-hooks/modified/desktop/tests/agent-local-checks.test.mjs \
  .task-local-check-hooks/modified/desktop/tests/offline-preflight.test.mjs
```

**42/42 PASS**, joined exit 0: 13 new permission/origin/race tests and 29
unchanged offline-controller tests. Initial projection setup misses (missing
public JSON imports and a null-prototype assertion) were corrected. This run
also caught an actual default-behavior regression from globally blocking GUI
submission; narrowing that counter to agent adoption restored all 29 tests.
No failure is represented as a successful native run.

Distinct source review found two permission-controller gaps: synchronous
listeners could Revoke before Allow dispatch, and status-only reconnect could
lose the original API. The corrected same-work/epoch/current-context pre-call
guard and retained status API have **15/15 affected Node tests PASS**, joined
exit 0, including two new reentrant/status-rebind regressions. The unchanged
29 offline-controller results above are reused; no unnecessary rerun.

All six new Rust files pass rustfmt syntax/style checks. All 17 modified Rust
copies syntax-parse. Patch application is checked against the current Root
tree; Rust syntax is not a compile/trait/custody qualification.

**23 Rust tests authored, NOT RUN here.** Root's real graph selectors:

- `agent_local_checks::tests::` — 14 portable inbox/protocol tests, four actual
  original-owner inert tests, and two Doc consent/dormant-host tests.
- `application_service::local_checks::tests::` — one actual private Store and
  Service fixture: separate consent, exact saved revision/stale idempotence,
  revoked client rejection, reconnect/query/STOP without execution renewal.
- `installed_cli::local_checks::tests::` — two closed CLI/framing/lost-ACK tests.

Important cases include revoke before/after original STOP attachment; fixed
expiry tightening original clocks; common Start rejecting ordinary GUI
consent before consuming Prepared; unknown absorption; lost admission/history
ACKs; ledger saturation/no eviction; same-instance body matching; restart
refusal; unchanged old GUI cancellation behavior; pending GUI adoption; and
event-time selection/revoke races.

No Cargo, actual service/native/Store test, project code, credential, provider,
CI, or installed operation was run by this lane. Root must compile the actual
library/thin CLI/frontend and test their integrated graph. Native Desktop/CLI
execution remains separately unqualified until exercised through originals.
