# One fresh Activity overview through the installed CLI

Author base: `658d8cbd397d764dd668c4b1f83990d216ac874c`. This is an implementation/source-review packet, **not native or provider qualification**. Shared changes are only the detached `github-activity-cli-hooks-20261021.patch`; Root composes those hunks, not whole after-images.

## Delivered boundary

The existing Advanced GitHub delegation control can approve exactly one `activity-overview` using the genuinely returned Activity metadata and selected original Connection. No preceding provider Activity Read or fake Prepared/consent ID is needed. Normal project READ alone is insufficient: the separate consent is `agent-activity-overview-once-v1`. The existing three commands remain:

```
mrk github-submit PROJECT INSTANCE GRANT --reviewed
mrk github-status PROJECT INSTANCE REQUEST --json
mrk github-cancel PROJECT INSTANCE REQUEST
```

There is still one grant, one 32-row inbox and namespace9. Existing six kinds keep their exact CLI selection, consent and absent-snapshot encoding. The new selection carries session, Activity revision and Connection revision; native captures the real account/repository IDs, target, root/generation, SavedEditStamp and original READ. No token, URL, branch, private body, source path or arbitrary query is accepted.

The unchanged core `github_activity.py::Reader` performs `/user`, repository identity, first30 open PRs, first30 workflow runs, then repository identity again, through the unchanged Activity/Connection/Setup/HTTP owners. The compact historical result has numeric IDs/statuses, time and original availability/coverage/reason/counts. Optional403/404 remains unavailable, not empty. It is not an atomic/complete history, current-head or CI assertion, Prepared/BoundResult, or authority for another action. No jobs/logs/artifacts, CLI authentication, branch/detail reads, automatic refresh, History or release-dispatch extension.

## Originals, clocks and completion

- `service_github_activity_native.rs` is a child of the existing Connection Activity, not another owner. The optional private permission compares the actual original scope and edit stamp at Allow, relay admission and GO. Any private preflight/release/setup/publication/repo-create/PR/retry/cleanup review refuses the agent read instead of discarding a GUI winner.
- Existing Document/registry/Connection checks and the same retained relay call start the read. Existing Supervisor roster insertion arms its Entry before spawning. GO remains the original one-use gate.
- Submit captures T before queueing. Work ends at `min(T+60s, READ.end, credential.end)`. Grant120s is admission-only. Existing100ms watchdog sampling includes READ.end and continues after STOP; earlier READ F tightens the original Activity `min(F,work_end)+2s` cleanup. No new task, timer, retry or credential clock.
- Only the tail of actual `accept_github_activity`, after original receipt/control/currentness/credential processing, compacts the borrowed observation and publishes the native fact. A successful CLI row still requires **that native acceptance, the original relay return, and matching history publication return**. Unknown/history loss stays absorbing. Known pre-entry refusal uses the original NeverAdmitted path, never a fabricated native receipt.
- Effect is always `none`, including GO/unknown. Compact DATA is published under the same Row mutex as its native fact and exposed only after the three-return cut. Exact request Query remains historical even when a later Activity view supersedes it. Existing per-project IPC pre-send gate and current READ remain required.

## Actual MAIN revocation race correction

All seven kinds now use the existing Doc `agent_github_action_revoke_epoch` as MAIN-only `permissionRevision`: canonical full-u64 decimal string, including `"0"`; no JS number. The Allow body requires the **original** `expectedPermissionRevision`, pinned from a genuinely joined Access before listeners/raw invocation. It is compared at both original Doc cuts. `checked_add` happens before installation, success consumes once, and status never mutates it.

Empty Revoke and relay loss serialize their existing counter/close actions on that same Doc. Revoke captures STOP before waiting for Doc. At MAX, all Allows refuse; Revoke/relay close still stop/close the original before returning any overflow error. Neither path holds Doc across a new off-Doc Service call. Frontend retains normal/Allow/Revoke promises and the original revision through reentry/late replies; it does not rearm a lost invocation.

The same four existing MAIN commands return typed `MainAccess`/Status instead of a transient `Value` tree. Standard Tauri/serde JSON, command names, platform fallbacks and MAIN ACL remain; there is **no new Tauri command or ACL**. CLI Access/Status do not gain the MAIN counter. Ordinary GTK/Mac observer root module declarations remain sufficient.

## Unchanged accounting, concrete representations

- GH remains **786432B**: `32*16KiB` full original rows + `128KiB` ancillary + `32*4KiB` compact snapshots (the former slack, still fully debited). History retains scalar facts, not another snapshot. Every retained native/history/original row remains charged.
- Snapshot bound includes actual vector capacities, typed30+30 rows, timestamp capacity, outer struct and Arc header. IDs are stored as u64 and serialize as exact strings; enums have no prose allocation. Overallocation or overbound data refuses without truncation.
- Complete new CLI response is≤8KiB; old six stay≤2KiB. Existing counted outer encoder and bounded typed validation are reused. Same GH32KiB IPC worker quote covers request/IDs, one4KiB compact copy and two8KiB scratches; all inline enum cells stay in existing global H. Same eight workers/Metadata exclusion, no new quota.
- Same128KiB ancillary additionally names at most normal+Revoke typed MAIN serialization (`2*3*8KiB` growable old/new peak) and four4KiB public copies. `row_bytes`/`ancillary_bytes` and whole-IPC actual-type guards refuse if the real ABI fails; the author has **not executed** these Rust numerical guards.
- Native Activity128KiB reply/2MiB retained and original Document limits are unchanged. Private capture heap is included in existing Activity State census.

The wire/Entry children import only existing service DATA dependencies in the standalone `installed_cli_main` graph. Borrowed native `Snapshot::from_observation` lives in the existing Connection child. The service UTC predicate is the exact existing Connection grammar; an inert parity table covers boundaries. No new crate-root or runtime source roster is added. `lib.rs` and `tests/installed_shell_observation.rs` already declare the relevant native parents.

## Files, review evidence and pending work

Eight new source/test leaves: `service_github_activity_{protocol,requests,native}.rs` and their `_tests.rs`; `githubActivityDelegation.ts`; `github-activity-delegation.test.mjs`. Thirty detached parent hooks include the same protocol/Entry/MAIN/Activity/Supervisor/CLI and shared frontend call sites plus the default/focused Node test entry. Exact before/after pins and root replay results are in `.task-activity/parents/pins.json`; frozen own/tree/test pins are in `.task-activity/frozen.json`.

Source plan pins: `activity-read-plan-658d.md` SHA `aaa2a9e36e60af1f2e3edd66f097c7e7004a026c9e5a633e0ed2a917e37c7623`; mandatory revision amendment SHA `883e2c40b8ec97725c6fa3969c246ee8d45098af0984556da36676912cb15d28`. Root accepted both and the same-four typed-response amendment; distinct actual review is separate.

Author evidence (`.task-activity/results`):

- **91 distinct inert Node cases PASS** (10 new +81 existing). Normal serial/default isolation is reused; actual codecs/controllers and original deferred promises only. First run retained15 old passes then timed out on a bad new fixture that changed account/generation without advancing native revision. Its child was killed/joined and exact projection removed; corrected fixture asserts no raw call before await. Second run39 passed but missed one imported publication fixture file; that was an explicit projection error, not a full pass. Adding the exact existing fixture yielded37 publication passes. These historical failures remain in the evidence; unchanged passed tests were not broadly repeated.
- Review successor expands the existing MAIN decimal test with final/leading/embedded LF, CR, U+2028 and U+2029 across revision, raw Allow and compact IDs. The original parser already rejects these in the actual Node runtime: the reported regex concern was withdrawn, **not a reproduced failure**. Production bytes remain unchanged. The exact final expanded case passed in the same bounded nonroot/networkless recipe; original caller joined and owned projection removed. This is one extended case, not an increase to the91 distinct total.
- **One composed whole TS noEmit PASS21.085s**, current Root16456758 including the explicitly captured stable LocalCheck frontend plus Activity. Original caller joined, own projection/link removed, minimum available8032522240B. No install; cached dependencies only, nonroot/networkless, heap768MiB and existing entry/floor limits.
- New/changed Rust syntax checked only. **17 new Rust methods and the listed genuinely affected methods remain UNRUN**; tests exercise codecs, real unentered Entry/Doc/Connection methods, capacities and caller/history ordering, not fabricated native receipt/authorization. Source graph and neutral constructors were inspected without compilation.
- Core Reader/provider, native runtime/Tauri/IPC/Connection/STOP and actual credentials were not executed. No new network/remote write, CI, availability flag or shipping qualification.

Root must compose current parent deltas, perform the ordinary combined library/CLI/observer graph and actual resource checks, and schedule any genuine native journey separately. This packet does not expand or fix the separate local Git4 delegation race.
