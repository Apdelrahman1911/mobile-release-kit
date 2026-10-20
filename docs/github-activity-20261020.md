# GitHub pull requests and Actions: bounded read-only view

This source packet adds a useful Activity panel to the existing GitHub page.
It does not create a pull request, approve a review, rerun a job, dispatch a
workflow, download logs/artifacts, or grant permission to release. General PR
creation and rerunning failed jobs remain separate follow-on operations with
their own explicit review, authorization and uncertain-write reconciliation.

## Existing owners, not another transport

The new fixed `mrk-github-activity/1` dialogue runs through the existing Setup
bootstrap, Supervisor Owner/Resources, private GitHub HTTP transport and
ConnectionState. It borrows only that original connection's retained token,
verified account/repository IDs, registered project root and SavedEditStamp.
The renderer supplies neither the repository, account, token, URL nor a path.

Three main-window commands accept strict RAW UTF-8 JSON, at most 1,024 bytes:

* `github_activity_status {}` — local original-owner status, no HTTP refresh.
* `github_activity_read {sessionId, projectId, expectedRevision,
  expectedConnectionRevision, selection}` — an explicit bounded read.
* `github_activity_cancel {operationId}` — Stop that same original operation.

`selection` is exactly `{kind:"overview",branch:null|string}`,
`{kind:"pull-request",number:decimalString}`, or
`{kind:"workflow-run",runId:decimalString,attempt:1..1000}`. Numbers remain
decimal strings where GitHub IDs can exceed JavaScript's safe integer range.
The existing local status relay emits `github-activity-status`; it never starts
another provider read. The bridge unwraps the event through its existing
listener contract. Preview has no Activity port.

Before admission and again at original READY/GO, the native path checks the
same connection/session, project/root/registration, edit stamp, account and
repository pins, peer owners, clock and cooldown. The Supervisor's existing
one-use GO claim, child/IO/native-management joins and first-failure cleanup
deadline remain authoritative. The read uses at most 60 seconds, also bounded
by the original connection expiry. Status, navigation and Stop do not renew it.

Only the original typed Supervisor receipt can settle the operation. Unknown
cleanup remains absorbing, including after a later nominal terminal reply.
Ordinary read completion preserves the connected credential session; credential
retirement completes only when actual private retirement was requested. The
same ConnectionState pending/material/retirement/heap census and sibling GO
gates include this read. No public result, fixture or metadata count supplies a
native admission or finality proof.

## What each explicit read means

Every schedule begins with fresh `/user` and repository immutable-ID checks.
All requests use fixed GET roles on `api.github.com`; no generic HTTP endpoint
or additional auth discovery is introduced.

| Selection | Maximum GETs | Data and final comparison |
| --- | ---: | --- |
| Recent repository activity | 5 | First 30 open PRs and workflow runs; final repository-ID check, including empty pages |
| This repository's branch | 7 | Same lists plus exact own-branch ref before/after; a fork with the same branch text is not this branch |
| One pull request | 8 | PR, first 30 changed filenames/counts, review records, exact-head commit statuses/check runs; repeat PR ID/head/base and file-count comparison |
| One workflow attempt | 5 | Exact run/attempt and first 30 jobs bound to its run ID/attempt/head SHA; repeat the same attempt comparison |

These sequential reads are not an atomic snapshot. An exact old run attempt is
not claimed to be the latest attempt. **GitHub's review endpoint returns a
chronological first page**, not the latest review per person: the panel says so
and never converts review records into overall approval or branch-protection
eligibility. Zero checks, skipped/neutral conclusions and omitted permissions
are not a pass. Full diff/run links are canonical `https://github.com/…` links
constructed from admitted coordinates and numeric IDs, never provider URLs.

Sections distinguish a bounded page from a complete reported count and from
403/404 inaccessible data. No-total lists always remain windowed, even when
empty. Missing access is not proof of absence. Duplicate/malformed/oversized
rows refuse the result rather than claiming a complete partial list. PR bodies,
patches and other surplus fields in the private upstream response are never
projected into public results; no logs or artifact-content endpoint is called.

Private HTTP bodies remain limited to 256 KiB each and 2 MiB total across at
most eight requests. Initial/GO frames remain 8 KiB; the typed final/public view
is at most 128 KiB. Owned result capacity, not just serialized length, is charged
against the 2 MiB retained Activity cap. Existing runtime core packaging already
inventories these three Python leaves into held `core.zip`; the fixed Setup
bootstrap, native source roster, slots and descriptor count are unchanged. The
normal existing core-file/count/byte limits still apply; no qualifier flag,
runtime installer, source path or new journal is added.

## UI and lifetime integration

The single App-owned controller retains every actual subscribe/read/status/
Stop Promise and the original port. It latches before invocation and rechecks
context/revisions/peers after synchronous listeners. A terminal event cannot
discard a pending invocation; a historical admitted reply cannot rewind newer
native status. Only a known native pre-admission refusal releases that attempt
without inferring completion. Lost acknowledgements, malformed replies and
contradictory terminal evidence stay unknown and cannot enable retry/reconnect.

Account/repository/project/service and workspace-intent changes invalidate
results and detail-row actions. Original Status/Stop controls remain reachable
globally while work is active/unknown, including after navigation. Detail reads
must come from the exact still-current overview object and row. The optional
branch draft survives failures; a local Git branch is only an explicit cached
suggestion, not a fresh remote observation. No mount, status or page navigation
starts HTTP work.

## Root integration and verification boundary

Apply `github-activity-hooks-20261020.patch` only after integrating the new leaves.
It changes 19 existing targets: common HTTP/Setup dispatch; Supervisor profile
and receipt arms; ConnectionState and its Publication/RepositoryCreate/
Enrollment peer gates; Document status/GO; lib plus the manually composed
installed-observer graph; shell relay/RAW commands and existing permissions;
App, types, bridge, GitHub page slot and the focused Node test roster. Existing
read/write routes and prepared reviews remain independently owned. The patch
was checked against integration `e46ebe512633ac7dc4de2647ee4126b1fb70e9c9`.

Author verification on complete current-source projections plus intended hooks:

* 15 inert Python tests passed (0.013 s): closed schedules/roles, identity and
  moving selection, permission gaps, privacy projection, exact attempts,
  bounded counts, cooldown and single original budget. No real HTTP/process.
* 16 Node tests passed (339.280362 ms, zero skips): actual composed bridge and
  controller with fake ports, original Promise/event order, context/API/ABA,
  reentrancy, Stop, refusal versus lost acknowledgement, stale row actions,
  parser limits, disposal and listener-close uncertainty.
* Full projected frontend `tsc --noEmit` passed. No React DOM/Vite/native proof.
* New/shared Rust syntax parsed with rustfmt only; four DATA/control tests below
  are defined **but unrun**. No Cargo, Mac, installed runtime or live-provider
  qualification is claimed. Root must compile/test the actual composed graph.

Focused commands after actual integration (no package install required):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B tests/unit/test_github_activity.py -v
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/github-activity.test.mjs
```

Root's eventual Rust selectors are `activity_data_tests::` (three) and
`activity_control_tests::activity_stop_can_return_only_exact_retained_terminal_data`
(one). They test closed DATA/control behavior, not genuine native finality.
