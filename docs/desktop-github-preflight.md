# Desktop GitHub nonpublishing preflight

This is a separate action family, not an extension of the read-only
connection’s five-GET schedule. The current source candidate selects only the
exact installed Linux x86_64 GNU payload in the normal Desktop shell, together
with this action’s publisher-bound immutable tooling commit and canonical
caller digest. Missing bindings refuse before inspection; read-only selection
does not grant or replace this action profile. The original action-specific
runtime custody, session, consent and finality checks still apply.

`GITHUB_PREFLIGHT_NATIVE_QUALIFIED` remains `false`: this narrow source selector
and inert tests are not native runtime, journal, network, GitHub API or hosted
workflow qualification. Native/service evidence and independent implementation
acceptance remain required before delivery. macOS, Windows and the separate
GitHub release action profile remain unavailable; no global gate is enabled.

## UI journey

1. Select the application project and its explicit GitHub repository, then use
   the existing session-only connection. No new token field or token store is
   added. For dispatch, a fine-grained token needs that selected repository’s
   Contents read and Actions write access (plus GitHub’s Metadata read).
2. Enter an explicit branch and choose Android, iOS or both. **Prepare** reads
   the branch’s immutable commit and exact canonical caller, with the toolkit
   commit bound by the application publisher—not an arbitrary renderer value.
3. Review the repository/account IDs, commit, workflow, caller digest, requested
   platform, runner usage and native short-lived consent. Explicitly confirm
   before **Dispatch once**. Changed selection or original connection refresh,
   expiry, revocation or use invalidates the review.
4. **Track** reads only the known run’s original attempt. If the response was
   lost, **Reconcile** considers one complete bounded page and requires the
   entire exact request title plus repository, actor, triggering actor,
   workflow, branch, source, event and attempt identity. It never adopts “latest”.
5. After reconnecting the same project/account/repository, **Load pending**
   reads the small native per-account record directory. It performs no network
   request. An unresolved dispatch is never automatically retried.

Every important input/action has contextual `?` guidance. Navigation performs
no GitHub request, and the original local observer remains associated with an
unacknowledged action. **Read local Status** is not remote polling.

## Important limits

- The reviewed canonical workflow does not sign, upload to a Store or publish.
  It can execute trusted project code, download dependencies, use hosted minutes
  and upload diagnostics. GitHub dispatch uses a mutable branch, **not an
  atomic commit condition**. Authorized writers can replace its workflow after
  review; use a trusted protected branch. The expected-ref/source guard stops
  the canonical workflow on a moved source, but cannot control a replacement
  workflow written by a repository administrator.
- Accepted run ID ≠ observed run ≠ passing release checks ≠ release evidence.
  A completed successful run is projected only with observed successful guard
  and requested platform jobs. Skipped/missing jobs do not pass. The workflow
  can still explicitly defer private-dependency builds; reports/attestations
  are not downloaded or interpreted by this journey.
- **Stop this local action** requests original local cleanup only. It does not
  cancel a workflow accepted by GitHub. Remote cancellation, reruns, ref
  creation, secrets/variables/environments provisioning, signing and Store
  releases are outside this action family.
- One POST uses GitHub API `2026-03-10` and `return_run_details: true`. HTTP 200
  yields only a candidate exact run ID; 204, response loss, malformed responses
  or post-entry exceptions remain potentially applied. Actual service support
  and the exact job names require service evidence before enablement. Existing
  connection reads retain API `2022-11-28` and their existing five-GET maximum.

## Native integration contract

| Explicit action | Maximum fixed network schedule |
| --- | --- |
| Prepare | 6 GETs: account, repository, branch, workflow, immutable caller, repository |
| Dispatch | 4 GETs then one POST: account, repository, branch, workflow, dispatch |
| Track | 5 GETs: account, repository, attempt 1, jobs, repository |
| Reconcile | 6 GETs: account, repository, filtered runs, attempt 1, jobs, repository |
| Pending / Status / local stop | No GitHub request |

The existing document-owned `ConnectionState` retains the original credential,
monotonic one-hour ceiling, shortening-only server expiry, cooldown and
retirement. Its preflight metadata is not a second owner. The existing
Supervisor retains its original startup-inclusive 10-second operation and
2-second cleanup endpoints, original writer/stdout/stderr, child, watchdog and
join/finality chain. A distinct installed-custody domain never substitutes the
read-only domain’s ledger.

The helper first receives only nonsecret intent. Dispatch creates and syncs a
create-only intent before READY; the original writer then rechecks the actual
document, project registration, session and expiry before one-use GO. Only GO
can contain the original token. Final publication requires the same original
owner’s settled receipt. Lost acknowledgements do not release the UI latch.

The Linux journal uses no-follow retained ancestors, actual nonroot account
ownership, private directories, single-link read-only records, a nonblocking
directory lock, bounded complete inventory, exclusive creation, sync/readback
and original closes. It never overwrites or deletes records. Bounds are 64
intents / 128 entries; refusal preserves unexpected files. Native filesystem
behavior, response-loss and process-lifecycle checks are separate qualification
requirements, not proven by pure record/frame tests.

Current packaging must include `github_preflight_bootstrap.py` through the
current-only publisher roster while preserving historical six-bootstrap
supplier identities. Platform enablement and release delivery require actual
source-bound independent implementation review and applicable native/service
evidence; no physical-Mac-only requirement is introduced here.
