# Create a draft pull request — bounded vertical slice

This adds one explicit **same-repository draft PR** to the existing authenticated
GitHub connection and Setup/HTTP owner. It does not push commits, create branches,
merge, mark ready for review, trigger a workflow directly, or authorize publishing
or release. Existing repository workflows **can run when the PR is created**;
the separate confirmation says so. Both remote branches must already exist.

## User flow and privacy

One retained controller/form: Base branch → Head branch → title → optional
description → **Review draft pull request** → exact text/branch preview and
CI-trigger confirmation → **Create draft pull request**. Last-read default/local
branches are suggestions behind explicit buttons, not automatically selected or
claimed current. The preview links to the full comparison using admitted
repository coordinates and exact commit SHAs; it shows at most four file names,
not patches. Status, original Stop and unused-review Close remain reachable on
other pages. No navigation, mounting, status query or retry starts a provider
write. Local text survives context changes and failures; old consent does not.

Title/description exist only in the local draft and original private request/GO.
They are not public status/journal fields or diagnostics. Native `Draft` is not
Debug and zeroizes its retained text on drop. Python cannot promise immutable
string erasure; it releases those references after the bounded invocation and
zeroizes its private GO receive buffer. No token, native home or source path is
accepted from the renderer. Saved records contain hashes of approved text and a
small marker, not that text. Links are constructed, never arbitrary provider URLs.

## Existing authority and finite schedule

The new typed `GitHubPullRequest` profile borrows the **same Supervisor**, Setup
runtime/source descriptors, original clock/READY/GO/EOF/C-A-W/management/native
joins, HTTP implementation and private journal custodian. There is no additional
task framework, process owner, resource slot, qualification flag or timeout reset.
Doc rechecks the exact registered root/generation and saved-edit stamp before
one-use GO. ConnectionState owns the token, selected `/user` immutable account ID
and repository ID. Other original operations/reviews remain reciprocal gates.

Every invocation has the existing **60-second** work limit (also bounded by its
original connection/consent deadline), at most **12 fixed HTTP requests**, body
limit **256 KiB each** and **2 MiB aggregate**, including the actual shared `_Budget`.
Prepare uses nine GETs: `/user`, repository, both branch refs, exact-SHA comparison,
the first filtered open-PR page, then both refs and repository again. Create
repeats these exact checks, writes an immutable intent+claim, makes **one POST**
with the approved title/body plus marker and `draft:true`, then checks the returned
immutable PR ID/number and repository. No arbitrary URL, verb or body is admitted.

Repository write permission is a prerequisite, not a grant of PR permission or
proof of branch rules. Unknown/access/rate/pagination failures never become
absence. An empty filtered page is only a point-in-time observation; any Link or
ambiguous Link on an empty list refuses it. Comparison and readback remain
sequential observations, not an atomic lock over GitHub.

The same journal custodian holds at most 32 attempts/96 immutable leaves; files
and total inventory have fixed bounds. A repository-ID + base/head pair is fenced
across new nonces, accounts and local project aliases. Loaded intents are read-only
and cannot claim another POST. No deletion or automatic reset of a branch-pair
fence exists in this slice, even after a PR closes. **Pending/Reconcile use only
GETs.** A matching marker after lost POST is `found-unattributed`, never proof this
original created it. Only an actual 201 immutable ID acknowledgement, then exact
readback, yields `created-observed`. A retained 201 with failed readback is clearly
`acknowledged-unconfirmed`. A failed durable receipt preserves the actual 201
in the current original but cannot reconstruct it from a later name/marker.

Stop cannot undo a sent request. Lost Start/Close replies and original cleanup
Unknown remain owned and block replay/reconnection. Events cannot release an
unsettled invoke; historical coherent status cannot rewind newer evidence.
An exact native pre-admission Close refusal (for example an expired review) is
different: retain the original and local text, disable repeated Close, and require
an explicit fresh **Check task status**. Old events or a poll started before that
refusal cannot bypass this check; an uncertain/lost acknowledgement stays Unknown.
Discard removes only unused in-memory consent, never an uncertain journal fence.
Only an actual private retirement invokes shared `complete_retirement`: an
ordinary settled Prepare/Create does not disconnect or erase the connection.

## Exact Root hooks

Apply `github-pull-request-hooks-20261020.patch` (21 existing paths) after these
new leaves. It adds the closed Python profile/roles/bootstrap arm, native typed
Supervisor and ConnectionState child/GO/retirement/capacity paths, Doc integration,
seven shell permissions/handlers, and both library and manually composed observer
protocol declarations. The ordinary fixed Setup bootstrap and core archive roster
already carry Python package modules; no new held runtime descriptor is invented.

All seven commands accept **RAW UTF-8 JSON only**. Prepare is bounded at 16 KiB;
the other six at 1024 bytes, with strict duplicate/unknown-field rejection:

| Command suffix (`github_pull_request_…`) | Renderer input |
| --- | --- |
| `status` | `{}` |
| `prepare` | `{sessionId, expectedRevision, expectedConnectionRevision, draft:{base,head,title,body}}` |
| `create` | `{sessionId, expectedRevision, consentId, confirm:true}` |
| `pending` | `{sessionId, expectedRevision, expectedConnectionRevision}` |
| `reconcile` | `{sessionId, expectedRevision, marker}` |
| `discard` | `{sessionId, expectedRevision, consentId}` |
| `cancel` | `{operationId}` |

Each returns the closed native Status. Event: `github-pull-request-status`.
Status has separate original operation, unused consent, bounded pending records,
acknowledgement and observed result; it contains no approval from a public DTO.
Pending's target has **null intent**, not fabricated branch/marker/text input.

The App patch installs one controller, self-excludes only its new admission, and
adds it to original saved/passive/peer/reconnect/CLI admission guards and lifecycle
invalidation. The GitHub page renders this form once alongside the read-only
Activity view; other pages use the same controller's compact original controls.
The existing package test command includes `tests/github-pull-request.test.mjs`;
other current entries, including the agent-identity action tests, are preserved.
Activity help is mechanically corrected to distinguish this new draft-only action
from still-unfinished regular PR/ready-for-review and failed-job rerun actions.

## Verification and remaining limits

Author verification uses a finite copy of complete current Root Python/frontend
modules plus these exact hooks/leaves; no source-snippet transpilation or fake
native witness. All tool callers joined normally.

* **16 Python PASS**, inert fake HTTP + actual journal state machine with byte-map
  backing only, 0.043s: fixed 9/12 schedule and actual aggregate budget, complete
  response/identity/movement refusals, cross-nonce fences, lost POST/201, loaded
  no-write, private/public frames, Unicode and fixed GO limit/deadline.
* **18 Node PASS**, 0 skipped, 384.042ms, followed by **3 affected cases PASS**,
  0 skipped, 324.901ms (including one new Close-refusal regression; **19 unique
  cases**, not a claimed full nineteen-case rerun): real controller and composed bridge,
  RAW seven commands, exact draft review, original promise/STOP/Close retention,
  pre-invoke reentrancy and consent withdrawal, ABA/context changes, monotonic
  events, typed refusal versus lost acknowledgement, absorbing Unknown and
  GET-only reconciliation. The successor covers expired/changed Close refusal,
  older polls/events, explicit fresh Check, and lost/synchronous acknowledgement.
  Two parser typing errors were corrected without weakening runtime validation;
  full successor projected **TypeScript `tsc --noEmit` PASS** against current Root.
* **Five Rust tests authored, not executed** here: four
  `github_pull_request_protocol::pull_request_data_tests` and one
  `github_connection_session::pull_request::pull_request_control_tests` using an
  existing inert connection fixture, not native completion construction.

Focused commands (using the complete composed source, not this older WT's bridge):

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<projection>/python/src:tests python3 -B -m unittest -v unit.test_github_pull_request
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 <projection>/frontend/tests/github-pull-request.test.mjs
node <existing-deps>/typescript/bin/tsc --noEmit -p <projection>/frontend/tsconfig.json
```

Root still owns actual Rust/test-graph integration, packaging, native runtime,
real provider and installed qualification. No live GitHub request, provider
creation, native execution, build, CI or installer verification was performed by
this lane. Regular non-draft PR creation/ready-for-review, failed-job rerun,
fork PRs, local pushes and branch-fence reset remain explicitly separate work.
