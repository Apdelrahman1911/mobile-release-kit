# GitHub connection and read-only observations

## Current status: guidance integration and read-only source preparation (G1A)

This increment is **not a working GitHub connection**. It adds a credential-free
core projector and help resource, closed public/native wire contracts, an inert
controller and a status/help component. The separately reviewed lead composition
mounts that component with no native port and null status, exposes nullable core
help through the catalogue, and registers the pure Rust module for compilation.
No code in this increment
collects a token, implements a live observation port, registers a native command,
launches a helper, authenticates, contacts GitHub or changes a capability gate.
This pure-help composition does not activate a backend.
The new tests are authored cases, not verification results.

Local workflow preview/Apply stays independent. Installing local caller files
does not push them, authenticate an account, configure remote resources or make
a release ready. Remote mutation and workflow dispatch remain unavailable;
template compatibility and release readiness remain unknown. Existing credential
assets, configuration, project history, Store guards and protected-environment
requirements are unchanged.

## Pure core boundary

`mobile_release.api._github_connection` is not a network API method.
Its three entry points have separate, narrow roles:

- `project_github_observations(data)` projects **supplied DATA**, not transport
  evidence. It takes no credential and has no filesystem/network/environment,
  subprocess, Git, `gh` or native-session authority.
- `stale_github_observations(facts, reason)` validates and deep-copies earlier
  facts, marking retained values stale without changing identities/times. It
  does not read a clock, extend a deadline or settle an operation.
- `github_connection_help()` reads only the fixed bundled
  `api/data/github-connection-v1.json` resource. Invalid/missing help produces a
  fixed refusal, not fallback instructions or credential entry. The catalogue
  catches only its `resource_unavailable` refusal and returns
  `githubConnection: null`, preserving existing catalogue/Setup/Apply help.

The exact projector input keys are:

```text
repository, observedAt, expectedAccountId, expectedRepositoryId,
account, repositoryBefore, workflowPages, repositoryAfter
```

Both expected IDs are required nullable fields. A repository ID requires an
account ID. `repository` is the explicit application `OWNER/REPO`, using the
existing core repository grammar, not the toolkit coordinate or an inferred Git
remote. `observedAt` is supplied RFC3339 UTC-seconds display data, not time or
custody authority.

Each supplied read is exactly `{status, body, failure}`. HTTP 200 has a bounded
object body and `failure: "none"`. Other HTTP statuses require a null body; raw
GitHub error bodies never enter this interface. A supplied transport failure has
null status/body and a finite failure reason. There are at most two 100-record
workflow pages and five reads total, 256 KiB per body and 1 MiB for the complete
input, with depth/node bounds. The future transport must independently enforce
the actual IO/framing/TLS bounds; this projector cannot certify them.

The output is exactly `{schemaVersion: 1, account, repository, automation}`.
Unknown upstream success fields are bounded then discarded. Only account ID and
login, repository identity/default branch/visibility/archive/reported roles, and
four core-roster workflow metadata rows are returned. IDs are canonical positive
u64 decimal strings; Python converts upstream integers without a JavaScript
floating-point round trip. Display strings are bounded plain text without
control/format characters. No token, email, avatar URL, response header, raw
diagnostic, arbitrary URL, native capability, revision, operation, session or
expiry is returned.

An ending repository read brackets the original immutable identity. Changed
expected account/repository IDs or a changed target coordinate refuse adoption.
This bracket is not an atomic snapshot. Workflow selection uses the exact
existing `workflow_payloads.GITHUB_WORKFLOWS` paths, not names, URLs or arbitrary
YAML. Complete bounded coverage permits `not-listed`; incomplete coverage permits
only listed/unknown. Duplicate IDs/paths, inconsistent counts or ambiguous pages
become limited/unknown rather than verified absence. `not-listed` means only
not returned by this Actions listing, **not absent from Git**.

401 is unauthorized, 403 forbidden/possible organization or SSO policy, 404
not-found-or-inaccessible, 429 rate-limited and 5xx network-unavailable. These
never become verified workflow absence or instructions to escalate permissions.
Malformed data yields a fixed redacted error. Earlier observations can be marked
stale; they must not be silently relabelled fresh after failure.

## Public status and proposed private wire

The TypeScript and registered pure Rust modules describe this closed status:

```text
schemaVersion, revision, capability, session, operation,
account, repository, automation, facts
```

All nullable keys are required, with explicit null values. Revisions are positive
nonwrapping u32 values; session/project/operation IDs use the existing bounded
opaque-ID grammar. Status is at most 64 KiB, depth 12 and 2000 nodes. The public
wire never carries a credential.

Each `Fact<T>` has `{state, value, observedAt, reason}`. `not-observed` and
`unavailable` have null value/time; `observed` has a value/time and no failure;
`stale` retains a value/time with a finite stale/failure reason. Child values
require parent values, and a fresh repository/workflow observation requires a
fresh parent observation. Reported pull/push/admin roles are not effective token
grants or authorization of a future mutation.

Sessions are checking, connected, expired, disconnecting, failed or
cleanup-unknown. Connected requires an observed account and explicit expiry; it
does not imply repository access or automation administration. Operations carry
their original ID, connect/refresh/disconnect kind and running/settled/
cleanup-unknown phase. Checking and retiring states cannot carry fresh observed
facts. Cleanup-unknown requires unavailable capability and matching operation
uncertainty, and cannot be cleared by a late positive result.
Any fact-level cleanup-unknown reason must agree with that same session/operation/
capability graph; a connected-looking status cannot hide cleanup uncertainty in
an unavailable child fact.

The fixed disclaimer is
`facts.repositoryActionsSettingsObservation: "not-run"`: repository Actions
**settings/policy** are unobserved even when workflow metadata has been listed.
Environment, secret, variable, protection and runner observations remain not-run;
remote mutation/dispatch remain false and readiness/compatibility remain unknown.

Exactly four future commands are described, but none is registered here:

| Command | Exact arguments |
| --- | --- |
| `github_connection_status` | `{}` |
| `github_connection_connect_token` | `{projectId, repository, token}` |
| `github_connection_refresh` | `{sessionId, expectedRevision}` |
| `github_connection_disconnect` | `{sessionId}` |

Requests are at most 8 KiB. A future advanced token is nonempty printable ASCII
without whitespace, at most 4096 bytes; there is no trimming or token-prefix trust.
The TS request-shape helper returns only a Boolean, never a private object. Rust
credential-bearing inbound request types have no Debug/Clone/Serialize, and all
rejections use fixed diagnostics. The private future helper envelope is fixed
`mrk-github-readonly/1` with `{protocol, id, params: {repository,
expectedAccountId, expectedRepositoryId, token}}`; both expected IDs are required
nullable fields. This is a wire description, not a private pipe/launch path.

## Inert UI coordination

`GitHubConnectionController` accepts only an explicitly supplied observation
port. The interface has Status, Refresh, Disconnect and subscription methods,
**no Connect/token method and no live implementation**. Preview/unavailable ports
are never called. The exported entry-availability constant is false and the
component has no active credential input. Hypothetical available statuses in
inert tests do not change any runtime capability.

The controller subscribes before its first retained Status read. Document,
project-generation, target and service changes invalidate callbacks before
asynchronous work, including away-and-back changes and late listener teardown.
Admission is also rechecked immediately before invoking a queued Status or
Refresh: a synchronous subscriber can retire the context, disconnect, invalidate
help or deliver a newer status before the original call has even been sent.
Older revisions cannot replace newer events; equal revisions must be immutable.
Old read rejections and malformed old read replies cannot erase newer valid
events. Original account/repository IDs stay pinned through temporary unavailable
facts. Expiry cannot extend in a continuing session; display dates never decide
admission or trigger renderer timers.

Busy rejects **new Connect/Refresh**, not retained Status or immediate
exact-session Disconnect. Refresh uses the original session/revision and pins
its acknowledged operation ID. A lost reply stays uncertain: no automatic retry,
queued replacement, assumed settlement or latest-operation adoption. Status can
observe the retained original state; Disconnect can retire the original session
even during Refresh. Old positive replies/events cannot resurrect a locally
retired session. Cleanup-unknown stays blocked.

Context changes and disposal may issue a best-effort exact-session Disconnect;
they are not evidence that native consumers stopped, memory was erased or remote
grants were revoked. Replacing a service with unresolved retirement remains
blocked. The future original owner must independently enforce document identity,
deadline, cancellation, successful settlement and secret lifetime.

`GitHubConnection.tsx` is isolated presentation using existing icons and help
buttons. It labels retained/stale facts, reported roles, limited metadata,
expiry, failure and unknown cleanup without rendering remote HTML or fetching
avatars. Its separate Remote setup card stays unavailable. Fixed core help is
available before a valid connection input; missing/previous help never enables
entry or Refresh, but does not disable Status/Disconnect. Input IDs are repository
and token; guidance IDs are authentication, permissions, session-memory,
repository-identity, automation-observation, remote-changes and revocation.

## Narrow lead-owned integration

The ten-file authoring freeze is preserved separately. Its accepted SOURCE
amendment is now composed through these narrow seams; none activates a backend
or supplies verification evidence:

1. **Core help only:** `api/_catalog.py` and `api/contracts.py` expose nullable
   `githubConnection` help. Only the fixed guide is read; unrelated errors still
   propagate. Projection is not registered as a query or network method.
2. **Useful disabled UI:** `types.ts`, `bridge.ts` and `preview.ts` consume the
   strict core guide. Missing/invalid additive help becomes null. `App.tsx` mounts
   the component on the GitHub page with no port or native status/session/revision.
   Bootstrap/service and project-selection changes invalidate help synchronously;
   a separate identity token prevents late catalogue replies from restoring it,
   including an away-and-back selection. Retained help is marked previously
   loaded. Reloading service/guidance uses the existing bootstrap, not a fake
   connection. Existing Setup/Apply/configuration/asset ownership is unchanged.
   Local files, connection observations and remote setup keep separate claims.
3. **Pure Rust registration:** `lib.rs` declares `github_connection_protocol`.
   This makes its wire types and inline tests reachable by the real headless
   crate without adding a handler, owner, service, shell command or capability.
   Earlier compilation before this declaration covered none of this module.
4. **Regression registration:** the normal UI test script includes the new
   connection leaf after all existing leaves. Focused validation still uses only
   the affected leaves; registration does not justify repeating the whole suite.

The new TS/TSX files already match `desktop/tsconfig.json`'s existing include
patterns, so the existing TypeScript no-emit entry point can typecheck them
without mounting the component. Node strip-types cases do not typecheck TSX or
prove rendered UI behavior. No dependency/lock/build/runtime change is needed
merely to author these isolated files.

## Remaining live-route obligations

A distinct original-owner/TLS/credential-lifetime review is mandatory before a
token route exists. Reuse one closed private original-supervisor profile rather
than a new job owner or passive API execution route. Only five fixed verified
HTTPS GETs on the admitted GitHub API host are proposed; no redirects, returned
URLs, retries, ambient proxy/CA overrides, external tools, hooks or TLS bypass.
Actual private framing, successful original settlement, failure cleanup, cooldown,
response bounds and target binding need fresh native qualification. HTTP 200 or
a helper exit alone is not successful original settlement.

The proposed native ceiling is 60 minutes from acceptance, shortened by known
expiry, never extended by Status/Refresh/navigation. Credentials remain in
private session memory, not project assets, environment/argv/temp files, logs,
renderer stores or configuration. Retirement blocks admission immediately;
release follows actual settlement. Unknown cleanup retains ownership. Do not
promise erasure of allocator/serializer/OS copies.

Preferred App/device login separately requires the owner's publisher registration,
public client-ID/permissions/distribution binding and qualified fixed native
browser/authentication flow. This increment invents none of those. Advanced
session-only token development does not require a keyring or a publisher App,
but still needs its own native qualification. Optional persistence needs a later
qualified OS-keyring lifecycle; plaintext fallback is never allowed. Local
Disconnect is not remote revocation; the fixed help gives manual GitHub Settings
navigation without opening a browser or retaining a credential.

## Focused checks to propose after source review

No command below has been run for this increment. Bind the actual source/tool
identities and admit execution separately; do not fetch/install dependencies or
rerun unrelated historical matrices to qualify this pure boundary.

- From the repository root:
  `PYTHONPATH=src python3 -B -m unittest discover -s tests/desktop -p test_github_connection.py`.
  One supplied-DATA/help leaf covers whitelisting, identities, complete/limited
  listing, finite failures/bounds, stale copies and ambient-IO tripwires.
- From `desktop`:
  `node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 tests/github-connection.test.mjs`.
  One fake-port leaf covers closed DTOs/commands/help, public privacy, generations,
  Busy retirement, reply/event races, lost replies, expiry and sticky cleanup.
- From `desktop`, with an already admitted local compiler/dependency tree:
  `node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json`.
  This is the existing no-emit typecheck entry point, not a build, browser or
  native qualification result.
- **Only after the separately authorized module declaration**, propose the real
  crate leaf from `desktop/src-tauri`:
  `cargo test --offline --locked --no-default-features --lib github_connection_protocol::tests`.
  Its build script/dependency compilation are still execution boundaries needing
  admission. The inline cases concern strict wire/null keys/facts/privacy only,
  not a live credential, owner, TLS profile, secure storage or device flow.

No new harness, network test, package build, native GUI or existing gate flip is
needed to establish the limited claims of G1A.
