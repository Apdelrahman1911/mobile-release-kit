# GitHub connection and read-only observations

## Current status: integrated read-only connection source, not enabled

The Desktop application does **not yet provide a usable GitHub login**. The
source now includes the guided connection UI, fixed native commands, session
lifecycle, original-process supervisor integration, private engine protocol and
fixed-host HTTPS transport. These extend the earlier credential-free guidance
and pure projector; they are not just an unconnected UI proposal. Native session
and TLS qualification gates nevertheless remain false. Ordinary builds refuse
credential admission before copying a token into the native session, and cannot
use a test fixture to activate the connection.

The exact commit `d84a15db77e4776c5d89e23b87b868e21fb3a314` passed the
[focused Linux native job](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/35299903903)
(attempt 1): **17 original-owner cases and 6 controlled document cases**.
Its original finality and finite cleanup evidence were independently reconciled.
The fixture exchanges synthetic private frames without contacting GitHub. This
does not verify TLS, real authentication, native WebView callbacks, macOS or
Windows GitHub behavior, an installed runtime, or a shipped Desktop application.

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
input, with depth/node bounds. The separate transport must independently enforce
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

## Public status and private wire

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

Exactly four fixed commands are registered in the native shell. Registration
does not bypass the closed runtime and connection gates:

| Command | Exact arguments |
| --- | --- |
| `github_connection_status` | `{}` |
| `github_connection_connect_token` | `{projectId, repository, token}` |
| `github_connection_refresh` | `{sessionId, expectedRevision}` |
| `github_connection_disconnect` | `{sessionId}` |

Requests are at most 8 KiB. An advanced session-only token is nonempty printable ASCII
without whitespace, at most 4096 bytes; there is no trimming or token-prefix trust.
The TS request-shape helper returns only a Boolean, never a private object. Rust
credential-bearing inbound request types have no Debug/Clone/Serialize, and all
rejections use fixed diagnostics. The private helper envelope is fixed
`mrk-github-readonly/1` with `{protocol, id, params: {repository,
expectedAccountId, expectedRepositoryId, token}}`; both expected IDs are required
nullable fields. The original Supervisor owns this private pipe/launch path;
the renderer cannot choose a helper, command line or destination.

## UI coordination and gated native handoff

`GitHubConnectionController` accepts only an explicitly supplied observation
port. The observation interface has Status, Refresh, Disconnect and subscription
methods, but no token field. A separate one-shot native handoff implements
Connect; the controller never stores its token in public state. The fixed native
port is wired, while preview/unavailable ports are never called. The exported
entry-availability constant remains false and the component has no active
credential input. Hypothetical available statuses in inert tests do not change
any runtime capability.

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
blocked. The native original owner independently enforces document identity,
deadline, cancellation, successful settlement and secret lifetime; rendered
native callback qualification remains outstanding.

`GitHubConnection.tsx` is isolated presentation using existing icons and help
buttons. It labels retained/stale facts, reported roles, limited metadata,
expiry, failure and unknown cleanup without rendering remote HTML or fetching
avatars. Its separate Remote setup card stays unavailable. Fixed core help is
available before a valid connection input; missing/previous help never enables
entry or Refresh, but does not disable Status/Disconnect. Input IDs are repository
and token; guidance IDs are authentication, permissions, session-memory,
repository-identity, automation-observation, remote-changes and revocation.

## Guidance and application integration

The earlier pure guidance composition is retained in these application seams;
the subsequent gated native integration does not turn guidance into authority:

1. **Core help only:** `api/_catalog.py` and `api/contracts.py` expose nullable
   `githubConnection` help. Only the fixed guide is read; unrelated errors still
   propagate. Projection is not registered as a query or network method.
2. **Useful disabled UI:** `types.ts`, `bridge.ts` and `preview.ts` consume the
   strict core guide. Missing/invalid additive help becomes null. `App.tsx` mounts
   the component on the GitHub page and attaches the fixed observation port.
   Native Status can explain an unavailable gate; a working observation port
   does not authorize token entry or manufacture a connected session.
   Bootstrap/service and project-selection changes invalidate help synchronously;
   a separate identity token prevents late catalogue replies from restoring it,
   including an away-and-back selection. Retained help is marked previously
   loaded. Reloading service/guidance uses the existing bootstrap, not a fake
   connection. Existing Setup/Apply/configuration/asset ownership is unchanged.
   Local files, connection observations and remote setup keep separate claims.
3. **Separate native integration:** the registered protocol and session modules,
   original Supervisor ticket, document binding and fixed shell commands now
   connect the application layers. The private read-only profile is not a
   passive API method, a general command runner or an enabled capability.
4. **Regression registration:** the normal UI test script includes the new
   connection leaf after all existing leaves. Focused validation still uses only
   the affected leaves; registration does not justify repeating the whole suite.

The new TS/TSX files already match `desktop/tsconfig.json`'s existing include
patterns, so the existing TypeScript no-emit entry point can typecheck them
without mounting the component. Node strip-types cases do not typecheck TSX or
prove rendered UI behavior. No dependency/lock/build/runtime change is needed
merely to author these isolated files.

## Implemented lifecycle and remaining qualification

The implemented token route uses one closed private original-supervisor profile,
not a new job owner or passive API execution route. The transport permits at most
five fixed HTTPS GETs on the admitted GitHub API host; no redirects, returned
URLs, logical retries, ambient proxy/CA overrides, external tools, hooks or TLS
bypass. The native job above verifies original private-frame ownership and
controlled document integration only. Real-socket TLS authentication, EOF and
streaming bounds, destination/environment isolation, DNS/handshake/read deadlines,
trust-file failure behavior and actual native document callbacks remain separate
qualification obligations. HTTP 200 or a helper exit alone cannot prove them.

The implemented native ceiling is 60 minutes from acceptance, shortened by known
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

## Verification boundaries

Focused Python supplied-data, UI fake-port and Rust state/protocol tests protect
projection, privacy, wire contracts and lifecycle decisions. The TypeScript
no-emit check covers TSX types; neither it nor pure Node tests establish rendered
native behavior. The integration was locally compiled without running a native
fixture, and its 22 selected CI/GTK contract tests passed before the native job.

The dedicated native workflow runs only its fixed original-owner/document entry
on a disposable hosted Linux runner. It binds the exact source, one compiled
test artifact, runtime, original run/attempt and finite case roster. Successful
cleanup requires original finality, not just a green assertion or process exit.
Only six named redacted JSON records are published; no raw token, private frame,
runtime payload or local evidence is uploaded.

Native/process, real-socket, namespace and GUI fixtures must not be run on a
shared development machine. Use their reviewed disposable-hosted routes after
focused local checks. Keep failed, skipped and unexecuted checks distinct from
passes, reuse unchanged source-bound evidence, and do not enable a production
gate merely because the headless fixture passed.
