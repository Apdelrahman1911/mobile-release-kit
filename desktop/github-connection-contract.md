# GitHub connection: session-only authentication and observations

**Device flow status: authored source, not native-qualified or delivered.**
The advanced-token and device paths have separate exact-source native selectors.
Device login stays unavailable until both the device and final-read profiles are
qualified and the publisher supplies its real registered public App configuration.
A registered command or a supplied-data test cannot activate either selector.
Historical read-only evidence below is not evidence for the changed device source.

The guided screen distinguishes local workflow-file planning from GitHub
observations. Enter the **application** repository as `OWNER/REPO`; it is not the
toolkit repository. Help explains where to find each value and that observed
account/repository metadata does not establish effective token grants, Actions
policy, correct workflow contents, installed secrets or release readiness.

## Implemented interface

- `github_connection_status {}` observes retained native state only.
- `github_connection_connect_token {projectId,repository,token}` admits one
  explicit advanced-token read under the original document's mutex. It never
  replaces another session. The native project ID comes from the picker registry,
  not a renderer path or a Git remote.
- `github_connection_start_device {projectId,repository}` admits one deliberate
  publisher-bound device flow. It accepts no renderer client ID, endpoint or scope.
- `github_connection_open_device_page {sessionId,expectedRevision}` returns null
  or a closed error after one fixed OS handoff. The actual main-thread callback
  rechecks current document/project/session/revision/expiry before opening only
  `https://github.com/login/device`, outside all document/registry locks.
- `github_connection_refresh {sessionId,expectedRevision}` is one new explicit
  observation, not a replay. Original account/repository IDs stay pinned.
- `github_connection_inspect {sessionId,expectedRevision,stage,name}` explicitly
  observes one canonical environment input's metadata using the same original
  session, identity pins and read ticket. It accepts no path, URL, type or value.
- `github_connection_disconnect {sessionId}` immediately retires credential use
  and stops only that session's original ticket. It remains available when new
  reads are refused. It neither revokes a GitHub grant nor affects Store state.
- `github-connection-status` is best-effort safe status data from the existing
  100ms relay. Status repairs missed events; neither event nor UI arrival order
  is authority.

Only the closed `github_connection_refused_*` codes documented in the native
session module establish definite **pre-admission** refusal. Later startup,
transport and cleanup failures are retained session outcomes. Generic IPC errors,
an overtaking idle Status, an event subscription failure or a timeout must not
cause token replay or inferred refusal. One nonsecret retirement intent survives
lost Connect replies, context changes and UI disposal; a late exact session is
usable only for retirement, not restoring an abandoned connection.

## Credential and transport boundaries

The password input is uncontrolled and cleared synchronously after its one
handoff and on context/gate loss. No token belongs in React/controller/draft
state, public DTOs, event/error text, files, logs, Git, environment or arguments.
Native state retains at most one credential and one active original native step. The
private request uses one bounded buffer, a fixed helper and private stdin; this
does not claim complete allocator, framework or operating-system erasure.

The final read profile uses only fixed GitHub.com HTTPS GETs: account, explicit repository,
up to two workflow-metadata pages and the closing repository-identity bracket.
At most five calls, no arbitrary URL, redirects, automatic retries, CLI helpers,
ambient proxy/CA/credential lookup, remote HTML or Store/mutation/dispatch path in authentication.
The bundled CA is a separate required, bounded packaging input. Its actual
source/runtime/loader custody must remain bound to the native qualification.

The read shares the existing Supervisor's two slots, original startup-inclusive
10-second endpoint and first immutable 2-second cleanup allowance. No session
driver, watchdog, extra periodic task, guessed PID/group or replacement joiner is
introduced. Pending and RetainedUnknown are not final receipts. Only original
resource/IO/management settlement can produce Settled; late settlement may free
material, never erase prior cleanup uncertainty.

## Device flow and public status v2

Public status is schema2; help and safe read facts remain schema1. Required
nullable `authorization` is present only for a checking session with a running
`authorize` operation. All account/repository/automation facts stay not-observed
until the original final identity bracket settles. Capability includes
`deviceLogin` (publisher-unconfigured, not-qualified or available) and a nullable
control-safe publisher name of at most 96 UTF-8 bytes. Available describes a
qualified profile, not transient permission to start another operation.

| Phase | userCode | expiresAt |
| --- | --- | --- |
| requesting-code | null | null |
| waiting / slow-down | `[A-Z0-9]{4}-[A-Z0-9]{4}` | original UTC expiry |
| checking-access | null | same original UTC expiry |
| terminal, Disconnect or Unknown | authorization itself is null | |

One public `github-authorize-{sequence}` spans one private Start, sequential
Poll originals and the final read; receipt IDs never replace that public ID.
The native authorization endpoint is at most 15 minutes from admission and may
only shorten. Start calls `github.com/login/device/code`; Poll calls
`github.com/login/oauth/access_token` with the original private device code and
fixed device grant type. Bodies use form encoding; JSON responses are capped at
64 KiB. No client secret, returned URL or repository authorization override is used.

The existing relay separately drives due work; Status and receipt reconciliation
never admit a poll. Waiting retains no child. Each step reuses the Supervisor's
original custody/finality and has an endpoint no later than its own start+10s,
the authorization end or the credential end, plus the existing 2s cleanup bound.
A next poll is permitted only after the previous original settles with explicit
pending/slow-down, and no sooner than settlement+interval (minimum5s). Slow-down
uses max(previous interval+5s, returned interval). There are at most180 polls.
No timeout, lost reply, Unknown or ambiguous transport result authorizes replay.

The device result mailbox is consuming, not Clone/Debug. Secret-bearing outcome
containers are also non-Clone/non-Debug; unsuccessful Rust disposal zeroizes
owned secret strings and request/output buffers. Python refresh material is
excluded from the private native response and discarded; no allocator-wide or
OS memory-erasure guarantee is claimed. Late/cancelled/expired/Unknown positive
results cannot connect or restore admission. Failed Authorize requires settled
Disconnect followed by new deliberate Sign in, never Refresh.

`desktop/github-device-publisher.json` contains only public publisher data and
is compiled into Rust; it is not a new runtime resource. This source supplies
`publisher:null`, not a fictitious registration. The fixed build script binds its
digest; only validated public clientId enters the private helper request. A
separate device manifest/protocol/publisher-digest tuple stays unactivated until
new exact-source native evidence exists. No preparer/stager/resource-roster
migration is needed for this public static file.

## Read-only environment/input metadata (P1)

**Authored source only; no new native qualification, live service result or
delivery is claimed.** This is not remote provisioning. Before first inspection
the public schema2 shape is unchanged. After an attempt, optional
**inputMetadata** contains exactly:

- **selection: {stage,name}** for the actual original request, not the UI's latest
  dropdown selection;
- **environment: Fact<{id,name}>**;
- **field: Fact<{name,kind,createdAt,updatedAt}>**.

The three environment/secret/variable fact flags are derived from actual retained
values as **metadata-only** or **not-run**; they do not assert current credential
validity or a fully configured environment. Refresh and retirement stale these
facts, preserving their original selection and observation time. Public metadata
cannot appear on Connect/Authorize, revive on the same settled operation, or
survive a removed session. Successful Inspect requires its original metadata.

The private **mrk-github-input-metadata/1** request extends only the read params
with **stage** and **name**, and requires both original account/repository IDs.
The fixed environment and secret/variable classification come from the core's
shared **ENVIRONMENT_NAMES / ENVIRONMENT_INPUT_TYPES** authority, also used by
credential requirements. Local PATH alternatives, arbitrary names and
renderer-supplied field types/routes are not admitted.

One original helper makes at most five GETs:
account → repository-before → named environment → selected field →
repository-after. An ordinary environment refusal may omit only the field and
still bracket repository identity. Authentication/identity/malformed/rate-limit/
transport failures stop further reads. P1 uses documented REST version
2026-03-10 with owner/repository environment routes; the ordinary workflow
listing remains on its existing version. Environment metadata requires Actions
read; field metadata requires Environments read. Reported repository roles
are not effective grants; the app never requests a broader grant automatically.

The shared transport's 10s operation budget, body/header/TLS limits, 1MiB total
body bound and 64KiB final response bound remain. P1 allows at most4,000 JSON
nodes per reply (five replies remain within the original20,000 aggregate).
Variable responses include a value upstream; it is counted against bounds and
discarded before native/public output. Secret values are not returned by this
GET. Only bounded projected metadata reaches the original read receipt.
No result is a log, journal, credential asset or persisted readiness receipt.

Inspect requires a current observed account/repository under the existing
document/registry-generation check. It retains the exact selected field until
original settlement, reuses the same Supervisor profile and clamps admission to
the existing credential endpoint. A different returned selection is
response-invalid and retires credential use without erasing cooldown. Unknown,
expiry, cancellation, revocation, quit and lost IPC acknowledgements retain the
ordinary owner/finality rules. Status does not admit or retry Inspect.

Saved-local requirements come from existing core validation only when it
matches the observed saved configuration snapshot and no invalidating save/read/
validation remains. The UI labels that snapshot separately from remote
metadata. The network helper receives no project root or configuration and
retains its no-filesystem network profile. These sequential observations are
not an atomic remote snapshot and prove neither local/remote source equivalence,
input applicability, effective permissions, environment protections nor readiness.
HTTP404 means missing **or inaccessible**, not confirmed absence.

Multi-field provisioning is not implemented: independent writes could expose
mixed credential or operation-commitment groups to workflows. Any later write
design needs its own reviewed atomic group-consumption contract, explicit
consent, reconciliation and native evidence; P1 does not grant that authority.

## Lifetime, errors and recovery

The native 60-minute ceiling starts at admission using one full-precision
monotonic/wall-clock pair. Known expiry may only shorten it. Refresh, Status,
clock changes, page navigation and help reload cannot renew it. The displayed
UTC value is informational, not a renderer timer or an observed server expiry.

The current live transport has no evidenced GitHub expiration-header grammar:
an absent header means unknown, while a present unsupported/duplicate header
refuses with `response-invalid` and retires the credential. Independently valid
rate-limit information survives that refusal. Known retry-not-before delays up
to seven days use the original native settlement time, not a delayed Status
sample. Longer/unrepresentable limits and native deadline overflow block the
original document. Disconnect/replacement credentials cannot reset those limits.

HTTP401 anywhere, identity change, response-invalid, document loss, admitted
project selection and accepted quit retire credential use. A cancelled picker
does not restore it. Declining quit preserves the existing connection without
renewing its clock. A fixed failed read can be explicitly refreshed only after
actual settlement, while the original credential/pins remain valid, cooldown
has elapsed and native capability permits it. Helper work timeout is not proof
that the credential itself expired.

A fresh account may remain connected when repository/workflow observations are
unavailable. Old valued facts become stale; unavailable or skipped observations
must never look fresh. A settled operation's identity/reason is immutable.
Subsequent retirement uses a distinct preallocated Disconnect identity. A later
absorbing cleanup uncertainty uses its own preallocated identity if the visible
operation was already settled; it never rewrites that earlier terminal result.
Pending retirement remains nonterminal until its original final receipt.

Document loss, poison and counter exhaustion cannot create a new owner or wrap
revision authority. Exhaustion freezes one redacted unavailable snapshot while
retaining unresolved material for genuine settlement. Quit/exit additionally
requires GitHub material and original ticket settlement; ordinary vault locking
does not require GitHub disconnection.

## Verification still required

Supplied-byte/projection/clock/controller tests cover the stated logical
contracts only. Original helper/process/pipe lifecycle, native document/picker/
quit integration, real TLS/socket faults, exact CA/runtime/loader custody and
each supported platform require separately reviewed disposable native evidence.
No Linux mock is macOS/Windows evidence. Packaging, credential interoperability,
GitHub App registration and complete Desktop delivery remain separate work.

The dedicated development TLS fixture now describes sixteen fixed synthetic
cases: the original nine T1–T3 trust/framing cases plus T6 aggregate headers,
streamed body, chunk metadata, unauthorized early stop, invalid expiry with a
preserved 120-second cooldown, closing repository-identity change and redirect
refusal. This is source preparation, **not a passing native result**. The
original T1–T3 run `35303950385` / attempt 1 failed in its outer native step;
cleanup was skipped, and missing diagnostics do not establish its cause.

For the seven new cases, success additionally requires the original product
settlement, original completion-writer return/join before the unchanged peer
deadline, and separate peer-observed exact byte+EOF and original-listener
finality. The fixed redirect sink must independently observe no connection and
close. Only the body case receives larger byte ceilings. Narrow expected
client-close categories retain actual sent-byte floors; they do not measure
client reads or heap allocation. The same workflow compiles once, validates the
complete closed receipt and independent outer wait, then cleans only its finite
positively settled inventory. Failed or unknown finality cannot authorize that
cleanup. No additional workflow, product gate or public output path is added.

Ambient proxy/default-CA/keylog behavior, real network deadlines, native trust
file faults, packaged SSL-runtime custody and native GUI/document callbacks
remain unqualified. A sixteen-case receipt would qualify only its exact source,
fixture and original run—not real GitHub authentication, every supported
platform, standalone distribution or production activation.

### Authored Linux TLS follow-on: ambient inputs and real deadlines

The synthetic TLS lane has a separately claimed T4/T5 follow-on: six fixed
hosts-routed cases and one separately isolated withheld-DNS case. It uses the
same original compiled artifact as T1–T3/T6, with two explicit input-manifest
anchors. Four cases exercise the ordinary Supervisor/ticket; three explicitly
exercise a fixture-owned copy of the genuine bootstrap, not a fabricated
product runtime or a second product supervisor. These are authored checks,
**not a claim of execution, native qualification or production enablement**.

The ambient cases compare the correct sibling CA against a wrong ambient CA,
and the wrong sibling CA against a correct ambient CA. Original proxy-listener
observation, a genuinely writable control file, absent keylog, and the original
owner child's observed cleared environment are distinct required facts. An
empty ambient CA directory does not qualify populated/platform trust stores.

The deadline cases withhold actual DNS replies or handshake output, or offer a
real incomplete TLS response one byte per second. Owner cases require the
unchanged startup-inclusive10s endpoint/+2s cleanup and every original join.
The direct helper-read case separately requires the normally driven original
response reader to observe its complete typed refusal10–12s after actual spawn,
with first GET by2s and continued wire progress; delayed waits or generic errors
cannot establish that measurement. Each resource endpoint still starts before
the original acquisition and lasts16s, never restarts at readiness or spawn.

DNS qualification is deliberately restricted to the selected Ubuntu24 GNU
runtime: genuine Python glibc2.39 observation, exact mapped-library equality
after privilege drop, fixed configuration and absent applicable cache sockets.
It neither qualifies arbitrary NSS/platforms nor claims getaddrinfo is itself
10s-bounded/cancellable. Each namespace's actual outer wait remains independent
of its closed inner receipt. Any unknown original prevents the next namespace
or cleanup-to-success; only exact private task outputs can be removed. Reports
retain the two follow-on receipts separately from original T1–T3/T6 limitations.
