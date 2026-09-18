# GitHub connection: session-only read profile

**Status: implemented source under review, unavailable in production.** The
native document gate, runtime/TLS gate and renderer credential-entry gate remain
closed. A registered command or a passing supplied-data test is not native
qualification. Preferred GitHub App/device login is separately unavailable.

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
- `github_connection_refresh {sessionId,expectedRevision}` is one new explicit
  observation, not a replay. Original account/repository IDs stay pinned.
- `github_connection_disconnect {sessionId}` immediately retires credential use
  and stops only that session's original ticket. It remains available when new
  reads are refused. It neither revokes a GitHub grant nor affects Store state.
- `github-connection-status` is best-effort safe status data from the existing
  100ms relay. Status repairs missed events; neither event nor UI arrival order
  is authority.

Only the nine `github_connection_refused_*` codes documented in the native
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
Native state retains at most one credential and one original read ticket. The
private request uses one bounded buffer, a fixed helper and private stdin; this
does not claim complete allocator, framework or operating-system erasure.

Only fixed GitHub.com HTTPS GETs are implemented: account, explicit repository,
up to two workflow-metadata pages and the closing repository-identity bracket.
At most five calls, no arbitrary URL, redirects, automatic retries, CLI helpers,
ambient proxy/CA/credential lookup, remote HTML or Store/mutation/dispatch path.
The bundled CA is a separate required, bounded packaging input. No CA has been
shipped or native TLS profile qualified merely by adding its inventory contract.

The read shares the existing Supervisor's two slots, original startup-inclusive
10-second endpoint and first immutable 2-second cleanup allowance. No session
driver, watchdog, extra periodic task, guessed PID/group or replacement joiner is
introduced. Pending and RetainedUnknown are not final receipts. Only original
resource/IO/management settlement can produce Settled; late settlement may free
material, never erase prior cleanup uncertainty.

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
