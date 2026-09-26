# Desktop protected release workflows

## Availability and scope

This is a **source implementation, not a qualified or delivered release feature**.
`GITHUB_RELEASE_NATIVE_QUALIFIED` remains `false`. Browser preview never substitutes
a mock release engine or dispatches a workflow. Native integration, independent
implementation acceptance, platform verification and protected delivery remain
required before enabling the feature.

The Releases page provides a guided path to the toolkit's existing canonical
`candidate`, `external-testing` and `production-submit` workflows, one Android or
iOS platform at a time. It does not run a CLI, reimplement the Store engine, copy
signing inputs to GitHub, or approve a protected GitHub environment.

- **Candidate:** build/sign/validate once and request internal testing.
- **External testing:** select original candidate evidence; preserve build-once
  promotion and the existing tester/Store-state checks.
- **Production submission:** select candidate and external-testing evidence.
  Android prepares a draft, not a served release. iOS submits for App Review with
  manual release; it does not automatically publish publicly.
- **Same-step recovery:** select the original recovery evidence producer and
  original version. The core, not this form, authenticates the intent, original
  producer relationships, artifacts and actual Store state before acting.

The UI explains every selection, where to find its value, requiredness and
failure implications through contextual help. It separates current dispatch
source/configuration/version from declared original artifact details. The exact
original version enters the core's confirmation string. The declared original
source is retained review data, **not** another workflow input or a new source
authentication check. Current destination/checklist data is not proof of the
original artifact destination, effective secrets, permissions or approval rules.

## Architecture and ownership

`GitHubRelease.tsx` → `GitHubReleaseController` → seven closed native
`github_release_*` commands → the original `DocumentBinding` /
`ConnectionState` / `Supervisor` → `github_release_bootstrap.py` →
`github_release.py` → the existing protected workflows and Store core.

The command suffixes are `status`, `prepare`, `dispatch`, `track`, `reconcile`,
`pending` and `cancel`. The event is `github-release-status`; the private protocol
is `mrk-github-release/1`. A renderer cannot select a token, URL, workflow path,
toolkit pin, helper, timeout, home directory or arbitrary request body.

Release work reuses the original GitHub connection's session-only credential,
account/repository pins, expiration, cooldown, actual project registration and
cleanup owner. It does not introduce a second credential owner or scheduler.
Release consent, journal records and installed runtime domain are distinct from
credential-free GitHub preflight. Each typed runtime transfer/acquisition/GO
checks its exact family; a preflight consent cannot authorize a release.

Native Prepare selects a fresh marker. Successful Prepare creates a short-lived,
one-use review. Dispatch requires both the checkbox and the exact typed core
confirmation, plus the original document/project/account/repository/source
binding. Editing a selection, changing project, disconnecting, expiration or
starting another action revokes the review.

## Finite remote checks

Prepare makes ten GET requests: account, repository-before, branch-before,
workflow, immutable caller, immutable configuration, immutable recursive Git
tree, immutable version, branch-after, repository-after.

The tree request uses the actual root-tree SHA from the branch response, not a
commit interpreted as a tree. Caller/config/version must be regular blobs with
regular tree ancestors and matching blob SHA/size/bytes. Selected symlinks and
submodules, incomplete/truncated trees or changed branch observations are
refused. Unrelated symlinks/submodules are not traversed.

Limits are explicit: complete tree ≤1,000 entries/256 KiB wire, caller ≤16 KiB,
decoded configuration ≤512 KiB, version ≤64 KiB, selected version path ≤512 UTF-8
bytes/12 components. Only the fixed Prepare configuration response gets a768 KiB
wire allowance for base64 overhead. Only the selected version endpoint gets a
2,048-byte encoded path allowance. Prepare aggregate traffic remains ≤2 MiB;
the original10-second helper deadline is never renewed. Existing connection and
preflight limits are unchanged.

Dispatch rechecks account/repository/branch/workflow, then sends **one POST**.
The effect becomes `potentially-applied` before connection setup for that POST.
There is no automatic resend, redirect, pagination, retry or background poll.
The three optional Desktop caller inputs are forwarded together; the earliest
reusable guard rejects partial markers or source/ref mismatch before any
resolver/build/Store job. All-empty inputs preserve existing manual callers.
GitHub branch dispatch is not atomic compare-and-swap: authorized branch writers
must be trusted and protected against changing the workflow after review.

Track and Reconcile require exact original run/account/repository/source/title
and attempt1. Candidate completion requires the input guard and selected
resolver/Store jobs; reused evidence may legitimately skip online/build jobs.
Workflow observation is always labelled **not authenticated release evidence**.

## Durable requests, limits and recovery

The original helper creates an immutable intent under the actual account's
private `github-release` journal before READY. The original native document
rechecks custody/consent and supplies GO. Result publication requires original
helper/pipe/worker/journal closure and settlement; a READY or result frame alone
does not establish cleanup.

Pending history retains at most64 records, without deletion, replacement or
truncation. Each Prepared record is bounded to3,900 serialized UTF-8 JSON bytes;
each Run to4,096 bytes. Native admission checks the exact serializer-derived
worst complete Status budget, including all64 record wrappers, separators,
maximum fixed fields and a current review/run, against the unchanged256 KiB
result bound. The current Status must also serialize within that bound before a
new owner is installed. Oversized source/review/history is refused rather than
discarded to make a request fit.

Uncertain Dispatch stays recorded. Load Pending reads the local journal only;
Track/Reconcile make a finite read sequence only when explicitly clicked. A
missing displayed record does not prove absence of Store effects. Navigation
retains the original observer and status/stop controls. Stop means local
cleanup, **not remote cancellation, rollback or permission to resend**.

## Deliberately separate capabilities

- Authenticated remote history, secure artifact downloads and attestation
  verification are not provided by ordinary run/job observation.
- Exceptional Apple ambiguous-operation attribution/retry grants are not
  exposed by this form. They require the separate exact-evidence owner workflow.
- Remote GitHub secret/environment administration, local signed iOS export,
  complete signing-account recovery and private Store data editing are separate
  feature obligations; this dispatch slice does not count them as complete.
- Real account roles, WIF/SSO, environment administrator setup, Store agreements,
  tester membership and supported build toolchains remain external facts.

The source currently adds a Linux installed action profile, still disabled.
macOS/Windows native action integration and qualification are not implied by
cross-platform renderer code. Existing iOS workflow build/signing requires its
genuine supported macOS runner. No physical-Mac-only prerequisite was identified
for the remote dispatch slice; no Store mutation is needed merely to test it.

## Focused regression coverage

`tests/desktop/test_github_release.py` covers closed selections, immutable regular
source proofs, config/version ceilings, original/current version separation,
one-POST ambiguity, attempt/job binding, cross-family frames/journals, the
original helper sequence through fake IO, transport roles/deadline and full64
maximum-size serialized records. These are inert/local contract tests, not
native ownership or live service evidence.

`desktop/tests/github-release.test.mjs` covers exact typed consent, observer
retention, event-before-reply, reentrant clicks, context revocation, fixed bridge
commands and full64 escaped-UTF8 status boundaries. Rust protocol/owner tests
cover corresponding native DATA contracts and exact-family claims. The workflow
lifecycle subset verifies canonical packaged caller equality, manual input
compatibility, actual builtin-only earliest guards and non-bypass of resolver /
build / Store dependencies. It never runs a Store step or a release workflow.

Passing these tests does not qualify the installed runtime, GitHub permissions,
Store behavior, native platform boundaries or production delivery.
