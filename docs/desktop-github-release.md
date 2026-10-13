# Desktop protected release workflows

## Availability and scope

This is a **source implementation, not a qualified or delivered release feature**.
`GITHUB_RELEASE_NATIVE_QUALIFIED` remains `false` as a qualification status, not
as the normal installed selector. Linux selection requires the exact normal
installed target/manifest/protocol and this release family's own immutable
publisher bindings. This source change does not supply those bindings or claim
native/service verification. Browser preview never substitutes a mock release
engine or dispatches a workflow. Independent implementation acceptance, native
integration, platform verification and protected delivery remain required.

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
- The form exposes the three exact additional Apple recovery confirmations
  for candidate adoption, original-IPA upload retry and missing-create retry.
  Desktop validates their format only; the protected core still authenticates
  original authority, evidence and current state before permitting any effect.
- Remote GitHub secret/environment administration, local signed iOS export,
  complete signing-account recovery and private Store data editing are separate
  feature obligations; this dispatch slice does not count them as complete.
- Real account roles, WIF/SSO, environment administrator setup, Store agreements,
  tester membership and supported build toolchains remain external facts.

The normal Linux installed action profile is selectable only in the supported
desktop-shell/custom-protocol build, excluding development/runtime-publisher
builds, with its exact installed payload and R's own publisher binding.
A separate paired macOS ARM64/Intel installed profile is also implemented; it
requires the exact Mac installed bindings, bundled runtime and release publisher
binding. Neither platform selection alone proves installed/native qualification.
`build.rs` derives the three canonical caller digests from the immutable
`MRK_GITHUB_RELEASE_TOOLING_SHA`; missing bindings still refuse before native
inspection. Passive, read-only and GitHub-preflight selection cannot supply
release authority, and G's synthetic observations cannot qualify R.

An R-specific installed/native three-journey route is now authored, but source
authoring is not native execution, implementation acceptance or delivery.
Reviewed production delivery bindings remain required. The implemented Mac
UI-to-native-to-core dispatch route still needs genuine installed-Mac journey
verification; renderer tests and compilation do not provide it. Windows native
action integration and qualification remain separate. Existing iOS workflow build/signing
requires its genuine supported macOS runner. No physical-Mac-only prerequisite
was identified for the remote dispatch slice; no Store mutation is needed merely
to test it.

## Separate installed observation route (native3)

`verify/desktop-installed-github-release` selects only
`github-release-native3-v1`. It reuses the installed-shell workflow's original
source, preparation, compiler, artifact, system-manager owner and final-output
path. It does not run the historical full shell matrix, Android build cases,
GitHub preflight's matrix or any release workflow. This is an engineering
observation build, not an application to ship or a way to enable qualification.

The dedicated compiler alone supplies
`4c89f77c7a1e3f0b538a99ab12069b245484205d` as R's **observation source candidate**.
`build.rs` derives all three canonical caller digests. The source candidate is
not established as protected, delivered production tooling. Ambient release
bindings, the preflight family's selector, mixed scopes and another ref/job/case
are refused rather than accepted as equivalent proof.

Each case uses the ordinary project picker, GitHub connection and Releases page,
actual native IPC/status/consent controls and original release owner. The finite
physical TLS fixture accepts only `owner/app`, account11/repository22 and the
public noncredential sentinel `INERT_NOT_A_CREDENTIAL`; it has no GitHub or Store
fallback. Real Connect is a separate read-only owner using the existing D-S
fixture runtime. R's profile is independently selected:

| Journey | R runtime and actions | Total local HTTP / POST | Original owners |
|---|---|---|---|
| Normal Pending | Normal V; local Pending after genuine Connect | 4 / 0 | 2 |
| Response loss | D-S; Prepare, Dispatch, Pending, Reconcile | 25 / 1 | 5 |
| Revocation before GO | D-S; Prepare, Dispatch refused after READY | 14 / 0 | 3 |

- **Normal Pending:** the actual V helper opens, reads and closes an empty R
  journal with `token:null`; it creates no intent/run and no release transport.
- **Response loss:** the production-submit/iOS review keeps declared original
  source/version1.2.3/build42 distinct from current source/version2.0.0/build99.
  Exact typed consent and the checkbox authorize one Dispatch. The fixture
  observes the actual durable intent before losing that POST's response. Local
  Pending retains it without HTTP; explicit Reconcile records run9001/attempt1.
  The UI preserves the “not authenticated release evidence” warning, with no
  automatic resend or polling.
- **Revocation:** only the original writer pauses after real READY. Ordinary UI
  Disconnect stops/revokes that same owner before the retained sender releases
  it. The actual final claim refuses the changed target: no GO, token or
  Dispatch HTTP; one immutable intent/no run remains. The original first error
  stays `cancelled`, its two-second cleanup endpoint is not renewed, and the
  displayed terminal operation stays not-sent/cancelled.

The observer adds no credential holder, scheduler, process owner or cleanup
deadline. Product10s/cleanup2s/peer16s limits are unchanged. Success requires
original child wait, both EOFs, writer/observer/driver/watchdog joins, actual
native-slot settlement, peer/control closure and the normal application Quit
gate. A result, READY frame or receipt alone is insufficient. Journal output
exports only bounded identity/hash summaries, never raw intents or credentials;
later cases must not change earlier journals or unrelated project material.

Fixture inputs retain the original source and borrow only its common directory
prefix. Borrowers keep their own leaf and suffix FDs, verify that same live
anchor, and close owned suffixes once in reverse acquisition order before the
source closes. Conservative descriptor peaks35/49/48 stay below the unchanged64
limit; no directory, content or finality check is dropped to reduce usage.

Native execution requires the reviewed disposable Linux x86_64
`6.17.0-1022-azure` system-manager boundary, not a shared VPS or inert mocks.
The newly authored route and contracts still need independent source acceptance,
admitted focused local checks and actual source-bound native observations.
Even successful native3 does not establish real GitHub dispatch/job naming,
delivered production tooling, macOS/Windows action paths, Store behavior or
kernel-close fault injection. These limitations are retained in the closed
receipt rather than hidden behind a green test label.

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

`tests/desktop/test_github_release_native_route.py` adds focused inert contracts
for the separate ref/scope/caller binding, the three schedules, actual receipt
parsers, source-bound closed exports, borrowed FD custody and original journal
read/close/finality failures. Rust's private native3 contracts cover independent
normal-V/D-S selection, READY/GO/token and revocation ordering, retained sender
cleanup and UI terminal-data preservation. Authored tests are not a claim that
they have executed or that native journeys passed.

Passing these tests does not qualify the installed runtime, GitHub permissions,
Store behavior, native platform boundaries or production delivery.
