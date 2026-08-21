# Release lifecycle

The lifecycle is deliberately split so that cheap checks precede expensive builds and authority increases only at protected boundaries.

```text
configure -> doctor -> offline preflight -> signing preflight -> online preflight
          -> candidate build/internal upload -> Store readback
          -> external-testing promotion -> Store readback
          -> production draft/review submission -> Store readback
          -> manual Store-console release
```

All Store-mutating workflows use one non-cancelling concurrency group: `mobile-release-store-mutations`. A newer run must not cancel an older run after it has changed external state.

Each Store mutation lane performs an immediate authoritative readback and records the state it
observes. In v0.1, `mobile-release status` validates recorded evidence only; it does not query or
poll either Store. Later asynchronous progress requires a separate non-publishing Console or API check.

Before a promotion consumes downloaded evidence, it also queries the GitHub Actions run record.
The supplied run ID must belong to the current application repository, be a completed successful
manual run of the fixed candidate/external caller path, have the exact candidate head SHA, and have
the same run-attempt number recorded in the attested evidence.
Artifacts from a cancelled, failed, partial, differently named, or unrelated run are rejected even
if some files were uploaded before that run ended.

## Candidate

Candidate is manually dispatched for Android, iOS, or both. It is the only stage that compiles signed Store binaries and the only stage with keystore/P12/profile access. Subject to the required repository/organization runner-policy check, authority is split across fresh GitHub-hosted runners:

```text
non-publishing Store gate -> application build/sign job -> immutable same-run handoff
                     -> trusted Store/evidence job -> internal upload/readback
```

The application build/sign job has no `id-token: write`, Google authentication action, Play ADC,
or App Store Connect P8. The online and Store/evidence jobs never invoke Gradle, Xcode archive,
`prepareCommand`, or project checks. Every job aborts its steps unless `runner.environment` reports
`github-hosted`. That guard runs after scheduling and cannot replace the activation prerequisite
that no self-hosted runner be eligible for the pinned labels.

It performs:

1. actual dispatch-ref, repository-ID, branch-tip, tool-SHA, configuration, identity, and version checks;
2. non-publishing Store ownership, access, destination, and build-uniqueness checks (Google creates and deletes an uncommitted edit; Apple reads only);
3. source/application tests and bounded project preflight checks;
4. one Android Release build and/or one iOS Release archive/export;
5. normalization into a fixed-name, checksum-bound same-run handoff;
6. download on a fresh Store runner and independent final-artifact/signing/profile/entitlement validation;
7. upload to Play `internal` and/or internal TestFlight;
8. bounded processing wait and exact Store readback;
9. immutable candidate evidence generation and attestation.

The signing preflight report is the last effective application proof produced by application code.
The build job uploads the AAB/IPA, report, optional symbols/archive, and `SHA256SUMS` as a private
one-day artifact with a fixed platform name. The Store job compares the build job's upload receipt
digest with the current-run fixed-name artifact API record; the pinned download action recalculates
and verifies that service digest. It then validates the safe file layout and checksums before the
shared candidate command re-inspects the exact AAB/IPA signature, Store identity, version, and
public signer before mutation. Store credentials never coexist in a job with an application-owned
command.

Evidence paths:

```text
.mobile-release/manifests/candidate/android.json
.mobile-release/manifests/candidate/ios.json
.mobile-release/receipts/candidate/android.json
.mobile-release/receipts/candidate/ios.json
```

Android and iOS Store jobs produce separate manifests because they run on different operating systems and must not race to edit one aggregate file. Each Store job writes its initial output to `.mobile-release/staging/candidate/<platform>/`; the workflow validates and normalizes it before artifact upload. Private retained artifacts include the AAB, mapping/native symbols, IPA, xcarchive, dSYMs, the exact signing/project-check validation report, and the exact deterministic metadata archive hashed by the manifest. Android's archive contains only `android/**`; iOS's contains `ios/**`, `review/**`, and `testflight/**`, preserving those root-relative paths. The workflow copies the archive after manifest creation and rechecks the recorded metadata SHA-256; it never rebuilds it for retention. Each candidate manifest records hashes and public identity; it contains no binaries, credentials, tester identities, or review contacts.

dSYMs are validated and retained when `ios.symbols.policy` is `retain`. Version 0.1 intentionally
does not run a third-party symbol uploader. `required` remains a fail-closed activation sentinel and
blocks until an explicitly guarded candidate-stage upload integration exists.

If an upload outcome is ambiguous, do not retry blindly. Query the Store. Resume only if exact identity can be proved from the Store and local receipt. Otherwise commit a new build number and create a new candidate.

## Android external testing

The external-testing workflow:

1. downloads and validates candidate evidence;
2. verifies repository/source/tree/version/build and manifest hashes;
3. reads Play and proves the exact version code is in `internal`;
4. requires the `mobile-external-testing` environment;
5. promotes that version code to the configured closed or open track;
6. reads back the destination state;
7. writes `.mobile-release/receipts/external-testing/android.json`.

It never invokes Gradle or receives the Android keystore. Internal upload and external promotion are separate operator decisions.
For a closed track, promotion also proves that the Play edit has at least one Google Group assigned
before and after the mutation. The receipt records only
`closedTesterAssignmentVerified: true`; it never records group names or tester identities. A track
that relies only on email-list testers cannot currently be proved through the supported API and
therefore stops for manual resolution instead of claiming that the build is available to testers.

## TestFlight external testing

The external-testing workflow:

1. validates the candidate and exact App Store Connect build resource ID;
2. requires the protected external environment;
3. assigns the existing build to the configured external group with the candidate-bound reviewed
   `testflight/what-to-test.txt` text;
4. submits Beta App Review when Apple requires it;
5. reads back and records the actual asynchronous state;
6. writes `.mobile-release/receipts/external-testing/ios.json`.

It never archives or uploads another IPA. `submitted-for-review`, `in-review`, `approved`, and
`available-to-testers` are distinct states. A pending/approved Beta Review receipt is valid evidence
that the external stage ran, but it is not evidence that testers can install the build and is not
eligible for production submission. After Apple makes the exact assigned build available, rerun the
same external-testing workflow with the same candidate run ID. The lane reads the existing assignment
instead of uploading another IPA and emits a fresh attested receipt for the state it observes; only
a receipt that says `available-to-testers` is production-eligible. There is no background polling
engine.

## Android production preparation

Production is a separate manual Android-only dispatch. It requires:

- a candidate manifest;
- successful Android candidate and external-testing receipts;
- source/tree acceptance under the production branch policy;
- a confirmation containing platform, marketing version, and build;
- `mobile-production` approval;
- the production Google WIF identity.

The workflow reads the exact external-tested version code, promotes only that build to the Play `production` track with release status `draft`, and proves through readback that it remains draft. It writes `.mobile-release/receipts/production-submit/android.json`.

A draft is not served. The application owner later selects first/full release or an eligible staged rollout in Play Console. The shared system never completes or starts that rollout.

## App Store production submission

Production is a separate manual iOS-only dispatch. It requires the same provenance, confirmation,
and protected-environment gates plus an external-testing receipt whose exact readback state is
`available-to-testers`. Pending, in-review, or merely approved Beta Review evidence fails closed.

The workflow:

1. confirms no intended App Store version exists, or adopts an exact already-submitted version;
2. attaches the exact externally tested build resource;
3. uploads candidate-bound version metadata/screenshots/review notes;
4. submits for App Review with automatic release disabled;
5. reads back selected build and submission state;
6. writes `.mobile-release/receipts/production-submit/ios.json`.

Approval does not make the version public. The application owner releases it manually in App Store Connect.

On a production rerun, the lane reads App Store Connect before calling the submission action. It
adopts an existing submission only when the intended marketing version references the exact
candidate build, is already in a supported review/pending-developer-release state, and has release
type `MANUAL` with no scheduled date. A new submission is attempted only when no version record for
the intended marketing version exists. Any existing version with no selected build can be a partial
earlier mutation and therefore fails closed. An attached-but-unsubmitted, conflicting,
automatically scheduled, public, or otherwise ambiguous version is not resubmitted; the operator
must inspect it manually and allocate a new committed build when exact recovery cannot be proved.

## Source and promotion acceptance

A later protected production commit is accepted only if:

- the reviewed candidate commit is its ancestor; or
- the histories share a real merge base and their complete Git trees are equal.

An unrelated commit with copied bytes is rejected even if its tree hash matches. A version, tag, branch name, commit message, or partial diff is never sufficient provenance.

## Reruns

| Observed state | Required action |
|---|---|
| No candidate Store build exists | Build and upload the declared candidate once. |
| Exact build and matching receipt exist | Read back, then resume at the next incomplete gate. |
| Same version/build but different source, bytes, signer, or receipt | Fail and commit a new build number. |
| Store acceptance is ambiguous | Stop; inspect through a non-publishing Console/API path and never blindly resend. |
| Candidate Store job fails after build but before a proved upload | Rerun only that failed Store job so it consumes the same-run handoff; do not rerun all jobs and silently rebuild. |
| External or production receipt is missing/expired | Re-establish evidence; create a new candidate if retained authority cannot be proved. |
| TestFlight Beta Review is pending | Do not rebuild. After the exact build becomes available to testers, rerun external testing to issue a fresh eligible receipt. |
| App Review is pending after production submission | Check later through the non-publishing Store Console/API path; do not rebuild or resubmit blindly. |

An existing Android production-track version is not adopted when no valid production receipt is
available. The tool cannot prove that the already-uploaded production metadata is byte-for-byte the
candidate-bound metadata, so the safe recovery is a new committed build/version and candidate.

Android and Apple are independent systems. One can be pending or failed while the other succeeds. Receipts report partial progress; the tool never claims a cross-Store transaction or rolls back a successful external operation automatically.

## Manual external responsibilities

Before production submission, the owner confirms outside automation:

- developer agreements, banking, tax, roles, and account health;
- application ownership and signing registrations;
- privacy labels/Data Safety and source-backed legal truth;
- content rating, target audience, export/encryption answers, pricing, territories, and availability;
- tester consent, eligibility, and actual group membership;
- accurate support/privacy URLs and reviewer/demo-account details;
- human visual approval of screenshots and product claims;
- final rollout/release timing.

A checked box or syntactically valid file is not API or legal proof.
