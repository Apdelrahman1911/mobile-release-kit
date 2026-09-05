# Release lifecycle

Cheap checks precede expensive builds; authority increases only at protected boundaries:

```text
configure -> doctor -> offline/signing/online preflight
          -> one candidate build -> durable intent -> internal Store upload/readback
          -> durable external intent -> exact-build testing promotion/readback
          -> durable production intent -> draft/App Review submission/readback
          -> manual Store-console release
```

All Store workflows share non-cancelling concurrency group `mobile-release-store-mutations`.
This serializes workflow writers, not independent Console users. Unrelated Store drift fails
closed; there is no automatic rollback or cross-Store transaction.

`mobile-release status` validates recorded evidence only; it does not query or poll either Store.
Later asynchronous progress requires a separate non-publishing Console or API check. A new
external-testing dispatch can record later TestFlight availability; a completed receipt itself
never changes. Local checksum/schema validation is not GitHub attestation authentication.

## Authorization, execution, and final evidence

Each operation has three distinct identities: `authorizedBy` prepared its immutable intent,
`executedBy` produced the raw Store observation, and `producedBy` finalized the manifest/receipt.
A recovery producer may differ from the original preparer or raw executor. The application
candidate source, operation checkout, toolkit commit, and recovery dispatch are not interchangeable.

Before mutation, the Store job:

1. validates original artifacts or the complete authenticated predecessor chain;
2. captures read-only Store preconditions and binds exact confirmation, identity, version/build,
   configuration, metadata, artifacts/signers, source, destination, and workflow authority;
3. removes preparation credentials, creates an actual-job inventory sidecar, and attests the
   intent/proof (plus the exact candidate AAB/IPA);
4. uploads the immutable intent bundle with 90-day retention;
5. acquires execution credentials separately, then executes or reconciles only that operation.

After readback it removes credentials, retains private diagnostics, validates and attests the final
chain/inventory, and uploads the immutable final artifact **last**. A failed intent attestation or
upload prevents mutation. A later failure is recoverable from the already-durable intent.

Consumers verify GitHub service digests, complete safe layouts, GitHub attestations, exact producer
attempt/job identity and timing, raw/final agreement, original intent, and predecessor hashes.
They never compare against a run's mutable latest attempt. A valid completed platform remains
usable when another platform fails or cancellation follows final upload; run/job success alone
proves neither its authenticity nor completeness.

## Candidate

Candidate is a manual Android, iOS, or both dispatch. It is the only stage that builds/signs or
uploads a binary. Work is split across fresh GitHub-hosted runners:

```text
read-only evidence resolver
  -> (fresh only) non-publishing Store gate -> application build/sign -> retained handoff
  -> trusted Store job: authenticate -> prepare/persist intent -> upload/reconcile -> final
```

The resolver has GitHub read permissions, no Store environment and no `id-token: write`. An already
complete final skips all build/Store work. An incomplete original intent selects the original
handoff and operation source, never a rebuild. Handoff-only reruns have stricter prerequisites in
[Recovery](recovery.md).

The application build job has signing/service-client inputs and optional read-only dependency
credentials, but no Play ADC, App Store Connect P8, or Store-authorized OIDC. Online/Store jobs do
not run Gradle, Xcode compilation/archive, project generation, or application-owned checks.
Every job checks `runner.environment == github-hosted`; this is not a server-side scheduling
boundary. Administrators must prevent self-hosted runners matching the pinned labels.

Fresh creation validates the actual dispatch ref/tip/repository, committed version, tooling,
configuration, identity and metadata; performs Store ownership/destination/uniqueness checks;
runs application checks and the Release build; then hands the exact signed output to the Store
job for independent validation before authorization. The fixed handoff contains `SHA256SUMS`,
AAB or IPA, the retained iOS archive, validation report and optional symbols. It is retained for
90 days. The trusted build-output digest authorizes initial handoff consumption; recovery instead
also requires the original attested artifact bindings and exact binary attestation.

Candidate preparation retains a deterministic `store-metadata.zip` in the intent bundle.
Android includes only `android/**`; iOS includes `ios/**`, `review/**`, and `testflight/**`.
It is the exact archive hashed into the candidate, not a later reconstruction for retention.

Final package paths are:

```text
.mobile-release/package/candidate/<platform>/
  candidate-manifest.json
  candidate-receipt.json
  store-receipt.json
  workflow-provenance.json
  operation/
    candidate-operation-intent.json
    intent-provenance.json
    store-metadata.zip
```

External/production packages replace the stage receipt and preserve their complete original intent
under `operation/`, including original `candidate/` and, for production, `external/` evidence.
Working outputs live under `.mobile-release/staging/<stage>/<platform>/`; all are private artifacts,
not source files. Evidence manifests contain public identities and hashes, not binaries or private
review/tester credentials. Retained binary/archive/symbol handoffs are separate private artifacts.

For `ios.symbols.policy: retain`, symbols are validated/retained without a third-party uploader.
`required` remains a fail-closed activation sentinel, not an implemented upload integration.

## Android external testing

External testing authenticates the candidate, proves the intended version code is the authorized
internal build, and promotes it to the configured closed/open destination after protected approval.
It never runs Gradle or receives a keystore. The preserving Play adapter snapshots complete source
and destination tracks, requires the target release and bundle digest, preserves unrelated
completed/staged/halted/draft releases, validates the edit, commits once without mutation retries,
and reads back a fresh edit. Only exact retention/removal of the promoted source release is allowed
for Play's automatic deactivation; other changes fail.

An exact completed target under an original absent-target intent can reconcile without promotion.
An already-present target captured by a newly prepared external intent is observation-only and
emits `already-present`; it cannot by itself authorize production. Production requires `mutated`
or `reconciled` external evidence. Closed tracks must expose at least one assigned Google Group
before/after mutation; only a boolean is recorded. Email-list-only assignments are not verifiable
through this adapter and stop for owner resolution.

## TestFlight external testing

External testing selects the original App Store Connect build resource ID, configured external
group, and candidate-bound `testflight/what-to-test.txt`. It reconciles build encryption and
notification state, review details, localized what-to-test, group assignment and Beta App Review
resource by resource. Private input equality uses a protected HMAC key, not published contacts or
plain low-entropy hashes. Third-value drift, wrong group/build, expiry, rejection, or unsupported
transitions stop without compensating changes to other Store resources.

What-to-test updates/additions affect only `metadata.iosLocales`. Existing unconfigured locales
retain their exact text and resource IDs; changes, deletion/replacement, or additional foreign
locales after authorization stop recovery rather than being overwritten. The UTF-8 source file
is bounded to 64 KiB and 4,000 stripped characters; its original bytes and the configured sanitized
target are checked again before each mutation, including after partial success.

`submitted-for-review`, `in-review`, `approved`, and `available-to-testers` are distinct readback
states. Only `available-to-testers` is production-eligible. Once Apple makes the exact assigned
build available, create a **new external-testing dispatch** with the same candidate references and
no `recovery_run_id`. A rerun or complete-final recovery preserves the original pending receipt;
it does not retimestamp or reissue it. Neither path uploads an IPA. Ambiguous resource creation
may need the explicit new operator grant described in [Recovery](recovery.md).

## Android production preparation

Production is a separate protected Android-only dispatch. It requires the authenticated candidate,
production-eligible external receipt, accepted source history/tree, candidate-bound configuration
and metadata, and exact `production-submit:android:<version>:<build>` confirmation.

It promotes only the external-tested version code to `production` with status `draft`, applies
only intended metadata, verifies complete source/destination release preservation and listing/image
readback, and records the observed draft. A successful mutation remains recoverable when final
receipt/manifest/attestation persistence failed: the original intent identifies both before and
target states. An unrelated existing draft or metadata drift cannot be adopted or overwritten.

Every configured Android locale must already have valid exact-version or default release notes
in the candidate metadata. Preparation validates all notes before opening a Store edit and binds
their original UTF-8 text to the production intent. Execution and recovery require that exact
locale/text set; Supply workers receive an immutable copy, never an empty fallback or a later
filesystem read. The new target's 500-character requirement does not rewrite or reject unrelated
historical Store releases with empty or longer notes. Complete Store readback must still match
the entire authorized target, including notes, before a receipt can report success.

Play supplies the bundle SHA-256, but no mapping-file digest readback. Candidate recovery may replay
only the same original mapping for the same version code and requires an acknowledged edit commit;
this is documented scoped idempotency, not independent proof of the mapping's Store bytes.

A draft is not served. An owner later chooses the public release/rollout in Play Console.

## App Store production submission

Production is a separate protected iOS-only dispatch with the same evidence/source/confirmation
gates plus external `available-to-testers` proof. It selects only the original build, reconciles
candidate-bound version and app-info metadata/localizations/screenshots/private review inputs,
creates or resumes the exact review submission/item, and submits with `releaseType: MANUAL` and no
release date. Final readback verifies selected build, submission and manual release state.

Partial versions, missing local evidence, or an orphan empty review submission can resume only
under the original authenticated intent and explicit resource state machine. Already-submitted
states are observation-only. Conflicting builds, unrelated/duplicate submissions, regressive or
public states, scheduled/automatic release, metadata drift and private-input mismatch fail closed.
No aggregate Deliver rerun rewrites unspecified Store state. Screenshot retries preserve unrelated
assets; uncertain missing creates never silently repeat a POST.

Apple approval does not release publicly. An owner releases manually in App Store Connect.

## Source acceptance and recovery

External testing requires the exact candidate source commit/tree. A production operation source
may have the candidate as an ancestor, or have common history and an identical complete Git tree.
An unrelated copied tree, version label, tag or partial diff is insufficient.

An explicit recovery dispatch preserves the original operationSource checkout and separately
validates its current protected dispatch authority. No stage rewrites `GITHUB_SHA` to conflate them.
The original toolkit SHA, intent and predecessor hashes are immutable.

Recovery reuses a complete final artifact without Store access, binaries, reattestation or upload.
Incomplete operations use the original durable intent and required handoff; later signing warnings
or asset expiry alone do not strand an already accepted Android/iOS build. Every new AAB upload or
Transporter dispatch still passes isolated current signing/identity/profile checks, followed by
fresh Store precondition and final-byte validation; historical evidence never authorizes a new send.
Play logical upload retries are disabled without replacing Google's same-session resumable protocol.
Apple cannot independently expose IPA byte equality or a
universal exactly-once request guarantee. Owner attribution/create-retry decisions remain explicit.

Per-platform evidence run/artifact outputs preserve partial Android/iOS success. External callers
accept common or separate candidate run IDs; production also accepts external run IDs. Conflicting
common/platform-specific selectors fail. There is no alias traversal or evidence reissue to hide
mixed origins. See [Recovery](recovery.md) for the exact mode table, confirmations and retention limits.

## Manual external responsibilities

Owners remain responsible for agreements, banking/tax/roles, Store ownership and signing
registration, legal/privacy/content truth, export classification, rating/audience, pricing,
territories, tester consent/membership/eligibility, working review accounts and URLs, human
screenshot approval, independent Apple ambiguity resolution, and final rollout/release timing.
A checkbox or a syntactically valid file is neither API evidence nor legal proof.
