# Credentials and external assets

Production use is **NOT READY until** remediation verification and a new comprehensive
production-readiness audit pass;
see [preparation status](../README.md#preparation-status).

The shared repository contains no application credential, private key, account identifier, signing asset, tester identity, or reviewer contact. Public certificate fingerprints and non-secret Store/team identifiers belong in the consuming application configuration.

`mobile-release credentials` calculates requirements from enabled platforms and capabilities. It prints names and status only:

- `CONFIGURED`
- `MISSING`
- `INVALID`
- `NOT_APPLICABLE`
- `MANUAL_EXTERNAL`

## GitHub environments

### Complete input-group secrets

The envelope-aware toolkit also accepts one **complete input group in one
environment secret**, using protocol `mrk-github-input-group/1`.
All members, including formerly public variables, travel together. An applicable
nonempty group secret wins over the entire legacy group below; missing members
are never filled from a legacy password, identifier or file path. A malformed
applicable envelope refuses before use, including when a credentials file was
explicitly selected. With no envelope, the existing legacy behavior is unchanged.

| Group | Canonical environment secret | Complete fields |
|---|---|---|
| Android keystore | `MOBILE_RELEASE_INPUT_ANDROID_KEYSTORE_V1` | file, storePassword, keyAlias, keyPassword |
| Android Firebase | `MOBILE_RELEASE_INPUT_ANDROID_FIREBASE_V1` | file |
| Apple distribution P12 | `MOBILE_RELEASE_INPUT_APPLE_P12_V1` | file, password |
| Apple provisioning profile | `MOBILE_RELEASE_INPUT_APPLE_PROFILE_V1` | file |
| App Store Connect P8 | `MOBILE_RELEASE_INPUT_ASC_P8_V1` | file, keyId, issuerId |
| iOS Firebase | `MOBILE_RELEASE_INPUT_IOS_FIREBASE_V1` | file |
| Google WIF | `MOBILE_RELEASE_INPUT_GOOGLE_WIF_V1` | provider, serviceAccount |
| Project dependency token | `MOBILE_RELEASE_INPUT_PROJECT_READ_TOKEN_V1` | token |
| Apple review contact | `MOBILE_RELEASE_INPUT_APPLE_REVIEW_CONTACT_V1` | firstName, lastName, email, phone |
| Apple review demo account | `MOBILE_RELEASE_INPUT_APPLE_REVIEW_DEMO_ACCOUNT_V1` | username, password |
| Apple operation commitment | `MOBILE_RELEASE_INPUT_APPLE_OPERATION_COMMITMENT_V1` | keyBase64, keyVersion |

The JSON object contains exactly `protocol`, `kind` and `values`;
`kind` is the existing credential-guide kind (for example,
`android-keystore`), and `values` contains exactly the field IDs
in the table. File fields contain canonical Base64, never local filenames.
The exact UTF-8 JSON envelope is limited to **48,000 bytes**. Larger files may
still be valid for local signing but cannot use this GitHub channel; nothing is
truncated, split or silently omitted.

Only groups selected by the existing stage/platform/purpose policy are decoded.
Candidate signing/Firebase/dependency inputs never enter promotion jobs; Store
credentials never enter project build jobs. Disabled Firebase/demo-account
groups are ignored. Offline preflight may use the explicitly required dependency
token, but does not acquire signing or Store groups. CLI environment mode still
requires `--credentials-from-env`; merely selecting a credentials file
does not grant access to ambient envelopes. GitHub's empty expansion for an
absent secret is treated as absence; whitespace or otherwise malformed JSON is
not an absence fallback.

A credentials-file override of an active group must supply every member of that
group and pass the existing private-path and scalar/material checks. A complete
local file alternative is permitted, but a password-only override is refused.
Without an active envelope, legacy file-over-environment behavior is unchanged.

All seven Google authentication steps validate one complete public WIF pair
before the existing pinned auth action. They read an applicable group envelope,
or validate both legacy variables together when no envelope exists. Only those
two public identifiers become action outputs. Local online/Store consumers keep
using their existing authenticated ADC file; they do not acquire the unused WIF
envelope themselves. Private decoded scalar/Base64
values are registered individually with GitHub's escaped masking command before
use. The group decoder does not write private values to runner output/environment
files, project files, journals or artifacts; later materialization remains inside
the existing core's owned private-file lifecycle. Group envelopes are also removed
by the existing child-environment credential scrubbing. Native certificate/keystore/API validation
still belongs to the existing signing/Store consumers, not to this JSON decoder.

The credential name inventory can recognize an envelope's secret name, but
**cannot read or certify its contents**. Support at this consumer boundary is
not proof that an older pinned workflow understands the protocol. Desktop remote
provisioning must remain unavailable until the exact reviewed toolkit revision,
canonical caller, assigned record and native action path are qualified. This
consumer change does not itself enable remote writes or provide release consent.

Each confirmed group update is a separate ordinary secret upsert, not a
cross-group transaction, compare-and-swap or proof of a release-wide snapshot.
Legacy values remain untouched. Commitment input support does not generate,
rotate or back up a key, or prove compatibility with an older operation.

The following environment tables describe the retained **legacy fallback names**
and the same underlying field requirements.

### `mobile-candidate`

This is the only environment that receives build-signing material.

| Name | Kind | Required when |
|---|---|---|
| `MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64` | secret | Android enabled |
| `MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD` | secret | Android enabled |
| `MOBILE_RELEASE_ANDROID_KEY_PASSWORD` | secret | Android enabled |
| `MOBILE_RELEASE_ANDROID_KEY_ALIAS` | variable | Android enabled |
| `MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64` | secret | iOS enabled |
| `MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD` | secret | iOS enabled |
| `MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64` | secret | iOS enabled |
| `MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64` | secret | iOS enabled |
| `MOBILE_RELEASE_ASC_KEY_ID` | variable | iOS enabled |
| `MOBILE_RELEASE_ASC_ISSUER_ID` | variable | iOS enabled |
| `MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64` | secret | Android Firebase required |
| `MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64` | secret | iOS Firebase required |
| `MOBILE_RELEASE_PROJECT_READ_TOKEN` | secret | a project-owned dependency explicitly needs it |
| `MOBILE_RELEASE_GOOGLE_WIF_PROVIDER` | variable | Android enabled |
| `MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT` | variable | Android enabled |

The candidate uses Google/Apple Store access only in dedicated online-gate and Store/evidence jobs.
The separate Android/iOS build jobs receive only their platform signing, service-client, and optional
read-only project dependency inputs. They have no OIDC permission, Play ADC, App Store Connect P8,
or Store mutation path.

For Android, each Google job confines the exact generated ADC path to runner-scoped directories,
rejects symlinks and non-files, restricts it to mode `0600`, validates it, and removes it. The build
job runs on a fresh runner after the non-publishing online gate, so Gradle and project checks cannot inherit ADC
state. The later Store job validates the original handoff, obtains preparation credentials for
read-only Store inspection, and removes ADC before attesting and durably uploading its intent.
It then obtains separate execution credentials, uploads/reconciles, reads back, and removes ADC
before diagnostics, final attestation, and final-artifact upload. The handoff and intent are retained
for 90 days. Deleting ADC removes that file, not the job's OIDC authority: no application-owned code
may run anywhere in a Store/OIDC job, including cleanup and evidence steps.

For iOS, the build job receives P12/profile signing material but no P8. Online and upload steps receive
the P8 only in their own step environment and never receive the P12/profile. No job that can invoke
Gradle, Xcode archive, `prepareCommand`, or project checks has Store authentication or
`id-token: write`.

### `mobile-external-testing`

Required Android variables:

- `MOBILE_RELEASE_GOOGLE_WIF_PROVIDER`
- `MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT`

Required iOS items:

- `MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64`
- `MOBILE_RELEASE_ASC_KEY_ID`
- `MOBILE_RELEASE_ASC_ISSUER_ID`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE`
- `MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME` when `ios.review.demoAccountRequired` is true
- `MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD` when `ios.review.demoAccountRequired` is true
- `MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64` (secret; exactly 32 decoded bytes)
- `MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION` (variable; `[A-Za-z0-9_.-]{1,64}`)

This environment must not contain a keystore, P12, provisioning profile, or Firebase client file.

### `mobile-production`

Use a production-specific Google WIF service account and provider, scoped independently from testing. Use an App Store Connect key with the least privilege needed for review submission.

The environment contains the same generic WIF/ASC names because environment scope selects the value. It also contains private Apple review fields:

- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL`
- `MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE`
- `MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME` when `ios.review.demoAccountRequired` is true
- `MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD` when `ios.review.demoAccountRequired` is true
- `MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64`
- `MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION`

Production contains no build-signing assets.

Do not use `secrets: inherit`. Configure the fixed environment-scoped names; each reusable job
selects one protected environment and explicitly binds only its explicitly named `secrets.*` values
into the exact steps that consume them. Multiple candidate jobs select the same fixed environment,
so its protection rules may gate the online, signing, and upload boundaries separately. The thin caller
does not forward environment secrets: GitHub resolves them after that environment's protection rules
pass, and environment values take precedence over caller-passed values. The credential inventory and
these step bindings make the external-input surface reviewable.

## Google authentication

GitHub CI uses OIDC/Workload Identity Federation. Exported service-account JSON keys are not supported for CI.

The GitHub authentication action writes a short-lived `external_account` ADC file. The pinned
Fastlane/Supply version dispatches that JSON type to Google external-account credentials; the
workflow restricts the generated regular file to owner-only mode `0600`, passes its exact path, and
never reinterprets it as a long-lived service-account key.
The shared CI inspects the locked Supply source for this compatibility contract without requesting
an access token or contacting Google.

Every reusable job additionally aborts its steps unless GitHub reports the runner environment as
exactly `github-hosted`. This is defense in depth after scheduling, not proof that credentials were
never delivered to an eligible malicious runner. Before creating secrets or activating a caller, a
repository or organization administrator must verify runner inventory and policy so no self-hosted
runner can match the pinned `ubuntu-24.04` or `macos-26` labels, and must preserve that invariant.
The toolkit does not configure or select a trusted custom runner group.

The trust policy should bind at least:

- GitHub repository full name;
- immutable repository ID;
- intended GitHub environment;
- expected workflow/ref policy where supported.

Testing and production use separate Google service accounts with only the Play permissions required for their stage. Repository configuration stores the provider/service-account resource names as environment variables, not secrets.

Local online checks use Application Default Credentials or another explicit least-privileged Google credential accepted by the adapter. They must not silently reuse a CI JSON secret. Android Publisher inspection creates a temporary edit and deletes it without commit; it does not publish or retain a Store change. Apple online preflight performs reads only.
The GitHub-environment WIF provider and service-account resource names are CI inventory only; they
do not authenticate a developer workstation. For local Android online preflight, set
`GOOGLE_APPLICATION_CREDENTIALS` to an explicit least-privileged ADC JSON file outside the
repository.

## Apple authentication

App Store Connect uses a P8 API key supplied only to a job that needs it. Prefer a dedicated individual key with restricted app access where the account model allows; otherwise use the least-privileged team key.

The Store API key is distinct from the Apple distribution certificate and provisioning profile:

- P8 authenticates App Store Connect API operations.
- P12 contains the distribution signing private key and certificate.
- The provisioning profile authorizes the Store application identity, Team, entitlements, and distribution method.

Possession of one is not evidence that another is correct. The toolkit checks
API access, final signatures, complete profile-content relationships and Apple
profile issuer authority separately. Both CMS layers require real signatures and
the native production iOS provisioning policy under pinned Apple roots; decoding
alone is insufficient. See [profile authority](ios-profile-authority.md).

### Private review-state commitments

iOS external testing and production additionally require a dedicated, randomly generated 256-bit
HMAC key and its version. Provision it through the environment's secret-management process; never
derive it from the P8, a password, or review-contact fields. Only preparation/execution steps receive
it. Intents and receipts retain domain-separated HMAC commitments to before/target private review
state, never the values themselves. This lets recovery reject changed inputs without publishing
guessable hashes of email addresses or demo credentials.

Keep each incomplete operation's original key **and version** available throughout the 90-day
retention window. Changing either is not an evidence migration: restore the original protected
configuration to reconcile that operation. Completed authenticated final reuse needs neither the
key nor Store credentials. Key generation, rotation and retention are administrator responsibilities.

## Desktop private review inputs

In the Desktop **Credentials** screen, select iOS and the intended external-
testing or production-preparation context, then choose **Apple review contact**
or **Apple review demo account**. The contact group has four private fields:
first name, last name, email and phone. The demo group has a dedicated in-app
username and password; it is selected by the core only when
`ios.review.demoAccountRequired` is true. An Apple Developer password is
never a demo login.

Each masked field has contextual help explaining where to obtain its value.
Enter values directly; do not create a private JSON/.env file or copy anything
into the repository. Prepare checks bounded original values (4,096 UTF-8 bytes
per field, no NUL); only the email additionally receives the existing core
syntax check. It does not contact the person, call the phone number or test
a login. Missing values matter only for core-selected requirements.

Review the safe findings, explicitly Keep the private input, then explicitly
Assign it to the submitted context. Changing the draft or context invalidates
prior authority. Replacements never expose stored values and failed/cancelled
replacement cannot automatically restore an assignment. Session-only records
last for the current launch. Encrypted storage is unavailable in this build;
no new vault/keyring/provider is enabled by these scalar kinds.

The existing authenticated vault descriptor format can represent these
closed scalar layouts without private values in descriptors or persisted
approvals. No format migration, reset or deletion is introduced. An older
application may not understand a new kind: preserve the vault rather than
resetting it, and reopen only with a compatible qualified application.

**Apple operation recovery key** uses the same separate Prepare, Keep and Assign
steps for the existing retained commitment key/version pair. Obtain the original
pair from the release owner's secure backup or secret manager; GitHub cannot
reveal a secret already saved there. This is not an Apple password, P8 or P12.
The key accepts standard base64 decoding to exactly 32 bytes under the unchanged
core policy, including its existing legacy pad-bit acceptance. The matching
version is 1–64 ASCII letters, digits, underscores, dots or hyphens. The key is
masked; the version is visible while editing, but neither is read back from
native records. The same per-field bounds and context/finality gates apply.

Do not generate or rotate a key through this session. Format checks cannot prove
randomness, correspondence to a retained key/version or a match to an unfinished
operation. Keep the original pair securely backed up. Core requiredness selects
this pair independently of demo-login requirements for iOS external testing and
production preparation with full/store roles, never signing.

This UI slice does not configure the private review-note files, GitHub environment
secrets or a Store consumer. Those remain separate lifecycle steps. Nothing is
uploaded, published or added to an iOS signing input by preparing or assigning
these values.

## Local credential file

Keep the file outside the repository:

```text
MOBILE_RELEASE_ANDROID_KEYSTORE_PATH=/absolute/private/upload.jks
MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD=...
MOBILE_RELEASE_ANDROID_KEY_ALIAS=upload
MOBILE_RELEASE_ANDROID_KEY_PASSWORD=...
MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH=/absolute/private/distribution.p12
MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD=...
MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH=/absolute/private/app.mobileprovision
MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH=/absolute/private/AuthKey.p8
MOBILE_RELEASE_ASC_KEY_ID=...
MOBILE_RELEASE_ASC_ISSUER_ID=...
GOOGLE_APPLICATION_CREDENTIALS=/absolute/private/google-adc.json
```

Set mode `0600`. The parser accepts strict `KEY=VALUE` records; it does not source the file,
expand variables, execute substitutions, or log values. Private paths must be absolute regular
files outside the project. Ambient environment credentials require explicit opt-in.

On Darwin only, checked acquisition accepts the root-owned direct system aliases `/tmp` to
`private/tmp` or `/private/tmp`, and `/var` to `private/var` or `/private/var`. The physical root,
`/private` and `/private/var` must be system-protected; shared-writable `/private/tmp` must be
root-owned and sticky. No lower-directory or leaf symlink, crossed/indirect alias, or `..`
traversal is allowed. These exceptions do not relax project/recovery-root rules or permit changing
OS aliases. Other platforms follow no symbolic links.

The reader binds parent and file identity/metadata, bounded contents and successful descriptor
retirement before returning bytes. Credential files are limited to 256 KiB, small material to
4 MiB and general/ADC material to 32 MiB. Native path consumers borrow an exclusive `0600`
snapshot from a finite scratch owner; they do not reopen the external original after selection.
A successful path diagnostic alone grants no later-read or deletion authority.

Standalone scratch owners freeze a nonempty `TMPDIR` at construction; absent or empty
`TMPDIR` selects `/private/tmp` on macOS or `/tmp` on Linux. The parent must be a
bounded absolute path without parent traversal. Rejection does not retry another
location: `TMP`, `TEMP`, and Python's cached temporary directory are not fallbacks.
Only default-selected macOS parents may use the genuine root-owned `/tmp` and `/var`
aliases described above, with protected physical ancestry and original-descriptor
checks. Lower links and aliases in explicit project/build/readback parents remain
refused. Finite ownership, consumer finality and sandbox permissions are unchanged.

Do not Base64-encode local files merely to match GitHub. Base64 is transport encoding, not encryption.

## Validation

Credential inventory checks only strict Base64/path presence, safe external file location, permissions, and symlink rules. It does not claim that encoding proves cryptographic suitability.

Required Firebase clients receive an application-identity check during signing-material validation
and again on the exact bytes selected for build-input publication. Android clients must contain the
configured application ID; the iOS client's `BUNDLE_ID` must match the configured Bundle ID. Missing,
malformed or mismatched selected clients fail before any client-file replacement or build. An earlier
PASS cannot authorize different bytes after an external file is rotated. This checks application
identity, not Firebase project ownership, backend configuration or service availability.

Signed final-artifact validation checks:

- the final AAB signature and configured public upload-certificate fingerprint;
- the exported application signature/nested code and configured Apple distribution fingerprint;
- Apple issuance of both signed CMS layers, embedded profile Bundle ID, Team, distribution type, validity interval, complete
  typed entitlement grants and certificate membership, correlated with modern DER content;
- exact artifact identities and committed version/build values.

Fresh Android preparation and every new AAB send require the pinned bundletool,
Java 21 `jarsigner` signature checks (including expiry warnings), and the configured
public upload-certificate fingerprint from `keytool`. Historical recovery instead
authenticates the original intent and exact bytes before reconciling an accepted
bundle or completing evidence; a later signing warning is not a reason to rebuild
or re-sign it. Current-upload validation runs in an isolated, credential-free child.
Only the public bundletool path and Java runtime context cross that boundary, not
Store access, signing secrets or Java/Python runtime-injection variables.

Fresh iOS preparation validates every inspected profile's creation/expiry dates and actual signing
leaf-certificate validity. A new Transporter upload repeats current validation immediately before
dispatch, including explicit same-byte upload retries. Reconciliation of an already accepted build
can use the original authenticated validation and exact original hashes after signing assets expire;
it cannot use that old validation to authorize a new upload. See [Recovery](recovery.md).

Every code architecture must have consistent signed claims, Team and signer.
Nested apps/extensions use their own profiles; profileless code cannot borrow
an enclosing app's grants. Profile issuance verification is read-only/offline;
profile dates and application certificate dates still need to be current for new
uploads. See [iOS entitlements](ios-entitlements.md) and
[profile authority](ios-profile-authority.md). Local signed iOS builds acquire a
persistent account-wide lease before private/application work; overlap fails safely
before global mutation. Pending ownership needs [local signing recovery](local-signing.md),
not lock/journal deletion. The separate outer invocation reserves the environment before
credential snapshots, then admits the applicable account and project. All offline/signing modes,
including skip-builds, hold the project; online acquires no project/account owner. Original decoded
inputs and client-file replacements remain under [build-input custody](build-inputs-recovery.md)
through inner signing and consumer cleanup. Supplied owners are borrowed, never reacquired.

Successful online preflight requires actual provider authentication and visibility of the intended
Store application. Provider authentication, not Base64 formatting or a unit-test policy result,
is the authority for API-key suitability.

One live selection binds configuration, platforms, invocation and the original cancellation owner
across material validation, the blocker gate, credential environment and Store adapters. P8 native
validation and outbound Base64 use the same selected bytes; ADC JSON validation and the Ruby
adapter use the same retained snapshot. When both are selected, P8 validation precedes ADC
acquisition, so a P8 failure cannot trigger a later private ADC read. Changed, rejected, closed or
foreign selections cannot authorize a query; a copied credential mapping is not that authority.

Online ownership queries can run for an **unverified**, but not explicitly
**blocked**, identity despite unrelated build/signing/metadata diagnostics. The
complete query identity, committed version and Store credentials must still be
available; failed material validation stops the query. Missing local ADC is a
static diagnostic, not permission to read other private inputs. Online checks
never execute application-owned checks or builds. Unconfirmed process/resource
cleanup stops every mode; an independent query PASS cannot clear other failures.

After signing, it verifies the final AAB/IPA independently and records only public identity evidence and artifact hashes.

## Cleanup and logs

Local profile checks correlate bytes and the same observed file identity/metadata,
including after the bounded reader closes. Identical bytes do not prove ownership.
An observed installer conflict preserves that name and leaves its original signing
session pending, instead of letting outer cleanup retry it implicitly. Establish
account quiescence and use [explicit local recovery](local-signing.md); never delete
unknown stages or journals. Safely absent owned files require no deletion.

- Arm cleanup and the original cancellation owner before acquiring private resources.
- Use finite, owned mode-`0700` scratch directories and mode-`0600` files.
- Use an ephemeral Apple keychain.
- On catchable exit, settle consumers/signing before removing unchanged owned inputs; retain
  uncertain resources and report failure rather than retrying ambiguous cleanup.
- Disable shell tracing around all credential operations.
- Never upload credential directories, raw command output containing secrets, or private review/tester data as artifacts.
- Reports may state that a named item exists or is invalid, never its value.

Outer build-input cleanup preserves admitted original client-file inode, bytes and exact mode,
including empty/mode-`000` originals; it never chmods an original merely to read it. All selected
targets are inspected before a no-replace publication batch. Restoration retires only unchanged
owned replacements and restores unchanged backups into absence. Changed targets, parents,
backups or unknown entries remain conflicts; no recursive cleanup removes foreign content.
Environment restoration is conditional, same-owner LIFO; unresolved ownership prevents process reuse.

Profile/signing/authentication and build-input owners share default main-thread signal protection
and first-primary arbitration. Descriptors are retired before one close attempt; ambiguous closes
are not retried. Neither cancellation nor manual recheck repairs fatal cleanup or authorizes a new
operation in the failed invocation. End it and establish exact-owner quiescence. Resolve account
signing first when necessary, then use [project-input status/recovery](build-inputs-recovery.md)
for the original root/session. A terminal project control authorizes metadata retirement only,
never re-comparison or restoration of current client files.

Custom handlers and worker threads retain host semantics; hard termination/power loss cannot run
cleanup. Pending `.mobile-release/build-inputs/` state may contain original client files or private
material: never commit, upload or broadly delete it. Preserve unresolved evidence; an idle/absent
later status does not turn the earlier failure into a pass.

Secret rotation and IAM/account provisioning remain external administrator tasks. Run `credentials` and signing/online preflight after any rotation before the next candidate.
