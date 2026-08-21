# Credentials and external assets

The shared repository contains no application credential, private key, account identifier, signing asset, tester identity, or reviewer contact. Public certificate fingerprints and non-secret Store/team identifiers belong in the consuming application configuration.

`mobile-release credentials` calculates requirements from enabled platforms and capabilities. It prints names and status only:

- `CONFIGURED`
- `MISSING`
- `INVALID`
- `NOT_APPLICABLE`
- `MANUAL_EXTERNAL`

## GitHub environments

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

For Android, each Google job validates and removes its exact bounded short-lived ADC file. The build
job runs on a fresh runner after the non-publishing online gate, so Gradle and project checks cannot inherit ADC
state. The later Store job downloads the fixed same-run handoff, revalidates its checksum and final
signature, authenticates, uploads, reads back, then removes ADC before attestation or retained-artifact
upload.

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

Production contains no build-signing assets.

Do not use `secrets: inherit`. Configure the fixed environment-scoped names; each reusable job
selects one protected environment and explicitly binds only its explicitly named `secrets.*` values
into the exact steps that consume them. Multiple candidate jobs select the same fixed environment,
so its protection rules may gate the online, signing, and upload boundaries separately. The thin caller
does not forward environment secrets: GitHub resolves them after that environment's protection rules
pass, and environment values take precedence over caller-passed values. The credential inventory and
these step bindings make the external-input surface reviewable.

## Google authentication

GitHub CI uses OIDC/Workload Identity Federation. Exported service-account JSON keys are not supported for CI in version 1.

The GitHub authentication action writes a short-lived `external_account` ADC file. The pinned
Fastlane/Supply version dispatches that JSON type to Google external-account credentials; the
workflow passes the exact ADC path and never reinterprets it as a long-lived service-account key.
The shared CI inspects the locked Supply source for this compatibility contract without requesting
an access token or contacting Google.

Every reusable job additionally aborts its steps unless GitHub reports the runner environment as
exactly `github-hosted`. This is defense in depth after scheduling, not proof that credentials were
never delivered to an eligible malicious runner. Before creating secrets or activating a caller, a
repository or organization administrator must verify runner inventory and policy so no self-hosted
runner can match the pinned `ubuntu-24.04` or `macos-26` labels, and must preserve that invariant.
Version 0.1 does not configure or select a trusted custom runner group.

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

All three relationships are checked; possession of one is not evidence that another is correct.

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

Set mode `0600`. The parser accepts strict `KEY=VALUE` records; it does not source the file, expand variables, execute substitutions, or log values. Paths must be absolute regular files, not symlinks. Ambient environment credentials are used only with an explicit opt-in flag.

Do not Base64-encode local files merely to match GitHub. Base64 is transport encoding, not encryption.

## Validation

Credential inventory checks only strict Base64/path presence, safe external file location, permissions, and symlink rules. It does not claim that encoding proves cryptographic suitability.

Signed final-artifact validation checks:

- the final AAB signature and configured public upload-certificate fingerprint;
- the exported application signature/nested code and configured Apple distribution fingerprint;
- embedded profile Bundle ID, Team, distribution type, expiry, production entitlements, and certificate relationship established by the signed export;
- exact artifact identities and committed version/build values.

Online preflight proves that the configured Google or Apple API credential can authenticate and see the intended Store application. Provider authentication is the authority for API-key suitability; a Base64 format check is not.

After signing, it verifies the final AAB/IPA independently and records only public identity evidence and artifact hashes.

## Cleanup and logs

- Install cleanup handlers before decoding or importing anything.
- Use a mode-`0700` temporary directory and mode-`0600` files.
- Use an ephemeral Apple keychain.
- Remove temporary profiles, keychains, decoded files, and unsigned request material on success, error, cancellation, and injected failure.
- Disable shell tracing around all credential operations.
- Never upload credential directories, raw command output containing secrets, or private review/tester data as artifacts.
- Reports may state that a named item exists or is invalid, never its value.

Secret rotation and IAM/account provisioning remain external administrator tasks. Run `credentials` and signing/online preflight after any rotation before the next candidate.
