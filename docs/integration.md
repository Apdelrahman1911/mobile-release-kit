# Integrating an application

This guide adds Mobile Release Kit without moving application build logic into the shared repository.

## Prerequisites

The application must have:

- a Gradle wrapper for Android and/or an Xcode project/workspace for iOS;
- an ordinary Debug/Development identity that is different from the canonical Store identity;
- an ordinary Release build/Archive action that uses the canonical Store identity;
- one committed marketing version and positive integer build number consumed by every enabled platform;
- externally managed signing and Store accounts.

Local Store-backed commands also require exactly Ruby 3.3.12 and the Bundler 4.0.16 recorded in
`Gemfile.lock`. Confirm the selected executables before using `--online` or any Store lane:

```bash
ruby --version
```

After selecting Ruby 3.3.12, install the exact Bundler only if it is absent, then verify it:

```bash
gem install bundler --version 4.0.16 --no-document
bundle --version
```

If the pinned Gem bundle is absent, the CLI fails before Store access and prints an exact
`BUNDLE_GEMFILE=<installed-path> bundle install` command for its pinned assets. Install Bundler
4.0.16 and run that command deliberately; the CLI never downloads Gems automatically. A source
checkout may instead be selected explicitly with `MOBILE_RELEASE_TOOLING_ROOT`, but it must be the
same full commit used by the callers.

Signed local Android artifact inspection also requires the same bundletool used in CI. Keep the JAR
outside the application repository and verify it before exporting its path:

```bash
curl --fail --location --proto '=https' --retry 3 --tlsv1.2 \
  https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar \
  --output /absolute/private/tooling/bundletool-all-1.18.3.jar
echo 'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29  /absolute/private/tooling/bundletool-all-1.18.3.jar' \
  | shasum -a 256 --check
export MOBILE_RELEASE_BUNDLETOOL_JAR=/absolute/private/tooling/bundletool-all-1.18.3.jar
```

Do not commit the JAR or replace it with an unverified ambient installation. CI downloads this
exact version and rejects any different SHA-256.

Play tracks and TestFlight groups are distribution stages of the canonical Store application. Do not create `.testing` application IDs, flavors, or schemes to represent them.

Before changing an identifier, inventory Firebase, APNs, associated domains, Keychain/app groups, OAuth callbacks, URL schemes, deep links, backend allowlists, and other identifier-bound services. A syntactically valid replacement identity is not enough. Record whether a new Development Keychain/app-group identity can start clean, must coexist, or needs an explicit data migration; an identifier suffix can otherwise strand local data.

## 1. Pin the tool

Choose a released semantic version and copy its full commit SHA. Install that exact commit locally. The generated workflows must use the same SHA twice:

```yaml
jobs:
  release:
    uses: <TOOLING_OWNER>/<TOOLING_REPOSITORY>/.github/workflows/reusable-candidate.yml@<FULL_SHA>
    with:
      tooling_sha: <FULL_SHA>
```

The consumer owns the tooling repository coordinate; the reusable core has no account default. The
called workflow uses GitHub's resolved reusable-workflow repository/ref/SHA identity to check out
its own source at `tooling_sha` and verifies the resolved commit. A tag comment may document the
human-friendly version, but a tag or branch is not authority.

The reusable workflows also force Python safe-path mode and invoke the module with `python -P`.
This prevents an application-owned `mobile_release` package in the working directory from
shadowing the pinned tooling checkout. Every reusable job aborts its steps unless
`runner.environment` reports `github-hosted`, but this first-step guard is not a server-side runner
selector. Before activation, a repository or organization administrator must verify that no
self-hosted runner is eligible for the pinned `ubuntu-24.04` or `macos-26` labels and preserve that
runner policy. The toolkit does not configure a trusted custom runner group; merely copying hosted
labels onto a self-hosted runner is unsupported and may expose the job before its guard aborts.

## 2. Establish one version source

New projects use:

```properties
VERSION_NAME=1.0.0
BUILD_NUMBER=1
```

in `release/version.properties`. Wire Gradle and Xcode to those values. Existing projects may point the configuration to a different tracked key/value file.

Marketing versions use two to four dot-separated numeric components, with an optional suffix for an
Android-only release. When iOS is enabled, App Store compatibility narrows this to two or three
numeric components with no suffix. Build numbers are canonical positive base-10 integers from 1 to
2,100,000,000; signs, whitespace, zero, and leading zeroes are rejected.

The file is reviewed source. CI never edits it, derives a replacement from a workflow run, or asks a
Store to allocate a value. Fresh-candidate online preflight rejects a consumed value. Recovery of
an interrupted original operation follows its authenticated intent instead of rerunning that
uniqueness gate or allocating another build number.

## 3. Preview discovery

Run:

```bash
mobile-release init
```

The command discovers likely Gradle application modules and literal application IDs, Xcode
projects/workspaces and shared schemes, Bundle IDs visible in project configuration, and supported
committed version files. It prints its proposed integration and unresolved decisions; it does not
write by default. Tracks, Store ownership, signing fingerprints, account IDs, service policy,
review answers, and ambiguous variants/configurations remain explicit decisions.

Review the proposal, then apply it explicitly. The expected application additions are:

```bash
mobile-release init --apply \
  --tooling-repository <TOOLING_OWNER>/<TOOLING_REPOSITORY> \
  --tooling-sha <FULL_SHA>
```

```text
release/mobile-release.json
release/store/
.gitignore (`.mobile-release/` is appended when absent)
.github/workflows/mobile-preflight.yml
.github/workflows/mobile-candidate.yml
.github/workflows/mobile-external-testing.yml
.github/workflows/mobile-production-submit.yml
```

`--apply` creates the required locale/review/TestFlight text files as empty review prompts. Empty
content intentionally fails metadata preflight until the product owner completes it. Existing
regular metadata files are preserved even with `--force`; a symlink or non-file at a required
destination aborts the entire integration before any file is written. The root `.gitignore` is
created when missing or receives one exact `.mobile-release/` line when absent; existing text is
preserved, while a symlink, non-file, non-UTF-8 file, or file over 1 MiB fails before any write.

## 4. Complete application policy

`release/mobile-release.json` must state:

- version source and key names;
- candidate and production branches;
- enabled platforms;
- expected canonical Store IDs;
- identity status;
- external testing destination;
- public signing certificate fingerprints;
- App Store app/team IDs;
- locales and Firebase/symbol policy;
- reviewed iOS encryption/demo-account policy.

Set `source.projectReadTokenRequired` only when a project-owned build dependency demonstrably requires authenticated source/package access. It defaults to false; the shared core never requests a broad repository token speculatively.

When Android discovery is ambiguous, set `android.module` with Gradle project-path syntax. Use `:`
for an application plugin applied in the root project, or a colon-separated path such as `:app` or
`:mobile:app`; filesystem paths and empty segments are invalid.

Specify an Android module/variant or Xcode project/scheme only if automatic discovery is ambiguous. For generated Xcode projects, set one `ios.prepareCommand` argument array.

An identity is:

- `unverified` until its existing/new Store record and dependent services are checked;
- `approved` only after ownership is proved;
- `blocked` when it is known to collide, belongs elsewhere, or must not ship.

Only `approved` identities can create candidates.

For an approved iOS identity, `ios.review.usesNonExemptEncryption` and `ios.review.demoAccountRequired` are reviewed source. The tool does not infer encryption classification or whether review can reach protected functionality. Demo credentials stay private and are required only when `demoAccountRequired` is true.

## 5. Adapt native signing inputs

The Android Release signing configuration reads these runtime values:

```text
MOBILE_RELEASE_ANDROID_KEYSTORE_PATH
MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD
MOBILE_RELEASE_ANDROID_KEY_ALIAS
MOBILE_RELEASE_ANDROID_KEY_PASSWORD
MOBILE_RELEASE_REQUIRE_SIGNING=true
```

It may permit unsigned Release assembly for `preflight --offline`, but it must fail when signing is required and any field is missing. The final AAB signer must match `uploadCertificateSha256`.

The Xcode Archive action remains Release and uses the application’s existing manual-signing configuration. The shared candidate workflow installs the configured P12/profile into an ephemeral keychain and passes explicit signing/export settings. The archive and exported IPA are validated independently.

The shared credential contract owns exactly one provisioning profile and maps export options
only for the configured main application Bundle ID. If an archive contains an extension, watch app,
or another target with its own Bundle ID/profile, the application must provide a bounded
project-owned signing-preparation step for those additional profiles and export mappings. Such a
project is otherwise unsupported by the shared profile inventory. Final nested-code validation
still checks the exported artifact; it does not discover or install the missing profiles.

The toolkit supports `ios.symbols.policy: retain`: it verifies the exact archive dSYMs, retains
them with the candidate, and never contacts Crashlytics or another third party. Automated symbol
upload is intentionally not part of the shared pipeline. `required` is a fail-closed activation
sentinel: its argv is syntax-checked but never executed, and signing preflight blocks until a
separately guarded candidate-stage integration exists. Do not select `required` expecting an
implicit local or CI upload.

Native Apple jobs use the versioned `macos-26` runner and select Xcode 26.3 build
17C529 explicitly. The job fails before project work if that compiler is absent or different. A
consumer must prove compatibility with this baseline during shadow integration; compiler changes
are shared-tool upgrades, not ambient `macos-latest` changes.

Map these user-defined values on the application target's Release configuration; do not pass the
standard signing keys globally, because they can leak into Swift Package or dependency targets:

```text
CODE_SIGN_STYLE = $(MOBILE_RELEASE_IOS_CODE_SIGN_STYLE)
CODE_SIGN_IDENTITY = $(MOBILE_RELEASE_IOS_CODE_SIGN_IDENTITY)
DEVELOPMENT_TEAM = $(MOBILE_RELEASE_IOS_DEVELOPMENT_TEAM)
PROVISIONING_PROFILE_SPECIFIER = $(MOBILE_RELEASE_IOS_PROVISIONING_PROFILE_SPECIFIER)
```

Give the user-defined values the same defaults the project already uses for ordinary local builds.
The shared signed path overrides them only for the application archive and verifies the resulting
profile, signature, Team, Bundle ID, and final exported artifact.

## 6. Add product-owned metadata

Use the configured metadata root:

```text
release/store/
├── android/<locale>/
│   └── images/
├── ios/<locale>/
├── ios/screenshots/
├── testflight/what-to-test.txt
├── review/ios-beta-notes.txt
└── review/ios-notes.txt
```

Only public product copy and approved fictional screenshots belong in Git. Private tester lists, reviewer contacts, demo credentials, signing material, and API keys do not.

Every configured Android locale requires `title.txt`, `short_description.txt`, and
`full_description.txt`. Every configured iOS locale requires `description.txt`, `keywords.txt`,
`privacy_url.txt`, `support_url.txt`, and `release_notes.txt`; iOS also requires reviewed
`testflight/what-to-test.txt`, `review/ios-beta-notes.txt`, and `review/ios-notes.txt`. Images alone
never satisfy metadata preflight.

Candidate metadata evidence is platform-scoped. The Android candidate archives only `android/**`;
the iOS candidate archives `ios/**`, `review/**`, and `testflight/**`, retaining those root-relative
paths. Promotion recomputes the same selected-platform archive, so an unrelated platform edit does
not invalidate a valid candidate.

Mechanical validation cannot establish that screenshots are honest or that privacy/content declarations are legally correct. Record those checks in the application’s release documentation and Store console.

Metadata preflight validates PNG/JPEG headers and positive image dimensions, not Apple/Google
device-specific screenshot sizes, color profiles, screenshot counts, or locale/device coverage. It
also validates that `*_url.txt` contains one absolute credential-free HTTPS URL, but does not make a
network request to prove reachability, redirects, ownership, or page content. Store upload and a
human visual/link review remain required.

## 7. Add bounded project checks

Generic validation cannot prove application-specific security or product behavior. Add only demonstrated checks:

```json
"projectChecks": {
  "preflight": [["./gradlew", "check"]],
  "androidArtifact": [["./scripts/verify-android", "${MOBILE_RELEASE_AAB_PATH}"]],
  "iosArtifact": [["./scripts/verify-ios", "${MOBILE_RELEASE_IPA_PATH}"]]
}
```

The public reusable preflight runs credential-free builds by default. When
`source.projectReadTokenRequired` is true, it still runs configuration, metadata, discovery, and
project checks, but records that compilation is deferred. Run that build locally with an explicit
read-only credential or let the protected candidate preflight perform it; the public job never
borrows candidate secrets.

Each command is an argument array, not a shell string. Supported artifact variables are substituted as complete arguments. The runner does not invoke a shell, interpolate environment syntax, or execute arbitrary before/after hooks.

Project checks may validate bundled endpoints, native libraries, source signatures, permissions, or legal resources. They must not publish backends, mutate a Store, or redefine the shared release lifecycle.

## 8. Configure external authority

Create the three fixed GitHub environments and add only the items reported by:

```bash
mobile-release credentials --stage all
```

Configure required reviewers for production. Configure Google WIF trust using the immutable GitHub repository ID and intended environment. Add a least-privileged App Store Connect API key. See [credentials.md](credentials.md).

For iOS external testing and production, also provision the dedicated 32-byte private-state HMAC
key and its version from the credential inventory. Retain the original key/version for incomplete
operations; rotation must not strand their authenticated private-state commitments.

Candidate first resolves any existing evidence in a read-only job without a Store environment.
Fresh candidates use the same fixed environment across three capability-separated jobs per selected
platform: a non-publishing Store/API gate, an application build/sign job, and a Store/evidence job. Depending
on environment protection settings, GitHub may request approval at more than one of these job
boundaries. That is intentional: the build job never has Store/OIDC authority, and the Store jobs
never run application commands. The signed AAB/IPA crosses the boundary only as a fixed-name,
checksum-bound artifact and is independently revalidated before upload. The Store job must persist
an authenticated intent before mutation. Recovery retains the original intent, handoff and source;
a complete final skips all Store/build work. These artifacts have 90-day retention, not an unlimited
recovery guarantee.

## 9. Prove the project locally

Run in order:

```bash
mobile-release doctor
mobile-release preflight --offline
mobile-release preflight --signing --credentials-file /absolute/private/mobile-release.env
mobile-release preflight --online --credentials-file /absolute/private/mobile-release.env
```

The first Store mutation should happen only after every applicable local finding passes and every manual prerequisite is explicitly listed.

## 10. Prove the lifecycle without removing the old path

For an existing application:

1. Run shared preflight beside current validation.
2. Compare final identities, versions, signatures, permissions/entitlements, hashes, and symbols.
3. Upload one internal candidate.
4. Promote the exact Store build to external testing.
5. Prepare a Play production draft and/or submit the exact Apple build with automatic release disabled.
6. Keep the old release path disabled but recoverable for one release cycle.
7. Remove old release logic only after the replacement receipts and readback are accepted.

Never migrate multiple applications by deleting their old workflows first.

## 11. Rehearse recovery and preserve evidence references

Use credential-free failure-injection tests or an explicitly authorized non-public canary to check
failure after intent upload and after Store acceptance, but before final evidence upload. Confirm
that recovery keeps the original bytes/version and does not overwrite unrelated Store state.
Do not test failure handling by starting a public rollout.

Keep per-platform evidence run/artifact outputs. Partial success may leave Android evidence in the
original run and iOS evidence in a recovery run; use the platform-specific candidate/external run
inputs instead of inventing one shared origin. A complete pending TestFlight receipt is immutable:
use a new external dispatch after availability, not a rerun to rewrite it. Read [Recovery](recovery.md)
for `recovery_run_id`, protected Apple ambiguity confirmations, retention and HMAC-key requirements.
