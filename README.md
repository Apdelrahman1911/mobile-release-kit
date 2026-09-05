# Mobile Release Kit

Mobile Release Kit is a small, versioned release layer for Gradle Android and Xcode iOS applications. It makes local release checks and GitHub Actions use the same configuration, builds each Store binary once, and promotes the exact recorded Store build through testing and production preparation.

It does **not** make an application public. Android automation stops at a non-served production draft. Apple automation stops after submitting an exact build for review with automatic release disabled. The application owner makes the final release decision in Google Play Console or App Store Connect.

## What lives here

- `mobile-release`, a Python CLI for discovery, configuration, credential inventory, preflight, artifact validation, metadata validation, and evidence.
- Four reusable GitHub Actions workflows for preflight, candidate upload, external testing, and production submission.
- Pinned Fastlane code used only for Google Play and App Store Connect operations.
- Strict JSON contracts for configuration, immutable operation intents, candidate manifests, Store receipts, and authenticated workflow inventories.

An application keeps its Gradle and Xcode source, signing integration, product metadata, privacy/legal decisions, and bounded application-specific checks. It normally adds one `release/mobile-release.json` file and four short workflow callers.

## Safety model

The release authority chain is:

```text
reviewed commit and Git tree
  -> one committed marketing version and build number
  -> signed final AAB / IPA
  -> durable attested operation intent and retained original artifacts
  -> immutable candidate manifest and artifact hashes
  -> exact Google Play / App Store Connect build IDs
  -> protected external-testing promotion
  -> protected production draft or review submission
  -> manual Store-console release
```

The non-negotiable rules are:

1. Debug and Store application identities differ; Store testing and production share the canonical Store identity.
2. CI never allocates or silently changes a version/build number.
3. Candidate is the only stage that builds or uploads a binary, but its application-build jobs and Store/OIDC jobs are separate runners with disjoint credentials.
4. External testing and production consume receipts; they do not compile, sign, or upload a replacement binary.
5. Every Store mutation requires durable authorization first and authoritative readback afterward; interrupted evidence creation is recoverable from the original intent.
6. Production is a separate manual, protected, single-platform operation.
7. No workflow turns a release public automatically.
8. Legal, privacy, content-rating, agreement, pricing, availability, tester-membership, and launch decisions remain human responsibilities.

## Supported projects

Version 0.3 targets:

- Android applications built with a Gradle wrapper and an Android application plugin.
- iOS applications archived and exported with Xcode, including KMP applications.
- Checked-in Xcode projects/workspaces or a deterministic project-generation command such as XcodeGen.
- Manual Android keystore and Apple P12/profile signing material supplied at release time.
- Google Play CI access through GitHub OIDC/Workload Identity Federation.
- App Store Connect API access through a P8 key.

The shared Apple credential contract installs one provisioning profile and maps export options for the
main application Bundle ID. An app with extensions, watch targets, or other separately provisioned
bundle IDs must keep its additional profile installation/export preparation in a bounded,
project-owned signing step; it is not supported by the shared profile inventory. Nested-code
validation still inspects the signed output, but does not provision those extra targets.

Desktop distribution, non-Gradle Android builds, non-Xcode Apple builds, certificate creation, account/IAM provisioning, and automatic public rollout are intentionally outside this repository.

## Quick start

Install and pin one released version. Never consume `main`:

```bash
pipx install "git+https://github.com/<TOOLING_OWNER>/<TOOLING_REPOSITORY>.git@<FULL_COMMIT_SHA>"
```

From an application repository:

```bash
mobile-release init
mobile-release init --apply \
  --tooling-repository <TOOLING_OWNER>/<TOOLING_REPOSITORY> \
  --tooling-sha <FULL_40_CHARACTER_COMMIT_SHA>
mobile-release doctor
mobile-release credentials --stage all
mobile-release preflight --offline
```

The first `init` previews its proposed files and does not write. Review discovered values and
unresolved policy fields, then run the explicit `--apply` command with the same full commit used to
install the CLI. Apply stages the complete integration under a project lock, preserves existing
metadata and ignore bytes, and rolls back ordinary precommit failures. After abrupt termination,
run `mobile-release init --recover` before applying again; committed recovery only finishes cleanup.
Never commit/upload the private `.mobile-release-init-prepare/`, `.mobile-release-init/` or
`.mobile-release-init-cleanup/` directories: they can contain original configuration backups.
Apply appends their exact ignore lines and `.mobile-release/`, but interruption may precede that
write. See [initialization recovery](docs/init-recovery.md) for supported filesystems and conflicts.
Only then run `doctor`. Store identities begin as `unverified`; candidate upload
remains blocked until ownership is proved and the reviewed configuration says `approved`.

Before CI, validate signing and Store access locally using an explicit credentials file outside the repository:

```bash
mobile-release preflight --signing --credentials-file /absolute/private/mobile-release.env
mobile-release preflight --online --credentials-file /absolute/private/mobile-release.env
```

Then configure these GitHub environments:

- `mobile-candidate`
- `mobile-external-testing`
- `mobile-production`

Before adding any environment credential, have a repository or organization administrator verify
that no self-hosted runner is eligible for the pinned `ubuntu-24.04` or `macos-26` labels. The
first-step runner guard is not a server-side scheduling boundary.

The generated callers pin the explicitly selected tooling repository and bind both `uses:` and
`tooling_sha` to the same full commit SHA. The reusable core contains no personal account
coordinate. See [Integration](docs/integration.md), [Credentials](docs/credentials.md), and
[Lifecycle](docs/lifecycle.md) before the first Store operation.

## Project contract

The default file is `release/mobile-release.json`. It contains only policy that cannot be inferred safely:

- version source and key names
- candidate and production source branches
- canonical Store identities and approval state
- external Play track and TestFlight group
- expected public signer fingerprints
- Store/team identifiers
- required locales and optional services
- reviewed iOS encryption/demo-account policy
- bounded project-specific check commands

Gradle module/variant and Xcode project/scheme fields are optional when discovery finds exactly one
answer. An explicit Android module uses Gradle path syntax (`:` for the root project, or a path such
as `:app`). Unknown keys, duplicate JSON keys, absolute/traversing paths, shell command strings,
disabled-platform configuration, and unapproved identities are rejected.

The authoritative schema is [`schemas/project.schema.json`](schemas/project.schema.json); [`templates/mobile-release.json`](templates/mobile-release.json) is a sanitized starting point.

## Commands and reports

| Command | Network or credentials | Purpose |
|---|---|---|
| `mobile-release init` | none | Discover a project and preview the thin integration. |
| `mobile-release init --recover` | none | Restore an interrupted init, or finish private cleanup after commit; no project discovery or Store calls. |
| `mobile-release doctor` | none | Validate configuration, discovery, tool availability, and identity policy. |
| `mobile-release credentials` | optional name-only GitHub access or local files | Report `CONFIGURED`, `MISSING`, `INVALID`, `NOT_APPLICABLE`, or `MANUAL_EXTERNAL` without revealing values. |
| `mobile-release preflight --offline` | no Store access | Run project checks and inspect unsigned release outputs/effective settings. |
| `mobile-release preflight --signing` | local signing files | Sign and deeply verify final AAB/IPA outputs without uploading. |
| `mobile-release preflight --online` | Store API credentials | Run a non-publishing access/uniqueness/destination check. Google uses a temporary edit that is always deleted without commit; Apple performs reads only. |
| `mobile-release status` | none | Validate and summarize recorded evidence; it does not query either Store. |
| `mobile-release explain` | none | Explain a finding or list the contract for a capability/stage. |

Commands produce a concise human report and can emit machine-readable JSON. Secret values, private tester identities, review contacts, and signed binaries are excluded from reports.

Metadata preflight checks required locale files, UTF-8/JSON structure, known text limits,
credential-free HTTPS URL syntax, placeholders/secret patterns, bounded safe paths/files, and valid
PNG/JPEG headers with positive dimensions. Local metadata validation does not contact those URLs or enforce
Store/device-specific screenshot dimensions, color profiles, counts, or visual truth; those remain
Store and human review gates.

Android requires reviewed `changelogs/<versionCode>.txt` or `changelogs/default.txt` for each
configured locale before candidate creation. Notes are limited to 500 Unicode characters including
uploaded whitespace/newlines, and the production intent binds their exact text. Fill or remove
init's empty default when using exact-version files; see [metadata setup](docs/integration.md#6-add-product-owned-metadata).

Reusable preflight compiles credential-free projects. If a project explicitly declares a private
dependency token requirement, the public job records compilation as deferred and leaves that check
to local preflight with an explicit read-only credential or the protected candidate environment.

Every reusable job aborts its steps unless `runner.environment` reports `github-hosted`. This is a
defense-in-depth runtime check, not a server-side scheduling control: before activation, a
repository or organization administrator must verify that no self-hosted runner is eligible for the
pinned `ubuntu-24.04` or `macos-26` labels. The toolkit does not configure trusted runner groups.
All workflow CLI calls use Python safe-path mode, so an application-owned `mobile_release` package
cannot shadow the pinned tooling checkout.

## Evidence paths

CI writes per-platform release evidence beneath `.mobile-release/`. Linux and macOS jobs never race to edit one aggregate manifest. Each final artifact contains:

```text
.mobile-release/package/<stage>/<platform>/
├── operation/                  # Original intent, producer proof, metadata/predecessors
├── candidate-manifest.json     # Candidate only
├── <stage>-receipt.json
├── store-receipt.json          # Exact raw Store readback
└── workflow-provenance.json    # Attested complete inventory and actual producer job
```

Candidate build jobs upload a fixed-name, 90-day handoff containing the signed binary, archive,
validation report, optional symbols, and `SHA256SUMS`. Before any original upload, a separate Store
job verifies the trusted build-output/service digest, safe layout, hashes, identity, and signing;
it then attests the exact binary and persists its operation intent. On recovery, the authenticated
original intent binds the retained handoff instead of relying on a new build-job output.
The read-only helper verifies GitHub attestations against the actual producer attempt/job and
pinned workflow, not the latest run attempt or overall success flag. These are private workflow
artifacts, not source files or public release assets.

iOS candidates require the retained archive under every symbol policy. Private-snapshot checks
correlate every IPA/archive native image, bundle/resource inventory and present dSYM before
authorization; exact artifact hashes remain authoritative during recovery. Export permits
re-signing but not stripping/thinning. See [iOS artifact correspondence](docs/ios-artifacts.md),
including the separate outstanding nested-symbol completeness requirement and native rehearsal.

All iOS signed entitlements are compared with their own bundle's modern DER profile
grants across every native architecture; profileless code cannot borrow a parent's
grants. Both profile CMS signatures and the production Apple issuer are independently
verified with pinned public roots in isolated credential-free workers. See
[entitlement validation](docs/ios-entitlements.md) and
[profile authority](docs/ios-profile-authority.md) for the supported native policy,
offline scope, recovery, required consumer rehearsal and separate local-signing
concurrency blocker. These checks alone do not establish overall production readiness.

Each candidate hashes a deterministic platform-scoped metadata archive: Android includes only
`android/**`; iOS includes `ios/**`, `review/**`, and `testflight/**`. An unrelated platform's
metadata cannot invalidate promotion of the selected candidate.

## Recovery and partial success

An incomplete operation resumes from its original attested intent and original bytes, including
after Store success but manifest, attestation, or final-artifact failure. A complete final artifact
is reused unchanged without Store access, binaries, rebuilding, or reissuing evidence. Android and
iOS can return different evidence run IDs; promotion inputs support those per-platform origins.
For older runs, use an explicit protected `recovery_run_id` dispatch with the same pinned tooling.

Apple exposes no IPA digest and does not guarantee idempotent resource creation. Ambiguous uploads
or missing creates may therefore require an exact, new operator recovery confirmation after
independent resolution; continued absence alone never authorizes another request. Existing accepted
builds can reconcile after signing assets expire using their authenticated original validation;
every new Transporter upload must still pass current signing/profile checks. See
[Recovery](docs/recovery.md) for required artifacts, immutable receipt reuse, safe retry cases,
HMAC-key retention, and fail-closed limitations. Recovery never makes a release public.

## Development

Run the repository tests without credentials:

```bash
python3 -m pip install -e '.[test]'
python3 -m unittest discover -s tests -v
bundle install
bundle exec ruby tests/workflow/test_play_store.rb
ruby tests/workflow/test_workflow_yaml.rb
bundle exec ruby tests/workflow/test_play_lanes.rb
ruby -I. tests/workflow/test_fastlane_support.rb
bundle exec ruby tests/workflow/test_apple_store.rb
bundle exec ruby tests/workflow/test_apple_lanes.rb
bundle exec ruby tests/workflow/test_apple_production.rb
bundle exec ruby tests/workflow/test_apple_production_lane.rb
bundle exec ruby tests/workflow/test_apple_asset_upload.rb
bundle exec ruby tests/workflow/test_ios_upload_validation.rb
bundle exec ruby tests/workflow/test_supply_wif.rb
bundle exec ruby fastlane/run_lane.rb --validate
```

Workflow-contract tests reject mutable action references, inherited secrets, Store/OIDC authority
in application-build jobs, build commands in Store jobs, missing hosted-runner runtime guards,
Python import shadowing, signing material in promotion workflows, missing protected environments,
cancellable Store mutation, and unsafe production defaults.

No shared-repository test uses a consumer credential or a real application/account identifier.

## Documentation

- [Integration](docs/integration.md)
- [Credential and secret contract](docs/credentials.md)
- [Release lifecycle](docs/lifecycle.md)
- [Recovery and resumability](docs/recovery.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Upgrading pinned consumers](docs/upgrading.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
