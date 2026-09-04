# Mobile Release Kit

Mobile Release Kit is a small, versioned release layer for Gradle Android and Xcode iOS applications. It makes local release checks and GitHub Actions use the same configuration, builds each Store binary once, and promotes the exact recorded Store build through testing and production preparation.

It does **not** make an application public. Android automation stops at a non-served production draft. Apple automation stops after submitting an exact build for review with automatic release disabled. The application owner makes the final release decision in Google Play Console or App Store Connect.

## What lives here

- `mobile-release`, a Python CLI for discovery, configuration, credential inventory, preflight, artifact validation, metadata validation, and evidence.
- Four reusable GitHub Actions workflows for preflight, candidate upload, external testing, and production submission.
- Pinned Fastlane code used only for Google Play and App Store Connect operations.
- Strict JSON Schemas for application configuration, immutable candidate manifests, and Store receipts.

An application keeps its Gradle and Xcode source, signing integration, product metadata, privacy/legal decisions, and bounded application-specific checks. It normally adds one `release/mobile-release.json` file and four short workflow callers.

## Safety model

The release authority chain is:

```text
reviewed commit and Git tree
  -> one committed marketing version and build number
  -> signed final AAB / IPA
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
5. Every Store mutation is read back and recorded.
6. Production is a separate manual, protected, single-platform operation.
7. No workflow turns a release public automatically.
8. Legal, privacy, content-rating, agreement, pricing, availability, tester-membership, and launch decisions remain human responsibilities.

## Supported projects

Version 0.1 targets:

- Android applications built with a Gradle wrapper and an Android application plugin.
- iOS applications archived and exported with Xcode, including KMP applications.
- Checked-in Xcode projects/workspaces or a deterministic project-generation command such as XcodeGen.
- Manual Android keystore and Apple P12/profile signing material supplied at release time.
- Google Play CI access through GitHub OIDC/Workload Identity Federation.
- App Store Connect API access through a P8 key.

The v0.1 Apple credential contract installs one provisioning profile and maps export options for the
main application Bundle ID. An app with extensions, watch targets, or other separately provisioned
bundle IDs must keep its additional profile installation/export preparation in a bounded,
project-owned signing step; it is not supported by the shared profile inventory in v0.1. Nested-code
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
install the CLI. Apply also creates or safely appends the exact `.mobile-release/` line to the root
`.gitignore`; it preserves every existing line and refuses an unsafe/symlinked ignore file. Only
then run `doctor`. Store identities begin as `unverified`; candidate upload
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
PNG/JPEG headers with positive dimensions. Version 0.1 does not contact those URLs or enforce
Store/device-specific screenshot dimensions, color profiles, counts, or visual truth; those remain
Store and human review gates.

Reusable preflight compiles credential-free projects. If a project explicitly declares a private
dependency token requirement, the public job records compilation as deferred and leaves that check
to local preflight with an explicit read-only credential or the protected candidate environment.

Every reusable job aborts its steps unless `runner.environment` reports `github-hosted`. This is a
defense-in-depth runtime check, not a server-side scheduling control: before activation, a
repository or organization administrator must verify that no self-hosted runner is eligible for the
pinned `ubuntu-24.04` or `macos-26` labels. Version 0.1 does not configure trusted runner groups.
All workflow CLI calls use Python safe-path mode, so an application-owned `mobile_release` package
cannot shadow the pinned tooling checkout.

## Evidence paths

CI writes per-platform release evidence beneath `.mobile-release/`. Linux and macOS candidate jobs never race to edit one aggregate manifest:

```text
.mobile-release/
├── manifests/
│   └── candidate/<platform>.json
└── receipts/
    ├── candidate/<platform>.json
    ├── external-testing/<platform>.json
    └── production-submit/<platform>.json
```

Candidate build jobs upload a fixed-name, one-day same-run handoff containing the signed binary,
validation report, optional symbols, and `SHA256SUMS`. A separate Store job downloads it, validates
that the upload receipt digest exactly matches the current-run fixed-name artifact API record, lets
the pinned download action recalculate and verify that service digest, validates the file checksums,
independently revalidates the final signature and identity, and only then uploads. It writes fixed
evidence under
`.mobile-release/staging/<stage>/<platform>/` and normalizes it into the paths above. These files are
workflow artifacts, not files to commit. Signed binaries and symbol archives remain private GitHub
Actions artifacts with bounded retention.

Each candidate hashes a deterministic platform-scoped metadata archive: Android includes only
`android/**`; iOS includes `ios/**`, `review/**`, and `testflight/**`. An unrelated platform's
metadata cannot invalidate promotion of the selected candidate.

## Development

Run the repository tests without credentials:

```bash
python3 -m pip install -e '.[test]'
python3 -m unittest discover -s tests
ruby tests/workflow/test_play_store.rb
ruby -I. tests/workflow/test_fastlane_support.rb
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
- [Troubleshooting](docs/troubleshooting.md)
- [Upgrading pinned consumers](docs/upgrading.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
