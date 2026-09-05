# Upgrading Mobile Release Kit

Consumers deliberately pin a known-good full commit SHA. Updating a tag or `main` must never change an application release pipeline automatically.

## Version policy

- Semantic versioning applies to CLI/workflow behavior.
- The configuration/evidence `schemaVersion` is an independent integer.
- Patch releases fix compatible behavior.
- Minor releases add compatible behavior or optional fields.
- Major releases may change workflow/configuration contracts or safety behavior.
- Pilot releases remain `0.x`; treat every documented breaking `0.x` change explicitly.

Review the changelog and record the full source commit. Repository CI verifies wheel construction
and installation; it does not publish a release, package index upload, or checksum/signature assets.
Verify any separately distributed assets through their actual publisher's provenance before use.

## Consumer update process

1. Read the complete changelog and migration notes.
2. Update the local CLI to the candidate full SHA.
3. Update `$schema` only to the immutable raw URL for the selected tooling repository and commit.
4. Update the selected tooling repository coordinate, every `uses:` reference, and every
   `tooling_sha` value together in one pull request.
5. Run:

   ```bash
   mobile-release doctor
   mobile-release preflight --offline
   mobile-release preflight --signing --credentials-file /absolute/private/mobile-release.env
   ```

6. Run non-publishing online preflight if Store adapter behavior changed.
7. Review any new required/missing/manual findings.
8. Merge only after source-side and workflow-contract tests pass.
9. Create an internal testing candidate before using external or production paths with the new version.

Do not update only the caller `uses:` SHA. The called workflow verifies that the separately supplied `tooling_sha` resolves to the same commit.

## Shared release validation

Before publishing a shared-tool version:

1. Validate schemas and sanitized fixtures.
2. Run CLI unit/adversarial tests on supported Python/macOS/Linux environments.
3. Run workflow syntax, permission, environment, concurrency, action-pin, and no-publication contract tests.
   CI pins actionlint 1.7.12 and narrowly suppresses only its stale schema errors for the officially
   documented GitHub.com `job.workflow_repository`, `job.workflow_sha`, and `job.workflow_ref`
   fields. Duplicate YAML keys and steps without exactly one `run`/`uses` are checked separately;
   no broader actionlint ignore is permitted.
4. Run recorded/mock Fastlane Store tests without credentials.
5. Verify the pinned Apple runner, Xcode version/build, Java, XcodeGen, Ruby 3.3.12, Bundler 4.0.16, and action
   versions expected by the release; never inherit an ambient runner/toolchain change silently.
6. Pin the release candidate in one canary consumer.
7. Complete secretless and signing-only shadow checks.
8. Complete an internal testing candidate in the canary.
9. Validate a second consumer before declaring a stable major release.

The shared repository’s CI never uses real consumer credentials.

## Schema upgrades

Unknown fields are rejected so an old tool cannot silently ignore new security policy. When `schemaVersion` changes:

- install the new CLI first;
- compare the new schemas and migration notes; there is no automatic evidence-migration command;
- review the complete configuration/caller JSON and YAML diff;
- update application configuration and workflow SHAs in the same pull request;
- regenerate new candidate evidence after the upgrade.

Old manifests and receipts remain immutable historical evidence. Do not rewrite them to a new
schema. Promotions and incomplete-operation recovery require the exact original pinned toolkit.
Resolve any ambiguous previous Store writes before deciding to create a separate new candidate;
changing a build number does not reconcile an earlier mutation.

### v0.3 durable-operation migration

Configuration remains schema v1. Candidate manifests are schema v2, raw/sealed Store receipts are
schema v3, and operation intents and workflow producer inventories are schema v1. These contracts
are intentionally not compatible with older evidence: old receipts cannot authorize a new intent,
and a checksum-only local conversion cannot manufacture pre-mutation authority.

Before switching, finish/reconcile in-flight operations with their exact original tooling or
explicitly resolve them with the owner/Store. Then create a distinct candidate under the new pin.
Update all caller templates as well as both SHA references: new recovery and per-platform evidence
inputs/outputs, permissions, intent retention and actual-producer verification are coordinated
contracts. Do not splice a new reusable workflow into an old evidence chain.

iOS external/production environments now need
`MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64` (32 decoded bytes) and
`MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION`. Retain the original key/version for incomplete
operations. Rehearse post-mutation failure and same-candidate recovery before activation; see
[Recovery](recovery.md). Completed finals are reused unchanged, including pending TestFlight
observations. Record later availability with a new external dispatch, never by resealing old bytes.

## Rollback

Before any Store mutation, reverting the consumer SHA/configuration is an ordinary source change.

After an internal upload, do not silently switch tool versions while continuing the same candidate. Either:

- use the exact original pinned tool and matching receipts to finish/read status; or
- after resolving the previous operation's Store state, commit a new build number and explicitly
  create a separate candidate with the chosen tool version.

Never move an immutable tag, replace a release asset, edit a receipt, or claim two different binaries are one candidate.
