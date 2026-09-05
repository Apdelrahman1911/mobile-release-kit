# Security policy

## Reporting a vulnerability

Do not open a public issue containing a secret, signing asset, private Store response, tester identity, reviewer contact, or exploitable release-pipeline detail. Use GitHub's private security-advisory reporting for this repository. If private reporting is unavailable, contact the repository owner through a private channel listed on the GitHub account and include only enough non-secret detail to establish contact.

No maintainer will ask for a keystore, P12, provisioning profile, P8 key, password, demo credential, or service-account key to reproduce an issue. Use sanitized fixtures.

## Security boundary

Mobile Release Kit protects the binding among reviewed source, final signed artifacts, Store build IDs, protected promotions, and readback evidence. It cannot prove:

- that an application owner’s legal/privacy/content declarations are truthful;
- that Store agreements, banking, tax, pricing, territories, or tester eligibility are correct;
- that Google, Apple, GitHub, or a runner is uncompromised;
- that a project-specific build script is safe merely because it was configured;
- that a public release should occur.

The final public-release decision is intentionally outside automation.

## Credential rules

- The shared repository and fixtures contain no real credential or account/application identifier.
- Consumers configure fixed environment-scoped names; reusable steps explicitly bind them and
  `secrets: inherit` is forbidden.
- Google CI uses OIDC/Workload Identity Federation rather than exported JSON keys.
- Apple P8, P12, profile, and Android keystore material are scoped to jobs that need them.
- Promotion/production jobs never receive build-signing assets.
- Candidate application build jobs have neither Store credentials nor `id-token: write`; Store/OIDC jobs never invoke application build, prepare, or project-check commands.
- Signed build output crosses to a fresh Store runner through an immutable fixed-name handoff.
  Original preparation verifies its trusted build-output/service digest, safe layout, file hashes,
  final identity and signing. Recovery additionally requires the original attested intent's complete
  artifact binding; artifact names and adjacent checksums alone cannot authorize Store access.
- Fresh iOS preparation inspects the required IPA/archive and supplied symbols on private
  immutable input snapshots. Every native image, bundle/resource counterpart and present dSYM
  must correspond. Signature-neutral hashes permit only bounded signing changes; complete signed
  artifact hashes authenticate the actual retained bytes, including signature-allocation slack
  that native codesign may not cover. UUIDs alone do not authenticate binaries or debug data.
  Original archive/symbol bindings remain mandatory for incomplete-operation execution/recovery.
- Historical Android recovery retains authenticated original signing/identity evidence rather than
  requiring an accepted build to remain eligible for a new upload. Every actual new AAB send repeats
  current pinned native validation in a credential-free child, full Store-state classification and a
  final exact-byte check. It cannot fall back to APK/batch/default discovery or a retrying Supply
  upload. The owned request disables logical retries without replacing Google's resumable protocol.
- Expected public certificate fingerprints are reviewed application policy.
- Local files live outside the repository with restrictive permissions.
- Initialization uses a root-directory lock and private recoverable staging on supported local
  Linux/macOS filesystems. Never commit/upload `.mobile-release-init-prepare/`,
  `.mobile-release-init/` or `.mobile-release-init-cleanup/`: their backups can contain original
  configuration. Ignore installation itself can be interrupted. Preserve pending state and use
  `init --recover`; unknown journals and intervening edits are conflicts, not authorization to
  overwrite or delete user files. This coordinates cooperating commands, not a hostile same-user
  process or a compromised filesystem. See [initialization recovery](docs/init-recovery.md).
- Temporary credentials are created after cleanup handlers and removed on every exit path.
- Secret values and private identities are not logged, summarized, cached, attested, or uploaded as artifacts.
- Store jobs remove preparation ADC files before intent attestation/upload, then separately acquire
  execution credentials and remove them before diagnostics/final actions. Apple P8/review/HMAC values
  are step-scoped. Deleting an ADC file is not revoking the Store job's OIDC capability: all pinned
  Actions in an `id-token: write` job remain within that privileged trusted-computing boundary.
- Private Apple review equality uses domain-separated HMAC-SHA256 under a dedicated protected
  256-bit key. Neither private values nor guessable plain hashes enter evidence. Retain its original
  key version for recovery; rotation is an explicit owner responsibility.

## Supply-chain rules

- Consumers explicitly select the shared repository, pin its workflows by full commit SHA, and
  provide that same SHA as `tooling_sha`; the reusable core contains no personal account default.
- Shared workflows pin every third-party action by full commit SHA.
- Every reusable job aborts its steps unless `runner.environment == github-hosted`, as defense in
  depth. This first-step assertion is not a server-side scheduling control and cannot prove that an
  eligible malicious runner never received a job payload or secrets.
- Before activation, a repository or organization administrator must verify and preserve runner
  policy/inventory so no self-hosted runner can match the pinned `ubuntu-24.04` or `macos-26`
  labels. Trusted custom runner groups are outside the shared contract.
- Workflow Python calls use safe-path mode and `python -P`, preventing an application package in the current directory from shadowing the pinned release module.
- Runtime dependencies are locked and upgraded through reviewed pull requests.
- Store jobs use exact Ruby 3.3.12 and the Bundler 4.0.16/Gem checksums recorded by the lockfile.
- A candidate records repository ID, commit, Git tree, configuration/metadata hashes, final artifact hashes, public signers, Store build IDs, and original authorization/actual execution/final producer identities.
- Promotion never rebuilds.
- Reruns fail closed when source, bytes, signer, Store identity, or receipts disagree.
- Before mutation, an attested immutable intent must already exist as a retained service artifact.
  Every final package retains the original intent proof and complete predecessor chain.
- Promotion authenticates fixed-path workflow-dispatch producers in the current application
  repository at their exact run attempt/job and pinned reusable workflow. It does not equate the
  producer with the latest attempt, nor reject a completed platform solely because another job
  failed. Application source, operation checkout, and current recovery dispatch are distinct claims.
- Workflow sidecars authenticate the complete payload inventory, including raw receipts. GitHub's
  service artifact API does not independently identify the uploader job. ZIP digest, producer
  attestation, exact job interval, immutable service selection, and complete chain are all checked;
  none alone is equivalent to the full authority proof.
- Complete final evidence is reused without reissue. Incomplete operations reconcile only under
  original intent and exact bytes. No missing-artifact fallback rebuild, overwrite, or silent Store
  adoption is allowed. See [recovery limitations](docs/recovery.md).
- Apple candidate reconciliation may require explicit owner attribution because Apple supplies no
  uploaded IPA digest. Later-process absence cannot authorize another create/upload request.
  Recovery is not a generic exactly-once network guarantee and never enables public release.

## Supported versions

Until the first stable major release, only the latest `0.x` release receives security fixes. After `v1.0.0`, the latest minor release of the current major is supported. Consumers remain pinned and must upgrade deliberately; security advisories will name affected versions and safe commits.
