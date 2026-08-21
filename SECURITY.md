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
- Signed build output crosses to a fresh Store runner only through a fixed-name same-run artifact.
  The Store job compares the build job's upload receipt digest with the current-run artifact API
  record, the pinned download action recalculates and verifies that service digest, and the workflow
  then checks file hashes, safe layout, final identity, and signature before mutation.
- Expected public certificate fingerprints are reviewed application policy.
- Local files live outside the repository with restrictive permissions.
- Temporary credentials are created after cleanup handlers and removed on every exit path.
- Secret values and private identities are not logged, summarized, cached, attested, or uploaded as artifacts.

## Supply-chain rules

- Consumers explicitly select the shared repository, pin its workflows by full commit SHA, and
  provide that same SHA as `tooling_sha`; the reusable core contains no personal account default.
- Shared workflows pin every third-party action by full commit SHA.
- Every reusable job aborts its steps unless `runner.environment == github-hosted`, as defense in
  depth. This first-step assertion is not a server-side scheduling control and cannot prove that an
  eligible malicious runner never received a job payload or secrets.
- Before activation, a repository or organization administrator must verify and preserve runner
  policy/inventory so no self-hosted runner can match the pinned `ubuntu-24.04` or `macos-26`
  labels. Trusted custom runner groups are outside the v0.1 contract.
- Workflow Python calls use safe-path mode and `python -P`, preventing an application package in the current directory from shadowing the pinned release module.
- Runtime dependencies are locked and upgraded through reviewed pull requests.
- Store jobs use exact Ruby 3.3.12 and the Bundler 4.0.16/Gem checksums recorded by the lockfile.
- A candidate records repository ID, commit, Git tree, configuration/metadata hashes, final artifact hashes, public signers, Store build IDs, and workflow run/attempt.
- Promotion never rebuilds.
- Reruns fail closed when source, bytes, signer, Store identity, or receipts disagree.
- Promotion accepts only completed successful fixed-path workflow-dispatch runs from the current
  application repository whose head SHA matches the candidate evidence.

## Supported versions

Until the first stable major release, only the latest `0.x` release receives security fixes. After `v1.0.0`, the latest minor release of the current major is supported. Consumers remain pinned and must upgrade deliberately; security advisories will name affected versions and safe commits.
