# Changelog

All notable changes to Mobile Release Kit are documented here. The project follows Semantic Versioning after the initial `0.x` pilot series.

## Unreleased

### Added

- v0.3 two-phase Store operations: strict immutable intents are attested and retained before
  mutation; final evidence retains original authorization, raw readback, predecessor proofs and
  actual producer run/attempt/job inventories. Candidate schema v2, receipt schema v3 and intent
  schema v1 intentionally reject earlier evidence rather than silently migrating it.
- Read-only recovery resolution, 90-day original handoffs/intents, explicit `recovery_run_id`, and
  per-platform evidence references for partial Android/iOS success. Complete authenticated finals
  are reused unchanged without Store access, binary retention, new attestations or replacement
  uploads. Incomplete operations never rebuild, re-sign or allocate new versions.
- Resource-granular Google Play and Apple reconciliation, private-review HMAC commitments,
  bounded Apple asset handling and explicit new operator grants for ambiguous uploads/creates.
  Before/target/readback checks preserve unrelated Store state and the manual-public-release boundary.
- Current iOS upload eligibility immediately before every Transporter dispatch; authenticated
  original validation remains usable to reconcile already accepted builds after signing expiry.
- Credential-free actual-lane cross-language contracts, failure-injection and workflow lifecycle
  tests, plus recovery/credential/upgrade documentation.

### Fixed

- Compare every iOS signed entitlement with its own modern DER profile grants using
  strict typed subsets and capability-specific wildcards. Inspect every native slice,
  reject profileless nested claims, malformed/duplicate encodings and stale certificate
  outputs; retain historical accepted-build recovery. Apple profile issuer authentication
  remains the separate open production blocker QA-002; CMS decoding alone is not authority.
- Validate complete original binary plist structure before conversion; reject unsupported
  integer/date precision and overlong XML references, and preserve real signed zero in
  archive/IPA resource comparisons without rewriting artifacts.
- Make `init --apply` recoverable across all configuration, caller, metadata and ignore writes,
  including forced replacements. Stage complete output before installation, restore original
  inodes on precommit rollback, serialize cooperating commands, reject path aliases, and preserve
  existing metadata/ignore bytes. Add explicit `init --recover` for interrupted transactions;
  committed cleanup never rewrites destinations. Require local Linux/macOS filesystem semantics
  for mutation, leaving preview portable; document private-state retention and conflict handling.
- Require and correlate iOS IPA/archive native images, typed bundle metadata, resources and every
  present retained dSYM on private snapshots before candidate authorization. Bind archive/symbol
  hashes at execution, reject source-path ABA/substitution, and disable export stripping/thinning.
  Preserve signature-only changes and authenticated historical recovery; complete missing-nested
  symbol coverage remains a separate requirement.
- Require bounded, reviewed Android release notes for every configured locale before candidate
  creation and production preparation. Generate an owner-completed default stub, bind exact raw
  text to the production intent, and use immutable validated notes in Supply workers without
  changing unrelated historical releases or retry/reconciliation behavior.
- Replace Supply's destructive one-release Google Play track writes with a guarded adapter that
  preserves every unrelated release, validates the complete source/destination state before
  commit, commits once without transport retries, and verifies the exact committed state through a
  fresh edit while allowing only Play's documented target-only source deactivation.
- Bind Store receipts to explicit mutation/reconciliation/observation outcomes and complete
  Play track-state relationships; v0.3 also binds original operation authority and raw observations.
- Retain a private per-attempt Play state journal after Google credentials are removed so an
  ambiguous or post-commit failure can be investigated without exposing credentials or binaries.

## 0.1.3 - 2026-08-22

### Fixed

- Restrict every GitHub OIDC-generated Google ADC file to owner-only mode `0600` before the shared
  private-credential validator or a Play Store adapter can read it, while retaining bounded-path,
  non-symlink, and unconditional-cleanup checks.

## 0.1.2 - 2026-08-21

### Fixed

- Canonicalize the final signed AAB with `jarsigner` so strict verification sees the same signed entries through both JAR stream and central-directory readers.

## 0.1.1 - 2026-08-21

### Fixed

- Query effective Android Debug application IDs through the modern Android Components API while retaining the legacy variant fallback.

## 0.1.0 - 2026-08-21

### Added

- Strict project, immutable candidate, and Store-receipt schemas.
- Sanitized configuration and evidence fixtures.
- Local discovery, credential inventory, preflight, artifact validation, and evidence contracts.
- Reusable preflight, candidate, external-testing, and production-submission workflow contracts.
- Pinned Fastlane boundary for Store upload, promotion, submission, and readback.
- Integration, credential, lifecycle, troubleshooting, security, and upgrade documentation.

### Safety defaults

- One committed cross-platform version/build source.
- Build once and promote exact Store build IDs.
- Separate Debug and canonical Store identities.
- Google production ends as a non-served draft.
- App Store production ends at review submission with automatic release disabled.
- Public release remains a manual Store-console decision.
- TestFlight production eligibility requires an externally assigned build read back as available to testers; pending Beta Review evidence cannot authorize production.
- App Store production reruns adopt only the exact already-submitted manual-release build and refuse ambiguous partial state.
- Candidate Store gates, application build/signing, and Store upload/evidence run as separate jobs;
  application code never shares a job with Store credentials or OIDC authority.
- Fixed-name same-run candidate handoffs are artifact-digest/checksum bound and independently
  revalidated for final identity and signature before upload.
- Candidate artifacts retain the exact manifest-bound metadata archive and signing/project-check validation report.
- Tooling repository ownership is a consumer input; the reusable core has no personal GitHub
  coordinate and binds itself through GitHub's resolved reusable-workflow repository/SHA context.
- Promotion verifies predecessor workflow identity, exact head SHA, and successful completion before
  consuming uploaded evidence.
- Project initialization safely ensures generated `.mobile-release/` state is ignored without
  replacing an existing root `.gitignore`.
- Candidate mutation credentials are acquired only by the Store job after the signed handoff and
  never coexist with a Gradle, Xcode, or project-check invocation.
- Every reusable job aborts its steps when `runner.environment` is not `github-hosted`, with an
  explicit activation prerequisite that administrators prevent self-hosted runners from being
  eligible for the pinned labels because the first-step guard is not a scheduling boundary.
- Python safe-path mode prevents application-owned packages from shadowing the pinned shared CLI.
- `symbols.policy: retain` validates and retains exact dSYMs; automated third-party symbol upload is
  intentionally absent, and `required` blocks as an activation sentinel.
