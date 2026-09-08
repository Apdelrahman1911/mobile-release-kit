# Required continuation workflow and final deliverables

## Rules carried from the user

Work **one confirmed issue at a time**. Preserve all existing user changes.
Never skip, downgrade, postpone indefinitely, or accept a confirmed finding
without concrete technical evidence that the original finding was incorrect.
Search repository records for any missing blocker; if its report truly cannot be
found, explicitly record that limitation rather than inventing it. The original
nine reports and all seven additional IDs have now been found and retained here.

For each issue:

1. **Re-analyze:** read the original finding, actual implementation, callers,
   workflows, tests, schemas, docs, Store interactions and edge cases. Reproduce
   safely where practical; identify the underlying cause before editing.
2. **Detailed plan:** specify root cause; exact files/behavior; compatibility,
   security, retry/recovery, concurrency, failure, regression and Store-state
   implications; tests, documentation and verification steps.
3. **Independent plan agent:** create a separate reviewer who re-reads the finding
   and code, challenges the plan, and checks lifecycle/provenance and unrelated
   Store preservation. Revise/re-review until technically sound; only then implement.
4. **Complete implementation:** focused code, adversarial/failure-injection tests,
   and accurate docs. Passing old tests alone is insufficient.
5. **Distinct implementation-review agent:** inspect actual diff/final behavior,
   callers and dangerous cases independently. Verify correction, idempotency,
   recovery, failure semantics and boundaries; find new bugs. Correct and repeat
   review where needed. The plan reviewer is not this second independent reviewer.
6. **Full validation:** all relevant regression tests and complete project gates,
   not only targeted tests. Freeze the exact source/tree and record actual outcomes.
   Never label blocked, skipped, unavailable or unexecuted checks as passed.
7. **Separate clean delivery:** only after approval and complete verification,
   commit the intended issue, push its branch, obtain required protected PR CI,
   merge normally to `main`, and verify actual main CI. Do not bypass protection,
   force-push main, combine all issues, or count a WIP checkpoint as a delivered fix.
8. **Resource closeout:** join/stop only workers you started; remove only proven
   disposable owned build/test outputs after preserving necessary proof. Then
   continue to the next issue.

The user's latest immediate-push request authorized this **handoff branch**, not
a false issue closure or an unverified protected-main merge. No release workflow,
Store operation, signing, public release or PR merge accompanies the handoff.

## Repository contributor rules

Python 3.11+ CLI source is under `src/mobile_release/`; reusable workflows under
`.github/workflows/`; callers under `templates/workflows/`; Fastlane in `fastlane/`;
schemas in `schemas/`; tests under `tests/unit/` and `tests/workflow/`; fixtures in
`tests/fixtures/`; guidance in `docs/`. Keep workflow/caller contracts synchronized.

Use four-space Python indentation, annotations, snake_case functions and PascalCase
classes; Ruby two-space indentation and frozen-string comments. Match neighboring
style; no global formatter is configured. Tests use unittest and Ruby assertions;
names are `test_*.py` / `test_*.rb`. Add regression coverage for every behavior
change; no numeric coverage threshold replaces semantic tests. Fixtures are fictional
and credential-free. Keep each commit focused with an imperative sentence-case title.

Read `SECURITY.md`. No secrets, signing assets, real account/application fixture
identifiers, signed binaries or raw `.mobile-release/` evidence in commits.
Third-party Actions/reusable workflows remain full-SHA pinned. Build, Store-authority
and promotion separation must survive every change. If `AGENTS.md` exists, read it
and never overwrite it as part of this task. The original user file was preserved
untracked; these portable instructions do not claim that a clone contains it.

## Non-negotiable release invariants

- Preserve **all unrelated** Google Play destination releases and verify complete
  before/after Store state. Metadata updates cannot accidentally replace other tracks.
- Retain authenticated immutable intent **before** mutation and reconcile readback
  after cancellation, process death, ambiguous network results, evidence/attestation/
  artifact failures and partial platform success. Never silently duplicate or adopt.
- Promote the original uploaded Store build: no rebuild, re-sign, version change,
  substitute artifact, or wrong Store selection. Preserve the manual public-release
  boundary and non-served Android draft / manual Apple release semantics.
- Distinguish application source, toolkit workflow, actual producer attempt/job/
  artifact, original authorization and current recovery dispatch. Checksums supplied
  with content are not independent authenticity.
- Build jobs have no Store credentials or Store-authorized OIDC; privileged Store
  jobs never execute application-owned Gradle/Xcode/checks. Exact confirmations,
  environments, checkout, outputs, artifacts and event/ref guards remain mandatory.
- Correlate IPA, archive, every relevant native image/slice, extensions/frameworks
  and retained dSYMs. Validate the complete signed entitlement set against each
  bundle's authorized profile, with typed wildcard/subset semantics. Do not weaken
  validation to make difficult configurations pass.

## Fresh production-readiness audit after the fixes

Start again as if conducting the first audit, tied to the exact new commit/tree.
Do not replace it with a check that the old IDs closed. Inventory **every first-party
file**, including hidden workflows/configuration, source, scripts, templates,
schemas, tests, fixtures, packaging, documentation and this handoff. Explicitly
classify historical inert snapshots, generated content and third-party code.
Maintain a coverage ledger with review method, result and remaining uncertainty.

Inspect all of these, including their cross-component contracts:

- Every Python command/subcommand: init, doctor, credentials, preflight, status,
  explain, ci; options/defaults, discovery, Android/iOS/KMP/monorepos/single-platform,
  ambiguous layouts, version/build source, unknown/duplicate/missing schema fields,
  paths, symlinks, archive extraction, subprocesses, errors and partial writes.
- All Fastlane and GitHub workflows/interfaces/triggers/jobs/permissions/secrets,
  OIDC/WIF, environments, confirmations, checkout/ref identity, artifacts/caches,
  third-party pins, concurrency, outputs, cancellation, skip/failure/rerun conditions.
- Android AAB metadata/package/version/signing/integrity, upload versus Play signing
  keys, internal/closed/open/production tracks, group assignment, changelogs/listing,
  complete edit/commit/readback preservation and non-public drafts.
- iOS Bundle/Team/version/build/certificates/profiles/entitlements, nested signed
  code, IPA/archive correspondence, every required dSYM, TestFlight processing,
  internal/external availability, beta review/groups, exact App Review selection
  and automatic release disabled; clear supported-profile limitations.
- Candidate, internal testing, external promotion, production preparation and
  manual release state machines; intent/receipt/manifest/attestation chains;
  exact bytes and producer/source identity; forged, replayed, incomplete, mismatched,
  substituted or expired evidence; legitimate promotion/recovery reuse.
- Partial platform success, interrupted local writes, ambiguous external outcomes,
  persistence/attestation/artifact failures, retention expiry, concurrent changes,
  idempotency, retries, reconciliation before resends, timeout/backoff/pagination,
  and failure to read back actual Store state.
- Signing and credential lifetime, account-wide local state, OIDC authority,
  profile authenticity, secret exposure through logs/args/reports/artifacts,
  redaction, retained resources and exact safe restoration.
- Real assertions/fixtures versus excessive mocks, text-only security contracts,
  mutation-sensitive tests, native Linux/macOS behavior, failure injection, whole
  package/wheel installs outside source, resource/schema contents, no-runtime-dependency
  claim, Python 3.11+, exact Ruby/Fastlane/Bundler/lockfiles/pins, tools and licenses.
- Every documented command/field/template/example/prerequisite, clean consumer
  integration journey, upgrade/recovery path, success/error message and guarantee.

Use synthetic/mocked Store interactions, not live mutations. Record actual commands,
exit codes and limitations. If Gradle is used, stop **that task's** daemon after
each sequence and remove only disposable owned outputs. Do not kill broad process
classes, delete shared caches, inspect private accounts or discard uncertain evidence.

Report severity-ordered stable findings with file/line, trigger, expected/actual,
evidence, impact, cause, correction/tests, and blocked lifecycle stage. Separate
confirmed defects, suspected issues, intentional limitations, maintenance and
external requirements. Reconcile ledger/findings/contracts at the end.

If new actionable defects are confirmed, apply the same independent plan/review/
implementation/review/test/protected-delivery process and repeat the full audit.
Issue **READY** only with evidence; otherwise **NOT READY** and every remaining
finding. Never confuse compilation, tests, comments or reassuring documentation
with production correctness.

## Final separate technical feature report

Only after the fresh audit justifies READY, produce a detailed product inventory,
not a short summary. For every major feature explain **what, why, how, implementation
locations, protective validation, covering tests, and limitations**.

Cover purpose/architecture/trust boundaries; platforms/project types; every CLI
option/config/discovery/version source; Android/iOS candidate/testing/production
flows; manual public release; Fastlane/reusable/caller workflows; signing, Apple
credentials/profiles and Google WIF; isolation/Store authorization; artifact handoff,
digests/manifests/receipts/attestations/source/workflow/run-attempt provenance;
recovery/resumability/idempotency/retries/reconciliation/concurrency; tracks/metadata;
entitlements/profiles/IPA/archive/dSYMs/nested binaries; filesystem protections;
credential safety/redaction; schema validation; package/dependency pins; initialization;
test architecture/security/failure handling; supported recovery scenarios; intentional
limitations/external requirements; and every other implemented repository feature.
