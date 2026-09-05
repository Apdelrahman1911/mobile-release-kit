# Troubleshooting

Start with the earliest failing command. Do not bypass an inexpensive failure and wait for CI to rediscover it.

## Finding statuses

| Status | Meaning |
|---|---|
| `PASS` | The check ran and proved its assertion. |
| `FAIL` | Evidence contradicted the required policy. |
| `MISSING` | A required configuration, file, variable, or secret name is absent. |
| `INVALID` | An input exists but cannot satisfy the required identity/format/purpose. |
| `SKIP` | The check is inapplicable or needs an unavailable optional capability; the reason is reported. |
| `MANUAL` / `MANUAL_EXTERNAL` | A human/console responsibility cannot be proved by the command. |

An applicable `FAIL`, `MISSING`, or `INVALID` blocks the next release stage. Do not turn it into `SKIP` to proceed.

## Configuration rejected

- Validate `release/mobile-release.json` against `schemas/project.schema.json`.
- Remove unknown keys and duplicate JSON keys.
- Use repository-relative paths without `..`, symlinks, or absolute prefixes.
- Represent commands as argument arrays, not quoted shell strings.
- Set only `enabled` on a disabled platform.
- Supply an explicit Gradle module/variant or Xcode project/scheme only when discovery reports multiple candidates.

## Identity is unverified or blocked

Candidate upload requires `identityStatus: approved` in reviewed source.

Do not approve an identity based only on syntax. Prove Store ownership and audit Firebase, APNs, associated domains, Keychain/app groups, OAuth callbacks, deep links, URL schemes, backend allowlists, and other identifier-bound services. A known collision remains blocked until replaced.

Debug and Store identities must differ. Test tracks use the canonical Store identity; adding a `.testing` application is not the fix.

## Versions disagree

- Check that Gradle and Xcode both read the configured file and keys.
- Inspect effective Android manifest/AAB and Xcode archive/IPA values, not only source text.
- Remove workflow-run, Store-derived, and hardcoded secondary build numbers.
- For a genuinely new candidate, commit one new build number if a Store consumed the current one.
  An interrupted original candidate instead needs intent-based recovery; do not change its version.

CI never rewrites a version or chooses the next integer.

## Signing asset invalid

Android:

- verify keystore password, alias, private-key entry, and key password independently;
- compare the final AAB/APK certificate SHA-256 to the configured existing Play upload certificate;
- a structurally valid self-signed or unrelated certificate is not acceptable.

Apple:

- confirm P12 private-key/certificate pairing and distribution purpose;
- confirm the profile includes that certificate and exact Team/Bundle ID;
- reject expired, development, ad-hoc, wildcard, or `get-task-allow=true` profiles;
- verify archive and exported IPA, including nested frameworks/extensions.

If the workflow fails after credential import, verify temporary keychains/profiles/decoded files were removed before retrying.

### Signed entitlement or modern profile comparison fails

- Check each app/extension's own profile grants, not only its parent's capabilities.
- Use a modern profile with `DER-Encoded-Profile`; outer/inner entitlement,
  certificate, identity and validity fields must agree. Do not strip DER to bypass a check.
- Inspect every native architecture and remove accidental entitlement claims from
  profileless frameworks/helpers. App groups are exact grants, not arbitrary wildcards.
- Correct capability/profile settings before a new candidate; never re-sign an
  accepted candidate to finish its original evidence. See [entitlement rules](ios-entitlements.md).
- An issuer/signature failure requires a genuine modern Apple-issued profile and
  supported macOS policy APIs/pinned toolkit resources. Do not remove DER, import
  a custom root, backdate validation or use `security cms -D` as a bypass.
- Issuer validation is offline, not a live revocation/account-status check. Finish
  existing candidates under their original authenticated pin/bytes; never renew
  profiles or rebuild an accepted candidate for evidence completion. See
  [profile authority and cleanup limits](ios-profile-authority.md).
- Do not overlap local signing preflights: global keychain/profile lifetime
  coordination remains the separate confirmed QA-003 blocker, pending remediation.
- A profile descriptor, selector, worker, scratch or handler-cleanup error is a
  failed validation even when authentication already completed. Do not retry an
  ambiguous descriptor close; end that process and inspect only its recorded
  owned residues. Default-signal protection does not cover custom host handlers
  or hard termination.
- QA-004 separately leaves outer build-input scratch/client restoration vulnerable
  to cancellation at cleanup entry. Verify decoded scratch removal and original
  client configuration before retrying. Do not infer outer cleanup from successful
  inner profile/keychain cleanup, or remove another task's files.

## dSYM or Crashlytics failure

- Use the dSYM from the exact archived candidate.
- Compare executable and dSYM UUID sets.
- Do not search an arbitrary DerivedData directory.
- For `retain`, archive, validate, and retain the exact symbols without contacting Crashlytics.
- There is no automated third-party symbol-upload stage. `required` is a fail-closed
  activation sentinel: its command is validated but never executed, so preflight blocks until a
  separately guarded candidate-stage integration is implemented.

## Store access denied

Google:

- verify WIF provider, service account, repository ID/name/environment conditions, audience, and Play permissions;
- use separate testing and production identities;
- do not replace WIF with a long-lived CI JSON key.

Apple:

- verify P8 structure, key ID, issuer ID, key role, app access, agreements, and app record;
- distinguish API authentication failure from signing-certificate failure.

Run non-publishing `preflight --online` before retrying a mutating workflow. Google inspection uses
a temporary edit that is deleted without commit; Apple inspection performs reads only.

## Upload timed out or returned an ambiguous error

Do not run a fresh upload or change the build number to hide an ambiguous outcome. Preserve the
original intent, handoff, raw readback, final evidence and diagnostics. Use the same pinned workflow
to resolve/reconcile the original operation. The [recovery guide](recovery.md) describes which exact
evidence is required and when a new protected `recovery_run_id` dispatch is appropriate.

For Android, download the attempt-specific `mobile-release-play-state-android-*` diagnostic
artifact before it expires. Check its ordered `history`, failure classifications,
mutation/readback edit IDs, and complete before/expected/observed track snapshots.
`committed-and-read-back` is a successful exact reconciliation;
`commit-response-ambiguous` or `failed` requires explicit reconciliation and must not be treated as
a receipt. Never edit or locally reseal evidence to manufacture success.

If the build succeeded and preparation failed before mutation, prefer **Re-run failed jobs**. The
90-day handoff's original trusted build digest and positive proof that every prior execute step was
skipped after a pre-execution failure are required. Rerun-all does not authorize a rebuild. Missing,
deleted or expired evidence is not proof that no Store write occurred: preserve what remains and
resolve through the owner/Store rather than substituting another binary.

An authenticated complete final is returned unchanged with no Store access. Incomplete external
or production operations reconcile their original intent resource by resource. A partial Apple
version or review submission can resume only when exact before/target and preservation checks
pass. An ambiguous absent Apple create requires a new inventory-bound protected confirmation,
never an automatic POST retry. Apple candidate attribution/upload retry likewise requires the
specific recovery confirmation described in [Recovery](recovery.md).

Profile/certificate expiry does not invalidate authenticated original validation for an already
accepted iOS build. Every new upload, including a same-byte retry, still needs current validation;
the toolkit never ignores a signing failure, rebuilds or re-signs during recovery.

For iOS, a submitted/in-review/approved Beta Review receipt cannot authorize production. Once the
exact assigned build is available to external testers, make a **new external-testing dispatch**
with the same candidate references and no `recovery_run_id`. A rerun preserves the old final and
cannot refresh it. Neither path rebuilds or re-uploads the IPA.

If a local manifest/receipt write failed, retain the matching original intent and raw observation.
The CLI never overwrites immutable evidence or falls back to a Store mutation when existing final
evidence is invalid. If surviving partial output cannot be completed, use a new empty output
directory with the **same intent and artifacts**; do not delete evidence to bypass the guard.

## Promotion selected the wrong destination

- Internal, external, and production are separate workflows.
- `android.externalTrack.name` cannot be `internal` or `production`.
- Review whether the configured external track is closed or open; that is a product choice.
- A closed track must expose at least one assigned Google Group through the Play API. The tool
  stores only a boolean proof and never group/tester identities. Email-list-only tester assignment
  cannot be verified by this adapter and fails for manual resolution.
- Production is not a generic track input and accepts one platform per dispatch.

Never delete/replace unrelated releases in a destination track automatically.
The guarded adapter treats any unrelated release change, duplicate target, multi-version source
release, unsupported source transition, or post-commit mismatch as a hard failure. Google may
remove only the promoted target from its source track automatically; that transition is recorded,
not treated as collateral loss. Resolve concurrent
Console edits before retrying; the tool never rolls back by overwriting current Store state.

## Git source rejected after a protected rebase

Fetch enough history. The accepted alternatives are direct ancestry or exact-tree equality with a real merge base. An unrelated repository/history with the same copied tree is intentionally rejected.

Do not use a tag, version string, or commit message as a workaround.

## Wrong release module or runner selected

Reusable workflows abort their steps unless `runner.environment == github-hosted`, set
`PYTHONSAFEPATH=1`, and invoke the shared module with `python -P`. The runner check is defense in
depth after scheduling; it does not stop a self-hosted runner carrying copied labels from receiving
the job. Have a repository or organization administrator remove that runner's eligibility for
`ubuntu-24.04` and `macos-26` before activation or retry. An application-owned `mobile_release`
package in the current directory is ignored by safe-path mode. Do not remove these guards to make a
custom runner work; trusted custom runner groups are outside the supported contract.

## Metadata rejected

Metadata preflight checks required locale text, its known character limits, UTF-8/JSON validity,
placeholders/secret patterns, absolute credential-free HTTPS URL syntax, allowed file suffixes and
sizes, safe non-symlink paths, and PNG/JPEG headers with positive dimensions. It does not contact
URLs or validate Store/device-specific screenshot dimensions, color profiles, screenshot counts, or
locale/device coverage. Use the Store validator and human review for those properties. A
mechanically readable screenshot still needs review for fictional/private data, locale/theme,
accurate UI, and honest claims.

Privacy, rating, pricing, agreements, territory, and legal answers must be corrected by the responsible owner in the Store console; the CLI does not invent them.

## Production did not go live

That is the intended boundary:

- Android automation ends at a Play production draft.
- Apple automation submits for review with automatic release disabled.

After review/approval, an authorized human performs the public release in the Store console.
