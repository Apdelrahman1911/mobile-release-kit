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
- Commit one new build number if any Store has consumed the current one.

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

## dSYM or Crashlytics failure

- Use the dSYM from the exact archived candidate.
- Compare executable and dSYM UUID sets.
- Do not search an arbitrary DerivedData directory.
- For `retain`, archive, validate, and retain the exact symbols without contacting Crashlytics.
- Version 0.1 has no automated third-party symbol-upload stage. `required` is a fail-closed
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

Do not rerun candidate upload immediately. Query the Store for the exact package/Bundle ID, marketing version, build number, and expected state. Resume only when exact identity can be proved. Otherwise commit a new build number.

If the candidate build job succeeded and the Store job failed before any possible upload, rerun only
the failed Store job so it consumes the original one-day same-run handoff. Rerunning all jobs would
compile a replacement binary and is not a valid continuation after an ambiguous mutation. If the
handoff expired, create a new candidate/build number rather than pretending a rebuild is identical.

External and production workflows may safely rerun when their candidate/previous receipt hashes and Store readback match.

For App Store production, a rerun adopts only an exact already-submitted manual-release version.
If the intended version record exists without a selected build, automation cannot prove whether a
prior metadata/submission attempt partially mutated it and refuses to call the submission action
again. Inspect App Store Connect manually; use a new committed build when exact recovery is not
possible.

For iOS, a submitted/in-review/approved Beta Review receipt cannot authorize production. Wait until
App Store Connect reports the exact assigned build as available to external testers, then rerun the
external-testing workflow with the same candidate run ID to create a fresh attested receipt. It does
not rebuild or re-upload the IPA.

## Promotion selected the wrong destination

- Internal, external, and production are separate workflows.
- `android.externalTrack.name` cannot be `internal` or `production`.
- Review whether the configured external track is closed or open; that is a product choice.
- A closed track must expose at least one assigned Google Group through the Play API. The tool
  stores only a boolean proof and never group/tester identities. Email-list-only tester assignment
  cannot be verified by this adapter and fails for manual resolution.
- Production is not a generic track input and accepts one platform per dispatch.

Never delete/replace unrelated releases in a destination track automatically.

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
custom runner work; trusted custom runner groups are outside the supported v0.1 contract.

## Metadata rejected

Version 0.1 checks required locale text, its known character limits, UTF-8/JSON validity,
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
