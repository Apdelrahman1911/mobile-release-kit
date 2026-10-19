# Existing App Store profile metadata read — 2026-10-19

## Scope

One explicitly authorized, selected-key read of **App Store profile and
referenced certificate metadata**, compared locally to the saved iOS Bundle ID.
This is not the account's complete certificate inventory, an authenticated
profile inspection, certificate/private-key matching, team proof or signing
readiness. No certificate or profile is created, replaced, revoked or assigned;
certificate/profile contents are not downloaded.

Root approved this direction; Tools independently approved its bounded plan.
The native trust/current-key/CSR/P12 inspection work remains separate. Nothing
here turns format-valid P8 custody into an Apple signing-key capability or
manufactures an `AppleResponse.settled` / `CertificateBinding` object.

## Reused original path

The existing LocalStorePreflight controller prepares the same native
`SavedCommandOwner` Session, Document/root/current credential context and
selected AscP8 material. Its new optional query is
`app-store-profile-reuse`; consent is exactly
`local-ios-profile-reuse-read-v1`. Neither Bundle-ID consent nor ordinary Store
access consent authorizes it. Prepare/Execute/Reconcile still reject queries:
the Python access helper's explicit query opt-in remains false for those callers.

`StorePreflightRun` retains its original saved-config/version byte comparisons,
P8 validation, five bundled runtime probes, fixed scratch roster, received
material checks and source/material POSTs. The seventh command alone is:

```
bundle exec ruby <original-held-tooling>/fastlane/apple_provisioning_profile_read.rb
```

It uses the existing 60-second maximum clamped to the original deadline, private
64-KiB capture, original `run_owned` process/finality and four scratches. There
is no readback file, eighth command, added process owner, generic command/URL
input, renewed deadline or new HTTP transport. Unknown/interrupted commands
propagate to the same original owner; a parsed response never settles cleanup.

The prior Bundle-ID reader's command body is factored into a private, closed
**two-query** raw-frame helper. Each wrapper still checks its own retained query
before calling it and parses only its own result. All original POST/cleanup
checks remain. The existing Bundle-ID path has regression coverage below.

The new Ruby entry defines only the fixed profile request. The original token,
`NoRefresh`, per-instance `ReadOwner`, raw Faraday callback and provisioning
`Adapter` are reused. Only the two exact input classes are admitted, not their
subclasses or arbitrary factories. The owner captures its exact request and
checks the actual outbound HTTPS origin/path/query/method/body/token before the
single wire attempt. It still has **no write permission**, even for otherwise
valid provisioning requests or approvals. No Fastfile, ambient account, token
refresh, SDK logical/transport retry, request/response logging or fallback is
introduced. Locked Fastlane/Faraday source provenance is in the preceding
`apple-provisioning-bundle-read.md`.

## Exact request and raw response

Reuse the already closed `api.list_profiles()` / Ruby provisioning Request:

```
GET https://api.appstoreconnect.apple.com/v1/profiles
filter[profileType]=IOS_APP_STORE
fields[profiles]=name,platform,profileType,profileState,uuid,createdDate,expirationDate,bundleId,certificates
include=bundleId,certificates
fields[bundleIds]=identifier,platform,seedId
fields[certificates]=certificateType,platform,expirationDate
limit=200
```

There is no invented `filter[bundleId]`, profile/certificate content, relationship
download, cursor, next request or account enumeration fallback. Consent explains
that this reads metadata visible to the selected key and filters locally.

The existing raw callback captures a single original response String, at most
32 KiB, **before** SDK JSON normalization. Only a same-status successful adapter
result can return those bytes, base64 encoded in the unchanged context-hash /
saved-Bundle-ID envelope. Duplicate/missing/oversized captures fail closed. The
Python parser sees the original raw bytes and rejects duplicate JSON members,
including members an SDK Hash decoder would otherwise silently collapse.

These are buffered-response/private-handoff caps, **not** SDK socket/RSS bounds
or native-runtime qualification. All existing runtime memory/admission and
original producer/reader/driver cleanup obligations remain with their owners.

## Conservative comparison

One page only: exact integer `meta.paging.total == len(data) <= 200`, no next
link, unique profile IDs and UUIDs. Sparse attribute rosters are checked for
**all** profiles and included resources before `Profile.parse`: unsolicited
`profileContent`, `certificateContent`, team assertions or other attributes
are rejected without invoking the download-capable content decoder.

Each profile has one scalar bundle reference and a nonempty, distinct
certificate-reference list within the existing 50-per-relationship bound.
Certificate relationships require an explicit integer paging total equal to
the returned list. Missing total is inconclusive, not implicit completeness.
Any provided to-one paging total must equal one; any next link refuses.

There are at most 200 bundle-reference occurrences and 400 certificate-reference
occurrences across the page (600 combined). Included metadata must equal the
exact unique referent union, at most 600 resources. Missing, extra, duplicate or
contradictory included resources refuse, including inconsistent identifiers on
unrelated returned rows. The previous permissive `validate_profile_included`
missing-resource behavior is deliberately not used as completeness evidence.

Every returned/included resource is parsed before projecting counts. Match only
the exact saved Bundle ID with compatible iOS/Universal metadata. `seedId` has
syntax checking only and is never compared as a Team-ID proof.

The conservative metadata/date candidate predicate requires an ACTIVE profile,
`created <= comparison time < profile expiration`, and **all** its referenced
certificate metadata to have a supported distribution type/platform and later
expiration. A mixed current/expired certificate list therefore has matching
metadata but zero candidates. This is not a statement that an existing profile
is unusable, nor a reason to issue another certificate. The worker comparison
clock is ordinary DATA, reported with exact UTC microseconds, not native trust,
account freshness or an authority to sign.

Only counts for matching profiles are projected; related certificate counts are
distinct references of those matching profiles, not unrelated account rows.
Provider names, UUIDs, IDs, attributes, seed IDs and raw bodies remain private.

Public result scope is `local-ios-profile-reuse-metadata-read`:

```
profileReuse: {
  observation: found | not-returned | not-permitted | inconclusive | not-checked,
  counts: { matchingProfiles, activeProfiles,
            currentMetadataCandidates, relatedCertificates } | null,
  checkedAt: "YYYY-MM-DDTHH:MM:SS.ffffffZ" | null
}
```

Counts and checkedAt are present only after complete parsing. `not-returned`
requires all zero counts and means this selected key's one response only — not
global absence, certificate quota availability, team ownership or permission to
create. 401/403 are not-permitted; other unsuccessful, unsupported, malformed,
partial or unconfirmed responses are inconclusive. Failed prerequisites are
not-checked. Those three states carry null counts/time. Public findings are the
same fixed prerequisite IDs/statuses, never Store-access success or raw errors.

The view is on the same existing controller, with an unchecked distinct consent,
original status/cancel controls and full saved-context historical comparison.
Earlier/other-project results are labeled as such. Unknown ownership never
becomes an empty list, a fresh attempt or an enabled signing/provisioning action.

## Root-only integration patch

`apple-provisioning-profile-read-wiring.patch` proposes exactly fourteen existing
file edits. No existing file in another worktree was modified by this lane:

1. `src/mobile_release/apple_provisioning_bundle_read.py` — same raw envelope /
   original command body, closed two-query dispatcher; old wrapper retained.
2. `src/mobile_release/_desktop_store_preflight_protocol.py` — second access-only
   query/result; default-false opt-in still closes all other Store contexts.
3. `src/mobile_release/desktop_store_preflight.py` — fixed seventh command and
   separate metadata report using the same original lifetime.
4. `src/mobile_release/tooling.py` — required bundled profile-reader file.
5. `fastlane/apple_provisioning_bundle_read.rb` — exact second input class and
   request-bound original owner; no new transport/lifecycle.
6. `desktop/src-tauri/src/apple_provisioning_bundle_read.rs` — second closed Query
   variant, separate consent and old-result refusal of profile fields.
7. `desktop/src-tauri/src/local_store_preflight_protocol.rs` — child declaration,
   exact query/consent/result discrimination; original finality unchanged.
8. `desktop/src-tauri/src/macos_store_runtime.rs` — same held source-file roster.
9. `desktop/src/localStorePreflightTypes.ts` — exact metadata comparison DTOs.
10. `desktop/src/localStorePreflightProtocol.ts` — closed raw grammar and bounds.
11. `desktop/src/localStorePreflight.ts` — same prepare/start owner, second query.
12. `desktop/src/components/LocalStorePreflight.tsx` — same-controller view entry.
13. `desktop/src/components/AppleProvisioning.tsx` — discoverable profile entry.
14. `pyproject.toml` — one existing data-file list entry for the actual Ruby file;
    no dependencies/lock/build framework. Root must approve/apply packaging.

No App, bridge, shell, lib, bootstrap or capability flag is changed. Root applies
and reviews the patch on its current graph; source copies are not an installed
runtime. Normal `git apply --check` and replay on task-owned copies were checked.

## Focused evidence and limits

Author results (zero skips):

- **17 new Python tests PASS**, 0.532 s: actual full Python package copy with the
  proposed source hooks, original finite input/file/scratch/StorePreflightRun,
  only command replies replaced with inert data. No actual subprocess allowed.
  Raw duplicates, attribute predecode guards, exact referent union, missing
  relationship totals, fractional boundaries, mixed certificate dates, 400 vs
  401 link occurrences, private projection, selected key validator failure,
  original STOP/source drift/unknown and zero-command other-Store refusals.
- **15 Bundle-ID Python regressions PASS**, 0.640 s, rerun because its shared
  raw/envelope command body changed. No broader Python suite was run.
- **21 Ruby tests / 450 assertions PASS**, 0.033157 s: 8 new profile tests plus
  the 13 existing shared-owner fake-SDK tests. Uses the original fake Faraday
  callback model, actual reader/adapter code, no maintained SDK evaluation,
  crypto, credentials, sockets or native execution.
- **17 Node tests PASS**, 353.305 ms: 9 new + 8 existing Bundle-ID controller/raw
  bridge tests because their shared protocol/controller changed. Fake native
  port only, no DOM or native provider.
- New Rust source formatted; three proposed native source copies parser-checked.
  New Python/shared source AST, both Ruby source syntax and exact one-entry
  packaging TOML checks passed. No Cargo or TypeScript graph build ran here.

After Root applies the hooks, focused commands are:

```
PYTHONPATH=src:tests python3 -B -m unittest -q unit.test_apple_provisioning_profile_read unit.test_apple_provisioning_bundle_read
ruby tests/workflow/test_apple_provisioning_profile_read.rb
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/apple-provisioning-profile-read.test.mjs desktop/tests/apple-provisioning-bundle-read.test.mjs
```

Root must compile the actual TypeScript/full Rust graph and run the five new
tests under `local_store_preflight_protocol::profile_read::tests`. These have
not been run here. Existing Bundle-ID tests reported by Root do not qualify this
new child. Actual Mac runtime/source/credential finality, real locked SDK/Apple
behavior and delivered package qualification remain distinct and unverified.
The current signing-key loan, CSR and distribution trust owners are not enabled
by this slice. No live account actions or real credentials were used.

## Bounded public schema inspection

Official public documentation JSON only, not provider/account endpoints:

`https://developer.apple.com/tutorials/data/documentation/appstoreconnectapi/`
followed by `profilesresponse.json`, `profile.json`,
`profilecertificateslinkagesresponse.json`,
`profile/relationships-data.dictionary.json`, and
`profile/relationships-data.dictionary/certificates-data.dictionary.json`.

Five bounded responses (~56 KiB total) were retained with their exact source URLs
at `/tmp/mrk-apple-profile-public-20261019-v1`. The certificate relationship has
optional `data`, `links` and `meta: PagingInformation`; this does not establish
completeness when meta is absent. The implementation keeps the independently
approved explicit-total requirement, treating otherwise permitted but
unconfirmed response shapes as inconclusive. No undocumented pagination
assumption or new endpoint was introduced.
