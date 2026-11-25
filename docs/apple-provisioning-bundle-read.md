# Saved Bundle ID read — bounded integration slice

Status: source/pure and synthetic-owner verification only. This does **not**
qualify an installed Mac, authenticate a real Apple account, establish a current
signing-key loan, or enable certificate/profile issuance. No live Apple calls,
real private keys, SDK evaluation, native processes, installation or builds were
used for these tests. Tools independently reviewed the plan, including the
pre-JSON raw-response amendment; distinct implementation review is still needed.

## Actual existing owner, not another provisioning engine

The supplied `apple-provisioning-bundle-read-wiring.patch` is for **Root to review
and apply**. No shared source in this lane was edited. Its only public request
extension is an explicit `query: "bundle-id-registration"` on an iOS
`prepare_local_store_preflight` request. It requires its own one-use
`local-ios-bundle-id-read-v1` consent, not the old app-access consent. The query
is retained in the actual native `Context`, `StoreCommand::Access` and prepared
attempt; no caller-selected Bundle ID, team, path, environment or secret is added.

The existing chain remains authoritative:

1. `asset_session_store_preflight` holds the same Document and registered root,
   reviews the original selected `AscP8` payload/native context and admits the
   existing Store memory budget. Start rechecks that same material and root.
2. `SelectedStoreMaterial::accepts_access_consent` matches the new consent
   against the retained query; `matches` compares the complete original context.
   No new credential borrower, key kind, inventory, actor or process owner exists.
3. `SavedCommandOwner` uses the existing Store-preflight installed runtime,
   bootstrap, C/A/W child path, private material writer, source/material POST,
   original STOP/deadline and child/reader/writer/driver/native cleanup joins.
4. `StorePreflightRun` validates actual saved configuration/version and selected
   P8, then runs its unchanged first six commands (P8 check + five bundled Ruby
   and dependency probes). The seventh is fixed:
   `bundle exec ruby <held-tooling>/fastlane/apple_provisioning_bundle_read.rb`.
   It captures private bytes for at most 60 seconds, further clamped to the
   original work endpoint. It never loads Fastfile or creates an access readback
   file. The original fourth `online-runner` scratch is reused; no fifth scratch.
5. Provisional Python result DATA becomes public only through the original
   terminal/finality checks. There is no manufactured `AppleResponse.settled`
   or success-shaped replacement for any original join.

The ordinary Google/Apple app-access grammar and results remain unchanged. The
shared Python context helper requires a separate default-false `bundle_query`
opt-in, used only by the access request/terminal parsers. Existing Prepare,
Execute and both Reconcile paths do not gain it through `apple_access=True`.
Other Store mutation contexts therefore do not accept the query. The retained saved-version
prerequisite is intentional reuse of the existing owner, not a requirement of
the Bundle-ID API itself. An otherwise format-valid **unverified** saved iOS
identity may omit appStoreAppId/TestFlight group; an invalid approved configuration
is still rejected by existing configuration policy. Nothing rewrites that policy
or downgrades a saved identity on the user's behalf.

## Supported SDK boundary and original HTTP bytes

The new entry constructs a **new token-based APIClient instance** using supported
`Spaceship::ConnectAPI::Token.create` and `APIClient.new(token:)`. All selected
P8/Key ID/Issuer ID inputs are explicit and private, with a fresh environment from
the existing installed runtime. Ambient Spaceship/Fastlane account, cookie,
enterprise, proxy and debug inputs are refused. Initial supported Token.create
may create its JWT; only that token is then extended to refuse later refresh.
No global token setter, cookie login or process-wide SDK modification is used.

It reuses `fastlane/apple_provisioning.rb`'s existing `Adapter` and per-instance
`ScopedTransport`: both logical retry layers and request/response logging are
suppressed. This read owner refuses **all writes**, even if presented with a
well-shaped provisioning approval. It admits only one wire entry:

```
GET https://api.appstoreconnect.apple.com/v1/bundleIds
filter[identifier]=<actual saved Bundle ID>
fields[bundleIds]=identifier,platform,seedId
limit=200
```

The APIClient ordinarily normalizes HTTP JSON before returning its Hash. A
duplicate `data` key ending in an empty list would otherwise be lost. Before the
first request, this one instance appends a `RawResponse` middleware through the
public Faraday `RackBuilder#use` interface. In locked Faraday1.10.6 the last
handler is nearest the adapter; its `on_complete` callback sees the original
String/status before the SDK's JSON/plist response parser. The owner retains one
exact binary copy only. Missing, repeated, oversized or non-String captures and
different final status refuse a successful response handoff. The adapter's
normalized Hash is **never** the input to the Bundle-ID comparison.

Private handoff (never a renderer/status DTO):

```
{schemaVersion:1, contextSha256:<complete query-context hash>,
 bundleId:<saved ID>, response:{status:<integer|null>,
 bodyBase64:<original HTTP bytes|null>,
 failure:<null|"provider_request_unconfirmed">}}
```

Bounds: original HTTP String at most 32 KiB, private Ruby stdout/stderr capture
at most 64 KiB, existing public terminal at most 16 KiB, one page at most 200
resources. The raw/handoff caps apply **after** the HTTP adapter buffers the
body; they are not socket ingress or SDK RSS bounds. The existing native Store
runtime/admission remains necessary. The fresh process and selected material
remain owned through actual original finality.

## What the user can conclude

`observation` is one of:

- `found`: a complete, single matching iOS/Universal resource was returned.
- `not-returned`: this selected key returned a complete empty response to this
  one read, **not** global availability or permission to register.
- `not-permitted`: the same captured response was 401/403; never absence.
- `inconclusive`: incomplete/unsupported/contradictory response, transport or
  capture failure, unexpected status, multiple matches, or pagination needed.
- `not-checked`: existing key/runtime/saved-input prerequisites blocked the read.

The raw parser rejects duplicate JSON members, mismatched context/identifier,
noncanonical base64, foreign/nonmatching resources, duplicate IDs, unknown
attributes, non-iOS platforms, non-null `next`, missing total or
`total != len(data)`. It neither follows another page nor retries. `seedId` is
syntax-checked comparison DATA, **never selected-team evidence**.

Public scope is `local-ios-bundle-id-registration-read`, with nine fixed
limitations and only existing bounded prerequisite finding IDs/statuses. There
is no public provider body, resource ID, prefix/team, token or account detail.
No result becomes a `CertificateBinding`, assignment, availability claim or
release-readiness fact. Individual API keys/unsupported roles or Apple account
agreements may require manual Developer-account work; no role escalation or
configuration rewrite is attempted.

`AppleProvisioning.tsx` is a view of the **same existing controller**. The ordinary
iOS access panel exposes its review under a disclosure; a retained Bundle-ID
query shows distinct consent/cancel/status/result copy. No App, bridge, shell,
lib, event relay, bootstrap or availability flag change is required. Earlier or
different saved contexts stay labeled as such. Status/cancel remain discoverable
on unknown outcomes; they do not enable retry. The result never masquerades as
the old Store-access success.

## Exact Root hooks

The patch contains these ten paths only:

1. `_desktop_store_preflight_protocol.py`: closed optional query/result branch.
2. `desktop_store_preflight.py`: fixed query command, bounds, scratch sequence and
   worker call after original P8 validation, preserving old access path.
3. `tooling.py`: add the two Ruby files to the existing complete tooling roster.
4. `local_store_preflight_protocol.rs`: child declaration, retained query,
   exact matching consent and closed result branch; four new child codec tests.
5. `macos_store_runtime.rs`: require those same two held installed tooling files.
6–9. `localStorePreflightTypes.ts`, `localStorePreflightProtocol.ts`,
   `localStorePreflight.ts`, `components/LocalStorePreflight.tsx`: closed types,
   parser, explicit query choice on the same attempt and the controlled view.
10. `pyproject.toml`: **proposed additional Root packaging-consistency hook**,
    exactly two entries in existing `share/mobile-release-kit/fastlane`
    data-files. Root approval of this tiny amendment is pending. Without it,
    adding required tooling files would make a newly built wheel incomplete.

`desktop/tools/prepare_macos_store_inputs.py` already consumes
`REQUIRED_TOOLING_FILES`; core preparation already packages all admitted core
source. Neither needs a new builder. The complete signed inventory remains
authoritative; old/incomplete packages cannot substitute ambient gems. No
dependency, lock, schema or workflow is changed.

Root applies the artifact only after review, e.g. `git apply --check <patch>` then
`git apply <patch>`. Empty context lines are serialized without trailing spaces;
actual Git apply was checked and replayed on task-owned source copies, producing
byte-for-byte the intended ten files. Root's real source was not modified.

## Verification and limits

Focused author results (zero skips):

- Python: **15 new tests PASS**, 0.665 s. Actual full current Python source copy
  plus the three proposed source hooks; original input FD/guard/finite scratch
  and `StorePreflightRun`, with only command execution replaced by inert replies.
  Covers seven fixed commands, source POST drift, actual input STOP, unknown
  command outcome, no replay, raw duplicates/counts/pagination and safe output.
  A distinct review found that Prepare/Execute/Reconcile reuse the context
  helper: corrected the initial implicit query opt-in and added valid legacy
  controls plus query refusal for all four paths, with zero commands.
- Python: **4 existing access tests PASS**, 0.383 s, explicitly selected Android
  six-command, Apple seven-command, closed contexts and finality tests.
- Ruby: **13 fake-SDK tests, 295 assertions PASS**, 0.024 s. Includes actual new
  reader + existing scoped adapter, raw callback before simulated JSON collapse,
  zero-write owner, no retry/logging, exact source/context, expired/changed token,
  replay refusal, missing/duplicate/oversized callback and redacted failures.
- Node: **8 new tests PASS**, 0.357 s, actual current frontend source copy plus
  four hooks, fake existing native port/raw bridge only. **8 unchanged access
  tests PASS**, 0.363 s. No DOM/browser/native automation or new fake owner.
- New Python AST, Ruby syntax, new Rust formatting/parser and two native patched
  source parser checks passed. Proposed packaging TOML has each new path once.
  Root-current patch apply-check and exact temporary replay passed.
- Initial author checks found and corrected one missing Python parenthesis and
  two fixture assumptions (exception type/approved config requirements; Node
  null-prototype comparison). Reported passing results are subsequent runs.

After Root applies the shared hooks, ordinary focused commands are:

```
PYTHONPATH=src:tests python3 -B -m unittest -q unit.test_apple_provisioning_bundle_read
ruby tests/workflow/test_apple_provisioning_bundle_read.rb
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/apple-provisioning-bundle-read.test.mjs
```

The Apple worktree's unchanged base shared protocols alone cannot run the new
hook-dependent tests; do not mistake a source copy for an installed path. Root
owns full graph TypeScript/Rust compilation and the four Rust tests under
`local_store_preflight_protocol::bundle_read::tests`. None ran here. Actual Mac
runtime nomination/packaging/private-custody finality and real locked SDK/Apple
behavior remain unverified. This patch enables no unqualified flag. Dedicated
current signing-key/CSR/P12 inspection and distribution trust remain absent;
issuance, certificate/profile reuse assignment and provisioning writes remain
separate work, not claimed by this read.

## Bounded public source provenance

Inspected text only, no gems installed or evaluated. Exact versions agree with
the repository Gemfile.lock: fastlane2.235.0, faraday1.10.6,
faraday_middleware1.2.1. Selected public source/licenses are retained at
`/tmp/mrk-apple-fastlane-public-20261019-v1` for this review, not private origins.

- `https://raw.githubusercontent.com/fastlane/fastlane/2.235.0/`:
  `spaceship/lib/spaceship/connect_api/api_client.rb`
  SHA256 `2c42e182c02c2a5ecb2cad99d5c77d0c5c663bb3b6a595c38718314d3cefeffa`;
  `connect_api/token.rb`
  `cba60231cd70b1a6097b96f4048720ee44962a444e6abed7b410f8c2d8483982`;
  `spaceship/lib/spaceship/client.rb`
  `36e0e0ce570687173bb9681a93df9bfad7eb4fa450f44d0516fbaab14563c71a`.
  Also inspected TokenRefresh/Stats middleware and top-level require entry.
- `https://raw.githubusercontent.com/lostisland/faraday/v1.10.6/`:
  `lib/faraday/rack_builder.rb`
  `5fbd4bb4bd6e278a82a47c96cd7a0be931b71250d18fe1e7dd799fc8a0816b96`;
  `lib/faraday/response.rb`
  `53015bad468c4ee9333e4f7a0842d4dd36ac1076b2ca220bf876f15db937c2f0`.
- `https://raw.githubusercontent.com/lostisland/faraday_middleware/v1.2.1/`:
  `lib/faraday_middleware/response_middleware.rb`
  `9277ba94dfb49158679c65d8ae63536210754cc86bbc7bbb2c3046f57f528afc`;
  `lib/faraday_middleware/response/parse_json.rb`
  `cd8addf857752def087813f6b561bb6f65895938518883bd3f8cf544de357db5`.

Each project's MIT license text was retained alongside these public files.
These source observations justify interface/callback ordering only, not native
trust, runtime availability or live API acceptance.
