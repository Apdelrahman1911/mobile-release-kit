# Current iOS Store versions and explicit allocation policy v2

## Delivered source scope

The existing local Store-preflight action gains one explicit, read-only iOS
query, `ios-current-versions`, and a mounted panel in the existing Store view.
It uses the same saved config/version inputs, assigned P8, private material,
Store runtime, command owner, cancellation, cleanup and native retirement. It
does not start on mount, change the default manual version policy, upload,
create a Play edit, build, sign, or change a project file. The existing access,
Bundle ID and profile checks retain their separate query/consent vocabulary.

This packet also adds an explicit v2 consumer to the existing Python allocator,
native allocation state/dialogue, and authentic version-edit preparation helper.
It **does not yet install the native Reserve operation**. The selected GitHub
account + Source + original native state-job/ACK choreography, its separate
reservation consent, and the mounted automatic-policy action remain necessary.
The installed CLI/CI have no new allocation command. No availability or native
qualification flag is enabled here.

## What the observation means

`asc-ios-current-inventory/1` means complete traversal of three bounded
**currently visible** collections for the saved numeric App Store app ID and
bundle ID. It is neither an atomic snapshot nor every version/build ever used.
Historical uploads may no longer be returned; another uploader can act after
the read. A shared GitHub counter coordinates cooperating clients only.

Fixed GET schedule, with one original 60-second query deadline:

1. `/v1/apps/{id}` before the lists: exact numeric ID and bundle ID.
2. `/v1/builds`, filtered only by that app, including `app` and
   `preReleaseVersion`. A build has no platform attribute: each row must join
   the exact app and its version/platform/app prerelease-version relationship.
   Unjoinable processing/failed rows are not silently skipped.
3. `/v1/apps/{id}/buildUploads`, reading `cfBundleVersion`,
   `cfBundleShortVersionString`, `platform` and `build`. This collection is
   bound by its app-scoped path, not a fabricated app relationship. A null or
   absent build relationship still reserves the upload's requested number.
4. `/v1/apps/{id}/appStoreVersions`, reading `versionString` and `platform`.
5. Repeat the exact app check after the lists.

There are no status, expiry, build-number or marketing-train filters. Each
collection has at most two pages of 200 records, with exact continuation query,
stable reported count, distinct IDs, and no extra page/cycle. At most eight GETs
are attempted. Over 400 records or an unfinished traversal is unavailable, not
a partial floor. Counts shown in the UI are iOS records; traversal bounds also
include returned records for other supported platforms.

Public API source used for the endpoint/field review:

- <https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builds>
- <https://developer.apple.com/documentation/appstoreconnectapi/get-v1-apps-_id_-builduploads>
- <https://developer.apple.com/documentation/appstoreconnectapi/get-v1-apps-_id_-appstoreversions>

The existing selected-token `RawResponse`/`ScopedTransport` captures raw bodies
before SDK JSON normalization. Caps are 128 KiB per raw page, 1 MiB aggregate,
and 2 MiB for the private frame; the public Store result remains at its original
16 KiB limit. These are serialization/input caps, **not a Ruby/Python RSS or
network-stream-allocation guarantee**. There is no SDK pagination or retry.
The raw frame's `queryFinished` is true only after the original final
token/deadline check; it is DATA, not native finality. Error/partial frames
cannot become an empty successful inventory.

Dotted, suffixed, noncanonical or oversized build numbers require manual
review; they are not coerced into integers. Marketing-only records are valid
and distinct from an entirely empty current inventory. Neither establishes an
unused application or historical uniqueness. Failed prerequisite findings
cannot coexist with an observed result.

## Original native observation

`saved_command_store_versions.rs` retains a weak pointer to the actual started
Store session, its earliest native admission clock, and a weak exact P8
assignment/context witness. Only the existing successful watchdog retirement,
after the real command/IO/manager/runtime joins and material retirement, can
record a `StoreVersionObservation`. The seven-command terminal and all existing
source/input/handler/invocation closure checks are still required. Public JSON,
a terminal callback, or a newly reconstructed same-ID session cannot mint it.
Normal terminal input-close STOP is not a cancellation/failure; the original
first-stop, reason, unknown/currentness and real final-join checks remain the
vetoes. The inert regression drives the actual terminal/STOP handlers without
inventing a successful native join or receipt.

Freshness uses the earliest admission, not completion/receipt time. Monotonic
and wall clocks must remain consistent; rollback/jump refuses without renewing
the clock. New reads, context changes, shutdown and document loss invalidate
the original receipt. Weak references retain no P8 bytes after payload removal
and reject context ABA. The existing Document census gets one bounded retained
receipt allocation; code and child runtime memory remain separate.

The native v2 serializer accepts that original observation plus the **already
durable full selected request** from `VersionAllocationStatePort`. It matches
the complete Store context digest, saved config/version hashes, baseline name
and build, and the requested age. The future allocation caller must additionally
call the pure original Document/P8/root gate and recheck its actual saved-source
stamp/ref/commit/tree before pending ACK/PUT and before the version edit. The
serializer is not permission to omit those gates.

## Same ledger, explicit policy v2

Manual remains default. The old schema-1 `application-all-builds` contract,
proposer, row bytes, hashes and genesis remain unchanged. It refuses current
inventory input rather than silently weakening “complete.” Explicit schema-2
automatic policy adds `storeScope: require-current-ios-inventory`; it supports
only an iOS-only project and binds `storeContextRevision` into the full request.

The same fixed ledger branch/path, immutable repository/ledger identity,
genesis, high-water sequence, protected-branch assumptions, checkpoint,
candidate selection and durable pending intent are used. The first v2 append
changes the envelope to `mrk-version-allocation/2` and appends a domain-v2 hashed
row; previous v1 rows remain byte-equivalent. Replay chooses each row's original
proposer. Old clients reject the newer envelope. There is no second counter,
reset, migration rewrite, absent-as-empty fallback or inferred genesis.

The proposer takes the next integer above saved build, retained high-water and
the fresh current inventory, with the existing Android/iOS format constraints
and policy ceiling; this v2 lane refuses Android rather than inventing its
floor. The integer iOS policy stops at 9999. Exact reviewed branch/tag rules
retain build/patch/minor/major semantics. Existing native Source capture remains
heads-only; this packet does not make tag capture available.

The existing dialogue now validates the explicit v2 observation before it can
construct an HTTP transport, then repeats freshness before the single CAS.
Durable pending ACK still precedes PUT, and checkpoint/resolution ACK precedes
a returned reservation. An unknown send retains the same original pending
candidate; reconciliation is read-only, needs no new Store observation, and
never renumbers. Recovered reservation DATA is not current edit/upload
eligibility. No max+1/local mutex or blob CAS is represented as distributed
exactly-once or protection against external uploaders/admin branch rollback.

`prepare_reserved_version_edit` now requires fresh v2 inventory in addition to
the unchanged original RELEASE_VERSION lease/checkout, exact baseline, source
hashes and platform tuple. It delegates to the existing transaction prepare;
Apply/recovery remain the original writer. Stale or consumed reservations do
not autofill a manual editor or bump themselves. Source after an applied edit
must be separately committed/rebound before a build. Separate explicit Reserve
and Apply consent and the genuine native gates remain integration work.

## Root integration and packaging

Apply `ios-store-current-inventory-hooks-20261020.patch` together with these
leaves. It changes 23 existing files: seven tested Python/Ruby dispatch hooks,
eleven native parent hooks, four TypeScript/React parents, and the fixed tooling
list (the native Store-runtime roster is among the eleven). No shell command,
permission, manifest schema or new process/credential owner is introduced.

The Store runtime must include the literal
`fastlane/apple_store_versions.rb` in both `REQUIRED_TOOLING_FILES` and its native
required-file roster. `stage_macos_installed.current_source` and
`prepare_runtime._store_inputs` assemble **current first-party tooling** and
discard older component tooling. The existing signed Ruby/gem component can be
reused: no Gemfile/Gemfile.lock changed. Fresh full runtime/manifest/app assembly
and actual native behavior still require qualification; old assembled app
artifacts do not gain this script just because Python source changed.

## Focused evidence and remaining checks

Author's explicit, joined synthetic runs (overlap is not double-counted):

- Policy/allocation/current-inventory: 55 Python tests passed. Current inventory
  was rerun after final-check/contradiction hardening: 14 passed.
- Actual fixed allocation dialogue: 17 Python tests passed (4 new v2 cases;
  inert FDs/HTTP/native ACKs), including pending-CAS/STOP and stale refusal.
- Actual version-writer adapter plus inventory: 21 Python tests passed (2 new
  reserved-edit cases). Source bytes/custody are synthetic; no user project IO.
- Ruby original raw-reader ABI: 20 tests / 358 assertions passed (7 new).
- Existing frontend controller/strict parser: 10 Node tests passed with inert
  native replies against the exact projected shared hooks, including subscriber
  invalidation/ABA/source/peer changes between notification and native invocation.
  The new query rechecks its original intent immediately before Prepare/Start;
  no original pending promise is discarded. No DOM/native calls.
- Four new Rust leaves and eleven shared native projections parsed with
  rustfmt; **ten Rust tests are unrun**, including one actual private temp-Store
  state roundtrip. Root owns the combined graph/typecheck/test batch.

No live App Store/GitHub request, key, upload, native process qualification,
signing, packaging, CI run or full build was performed by this lane. No Android
current-inventory claim is made; its temporary-edit lifecycle requires separate
explicit consent and implementation. Reserve's remaining native admission and
CLI/CI consumers are not called available by this packet.
