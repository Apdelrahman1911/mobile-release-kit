# Android current inventory → reserved saved version

This extends the existing local Store check and Reserve → version-editor path
to **Android-only saved configurations**. Manual versioning is unchanged and
remains the default. There is no automatic check on mount, credential selection,
refresh or policy selection.

The sequence is explicit: **review Play check → authorize temporary edit → read
current versions → review reservation → reserve → open version editor → review
file changes → Apply**. Reading does not reserve; reserving does not change the
project; a public status or reservation-shaped object is not an edit grant.

## What Google exposes, and the external effect

The fixed production reader uses the already pinned Google Android Publisher
SDK / HTTPClient and the original selected Google service-account material. It
does not add another HTTP engine, process runner, credential discovery or store.

Within one command and the original owner's deadline:

1. Obtain one OAuth token from `https://oauth2.googleapis.com/token` using that
   explicit key. No ADC, gcloud, external/executable credentials or token refresh.
2. `edits.insert` for the saved application ID, with an empty `AppEdit`.
3. `edits.tracks.list`, `edits.bundles.list`, and `edits.apks.list` on that exact
   returned edit ID. All returned tracks and release statuses count. A version
   code appearing on several tracks is normal, not an error.
4. Attempt one `edits.delete` for that same ID. Never commit/validate the edit,
   upload, change a track or guess an edit ID.

**This is non-publishing, not side-effect-free or GET-only.** Opening a Play edit
can invalidate another in-progress edit for the same app/account. The consent
and UI warn users to coordinate with other editors first. Our original native
owner excludes our own overlapping operation, not work in Play Console or an
external client.

The inventories describe records **currently visible in that edit**, not all
historical uploads, a Store-wide used-code registry or an atomic snapshot. Track
release names are labels and do not supply a marketing-version floor. Other
uploaders can consume a code after this check. No claim of historical uniqueness
or Store acceptance is made.

Public API references underlying the fixed calls:

- `developers.google.com/android-publisher/api-ref/rest/v3/edits/insert`
- `developers.google.com/android-publisher/api-ref/rest/v3/edits/tracks/list`
- `developers.google.com/android-publisher/api-ref/rest/v3/edits/bundles/list`
- `developers.google.com/android-publisher/api-ref/rest/v3/edits/apks/list`
- `developers.google.com/android-publisher/api-ref/rest/v3/edits/delete`
- `developers.google.com/android-publisher/edits`

Source review used existing local gem archives, not live API calls:
`google-apis-androidpublisher_v3` 0.106.0, `google-apis-core` 0.18.0,
`googleauth` 1.17.3, `signet` 0.22.0 and `httpclient` 2.9.0. The three pinned
list methods have no page-token argument. Any unknown pagination field or
unsupported response shape refuses the entire inventory rather than accepting
one page as complete.

### One-send, bounded raw response and cleanup

`fastlane/android_store_versions.rb` attaches a filter to the **one actual
HTTPClient instance**. In HTTPClient 2.9, `do_get_block` calls `filter_request`
before `Session#query` on each keepalive/protocol retry. The fixed slot is consumed
there before wire entry; a failed or partial send cannot obtain another slot.
Neither `retries = 0` nor `connect_retry = 0` is treated as sufficient: the former
does not prevent SDK auth retry; the latter means unlimited connect retry in the
pinned client. The filter also guards underlying repeated sends.

Only the SDK-created command's `execute_once` is specialized: it still uses the
same client, synchronously streams with redirects disabled, caps chunks **before
append**, and retains raw success/error bytes before SDK JSON normalization.
The service authorization is a private String token, not a refreshable signer.
Signet's supported non-Faraday connector uses that same filtered client for the
one token request; its retrying bang wrapper is not used. No global patch or
caller-selected endpoint is exposed.

Limits are 128 KiB per list, 16 KiB per token/edit response, 1 MiB aggregate raw,
2 MiB private command frame, and the existing 16 KiB public terminal. At most
400 tracks, 400 total releases, 4,000 code references, 400 bundles and 400 APKs
are accepted. Bounds exceedance is unavailable/too-many, not a truncated floor.
These are finite raw/framing bounds, **not a Python/Ruby heap or OS RSS limit**.

The exact attempted insert and completed response/ID are retained before a late
clock refusal. A known ID gets at most one delete under the same absolute
cleanup cutoff; malformed/lost insertion cannot be retried or replaced. A
successful empty 204 delete differs from failed, partial or nonempty deletion.
After a late successful delete its actual returned fact is retained, but it
cannot revive an expired inventory. No successful delete or missing worker
response is invented. Failed or unconfirmed cleanup produces no floor and warns
that an uncommitted edit may remain until Google expires it; inspect Play Console
and coordinate before another explicit check. Cancellation may prevent deletion.

The reader gets at most 50 seconds of read work plus cleanup within its original
60-second command ceiling, further clamped by `StorePreflightRun`'s existing
endpoint. First failure only contracts cleanup. C/A/W, input/material/runtime
postchecks and native joins remain on the original owners. A response or child
exit alone never mints a native receipt.

## Reuse, policy and writer

The new closed query/consent are `android-current-versions` and
`local-android-current-versions-edit-v1`. They cannot enter the old access or
delivery Prepare/Execute/Reconcile grammars. The Python reader is the original
StorePreflightRun's sixth command, with the same held source, Google snapshot,
runtime and process cancellation owner. The native receipt retains the earliest
original observation clock and a weak witness to the **same assigned Google
payload/context**, not a new key loan or a serialized credential assertion.
Changing platform, assignment, record, root or context invalidates it.

Version policy **v3** explicitly means `require-current-android-inventory` and
exactly `['android']`. The ledger remains at the existing fixed branch/path with
the same genesis, high-water mark, checkpoint, conditional GitHub Contents PUT,
durable local namespace and immutable full candidate binding. Existing v1/v2 row
bytes, hashes and replay rules do not change. First v3 append changes only the
envelope version and adds a v3-domain row; a legacy client must refuse that
envelope, not silently reinterpret it. There is no counter reset or migration
that discards pending work.

Build/patch/minor/major reuse the existing allocator. Android whole-number builds
are bounded by 2,100,000,000; the iOS-only native policy stays at 9,999. Numeric
marketing versions still follow the existing policy and saved controlling
version source. Unsupported formats/layouts require manual review, not an
implicit conversion. The next code must exceed the saved, central and observed
current floors, **under the existing coordinated authority and CAS**. Local
`max + 1` or a mutex is not distributed allocation. Branch protection and
cooperating clients remain prerequisites; arbitrary external uploaders are not
coordinated.

Same-candidate retry/restart returns the original durable reservation DATA, never
a new number. Lost PUT ACK remains pending and reconciles read-only. A later
Store floor consuming that number vetoes editing; the candidate is not silently
renumbered. Identity/source/policy changes require the existing explicit new
candidate or recovery path, never an allocation retry loop.

The native extension dispatches its existing receipt, selected request and port
into the same Reserve jobs/ConnectionState/NativeUse and Pending-ACK-before-PUT
dialogue. It does not add an owner or reset the original 60/70-second Reserve →
Edit clock. The consume-once handoff still binds the exact candidate, source,
allocated values and finite same-Session registration publication chain. Reserve
sources actually close; Edit opens fresh existing GitReadSources. The live
Python Source retains its actual root flock through the authentic Init borrower
and existing `RELEASE_VERSION` transaction. Unrelated source/credential/epoch
changes, late jobs, unknown CAS or unknown edit cleanup still refuse/retain.

**Shared Android+iOS saved sources remain unsupported.** One local credential
context cannot supply two simultaneously current native witnesses. The UI gives
negative guidance from current saved configuration bytes, never draft values.
The actual Source reader and v2/v3 request guards independently reject mixed
platforms. No fabricated second floor, manual-truth fallback or first-witness
invalidation exception is introduced.

The installed CLI/CI do not acquire a new credential, reserve or edit endpoint
from this packet. The shared ledger remains usable only by separately admitted,
compatible cooperating consumers. This packet's actual producer is the explicit
Desktop local Google owner; it does not reuse that file identity as CI WIF or
claim cross-client native qualification.

## Integration and verification

Commit the owned leaves and the actual policy/allocation edits, then Root applies
both supplied patches together:

- `android-version-inventory-native-hooks-20261020.patch`: 13 native and 10
  frontend/test targets. Existing shell commands, permissions, bootstrap,
  Supervisor/Edit owners and observer module roster are reused. Both new Rust
  files are children of already registered modules.
- `android-version-inventory-python-hooks-20261020.patch`: six existing Python
  targets. These were tested as real own-worktree modules but are deliberately
  excluded from the leaf commit so Root composes shared ownership once.

Hook originals are `649ee310`; both apply-check cleanly to Root `3aed5f83`.
New raw Ruby tooling is in `REQUIRED_TOOLING_FILES`. The existing runtime
assembler substitutes **current first-party tooling** into the Store component;
there is no Gemfile/Gemfile.lock change and no gem-component rebuild is implied
solely by this script. A fresh assembled runtime/manifest/app and actual native
behavior verification are still necessary. No availability/qualification flag
is enabled here.

Author checks, with no live credentials/provider/process commands:

- **86 Python tests passed**, including 19 new Android cases, original private
  Source/Init temporary-file edit, above-iOS-range Android write, durable
  candidate retry, shared-source refusal, old policy/ledger and iOS regressions.
  Command: `PYTHONPATH=src:tests/unit python3 -B -m unittest
  tests.unit.test_android_store_versions tests.unit.test_android_store_versions_owner
  tests.unit.test_ios_store_versions tests.unit.test_version_policy
  tests.unit.test_version_allocation tests.unit.test_desktop_version_reserve
  tests.unit.test_reserved_version_edit`.
- **9 Ruby fake-ABI tests / 77 assertions passed**; covers underlying repeated
  send guard, token/response caps, raw error redaction, exact late ID/delete and
  no renewed cleanup. `ruby tests/workflow/test_android_store_versions.rb`.
- **45 Node tests passed**, 14 new Android plus 10 existing iOS, 8 access and
  13 Reserve tests, using actual projected shared modules and inert native
  Promises. Tests cover no auto effects, exact consent, lost ACK, source/account
  ABA/reentrant peer/expiry veto and saved-vs-draft mixed-platform guidance.
  No DOM/React/native assertion is implied.
- Two new Rust leaves formatted; 13 projected Rust targets syntax-parsed.
  **Seven new Rust tests plus the extended actual normal-terminal handler
  regression are unrun.** Root owns the combined real graph/TypeScript build
  and safe focused Rust batch, followed by native qualification.

Task-owned logs are under `.task-android-version-hooks/`. Initial test fixture
mistakes (private `_evidence=None`, one-worker fixture lifetime, and null-prototype
DATA comparison) were corrected; failed first logs are retained, not represented
as passes. Python synthetic C/A/W/native ACKs and Ruby SDK ABI fixtures are not
real provider, native cleanup or installed-runtime evidence.
