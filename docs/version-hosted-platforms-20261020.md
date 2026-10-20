# Reserve Android or shared Android+iOS versions in Actions

This extends the [existing hosted reservation](version-hosted-20261020.md),
using **the same counter, candidate and allocator as Desktop and the installed
CLI**. Manual versions and ordinary candidate builds stay the defaults. This
action reserves only: it does not build, upload, sign, edit or commit source.
It does not promise historical Store uniqueness or coordinate outside uploaders.

## Select and approve the exact saved platforms

Use the updated, pinned caller template with operation **reserve-version**.
The platform must exactly match the enabled platforms in committed
`release/mobile-release.json`, with actual app IDs and one supported controlling
version file. Recovery and Desktop-dispatch fields must remain empty.

| Saved platforms | Confirmation | Policy version / `storeScope` |
| --- | --- | --- |
| iOS only | `reserve-version:ios` | 2 / `require-current-ios-inventory` |
| Android only | `reserve-version:android:temporary-play-edit` | 3 / `require-current-android-inventory` |
| Android and iOS | `reserve-version:both:temporary-play-edit` | 4 / `require-current-shared-inventory` |

**Android creates and deletes a temporary Google Play edit.** This is a real
external effect, although it does not publish a release. Opening an edit can
invalidate another in-progress edit for the same app/account, including one
belonging to another client. Approve explicitly and avoid overlapping Play
operations; our workflow serialization does not exclude outside clients.

For example, a reviewed shared policy in protected
`MOBILE_RELEASE_VERSION_POLICY` could be:

```json
{"schemaVersion":4,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}],"buildCeiling":9999,"storeMaxAgeSeconds":900,"storeScope":"require-current-shared-inventory"}
```

Use the actual full branch ref; `patch`, `minor` and `major` remain supported.
This hosted path refuses tags and the counter branch. Android-only retains
its integer bound; a pair uses the existing iOS/Android **9999** intersection.
Neither failed provider can fall back to an old, empty or single-platform floor.

## Protected inputs

Keep the existing enrolled `MOBILE_RELEASE_VERSION_AUTHORITY`, classic branch
protection and dedicated App setup in the iOS guide. The renamed
**`version_reserve`** is the sole protected reserve job. Its pinned official
App action still mints Administration-read / Contents-write / Actions-read for
exactly the caller repository, exposes its token only to the fixed worker,
and performs default same-job post revocation. No App key/token enters normal
candidate/build/Store jobs; no `GITHUB_TOKEN` fallback is added.

In the protected `mobile-candidate` environment:

- iOS/shared: existing `MOBILE_RELEASE_ASC_KEY_ID`,
  `MOBILE_RELEASE_ASC_ISSUER_ID`, and
  `MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64`.
- Android/shared: new secret
  **`MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64`**, strict base64 of the
  selected service-account JSON, at most **16 KiB decoded**. The account must
  have intended access to create/read/delete the temporary edit for this app.

No account, role, App, secret or permission is created by this code. The fixed
reserve reader accepts `service_account`, not normal candidate WIF's
`external_account` file. Missing/unsupported keys refuse with guidance; there
is no ambient ADC, gcloud, WIF or account fallback. **Normal candidate WIF is
unchanged.** The workflow projects unused provider inputs to empty; the worker
rejects nonempty unused families or ambient `GOOGLE_APPLICATION_CREDENTIALS`.

Each child receives only its provider's inputs, never the other key or GitHub
token. Google uses the existing private finite scratch and original snapshot
checks before/after the fixed child. Both scratch owners must close before
cleanup acknowledgement. Raw errors, private inputs and edit IDs are not
printed, exported or put into the repository journal.

## Result, concurrency and runner loss

The result retains the same candidate UUID, row hash, reserved values,
authority data, exact two-span version-file change and commit trailer. Review
that change, then make **one version-only commit directly after the reserved
source**, with the exact trailer. Run the **separate** candidate action afterward.
The [CI consumer](version-ci-20261020.md) validates the full ledger and source
change. Copied output is preparation DATA, not native consent or readiness.

The full request is durably selected before Store work. Paired mode reads iOS
first; failure means **zero Play insertion**. Android reads all current tracks,
statuses, bundles and APKs, with confirmed deletion. Both observations use one
earliest timestamp/context and canonical Android,iOS order. These are complete
bounded **current-visible** traversals, not atomic snapshots or all past uploads.

The same `release/.mrk-version-ci-state-v1.json` gains explicit envelope v2:
unchanged allocation state, monotone storage revision, and nullable `playQuery`
(`candidateId`, full `requestSha256`, random `attemptId`). This is not another
version counter. V1 still round-trips exactly; every later v2 write stays v2.
Every write uses the existing blob CAS and exact commit-pinned readback.

1. Acknowledge the exact pending Play slot **before** starting its child.
2. Only the **same original attempt** may clear it after genuine C/A/W return,
   strict same-context response, actual scratch closes, and current material/
   deadline. It must prove **deleted** or valid **not-started**. An unsupported
   floor with confirmed deletion may clear cleanup, but still cannot allocate.
3. Continue the existing pending-before-single-ledger-PUT allocator. Source,
   full candidate, current inventories and journal ancestry are checked again.
   Edit cleanup is not floor/source authority.

An unresolved Play slot fences later hosted requests: no TTL, expiry, reset,
reinsert, eviction or caller-supplied result can clear it. Lost clear ACK leaves
that original unusable; a later runner trusts only verified remote state.
A fresh explicit inventory after confirmed cleanup is a new query, **not a new
version candidate**. Full-request drift or a consumed number refuses; retries
never silently renumber. Uncertain ledger writes retain existing read-only
exact-row reconciliation; absence is never permission to resend.

**Recovery limitation:** a known edit ID may remain private in the live process,
but the current reader does not durably export it. The fence preserves runner-
loss uncertainty; it does **not** implement automatic remote edit recovery.
Preserve any surviving slot and investigate the original operation. There is
no automatic or manual-clear endpoint in this slice.

All cooperating clients must use the same ledger. A fresh runner cannot detect
an administrator erasing newer history and restoring an older valid-looking
ref/state without an independent newer anchor. Protection is checked, not a
forever guarantee; outside uploaders are not coordinated.

## Finite execution and integration

- One original **60-second** endpoint covers source, journal, both provider
  reads and allocation; existing owned-child cleanup only contracts its
  **3-second** tail. No per-provider renewal or native 60/70 receipt.
- At most **12 Git reads / 44 GitHub requests / 7 journal writes**. New modes
  move only the pre-selection HEAD check to after Play pending ACK/pre-Play;
  initial raw source/fresh remote checks and pre-ledger/final HEAD remain.
  iOS identity/context hashes and order remain unchanged: first-use success
  still uses 37 GitHub calls / 5 writes.
- At most two sequential fixed Ruby children with remaining original time.
  Play `read_end=min(now+50,hard_end-10)`, `hard_end<=source.end`; original first
  failure contracts its sole deletion tail.
- Same journal **128 KiB / 4096 nodes / depth20** input/output cap, GitHub
  **256 KiB/body / 10 MiB aggregate**, existing provider raw/row limits and
  **2 MiB frames**, and **16 KiB per selected input**. No eviction or RSS claim.

Apply `version-hosted-platforms-hooks-20261020.patch` with this successor. Its
four targets are the two existing YAML files, fixed hosted TLS request cap,
and one closed `workflow.Context.current` Both reserve arm. Global platform
enumerations, build/Store/recovery contexts, ordinary WIF and Ruby readers are
unchanged. It assumes accepted iOS source/hooks and the separate LF frame fix;
do not reapply the original hosted hook artifact.

Focused tests use real core/state/parsers with synthetic process/HTTP/provider
boundaries; one exercises actual private finite-scratch files. Run networkless
as a nonroot user with a private `TMPDIR` (no credentials needed):

```sh
PYTHONPATH=src:tests/unit python3 -B -m unittest test_version_hosted test_version_hosted_store test_version_hosted_platforms
ruby tests/workflow/test_version_hosted_yaml.rb
```

No provider edit, GitHub/Store call, credential, hosted workflow, native run,
signing or publication has been qualified by these tests. External App/Store
access and protected environment configuration remain owner setup.
