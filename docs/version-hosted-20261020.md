# Reserve an iOS version in GitHub Actions

This optional action reserves a number in the **same counter used by Desktop
and the installed CLI**. It does not build, sign, upload, change project files,
or create a release. Manual versions and the existing candidate action remain
the defaults. This page describes the original iOS setup; the
[Android and shared-platform extension](version-hosted-platforms-20261020.md)
adds explicit Play-edit consent and supersedes the shared request cap/hook
packet. Existing Desktop/installed-CLI paths are unchanged.

## Set up once

1. Use an existing enrolled counter and its completed reservation's **Use this
   reserved version in GitHub Actions** data. Put the supplied, nonsecret
   `MOBILE_RELEASE_VERSION_AUTHORITY` in the application's protected
   `mobile-candidate` environment. Do not invent a genesis/checkpoint, replace
   it with another authority, or move it backwards to bypass an error. This is
   explicit CI opt-in, not an automatically synchronized Desktop preference.
2. Keep the counter's `mrk-version-allocations` branch protected: enforced for
   administrators, force pushes disabled, deletions disabled. The current
   implementation verifies **classic branch protection**; inaccessible or
   ruleset-only controls refuse rather than imply an equivalent guarantee.
   Cooperating clients must all use this one counter.
3. An owner must install a **dedicated GitHub App on this repository** with
   **Administration: read**, **Contents: write**, and **Actions: read**. Its
   bot must be allowed to make the intended counter updates without bypassing
   the required controls. Configure the caller's two explicitly named secrets:
   `MOBILE_RELEASE_VERSION_APP_ID` and
   `MOBILE_RELEASE_VERSION_APP_PRIVATE_KEY`. Keep workflow/settings changes and
   the `mobile-candidate` environment subject to appropriate branch restrictions
   and review. No App installation or secret is created by this code.
4. In that protected environment, retain the existing selected Apple inputs:
   variables `MOBILE_RELEASE_ASC_KEY_ID`, `MOBILE_RELEASE_ASC_ISSUER_ID`, and
   secret `MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64`. They must permit reading
   the configured App Store app. Configure `MOBILE_RELEASE_VERSION_POLICY`,
   for example (choose your actual full branch ref and reviewed increment):

   ```json
   {"schemaVersion":2,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}],"buildCeiling":9999,"storeMaxAgeSeconds":900,"storeScope":"require-current-ios-inventory"}
   ```

   The other supported increments are `patch`, `minor`, and `major`. Rules are
   exact full refs, not globs. This hosted slice accepts branches only, never
   the counter branch itself. The saved config must enable **iOS only** and
   identify the actual app and controlling version file. Dotted/non-numeric
   Store build formats and values outside the existing iOS range refuse.

Use a pinned tooling revision containing this worker and its matching caller
template. The dedicated App secrets are passed only by the reserve caller.
Inside the protected reserve job, pinned official
`actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349`
mints a short-lived token for **exactly the caller repository and those three
permissions**. Only the fixed worker receives that token; the App private key
is supplied only to the mint step. Normal candidate/build/Store jobs receive
neither. There is no cross-job token output, skipped revocation, inherited
secret set, PAT, or `GITHUB_TOKEN` fallback. The official action performs its
normal same-job post revocation; token revocation is not ledger rollback or
evidence that interrupted work settled.

An ordinary Actions token cannot inspect classic protection's Administration
permission. Missing App setup is an explicit prerequisite for **hosted
reservation**, not a reason to disable ordinary builds/manual versions or
Desktop reservation. Metadata-only active rules cannot prove hidden bypass
actors and are deliberately not substituted for the protection check.

## Reserve, review, then build separately

1. Commit configuration and other project changes first. Run **Mobile internal
   candidate**, choose operation **reserve-version**, platform **ios**, and
   confirmation **reserve-version:ios**. Recovery and Desktop-dispatch fields
   must be empty. Approve the protected environment as usual.
2. The action checks the current branch/source, counter and current Apple
   inventory, then returns one JSON result containing the reserved version,
   candidate UUID, exact row hash, commit trailer, authority-setting data, and
   the two version-file value replacements. This is preparation data, **not**
   release readiness or permission to edit automatically. No build or Store
   upload job can follow this reserve-only path.
3. Review/apply only those two values without changing other version-file
   bytes or its mode. Make **one version-only commit** directly on the reserved
   source commit, retaining the exact returned `MRK-Version-Reservation`
   trailer. Then run the separate ordinary candidate action on that commit.
   The [existing CI consumer](version-ci-20261020.md) checks the complete ledger,
   both raw commits/trees, and exact rendered change before fresh build/Store
   work. Copying JSON or a trailer is never native approval.

The authority setting opts normal CI into requiring that trailer. An absent
setting **and** absent trailer mean unconfigured/manual; invalid/partial
configuration does not select a fallback. Reservation does not refresh Store
eligibility for the later upload, waive existing approvals, or promise that
an outside uploader cannot use the same number.

## Retry, concurrency, and runner loss

The sole allocator remains `version_allocation.allocate_version`; immutable
v1–v4 ledger rows and the existing monotonic high-water mark are unchanged.
A fixed `release/.mrk-version-ci-state-v1.json` on the counter branch retains
the existing schema-3 allocation state inside a storage-revision envelope.
This revision is not another version counter. Every journal write uses blob
CAS and an exact commit-pinned readback, even when state bytes are otherwise
identical. No runner file, Actions artifact, or native acknowledgement is used
as substitute durability.

The full request is saved before Store work. Exact source `(ref, commit)` reuse
finds that request and its original candidate UUID; changing policy/config/app
or credential context does not remint it. Two runners or a concurrent Desktop
writer must win the existing conditional writes; conflicts never spin or
allocate again automatically. The journal's full pending intent is acknowledged
before the **single** possible ledger PUT.

- Lost selection/journal acknowledgement: preserve the state and explicitly
  retry only the same source/request. The original adapter cannot reopen.
- Pending ledger outcome: later attempts perform read-only reconciliation.
  An exact existing row can resolve it; absence is **not** permission to resend
  or clear the pending intent. A known original 409/422 remains distinct from
  an unknown send and permits only the existing explicit subsequent attempt.
- Already resolved reservation: retry returns the same allocation only after
  another journal CAS. A later Store floor consuming that value refuses; it
  never silently renumbers the candidate.
- Missing established journal/history, rollback, malformed state, or full
  capacity: refuse without truncation, eviction, resetting, or a manual
  fallback. Manual versioning remains a separately chosen workflow.

Initial creation is one complete request/enrollment write after the protected
checkpoint/full ledger and exact missing-file history checks. This cannot
detect an administrator who erases all newer history and restores an old
valid-looking state and ref. Protection remains an observed prerequisite, not
an immutable promise. Uncoordinated writers/external uploaders are outside the
shared counter's guarantee; this is not distributed exactly-once execution.

## Execution and integration limits

One original 60-second worker deadline covers source, journal, Store and all
allocation stages. Existing ordinary `run_owned` C/A/W has its contraction-only
3-second child cleanup, not the native 60/70 dialogue. At most 12 fixed Git
reads and 5 journal writes are used by iOS (37 GitHub requests on first-use
success). The shared profile now admits at most 44 requests for the explicit
Play-bearing extension; no retry or redirect loop. GitHub uses the existing fixed TLS implementation and the
hash-checked `desktop/cpython-source-inputs/github-ca.pem` from pinned tooling,
not ambient trust. Setup and the official App token step precede that worker.

Journal input/output is at most 128 KiB/4096 nodes/depth20; it can fill before
the existing 64-row ceiling. GitHub bodies are at most 256 KiB each/10 MiB total.
Apple reuses the existing raw reader: 8 GETs, 128 KiB per page/1 MiB aggregate,
2 MiB frame, and at most 400 rows per collection. Builds, pending uploads and
App Store versions are complete **current-visible** traversals, not an atomic
snapshot or all historical used numbers. Failure or stale private/source
inputs cannot become an empty floor. These are byte/time/call bounds, not a
Python RSS or native qualification claim.

Apply `version-hosted-hooks-20261020.patch` with the new modules/tests. Its four
targets are based on `7444f6ed`, with the TLS target refreshed to `e46ef4f6`
(preserving the complete GitRemote first-failure/control callbacks): the
existing allocation state's unchanged pure
transitions are shared; the original native port/ack remains intact; the fixed
TLS profile and existing caller/reusable workflow get closed hosted arms.
The separate Root frame fix `e46ef4f6` is required and is **not duplicated** in
this packet. No Ruby/gem/dependency, native/service namespace or runner is added.

Author checks: 24 hosted Python + 32 existing state tests **passed** with mocked
Git/HTTP/command boundaries; 4 parsed-workflow Ruby tests / 98 assertions passed.
The new tests cover runner loss, competing CAS, retained request/unknown send,
byte limits, actual raw parsing, source drift, private environment, same-job
token scope and default/candidate separation. No provider, credential, hosted
workflow or native execution has been performed. After applying the hooks:

```sh
PYTHONPATH=src:tests/unit python3 -B -m unittest test_version_hosted test_version_hosted_store test_version_allocation_state
ruby tests/workflow/test_version_hosted_yaml.rb
ruby tests/workflow/test_version_ci_yaml.rb
```
