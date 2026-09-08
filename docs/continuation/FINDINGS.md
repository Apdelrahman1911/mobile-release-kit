# Canonical finding and delivery ledger

**Authoritative continuation status: 2026-09-08, NOT READY.** Historical plans and
reports can say “open” before a later delivery; this ledger records the latest
disposition. No additional issue is waived because another guard reduces its impact.
Line references below are to the stated original baseline; re-locate them in the
actual source when resuming. Full original MRK findings are retained separately.

## Delivered original findings

| ID / severity | Original defect and verification requirement | Protected main commit |
| --- | --- | --- |
| [MRK-001 / High](original-findings/MRK-001.md) | Google Play destination updates replaced unrelated releases. Preserve the complete release set and compare full before/after readback across internal/external/production draft paths. | `04e4cc905b8b4f687cef9e58a8f57d5e0445125d` (#4) |
| [MRK-002 / High](original-findings/MRK-002.md) | Store mutation preceded durable evidence. Retain authenticated intent before mutation; reconcile original identity/bytes after cancellation, uncertain response, local persistence, attestation, or upload failures without silent duplicate uploads. | `b8c947344e67f21175c5b1a3b1a14177781f9224` (#5) |
| [MRK-003 / High](original-findings/MRK-003.md) | Latest run-attempt comparison rejected legitimate earlier-attempt artifacts. Bind actual producer attempt/job/artifact and keep source/toolkit/recovery identities distinct. | `a0f6a54b5de918bb8ebdb971dde6a237b5ccb958` (#6) |
| [MRK-004 / Medium](original-findings/MRK-004.md) | Missing localized Android changelogs passed. Require immutable nonempty version/default release notes and validate generated skeletons and fallback behavior. | `52d7953a48f4aaae5614df04c4c1c34c80ba2218` (#7) |
| [MRK-005 / Medium](original-findings/MRK-005.md) | Independently valid IPA/archive/symbol inputs could disagree. Correlate immutable shipped/retained images, nested counterparts, and supplied symbols. **Mandatory complete symbol retention remains MRK-009.** | `4373945e5530e403e18fa0acaf01312f0b67d8ff` (#9) |
| [MRK-006 / Medium](original-findings/MRK-006.md) | `init --apply` left partial integration after a later write failed. Stage/journal transactionally, preserve original files, and recover without overwriting intervening edits. | `ddf416abbeb88d4b54f6c3e4e4c9b80a3fa51055` (#10) |
| [MRK-007 / Medium](original-findings/MRK-007.md) | Profile validation omitted parts of signed entitlement sets. Validate complete typed authorization, wildcard/subset semantics, nested bundles, and authoritative DER content. **Issuer authenticity was separately completed as QA-002.** | `199e6f090bc18dacf19244333a3ce1d438778943` (#11) |

These deliveries were previously independently reviewed and fully verified for
their issue snapshots; their commits are present in the handoff base history.
They are not a claim that all later compositions or the entire repository passed
a new audit. Re-open their cross-component contracts in the mandatory final audit.

## Delivered additional findings

### QA-001 — Medium — deterministic Python process-boundary fixtures

- **Affected:** `tests/workflow/test_workflow_recovery.py` and the shared
  `tests/workflow/process_fixture.py`; actual `workflow.Transport` consumers.
- **Cause/trigger:** fixture executable startup and descendant readiness shared a
  short assertion timeout. Delayed PID publication could invalidate cleanup proof.
- **Expected/correction:** explicit interpreter and actual owned handles; bounded
  readiness, real no-EOF pipe observations, separate timeout semantics, mutation
  sensitivity, and actual cleanup before harness fallback. Runtime constraints
  must remain unchanged.
- **Impact/blocker:** required verification reliability, not a Store bypass.
- **Delivered:** `39e790869c1d081d444e9402a6cb4a9a31bcb564` (#8).
- **Final audit:** keep real process/cancellation/descendant tests; do not confuse
  this Python fixture correction with the separate Ruby QA-006 and runtime QA-007.

### QA-002 — Medium — provisioning issuer authority

- **Original baseline:** `ddf416a`; `src/mobile_release/ios.py:203–227`, consumers
  `:504–574,671–711,859–924`; preflight, CLI, and current-upload validators.
- **Cause/trigger:** native CMS decoding and plist shape were treated as proof
  of Apple issuance; decoding alone does not authenticate a profile's grants.
- **Expected/correction:** authenticate both applicable CMS layers, exact production
  provisioning issuer under pinned Apple roots, and complete authoritative content;
  keep native checks isolated, bounded, credential-free, and exact-byte bound.
- **Evidence/impact:** the original credential-free native decoding probe accepted
  unsigned content. This did not bypass Apple Store/device checks; it invalidated
  toolkit pre-upload assurance and blocked iOS readiness.
- **Delivered:** `2beb37336fa8002b69f598fe431082606368310d` (#12); 35 prior frozen
  local gates and PR/main CI recorded. Main CI was freshly observed at handoff.
- **Limit:** offline issuance verification is not current revocation status.
  Adjacent local-resource owners are separately tracked below, not covered by
  this issue's closure.

## Remaining issues, in required execution order

### QA-006 — Medium — Ruby descendant fixture readiness and safe verification

- **Baseline:** main `2beb373`; `tests/workflow/test_ios_upload_validation.rb:42–52,153–175`,
  `test_android_upload_validation.rb:41–51,166–188`; common consumer
  `fastlane/native_upload_validation.rb:12–61`; original CI `:116–118`.
- **Trigger/cause:** a three-second timeout can occur before the post-fork PID
  marker exists. The test then reads the absent marker without proving readiness,
  a reaped leader, a live pipe-holding descendant, or production cleanup.
- **Evidence:** actual QA-003 final-r4 gate 26 failed with ENOENT (13 methods,
  86 assertions, one error). Independent controlled startup and publication
  probes reproduced it; the exact historical scheduling point remains unknown.
- **Expected/correction:** shared explicit-interpreter fixtures, early real
  ownership, independent readiness deadline, actual no-EOF observations, bounded
  fallback, delayed/unready/mutation controls, mandatory Linux and macOS coverage.
  This is tests-only; do not weaken runtime deadlines or upload validation.
- **State:** seven-path R6 patch retained. No required source correction remained
  in the completed independent pre-entry scope, but entered identity/substitution
  proof and other mandated native/full observations were **not executed**.
  Review result: **INCOMPLETE_VERIFICATION**, not accepted/delivered.
- **Next:** follow [QA-006 checkpoint](QA006-CHECKPOINT.md). Independent complete
  implementation acceptance, all gates, protected delivery and main CI remain.
- **Blocks:** reliable toolkit verification/delivery; also stalls QA-003 full rerun.

### QA-007 — Medium — native process-group lifetime authority

- **Baseline:** `2beb373`; `fastlane/native_upload_validation.rb:38–57`, especially
  `:44–45,50–52`; Android/iOS adapters `:47,59–64` / `:55,91–96` and actual new-upload
  gates in `fastlane/Fastfile` and `fastlane/play_store.rb`.
- **Trigger/cause:** validation rejection or post-reap cancellation reaches cleanup
  after Open3's independent waiter released the leader identity. A result-success
  flag is not continuing process-group ownership.
- **Evidence:** independent credential-free tests of the actual capture path
  observed three post-reap signal requests; every syscall was vetoed. A separate
  live-descendant/no-EOF control proves that merely skipping cleanup after leader
  exit is incorrect. No recycled-group collateral termination was attempted.
- **Expected/correction:** retain real group-lifetime authority until the final
  possible signal decision, using an independently reviewed owned spawn/reap or
  supervisor protocol. Preserve both stream limits, timeout, descendant containment,
  environment/argv isolation, sanitized errors, original cancellation and guards.
- **Do not substitute:** a stored PID, racy alive/getpgid checks, earlier success
  publication, or disabled descendant cleanup.
- **Tests:** real success/rejection, async cancellation before result publication,
  cleanup interruption, timeout/overflow, dead leader with live descendants,
  closed streams with live leader, setup failure; prove cleanup before fallback
  on Linux/macOS and source/wheel paths.
- **State:** confirmed, not implemented. Separate issue after QA-006; no runtime
  edits are hidden in the seven-path fixture patch.
- **Blocks:** safe local runtime cleanup, toolkit readiness, candidate/new-upload
  retry assurance. Not a demonstrated promotion, public-release, or credential bypass.

### QA-003 — Medium — overlapping local signing state

- **Original baseline:** `199e6f0`; `src/mobile_release/credentials.py:960–975,1063–1072,1086–1122,1132–1163`;
  signed local preflight and cross-project same-home consumers.
- **Trigger/cause:** overlapping signing contexts snapshot/replace user-global
  keychain state and reuse profiles without an account-wide lifetime lease.
  One context's cleanup can remove another's active profile or restore stale state.
- **Evidence:** deterministic synthetic overlap exercised actual profile filesystem
  creation/reuse/removal and modeled only native keychain/signing commands. It
  observed removal and stale restoration while the second context was active.
- **Expected/correction:** whole-lifetime account-wide admission before credential
  or application work, durable ownership/intent/recovery, conditional complete-state
  restoration, authenticated profile identity, contained child lifetimes, and
  preservation of foreign/intervening changes.
- **State:** complete 55-path pending implementation retained; distinct R9/R5
  **APPROVED_IMPLEMENTATION_ONLY** for tree `387856e…`. Final-r4: **25 PASS / 1 FAIL /
  32 unexecuted**, failure now tracked by QA-006. Prior wheel EEXIST is unresolved.
- **Next:** deliver QA-006 and QA-007 separately, reconcile this patch against
  new main, review composition and refreeze/reverify from zero. Do not redo already
  preserved implementation analysis unnecessarily or reuse the consumed failed run.
- **Tests:** concurrent projects/processes, busy rejection before global work,
  all setup/crash/recovery cuts, same/different profiles, foreign replacements,
  native-active matrix, exact cancellation/descriptor ownership, source and wheel.
- **Blocks:** reliable concurrent local signing/consumer integration and READY;
  does not require re-signing an already authenticated Store candidate.

### QA-004 — Medium — outer build-input restoration on cancellation

- **Original baseline:** `199e6f0`; `credentials.py` `_restore_build_targets`
  (`1757ff` at baseline) and `materialize_build_inputs` (`1773ff`), signed
  `preflight.py:1027–1061` caller. Re-locate after QA-003.
- **Trigger/cause:** default cancellation at outer scratch teardown or client-target
  restore entry after the inner signing owner has restored handlers. Those outer
  resources are not covered by the inner cleanup owner.
- **Evidence:** actual materialization with fictional input left private scratch
  or temporary client bytes under controlled default-signal entry injection;
  inner signing cleanup had completed. No real credentials were involved.
- **Expected/correction:** register ownership for the complete outer materialization
  lifetime, independently attempt safe cleanup/restoration, preserve primary errors,
  report unresolved resources, and never overwrite intervening user changes.
- **Tests:** acquisition/handoff/cleanup-entry signals; both/single platforms;
  setup/body failures; multiple targets; bytes/modes; foreign replacements;
  independent cleanup failures and supported recovery. Do not broaden deletion.
- **State:** confirmed, no implementation. Needs full issue workflow after QA-003.
- **Blocks:** safe local material handling/consumer integration and READY, not
  original Store-candidate identity or a need to rebuild accepted artifacts.

### QA-005 — Medium — actual source observation versus display fallback

- **Baseline:** `2beb373`; `src/mobile_release/discovery.py:78–88`,
  `cli.py:815–843`, `stores.py:151–162`.
- **Trigger/cause:** a failed actual HEAD observation can populate source fields
  from environment metadata; authority consumers cannot distinguish that fallback
  from an observed checkout identity.
- **Evidence:** a real isolated two-commit repository and single unavailable-read
  injection exercised discovery and its actual guard, with all other reads real
  and zero Store calls. The guard accepted an unobserved source identity.
- **Expected/correction:** authority requires independently successful actual HEAD,
  tree and status observation; any display-only fallback must be non-authoritative.
  Preserve original-source recovery versus current-dispatch identity separation.
- **Tests:** failed HEAD/tree/status separately, mismatches, legitimate clean
  checkout and recovery source, actual caller integration and a Store-call sentinel.
- **Limits:** pinned workflows independently constrain checkout/provenance. No
  complete hosted/publication bypass was demonstrated; those guards do not fix
  the CLI's own incorrect authority contract.
- **State:** confirmed, not implemented; after QA-004. **Blocks:** complete CLI
  fail-closed assurance and READY, not every valid candidate or existing evidence.

### MRK-008 — Medium — supported macOS filesystem aliases

See the [original finding](original-findings/MRK-008.md).
`tooling.py:29–50` and `credentials.py:562–592` at original audit baseline reject
ordinary system-owned `/tmp` and `/var` aliases. A real safe temporary path failed.
Use the reviewed canonical-path policy while retaining no lower user-controlled
symlinks, private modes, size, regular-file, containment and outside-repository
requirements. Cover actual macOS aliases, malicious lower links, races and each
credential/tool consumer; do not implement blanket `resolve()` acceptance.
**Not implemented. Blocks macOS consumer integration/local preflight.**

### MRK-009 — Medium — complete retained symbol inventory

See the [original finding](original-findings/MRK-009.md).
Original `ios.py:785–880` could report dSYM success for the main app while a
shipped framework lacked symbols. MRK-005 now correlates shipped/retained code
and **present** dSYMs; that is not mandatory completeness.
Inventory every relevant shipped Mach-O/slice across the IPA, archive, apps,
extensions, frameworks and retained dSYM DWARF files. Reject missing/mismatched,
duplicate/ambiguous/substituted symbols; preserve strong content correlation,
not UUID-only matching. Supported valid nested/architecture configurations must
work; clearly reject unsupported cases without weakening validation.
**Not implemented. Blocks iOS candidate symbol-retention assurance.**

## Separate supporting blockers and uncertainty

The unfinished verifier's original-parent finality repair, current-host shared-clock
mismatch, and safe execution setup are explicitly retained under QA-006, not
quietly counted as new delivered product findings. Known paused draft defects
are listed in full in [QA006-VERIFIER-TODOS.md](QA006-VERIFIER-TODOS.md).

Older EEXIST, missing raw process observation, unknown failed scratch and optional
archive/xattr ambiguity remain unresolved observations. Their precise causes
must not be invented or their runs relabeled. Externally unverifiable Store,
runner-policy, agreements, account access, live revocation and physical-device
requirements must be separated from repository-executable blockers in the fresh
audit. Do not label unavailable checks PASS.
