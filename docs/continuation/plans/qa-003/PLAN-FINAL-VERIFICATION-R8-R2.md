# QA-003 R8-R2 — fresh complete final verification plan

## Scope and dependencies

This revision supersedes PLAN-FINAL-VERIFICATION-R8.md only to clarify mutable
tool destinations, controller-loss handling, and wheel-smoke forensic limits after
independent plan review. No helper, gate, bound, expected outcome or cleanup
implementation is changed. Original plan and review observations remain retained.

Do not execute until independent R8 implementation review approves the actual
source snapshot, this plan passes separate review, and the actual preparation /
wrapper has been independently checked. Proposed source tree currently
f8f489a20ad852c8e649ea9e2eee09f8679f179a (172 files,54 intended changes), HEAD/main
2beb37336fa8002b69f598fe431082606368310d, version0.3.0. Review failure reopens source
and invalidates this proposed acceptance; no product edits during a frozen run.
Preserve AGENTS SHA7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb.

## New namespace and behavior

Create NEW `.mobile-release/remediation/QA-003-final-r3/` only when absent.
Copy these seven helpers byte-for-byte from the reviewed, unused r2 preparation:
freeze.py, verify-all.py, verify-matrix.py, verify-pins.py, wheel-smoke.sh,
probe-jdk21-signing.py, cleanup-build.py. Their root/evidence paths are already
relative to their own file. Do not alter commands, conditions, timeouts, expected
outcomes, cleanup scope, tests or matrix shard selection.

Copy the corrected r2 run-once.sh with ONLY its absolute evidence path and private
TMPDIR replacement. Retain set -euo pipefail / noclobber, exclusive log descriptor,
explicit if/else exit capture, close log FD and exclusive exit marker. No old log,
partial gate, wheel or proof is adopted. Preserve r2 preparation and its zero-gate
SUPERSEDED record; its removed owned temporary parent is never reused.

Create one mode0700 private temporary parent using mkdtemp under repository.parent
(prefix `.mrk-qa003-final-r3-`), with owned mode0700 tmp/ child and an identity-bound
owner marker. Record device/inode and marker bytes before further creation. Use
that tmp/ only for this invocation. No shared temp-pattern cleanup. Keep the
original forensic installation .mrk-qa003-final-matrix-tgf343b1 and original failed
wheel/namespace unchanged. Save a before/after preservation record.

After source and preparation acceptance, freeze the actual172-file proposed tree
using the copied temporary-index helper (real index stays unchanged/empty; user
AGENTS excluded). Bind all seven helper hashes and separately wrapper bytes/owned
parent identity. Record tools/versions and existing tracked/untracked state. Assert
the new proposed tree equals the implementation-approved tree before dispatch.

## Mutable tool destinations and exclusive execution

Before preparing the final freeze, wait for the development full-suite controller
and all exact owned children to finish; record their actual exit and cleanup.
Coordinate explicitly with both reviewers: nobody may concurrently install into
or mutate the retained MRK-002/venv, Bundler destinations, or checkout build / egg-
info destinations during final preparation and execution. Reviewer read-only work
or isolated probes must not use these as output/install destinations. Inspect the
actual process evidence and relevant exact destinations; if another task needs
one, do not stop it or race it. Delay final dispatch until exclusive use is known.

Record actual Python executable/version, venv identity/configuration, resolved
PATH commands (python3, ruby, bundle, actionlint, gh, java, xcodebuild), Gemfile.lock
and pyproject hashes, effective Bundler paths/frozen settings and actual tool
versions. Record the runner's exact named environment overrides: venv-prepended
PATH, PYTHONSAFEPATH=1, MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS=1,
MOBILE_RELEASE_TEST_PYTHON, BUNDLE_FROZEN=true, FASTLANE_HIDE_CHANGELOG=true,
FASTLANE_OPT_OUT_USAGE=true, FASTLANE_SKIP_UPDATE_CHECK=true, and the new private
TMPDIR. Only capture named non-secret settings; do not dump the environment,
credential configuration, Bundler authentication or real account files. Preserve
inherited dependency resolution; do not silently switch interpreters or add
overrides beyond the already reviewed wrapper/helper. Stop and reanalyze unexpected
resolution/drift before execution. The unchanged runner's editable/bundle installs
may mutate their known dependency destinations; compare source/index/lock hashes
and final pip/bundle checks, not a false promise of an immutable venv.

## Required gates and failure handling

Run all58 original categories sequentially from zero: freeze; editable install;
Bundler install/check; entire Python suite; init/entitlement/profile/default-signal/
local-signing/owned-process/native/CI/plist/Mach-O regression groups; all Ruby
Fastlane/Play/Apple/native-upload/lane/contract tests; Supply/WIF; Fastfile validate;
actionlint; actual GitHub Action SHA/dependency/runtime import pin verification;
fresh wheel installation/contents/bootstrap/init/native source-vs-wheel checks;
matrix contracts and fresh isolated wheel environment; every source/wheel pair
for shards00–15; actual complete disjoint union; exact owned matrix/build cleanup;
pip check; JDK21 signature policy; diff and unchanged freeze.

The new local-signing failure module is already included in full discovery,
local-signing glob and mandatory native PATTERNS for BOTH source and wheel.
Enumerate the actual new logical matrix inventory; previous26604 is historical,
not a number to assert by assumption. Keep each420-second package launcher,
900-second pair and890-second adapter bound exactly as previously reviewed.
No concurrency increase, pass adoption or gate omission is proposed.

The runner records actual exits/log hashes and stops on any failing gate. A timeout,
cleanup error, unavailable dependency/API or partial execution stays FAIL/unexecuted
as appropriate, never PASS. Preserve failures and live ownership observations;
reproduce/investigate rather than automatically rerun. The original EEXIST is still
an actual historical FAIL with unknown cause after bounded independent investigation;
a fresh pass does not explain it. Reconcile that evidence with reviewed fail-closed
injection behavior and explicitly record remaining uncertainty; do not claim a
confirmed production cause or suppress exclusive collisions.

## Cleanup, delivery and later work

The live gate controller attempts cleanup of its exact reserved child group and
records a failing result if absence cannot be confirmed. This is NOT a guarantee
under controller death: an interrupted/disappeared controller can leave a live
gate or missing/unknown exit. Preserve the partial namespace, logs, current process
observations and pending installations, and reconcile before any further action.
Do not replay a gate, infer its exit from partial output, reuse the namespace,
restart the runner or signal a stale numeric PID/PGID. Signal only while a current
reserved/owned process identity establishes authority; otherwise observe and retain
uncertainty. Do not stop a live worker needed by another task.

Tests remove only their synthetic trees. The unchanged wheel-smoke EXIT trap
removes its exact temporary smoke installation on BOTH ordinary success and
ordinary failure. Its logs and newly built wheel remain; the failed installed
tree is unavailable for later inspection. This is an explicit forensic limitation,
not a passed check or proof of unconditional trap execution after hard termination.
If termination prevents the trap, preserve and inspect its exact known residue;
never use a shared temp-name sweep. The original failed matrix installation is
different and remains fully retained for investigation.

Full matrix cleanup requires all16 source/wheel proofs and observed group/path
absence; retain all raw reports and the new wheel. Failed or interrupted matrix
installations remain until investigation shows they are unnecessary; do not adopt
partial passes. Remove checkout build copies only after byte equality to source
is proven. After a reconciled runner exit, verify owner identity and expected
marker, remove only the empty tmp/ and marker/parent; unknown residue prevents
deletion and needs inspection. Stop no unrelated worker/Gradle/native service
and remove no user file or shared cache. Preserve all required evidence and the
original failed namespace, wheel and entire forensic installation.

Review final ledger/artifact/source/hash/cleanup reconciliation before scoped QA-003
commit. Use normal protected PR/merge to main and require hosted Linux/macOS/matrix
and main CI success; no protection bypass, force push or Store mutation. Progress
counts change only on verified delivery. QA-004/QA-005/MRK-008/MRK-009 and the full
fresh production audit/new-blocker remediation/conditional feature report remain.
