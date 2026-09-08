# QA-003 R8 — fresh complete final verification plan

## Scope and dependencies

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

Every gate owns/reaps its exact child group; tests own/remove only synthetic trees.
Wheel smoke removes its exact mktemp install at exit. Full matrix cleanup requires
all16 source/wheel proofs and observed group/path absence; retain all raw reports
and the new wheel. Remove checkout build copies only after byte equality to source
is proven. After runner exit, verify owner identity and expected marker, remove
only the empty tmp/ and marker/parent; unknown residue prevents deletion and needs
inspection. Stop no unrelated worker/Gradle/native service and remove no user file
or shared cache. A failed namespace/installation required for investigation stays.

Review final ledger/artifact/source/hash/cleanup reconciliation before scoped QA-003
commit. Use normal protected PR/merge to main and require hosted Linux/macOS/matrix
and main CI success; no protection bypass, force push or Store mutation. Progress
counts change only on verified delivery. QA-004/QA-005/MRK-008/MRK-009 and the full
fresh production audit/new-blocker remediation/conditional feature report remain.
