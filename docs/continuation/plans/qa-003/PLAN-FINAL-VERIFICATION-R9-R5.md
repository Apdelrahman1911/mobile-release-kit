# QA-003 R9-R5 — fresh complete final verification

## Scope, prerequisite and acceptance boundary

PROPOSED: no permission to run final gates is implied. This replaces the unused
R8-R2 verification plan only for the corrected, independently reviewed R9-R5
implementation and a fresh namespace. It does not change helper semantics,
commands, deadlines, required gates, cleanup scope or expected results.

Bind acceptance to candidate tree `387856e314cb3475c20509fb70f5a8c3708a87af`,
173 first-party files, 55 intended changed/new files, HEAD/main
`2beb37336fa8002b69f598fe431082606368310d`, branch
`fix/qa-003-local-signing-lease`, version 0.3.0. The original QA-003 finding,
R9 identity corrections and approved R9-R5 amendment remain the implementation
contract. The distinct implementation review must explicitly approve this tree
before preparation/freeze/dispatch. A test pass cannot replace that approval.

Current development evidence: 712 full Python/workflow tests, zero skips,
515.340 seconds; 66 targeted tests, zero skips; seven replay scripts and 30
corrected/control cases. All completed with exit 0 and exact owned scratch
cleanup. These are not final gates and none is carried into the new gate ledger.
The independent implementation reviewer also owns its separate probes/results;
require its final reconciliation and release of workers/shared destinations.

Preserve user-owned untracked AGENTS.md with SHA256
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb` and the
empty real index. No implementation, schema, workflow, dependency or test edit
is allowed during the freeze. Any such change invalidates it and requires review
and a new final run, not adoption of earlier gates.

## Preparation and unchanged helpers

After independent approval of this plan, prepare only NEW
`.mobile-release/remediation/QA-003-final-r4/`, requiring it to be absent.
Copy the seven reviewed r2 helpers byte- and mode-identically: `freeze.py`,
`verify-all.py`, `verify-matrix.py`, `verify-pins.py`, `wheel-smoke.sh`,
`probe-jdk21-signing.py`, `cleanup-build.py`. Root has inspected all seven and
the corrected wrapper; r2/r3 helper copies match. Preserve both old namespaces.
Never run their superseded wrappers.

Copy the corrected r2 `run-once.sh`, changing ONLY its absolute evidence path
and private TMPDIR. Keep `set -euo pipefail`, noclobber, exclusive log FD,
explicit if/else exit capture, FD close and exclusive final exit marker.
No old gate output, wheel, proof, installation or partial execution is adopted.

Use a new mode0700 `mkdtemp` parent under repository.parent with prefix
`.mrk-qa003-final-r4-`, a mode0700 `tmp/`, and an identity-bound owner marker.
Record parent/child/evidence identities, marker bytes and exact intended paths
before further use. Do not use shared temporary-pattern cleanup. Adapt only
preparation bindings from the retained preparation script for the current
snapshot, implementation approval, plan approval, namespace and development
evidence; have the actual script/copies/wrapper/ownership independently checked.

After actual preparation acceptance, run the unchanged temporary-index freeze
helper and prove its proposed tree equals the implementation-approved tree.
Bind all seven helper hashes, wrapper bytes/mode, owner marker and tool resolution
separately. Confirm 173 first-party paths, exact 55 issue paths, AGENTS exclusion,
unchanged HEAD/branch and real index. Before dispatch, require the independent
reviewer to accept the actual freeze/preparation, not merely this written plan.

## Shared destinations, toolchain and exclusive execution

No root development/test/replay controller remains. Wait for the implementation
reviewer to finish and reconcile its own resources. Coordinate with both reviewers
that nobody may install into or mutate MRK-002/venv, effective Bundler destinations,
or checkout build/egg-info during final preparation/execution. Read-only review
and fully isolated probes must not write these shared destinations. Observe only
needed process identities/names; do not read real credentials or kill another task.

Record the exact Python interpreter/version/venv configuration; effective
`python3`, Ruby, Bundler, actionlint, gh, Java and Xcode resolution; Gemfile,
Gemfile.lock and pyproject hashes; and Bundler path/frozen settings. Preserve
existing dependency resolution. Current expected tools are Python3.11.16,
Ruby3.3.12, Bundler4.0.16, actionlint1.7.12 and Java21.0.11. Local Xcode26.5
does not substitute for hosted pin26.3; required hosted Linux/macOS CI follows.
Stop on unexpected tool or source drift instead of silently switching tools.

Record only these named effective overrides from the unchanged runner/wrapper:
venv-prepended PATH, PYTHONSAFEPATH=1,
MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS=1, MOBILE_RELEASE_TEST_PYTHON,
BUNDLE_FROZEN=true, FASTLANE_HIDE_CHANGELOG=true,
FASTLANE_OPT_OUT_USAGE=true, FASTLANE_SKIP_UPDATE_CHECK=true, and private TMPDIR.
Do not dump environment values, authentication settings or real account files.
Editable/Bundler installs may update their known dependency destinations; compare
source/index/lock hashes and final pip/Bundler checks, not an immutable-venv claim.

## All 58 gates from zero

Run the unchanged runner sequentially: freeze check; editable installation;
Bundler install/check; entire Python suite; initialization, entitlements, profile
authority/installation, default cancellation, local signing, owned process,
native profile/process/CI, binary plist and Mach-O regressions; all Ruby support,
native capture, Play/Apple/lane/upload contracts; Supply/WIF; Fastfile validation;
actionlint; live GitHub Action full-SHA/dependency/runtime-import verification;
fresh wheel installation/resources/bootstrap/init/native source-versus-wheel;
matrix contracts and fresh isolated wheel; all sixteen source/wheel shard pairs;
actual complete disjoint union; exact owned matrix/build cleanup; pip check;
JDK21 signing policy; diff check and final unchanged freeze.

R9-R5 regression modules are included by actual full discovery, local-signing
patterns and mandatory native source/wheel PATTERNS. Enumerate the current
logical case inventory and reconcile actual observed cuts; historical 26,604
is not an assumed expected count. The unchanged bounds are 420 seconds per
package launcher, 890 seconds for the adapter and 900 seconds per gate/pair.
No added concurrency, lowered validation, omitted category or pass adoption.

Every result records command, actual exit, duration and log digest. Any failure,
timeout, unavailable external check, ambiguous cleanup or controller loss stops
acceptance. Preserve actual FAIL/unknown/unexecuted states. Do not automatically
retry a failed gate or restart a partially executed namespace.

## Historic failure and failure handling

Preserve the original unexplained `matrix-source-wheel-02` EEXIST FAIL, its
37 earlier PASS + 1 FAIL ledger, original wheel SHA256
`196af66f6ecf8af9981a24b33f21acb4f84ef404f8f64c2fe4b80db8d13c2f11`, all
43 failed-namespace entries, and the entire 2,261-entry installation
`/ORIGINAL_HOME/Projects/.mrk-qa003-final-matrix-tgf343b1`. Verify the retained
identity/content snapshots before and after this new run. R9/R5 corrections are
not its established cause. A fresh pass cannot explain or erase that failure;
the final reconciliation must state the remaining uncertainty explicitly.

The gate controller cleans only its exact reserved child group and fails if
absence is not confirmed. This is not protection after controller death. If the
controller disappears, preserve partial logs/installations and observe current
ownership before any further action. Do not infer success from partial output,
reuse a namespace, or signal historical numeric PIDs/PGIDs. Signal only with
current reserved process identity; otherwise retain uncertainty and investigate.

The unchanged wheel-smoke EXIT trap deletes only its exact temporary installation
on ordinary success/failure; wheel/logs remain. A failed installed smoke tree is
therefore unavailable for later inspection, an explicit forensic limitation.
Hard termination may prevent that trap; preserve and inspect exact known residue.
This does not authorize deleting the separate original forensic installation.

## Resource cleanup, delivery and remaining work

Full matrix cleanup requires all sixteen proofs, complete actual union and each
owned child-group/path absence proof. Preserve raw reports and wheel. Failed or
interrupted matrix installations remain needed until investigation establishes
otherwise. The unchanged build cleanup removes only byte-proven source copies,
not required editable metadata, user files, shared caches or source files.

After reconciled runner exit, verify exact parent/child/evidence identities and
marker bytes, then remove only the empty tmp, marker and owned parent. Unknown
residue prevents removal and requires inspection. Preserve all failure evidence.
No Gradle build is planned; if later needed, stop only our daemon after the
sequence. No real credential/keychain inspection or live Store mutation is allowed.

Reconcile all final gates, source/helper/artifact hashes, cleanup, historical
limitations and independent reviews before a scoped QA-003 commit. Stage only
the approved 55 issue paths, never AGENTS or ignored remediation evidence.
Use normal protected PR delivery to main and require hosted Linux/macOS matrix,
required PR checks and main CI success. No force push or protection bypass.
Delivered percentages change only after verified delivery.

Continue sequentially with QA-004, QA-005, MRK-008 and MRK-009; then perform the
required fresh, first-pass-style complete repository/all-release-path audit,
remediate further confirmed blockers with the same review workflow, and produce
the comprehensive feature report only after a justified READY verdict.
