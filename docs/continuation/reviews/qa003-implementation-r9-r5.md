# QA-003 R9-R5 — independent actual implementation review

## Verdict and exact binding

**APPROVED_IMPLEMENTATION_ONLY.** No additional required implementation correction
was found in the reviewed whole QA-003 diff and corrected R5 amendment. The two
confirmed R9 omissions are closed by actual code and independent behavioral
verification below; neither was waived. The preceding coherent-profile-identity
correction and original cooperating local-signing lifetime repair are also accepted
within this implementation-review scope.

This is **not** final verification, QA-003 delivery, a commit/merge authorization
without the remaining gates, or a READY verdict. The historical unexplained
wheel-shard failure remains preserved and unwaived. A fresh full-repository
production-readiness audit has **not** occurred in this review.

| Binding | Reviewed value |
| --- | --- |
| HEAD/main | `2beb37336fa8002b69f598fe431082606368310d` |
| Branch / version | `fix/qa-003-local-signing-lease` / `0.3.0` |
| Complete proposed Git tree | `387856e314cb3475c20509fb70f5a8c3708a87af` |
| Source inventory / intended diff | 173 first-party files / 55 changed or new files |
| Approved R5 amendment SHA256 | `88803087c6a0d570a3447bc5417af44f23a81acc0151da48ed859495311b4fff` |
| Unchanged approved R4 base SHA256 | `9cea9edceafb0c666ce339ad3fe54a3baffcda014f03f3e98c5e86068e7f2f38` |
| Real Git index SHA256 | `0ddba9fac6daeb32b7f66749135fcc7c4fb049459a7d46b71663ea963e5d6af7` |
| Preserved user AGENTS.md SHA256 | `7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb` |

The implementation reviewer is distinct from the independent plan reviewer.
Original `FINDING.md`, `FINDING-IDENTITY-R9.md`, rejected R9 implementation report,
R4/R5 plans and independent plan approval were reconciled against actual sources.
All 173 contents, Git blob IDs and executable modes match the proposed tree;
HEAD/main/branch, real index, user AGENTS, plan and parent snapshot are unchanged.
The index remains empty of staged changes. Exactly the intended 55 paths differ.

## Closure of the confirmed omissions

### QA003-IR9-01 — setup-stage observation/removal uncertainty

**Fixed:** `src/mobile_release/credentials.py:1169–1186` now places the narrow
setup-stage stat/identity/comparison/unlink sequence behind an ordinary OSError
latch. `conflict(stage)` executes before unwind, including failed context entry
before ExitStack registration. The original stage slot is cleared only after
confirmed unlink success. The installer skips the conflicted name and cannot
emit `resolved`; the composing owner's no-I/O callback gates subsequent
reconciliation/finalization (`956–963`, `1067–1088`, `1289–1291`, `1335–1350`).
Independent destination/native cleanup and raw-handle closure remain active.

The special absence rules were **not** weakened or conflated: actual absence at
the first setup stat or final unlink still rejects signing admission while
allowing safe owned cleanup and idle state. Disappearance at `require_current`'s
already-observed comparison remains latched and pending. Fatal ProcessError and
cancellation classification remain outside the new ordinary-error catch.

Independent actual-filesystem verification covered three roles (owned destination,
real foreign EEXIST borrower and own-inode EEXIST) at four ordinary-error cuts
(first stat, comparison stat, unlink before effect, unlink after effect): **12
cases**. All rejected body/native creation, retained original intent bytes/inode
and checkpoint, made no later implicit access to the failed stage name, omitted
`resolved`, preserved borrowers and performed independently safe cleanup.
Separate fresh original-session CLI recovery completed, followed by idempotent
`absent` recovery. Another **nine actual absence cases** proved the three
boundary-specific outcomes rather than manufacturing FileNotFound return values.

### QA003-IR9-02 — EEXIST borrower fell through into owned cleanup

**Fixed:** `src/mobile_release/credentials.py:1033–1066` now gates the owned-attempt
branch on `reused_identity is None`. The borrowed branch validates its actual
bounded-read metadata and final post-close path observation; it no longer makes
an additional ignored owned-role stat against the unrelated stage identity.
Independent stage cleanup is unchanged. Importantly, owned cleanup is not gated
only on `linked=True`, preserving ownership when linking succeeded before an
ambiguous syscall outcome.

An independently instrumented genuine EEXIST stable control reached exactly
**three** installer destination observations at `resolved`, not four. Seven
additional cases changed the real destination or raised an ordinary error before
the actual **remaining final** stat, after the real bounded reader closed:
metadata, same-byte foreign inode, different-byte foreign inode, disappearance,
same-inode content edit, symlink replacement and final-stat I/O failure. Every
hook fired. All cases preserved the observed conflict and original pending
controls, performed no borrowed unlink, and completed independently safe native
cleanup. Foreign objects and the symlink's unrelated target survived. Explicit
recovery returned the exact expected `recovered` or `recovered-with-conflict`
response/exit, and repeated recovery returned `absent`.

Three owned-link controls additionally passed: real own-inode EEXIST; successful
link followed by KeyboardInterrupt; successful link followed by OSError. Original
owned names were cleaned safely, unrelated paths were not adopted, and normal
admission occurred only for the stable owned-EEXIST case. The removal of the
obsolete fourth-stat hook was **not** counted as rejection coverage.

### Preceding identity/lifetime contracts

The earlier coherent-profile correction remains present: bounded reads return
actual bytes and observed file metadata (`credentials.py:901–923`), comparisons
bind read identity to initial/expected/current observations, and cleanup retains
per-name contradictions across both owners. `local_signing.py:72` excludes access
time but compares the relevant observed metadata; `cleanup_profile` at757 and
recovery at1029 preserve role-aware ownership and observed conflicts. Initial,
EEXIST and final admission cannot silently reselect an inode using earlier bytes.
Actual disappearance is explicitly handled rather than indexing a missing
snapshot. Existing identity tests and fatal-cleanup tests passed again on R5.

The original QA-003 account-wide cooperating lease still spans credential/global
state inspection, temporary profile/keychain use and teardown. Pending state
blocks new signing; recovery uses original intent and observed resource ownership.
Forked copies do not inherit parent mutation authority; owned process completion
and cancellation evidence bound cleanup. Those invariants were inspected across
both owners and exercised by the original lease/composition/recovery tests below.
This is not a claim that unrelated native apps honor the lease or that arbitrary
same-UID writes after the final validated observation are atomically prevented.

## Whole-diff coverage and cross-component reconciliation

`REVIEW-COVERAGE.json` records every path and hash, review method and this revision's
independent module-execution coverage. The broad R9 continuation completed the
remaining 26 test/fixture reviews before R5 arrived; unchanged sibling hashes
still match, and all five R5 amendment files were reread in their corrected form.

| Area | Actual inspection / verification |
| --- | --- |
| Runtime, 10 changed/new files | Full new lease and owned-process modules; cancellation, credentials, profile authentication and changed Android/iOS/preflight/discovery/CLI paths; affected callers, no-I/O conflict registration, native cleanup, durable state, status/recovery and fatal precedence |
| Tests/fixtures/helpers, 35 changed/new files | Full new files or all changed assertions and surrounding behavior; actual filesystem mutations, no-clobber ownership, recovery, process/fork/signal lifetime, persistent matrix contracts/runner/fixtures, dangerous hooks and cleanup before fallback |
| Documentation, nine changed/new files | Local-signing guide, credentials, integration, profile authority, troubleshooting, upgrading, README, SECURITY and CHANGELOG reconciled with implementation and intentional host limits |
| CI workflow, one changed file | Native/source/installed-wheel pattern inclusion, process watchdog/fixture contracts and fail-closed aggregate dependency behavior; applicable workflow test modules executed |
| Other 118 first-party paths | Inventoried and hash/blob/mode bound, unchanged outside this QA-003 diff; not claimed as a fresh full-source read of the entire repository |

No Fastlane, Store-client, receipt/manifest schema, provenance authority, reusable
release workflow or caller-template change is in the QA-003 diff. Changes to build
callers route local process/lifetime checks; they do not grant Store credentials
or Store-authorized OIDC to build jobs. No Store mutation was invoked. Consequently
this fix does not overwrite Google Play tracks, select a new Apple build, change
candidate artifacts or bypass the manual public-release boundary. This static
scope check is not substitute proof of the later mandatory whole-release audit.

## Independent verification results

All Python executions used Python **3.11.16**, the existing MRK-002 venv read-only,
`PYTHONDONTWRITEBYTECODE=1`, explicit repository `src`/`tests` paths and a dedicated
reviewer-owned TMPDIR. Exact commands, environments, raw log hashes, exit markers
and session completion are in `REVIEW-VERIFICATION.json`.

| Check | Actual result |
| --- | --- |
| `unit.test_local_signing_profile_identity`, `unit.test_local_signing_failures`, `unit.test_ios_profile_installation` | **66 methods PASS, zero skips, 21.905s, exit0**, session45422 polled complete |
| `unit.test_local_signing`, `unit.test_local_signing_composition`, `unit.test_local_signing_native`, `unit.test_local_signing_recovery`, `workflow.test_local_signing_matrix`, `workflow.test_native_profile_ci` | **56 methods PASS, zero skips, 72.690s, exit0**, session45995 polled complete |
| Reviewer-authored `probe-r5-independent-v2.py` | **32 cases PASS, exit0**, session43655 polled complete; 44 actual fresh CLI subprocesses joined; 4,725 tracked production FD acquisitions closed before fixture fallback |
| Fresh CLI outcomes within those 32 cases | 39 expected exit0 results and five expected exit1 `recovered-with-conflict` results; no unexpected exit was called success |
| Current `git diff --check` | **PASS, exit0**; new final log/marker preserved |
| Final source/ownership reconciliation | **PASS:** 173 contents/blobs/modes, exact55 changed paths, plan/snapshot/HEAD/main/branch/index/AGENTS identities, scoped cleanup |

The second suite executes isolated real flock/fork/default-signal/process paths,
original protocol crash-cut coverage, synthetic recovery, and workflow reducer/
launcher lifetime. Its small synchronous clang fixture checks the Darwin statfs
ABI, not a mobile build or live signing operation. This suite is **not** the full
persistent source/wheel crash matrix or complete frozen58 gate union.

### Preserved negative review-harness result

The first reviewer probe draft failed exit1 before any CLI child because it used
nonexistent private `allow_pending`/`existing` APIs. This is a **review-harness
setup/API error, not a product finding or PASS**. Its original script, raw log,
exit marker and exact cleanup record are preserved. `HARNESS-CORRECTION.json`
pins the separate corrected v2 script: it uses the inspected `recovery=True`
acquisition and actual `os.listdir(owner.fd)`, in a new output namespace. No
behavioral assertion or production implementation was weakened. The v2 results
alone support the 32-case pass above.

## Remaining limitations and required next steps

1. Root must prepare and independently review a **new** final-verification
   namespace after this acceptance, then execute all **58 gates from zero**, all
   **16 source/wheel shard pairs** and the actual complete persistent union.
   Never run stale final-r2/r3 wrappers or adopt development results as final gates.
2. Complete Python/Ruby/workflows/Supply-WIF/Fastlane/actionlint/Bundler/pinning,
   installed-wheel/runtime-dependency, native/JDK21, diff and resource-cleanup
   gates, protected delivery and main CI remain root responsibilities. They were
   not executed by this reviewer on the corrected tree and are not marked passed.
3. Root's 712-test development pass and separate corrected repro replays are
   separate evidence, not this reviewer's independent final-gate execution.
4. The historical wheel-shard `state.pending` EEXIST failure and preserved
   `/ORIGINAL_HOME/Projects/.mrk-qa003-final-matrix-tgf343b1` installation remain
   **unexplained and unwaived**. The two R5 fixes do not establish its cause; all
   negative/forensic evidence remains intact.
5. No real credential/keychain, protected consumer build/export, authenticated
   native signing service, live Store, asynchronous Store behavior or public
   release was exercised. No unsupported host/toolchain was called passed.
6. QA-004, QA-005, MRK-008, MRK-009 and the mandatory fresh all-file/all-lifecycle
   production-readiness audit remain separate. Overall readiness is still
   **NOT READY**; implementation approval is not final product acceptance.

## Preservation and task cleanup

No product source, committed test, public document, workflow, index/ref or user
AGENTS was changed by this reviewer. Writes are confined to new ignored evidence.
Both independently owned probe scratch directories were removed only after
recording results. The exact dedicated test directory was verified empty and
identity-matched (device16777232/inode82983525), then removed with **rmdir only**.
All raw scripts, results, logs and failed-harness evidence remain.

Both test sessions and the probe session completed; all 44 independent CLI
children were joined. No reviewer process still needs the shared MRK-002 venv,
Bundler, checkout build/egg-info or other shared output. No package install,
Bundler operation, mobile/Gradle build, shared-process signal or forensic-resource
cleanup occurred. The test-owned synchronous ABI fixture completed inside the
now-empty removed TMPDIR. `TEST-TMP-CLEANUP.json` records this reconciliation.
