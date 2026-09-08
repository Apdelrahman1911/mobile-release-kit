# QA-006 R6 — independent actual-implementation review

**INCOMPLETE_VERIFICATION — implementation acceptance withheld.**

Reviewer: `/root/qa006_implementation_review`, 2026-09-07.

The completed source review and independent **pre-entry** verification support
R6's correction of QA006-IR-06: the original unexpected exception now survives
through the native wrapper, nested lifetime, cleanup, outer lifetime and final
result. No new implementation defect was confirmed in the completed scope.
However, mandatory entered-native observations, the identity-predicate mutation
control and complete regression suites remain **unexecuted**. This is **not**
whole-implementation acceptance, completed QA-006 remediation, final verification,
commit/push authorization, or a READY verdict.

The original QA-006 finding, R5/IR06 report and approved R6-R2 plan were re-read.
R5's interrupted review does not turn its outstanding checks into R6 passes.
The current review completed its authorized safe portion, not the prohibited
capture-entered or whole-project portion. Distinct production defect **QA-007**
remains unresolved; this review neither edits nor waives that runtime defect.

## Exact reviewed snapshot

- Version **0.3.0**, HEAD `2beb37336fa8002b69f598fe431082606368310d`.
- Branch `fix/qa-006-upload-process-fixtures`.
- Source `/ORIGINAL_QA006_SOURCE`.
- Canonical proposed Git tree **`6009247f3627c9825e9ad9c790a57876e09f3726`**.
- **152 files; seven changed paths versus HEAD; only two changed paths versus R5**:
  `tests/workflow/upload_process_fixture.rb` and
  `tests/workflow/test_native_upload_validation.rb`.

| Binding | SHA256 |
| --- | --- |
| Approved `PLAN-R6-R2.md` | `669c9c4398a9c80a52e2f35a02f0c6338341e4a8c171396057b4e70a235f91a1` |
| `plan-review-r6-r2/PLAN-DECISION.json` | `484a59265ec9d79bafc154c0fb296dc061e08f91cba6de2367d9a9f233f1ad09` |
| `implementation-r6/SNAPSHOT.json` | `abb6503fe36d442b229ed294a423e6fdabd507a49d4c2628d399c2544fa2226a` |
| `implementation-r6/complete.diff` | `2887af02483daa161f58de7a9e0c7d1af711953a3c445cfc4ceb77eb97a7b251` |
| `implementation-r6/r6.diff` | `88413fb5c79cb1d2264486708065b4fb5bee1216a7fd040047ab9164518bf299` |
| R6 `upload_process_fixture.rb` | `0dbdec86b0cae49390b7848e31af1a7e828030fb72f2d18b3d248ff757b2407b` |
| R6 `test_native_upload_validation.rb` | `661d81ba83e83ad70dd1ea3cb4a49421056460c46a1f608f8d5862f1b7d49a4f` |

All 152 actual file hashes and executable modes matched. The reviewer independently
recomputed canonical Git blob/tree encoding from their bytes and obtained the
exact proposed tree, then regenerated both supplied diffs from actual HEAD/R5 Git
blobs and current bytes: both matched byte-for-byte. The R6 proposed tree was
**not materialized in the shared Git object database**; an initial `cat-file`/
`ls-tree` lookup therefore failed. Root confirmed no alternate object location
exists. This is not a source mismatch or a claim that the tree object was checked
out/persisted. No object/index writes were performed to manufacture such a claim.
See `BASELINE.json` and `SOURCE-SNAPSHOT-REVIEWED.json`.

Both real indexes were empty and their exact byte hashes were preserved. All
**174** baseline root user/source files, the separate QA-003 work, both working-tree
status records and untracked user `AGENTS.md` remained unchanged. AGENTS SHA256:
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.
This inventory reconciliation is not a semantic re-audit of every repository file.

## IR06 correction: source and observed behavior

The rejected R5 implementation caught every native error, then used a four-mode
allowlist to decide whether it was a genuine harness failure. An unexpected
publication error in an ordinary mode consequently became a later first-close
assertion or cleanup exception. Runtime IOError redaction was legitimate; losing
the separately held original fixture error was not.

R6 addresses that cause rather than adding more exception-policy mode names:

1. `upload_process_fixture.rb:547–601` publishes the real nested `Lifetime` reference
   before native acquisition. `:657` selects its first primary before callback or
   wrapper errors. `:658–660` raises unexpected primaries before later assertions
   or cleanup-error promotion. Native runtime redaction remains byte-identical.
2. `:630–640` consumes an expected native injection only when actual entry,
   one actual matching close, completed descriptor close and the **same intended
   object** all agree. Saved message/status values avoid comparing an object to
   its own mutable current property. Intended IOError still requires the exact
   existing redacted ContractError type/text; a matching string alone is insufficient.
3. `:662–672` retains the positive joined-worker/SIGKILL/death-before-fallback
   requirements after expected-error classification. `:675–715` still fails on
   incomplete descriptors/threads/traps/registry/cancellation or cleanup errors.
   Secondary cleanup information remains distinct and cannot replace an earlier
   unexpected primary. Extracted `start_watchdog` (`:530–541`) retains deferred
   acquisition/publication and the existing deadlines/private EOF fallback.
4. `:25–45,719–949` adds **29 fixed proof cases**, not arbitrary code or platform
   parameters. They invoke ordinary native driver modes. The proof observes actual
   backend/callback entry, a source-anchor-derived final error, actual waiter
   status/ECHILD and descriptors. Raw failed `result.json` and driver status remain
   distinct from `primary-proof.json`; parent handling (`:288–318`) does not rewrite
   raw failure into native success or grant any Store authority.
5. `:241–247,483–485` permits no-child completion only for the explicit pre-spawn
   cases and their zero-attempt/closed-descriptor evidence. Frame-only proofs
   additionally require independently observed zero backend/callback entry.
   Unknown acquisition does not become a generic no-child acceptance path.

**Independently observed on R6:** all four original reviewer publication-failure
probes now retain the actual original outer object, including IOError plus a later
real-EOF close failure. StandardError remains the actual native return; IOError
still becomes the runtime's exact sanitized ContractError. Both secondary faults
remain separately recorded; all raw drivers fail rather than authorize upload.
Every actual native worker exits0 through its original private EOF, joins and
returns ECHILD on a subsequent real waitpid. Seven descriptors close and handler/
registry/cancellation state is restored. No signal is requested.

An isolated, reviewer-owned source copy restored **only the old R5 consumption
section**. The actual new publication proof rejects it: outer identity and saved
message assertions fail while nested/callback identity remains correct. The
mutated proof exits1, with real EOF/reap/descriptor cleanup and no signals. This
is an expected mutation-test rejection, not an accepted mutated implementation.
See `PRIMARY-PROBE-RESULTS.json`, `PROBE-COPY-BOUNDARY.json`,
`MUTATION-BOUNDARY.json` and the raw `primary-*`/`old-consumption-mutant.*` records.

### Mandatory plan proofs: separate dispositions

- **R6-PLAN-02, frame-only original: independently executed and supported.** Both
  frame-only IOErrors occur at the actual pre-delegation anchor with the frame
  already published. Independent outer observation sees the original; backend,
  callback and spawn-attempt counts remain zero. Callback error is nil, normal
  runtime redaction remains, four actual descriptors close, and the later close
  fault cannot replace the original. No waiter/child/status is invented.
- **R6-PLAN-01, entered distinct IOError: source reviewed; NOT EXECUTED.** Its
  trace anchor (`:527,828–847`) is after the real first-close flags/count and before
  raising the intended object; the proof substitutes a distinct same-message
  IOError. The code retains intended-versus-substituted identity, exact redaction,
  failed raw result and actual SIGKILL/death-before-control-close requirements.
  But neither that execution nor the copy deleting only
  `primary.equal?(@injected_error)` has been observed in this R6 review. Source
  plausibility and pre-entry passes cannot substitute for either required proof.

## Security and lifecycle assessment

The complete seven-path diff is tests/CI only. Runtime adapters, native capture,
Store code, schemas, package inputs, manifest/receipt logic and dependencies are
unchanged. There is no new Store operation or route to overwrite Store state in
this change. Synthetic fixtures carry no credentials or application signing data.
Private EOF, real direct-child ownership and observation-only marker use remain
separate from production native group-signal behavior.

In particular, `NativePrimaryProbe::Driver#prepare_native` (`:799–817`) explicitly
is **not durable process authority**: its live-waiter check is only a rejection
observer for an entered proof requiring approved isolation. It must not be used
as permission to run QA-007's signal-bearing paths on the shared host. This review
used an additional **before-entry veto** and denied all native/unknown/post-reap
signal requests. Only actual exclusive direct `OwnedChild` reservations could
qualify for an observer/driver cleanup signal; **none was requested**.

Reviewing this fixture fix does not authenticate release evidence, validate real
AAB/IPA/profile input, resolve Store uncertainty, or establish production readiness.
Those separate application/release contracts were not exercised here.

## Executed verification

Host tooling: **Ruby 3.3.12, arm64-darwin25; Python 3.11.16**. Full argv, scrubbed
environment, working directory, actual subprocess exit and raw stdout/stderr are
retained in each `*.run.json`. No Store, signing, Xcode/Gradle build or install ran.

| Check | Actual result and qualification |
| --- | --- |
| Snapshot hashes/modes, canonical tree, both regenerated diffs | PASS; all 152 match, both real indexes preserved; proposed tree not stored in shared object DB |
| Independent guarded native safe subset, seed 43894 | **5 methods / 1946 assertions; 0 failures/errors/skips; actual Ruby exit0**. Not full or unmodified native suite |
| Independent guard observations for that subset | 33 driver cases; 30 actual native EOF workers joined; 82 actual spawn/wait pairs completed; six actual Thread#raise C-call events from distinct injectors; zero entry-veto hits, signal requests, violations or unreaped reservations |
| 28 new pre-entry proofs within subset | All actual final/nested originals retained; two frame-only zero-backend cases; expected secondary identities and raw failed results retained |
| Five existing named partial/setup cases within subset | Actual partial descriptors/publication/readiness/watchdog failure paths remain failed and clean; no native block entered |
| Invalid mode/platform/parameters matrix within subset | Rejected before acquisition through both parent and driver entry points |
| Original four independent reviewer probes | 4/4 retain original; actual commands exit0, raw drivers exit1; native exit0/EOF/ECHILD; no signals |
| Isolated old-consumption mutant | Expected proof exit1; actual identity/message rejection; real clean EOF worker, no signals |
| `tests.workflow.test_native_profile_ci` under Python3.11 | **3 tests, PASS, no skips, actual exit0**. Actual YAML/bash fail-stop/aggregate behavior; Ruby suites/native platform operations are seams, not hosted execution |
| Syntax of both adapter tests, native tests, fixture and ownership helper | Five pinned-Ruby `-c` checks: PASS |
| Tracked `git diff --check` | PASS, exit0 |
| Both untracked new Ruby files, `git diff --no-index --check` | No whitespace diagnostics; exit1 means content differs from `/dev/null`, independently calibrated against clean exit1/bad-whitespace exit3 |

The guard's own final-error observation is independent of `harnessPrimaryRetained`
and the proof envelope. It records real backend yield/unwind/wait statuses and
actual distinct-thread cancellation calls. See `GUARD-OBSERVATION-SUMMARY.json`
and the complete `guard-*.json` records; these also retain raw fixture documents
before successful parent cleanup removes their temporary directories.

Two reviewer-only metadata/setup mistakes were corrected and recorded, not
classified as product defects or final-gate retries: the initial baseline reader
expected R5's `tree` key rather than R6's `proposedTree`, and a convenience helper
expected exit0 rather than no-index diff's exit1. The shared-object lookup failure
is separately qualified above. `BASELINE-SETUP-NOTE.json` and
`WHITESPACE-CHECK-NOTE.json` retain these facts and the latter's negative calibration.

Implementer records were read, **not substituted for independent passes**.
`development-r6-r1/RESULT.json` remains a failed launcher (zsh readonly `status`;
Ruby exit unrecorded), despite its green test footer. `development-r6-r2` records
only safe development; `reproductions-r6-r1` is root's reproduction evidence.
No failed attempt was overwritten or relabeled as an accepted gate.

## Coverage ledger and outstanding work

| File/area | Completed review | Remaining unverified on R6 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | Whole file/diff, required native suites, pin reuse, read-only permissions, fail-stop shell/aggregate; three Python CI contracts executed | Actual hosted Linux/macOS jobs, third-party action availability and whole-CI runtime |
| `test_android_upload_validation.rb`, `test_ios_upload_validation.rb` | Whole files and deleted/replaced tests, complete adapter arguments, include/teardown/callers | Both full adapter suites and shared descendant/timing/mutant contracts |
| `test_native_profile_ci.py` | Whole file/diff and actual three methods | Native profile validation and installed-wheel gate are not run by these contract tests |
| `test_native_upload_validation.rb` | Whole file and five selected methods; new matrix/error/raw-result assertions reviewed | Entered substitution; three original first-close positives; missing-cleanup mutant; post-reap repeated cancellation; hard-driver-loss control |
| `upload_process_fixture.rb` | Entire 1380-line file, whole diff/R6 delta, worker/parent/parser/EOF/result/native/lifetime/probe flows; safe real observations and mutation test | Entered predicate mutation, full adapter and real-clock/inherited-pipe controls, hard driver loss, remaining failure interleavings |
| `upload_process_ownership.rb` | Entire 1064-line file, source/error/interrupt/ownership/observation contracts; actual R6 use in pre-entry probes | Full R4 asynchronous/policy/unknown-ownership/observation adversarial replays on R6 |
| `fastlane/native_upload_validation.rb`, both platform adapters | Complete unchanged source/call relationships inspected; shared-native pre-entry calls exercised, not platform adapters | QA-007 runtime authority correction and signal-bearing captures; no real upload validation |
| `workflow_harness.py`, `run_native_profile_checks.py`, `pyproject.toml` | Relevant complete caller/package-scope inspection; Python CI harness executed; fixture files excluded from configured wheel payload | Package/wheel install, native profile worker gates, full dependency/runtime checks |
| Original finding, IR06, approved plan and review/development records | Re-read, bound and reconciled | Original QA-006 is not finally closed by this scoped review |
| 152-file inventory beyond reviewed areas | Hash/mode/tree integrity only | Not a fresh semantic repository-wide audit |
| Whole project Python/Ruby, Fastlane, Supply/WIF, Bundler/lock/pins, actionlint, wheel/runtime dependencies | **NOT EXECUTED** as full R6 gates | Mandatory complete verification after approved safe execution prerequisites |
| Ignored verifier/isolation approval, protected delivery/main CI, all remaining findings, new full audit/feature report | Outside this review; **NOT COMPLETE** | Root's separate mandatory work; none waived here |

Required next observations, before implementation acceptance, are the entered
same-message/different-object proof, its identity-only predicate mutant, all
existing native controls and both complete adapters under separately approved
execution isolation. Then complete required project/platform/package gates,
reconcile exact source/evidence again and obtain the remaining review decision.
An authorized disposable isolation or hosted-verification contract must come first;
this report does not authorize a temporary branch, hosted dispatch or native signal
execution. If the tree changes, affected review/observations need rebinding.

No additional confirmed source finding arose from completed checks, but unexecuted
paths and new failure interleavings can still reveal defects. No bug-free claim is made.

## Own resources and preservation

All **35 actual native workers** started by this review completed private EOF and
joined (30 guarded subset, five independent/mutant probes). Guarded direct/native
reservations all have matching actual reap observations. Injectors/watchdogs are
joined, no cancellation remains in completed fixtures, and **no known reviewer
worker remains**. No cleanup signal was sent; no build process was started.

The sole R6 scratch root was inventoried and archived; every archived file hash
was checked before deletion: **26 files / 141906 original bytes**, retained in
`synthetic-scratch.tar`. Its SHA256 is
`ecf1154be1b2ad3fe0d0a5cdbdf95b7e5e4087632bfc6426d337351f9676be91`.
That scratch root and the tiny whitespace-calibration inputs were removed.
No other task's process, caches, source, deliverables or older R5 diagnostic trees
were touched. See `CLEANUP-DISPOSITION.json`, `SCRATCH-INVENTORY.json` and
`END-PRESERVATION.json`. Checksums bind local evidence integrity; they are not
independent authentication or implementation approval.
