# Independent plan review: inheritance shared-clock correction R1

## Decision and authority

**APPROVED_PLAN_ONLY**, for the original R1 plan **together with** its immutable fixture-inventory supplement. There is no remaining confirmed plan-level blocker in this bounded scope. Root may separately authorize implementation of this exact combined design; this review is not implementation acceptance or live execution permission.

- Plan: `SANDBOX-INHERITANCE-CLOCK-CORRECTION-PLAN-R1.md`, 14425 bytes, SHA256 `8f0d16050f95f13704d3aeb05a92a756a6f6a8b2ea1653b3db310130c0d77f96`.
- Required supplement: `CLOCK-CORRECTION-PLAN-SUPPLEMENT-R1.md`, 2034 bytes, SHA256 `b11fc2dda0396acfee2907ab5d6beac945d9ba20d16784dff72f47fb56e3d5a2`.
- Input manifests: `fcc0f519f9029337724ecd8aa5c57af99886cc5285232fbdc19618adb514e337` and `a521ee2a2a03384eab1dcf382eec35892a103130253f67028e6152ea6ce33411`.

Reviewer: `/root/qa006_clock_correction_plan_review_r1`, independent of the root plan author. Read AGENTS, SECURITY and applicable audit, provenance, signing and Store-operation skills. All existing inputs remain untouched. No helper was imported, compiled for execution, or run. AST parsing here is static inspection, not a Python/Ruby/native test.

## Reanalysis against actual code and evidence

QA-006's original FINDING remains a fixture-readiness/verification-reliability blocker, not a demonstrated Store bypass. The current supporting helper has a separately evidenced clock-contract defect: `runtime.py:21-28` uses Python `time.monotonic`, while `ruby_relay.rb:45-52,167-197` consumes Python endpoints using Ruby CLOCK_MONOTONIC. Both capable-entry consumers enforce the original lower bound; the defect cannot be corrected by deleting that bound or adding tolerance.

Read both independent result reviews and the complete scalar raw/outer/result records. Independently recomputed the current scalar gap as exactly **5.522709291 seconds** with Decimal arithmetic. The Ruby helper samples precede the Python-before helper samples, whereas each identical explicit clock ID (6, 4, 8) is correctly bracketed across interpreters. Root's actual scalar execution was `2a5a0c`, exit0; local hashes establish consistency of its retained evidence, not independent historical execution authentication.

The failed inheritance invocation remains actual exit1, three narrow observations, one Ruby entry failure and seven unexecuted routes. Its missing Ruby sample has not been reconstructed; this plan must not claim retrospective proof of that exact operand/cause. Original unknown-resource flags, failed scratch and negative/unexecuted gates stay retained.

## Clock design and lifecycle assessment

Using **the same Darwin clock_gettime API and CLOCK_UPTIME_RAW ID8** in both language getters removes the mismatched-origin assumption. It does not calibrate offsets. It is appropriate for this deliberately Darwin-only, pinned helper and preserves the existing Python-origin uptime budget model; it does not introduce a wall-clock-including-sleep guarantee. Unsupported systems must reject rather than choose another clock.

The plan correctly requires exact integer constant identity, available callable API, finite nonnegative float samples, and visible failure on unsupported platform, absent/wrong constants or API errors. No import-time sampling, fallback, translated old endpoints, deadline renewal or tolerance is allowed. The original single-language pure-driver measurement callables/scopes remain separate; changing their clock semantics would not be this fix.

I traced the complete nine runtime files. Controller initial/row/query timestamps flow through the shared Python getter; Python sender/relay/canary import it. Ruby entry, work, disposition, write, charge, cleanup and fork/exec checkpoints flow through its getter. Contract and reconciler timestamps are comparisons only. `contract.py:238-252`, `runtime.py:187-221`, `controller.py:363-388,589-717,786-925`, and `reconcile.py:166-444` must retain their exact original comparisons and finality gates. Bash remains an exec-only trampoline with `clockSample:null`, not a third independently timed owner.

Clock failure must stop new work and later rows, retaining actual failure. Required already-owned closure and bounded failure evidence are not permission to acquire another native worker, guess a signal target, substitute a clock or extend a disposal endpoint. Persistent clock failure can leave disposal unverified; record that uncertainty rather than falsely asserting cleanup. Original terminal-commit and actual-parent-wait rules remain unchanged.

## Paths, fixtures, selectors and authority

The new literal BASE, Ruby BASE, Bash Ruby target and root approval path must agree. The old consumed approval must never authorize the new scripts. Clock descriptor and exact correction/evidence bindings must be checked before Evidence/native acquisition, alongside the existing script, matrix, reference and selector barriers; required descriptor types should be compared exactly, not through truthy/coercive equality.

The context/frame schema need not change: the existing complete script map binds the producer and consumer implementation. Record the exact shared-clock descriptor in both the new grant and baseline, and keep the governing original plan plus new correction identity explicit. Historical clocks/contexts cannot be adopted into the new package.

The supplement resolves a real initial inventory omission: the complete driver reads `legacy-r3-r3-snippets.txt` and both `selector-control-snapshots` JSON files (`test_pure.py:1571-1572,2516,2810`). All three match original semantic-file bindings and must be copied byte-identically at their original relative names. They are pure fixtures, not replacement live selector authorities. Keep all46 original reference entries, bounded additions and original152 source/174 root-user/two-index selection unchanged. I did not follow those selectors to actual source/index/cache payloads.

One mandatory detail within the plan's already allowed narrow expectation changes: `test_pure.py:2782` currently constructs an old root by truncating the final character and appending `3`. In the new package that would name an invented correction-r3 root, not the actual consumed R3-R4 root. Bind this negative mutant explicitly to the complete original `sandbox-inheritance-r3-r4` literal. The expected new root must remain independent of the code under test. Preserve all11 route and seven Ruby-path checks.

## Required tests and safety review

The proposed tests address the cause, not merely the observed exception:

1. Keep all original93 Python methods and40 Ruby case obligations. Their old passes cannot transfer to new getters/loaded pairs. Freeze the entire new inventory.
2. Use ID-sensitive OS leaves with incompatible ID6/ID8 values. Exercise real getters and real entry predicates; the Ruby positive must invoke the complete constructor, not only the old `Relay.allocate` fixture (`test_pure_ruby.rb:170-180`). The legacy Python `time.monotonic` and legacy Ruby ID6 getter must each fail the regression. Any in-memory legacy getter must remain behind fictional leaves; do not accidentally call a real clock through the mutant.
3. Reject missing/wrong-type/wrong-ID constants, wrong platform, API errors and bool/integer/nonfinite/negative samples. Assert no added native acquisition, no fallback, no success label, and unchanged original endpoints.
4. Keep lower-bound/equality-at-expiry, late multihop, work/disposition/query, cancellation/control, no-EOF, terminal-commit and selector adversaries. Include current descriptor/evidence/grant substitution and stale-grant rejection before acquisition.
5. Add the clock_gettime veto before Python helper definition loading. Preserve the Ruby before-load veto and both retained real pure limiters. No fake may forward to a real native leaf or erase the attempt ledger. Re-read the complete changed pair and transitive fixtures in actual-code/safety review before admitting tests.

The original Ruby fake at185 ignores the clock ID; the Python fictional world at809-823 replaces common getters wholesale. Their historical passes therefore cannot establish clock interoperability. The new tests specifically eliminate that blind spot. Pure tests still cannot replace fresh native feasibility.

## Finite verification and permissions

Original consumption remains **Python3/4, Ruby2/2, inheritance native1/1, scalar diagnostic1/1**. No namespace adoption, reset, retry, old-scratch deletion or scalar repeat follows from this decision.

The plan explicitly proposes, rather than silently assumes: conditional original Python004; one separately charged additional Ruby pure invocation (cumulative3); and one separately charged fresh complete inheritance invocation (cumulative2). The additional Ruby/native proposals are technically bounded and suitable for a later exact-code/root-admission decision. This plan review grants **zero** live invocations. Each requires the specified separate safety/code approvals, original-count evidence, absent literal namespace, exact startup/tool/source bindings and root grant; failure remains consumed with no automatic repeat.

Full native scope stays11 rows;44/57 route acquisitions/execs, at most6 observers (50/63 total), hard64/96;30s work+10s disposal,180s outer;64KiB streams,4KiB chunks,512-byte commit,2MiB capture,8MiB runtime evidence. No Store call, build, credential access, Git dispatch, network/FFI, new query/signal route or application code is proposed. Unrelated Store state cannot be changed by this scoped correction.

## Verification, coverage and uncertainty

Static utility **437194, actual exit0**, rechecked all29 combined bound QA inputs (587749 bytes), parsed eight Python ASTs, counted93 unique Python test methods, independently reconstructed the11-row44/57 matrix with SHA256 `5eaae4e81cb621555d117cf86ae808c31a29d75091fa14c68bfc6b5c27216697`, checked46 references and cross-bound the three supplemental fixtures. Ruby40 is a source-derived closed-loop count, not a Ruby execution. Final report creation rechecked these same input pins.

Coverage is recorded separately. All runtime code and the440-line Ruby driver were read. Python's whole AST, native-guard/loader structure, complete test-method inventory and relevant clock/entry/approval/selector/terminal/BASE tests were inspected; this is not a new full implementation review of every inherited Python fixture. Fixture JSONs and legacy snippets were hash/structure checked without following selected payloads or executing snippets. Original reference *inventory* was reviewed; all46 referenced contents were not freshly reread here.

One multi-file display (`bd151f`) was truncated; its missing native-decision section was reread in `eede49`. No display truncation, static parsing or historical test label is counted as a fresh behavior pass. No native clock diagnostic, pure suite, build, Store rehearsal, source/wheel/hosted/full-project gate or current Git/remote observation ran in this review. The plan's SDK-header citation was not independently reread; same-ID bracketing is not a portable specification.

Actual correction feasibility, implementation correctness, safe full verification, QA-006/007 closure and product readiness remain unverified. Delivery remains9/16 (56.25%), **NOT READY**, with all remaining findings, fresh whole-repository audit and feature report still mandatory.

No background/build worker or persistent session was started. No existing file or disposable build output was deleted. Only these new required review deliverables were written; there is no reviewer-owned worker to stop or build output to reclaim.
