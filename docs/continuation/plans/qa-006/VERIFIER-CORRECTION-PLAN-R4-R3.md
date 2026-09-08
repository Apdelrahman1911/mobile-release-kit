# QA-006 — verifier correction R4-R3: actual consumption boundaries

**PROPOSED ONLY.** Obtain independent plan approval before changing any helper.
This is ignored-verifier correction, not product acceptance, a native launch,
source-cache hold release, a final-suite pass or permission to commit/push.

## Reanalysis and exact retained baseline

The complete independent actual-code report is
`verifier-implementation-review-r4-r2/IMPLEMENTATION-REVIEW.md`, SHA256
`96c69f5216d08424d2a4cb092bd5ff72aeebe7e54c69e73a26fa88d0eb8e7c6c`; decision SHA256
`5a436bd2c4d84d721f9427050a26a87ae3b97fe82ef4ca516ebeb17695b8a2b2` is
**REQUEST_CHANGES**, not execution authority. Its entire37-input coverage and
retained raw-result qualification remain. Root read that complete report, the
complete approved R4-R2 plan, actual observer/authority/ledger chain, runner/
process collector, all wheel guards/producer/seal/script and relevant schemas,
bootstrap callers and generated tiny-producer code.

Frozen rejected package: `verifier-implementation-package-r4-r2/`, snapshot SHA256
`53072272200e94c6cf374ac76ed2a4b7b13e73555e2d01f7e117526642af98a8`; finite manifest
SHA256 `299fa56907349b9c039822fbd5b2deb441d4077747bcdf75d9f62ffcb66665e7`. Preserve
every file and failed run. R4-R2's original plan SHA256 is
`cbc7f824bfbd9a6dd8397bec4697a222657c660e089819c1a0acaa332b37b8e4`.

The four confirmed supporting defects are reachable in actual consumers:

| ID | Actual root cause and affected package paths |
| --- | --- |
| VRI4R2-01 | `current28/observe-owned-workers.py:8–16` omits the authority argument after `check_frozen`; `owned_outputs.py:613–643` reloads it and `bindings.py:900–903` deterministically rejects. Gate40 cannot complete. |
| VRI4R2-02 | `process_gate.py:379–431` hands its log fd directly to the child; `drivers/run-finite-proofs-r4.py:237–264` checks64MiB only after exit. The declared live writer bound is absent. |
| VRI4R2-03 | `drivers/run-finite-proofs-r4.py:123–147,186–201` verifies source then invokes SourceFileLoader, which may read unbound bytecode. Named helper inventory alone does not exclude cached imports. |
| VRI4R2-04 | `owned_outputs.py:373–385,509–553` guards package subsets, not the newly produced interpreter/configuration/full startup namespace. `wheel-smoke.sh:24–25` uses the new venv before such a guard, and later checks are still incomplete. |

These are static, source-derived counterexamples. No existing malicious cache,
injected startup file, disk exhaustion or native reproduction is alleged. They
are not new numbered product findings. Original VRI3R3-01..05 and VPG-01..10 remain
open pending actual evidence, not merely implementation changes.

Fresh root named preservation R12 matched152 QA-006 and173 root source files,
AGENTS, indexes and fixed local refs; no real Git command or object write.
`continuation-2026-09-07-r12/PRESERVATION.json` SHA256
`051f904d822f1cd4561ed145e277c7038de4eb1912e6e2479f1ba55280eedbd2`, actual tool exit0.
QA-006 calculated tree remains6009247f3627c9825e9ad9c790a57876e09f3726; preserved
QA-003 tree387856e314cb3475c20509fb70f5a8c3708a87af; HEAD/local main2beb373, version0.3.0.

## Scope, compatibility and invariants

Change only active ignored `verification-final-r1/` helpers and new
`verifier-correction-r4-r3/` preparation/driver records. Retain exact before copies
and a new frozen package; never overwrite the rejected package, its manifest or
old proof results. Expected code changes:

- `observe-owned-workers.py`, `bindings.py`: explicit authority forwarding,
  cache-free helper namespace checks and bootstrap-input binding.
- `process_gate.py`, `evidence_schemas.py`, affected completed-row/controller
  consumers: bounded combined pipe collection and its exact result contract.
- `owned_outputs.py`, `wheel-smoke.sh`: genuine venv/install subcommand custody,
  complete before-first-use and subsequent runtime guards; completion/cleanup.
- `verify-frozen-diff.py`, `verify-process-gate.py`, existing mapped/integration/
  VPG/pure drivers and the finite runner: preserve existing cases and add actual
  entrypoint/output/bootstrap/runtime tests. New fixed correction proof driver
  is permitted and must be in the exact reviewed driver inventory.
- New static `WHEEL-BOOTSTRAP.json`, plus `CONFIG.json`, schema/helper inventories
  and generated fixture bindings: explicit reviewed bootstrap source/tool policy.

Use new private policy version `qa006-verifier-r4-r3-v1`; update all exact producers,
consumers, fixtures and inventories together. This is not a product schema/version
change. Old frozen authority cannot be accepted under the new policy. Preserve
all45 real gate IDs/order, all13 Ruby files and every prior proof obligation.
Do not loosen duplicate authority registration, source/cache exclusion, complete
evidence schemas, byte/hash/source equality, Store isolation or ownership guards.
No original LIMITS/ROLES ceiling may grow; new controls count in original budgets.

## VRI4R2-01 — the actual observer shares its one authority

At the thin entrypoint, call `load_frozen` once in the existing single action;
pass that exact registered instance into `check_frozen` and `prior_workers`.
Recheck its backing references immediately before publishing the observation.
Do not change `check_frozen`'s return type, return unvalidated dictionaries, reuse
an authority across actions, create a replacement action or remove the duplicate-
load guard. Original fresh collection/group query and complete predecessor/log
validation remain required. Audit other thin callers for the same omission.

Add an actual entrypoint route with genuine preceding synthetic controller
completions/logs and actual read-only group observations after later native approval.
Count through the real loader: exactly one load, actual child exit0, a fully bound
receipt and no deletion. Add missing/changed predecessor/log/reference and wrong/
closed authority cases; no success receipt on rejection. A function-only mock or
45-name routing enumeration is not this test. Include this real entrypoint in the
new actual-sized lifecycle proof as well as preserving original219 cases.

## VRI4R2-02 — bounded output before it reaches retained storage

Replace direct child-to-log redirection in `execute` with an owned nonblocking
combined pipe (`stdout=PIPE`, `stderr=STDOUT`). The child receives no log fd. The
parent incrementally drains fixed bounded chunks and writes no more than the
declared combined cap. One observed overflow byte may detect overrun but must
never be persisted beyond the cap or treated as valid output. Do not buffer the
whole log in memory. Keep an exclusive/no-follow owned regular log, actual write
counts/digest, retained-prefix/overflow/error fields, actual EOF and close states.

Keep the original900-second maximum work deadline, original stop/group allowances,
flag-only cancellation and concrete Popen ownership. Check cancellation/deadline
after potentially blocking operations and immediately before acquisition and log
write. Overflow, read/write/select/close failure or cancellation latches failure,
stops ordinary work and forbids PASS. Dispose only the unambiguously retained
direct child under the existing stop protocol. A reaped/unknown child never grants
a numeric group signal. If a reaped leader leaves a pipe held open, boundedly stop
draining and report unresolved EOF/group state rather than guess signal authority.
Close every owned pipe/log/selector once; preserve first and secondary errors.

The disk contract is explicit: before dispatch require the existing4GiB floor plus
512MiB headroom; while collecting, check the free-space observation on every loop
and before every retained log write, refusing a write that would cross the4GiB
floor. After each blocking observation/write, reconcile deadline/cancellation and
the next permitted operation. Keep post-command/fixture checks too. This is a
cooperative admission policy on observed free space, not an atomic reservation or
guarantee against unrelated writers/OS allocation. If space falls below floor,
retain available evidence and stop later work; never delete history or other tasks.

Accept only finite positive typed limits no larger than the fixed caps; tests may
use smaller caps to exercise exact boundaries without64MiB fixtures. All callers
use explicit reviewed caps/space policy, not caller-widened unrestricted integers.
Update exact successful/completed-gate schemas and all consumers with these new
bounded-output fields; success needs full EOF, complete writes, reaped exit0,
uncancelled timely work and valid clear group evidence. Failure-only fields cannot
be smuggled into a successful schema. Preserve raw failing outcomes separately.

Tests: real owned no-fork children for exact-cap, one-over and endless mixed
stdout/stderr; closed streams before child exit; reaped child with held pipe;
cancellation; acquisition/poll ambiguity; log collision, read/write/close faults;
terminal completion/error publication. Retained bytes never exceed cap; assert
real stop/reap/EOF or truthful UNKNOWN and zero later child acquisition. Fake only
the named disk-stat seam to cross floor/headroom exact/one-below while a real child
is active; do not fill the actual disk. Native cases require later exact approval.

## VRI4R2-03 — authenticated source, not incidental bytecode

Replace the parent's `spec_from_file_location`/`exec_module` bootstrap with a
definition-only module created from the exact source bytes returned by the bounded
no-follow authenticated read against the approved package reference. Compile and
execute those same bytes; never reopen via a source loader or consult .pyc. Preserve
the fixed module name/__file__ semantics and isolated interpreter; no dynamic
plugin path or arbitrary module selector. Validate package/review scope and all
required source/authority inputs before this bootstrap or any native acquisition.

Audit each sibling helper/proof entry's actual import root. Ordinary imports are
allowed only from a freshly owned, exact reviewed helper-copy namespace which is
proven free of bytecode/cache/import-configuration entries immediately before use.
For active final-helper consumers, reject `__pycache__`, `.py[cod]`, symlinked/helper
replacement or unknown importable names by bounded metadata-only inventory before
imports; do not read a rejected cache payload. Recheck after participating work.
Do not treat named `.py` hashes or `-B` alone as a cache-free namespace proof.
The initial direct script/stdlib runtime remains part of the pinned runner TCB;
this is not an assertion of entire-host/interpreter authenticity against compromise.

Pure tests use a new fictional review package and a synthetically generated valid
conflicting timestamp/hash pyc whose only alternative behavior is a harmless
in-memory sentinel. Keep named source bytes unchanged. The actual parent loader
must execute authenticated source only, or reject before helper execution/native
acquisition. Include absent cache, unknown cache name, symlink, replacement and
fresh-copy import paths; native acquisition is independently vetoed. Do not inspect,
change, relocate or delete either real source cache or any frozen package cache.

## VRI4R2-04 — small sealed execution runtime before first use

Use a minimal owned **pip-free target venv**, rather than admitting arbitrary seed
startup packages. This is a private wheel-verifier change, not a product runtime
dependency change or a weaker installed-package test. Keep actual wheel installation,
console entry point, package/resources/import checks, init/recovery and all native
wheel gates. The exact tested target remains outside the source checkout.

### Independent bootstrap and genuine subcommand chain

`WHEEL-BOOTSTRAP.json` is a new reviewed static input, included in the exact accepted
helper/static inventory. Bind the fixed selected/effective Python tool relationship,
the required existing venv stdlib entry/template inputs, and the existing reviewed
bundled `pip-24.0-py3-none-any.whl` file (path/identity/size/hash), plus the exact
minimal layout and pip-launch contract. The bundled wheel is already a named
preparation prerequisite; do not install/download a different pip or infer trust
from its version string. Use typed exact schema/reference checks and include it
in stable authority and all rechecks. This does not enumerate unrelated runtime
or user configuration or attest the whole standard library.

1. Under `WHEEL-OWNER` and the active wheel-install gate, record exclusive attempt
   ownership before any venv dispatch. Require the target absent. Actually invoke
   the bound base Python with `-I -B -S -m venv --without-pip TARGET` through the
   reviewed owned collector, not a shell-supplied status. `-S` removes startup site
   authority for this base bootstrap; it is not used to pretend target prefix
   detection works differently on Python3.11.
2. After actual success/EOF/reap, use the already trusted base helper to inspect
   the complete target namespace without executing the target. Require expected
   fixed minimal directories, exact literal Python aliases to the bound effective
   interpreter, unchanged interpreter selection/bytes, restrictive owner/modes,
   strict `pyvenv.cfg` with system-site disabled and correct home/version/executable/
   command, empty site-packages, and only independently justified venv activation
   files/template transforms. Check optional platform `lib64` alias exactly when
   justified by the bound platform. No unknown file, .pth, customizer, module,
   bytecode, symlink target or extra directory can approve itself. Guard config,
   aliases and executable without using the unvalidated target Python.
3. Publish a no-adoption VENV creation receipt only after completed child/log,
   exact policy/owner/input references, full verified inventory and rechecks.
   The original attempt/receipt must bind actual run/action/subcommand, not a
   future wheel-gate PASS. Failed/partial/cancelled output remains held and blocks
   all target use; no missing-receipt recovery/adoption.
4. Before installation, recheck that genuine receipt, complete namespace/config/
   alias/interpreter custody, reviewed pip bootstrap and exact wheel. Invoke the
   **bound base Python with `-I -B -S` and the bound bundled pip wheel's fixed
   `pip` entry**, using pip24's `--python TARGET/bin/python install --no-deps
   --no-index --no-compile WHEEL`. Pip's target subprocess is an explicitly reviewed
   consumer after this pre-use guard, not an implicit exception. Inspect its pinned
   implementation/argv/environment in plan/code verification. Disable user-site,
   ambient Python paths, pip config/index/cache/network behavior; use fixed private
   cwd/HOME/temp. No invocation may use an unguarded installed target pip module.
5. Own actual pip parent completion and its target-child contract. After success,
   inspect complete venv again from the trusted base. Permit only the exact delta
   derivable from the verified wheel and pinned installer: full package/resources,
   complete dist-info/RECORD/direct URL/INSTALLER/REQUESTED semantics and the exact
   generated target console launcher. Preserve baseline interpreter/config/aliases
   and activation bytes. Any extra startup/cache/module path fails before first
   target module/console invocation. Persist an INSTALL completion receipt binding
   both actual producers and exact wheel/venv/predecessor inputs.
6. All later `guarded` target launches must recheck this receipt, full venv namespace,
   exact interpreter/config/aliases and all import/startup/package/resource bytes.
   Generated project/test/log outputs outside venv retain their own existing
   consumers; they cannot authorize changing runtime inputs. Do not inventory and
   bless unknown startup files only at seal/cleanup. Preserve `-I`/safe-path/env
   flags as defense in depth, not as a .pth prohibition.
7. Run the final dependency check using the same authenticated bundled base pip
   entry and `--python TARGET/bin/python check`, under the same pre-use guard.
   Do not seed target pip merely to run this check. Update the tiny genuine offline
   producer to use the same new real functions; no alternative mocked receipts.

Bound both producer receipts in final wheel completion and cleanup. New strict
schemas require complete attempt/log/action/owner/predecessor/wheel/inventory
relationships, unknown/missing/type/old-policy rejection and backing-byte rechecks.
No delete permission follows from production/installation receipts: existing
successful outer gate, complete seal, prior workers and immutable exact inventory
are still mandatory for cleanup. Preserve all failed/foreign/substituted outputs.

### Runtime regression evidence

After separate native approval, use the existing tiny offline source/builder and
real target venv/pip/wheel operations. Add negatives before pip, first import and
later guarded import: foreign .pth, `sitecustomize.py`, `usercustomize.py`, unknown
module/cache, changed pyvenv.cfg/system-site flag, replaced interpreter/alias/root/
site directory, extra dist-info or changed launcher, malformed/missing/failed/
wrong-owner/wrong-tree/wrong-predecessor receipt. Assert the real guard denies
before the affected child is acquired, all unknown bytes survive, and no cleanup
or subsequent consumer runs. Keep unchanged positive actual install/CLI/module/
dependency checks and existing post-seal cleanup negatives as separate evidence.
Test cancellation after mutation/child success but before receipt, file/fsync/
publication faults and reruns: fail/retain, never silently adopt or continue.

## Proof matrix, budgets and truthful verification

Before native dispatch create/review a new finite case manifest including all
original103+62 pure cases, original219, mapped30, integration5, VPG143 and their
69 schema/67 preparation subcases, plus the new cases above. Preserve historical
25 mappings,10 controller and24 protocol controls and both separate Bash `-n`
checks. Explicitly record added case order/counts and exact helper/driver/static
inventory; new WHEEL-BOOTSTRAP must not disappear behind the old28-name assertion.
Do not substitute a subset/AST pass for a required native actual consumer.

Preserve all original action/time/byte/fd/launch/output/graph quotas. New receipts,
bootstrap reads, repeated runtime inventories and streamed logs are charged to
actual roles. Prove the fresh **actual-sized prepare → actual parent completion →
late check → real observer → guarded cleanup** sequence fits without resetting
actions/raising limits/eliding checks. Earlier218PASS/1FAIL/exit1 and all partial
pure runs remain intact; every new failure is retained with actual outer exit.

Before actual-code review only bounded pure/file-only preparation is allowed:
fresh exact namespaces, fixed registered cases, native/network/process/signal
boundaries denied, original cooperative deadline/output/write ceilings, all
failures and raw receipts retained. Do not run the finite native runner merely
because this plan passes. Freeze all new code and driver bytes and obtain a
distinct actual-code safety decision; only then seek exact one-shot proof launch
authority. Inspect existing bundled pip/venv sources file-only; do not execute
or extract them during plan review or use unrelated installed packages.

## Risks, recovery, documentation and next gates

Risks include bypassing fresh authority checks, losing output while reporting
success, post-reap signals, changing completed schemas without all callers,
unauthenticated nested import/bootstrap inputs, venv/pip platform layout mismatch,
accepting post-install drift and quota amplification. Tests must hit the actual
consumer rather than mock successful guards. Unsupported fixed host/layout fails
clearly; do not weaken Python3.11+ package tests or claim macOS implies Linux proof.

All failed/partial verifier invocations are retained and non-resumable; a new
reviewed invocation is required. No output overwrite/adoption or automatic
resource removal. Document new private runtime/proof contract and every unexecuted
gate in ignored READMEs/coverage/progress, not consumer product docs.

Required sequence: exact plan approval → ignored implementation/pure regressions
→ distinct actual-code/package/finite-runner review → separately approved complete
synthetic/native proof matrix and independent actual-result reconciliation →
first-party acceptance and separately reviewed full isolation/launch contract →
real final freeze/all45 gates/hosted validation → scoped protected delivery/main CI.
Cache retention/hold release, inheritance feasibility and resource archive are
separate gates; this plan changes none of their authority.

Then continue every remaining finding and the mandatory **new full first-pass-style
repository audit**, fix new confirmed blockers through the same workflow, and
produce the complete feature inventory only after a justified READY verdict.
No Store operation, public release, build/background worker, helper/source edit,
native experiment, commit or push occurred in this plan's authoring. Preserve
AGENTS/source/user changes/required evidence and other tasks' resources; stop/join
only owned workers and remove only proven disposable owned outputs after evidence.
