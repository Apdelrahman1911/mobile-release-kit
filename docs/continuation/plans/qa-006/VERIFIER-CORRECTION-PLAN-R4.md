# QA-006 — verifier correction plan R4

**PROPOSED. No implementation or native experiment is authorized until independent
plan approval and the applicable actual-code safety review.** This is a bounded
correction of the ignored verifier, not acceptance of QA-006, remediation of
QA-007, permission for a complete project run, or a product delivery.

## 1. Reanalysis and retained authority

The independent actual-diff review is
`verifier-implementation-review-r3-r3/IMPLEMENTATION-REVIEW.md`, SHA256
`70a175c5278abf2339ad1e3f89937e78cf568e784927ec68c4ad328a1ab46f3d`.
Its decision SHA256 is
`78e8a3ba9df73aa333ba8cc8ad838538852376ed6de950d18b3c653c5de838d0`.
All five findings and VPG-01 through VPG-10 remain requirements, not waivers.

The exact rejected 25-file helper set is retained in
`verifier-implementation-package-r3-r3/current25/`; snapshot SHA256
`ec1804a4c8efe176954a7fe13bbddf3882d098ba703d3182ff0e6a4e4d4c10be`.
The original20/current25 diff and all previous failed runs stay immutable.
Approved R3-R3 requirements continue except for the explicit data-flow and
source-inventory corrections below. No resource ceiling is increased or reset.

Root read the report, raw applicability result, producer/consumer paths in
`bindings`, `frozen_diff`, `owned_outputs`, `action_io`, `native_reader`,
`process_gate`, `git_readonly`, `freeze`, and the final controller. The independent
23 pure controls are retained evidence, not newly repeated product tests.

| Finding | Root cause and concrete correction |
|---|---|
| VRI3R3-01 | The same freeze/creation observation is decoded and validated repeatedly by nested predecessor, worker, and fresh-check calls. Load once per action and pass explicitly validated action-local authority; still independently validate every distinct original, preparation, and freshly produced observation. |
| VRI3R3-02 | Native selected names are the only discovery authority, and final checks only revisit known names. Enumerate source structure and ignore controls independently with no-follow descriptors; run native name selection against an owned data-only mirror; repeat the complete structural/control inventory before publication/deletion. |
| VRI3R3-03 | Some participating operations and native finalization do not latch failures before callers can catch them. Cover all public participating boundaries, including generator entry/exit, while preserving intentional absence queries and mandatory descriptor/child disposition. |
| VRI3R3-04 | Nested scalar/schema semantics are incomplete, and `parse_constant` misses finite-syntax float overflow. Share exact typed validators between producers/consumers and reject nonfinite decoded numbers, including exponent overflow. |
| VRI3R3-05 | Migrated callers retain generic digest roles and numeric queries omit shared launch charges. Assign exact roles at every call and charge each participating query attempt before acquisition. |

Actual-sized evidence is not hypothetical: the retained freeze is535,383 bytes,
creation observation479,368 bytes, seal100,055 bytes, and prepare observation
109,709 bytes. Prepare recorded238,414 JSON tokens; late check exceeded262,144.
The fix must fit **prepare, controller binding, late check, and cleanup**, not
only remove the first observed failure. Current free space was about13.9GB;
remeasure before native proof fixtures and retain at least4GiB free.

Baseline remains toolkit0.3.0, HEAD/main
`2beb37336fa8002b69f598fe431082606368310d`. QA-006 proposed tree
`6009247f3627c9825e9ad9c790a57876e09f3726`:152 first-party files/seven issue paths.
Root QA-003 proposed tree `387856e314cb3475c20509fb70f5a8c3708a87af` and all
174 root/user bindings, both indexes/refs, and user AGENTS remain preserved.

## 2. Exact scope and dependencies

Only ignored helpers under `verification-final-r1/` and new R4 preparation/review
evidence may change. Expected components:

- `bindings.py`, `frozen_diff.py`, `owned_outputs.py`, `freeze.py`,
  `verify-all.py`: explicit shared validated-input data flow and final rechecks.
- `git_readonly.py` plus a small `source_inventory.py`: bounded structural/control
  inventory, owned mirror, native name selection, and mirror readback/cleanup.
- `action_io.py`, `native_reader.py`, `process_gate.py`: complete error latching,
  exact accounting, finite numeric decoding, and unchanged lifetime safeguards.
- A small pure `evidence_schemas.py`, if needed to avoid import cycles: shared
  scalar, owner, action, completion/group, and record schemas. It must be included
  in the exact helper inventory; no dynamic extension/plugin loading.
- `verify-frozen-diff.py`, `verify-process-gate.py`, `verify-result-protocols.py`
  where needed, and new preparation drivers: regression/proof coverage.
- `CONFIG.json` and helper/static-policy bindings: new explicit verifier policy
  version; old snapshots are not silently migrated or accepted as the new version.

Keep all45 final gate identities/order and all13 complete Ruby files. No first-party
file, Gemfile/lockfile, package API, Store/schema/workflow, signing identity, R6
fixture, root AGENTS, source index/ref, or historical evidence is edited. Thin
entrypoints can change only to pass the new explicit action-local authority.

The separate primary signal-fence experiment ran once and awaits independent
results reconciliation. Even a reconciled PASS does not authorize full suites.
This correction needs only existing bounded pure/native-Git/synthetic verifier
proofs, not production native capture or Store/signing operations. The reviewed
proof launch contract must explicitly exclude QA-007-bearing runtime paths.

## 3. VRI3R3-01: one validated authority per actual action

Introduce one explicit action-local loaded-input bundle, created only by a full
`load_frozen` validation for this `ctx` and canonical evidence root. It contains
the retained freeze file binding, exact stable projection/digest, validated
creation observation and the distinct referenced-record bindings. It is not a
global cache, on-disk PASS flag, cross-action token, or unverified digest shortcut.

1. Top-level prepare/check/cleanup/controller-binding loads this authority once.
   `active_ledger`, `predecessor`, `prior_workers`, `load_seal`, and `check_frozen`
   explicitly receive the same action-bound object instead of recursively loading
   the freeze again. Standalone callers create their own fully validated object.
   Reject arbitrary dictionaries, a different ctx/root, and expired/failed contexts.
2. Keep original creation, preparation source, and newly collected observations
   **distinct**. Each is byte-read/validated in its actual role; old observations
   never substitute for the fresh collection appended by this current action.
3. Have `collect` return its already computed canonical stable digest alongside its
   projection and exact fresh reference. Consumers use this immediate result of
   the actual producer, not a supplied hash or a previously accepted invocation.
   Eliminate only duplicate serialization of the identical in-memory projection.
4. Record the bundle's authoritative file references as they are read. Before any
   success/seal/completion publication or destructive operation, re-read those
   exact files using no-follow descriptors and compare identity/bytes/hash. This
   detects replacement after initial validation without decoding unchanged JSON
   repeatedly. No file that influences authority may be omitted from that set.
5. Preserve whole stable equality, pre-native tool/config/helper checks, original
   action cutoffs, actual slot4 parent completion, native readbacks and fresh
   worker requirements. Never use a future wrapper exit as a child prerequisite.
6. No mutable public setter or persistent validated-state adoption. Values remain
   private to the trusted helper call chain; same-action substitution/mutation
   controls must fail before publication. New actions always perform full loading.

The acceptance test records actual cumulative counters for the entire actual-sized
lifecycle. If any stage still exceeds a fixed cap, it remains FAIL; do not reset
the context, enlarge quotas, omit validation, or accept a smaller-only fixture.

## 4. VRI3R3-02: complete discovery without reading private or linked content

Do not fix this by running Git against a possibly changed live `.gitignore` after
a preliminary lstat. That would leave a check/read race. Native name selection
will consume a newly owned **data-only worktree mirror**, not the live source.

### Structural universe and explicit exclusions

Define a versioned, fixed repository-verifier discovery policy, not a new Gitignore
parser. Independently inventory every non-excluded directory entry with no-follow
descriptors and existing name/path/fanout/depth/visited budgets. Record canonical
relative names, kinds, directory identities, and all `.gitignore` file bindings
and tracked status, including self-excluded/otherwise ignored controls. Read no
ordinary unselected file contents during discovery. Reject symlinked/special source
directories, controls, and candidate leaves before native selection.

The only pruned areas are explicitly classified generated/private/tooling regions
already present in this repository's `.gitignore`: Git storage (separately raw
bound), `.mobile-release*` working-state directories named there, Python/test caches,
venv roots, `build`/`dist`, Bundler/vendor outputs, the listed Fastlane outputs,
native package/archive/dSYM outputs, signing/credential suffixes, and
`release/private`. List the exact path/component/suffix rules and reasons in a
bound constant; do not treat an arbitrary new ignore pattern as permission to
prune a source subtree. `.gitignore` itself is never pruned in an inspected
directory. Unknown ignored directories remain inspected or fail the fixed bounds.

Before pruning, prove the complete raw tracked index and accepted source-file
set have no member in a pruned region; otherwise fail applicability clearly,
without reading the excluded contents or dropping tracked source. Include an
explicit test where a tracked file attempts to enter each excluded category.
These are verifier limits for this exact toolkit, not newly claimed product limits.

Generated/private contents may legitimately change during verification; their
entry contents/presence are not added to the stable source universe. Their fixed
classification is bound instead, and existing per-output ownership gates remain
mandatory. Root AGENTS remains separately byte-bound and never a deliverable file.

### Safe native mirror and final comparison

1. Create the mirror inside the current exclusively owned metadata view. Recreate
   only inventoried directory names, empty regular placeholders, and the exact
   descriptor-read `.gitignore` bytes. Never copy ignored ordinary content, real
   Git storage, symlinks, credentials, hooks, or application executables.
2. Bind the mirror inventory and original source-universe/control record into the
   view observation. Native `ls-files` receives the existing copied raw index and
   this owned mirror as worktree; cwd remains outside its worktree. The fixed
   no-hook/no-filter/no-network native policy is otherwise unchanged.
3. Mirror placeholders preserve file-versus-directory semantics; native Git remains
   the authority for actual Gitignore matching. Verify stages/flags as before.
   Compare resulting candidate names with the accepted snapshot before reading
   their real payloads. A new unknown selected file fails before its contents are
   read. Missing/deleted tracked entries retain their explicit deletion contract.
4. Extend exact mirror/view scaffolding, readback, native argv validation and owned
   cleanup expectations. A marker from another source/view or incomplete mirror
   cannot satisfy the observation. Include removed mirror entries in actual cleanup.
5. Before `collect` publishes, and again after later native work before prepare/check
   publication or cleanup, independently repeat the full no-follow structural and
   control inventory and compare it with the initial stable record. Also retain
   all existing source payload/mode and raw Git rechecks. A late new file/directory,
   removed entry, mode/type/control change or replacement fails this action.

This makes selected-file discovery reproducible from bounded owned data, prevents
unbound ignore controls from being read by native Git, and detects additions even
when a new ignore file would hide them. It does not claim an atomic snapshot against
an arbitrary malicious same-user process; cooperative descriptor/identity/content
rechecks and fail/retain on detected drift remain the explicit filesystem model.

## 5. VRI3R3-03 and05: failures and accounting cover actual operations

- Audit every public participating function, not only the reproduced two. Latch
  the first failure before control returns to a caller for open/stat/read/decode,
  iteration, create/write/rename/fsync, close and native finalization. A wrapper
  around a generator's creation is insufficient: cover actual entry/yield/exit.
- A caught failure cannot enable ordinary reads/writes, a new native acquisition,
  success publication, owner adoption or deletion in the same context. Keep the
  first error and separate later close/disposition failures; all known descriptors
  and children must still receive their actual bounded disposition attempts.
- Preserve `exists` as an intentional absence query. Handle allowed ENOENT inside
  its private no-follow query before a participating failure is published. Never
  clear a latched error to emulate optional absence. Other errors remain failures.
- Native selector/pipe close and diagnostic-finalization failures latch immediately
  and keep the real failed completion record. Numeric query acquisition/parsing/
  finalization failure also poisons its supplied context; a valid PARSED query
  reporting LIVE/INDETERMINATE is an observation, not automatically an I/O failure.
- At every digest/read call use the actual source/record/log/tool/object role.
  Repeated source reads count toward payload; nested records retain their narrower
  role cap. No default `other` for known source, log or owner-record paths.
- Each `numeric_snapshot(ctx=...)` charges `launches` **before** attempting Popen,
  including failed acquisitions, and participates in existing same-action worker
  accounting. Preserve its stricter2s/2MiB query limits and5s owned-stop allowance.
  Clearly separate existing controller calls outside any action; do not manufacture
  an action counter for them. Counters never confer signal or cleanup authority.
- Fixed FAIL-only diagnostics may use remaining original time/counters. When
  exhausted, retain the actual failure and available raw evidence; no fresh
  diagnostic budget or false completion. Mandatory close/join is not skipped.

## 6. VRI3R3-04: exact complete schemas and producer relationships

Use small shared pure validators, with named record roles and explicit allowed
variants derived from actual successful producer output. Validate at creation and
consumption; do not infer a complete record from a top-level status or subset test.

Required levels include: freeze/stable/configuration/policy; file references and
role limits; owner/path/identity/ancestry/tree/purpose; source-universe/control and
mirror records; preparation/seal/root-hash/inventory/native rows; action timing,
nonce/name/counters; completed gate/log/protocol/prepared-evidence records; and
complete numeric query/group observations. Unknown/missing fields fail. Successful
variants may not contain failure-only stop/error fields unless the actual accepted
producer explicitly has an innocuous, exactly typed value for that field.

Reject bool in integer/version/PID/counter fields, non-string labels/nonces, malformed
hashes/paths, negative or nonfinite timing, over-limit/unknown counters, partial
root-hash records and status-only group proofs. JSON decoding must reject `1e999`
and `-1e999` as well as NaN/Infinity; finite exponents and legitimate integers remain
supported within the existing lexical bounds. A decoder failure poisons the action.

Check group evidence's actual query result, scope, identities, ordered observations,
typed numeric matches and terminal CLEAR classification; the complete successful
producer shape is required. Do not claim numeric evidence authorizes signaling or
proves escaped/session-changing descendants absent. Check original action deadlines,
work/group allowances, actual gate routing and exact log protocol/count agreement.

Preparation must bind the same action start/cutoff, correctly related native/view
and participating-query counts, exact owner/root objects and original/fresh receipts.
Keep the collection's fresh observation nonce distinct from permanent artifact and
action owner nonces; validate their actual defined relationships instead of forcing
all nonce fields equal. Exact consumer tests must use fresh fully rebound synthetic
references, not mutate historical evidence or stub the dangerous validator.

## 7. Required proof ledger (all old cases preserved)

Create a finite case manifest before native dispatch. Retain the original219
implemented cases and historical25 migration plus5 additions, original10 controller
and24 protocol controls, wrapper-tail/startup/applicability controls, and all existing
real native/reference/cleanup oracles. A failed historical attempt stays failed.

| Gap | New direct tests and required oracle |
|---|---|
| VPG-01 | Tracked/untracked/self-excluded/nested `.gitignore`; excluded subtree classification; tracked-file-in-exclusion rejection; symlinked control/directory/leaf and substitution with a fictional outside canary; changed controls and late selected/ignored file or directory addition/deletion/mode/replacement. Prove no outside bytes are read and mirrors—not live source—reach native selection. |
| VPG-02 | Catch open/stat/read/UTF8/JSON/scandir/create/rename/fsync/close faults inside the same action, then attempt ordinary read/write, a second native launch and removal: all reject before those operations. Normal missing-path queries remain usable. Include final selector/pipe faults, original/secondary error identity, remaining/exhausted diagnostic budget, real child/descriptor disposition. |
| VPG-03 | Actual `check_frozen` rejects independent source bytes/mode/name/control, raw HEAD/ref/index/locator, root/AGENTS, tool bytes/identity/version, helper/config/policy, permanent owner and acceptance/referenced-byte drift. Every changed item is fixture-owned; no real source/tool mutation. Include same-action bundle reuse in wrong ctx/root and mutated/substituted authority. |
| VPG-04 | Original and fresh missing/corrupt/old/copied/wrong-scope/failed/unclean observations, changed stable plus corresponding volatile/reference changes, missing stable fields, permanent nonce substitution. Use actual fresh collection and consumers, not fabricated collect PASS returns. |
| VPG-05 | Table-driven unknown/missing/wrong-type/bool/negative/nonfinite/over-limit cases for every nested role, genuine producer positives, and complete load-seal/predecessor/completion cases with newly rebound synthetic metadata. Include all14 independent defect reproductions as regressions with expected rejection. |
| VPG-06 | Before/after each actual owner creation, object write/readback, observation/seal write/fsync and final publication boundary; post-diff/pre-seal and handler-restoration cancellation; exact existing/partial owner/store/seal/failure collisions. Call real unaffected operations, inject only the named fault; prove fail/no-adoption and preserve exact partial resources. |
| VPG-07 | Real frozen-cleanup consumer with genuine prerequisite/log/group evidence; fail after at least one actual removal, substitute a later owned fixture path, and cancel between removals. Original failure and completed removals remain explicit; all remaining/foreign/neighbor bytes survive and a second invocation refuses adoption. |
| VPG-08 | Simultaneous near-cap stdout/stderr pressure, exact and one-byte-over limits; actual graph name/path/depth/object/reference/aggregate boundary cases; growing files across narrow-role reads; cumulative source payload; query launch cap consumed before acquisition. Real direct-child waits/EOF required, no guessed-PID signals. |
| VPG-09 | Invoke actual pinned Bash `-n` separately for each shell script. Preserve both complete commands/exits; the old two-positional-argument invocation does not count as checking both. |
| VPG-10 | Fresh actual-sized full prepare → actual parent completed binding → late check → guarded cleanup under unchanged counters; complete matrix and all old mapped/integration routes on the exact revised helper set. Retain actual outer/child exits, every raw failed-operation result, counter totals and resource disposition. |

For filesystem failure injection, anchor the named actual operation and its
fixture-owned path; never manufacture a completed child, native status, removal,
EOF, source read, or successful consumer return. A regression envelope may pass
only by observing its exact intended rejection plus required safe disposition.
Its underlying failed-operation evidence stays separate. Store-facing/public
operations are never involved.

## 8. Regression risks, compatibility and recovery

Risks: accidentally treating a reused bundle as cross-action trust; mirror path
semantics differing from real Git selection; exclusions hiding tracked files;
missing late additions; strict schemas rejecting legitimate successful variants;
poisoning intentional absence; swallowing primary errors during required closes;
missing query charges; and reintroducing quotas through larger mirror records.
Each has an explicit direct proof above. Bound helper imports and update exact
helper/argv/observation validators together; no loose field-stripping comparisons.

This changes only unreleased private verifier contracts. Use a new explicit policy
version and new preparation namespace; rejected R3 records remain readable historical
evidence, never accepted R4 freeze/authority. No user/consumer upgrade or Store
reconciliation is needed. A failed/partial verification invocation is not resumed;
retain it and use a newly reviewed fresh invocation after correction. No force push,
main bypass, or temporary CI-branch exception is inferred from this plan.

## 9. Review, execution, cleanup and documentation

1. Obtain independent approval of this exact plan; revise before implementation if
   any source-universe, data-flow, schema, resource or ownership requirement is unsound.
2. Implement only the approved ignored correction; preserve source152/root174,
   both real indexes/refs, user AGENTS and immutable rejected evidence. Safe AST/
   pure checks may run in new owned namespaces; no native experiment by implication.
3. Obtain distinct actual-diff safety review of revised helpers and the finite
   proof runner before new native preparation runs. Existing owned-child/disposition
   rules must remain safe independently of whether a test succeeds.
4. Run the approved preparation matrix once per declared fresh fixture, retain
   actual exits/counters/raw states, and return all results for distinct implementation
   acceptance. Correct/re-review failures; never adopt a partial failed run as a
   final gate pass. Actual-sized applicability and complete required gaps are mandatory.
5. Only after verifier AND first-party acceptance plus an independently approved
   complete isolation/launch contract may real final freeze/all45 gates proceed.
   Hosted Linux/macOS verification, protected delivery and actual main CI remain.
6. Join/stop only actual owned workers and close their descriptors at each completed
   task. Archive required synthetic evidence before removing exclusively owned,
   byte-inventoried disposable outputs. Preserve unresolved states, old failures,
   worktrees/venvs/wheels required for review, shared caches and other-task resources.
   Do not bulk-delete the16 historical proof roots/53 fixture venvs. A separate
   evidence-preserving ownership-checked disposition is needed after their review.

Update new ignored implementation/proof/coverage/resource records and current
progress pointers; preserve checkpoint history. No consumer documentation changes
are justified for private verifier-only behavior. QA-006, QA-007, QA-003–005,
MRK-008/009, the mandatory **new whole-repository audit and further remediation**,
and the comprehensive feature report remain outstanding until separately completed.

**Authoring outcome:** proposal only; no helper/source modification, test/native
launch, Store action, commit or push. No author-owned build/background worker remains.
