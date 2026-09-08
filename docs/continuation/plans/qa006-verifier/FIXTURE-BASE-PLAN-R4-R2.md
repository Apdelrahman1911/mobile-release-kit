# QA-006 verifier — proposed fixture-base bootstrap amendment R4-R2

**PROPOSED; NOT APPROVED FOR IMPLEMENTATION OR EXECUTION.** This revision replaces
only rejected `FIXTURE-BASE-PLAN-R4-R1.md`; it retains approved R4-R4/R4-R3 and all
their unfulfilled actual-code/proof/final gates. It addresses independent review
`VFBP-R1-01` without changing product files, source-cache disposition, Store state,
Git, original fixtures, rejected packages, prior evidence or another task's work.

## 1. Reanalysis, exact scope and original review

R1 correctly identified a second newly produced runtime: `Proofs.full_fixture()`
creates `owner/venv` with `-m venv`/default ensurepip, then executes its Python to
collect tools. The default creation can consume unbound venv bytecode and execute
the newly seeded target before complete startup validation. It is not the later
wheel-smoke target. The rejected package path is
`verifier-implementation-package-r4-r2/current28/verify-frozen-diff.py:503-505`;
stable R1 code snapshot has the corresponding setup at
`current29/verify-frozen-diff.py:591-593`. No native reproduction was attempted here.

R1's seed-only authority was insufficient. The mandatory genuine cleanup route
(`current29/verify-frozen-diff.py:1210-1218`) runs editable pip into **this same**
base. Its source-owned output receipt currently covers only build/egg-info
(`owned_outputs.py:288-319,380-449`); it does not authorize installed pth, console,
data and distribution files. The next frozen input guard would correctly reject
them. Adopting the changed bytes, broadening an exclusion or rewriting a freeze
would instead recreate the trust gap. This is the confirmed plan omission, not a
new production Store finding.

Independent R1 review is preserved unchanged:

- `verifier-fixture-base-plan-review-r1/PLAN-REVIEW.md`, SHA256
  `26fae4545688aaaf43e284264242071366e745f524dce708b9c07659fb995f15`.
- `verifier-fixture-base-plan-review-r1/DECISION.json`, SHA256
  `90773f468b0550872476a52e6a2b7b0d7162a71dfdc1b4e5ffb956601e38c650`.
- R1 plan SHA256 `7c64960127fe62b97e2a59897b8e7b1522b7dd4267b620560bfcad410df08871`
  and snapshot BINDINGS SHA256
  `450dc9ce04f4775495e235ad99c708a7fd8e313156a04b350932dee4cb8cb6f8`.

The R2 review snapshot separately reconciles seven already-present helper/driver
draft changes since the R1 snapshot; both old/new exact inputs are retained.
`DRAFT-RECONCILIATION-R2.md` records their hashes, semantics and static authoring
failures. These are still unreviewed drafts, not implementation of this amendment.

The correction is one concrete design: authentic minimal creation, exact pinned
two-wheel seed, then an explicitly predeclared, single genuine editable successor
validated by the still-trusted original parent. There is no separate editable
target, no skipped/mock installer and no expanded pre-existing-runner TCB.

## 2. Independently inspected inputs, not implementation-derived expectations

Use the original selected/effective Python binary reference, the R4-R4 bound
`venv/__init__.py`/four activation templates, and only these existing seed wheels:

| Named wheel | Bytes | SHA256 |
| --- | ---: | --- |
| `pip-24.0-py3-none-any.whl` | 2,110,226 | `ba0d021a166865d2265246961bec0152ff124de910c5cc39f1156ce3fa7c69dc` |
| `setuptools-79.0.1-py3-none-any.whl` | 1,256,281 | `e147c0549f27767ba362f9da434eab9c5dc0045d5304feb602a0af001089fc51` |

Both are at the exact original MRK-002 runtime
`lib/python3.11/ensurepip/_bundled/` paths already bound in the original finite
prerequisites. Do not discover substitutes by installed versions or download.

File-only no-follow inspection checked their complete original identity/size/hash,
all 1,038 safe unique case-fold-distinct member names, central-directory sizes and
top-level RECORD entries. It retained 70 unique explicitly selected textual source
and metadata members (76 copies because RECORD was repeated), never imported or
executed them. It did not extract/install either archive. Exact references and
which other members remain semantically unread are in these new static ledgers:

- `fixture-base-member-inspection-r2/BINDINGS.json`, SHA256
  `0a733bf2f86a1c26d00b7a1b82231233bd9b16017a4df10a478ec0762ce810f8`.
- `fixture-base-member-inspection-r2-supplement/BINDINGS.json`, SHA256
  `9d77c9752bed1e0e532b3e8ff5a4678ea5ed39a9345a619bdc42fcadaf69aec0`.
- `fixture-base-member-inspection-r2-final/BINDINGS.json`, SHA256
  `f18d0e396e79f07c66e42118ce8ea8a5d6d8ac7c7450547f5be8214b6c072054`.
- `fixture-base-member-inspection-r2-hooks/BINDINGS.json`, SHA256
  `f8032b8138e278a0bcff3f6c077c2d13b48562acfeac15c3b8d5f46174dd93e6`.

`FIXTURE-BASE-MEMBER-REVIEW-R2.md` gives semantic ranges, actual conclusions and
remaining uncertainty. Crucially, pinned setuptools selects `_StaticPth` for the
fixed src-layout; installs configured Gemfile data non-editably; emits Metadata
2.4 and `Dynamic: license-file`; and has no top-level console entry points of its
own. Pip24 expands its wheel's pip3.10 entry point to actual pip3.11. Its backend
hook environment uses **`PEP517_BUILD_BACKEND`**, not newer guessed spellings.

The implementation must independently derive expected payload from original
bound source/backend/installer inputs. Never derive the expected hash from the
new runtime, newly generated wheel or its self-supplied RECORD. Bound third-party
members are inputs to a strict small renderer, not code imported to manufacture
the expected answer. Extra uninspected emitter/layout requirements are a hold for
further named file-only inspection/review, not permission for a fallback.

## 3. Immutable fixture request and authority states

Create exclusive `FIXTURE-BASE-REQUEST.json` under the actual newly owned case.
It binds case/parent nonce and directory ancestry, exact original parent selected
Python/effective binary, source/templates/seed references, absent `owner/venv`,
fixed creation/seed argv and environments, umask077, original source directory and
logical/physical source identities, fixed policy/schema and allowed successors.
The actual parent retains its byte reference before any producer acquisition.

The request permits editable transition only when the actual fixture creator
selects the exact built-in `SYNTHETIC_PACKAGE` file set, all bytes equal the bound
driver literal, and the later frozen route contains the exact declared editable
gate/backend/source/argv. The request records this fixed twelve-file delta policy
and expected source root **before** creation. Other fixtures, including cloned
actual-source applicability fixtures, have no editable successor. A scope string,
test-mode boolean, current path contents or caller-provided filename cannot grant
this authority. Subsequent source freeze binds this original request; no phase
may rewrite that request or original completed seed record.

`WHEEL-BOOTSTRAP.json` gains a strict tagged base-authority union. The unchanged
reviewed-pre-existing-base variant keeps its original runner selection/config/
binary anchors. The produced-fixture variant instead requires the original
fixture request and completed seed references, compact namespace reference and
predeclared editable policy. The frozen stable projection holds those immutable
anchors, **not** a mutable current-state flag. A produced target cannot be changed
to the pre-existing variant: request/owner/original parent/selected effective
Python and original finite fixture classification must all agree before any
member/path selector is followed. `tool_bindings` calls this validator before its
first Python probe; ordinary bootstrap/input/frozen checks consume it thereafter.

State machine (failure/cancellation in any transition is terminal retain/block):

```text
ABSENT -- original request --> CREATING
CREATING -- actual base completion + exact minimal validation --> MINIMAL
MINIMAL -- exact base-pip/target seed --> SEEDING
SEEDING -- actual parent completion + exact whole seed --> SEEDED
SEEDED -- permitted original-request-bound actual gate --> EDITABLE_PENDING
EDITABLE_PENDING -- actual completion + full independent successor + joint
                    receipt readback + original parent ledger save --> EDITABLE
SEEDED or EDITABLE -- immutable rechecks --> later declared consumers
```

No state is selected from whichever receipt/name happens to exist. A produced
base stays the produced-base authority type for its entire life. Missing,
partial, failed, cancelled or wrongly scoped proof never falls back to the
reviewed-pre-existing-runner variant. Valid EDITABLE reuse by later wheel/testing/
observer/cleanup consumers is allowed; a second editable installation or reversal
to SEEDED is not. The original request, seed and source freeze remain immutable.

## 4. Minimal creation and exact two-wheel seed (R1 protections retained)

1. Replace default `-m venv` with the fixed source-only proof-driver entry:
   `[BOUND_BASE, -I, -B, -S, BOUND_VERIFY_FROZEN_DIFF, --fixture-base-source,
   REQUEST_PATH, ORIGINAL_REQUEST_SHA256]`. Validate actual argv/environment,
   request/owner/type/absent target and selected interpreter first. Admit the
   copied helper namespace before any sibling import. This entry only creates
   this declared proof base, never arbitrary modules/commands/plugins.
2. Read/hash the no-follow bound venv source and compile those **same bytes** into
   a fresh non-colliding module with genuine interpreter metadata. Use fixed
   R4-R4 POSIX `EnvBuilder` options and `with_pip=False`; no `import venv`, cached
   loader, ensurepip or target execution. Recheck templates and aliases.
3. The genuine observing parent must receive successful exit/reap/EOF and valid
   original native accounting, then independently verify every minimal directory,
   activation/config byte, alias target/mode and preserved identity. Informational
   `pyvenv.cfg command` differs from actual source-only invocation. Copied-exe
   fallback rejects. Persist exclusive minimal completion/readback, not a child's
   claim to its own future parent completion.
4. Recheck complete minimal runtime and exact inputs immediately before:

   ```text
   BASE -I -B -S BOUND_PIP_WHEEL/pip --isolated --disable-pip-version-check
     --no-input --no-cache-dir --python TARGET/bin/python install
     --no-index --no-deps --no-compile BOUND_PIP_WHEEL BOUND_SETUPTOOLS_WHEEL
   ```

   Pip24 redispatch is `[TARGET/bin/python, BOUND_PIP_WHEEL/pip, *same_pip_args]`,
   including `--python`; no base Python flags are forwarded. Only the real pinned
   parent introduces `_PIP_RUNNING_IN_SUBPROCESS=1`. Retain actual parent
   accounting and pinned synchronous target semantics, not invented target
   PID/exit observations.
5. After successful parent completion, independently derive the full two-wheel
   installer delta from original archive references/top RECORD/name/size/mode
   metadata and pinned install policy; verify all actual file payloads against it.
   Preserve minimal entries and identities. Both exact wheels have no `.data`
   members; there are no unknown installer layouts. Include exact installed
   RECORD, direct_url, INSTALLER/REQUESTED and pip/pip3/pip3.11 launchers.
   Permit only the exact bound `distutils-precedence.pth` and every bound package/
   resource/vendor file. No name-only pth allowance, customizer, cache, pyc, extra
   module, copied interpreter, alias/config replacement or unknown metadata.
6. Persist exclusive `FIXTURE-BASE-COMPLETE.json` plus separately referenced
   compact namespace observation only after full validation and backing/owner/
   descriptor rechecks/readback. It binds original request, minimal predecessor,
   both real parent producer records and exact output observation. Only then
   write fixture CONFIG/acceptance and perform actual tool probes.

Both creation/seed operations use complete literal clean environments with
case-owned HOME/TMPDIR/TMP/TEMP, fixed PATH/locale and R4-R4 no-bytecode/safe-path/
no-user-site flags, unbuffered output and `PIP_CONFIG_FILE=/dev/null`. No ambient
Python/pip/config/proxy/loader/credential settings, incoming marker or
`ENSUREPIP_OPTIONS`. Umask077 is scoped and restored. Do not copy/alter trusted
runner installations. Static source derivation predicts 1,052 regular files and
142 directories excluding root, plus pinned platform aliases, for seeded base;
these counts are not a native creation/installation pass.

## 5. Exact editable contract and independently expected delta

Keep a real pinned offline PEP660 editable installation into the same base. The
declared fixture route remains prepare -> editable -> wheel -> cleanup. Strengthen
only this copied fixture's exact editable argv with pip's existing isolation/
no-network/no-cache policy (synchronize route/schema/attempt expectations):

```text
TARGET/bin/python -I -B -u -m pip --isolated --disable-pip-version-check
  --no-input --no-cache-dir install --no-deps --no-index --no-compile
  --no-build-isolation -e EXACT_FROZEN_SOURCE
```

The original parent passes a complete literal environment from the fixture
request: private case HOME and TMP*, fixed PATH including the exact target bin,
fixed locale, no-bytecode/safe-path/no-user-site/unbuffered flags and
`PIP_CONFIG_FILE=/dev/null`. No unapproved ambient keys, index/config settings,
editable-mode options, build options, source paths or backend-path overrides.
This is an explicit command environment, not a mutation of frozen outer CONFIG
or ambient HOME. The old/new route and original actual producer row must all
agree. The attempt/joint receipt bind the complete original parent dispatch
environment: a retained copy of the exact dictionary actually passed to the
collector, not a child-reported environment. Current generic collector rows have
argv/cwd, not an environment field; do not misdescribe their evidence or change
every generic gate schema to imply an independent child-environment observation.
The specialized parent dispatch validates and passes this exact declaration;
regression capture must assert the actual Popen kwargs.

Pinned pip with no build isolation uses `NoOpBuildEnvironment`; real PEP517 hook
children inherit these protections and add only the actual known backend input
`PEP517_BUILD_BACKEND=setuptools.build_meta`, `PIP_NO_INPUT=1` from the actual
`--no-input` handling, and `PIP_BUILD_TRACKER` naming that pip operation's newly
created `pip-build-tracker-*` directory under the original private TMP. Its random
leaf is produced bookkeeping, never a caller-supplied arbitrary path or separate
authority. `PEP517_BACKEND_PATH`, `PIP_EXISTS_ACTION` and the incoming/redispatch
marker are absent for this direct editable invocation.
Their literal argv is target Python, the bound installed pip in-process script,
the finite required hook name, and its exclusively owned temporary control dir.
No `-I/-B` inheritance is falsely asserted. Required feature/metadata/build hooks
wait synchronously **before** pip installs the completed wheel; no helper process
is started against partially mutated target startup. Final review/proofs must
verify this exact pinned environment transition, never allow arbitrary additional
keys or substitute fabricated child completions. The parent
observes the real outer pipe/exit/group; individual pip-internal PIDs are not
claimed unless separately genuinely observed.

For exactly `SYNTHETIC_PACKAGE`, expected new regular files are these **12**:

| Path relative to target | Exact independent content rule |
| --- | --- |
| `lib/python3.11/site-packages/__editable__.mobile_release_kit-0.3.0.pth` | Canonical original SOURCE + `/src\n`, exact locale-encoded bytes. Fixed fixture owner/source path must be ASCII for this proof policy; unsupported paths reject before dispatch. |
| `bin/mobile-release` | Pinned pip24/distlib console template for `mobile_release.cli:main`, exact target shebang or pinned long-path POSIX wrapper, mode0755. |
| `share/mobile-release-kit/Gemfile` | Exact original bound synthetic `Gemfile`, mode0600. |
| `lib/python3.11/site-packages/mobile_release_kit-0.3.0.dist-info/METADATA` | Independently serialized fixed Metadata2.4 below; never copied as expectation from emitted egg-info. |
| same dist-info `/WHEEL` | Exact setuptools79.0.1 purelib py3-none-any message, no build tag line. |
| same dist-info `/entry_points.txt` | `[console_scripts]\nmobile-release = mobile_release.cli:main\n`. |
| same dist-info `/top_level.txt` | `mobile_release\n`. |
| same dist-info `/licenses/LICENSE` | Exact original bound synthetic LICENSE. |
| same dist-info `/INSTALLER` | `pip\n`. |
| same dist-info `/REQUESTED` | Empty. |
| same dist-info `/direct_url.json` | Pinned sorted-key JSON bytes for `{"dir_info":{"editable":true},"url":SOURCE_FILE_URI}` with pip's exact default spacing and no trailing newline. |
| same dist-info `/RECORD` | Independently derived sorted CSV/CRLF rows for these exact twelve installed files; original RECORD self row has empty digest/size, all other rows exact SHA256/size, with only prescribed `../../../bin` and `../../../share` relative mappings. |

All regular delta files except the console are mode0600 under umask077. Add only
four mode0700 directories: `share`, `share/mobile-release-kit`, project dist-info
and its `licenses`. Preserve identities of every pre-existing seed/minimal entry.
There is **no** installed `mobile_release/` copy, finder module, namespace-package
pth, editable link-tree, egg-link, easy-install.pth, pyc or source symlink.

Expected METADATA, with LF endings and the exact original README appended after
one empty line:

```text
Metadata-Version: 2.4
Name: mobile-release-kit
Version: 0.3.0
Summary: Synthetic R4-R2 verifier producer, not first-party toolkit
License-Expression: MIT
Requires-Python: >=3.11
Description-Content-Type: text/markdown
License-File: LICENSE
Provides-Extra: test
Requires-Dist: packaging==24.2; extra == "test"
Requires-Dist: typing-extensions==4.16.0; python_version < "3.13" and extra == "test"
Dynamic: license-file

# Synthetic verifier producer
Not the Mobile Release Kit implementation.
```

The extra-dependency declarations remain metadata only; `--no-deps` must not
install them into this base. Full source discovery/physical freeze proves the
canonical mapped source is still present and unchanged before **every** later
startup. A pathname alone does not authorize what Python can import through pth.

### Source-owned outputs are a different transition

For the exact pinned PEP660 route, do not assume editable also populated the
source-owned `build/` and `src/mobile_release_kit.egg-info/` roots. Pinned
`build_meta.prepare_metadata_for_build_wheel` directs egg/dist-info to pip's
temporary metadata dir; editable `_configure_build` redirects its egg-info to
temporary build space; `build_py.run` returns in editable mode. The independently
derived expectation for this fixed synthetic route is that the previously owned
source build/egg-info roots stay **empty**, with their original identities. These
are source-inspection conclusions, not an observed installer pass.

Require exactly that empty projection in this transition's joint receipt and
actual descriptor inventory, not the present unconditional six-file
`egg_info_entries` assertion. This allowance is not a generic `allow_empty`
escape hatch: it is accessible only through the authenticated fixed-source/
backend/editable transition and requires exact absence of every payload. An
unexpected file or a failed installer rejects. The later genuine **noneditable
wheel-build** stage is separately responsible for populating/validating its
full build and six-file egg-info outputs; retain its original strict validation,
actual completed producer and exact editable predecessor. Never backfill them
or fake an egg-info writer to make the editable test pass. Independently review
this pinned source-output derivation and demonstrate it in the genuine native
lifecycle before acceptance; if actual outputs differ, preserve the failed case
and re-analyze rather than accepting both namespaces opportunistically.

## 6. Trusted-parent transition and load_frozen ordering

Avoid seed-only deadlock without a generic bypass:

1. After the real controller saves editable gate RUNNING, use **one active original
   transition action** spanning prelaunch, actual child collection, output/runtime
   validation, joint completion and parent ledger persistence. It replaces, not
   adds fresh budgets to, this fixture gate's separate prelaunch/completion
   scopes. Load/register the original FrozenAuthority once while the runtime is
   still SEEDED; pass that same instance to guards and consumers. The observing
   parent is the original bound proof-driver interpreter, never the newly mutated
   target. Check the actual parent identity against original request before use.
2. Require actual earlier prepare gate PASS, all later gates BLOCKED, fixed route,
   no prior editable attempt/receipt, seed completion and original owned build/
   egg-info roots. Compute the independent successor description and validate
   the whole seeded runtime and mapped source immediately before acquisition.
   Exclusively publish `FIXTURE-EDITABLE-ATTEMPT.json` binding original request,
   seed completion/namespace, source freeze/tree/files, prepare completion,
   backend/installer refs, argv/environment/umask, active gate/route, source/output
   owners, actual parent/action nonce, absent delta and original pending ledger.
3. Mint an opaque action-local `FixtureEditableTransition` capability only from
   that genuine prelaunch. It is registered by identity against this same context/
   FrozenAuthority and becomes invalid on closure/failure/cancellation. It cannot
   be reconstructed from JSON, transferred from a closed action, used to spawn
   additional work, authorize cleanup or claim completion. Its only post-child
   consumer is the parent's joint `bind_output_completion` path. A generic
   `load_frozen`, prelaunch guard or bootstrap check during EDITABLE_PENDING fails;
   there is no `skip_runtime`, `test_mode` or arbitrary expected-state argument.
4. Dispatch the exact real editable gate through the actual collector, with the
   original remaining action budget and at most30s native work. Immediately
   retain the real row, including acquisition/PID/reap/group/EOF, output byte/hash/
   fsync/disposal and error facts. Failed protocol/exit/cancellation/UNKNOWN is
   terminal; it never authorizes a transition. No new target process or ordinary
   helper guard is invoked after mutation before successor validation.
5. Pass the same live original authority and opaque capability to
   `bind_output_completion`. Do **not** call `load_frozen` against changed startup
   or reload it into a second action. Split original bootstrap **immutable input**
   checks from effective-runtime checks internally: the capability permits only
   descriptor/source/request/predecessor rechecks plus this independently known
   namespace validation, not a generally usable FrozenAuthority. Recheck all
   original references and retained minimal/seed identities, then require complete
   exact successor files/bytes/modes and mapped source. Validate current owned
   build/egg-info against the exact phase-specific projection in section5 with
   unchanged genuine producer/owner rules and immutable source
   discovery/raw Git guards. This narrow in-progress path is inaccessible from
   ordinary load/launch/readback callers.
6. Jointly construct the existing `EDITABLE-COMPLETE.json`, with a strictly typed
   produced-fixture-only `fixtureRuntime` block. It contains the original base
   request/seed predecessor, exact attempt, independent expected-delta policy/
   input references, full observed successor identity binding and the **same**
   actual parent producer row as the source-owned output completion. Original
   `predecessorEvidence` stays the authentic prepare completion. There is no pair
   of mutually authorizing independently published success receipts and no
   circular self-hash. A separate compact observed-namespace file, if needed,
   is input to this joint receipt, not success authority by itself.
7. Publish exclusively only after every validation, original-input/owner/FD/path
   recheck and successful actual completion. Read back exact receipt bytes. Save
   the original parent ledger PASS row containing its exact `outputEvidence`
   reference only afterward, within the same unreset action and cancellation
   checks. Missing/write/close/fsync/readback/ledger-save failure leaves runtime
   unauthorized and later acquisition blocked, even if a success-shaped partial
   file exists. No delete, overwrite, retry or output adoption repairs it.
8. Later ordinary `load_frozen` authenticates the original immutable source/
   bootstrap/request/seed anchors first, then validates the complete actual
   ledger -> original joint editable receipt -> actual producer/attempt/prepare/
   seed chain. Only that valid original-request-permitted transition chooses the
   independently expected EDITABLE namespace. Load original records once per
   action and register backing refs with exact roles; no circular call back into
   load/guard/collect from runtime-chain validation. Fully recheck current startup
   and mapped source before tool probes or other native use. Mutable completion
   observations are not inserted into, or used to rewrite, stable source/freeze
   equality.

Implement the chain verifier as bounded descriptor-only validation of the fixed
finite predecessor graph. It must not call current `execution_outputs` as a way
to recursively select base state or take a future gate PASS as proof of itself.
An authentic joint receipt is necessary but not sufficient: independently exact
runtime/source validation is required on each consumption.

## 7. Lifetime, cleanup, compatibility and failure/recovery

Produced fixture bases are retained for their whole proof-case lifetime. Tool
probes, actual controllers, real wheel producers, observers, late checks and
cleanup entry points must consume SEEDED or authenticated EDITABLE as appropriate.
Wheel creation/installation uses its **separate** guarded target; it cannot replace
the editable base. The genuine tiny fixture retains actual installed-wheel imports
and console/backend coverage rather than replacing them with no-op success.

Wheel build legitimately changes source-owned build/egg-info after editable;
successful build cleanup removes them. The historical editable receipt must
therefore validate its original producer/owners/expected bytes as evidence, not
require its old source output inventory still to exist. Current source-output
validation follows its existing actual later producer/cleanup lifecycle. It must
still preserve the mapped immutable SOURCE/src and complete base runtime. Do not
make future cleanup fail on an obsolete egg-info snapshot or weaken source-output
guards to avoid that failure. No cleanup here retires the fixture base or source.

Unknown/malformed/changed pth/finder/module/cache/metadata, wrong source mapping,
seed replacement, alias/config drift, wrong case/nonce/policy/owner/predecessor,
forged/incomplete receipt, unexpected native child, lost EOF, collection errors,
quota/deadline/disk exhaustion and interrupted publication all retain the output
and block later use. A second attempt cannot adopt or uninstall a partially
installed runtime, reseed it, overwrite any evidence, revert its authority type
or rewrite the stable freeze. A fresh independently reviewed case is the only
retry. Legitimate later use of a successfully authenticated original successor is
not replay and does not repeat editable installation.

This is ignored verifier-fixture behavior only: no product schema/API, toolkit
dependency, consumer package/version, release lifecycle or Store mutation changes.
Only the fixed CPython3.11 POSIX/seeded synthetic layout is supported. Different
editable strategy/backend/source layout fails clearly rather than being blessed.
Original two source caches and all historical53 fixture-venv payloads are not
inputs, are not read/traversed and gain no disposition authority.

## 8. Budgets and representation

Original LIMITS/ROLES remain unchanged: action120s, per-native30s, active-native1,
all existing graph/object/name/JSON/payload/tool/output counts, finite outer900s,
4GiB floor and512MiB admission headroom. Creation and seed share the original
fixture setup action/counters; observation/publication do not renew that action.
Native-reader stdout/stderr caps stay their original2MiB/256KiB where used;
the streamed gate collector stays original64MiB combined cap. Do not silently
substitute the latter for a smaller setup cap. Actual parent graph, internal
backend descendants, output and disposal remain accounted by their original
owning mechanisms, not by resetting a timeout around each validation phase.

Keep stable bindings compact: original reference + immutable transition policy,
not repeated embedding of the entire 1,038-member input and three full runtime
maps. Persist compact fixed-order namespace identity observations separately
under existing record/JSON limits. Compute their content expectations from the
original wheel/metadata inputs, not observation values. Decode each distinct
original record once per action, reuse the immutable decoded representation,
recheck backing bytes on subsequent use, and freshly inspect namespace/payloads
at every actual consumption. No cached successful filesystem observation across
a producer or later launch, no file-role reclassification, and no quota bypass.

Genuine seeded-plus-editable full lifecycle feasibility under original limits is
**UNVERIFIED**, not inferred from these static counts. If it fails a quota, retain
that real failure, fix bounded duplicate work under the same policy, obtain any
required review and rerun only with separate authorization. Never raise limits or
claim the old218PASS/1FAIL/exit1 has disappeared.

## 9. Files/callers and regression obligations

Scoped implementation will touch only existing ignored helpers and copied proof
drivers/static bindings: `verify-frozen-diff.py` (fixed entry/request/setup/real
route), `verify-all.py` (single live trusted-parent transition), `owned_outputs.py`
(derived runtime/joint output binding), `bindings.py` (typed bootstrap/loader/
effective-state ordering), `evidence_schemas.py` (strict variant/receipt/attempt),
and relevant copied freezer/finite/case-regression drivers. Reconcile
`frozen_diff._inputs_unchanged`, tool_bindings, observer, mapped/VPG/integration
callers and generated tiny producer. No broad alternate test implementation of
the real guard. Update ignored coverage/README and complete frozen review package.

Preserve original103+62 pure,219 original,30 mapped,5 integration,143 VPG
(69 schema/67 preparation),25 historical mappings,10 controller,24 protocol,
all45 real gates/order,13 Ruby files and **two separate Bash syntax commands**.
All earlier failed/quota/partial evidence stays intact.

Add a finite named manifest covering at least:

1. Source-only minimal setup with harmless conflicting valid timestamp/hash pyc;
   no cache-payload consumption; actual argv/env/metadata/alias/template/source
   changes, module collisions and copied-exe fallback reject.
2. Complete two-wheel independent seed map/RECORD/scripts/pth, exact pip24
   parent/target marker/argv/env contract, poisoned ambient variables/config,
   missing/changed/extra package/startup/metadata/cache and wrong source input.
3. Real SEEDED -> original guarded probe -> genuine editable installer -> whole
   independent twelve-file/four-directory validation -> next actual target probe
   -> genuine wheel/controller/observer/late-check/cleanup successes. Preserve all
   original successful prefixes and validate installed import/backend/console,
   not just a version. Future approved native runs supply the actual evidence.
4. Independent fixed expected METADATA/pth/console/direct_url/RECORD/data fixtures
   and negatives mutating each. Expected bytes must come from this inspected
   source contract, never the output under test or the renderer being asserted.
5. Actual ordinary load/guard/bootstrap/tool consumers reject unknown pth/finder,
   wrong source mapping, extra package/customizer/cache/dist-info, changed seed,
   symlink/replacement/mode/link/config, unknown layouts and source-cache additions
   before the next real acquisition. Catching an early setup failure is not a
   substitute for reaching the intended later dangerous consumer.
6. Original-request/policy/owner/nonce/attempt/producer/active gate/route/argv/env/
   predecessor/log/output/receipt/freeze substitution or omission; no boolean tag,
   JSON lookalike capability, closed action, future PASS, seed-only fallback,
   repeated attempt or forged completion can authorize use. Same-action authority
   remains unique and backing references are rechecked.
7. Acquisition/poll/exit/EOF/group uncertainty, partial mutation, cancellation at
   each boundary, read/write/digest/fsync/close/disposal/readback/publication and
   ledger-save failure. Assert truthful actual accounting, retained partial data,
   zero subsequent acquisition, no substituted PASS/cleanup and no auto retry.
8. Valid later EDITABLE reuse; build/egg-info changed by wheel producer and removed
   by successful cleanup; specifically assert the real editable phase's empty
   owned roots and later wheel stage's full independently validated output.
   Historical evidence remains valid without requiring
   deleted generated bytes. Base pth/source/seed/runtime still protected. Original
   cleanup-negative assertions must first show genuine earlier producer PASS and
   reject only at their intended consumer.
9. Actual-sized original lifecycle, repeated guards, compact original-record
   deduplication, strict role/count/deadline bounds and disk admission. Pure/static
   or fictional-interface tests never stand in for genuine producer/provenance/
   process cleanup tests.

## 10. Approval sequence and honest limitations

Obtain a distinct independent review of **this R2 plan and bound member evidence**
before implementing the extra fixture bootstrap/editable amendment. Complete
implementation under unchanged guards, freeze all actual helper/driver/static
inputs/diffs, and obtain the separately appointed distinct actual-code review.
Only afterward may root authorize exact finite native proofs with original
prerequisites; final45/full repository verification and final acceptance remain
separate gates. This plan/its static utilities grant none of those authorities.

Separate cross-caller uncertainty: the same pinned backend's temporary metadata
behavior may also contradict the generic, non-fixture final editable gate's
unconditional six-file source egg-info assertion. This amendment does not claim
that generic contract is correct or authorize weakening it. Reconcile that actual
source/backend/caller path separately before actual/final acceptance; any required
broader correction needs its own approved plan and regression evidence.

Behavioral/native/installer test attempts in this plan revision: **0**. Static
authoring/inspection does not prove CPython's actual generated modes/aliases, pip's
actual installed namespace, cancellation/disposition, runtime quota fit, protected
CI compatibility or production readiness. These remain explicit later proof
obligations. No builds/background workers were started and no resource needs to
be stopped/deleted from this plan task. Source, original caches, historical
archives/fixtures and all partial evidence remain preserved. Final fresh full
repository audit/remediation and conditional complete feature report are still
mandatory; QA-006 is not delivered and the project is NOT READY.
