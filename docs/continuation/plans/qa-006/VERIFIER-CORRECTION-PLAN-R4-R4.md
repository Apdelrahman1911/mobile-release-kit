# QA-006 verifier R4-R4 — source-only venv and exact pip dispatch amendment

**PROPOSED ONLY.** This amends, but does not replace, the complete R4-R3 plan.
Obtain independent review before verifier implementation. Native execution,
source-cache access/disposition, final-suite authority and delivery remain separate
gates. No product source or active verifier helper is changed by this plan.

## Reanalysis and unchanged obligations

Read the complete independent R4-R3 rejection and its selected pinned-tool source
analysis. The rejected plan SHA256 is
`504ff1531fa246c44489efbd17ddf06e942a3a45d47c24a3c73f3265f5c2bbca`;
review SHA256 `7375d76f4c57fcac6b808fb022023e4445e908124a19e98259b0d320228a4c85`;
decision SHA256 `73ee54532e32a228557eb045fa71b4bf1aee62bc85ad0da4ad967e741993be66`.
Preserve them and the original actual-code rejection unchanged.

- **VRP4R3-01:** the proposed `-I -B -S -m venv` does not consume the newly
  authenticated venv source. Existing import bytecode can substitute for it;
  none of those flags forbids that lookup. Later target inspection cannot
  retroactively authenticate code already executed.
- **VRP4R3-02:** pinned pip24 redispatches to the target without the base
  interpreter flags. It reads configuration before redispatch. Abstract
  promises of isolation must become exact parent/target argv and environment
  contracts, including the configuration-file disable switch.

These are supporting helper/plan defects, not newly delivered product findings.
Do not broaden the cached-venv trusted boundary to avoid either correction.
Retain the complete original observer/streamed-output/source-only helper fixes,
minimal pip-free target, receipts/guards, all45 gates, all old/new proof matrices,
failure history, exact original limits and explicit native prerequisites.

## VRP4R3-01 — one authenticated source-only venv producer

Replace R4-R3's step1 `-m venv` command with one fixed reviewed source-bootstrap
entry in the already bound verifier code set. Use a definition-only callable
in the existing `owned_outputs.py`, dispatched through its existing bound CLI
with a new fixed `produce-venv` action, rather than inventing another launcher.
Its actual launcher, entrypoint cache-free bootstrap, callable and fixed dispatch
schema are all in accepted code bindings and final rechecks. There is no arbitrary
module/path, consumer command string, import-loader choice or test-mode permit.

1. The parent verifies the original WHEEL-OWNER, active action/gate, absent target,
   exact base interpreter/argv, and WHEEL-BOOTSTRAP and frozen authority before
   acquisition. Persist exclusive attempt ownership first. Use the bound base
   interpreter as `[BASE, -I, -B, -S, EVIDENCE/owned_outputs.py, produce-venv]`
   to invoke the fixed source-only entrypoint; every element is a literal or
   an exact validated bound path, not a shell expression.
   The entrypoint's own sibling imports retain R4-R3's source-byte/namespace
   protection; adding this bootstrap cannot reintroduce cached helper execution.
2. Inside that same base process, no-follow read the exact fixed named
   `venv/__init__.py` reference under its retained parent identities. Validate
   metadata, bounded length/hash, EOF and before/after name/fd stability. Compile
   **those already authenticated bytes** once into a fresh definition-only
   module namespace. Do not use `import venv`, `-m venv`, SourceFileLoader,
   `runpy`, or a second cache-capable source reopen. Reject a preexisting module
   collision rather than adopting it. The stdlib imports made by this pinned
   source remain the existing trusted base runtime; no claim is made to attest
   the entire standard library. They do not supply venv's own executable body.
3. Preserve real `sys.executable`, `sys._base_executable`, prefix/configuration
   and platform state. Set the module's `__file__` to its fixed authenticated
   source path and its package/name metadata deliberately; do not forge these
   interpreter values to match expected output. The pinned module's guarded
   main is not entered. Invoke only:

   ```python
   EnvBuilder(system_site_packages=False, clear=False, symlinks=True,
              upgrade=False, with_pip=False, prompt=None,
              upgrade_deps=False).create(EXACT_OWNED_TARGET)
   ```

   This is the explicitly supported POSIX verifier contract. No pip seed,
   upgrade, existing-target adoption, Windows fallback or target execution occurs.
4. WHEEL-BOOTSTRAP binds the complete finite venv template namespace and exact
   relevant common/POSIX template bytes. Verify it before creation and after
   child completion; no extra template directory/file can authorize a target
   script. Independently derive allowed transformed activation bytes from those
   reviewed templates and the real fixed context. The bound source may walk/read
   only that justified template namespace. Existing trusted stdlib/sysconfig
   behavior is explicitly external TCB, not an unbound file to silently bless.
5. Before any target use, require the complete expected minimal namespace,
   exact literal symlink aliases to the selected effective interpreter and its
   rechecked binding, private ownership/permissions, empty site-packages,
   expected lib64 alias only on the applicable platform, and deterministic
   activation/configuration bytes. If pinned EnvBuilder falls back to copying
   an executable, retain/reject that target. Do not accept it by inventorying
   new bytes as their own authority or running it to discover its identity.
6. Independently validate `pyvenv.cfg` against the real interpreter/context and
   pinned writer rules. Its informational `command` field contains the pinned
   source's literal `sys.executable -m venv ...` spelling even though actual
   dispatch used the source-only entrypoint. Bind **both** the actual argv and
   this generated field with distinct semantics. Neither can stand in for the
   other, source proof, prefix proof or completion. Do not modify generated
   configuration to conceal this distinction.
7. Publish VENV completion only after actual owned producer success/EOF/reap,
   complete independently expected inventory, source/template/interpreter
   rechecks and original action/owner/input binding. Failed creation, cancellation,
   partial output, template/source drift or receipt/fsync failure leaves retained
   state and blocks every target use. No missing-receipt recovery/adoption/reset.

Tests must exercise the actual new source-bootstrap entrypoint and real consumer
guards, not just a generic helper loader. A wholly fictional venv package has
unchanged authenticated source plus valid harmless conflicting timestamp- and
hash-based bytecode. The actual bootstrap must execute authenticated bytes only
or reject before body/target acquisition. Add missing/replaced/symlinked source,
module collision, wrong argv/interpreter metadata, extra/changed template,
copy-fallback and generated-versus-actual command negatives. Before native
approval these use independent fictional interfaces and native vetoes. Later
genuine offline creation/layout/CLI tests remain mandatory, not replaced by pure
sentinels or a fabricated successful VENV receipt.

## VRP4R3-02 — exact pinned pip parent, target and environment

The pinned wheel source review established support for the fixed runnable
`BUNDLED_PIP_WHEEL/pip` entry. Use only the already hash/identity/size-bound pip24
wheel; no installation into the target, download, replacement or version-only
selection. Encode literal argv builders and typed accepted contracts in the
existing wheel helpers and WHEEL-BOOTSTRAP.

Installation parent argv is exactly:

```text
BASE -I -B -S BUNDLED_PIP_WHEEL/pip --isolated --disable-pip-version-check
  --no-input --no-cache-dir --python TARGET/bin/python
  install --no-index --no-deps --no-compile EXACT_LOCAL_PRODUCT_WHEEL
```

Dependency-check parent argv is exactly:

```text
BASE -I -B -S BUNDLED_PIP_WHEEL/pip --isolated --disable-pip-version-check
  --no-input --no-cache-dir --python TARGET/bin/python check
```

Arguments are arrays, not shell interpolation. The pinned parser's expected
target argv is **`[TARGET/bin/python, BUNDLED_PIP_WHEEL/pip, *the_same_pip_args]`**,
including `--python TARGET/bin/python`. Pip itself sets
`_PIP_RUNNING_IN_SUBPROCESS=1` for that legitimate redispatch. The base flags
`-I -B -S` are **not forwarded**. Do not claim target isolation from their
presence on the parent. Neither use target `-S` (which would change Python3.11
venv-prefix/site behavior) nor run an installed target `pip` package.

Both operations use a complete clean parent environment, not inherited ambient
values with a few deletions. Inherit that exact reviewed environment into the
target, plus only pip's legitimate subprocess marker:

- `PYTHONDONTWRITEBYTECODE=1`, `PYTHONSAFEPATH=1`, `PYTHONNOUSERSITE=1`;
- `PIP_CONFIG_FILE=/dev/null`, which the pinned implementation uses to skip
  global/site/user configuration-file loading, including before redispatch;
- fixed reviewed PATH and locale values plus the already owned private
  HOME/TMPDIR/TMP/TEMP and working directory from the wheel action contract;
- only any additional explicitly enumerated tool-required nonsecret values
  justified in the existing accepted environment schema. No wildcard allowlist.

Exclude ambient PYTHONPATH/PYTHONHOME/PYTHONUSERBASE, startup/loader injection,
other pip configuration/index/cache/proxy/credential overrides, and incoming
`_PIP_RUNNING_IN_SUBPROCESS`. Do not pass empty strings as undocumented substitutes
for absent keys. `--isolated` alone is not the configuration-file prohibition.
`check` retains the global noninteractive/cache/version-check controls; it does
not receive install-only switches or generate new target packages.

Immediately before either parent acquisition, validate the genuine predecessor
receipt and full target namespace/config/interpreter/aliases, the bundled pip
binding and exact local product wheel. After installation, allow only the
independently derivable wheel/pinned-installer delta, including RECORD and console
launcher semantics; preserve the original baseline runtime files. Authenticate
and validate before the first and every later target module/console launch.
The already planned .pth/customizer/cache/unknown-module prohibitions stand.

Record actual owned parent argv/env policy, logs/EOF/reap/status and the source-
validated target dispatch contract distinctly. The pinned synchronous
`subprocess.run` target wait propagates failure; do not invent a separately
observed target PID/exit or per-target log receipt where the real collector only
observed the parent. Native proofs must exercise genuine redispatch plus failure/
cancellation/pipe behavior under reviewed ownership, with a truthful description
of what was observed versus established from pinned code. Target/parent failure,
unknown completion, runtime drift or receipt/publication failure blocks later
use and leaves all owned evidence retained; no silent repeat/adoption.

Tests assert exact parent argv, actual pinned parser target argv construction,
complete inherited environment and legitimate marker transition. In fictional
owned inputs, poison ambient pip configuration, Python paths, loader settings and
the subprocess marker; assert they cannot reach either child. Test malformed
dispatch schemas, missing before-use receipts, parent/target failure, cancellation,
post-install namespace drift and publication failures. Do not read real user
config, credentials or caches to construct negatives. Genuine offline install,
console/module execution and dependency-check positives remain later native gates.

## Compatibility, review, quotas and final obligations

Only ignored verification helper/bootstrap/schema/driver inputs change. Existing
product API, wheel contents, runtime dependency claim, Store/workflow identities
and application state do not. Update the new private policy/inventory and every
producer/reader/tiny-offline-producer/schema together; no stale caller remains.

Budget the authenticated source/template/pip reads, repeated target inventories,
new receipts and actual subprocess graph within the unchanged original quotas.
Measure the actual-sized lifecycle without dropping gates or resetting counters.
The two required Bash syntax checks and all original/follow-up proof cases remain
separate obligations. Preserve historical218PASS/1FAIL, all unknown/failed outer
receipts and every partial fixture. Unexecuted is never PASS.

Sequence: this exact amended plan's independent approval → scoped implementation
and bounded fictional tests → distinct complete actual-code review → separately
authorized native proofs/final gates → protected issue delivery. No plan/test
acceptance grants a cache move, historical archive/removal, unsafe shared-host
suite, pre-verification branch push, Store action or READY verdict.

No worker or build was started for this authoring. No source, user AGENTS, cache,
active helper, frozen package or historical evidence changed. Remaining findings,
the NEW first-pass-style whole-repository production-readiness audit/remediation
and the conditional complete technical feature report remain mandatory.
