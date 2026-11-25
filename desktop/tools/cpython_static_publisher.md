# Direct CPython static-module publisher — SOURCE ONLY

These files author one proposed Linux publisher recipe, not an available runtime,
build authorization, general execution controller, installer, linked SBOM or
native qualification. **No build-input lock is sealed and all three production
copy anchors are `None`.** Do not run these tools merely because they exist.
Do not fill anchors with a private proposal, fixture or caller assertion.
The existing PBS transformer, generic preparer, runtime limits and both native
execution gates are unchanged.

The profile is `cpython-3.14.7-linux-x86_64-static-v1`: ordinary-GIL CPython
3.14.7, GNU/Linux x86_64, Ubuntu 24.04 userspace, static optional modules and
static zlib/libffi, no shared libpython/extension payload. It covers the seven
passive methods (including `github.setup.propose`) and the existing dedicated
edit bootstrap's source dependencies, **not the whole CLI/service surface**.
Shipping unused pure Python/core source does not make SSL, credentials, network,
GUI, database or other omitted-native features supported.

## Files and ordinary boundaries

| File | Only intended operation |
|---|---|
| `cpython_static_recipe.sh` | Fixed ten-phase, single-job build using sealed absolute tools |
| `cpython_static_inputs.py` | Closed lock validation, fresh input materialization, phase/configuration data receipts |
| `cpython_static_link.py` | Generated ld entrypoints call the pinned real ld.bfd once and retain original evidence |
| `cpython_static_setup.local` | Exact 19 static / 59 disabled optional-module source profile |
| `prepare_cpython_static_payload.py` | Closed host-only offline copy of independently reviewed output/evidence/notices |
| `tests/desktop/test_cpython_static_publisher.py` | Explicitly selected inert algorithm tests; no `record()` or build invocation |

None acquires packages, downloads archives, extracts an image, installs anything,
launches a container, performs signature verification, chooses a toolchain, runs
application fixtures or qualifies an installed runtime. The shell is not a
configurable runner: there is no caller command, arbitrary phase, retry, cleanup,
network, approval, skip-check or fallback interface. The link shim is only the
ordinary compiler/ld boundary, not an execution owner or timeout controller.

Source authoring does not execute these files, their imports, syntax compilers
or tests. A later test authorization must select the inert test class/module
and its host separately; test fixtures are text and in-memory ar framing, not
real native outputs or replacement successful-link evidence.

## Required distinct admissions

1. Independently review these exact source/test bytes and this interface.
2. Separately admit bounded **data acquisition**: authentic source archives,
   immutable OCI manifest/blobs, signed fixed Ubuntu package snapshot, full
   binary/source package closure, archive paths/types/bounds and correspondence
   to the reviewed CPython/build-helper sources. No package scripts at this step.
3. Independently admit any offline image/package-maintainer preparation as real
   execution. Verify its resulting tools/rootfs, retain trust/preparation
   receipts and seal the final input lock. Unknown package revisions, image and
   tool hashes must remain unselected, not guessed.
4. Only an explicit one-build command/envelope may execute the recipe. It must
   specify the exact lock SHA256, pinned host tools, offline/no-network/private
   namespace, resource/time/disk bounds and retention/stop policy. Do not run a
   second build to replace missing original evidence.
5. Independently review original outputs, final-link members, startup/compiler
   runtime/glibc origins, actual dynamic closure, all copied-source notices and
   the new direct-build change summary. Construct and approve the copy inputs
   below. Only a separate reviewed source change may set production anchors.
6. Separately admit host-only copy and generic preparation. Recheck the current
   core/bootstraps/preparer byte profile at that handoff; do not rely only on a
   Git HEAD label. Installation, loader/path/custody and original-owner
   qualification remain distinct subsequent work.

A Ubuntu24 container does not qualify a kernel/mount adapter. The old hosted
6.17 development result is not a build of this candidate or a qualification of
the installed adapter. Its exact Azure `6.17.0-1022` source/ABI review does not
replace native or installed-runtime qualification. Unexpected DSOs stop handoff for review;
`ldd` is neither permitted here nor original-link provenance.

## Input lock, not an approval flag

The canonical JSON lock has exactly these top-level fields:

```
schemaVersion, state, target, builder, packages, tools, sources,
recipeFiles, coreSourceFiles, environment, configuration
```

`schemaVersion` is integer 1; `state` must be `"sealed"`. An engineering draft
must say `"UNSEALED"` and is refused. Missing/extra fields, duplicate JSON keys,
nonfinite numbers, noncanonical encoding and byte/hash drift are refused.
Canonical encoding is ASCII-escaped JSON, sorted object keys, compact `,`/`:`
separators, exactly one LF. Inventories and source/package/tool/recipe/core
rosters use sorted paths/ids/roles and no duplicates. The existing hash-pinned
core-profile JSON is deliberately read in its original pretty encoding.

An absolute-file record `F` is exactly `{path,size,sha256}`; `path` is an explicit
canonical, whitespace-free absolute path with no `..`, colon, shell escaping or
control characters. SHA256 is 64 lowercase hex; sizes are bounded integers.
A URL/file record is `{url,file:F}`. URLs are only retained HTTPS labels; their
presence is **not** authentication. The lock's nested shapes are:

- `target`: exactly `{triple:"x86_64-unknown-linux-gnu",userspace:"ubuntu-24.04",
  pythonVersion:"3.14.7",gil:true}`.
- `builder.image`: `{reference,manifest:F,blobs:[F]}`. `reference` must contain
  an immutable `@sha256:` digest equal to the retained manifest's digest.
- `builder.snapshot`: `{id,url,metadata:[F],keyFingerprints:[UPPERCASE_HEX],
  trustReceipt:F}`. Exact signed metadata and independent trust receipts must
  already have been reviewed; this validator does not run GPG or prove trust.
- `builder.sysroot`: `{inventory:F,aliases:[{path,target}]}`. Its canonical
  inventory is `{schemaVersion:1,files:[{path,size,sha256,package}]}`. Entries
  name resolved ordinary files; any required symlink/directory alias is listed
  separately and checked exactly. This verifies listed bytes and aliases, not
  completeness of a mutable host or that an image was actually booted.
- `builder.preparationRecipe`: `F` for the separately reviewed preparation bytes.
- `packages`: records `{id,name,version,architecture,binary:{url,file:F},
  source:{name,version,artifacts:[{url,file:F}]}}`; architecture is `amd64`/`all`.
  Every referenced sysroot/tool package must exist. Package/source identity,
  extraction and signed-snapshot correspondence are prior review obligations.
- `tools`: `{role,file:F,package}` for exactly `ar`, `as`, `cc`, `cc1`,
  `cc1plus`, `collect2`, `cxx`, `host_python`, `ld`, `make`, `ranlib`, `sh`.
  Tool records must match package-owned sysroot inventory entries. All other
  programs, compiler specs, host stdlib/zlib and loader/support bytes actually
  used must also be included in the reviewed sysroot closure, not PATH guesses.
- `sources`: exactly `cpython`, `libffi`, `zlib`, each
  `{id,version,archive:{url,file:F,receipt:F},root,inventory:F,patches:[]}`.
  Roots are `/work/inputs/sources/ID`; inventories are
  `{schemaVersion:1,files:[F]}` and exactly match ordinary extracted source files.
  Original sources remain unmodified; zlib gets a checked fresh build copy.
- `recipeFiles`: exactly the four build-executed files (shell, inputs, link,
  Setup) at the common admitted tool location, with byte hashes. Copy tooling
  and later approvals are separately reviewed, not added to a hash cycle.
- `coreSourceFiles`: all 61 whole-core files plus both bootstraps and the generic
  preparer (64 files), at `/work/inputs/core-source`. Their per-file hashes must
  match the frozen profile SHA256
  `988c9ba2ca2aa343c9c7f2caae4c92c36e0ca7224f53c519303f5cdeae9e319f`.
- `configuration`: `{profile,cpythonCommit,staticModules,disabledModules,
  pythonConfigure,zlibConfigure,libffiConfigure,makePhases,coreProfile:F}`.
  Arrays/values must equal the fixed constants in `cpython_static_inputs.py`.
  CPython commit is `823f0323ee6ec1402088b73bce1a38473cac36dc`.
- `environment`: exactly the values below plus a selected decimal-string
  `SOURCE_DATE_EPOCH`. No inherited credential/compiler/Python hooks are allowed.

The three pre-known archive candidates (not freshly authenticated here) are:

| Source | Bytes | SHA256 |
|---|---:|---|
| CPython 3.14.7 | 24053924 | `3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81` |
| zlib 1.3.2 | 1502830 | `bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16` |
| libffi 3.4.8 | 1397992 | `bc9842a18898bfacb0ed1252c4febcc7e78fa139fd27fdc7a3e30d9d9356119b` |

Exact release URLs are fixed in `SOURCE_PINS`; Git/autogen/archive substitution
and source patches are not supported. GCC 13-family / GNU ld.bfd 2.42 are the
reviewed interface baseline, **not selected package versions/hashes**.

A required command-supplied lock SHA256 binds the *later independently approved
command* to the lock. It is identity, not permission to execute or a production
approval switch. Embedding that SHA in a validator that the lock itself hashes
would create a hash cycle; this implementation deliberately does not do so.

## Exact recipe behavior and execution disclosure

Use only the admitted absolute shell and host Python. Command **shape**, not an
authorized/available command (all capitalized operands require later selection):

```
PINNED_ABSOLUTE_ENV -i \
  PATH=/usr/bin:/bin HOME=/work/home TMPDIR=/work/tmp LC_ALL=C.UTF-8 TZ=UTC \
  CONFIG_SITE=/dev/null PYTHONDONTWRITEBYTECODE=1 PYTHONSTRICTEXTENSIONBUILD=1 \
  PYTHON_COLORS=0 CFLAGS='-O2 -g0 -march=x86-64 -mtune=generic' \
  SOURCE_DATE_EPOCH=SELECTED_EPOCH \
  PINNED_ABSOLUTE_SH ABSOLUTE_RECIPE PINNED_ABSOLUTE_HOST_PYTHON \
  ABSOLUTE_SEALED_LOCK INDEPENDENTLY_REVIEWED_LOCK_SHA256
```

The input helper confirms the host interpreter identity. `/work` must already
be an ordinary private 0700 directory. `build`, `deps`, `stage`, `receipts`,
`capture`, `home`, `tmp` and `build-env.sh` must all be absent; no reuse/adoption
or cleanup. Entry environment must match the lock, with only shell bookkeeping
`PWD`/`SHLVL`/`_` allowed in addition. The fresh generated environment has quoted
assignments, absolute tools, GCC `-B/work/capture/ -fuse-ld=bfd`, and no inherited
compiler/library/Python search overrides. Only `ld` and `ld.bfd` entrypoints
are created in the capture directory; `-B` must not find extra libraries/headers.

The fixed phases are zlib configure/build/install, libffi configure/build/
install, Python configure, six HACL archive targets, normal Python build, and
`altinstall DESTDIR=/work/stage COMPILEALL_OPTS=-j1`. All make calls use `-j1`.
Configuration argv is both literal in the shell and closed in the lock helper.
Zlib/libffi are static PIC under `/work/deps`; Python uses the explicit archives,
not a system-library fallback. Python keeps upstream OPT and Linux's ordinary
export-dynamic setting, applies later O2/g0 flags, and adds no static-libgcc.
The six HACL `.a` Setup operands are intentionally linker-only; generic make
variables would also become compiler inputs. Upstream SIMD dispatch is retained;
`-march=x86-64` does not claim every HACL object is scalar.

**This build executes code.** It includes configure compile/run probes,
zlib/libffi helpers/examples, CPython bootstrap/freezer/sysconfig generators,
normal extension imports, build-details generation and compileall. It builds
`Programs/_testembed` but does not run its test suite. There is no PGO, LTO,
`make test/check`, regrtest, app fixture or native gate. It is not compile-only.

Review correction **C1** is literal: `PYTHONSTRICTEXTENSIONBUILD=1` is locked,
exported and checked; `"0"` is not a false value to the upstream checker. Original
phase logs/statuses remain available. Ignored-error/compileall diagnostics and
sticky/incomplete link captures fail a phase even if the original phase exited
zero. After configure/build/install, generated `Modules/config.c`, Makefile,
pyconfig.h and Setup files are retained. A data parser checks the **full 56-name
source table** (27 bootstrap + 10 intrinsic + 19 optional), no shared names and
exactly the disabled roster. This is not a runtime observation or the upstream
checker's smaller printed builtin count; `_contextvars` is not silently lost.

## Original-link evidence and fail-closed limits

For every link the generated wrapper invokes the pinned real ld.bfd **once**,
appending `-Map=... --cref -t -t --dependency-file=...`. Recognized exact version/
help queries have their own `query` receipts, not invented link artifacts.
Each `link-NNNNNN/` retains original/effective/expanded NUL-separated argv,
environment JSON, raw stdout/stderr/map/depfile, immediate original-result JSON
and final receipt. Response-file bytes and other artifacts also live in a
content-addressed `objects/SHA256` store. Private file modes are 0600.

The real linker receives the original `@response` operands. The shim's separate
analysis supports bounded ASCII GNU quote/backslash grouping (including escapes
inside either quote type), no shell expansion/comments, depth <=4, <=128 response
references and <=1 MiB combined response/argument data. It rejects unclosed
quotes/escapes and unsupported control/path syntax, retains response bytes and
rechecks them after the native call. GNU make depfiles support whitespace-free
paths, LF continuations and empty phony rules only. Concatenated `-o...` and
caller capture-output flags are refused, not guessed. Standard separate `-o`
and `--output[=...]` are supported. Unsupported actual formatting stops review;
do not rerun ld to manufacture a replacement map.

Map and double-trace member sets must match and belong to resolved dependency
paths; plain trace paths must appear in the depfile. Actual read inputs have
sealed package/source/build/driver-temporary origins and retained byte hashes.
Positional-looking argument candidates are explicitly **not proof of reading
or incorporation**. Linker plugin code and absolute plugin-option paths (such
as lto-wrapper) are separately retained as process-file evidence, not labelled
archive members or proof that an optional helper executed.

GNU ordinary archives retain complete bytes plus selected member bytes,
physical-header ordinals and offsets. Thin/BSD archives, unresolved long names,
missing members and same-name selected-member ambiguity are refused. An
extracted member can contain discarded sections: neither its full bytes nor a
DSO interface is a claim that every byte is present in the final executable.
The full linked-input/notice closure still requires independent output review.

Review correction **C2**: `originalResult` is `{kind:"exit",code:N}` or
`{kind:"signal",signal:N}`. Original nonzero exits remain nonzero; a native signal
is retained distinctly and the shell-facing wrapper returns `128+signal` (not a
claim that the wrapper has the same OS wait-status signal). Failed probes may
have unavailable map/deps/output fields with `reason:"original-link-failed"`;
available partial bytes and inputs are retained. `analysisComplete:false` does
not fabricate success. A preexisting output left by a failed link is explicitly
not a new successful product. Successful missing/irreconcilable evidence is
fatal. **Actual retention failures remain sticky even when ld also failed.**
`CAPTURE-FAILED.json` preserves the first known original result; phase checks also
reject incomplete link directories if that marker could not be written.

Bounds include 4096 link receipts, 64 MiB per diagnostic, 1 GiB per retained
native input, and the lock's input-inventory bounds. These are not a global
resource scheduler; the later execution envelope must bound memory/disk/time
and preserve the original workspace on failure. Filesystem checks assume a
single-job, quiescent publisher namespace, not a hostile compiler/privileged
host or installed-runtime custody.

## Closed offline copy inputs

The public `prepare()`/CLI has only these required absolute path operands:
`--stage`, `--output-inventory`, `--receipts`, `--provenance`, `--notices`,
`--notice-inventory`, `--host-inputs`, `--output`, `--report`. There is no hash,
policy, approval or skip override. It refuses **before any path inspection or
read** while any production anchor is missing. Any other private `_Policy`
identity is always labelled `inert-algorithm-test`, not production.

All metadata uses canonical JSON above. Relative file record `R` is
`{path,size,sha256}` with portable relative paths. The three separately reviewed
source-pinned documents are:

1. **Output inventory** `{schemaVersion:1,profile,target,inputLockSha256,
   hostInputsSha256,stage,finalInterpreter}`:
   - `stage` is `{sourcePrefix:"/work/stage/opt/mrk-python",files:[R],
     directories:[relative-path]}`. It lists *every* file and directory,
     including explicitly listed empty installed directories. The supplied
     stage may be a separately retained byte-identical ordinary local copy;
     the sourcePrefix denotes the original build path, not automatic discovery.
   - `finalInterpreter` is `{stagePath:"bin/python3.14",linkId,receiptSha256,
     size,sha256}`. It must match both the staged interpreter and the original
     successful `/work/build/cpython/python` link artifact, without strip.
2. **Provenance** `{schemaVersion:1,profile,inputLockSha256,
   noticeInventorySha256,files:[R],linkedInputClosure:R,dynamicClosure:R}`.
   `files` is the entire retained receipts/evidence tree, including separately
   reviewed closure documents. All original bytes must still exist and hash
   correctly, no extras or capture-failure marker. All ten original phase
   statuses/logs and the configuration audits are required. The final receipt,
   argv/environment/native-result/diagnostics/map/depfile, retained input/member/
   plugin objects and output bytes are cross-bound. Closure review documents
   are **hash-bound review evidence**, not signatures or a SBOM derived by this
   copier. Their correctness must be independently reviewed before anchoring.
3. **Notice inventory** `{schemaVersion:1,profile,
   pythonChangeSummary:"PYTHON-CHANGES.txt",files:[R]}`. The notice tree must
   match exactly. Nonempty public notices total <=2 MiB/128 files/512 entries.
   Review correction **C4**: it must be the newly reconciled direct-build change
   summary, not the PBS patch summary/private union. Cover configuration/module
   selection, pruning, python3 byte mapping, license relocation and generated
   landmarks. The PSF license's change-summary requirement is not erased by
   saying no upstream source patches were applied.

The output inventory separately binds **host inputs** by SHA256:
`{schemaVersion:1,hostPython:F,files:[F]}`. Files must contain the exact resolved
host interpreter and full independently reviewed host stdlib/zlib/support
closure, with checked bytes. Production additionally checks `sys.executable`
identity and `-I -S -B`. Completeness of this host closure and safe startup remain
the prior pinned-command review's obligations, not an interpreter sandbox.
This is correction **C3**: the pinned host interpreter runs; the candidate never
runs or imports during offline copying/preparation. The existing generic
preparer later runs under its separately admitted pinned host/stdlib/zlib.

## Copy result, limits and handoff

The copier inventories all stage bytes, then copies every ordinary installed
stdlib `.py` except top-level `test`, `ensurepip`, `idlelib`, `turtledemo`, `venv`,
`site-packages` and `config-3.14-*`. It also keeps exactly the Linux/GIL generated
`_sysconfigdata__linux_x86_64-linux-gnu.py`, its matching `_sysconfig_vars_*.json`
and `build-details.json`. Unknown sysconfig ABI variants stop, and unexpected
shared native files anywhere in the stage are rejected rather than hidden by
pruning. Generated metadata bytes are not rewritten, imported or authority to
look up the SDK paths they describe.

Exact outputs include:

```
python/bin/python3                         exact original final-link bytes, 0755
python/LICENSE.txt                         installed lib/python3.14/LICENSE.txt bytes
python/lib/python3.14/os.py                 retained stdlib, other files 0644
python/lib/python3.14/encodings/...
python/lib/python3.14/_sysconfigdata__linux_x86_64-linux-gnu.py
python/lib/python3.14/_sysconfig_vars__linux_x86_64-linux-gnu.json
python/lib/python3.14/build-details.json
python/lib/python314.zip                   b"PK\x05\x06" + 18 zero bytes
python/lib/python3.14/lib-dynload/README.mrk
python/licenses/REVIEWED_PUBLIC_NOTICES
python/licenses/PYTHON-CHANGES.txt
```

The marker bytes are exactly
`No shared extension modules are shipped in this profile.\n`.
LICENSE size/hash remains the separately known 13804-byte CPython license,
SHA256 `b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231`.
Other bytecode, wheels, SDK/static archives, headers, scripts and manpages are
not copied; omissions and original directory inventory are in the report.
No symlink, hardlink, special file, case alias, overwrite/adoption, unlisted
empty directory or strip transformation is allowed. All outputs are fresh
single-link regular files; generated directories are 0755 under a private
0700 output root. Public notices are present **before** any manifest generation.

The unchanged final-resource intersection is 2048 files, 8192 entries, 16 path
components/512 path bytes, 512 MiB per file and 1 GiB total. The copier reserves
three payload files (`core.zip` and both bootstraps), four entries including
manifest, >=64 MiB resource headroom, and the 1 MiB/20,000-node manifest envelope.
No final file count, executable hash, dynamic closure or reproducibility result
is asserted before real preparation. Private input-stage/evidence/report limits
are separate from these unchanged shipped-runtime limits.

Output and the separate 0600 report must be absent. A fresh `INCOMPLETE` sentinel
persists through writes and exact output byte/mode/inventory verification; it
is removed only after the report is retained and checked. Failures preserve
partial output, not roll it back or adopt it on retry. A report explicitly says
it is descriptive, **not a completion/handoff receipt**. On success the runtime
root contains only `python/`; the copier neither imports nor invokes
`prepare_runtime.py`. That existing pinned preparer is a separate admitted
step adding whole-core DEFLATE ZIP, both bootstraps and manifest. Its existence
and a successful copy are not production gate admission or installed custody.
