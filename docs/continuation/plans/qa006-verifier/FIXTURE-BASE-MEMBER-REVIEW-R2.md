# Fixture-base R2 — named pinned-member inspection ledger

**Static planning evidence, not code approval or a behavioral test.** No helper,
venv module, pip, setuptools backend, fixture, Store, process query or signal was
executed. Original held source caches and historical53 fixture-venv payloads were
not accessed. No build/background worker was started. All new files are retained
planning/review inputs; no cleanup was performed or authorized.

## Exact original archives and retained references

Both files are the original explicitly selected
`.mobile-release/remediation/MRK-002/runtime/python/lib/python3.11/ensurepip/_bundled/`
inputs, rechecked against `verifier-implementation-package-r4-r2/FINITE-PROOFS.json`
prerequisites. No replacement archive or installed-version inference was used.

| Input | Original reference | Inventory |
| --- | --- | --- |
| pip24.0 | 2,110,226 bytes, SHA256 `ba0d021a166865d2265246961bec0152ff124de910c5cc39f1156ce3fa7c69dc`, dev16777232/inode68424185/uid501/mode0644/regular | 524 members; 7,122,471 uncompressed bytes |
| setuptools79.0.1 | 1,256,281 bytes, SHA256 `e147c0549f27767ba362f9da434eab9c5dc0045d5304feb602a0af001089fc51`, dev16777232/inode68424186/uid501/mode0644/regular | 514 members; 4,348,283 uncompressed bytes |

Four exclusive static inspections retain 76 text copies representing 70 unique
named members (six copies are repeated top-level RECORDs):

| Directory / BINDINGS.json | SHA256 | Text copies |
| --- | --- | ---: |
| `fixture-base-member-inspection-r2/` | `0a733bf2f86a1c26d00b7a1b82231233bd9b16017a4df10a478ec0762ce810f8` | 39 |
| `fixture-base-member-inspection-r2-supplement/` | `9d77c9752bed1e0e532b3e8ff5a4678ea5ed39a9345a619bdc42fcadaf69aec0` | 20 |
| `fixture-base-member-inspection-r2-final/` | `f18d0e396e79f07c66e42118ce8ea8a5d6d8ac7c7450547f5be8214b6c072054` | 8 |
| `fixture-base-member-inspection-r2-hooks/` | `f8032b8138e278a0bcff3f6c077c2d13b48562acfeac15c3b8d5f46174dd93e6` | 9 |

The union is 39 pip members and 31 setuptools members. Each manifest lists exact
selected source-text snapshots, sizes/hashes and every unselected member. Those
unselected names received central-directory/top-RECORD validation only, **not**
semantic source review or extraction. All 1,038 names were unique, casefold-distinct,
relative/no-traversal, bounded, non-symlink archive entries; RECORD names/sizes
matched the complete inventory. Selected body hashes matched the original RECORD
(whose self-entry is intentionally unhashed and is independently hashed here).
Whole original archive hashes bind both selected and unselected payloads.

Archive authentication is an original independently supplied named input binding,
not trust in an attacker-supplied adjacent checksum. This is nevertheless not a
fresh whole-third-party-library security audit, and it makes no claim of an
external package-author signature or native installation success.

## Semantic source inspection and derived contract

Paths below are original member names; the manifests map them to retained `.txt`
files. Line ranges refer to those unchanged member bytes. Targeted semantic reads
are not represented as complete whole-file reviews unless marked whole.

### Setuptools/backend/startup

| Member | Semantic range/method | Relevant conclusion |
| --- | --- | --- |
| `distutils-precedence.pth` | Whole exact body | One specific startup statement imports `_distutils_hack` and adds its shim; arbitrary pth is not equivalent. |
| `_distutils_hack/__init__.py` | Whole | Exact shim/meta-path insertion, pip-sensitive behavior and version branches; must validate every installed input before startup. |
| `setuptools/__init__.py` | 1–89 | Adds exact bundled `_vendor` path then imports override/backend dependencies; no separately installed packaging distribution is needed for this fixed seed. |
| `setuptools/build_meta.py` | 307–377,379–480; targeted function/caller inspection | Metadata is generated in requested temporary directory; PEP660 delegates to editable_wheel; no replacement backend. |
| `setuptools/command/editable_wheel.py` | 52–81,103–418,558–580,602–674; strategy/finder index | Fixed simple src-layout chooses `_StaticPth` with canonical source/src + newline. No finder or link-tree is emitted. Header/script/data categories are noneditable; data includes configured Gemfile. |
| `setuptools/command/dist_info.py` | Whole | Exact normalized distribution directory; egg-info -> dist-info; keep-egg-info preservation is in requested temporary metadata root. |
| `setuptools/command/bdist_wheel.py` | 455–477,531–590; function index | Exact WHEEL headers/generator/tag; metadata copy, removal of empty dependency links and exact licenses subdirectory. |
| `setuptools/command/build_py.py` | 40–100,160–220 | Editable mode skips normal build copy. Manifest metadata uses existing temporary egg-info where available; later noneditable build is a separate producer. |
| `setuptools/command/egg_info.py` | 650–706; named writer index | PKG-INFO/name/version, top_level newline and entry-point emission. Root/source output must not be assumed from temporary metadata production. |
| `setuptools/_core_metadata.py` | 1–65,149–285,286–end | Metadata2.4 fields, exact extra requirements and dynamic-field treatment. |
| `setuptools/dist.py` | 357–467; license-pattern 469–531 | Requirement static-ness preserved; license expansion converts to plain list and therefore emits `Dynamic: license-file`. |
| `setuptools/_static.py` | Whole | Exact static values/collection wrappers; distinguishes that dynamic license-file field from fixed project metadata. |
| `setuptools/_normalization.py` | Whole | Exact `mobile_release_kit-0.3.0` filename normalization; no version or alternate distribution fallback. |
| `setuptools/_entry_points.py` | Whole | Deterministic group/name order and a single LF-terminated console_scripts entry. |
| `setuptools/config/_apply_pyprojecttoml.py` | 45–119,160–251; named field inspection | Project values marked static; README extension determines text/markdown; MIT expression and Python bound are literal. |
| `setuptools/config/expand.py` | 113–149 | Exact UTF8 README reading/concatenation; request still binds source and no-follow provenance independently. |
| `setuptools/compat/py312.py`, `py39.py` | Whole both | Python3.11 pth uses locale encoding; fixed ASCII fixture-path restriction makes the expected bytes explicit without forging runtime locale metadata. |
| `setuptools/_vendor/wheel/wheelfile.py` | 130–end | Wheel member emission, RECORD hash/size/self-entry and LF archive RECORD; installed RECORD is later pip CSV/CRLF. |
| `setuptools/_vendor/packaging/requirements.py` | Whole | Exact string formatting of fixed extras requirements. |
| `setuptools/_vendor/packaging/markers.py` | 137–162,286–287 | Single marker group normalization and exact quoted/space-separated marker form. |
| `setuptools/_distutils/command/install_data.py` | 36–end | Data files go to .data/data scheme, not editable mapping; actual target has share/mobile-release-kit/Gemfile. |
| `setuptools/command/_requirestxt.py` | Whole | Source egg-info requirement representation differs from METADATA; cannot compare the two as interchangeable bytes. |
| `setuptools-79.0.1.dist-info/{WHEEL,entry_points.txt,top_level.txt}` | Whole bodies | Purelib py3-none-any; no console_scripts group; package roots are _distutils_hack/pkg_resources/setuptools. |
| `setuptools-79.0.1.dist-info/METADATA` | Identity/Python/dependency headers only | Setuptools79.0.1, Python>=3.9; dependency declarations are extras, not additions to this no-deps seed. |
| `setuptools-79.0.1.dist-info/RECORD` | Complete bounded CSV/name/size/hash contract | Exact original output inventory, including bundled vendor metadata and startup inputs. |

The additional retained setuptools `discovery.py`,
`command/install_egg_info.py` and `_vendor/packaging/_parser.py` were retained/hash-
checked as bounded supporting inputs, not fully semantically reviewed. Source
layout/type assumptions must be independently checked in the actual-code review;
if implementation relies on further emitted behavior from these paths, complete
the named semantic inspection before implementing that behavior.

### Pip installer/dispatcher/provenance

| Member | Semantic range/method | Relevant conclusion |
| --- | --- | --- |
| `pip/__main__.py` | Whole | Removes accidental current-directory entry; zip invocation inserts the exact bound wheel path. |
| `pip/_internal/cli/main_parser.py` | 41–116 | Exact --python redispatch retains full pip args; parent adds marker and waits; base -I/-B/-S are not forwarded. |
| `pip/_internal/cli/main.py` | 63–79 | Dispatch/locale handling; no independently observed child environment is implied. |
| `pip/_internal/cli/base_command.py` | 134–175 | Actual --no-input introduces PIP_NO_INPUT=1; absent exists_action does not introduce PIP_EXISTS_ACTION. |
| `pip/_internal/configuration.py` | 244–265,334–359 | PIP_CONFIG_FILE=/dev/null disables file loading including global/site/user; --isolated alone does not mean no global/site config. |
| `pip/_internal/operations/install/wheel.py` | 200–390,426–589,620–703; complete install/script/record function index | Expected destinations, pip3.10 -> pip3.11 expansion, regular versus executable extraction, no-compile, exact script generation and generated metadata/RECORD. |
| `pip/_vendor/distlib/scripts.py` | 34–51,135–228,228–309 | Exact launcher text, quoting, platform shebang length, shell-wrapper fallback and executable mode. |
| `pip/_vendor/distlib/util.py` | 566–590 | Console file creation then OR0555 gives0755 under umask077. |
| `pip/_internal/utils/unpacking.py` | 88–110 | Executable regular archive members use mode0711 under umask077; ordinary payload remains0600. |
| `pip/_internal/locations/__init__.py` | 34–67,230–270 | CPython>=3.10 sysconfig default; original distributor override/layout remains a native prerequisite, not an invented metadata field. |
| `pip/_internal/locations/_sysconfig.py` | 124–199 | Fixed target purelib/scripts/data destinations, no user/root/prefix/header install in this plan. |
| `pip/_internal/utils/direct_url_helpers.py` | 1–end (direct/editable/archive construction) | Editable source URI/DirInfo differs from seed archive hash metadata. |
| `pip/_internal/models/direct_url.py` | 140–235; direct URL serialization | Exact editable JSON sorted keys/default spacing/no LF; seed archive legacy hash plus hashes map is inherited R4-R4 pinned contract. |
| `pip/_internal/utils/urls.py` | Whole | Canonical local path -> percent-escaped file URI, not an arbitrary remote locator. |
| `pip/_internal/operations/build/metadata_editable.py` | Whole | Genuine metadata hook in private modern-metadata temporary dir. |
| `pip/_internal/operations/build/wheel_editable.py` | Whole | Actual editable build hook/failure handling; no fake wheel or synthesized native completion. |
| `pip/_internal/req/req_install.py` | 247–257,536–620,847–865 | Cached backend support check, genuine PEP660 metadata and installed wheel/direct-url/requested paths. |
| `pip/_internal/wheel_builder.py` | 36–95,180–247 | Selects genuine editable build rather than legacy fallback; no-deps does not imply no backend. |
| `pip/_internal/commands/install.py` | 371–499 | Build/hooks complete before install_given_reqs mutates target; postinstall metadata lookup is not a separate interpreter launch. |
| `pip/_internal/req/__init__.py` | 38–103 | Real sequential installation/uninstall/rollback behavior; plan forbids any preexisting project dist to prevent uninstall of unrelated state. |
| `pip/_internal/operations/prepare.py` | 556–646,675–706 | Source editable direct_url; no replacement URL/cache-derived original identity. |
| `pip/_internal/distributions/sdist.py` | 27–100 | --no-build-isolation avoids dependency/backend installation; no fabricated seed-version proof. |
| `pip/_internal/build_env.py` | 137–169,283–end | NoOpBuildEnvironment does not inject the isolated-build sitecustomize/PYTHONPATH route. |
| `pip/_vendor/pyproject_hooks/_impl.py` | 295–end; named runner | Hook argv is selected Python + bound in-process script + hook + private control dir; exact key is PEP517_BUILD_BACKEND. |
| `pip/_vendor/pyproject_hooks/_in_process/_in_process.py` | 36–66,312–end; hook dispatch | Fixed backend input protocol and finite hook names; no claimed per-hook PID observation. |
| `pip/_internal/utils/subprocess.py` | 71–258 | Inherits explicit env, adds known hook values, synchronous read/wait/error propagation; parent must preserve actual EOF/group uncertainty. |
| `pip/_internal/operations/build/build_tracker.py` | 1–115 | PIP_BUILD_TRACKER is generated under owned TMP, saved/restored by pip, not incoming caller authority. |
| `pip/_internal/utils/temp_dir.py` | 160–193; lifecycle index | Owned temporary creation/normal cleanup; interrupted temporary state must be retained, not broadly deleted. |
| `pip/_internal/cache.py` | 170–214; named cache index | --no-cache-dir still has a generated ephemeral wheel cache; no persistent cache is approved by this plan. |
| `pip/_internal/metadata/importlib/_envs.py` | 150–224 | Postinstall lookup traverses distribution metadata; does not launch a target to validate its own new output. |
| `pip-24.0.dist-info/{WHEEL,entry_points.txt,top_level.txt}` | Whole bodies | Purelib wheel and exact pip entry points; actual interpreter-specific expansion is required. |
| `pip-24.0.dist-info/METADATA` | Identity/Python/dependency headers only | pip24.0, Python>=3.7, no seed runtime dependencies. |
| `pip-24.0.dist-info/RECORD` | Complete bounded CSV/name/size/hash contract | Exact original installed-member expectation; not the new runtime's self-supplied inventory. |

Additional retained pip `locations/_distutils.py`, `locations/base.py`,
`cli/req_command.py` and `cli/command_context.py` received supporting named-index/
retention checks, not complete semantic review. They are not silently counted as
full inspected implementations. Actual code/native review must confirm this fixed
runtime uses the expected sysconfig/no-isolation route and finite temporary
lifetime. Any newly relied-on behavior requires named source inspection first.

## Source-derived namespace expectations and remaining verification

- Neither seed wheel has a .data member. Complete immutable two-wheel expected
  namespace, original four activation files/config and pip installer additions
  yields 1,052 regular files and 142 directories excluding root; pinned aliases and
  Linux lib64 are additional platform entries. These are static counts only.
- Exact synthetic editable successor is 12 regular files and 4 new directories.
  It must not create a finder, module copy, cache, egg-link or arbitrary pth.
  METADATA, exact source/src mapping, console, data, direct_url and RECORD are
  specified independently in R2, not captured from a successful install.
- Source-owned editable output needs special reconciliation: backend source
  directs metadata/build temp elsewhere and skips build_py in editable mode.
  Expected source-owned build/egg-info roots stay empty, whereas the later real
  wheel build populates them. Native success and exact preserved root identities
  remain unverified; current unconditional six-file editable egg-info assertion
  cannot be treated as evidence that the backend produced them. The analogous
  generic non-fixture final editable contract remains a separate unresolved
  cross-caller question; this fixed-fixture amendment does not establish its
  correctness or authorize a generic empty-output exception.
- R2's original-parent transition, strict bootstrap union, receipt predecessor,
  source lifetime, later consumer guards and failure/replay handling are plans,
  not implemented or accepted behavior.
- Native source-only creation, actual aliases/modes/sysconfig, exact pip install,
  three backend hook behavior/environment, source-owned output transition,
  cancellation/group/disposal and complete original quota/lifecycle feasibility
  all remain **UNVERIFIED**. Further pinned member source may be read only if
  needed by a specific fixed implementation path; no blanket archive execution
  or new input authority is granted.

## Actual commands/outcomes and authoring limitations

All four newly authored `inspect-fixture-members*-r2.py` utilities ran foreground
with the existing approved utility Python using `-I -B`; each exited0, imposed a
native/network/signal audit veto, rechecked exact no-follow archive bindings,
retained only explicitly named UTF8 textual members, and created exclusive ignored
snapshots/BINDINGS. Their source references are in those manifests. Their outcomes
mean static input authoring completed, **not** a test or implementation PASS.
Separate static inventory arithmetic emitted the namespace counts above. Shell
cat/sed/grep/rg only read named files; some combined displays were truncated and
critical source ranges were re-read explicitly. Four drafting apply_patch context
mismatches were corrected; they were authoring failures, not behavioral tests or
evidence bypasses. No failed native result was discarded or replaced.

Neither selected interpreter metadata nor any pip/setuptools/venv body was
executed as a test. No full suite, final45, installer, process query, signal, Git,
source-cache hold release, historical archive operation, cleanup, commit/push,
product acceptance or READY was authorized. All original218PASS/1FAIL/exit1,
quota failures, remaining proof obligations and final fresh repository audit /
conditional feature inventory obligations remain.
