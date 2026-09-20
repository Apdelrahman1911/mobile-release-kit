# Conventional source-built CPython — source-only publisher contract

This is the separate `cpython-3.14.7-linux-x86_64-source-v1` origin accepted by
PLAN01. Its input lock, prerequisite envelope policy, current core and
root-preparation inputs now have independently reviewed literal pins. The
controls are in `desktop/cpython-source-inputs/`. **Input admission is not a
build result, supply acceptance, installed-runtime readiness or legal clearance.**
Hosted build H `35505213499/1` at `37079ce7874bedc804f434f8f8851c3adf5333ac`
passed and its original configuration, projection, components and notices have
independent bounded acceptance. The committed `conventional-review/` kit and
literal pins admit that exact result to offline DATA preparation A only.
A has not yet run; B, installed-runtime qualification and product gates remain
closed. This acceptance does not establish legal or release clearance.
Legacy/static semantics and selectors are unchanged. H/D4/D3 are not
modified or reused as execution authority. No linker shim, maps, probe recorder,
private-W adapter, new process owner or container/package installer is added.

## Acyclic admission root

`cpython_source_admission.py` contains only the three literal pins for
the input lock, prerequisite execution-envelope review and actual core roster.
It is **not** a member of the lock's `recipeFiles`: the independently admitted
final command must hash-pin this tiny root and every imported helper before any
import. All six actual recipe/helper/Setup files remain in `recipeFiles`.

Freeze helpers, then input-only lock **L**, then prerequisite envelope review
**E**, then literal admission root **A(L,E,core)**, then the separate exact final
command. E may bind L and the frozen inputs/envelope; it must not bind A or the
final command, which would recreate the cycle. No code is normalized, ignored
or excluded from final command authentication. There is no CLI/environment
approval override. These prerequisite pins do not authorize an arbitrary command.

E is a bounded canonical JSON object at the fixed path
`/work/inputs/source-execution-review.json`, hash-bound by A independently of L.
Its exact reviewed content is a prerequisite, not final execution authorization.
The build retains identical `execution-review.json` bytes and binds their hash
in `source-result.json`; the later source copier requires both. The selected E
records reviewed requirements, not observed runner enforcement or native success.
Final command admission and actual-result acceptance remain separate.

## Fixed recipe and original outcomes

`cpython_source_recipe.build(LOCK)` is the only build entry. It accepts no caller
argv, phase, environment, timeout, backend, profile, skip or approval parameter.
The literal `fixed_phases()` table uses the existing current-core `run_owned` /
ordinary C/A/W route, shared real cancellation, `capture=True`, `text=False`,
`cleanup=False`, no execution scope/journal/on_start authority, and the existing
`CleanupScope` unconditional-finally pattern. No owner source is changed.

One entry-time monotonic work endpoint is 2400 seconds. Every native timeout is
the positive integer floor of remaining time; less than one second refuses.
Original cleanup, DATA work, capture/persistence and final cancellation restoration
must all finish before that work endpoint. The separately admitted outer owner
must retain another finite 10 seconds for failure cleanup/reconciliation, with
the existing per-command three-second cleanup allowance unchanged. This clock
is not containment. Original exceptions/nonzero/late/incomplete results or any
write/read/close/refusal stop immediately, retaining partials without retry.
Capture is 16 MiB combined per phase, 256 MiB aggregate retained phase logs.

The fourteen operations are:

1. zlib configure `--static --prefix=/work/deps`;
2. zlib `make -j1`;
3. zlib `make -j1 install`;
4. libffi configure `--disable-shared --enable-static --with-pic --disable-docs
   --disable-multi-os-directory --prefix=/work/deps --libdir=/work/deps/lib`;
5. libffi `make -j1`;
6. libffi `make -j1 install`;
7. OpenSSL Configure `linux-x86_64 shared no-module no-dso no-engine
   no-autoload-config no-legacy no-tests --prefix=/work/deps --libdir=lib
   --openssldir=/nonexistent/mobile-release-kit/openssl`;
8. OpenSSL `make -j1 [fixed LDFLAGS] build_libs`;
9. OpenSSL `make -j1 [fixed LDFLAGS] install_dev`;
10. finite byte-identical OpenSSL layout (six projections);
11. CPython configure: ordinary GIL, no shared libpython, mimalloc, LTO, PGO,
    test modules, ensurepip or pkg-config; builtin hashes; private OpenSSL,
    `--with-openssl-rpath=no --with-ssl-default-suites=python --without-system-expat`;
12. `make -j1 [fixed assignments]` for six HACL archives and
    `Modules/expat/libexpat.a`;
13. `make -j1 [fixed assignments] python platform checksharedmods build-details.json`;
14. finite direct DATA projection, **not install**.

The exact configure tuples, environment and paths live in the source, not in a
caller-supplied shell fragment. Baseline CFLAGS are
`-O2 -g0 -march=x86-64 -mtune=generic`; dependency phases add `-fPIC`.
`PYTHONSTRICTEXTENSIONBUILD=1` stays enabled. Compiler/ld are real conventional
tool paths, not capture wrappers. One make argument is respectively:

```
LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'$$ORIGIN'
LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'$$ORIGIN/../lib'
```

Python make also gets `PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B` and
`PYTHON_FOR_FREEZE=./_bootstrap_python -B`. There is no altinstall, libinstall,
compileall, strip, relink or LD_LIBRARY_PATH rescue. `-B` does not prevent cache
reads. Admitted payload/tool-root rosters contain no Python caches.

The source Setup selects 23 optional +27 bootstrap +10 intrinsic =60 builtins,
55 disabled, zero shared Python modules. `_socket`, `_ssl`, `pyexpat` and
`resource` are added to R; `_hashlib`/`_elementtree` remain disabled. Bundled Expat
is CPython's 2.8.2, not PBS 2.8.4. Full generated builtin/Makefile rosters and
material ABI/module/compiler/loader predicates are DATA checks, not native API
observations. Configure's normal negative feature tests are not individually
attributed products; no claim of observing every historical allocation denial.

## Inputs and DATA schemas

All JSON produced here is canonical ASCII with a terminal LF and bounded reads.
Ordinary single-link/no-follow file readers and exclusive write/readback paths
are used. These schemas are distinct from legacy installed-file/link receipts:

* `mrk-cpython-source-root-request-1`: fixed authenticated D4 member correspondence,
  existing 151-package selection and exactly60 retained decoded streams (base
  plus59 additions). `materialize_source_root(REQUEST, ROOT, REPORT)` is closed
  until its distinct DATA/command review selects the request hash. Transported
  selection is the exact150507-byte public projection `9166c3b1…83ea4`: only nine
  private diagnostic path keys become fixed public role aliases; all twelve
  diagnostic hashes and every package/source/artifact field are unchanged.
* `mrk-cpython-source-rootfs-1`: all copied member/archive origins and aliases,
  generated root configuration, deterministic omissions and complete151/85/267
  package/source/artifact correspondence. D4's original `expected-members.json`
  (`a9ddc292…d13a9`) is DATA only and stays byte-identical with its original
  `ccff4af9…14fd` selection lineage. Root provenance records both public
  `selectionSha256` and distinct `memberSelectionLineageSha256`; it never relabels
  original lineage as transported bytes. Selected member reads are at most1MiB
  each with exact size/EOF; complete archive hashes/fanout/trailer rules remain.
  No live D4 tree, maintainer scripts, set-ID or
  device restoration, fabricated dpkg state or relocated Perl bootstrap.
  File aliases are independent ordinary copies; confined directory aliases are
  relative symlinks. Omit Python caches, ld.so.cache/preload and package database
  state; use fixed hosts/resolv/nsswitch text. Fixed empty `dev`, `proc`, `work`
  mountpoint directories are generated, counted, read back and explicitly
  recorded in `generatedDirectories` before the existing0555 final directory
  modes. No tmp/sys scaffold or mount is added. Modes alone do not enforce a
  read-only mount or qualify this interpreter/compiler/Perl/loader namespace.
* `mrk-cpython-source-lock-1`: literal configuration/environment, four source
  archives, their authenticated ordinary inventories, recipe source files,
  root report, host inputs and actual current whole-core N+8
  roster (six bootstraps, prepare_runtime and the fixed CA). Source inventories
  have `files` rows `{path,size,sha256,mode}`. CPython3.14.7, zlib1.3.2,
  libffi3.4.8, OpenSSL3.5.8, epoch1785925789 and CA `9cc2a774…30f` stay fixed.
  Neither A nor E is in this input-only lock.
* `mrk-cpython-source-phase-1`: original argv/cwd/environment digest, common
  deadline/timestamps, original exit code (null for DATA), original separate
  stdout/stderr and checked configuration/generated-file references. No link ID.
* `mrk-cpython-source-result-1`: fourteen original phase references, original
  input/root hashes, prerequisite `executionReviewSha256` and projection digest,
  written after cancellation restoration.
  Its meaning is only `mandatory-work-complete`, not original outer-owner finality.
* `mrk-cpython-source-output-1`: result reference and exact stage files,
  directories, source/build origins, modes and deterministic original omissions.
* `mrk-cpython-source-components-1`: complete85-source/151-package classification
  and exact version/patch artifacts, six native source scopes, conservative union
  coverage for all three native outputs, full retained evidence inventory,
  independent `configurationReview` and `obligationReview`, accepted notice hash,
  `SOURCE-AVAILABILITY.txt`, and `bundledExpatNotice` binding the exact1144-byte
  `Python-3.14.7/Modules/expat/COPYING` to its public notice size/hash. These review
  files and notice artifacts are the independently accepted, committed A inputs,
  not generated approval or product qualification.

Potential incorporation explicitly covers GCC13, GCC14 runtime/startup/header
components, glibc, Linux UAPI and libxcrypt as well as CPython/HACL/internal Expat,
zlib/libffi/OpenSSL. Build-only tools are not claimed as shipped executables.
File-scoped exceptions, other copyrights, exact upstream/Ubuntu patches and
source-availability/LGPL relinking-or-suitable-dynamic-link conditions remain
required for distribution; current acceptance is limited to nonproduction A/B
verification. A runtime exception is never a blanket license bypass.
No source artifacts or public notices are fabricated by this implementation.

## Projection, copy and remaining gates

Original Python -> `python/bin/python3`0755; original OpenSSL DSOs -> `python/lib/`
0644; authenticated `Lib/**/*.py` -> installed stdlib; actual confined
`pybuilddir.txt`-named sysconfig Python/JSON/build-details -> the same stdlib;
exact LICENSE -> `python/LICENSE.txt`. Two fixed landmarks complete the stage.
Six original OpenSSL projections cover the normal Python/bootstrap/freezer paths.
Do not rewrite generated configuration paths to pretend relocation succeeded.

Omit test/ensurepip/idlelib/turtledemo/venv/site-packages/Tk/turtle, non-Python
stdlib data, bytecode/caches and all development/build-tree outputs. Record
original Lib omissions. An unexpected native Python output refuses; it is never
hidden by pruning. Original objects/archives remain in the build for review.

`prepare_cpython_source_payload.py` accepts only fixed input/output/report paths.
The separate literal source policy requires independently accepted output,
component and notice hashes before any caller path access. It reuses the bounded
copier, notice union, sentinel/report/readback and existing limits; source origins
never say installed-file, originalLinkId or supplier strip attestation. Notices
are added only here. Current generic prepare_runtime remains unchanged and adds
six bootstraps +core.zip +CA and the manifest: reserve eight files/nine entries,
64 MiB headroom, unchanged2048/8192/512 MiB-file/1 GiB-total/1 MiB-manifest limits.

Remaining sequence: focused A literal/input DATA checks and independent diff
acceptance -> original offline copier/generic preparation A -> independent A
artifact acceptance -> separate B pin and bootstrap smoke -> actual installed
custody/loader/TLS/XML/API/cancellation/close qualification. Reuse the unchanged
source-bound publisher/route tests and successful H build; do not rerun them for
this DATA admission. No full-repository/native matrix is proposed here.
