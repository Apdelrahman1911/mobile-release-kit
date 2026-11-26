# Reconstructing the hosted verification components

Profile: `cpython-3.14.7-linux-x86_64-source-v1`.

This guide covers the interpreter, its selected standard library and the two
private OpenSSL libraries in a **completed** `hosted-evidence.tar`. It describes
ordinary recipient-controlled source builds, including use with an
interface-compatible modified glibc. It does not describe an application
installer, core ZIP, product manifest, signing workflow or production admission.
Do not import the gated production preparers or disable their checks to follow
this guide. No publisher credentials are needed for this personal source route.

The applicable component licenses permit their respective uses and changes.
Mobile Release Kit imposes no restriction on modifying this artifact for your
own use or on reverse engineering for debugging those modifications. See
`00-RUNTIME-NOTICE.txt`, `34-LGPL-2.1.txt`, the file-scoped notices and
`MOBILE-RELEASE-KIT-LICENSE.txt`. The chosen route remains LGPL-2.1 section
6(a)/(d); this guide does not substitute an unverified section 6(b) claim.

These instructions are not a report of a successful modified build. Match them
to the actual retained records before relying on an individual artifact. Missing
source, inconsistent configuration or unusable instructions are defects to
report, not evidence of success or permission to bypass production controls.

## 1. What is where

Paths in this table are relative to the unpacked archive:

| Material | Path |
| --- | --- |
| Four original native sources | `inputs/archives/{cpython,libffi,openssl,zlib}.archive` |
| glibc upstream, Ubuntu packaging/patches, `.dsc`, signature | `recipient/sources/glibc_2.39*` |
| Notices, this guide, toolkit license | `recipient/notices/` |
| Text roster and exact glibc source pins | `controls/recipient-materials.json` |
| Native source pins, empty upstream patch lists, configuration and environment | `controls/source-lock.json` |
| Source inventories and build-root/tool package identities | `controls/*-source-inventory.json`, `controls/rootfs.json`, `controls/host-inputs.json`, `controls/selection.json` |
| Recipe and its helper sources | `recipe/` |
| Fixed builtin/disabled module selection | `recipe/cpython_source_setup.local` |
| Original configure/make records and streams | `work/receipts/<phase>.json`, `.stdout`, `.stderr` |
| Original configuration | `configuration/{cpython,openssl,libffi,zlib}/` |
| Original ordinary object/archive material | `objects/{cpython,openssl,libffi,zlib}/` |
| Original files used in the projection | `originals/build/`, `originals/inputs/sources/` |
| Generated-file origins and the exact projection/omissions | `work/receipts/source-projection.json` |
| Native/stdlib projection | `work/stage/python/` |
| Pinned original toolkit, owner and bootstrap **source** | `inputs/core-source/<repository-relative-path>` |
| Unchanged public CA data | `controls/github-ca.pem` |

`retained-files.json`, supplied beside the tar, lists its actual members, sizes
and SHA256 values. The original outcome is in `work/receipts/source-result.json`
and the associated phase/output records. Source/helper availability is not a
claim that a production recipe can be run outside its admitted environment.
The core sources are included for reconstruction and inspection; they are not
an installed application, prepared runtime, product manifest or core ZIP.
Controller bubblewrap binaries are not part of these recipient materials.

The sources are CPython 3.14.7 (including its HACL/KaRaMeL and Expat 2.8.2
subtrees), libffi 3.4.8, zlib 1.3.2 and OpenSSL 3.5.8. The four native upstream
patch lists are empty. The separate `Modules/Setup.local`, configure choices,
generated configuration and projection are the local build changes. glibc is
the selected Ubuntu source package 2.39-0ubuntu8.9: its packaging tar contains
distribution changes in addition to the upstream 2.39 archive. The hosted
recipe does not build or decode that recipient source set.

## 2. Check inputs and prepare a private build environment

Authenticate the distribution through your chosen trusted channel; hashes
inside an artifact alone do not authenticate its publisher. Check any supplied
outer archive digest and member inventory, inspect paths, then unpack to a
private directory using your normal archive tools. Keep the original artifact
unchanged. Set `BUNDLE` to its absolute unpacked path, outside `/work`.

The following check reads data only and verifies the native archives and the
recipient files against their retained controls. Run it with your host Python,
not the newly built interpreter:

```bash
export BUNDLE=/absolute/path/to/unpacked-artifact
python3 -I -S -B - "$BUNDLE" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
lock = json.loads((root / 'controls/source-lock.json').read_bytes())
materials = json.loads((root / 'controls/recipient-materials.json').read_bytes())
def check(path, size, sha):
    assert path.is_file() and not path.is_symlink(), path
    data = path.read_bytes()
    assert len(data) == size and hashlib.sha256(data).hexdigest() == sha, path
assert {s['id'] for s in lock['sources']} == {'cpython', 'libffi', 'openssl', 'zlib'}
for source in lock['sources']:
    pin = source['archive']
    check(root / 'inputs/archives' / (source['id'] + '.archive'), pin['size'], pin['sha256'])
for row in materials['texts']:
    assert Path(row['path']).name == row['path']
    check(root / 'recipient/notices' / row['path'], row['size'], row['sha256'])
for row in materials['sourceArchives']:
    assert Path(row['path']).name == row['path']
    pin = row['transport']
    check(root / 'recipient/sources' / row['path'], pin['bytes'], pin['sha256'])
print('Supplied source/recipient bytes match the retained controls.')
PY
```

Use a disposable Linux x86_64 VM/container with a **new, empty `/work` writable
by your ordinary user**, enough RAM/disk for the source builds, and no publisher
secrets. Do not build as root or overwrite the host's libc. The original root
uses Ubuntu 24.04-family packages, GCC/G++ 13, GNU binutils and make, dash, Perl,
host Python 3.12, libc development headers and Linux UAPI headers. Exact selected
package/tool identities are retained in the controls; use those versions when
comparing original behavior. Normal extraction utilities, Bash, coreutils and
xz/gzip are also needed for these examples. Install prerequisites through your
own environment-management process, not through the publisher's gated recipe.
A different toolchain may produce different bytes or require separate diagnosis.

The commands below deliberately keep the recorded `/work` paths. They are
Bash examples; stop at any failed command and keep its actual output/status.
They do not manufacture original H receipts or reproduce H's security domain.

```bash
set -euo pipefail
test -d /work && test -w /work
test -z "$(find /work -mindepth 1 -maxdepth 1 -print -quit)"
umask 077
mkdir /work/inputs /work/inputs/sources /work/build /work/deps \
      /work/stage /work/receipts /work/home /work/tmp
for id in cpython libffi openssl zlib; do
    mkdir "/work/inputs/sources/$id" "/work/build/$id"
done
tar --extract --xz --file "$BUNDLE/inputs/archives/cpython.archive" \
    --strip-components=1 --no-same-owner --no-same-permissions \
    --directory /work/inputs/sources/cpython
for id in libffi openssl zlib; do
    tar --extract --gzip --file "$BUNDLE/inputs/archives/$id.archive" \
        --strip-components=1 --no-same-owner --no-same-permissions \
        --directory "/work/inputs/sources/$id"
done
cp -a /work/inputs/sources/zlib/. /work/build/zlib/
cp -a /work/inputs/sources/openssl/. /work/build/openssl/
mkdir /work/build/cpython/Modules
cp "$BUNDLE/recipe/cpython_source_setup.local" /work/build/cpython/Modules/Setup.local
```

zlib and OpenSSL build in copied source trees. libffi and CPython build out of
tree. Do not reuse partial build directories or mix old objects into this source
route. If deliberately changing a component, retain your changes separately and
start a fresh personal build rather than editing the original supplied archive.

## 3. Rebuild the four native sources

The table in `recipe/cpython_source_recipe.py::fixed_phases()` defines the 14
original phases. Its configure/make constants and environment are also readable
as data in `controls/source-lock.json`; you need not import either helper.
The following commands implement those build choices using ordinary tools.
The shell adds its own bookkeeping environment, so this is not a claim of an
identical H environment hash or byte-for-byte reproducibility.

```bash
env -i PATH=/usr/bin:/bin HOME=/work/home TMPDIR=/work/tmp \
  LC_ALL=C.UTF-8 TZ=UTC CONFIG_SITE=/dev/null \
  PYTHONDONTWRITEBYTECODE=1 PYTHONSTRICTEXTENSIONBUILD=1 PYTHON_COLORS=0 \
  SOURCE_DATE_EPOCH=1785925789 CONFIG_SHELL=/usr/bin/dash \
  CC=/usr/bin/x86_64-linux-gnu-gcc-13 CXX=/usr/bin/x86_64-linux-gnu-g++-13 \
  AR=/usr/bin/x86_64-linux-gnu-ar RANLIB=/usr/bin/x86_64-linux-gnu-ranlib \
  LD=/usr/bin/x86_64-linux-gnu-ld.bfd MAKE=/usr/bin/make PERL=/usr/bin/perl \
  /bin/bash --noprofile --norc <<'BUILD'
set -euo pipefail
base_cflags='-O2 -g0 -march=x86-64 -mtune=generic'
export CFLAGS="$base_cflags -fPIC"

# zlib-configure, zlib-build, zlib-install
cd /work/build/zlib
/usr/bin/dash ./configure --static --prefix=/work/deps
/usr/bin/make -j1
/usr/bin/make -j1 install

# libffi-configure, libffi-build, libffi-install
cd /work/build/libffi
/usr/bin/dash /work/inputs/sources/libffi/configure \
  --disable-shared --enable-static --with-pic --disable-docs \
  --disable-multi-os-directory --prefix=/work/deps --libdir=/work/deps/lib
/usr/bin/make -j1
/usr/bin/make -j1 install

# openssl-configure, openssl-build, openssl-install
cd /work/build/openssl
/usr/bin/perl ./Configure linux-x86_64 shared no-module no-dso no-engine \
  no-autoload-config no-legacy no-tests --prefix=/work/deps --libdir=lib \
  --openssldir=/nonexistent/mobile-release-kit/openssl
/usr/bin/make -j1 "LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'\$\$ORIGIN'" build_libs
/usr/bin/make -j1 "LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'\$\$ORIGIN'" install_dev

# openssl-layout: preserve built bytes in the same three locations.
export CFLAGS="$base_cflags"
for directory in /work/build/cpython/lib /work/build/lib /work/stage/python/lib; do
    mkdir -p "$directory"
    for name in libcrypto.so.3 libssl.so.3; do
        cmp "/work/build/openssl/$name" "/work/deps/lib/$name"
        install -m 644 "/work/build/openssl/$name" "$directory/$name"
    done
done

# python-configure
export CPPFLAGS=-I/work/deps/include LDFLAGS=-L/work/deps/lib
export ZLIB_CFLAGS=-I/work/deps/include ZLIB_LIBS=/work/deps/lib/libz.a
export LIBFFI_CFLAGS=-I/work/deps/include LIBFFI_LIBS=/work/deps/lib/libffi.a
cd /work/build/cpython
/usr/bin/dash /work/inputs/sources/cpython/configure \
  --prefix=/opt/mrk-python --with-platlibdir=lib --disable-shared \
  --without-mimalloc --with-pymalloc --with-lto=no --disable-optimizations \
  --disable-test-modules --with-ensurepip=no --with-pkg-config=no \
  --with-builtin-hashlib-hashes=md5,sha1,sha2,sha3,blake2 \
  --with-openssl=/work/deps --with-openssl-rpath=no \
  --with-ssl-default-suites=python --without-system-expat
py_make_args=(
  "LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'\$\$ORIGIN/../lib'"
  'PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B'
  'PYTHON_FOR_FREEZE=./_bootstrap_python -B'
)

# builtin-archives: all six HACL archives and the bundled Expat archive.
/usr/bin/make -j1 "${py_make_args[@]}" \
  Modules/_hacl/libHacl_Hash_MD5.a Modules/_hacl/libHacl_Hash_SHA1.a \
  Modules/_hacl/libHacl_Hash_SHA2.a Modules/_hacl/libHacl_Hash_SHA3.a \
  Modules/_hacl/libHacl_Hash_BLAKE2.a Modules/_hacl/libHacl_HMAC.a \
  Modules/expat/libexpat.a

# python-build: include the real module checks and generated build details.
/usr/bin/make -j1 "${py_make_args[@]}" \
  python platform checksharedmods build-details.json
BUILD
```

Do not omit `checksharedmods`, supply fake generated sysconfig files, ignore a
failed generator, strip/relink the originals after the fact, or run upstream
`altinstall`, `libinstall` or `compileall` for this projection. Configuration
differences should be understood using the retained `Makefile`, `pyconfig.h`,
`Modules/config.c`, `Modules/Setup.*`, config logs, OpenSSL `configdata.pm` and
headers. The retained per-phase streams show original argv outcomes; the
presence of a binary alone does not prove all mandatory work succeeded.

## 4. Project and use your personal native build

`python-project` is a data-copy phase, not another compiler command. The
following host-Python example applies the fixed source-stdlib omission rule and
copies your newly generated files, not the artifact's old generated outputs.
It is ordinary personal staging, not a production copier/admission bypass.

```bash
python3 -I -S -B - <<'PY'
import re, shutil
from pathlib import Path
src = Path('/work/inputs/sources/cpython')
build = Path('/work/build/cpython')
out = Path('/work/stage/python')
def copy(source, relative, mode=0o644):
    target = out / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)
libraries = {'libcrypto.so.3', 'libssl.so.3'}
for path in build.rglob('*'):
    name = path.name
    if path.is_file() and (name.endswith(('.so', '.dll', '.dylib', '.pyd')) or '.so.' in name):
        assert path.parent == build / 'lib' and name in libraries, path
copy(build / 'python', 'bin/python3', 0o755)
for name in sorted(libraries):
    copy(Path('/work/build/openssl') / name, 'lib/' + name)
excluded = {'test', 'ensurepip', 'idlelib', 'turtledemo', 'venv',
            'site-packages', 'tkinter', 'turtle.py'}
for path in sorted((src / 'Lib').rglob('*')):
    assert not path.is_symlink(), path
    if not path.is_file():
        continue
    relative = path.relative_to(src / 'Lib')
    leaf = relative.name
    assert not (leaf.endswith(('.so', '.dll', '.dylib', '.pyd')) or '.so.' in leaf), path
    if '__pycache__' in relative.parts or leaf.endswith(('.pyc', '.pyo')):
        continue
    if relative.parts[0] in excluded or not leaf.endswith('.py'):
        continue
    assert not leaf.startswith(('_sysconfigdata_', '_sysconfig_vars_')), path
    copy(path, 'lib/python3.14/' + relative.as_posix())
copy(src / 'LICENSE', 'LICENSE.txt')
generated = (build / 'pybuilddir.txt').read_text(encoding='ascii')
assert re.fullmatch(r'build/[A-Za-z0-9._+\-]+\n', generated), generated
assert '..' not in generated.strip().split('/')
for name in ('_sysconfigdata__linux_x86_64-linux-gnu.py',
             '_sysconfig_vars__linux_x86_64-linux-gnu.json', 'build-details.json'):
    copy(build / generated.strip() / name, 'lib/python3.14/' + name)
(out / 'lib/python314.zip').write_bytes(b'PK\x05\x06' + b'\0' * 18)
landmark = out / 'lib/python3.14/lib-dynload/README.mrk'
landmark.parent.mkdir(parents=True, exist_ok=True)
landmark.write_bytes(b'No shared extension modules are shipped in this profile.\n')
print('Personal projection:', out)
PY
```

Compare the file roster and intentional omissions with the original
`work/receipts/source-projection.json`. For an unchanged source selection the
paths should agree; changed build bytes are not expected to match old hashes.
If modifying Python's source/module selection as well, account explicitly for
any new source files or generated filenames instead of silently pruning them.
Retain this notice/source kit with any redistribution under the applicable
licenses; a personally staged directory is not automatically a compliant
product release.

For an initial personal check, outside the build tree:

```bash
cd /work
env -i PATH=/usr/bin:/bin HOME=/work/home LC_ALL=C.UTF-8 \
  /work/stage/python/bin/python3 -I -B -c \
  'import ssl, pyexpat, zlib, ctypes; print(ssl.OPENSSL_VERSION, pyexpat.EXPAT_VERSION, zlib.ZLIB_VERSION)'
```

Use this interpreter directly for your own programs. That requires no publisher
credentials and does not modify an installed product. This small import check
is not native TLS/XML/loader qualification, proof of all application API
behavior, or evidence that a different glibc was actually used.

## 5. A source-rebuild/relink route for modified glibc

The source alternative is intentional: it does not depend on guessing which
loose original objects to feed to a linker. Full source, original configuration,
generated inputs and original `.o/.a/.lo` files are available. Rebuilding the
four native sources regenerates their objects and final link commands using
your modified library's headers, startup objects and libraries. Do not combine
incompatible loader/libc versions or replace the operating system's libc.

In a separate disposable recipient environment, install the prerequisites for
the supplied glibc source package, including `dpkg-source` (dpkg-dev), GCC 13,
make, gawk, bison, Perl, Python, Linux headers and the usual GNU utilities. The
retained package's `debian/control` and upstream `INSTALL` document additional
version/build requirements. The following is an ordinary staged source build,
not a claim to reproduce the Ubuntu binary-package build configuration.

Choose a new absolute `G` path outside `/work`, without whitespace, quotes,
colons or commas for these simple wrapper examples. Keep it at the same path
when using its binaries. All four glibc files must remain together beside the
`.dsc`. `dpkg-source` unpacks the upstream and Debian source and applies the
selected distribution patch series; do not build a bare upstream tar while
claiming the selected Ubuntu source. Investigate any integrity/signature
diagnostic rather than silently disabling checking.

```bash
export G=/absolute/private/glibc-experiment
mkdir "$G"
cd "$G"
dpkg-source -x "$BUNDLE/recipient/sources/glibc_2.39-0ubuntu8.9.dsc" source
# Make your intended, interface-compatible source changes in "$G/source" now.
# Record the changes separately; leave the supplied archives unchanged.
mkdir "$G/build" "$G/sysroot"
cd "$G/build"
env CC=/usr/bin/x86_64-linux-gnu-gcc-13 \
  CXX=/usr/bin/x86_64-linux-gnu-g++-13 \
  libc_cv_slibdir=/usr/lib libc_cv_rtlddir=/usr/lib \
  "$G/source/configure" --prefix=/usr --libdir=/usr/lib --with-headers=/usr/include
make -j1
# Run and inspect the appropriate glibc checks for your modifications.
make -j1 install install_root="$G/sysroot"
```

`install_root` stages the installation under your private directory; it is not
an instruction to install over `/usr`. Check the installed layout and do not
continue if the following required files are missing:

```bash
test -f "$G/sysroot/usr/lib/ld-linux-x86-64.so.2"
test -f "$G/sysroot/usr/lib/libc.so.6"
test -f "$G/sysroot/usr/lib/libc_nonshared.a"
test -f "$G/sysroot/usr/lib/crti.o"
test -f "$G/sysroot/usr/lib/crtn.o"
test -f "$G/sysroot/usr/include/stdio.h"
```

Complete the development sysroot with the matching Linux UAPI headers used by
your build environment. On the stated Ubuntu x86_64 layout, those header trees
are `/usr/include/linux`, `/usr/include/asm-generic` and
`/usr/include/x86_64-linux-gnu/asm`:

```bash
cp -a /usr/include/linux /usr/include/asm-generic "$G/sysroot/usr/include/"
cp -a /usr/include/x86_64-linux-gnu/asm "$G/sysroot/usr/include/"
```

If your environment uses a different header layout, install its matching UAPI
headers into the sysroot instead; do not copy the host's libc headers over your
modified ones. Preserve the applicable header notices. GCC's own internal
headers, runtime support and tools remain compiler prerequisites, not files
claimed to be rebuilt by the glibc example.

For a personal native rebuild, use compiler wrappers that explicitly select
the new sysroot, startup objects, loader and runtime library directory. The
absolute runtime path here is a deliberate **recipient modification**, not the
publisher profile's original relative-only RUNPATH claim:

```bash
for role in cc cxx; do
    compiler=/usr/bin/x86_64-linux-gnu-gcc-13
    if [ "$role" = cxx ]; then compiler=/usr/bin/x86_64-linux-gnu-g++-13; fi
    cat > "$G/$role" <<EOF
#!/bin/sh
exec '$compiler' --sysroot='$G/sysroot' -B'$G/sysroot/usr/lib/' \\
  -Wl,--dynamic-linker='$G/sysroot/usr/lib/ld-linux-x86-64.so.2' \\
  -Wl,-rpath,'$G/sysroot/usr/lib' "\$@"
EOF
    chmod 700 "$G/$role"
done
for name in crt1.o Scrt1.o crti.o crtn.o libc_nonshared.a; do
    "$G/cc" -print-file-name="$name"
done
```

Verify those glibc startup/nonshared paths resolve inside `$G/sysroot`; if not,
fix the development sysroot before building. GCC's `crtbegin`/`crtend` and
libgcc support are separate compiler inputs. Inspect actual final link commands
and loader resolution as well; a wrapper name alone proves nothing.

Repeat sections 2-4 in a **fresh empty `/work`**, using a VM/container where
`$G` remains accessible at that exact path. In section 3's `env -i` command,
replace only the `CC=... CXX=...` assignments with `CC="$G/cc" CXX="$G/cxx"`.
Keep the dependency/include/static-library flags, builtin selection, OpenSSL
layout and make assignments. The wrappers supply the modified libc compile/
link choices to configure probes, bootstrap programs and final links. This
ordinary personal build does not call, impersonate or weaken H's production
admission. Preserve the new generated files and logs rather than labeling them
as original publisher evidence.

Check your loader's actual resolution, then use the resulting components with
the same modified loader and its library directory, for example:

```bash
env -i PATH=/usr/bin:/bin HOME=/work/home LC_ALL=C.UTF-8 \
  "$G/sysroot/usr/lib/ld-linux-x86-64.so.2" \
  --library-path "$G/sysroot/usr/lib:/work/stage/python/lib" \
  --list /work/stage/python/bin/python3
env -i PATH=/usr/bin:/bin HOME=/work/home LC_ALL=C.UTF-8 \
  "$G/sysroot/usr/lib/ld-linux-x86-64.so.2" \
  --library-path "$G/sysroot/usr/lib:/work/stage/python/lib" \
  /work/stage/python/bin/python3 -I -B -c \
  'import ssl, pyexpat, zlib, ctypes; print(ssl.OPENSSL_VERSION, pyexpat.EXPAT_VERSION, zlib.ZLIB_VERSION)'
```

Confirm that libc, libm and the loader resolve to the intended modified build,
and that both OpenSSL libraries resolve to your new private build. Do not
accept an unintended host-library fallback as a successful modified-library
test. Run the behavioral checks appropriate to your changes and retain actual
failures; these examples do not promise arbitrary ABI-breaking changes work.

Nothing here asserts that a modified build/relink/use demonstration has already
run, that every source/object/license correspondence is settled, or that any
native component is qualified for Desktop/product distribution. Product-specific
bootstrap preparation, manifest authentication, installation and signing remain
separate and unchanged.
