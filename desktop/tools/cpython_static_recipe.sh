#!/bin/sh
# SOURCE-ONLY until this exact recipe, sealed inputs and execution envelope are reviewed.
# Invoke with the pinned shell: RECIPE ABSOLUTE_HOST_PYTHON LOCK LOCK_SHA256.
# Start via the admitted clean environment; input validation rejects inherited extras.
# No download/package install/test/native qualification or automatic cleanup/retry.
set -eu
umask 077
[ "$#" -eq 3 ] || { printf '%s\n' 'Expected HOST_PYTHON LOCK LOCK_SHA256' >&2; exit 64; }
HOST_PYTHON=$1
LOCK=$2
LOCK_SHA256=$3
case "$0:$HOST_PYTHON:$LOCK" in /*:/*:/*) ;; *) exit 64 ;; esac
TOOLS=${0%/*}
"$HOST_PYTHON" -I -S -B "$TOOLS/cpython_static_inputs.py" materialize "$LOCK" "$LOCK_SHA256"
# Fixed, newly created, quoted assignments only; never source caller-supplied shell text.
. /work/build-env.sh

phase() {
    MRK_PHASE=$1
    export MRK_PHASE
    shift
    if "$@" >"/work/receipts/$MRK_PHASE.log" 2>&1; then status=0; else status=$?; fi
    "$HOST_PYTHON" -I -S -B "$MRK_TOOLS/cpython_static_inputs.py" phase \
        "$MRK_LOCK" "$MRK_LOCK_SHA256" "$MRK_PHASE" "$status"
}

BASE_CFLAGS=$CFLAGS
cd /work/build/zlib
CFLAGS="$BASE_CFLAGS -fPIC"; export CFLAGS
phase zlib-configure ./configure --static --prefix=/work/deps
phase zlib-build "$MAKE" -j1
phase zlib-install "$MAKE" -j1 install

cd /work/build/libffi
phase libffi-configure /work/inputs/sources/libffi/configure \
    --disable-shared --enable-static --with-pic --disable-docs \
    --disable-multi-os-directory --prefix=/work/deps --libdir=/work/deps/lib
phase libffi-build "$MAKE" -j1
phase libffi-install "$MAKE" -j1 install

cd /work/build/cpython
CFLAGS=$BASE_CFLAGS
CPPFLAGS=-I/work/deps/include
LDFLAGS=-L/work/deps/lib
ZLIB_CFLAGS=-I/work/deps/include
ZLIB_LIBS=/work/deps/lib/libz.a
LIBFFI_CFLAGS=-I/work/deps/include
LIBFFI_LIBS=/work/deps/lib/libffi.a
export CFLAGS CPPFLAGS LDFLAGS ZLIB_CFLAGS ZLIB_LIBS LIBFFI_CFLAGS LIBFFI_LIBS
phase python-configure /work/inputs/sources/cpython/configure \
    --prefix=/opt/mrk-python --with-platlibdir=lib --disable-shared \
    --without-mimalloc --with-pymalloc --with-lto=no --disable-optimizations \
    --disable-test-modules --with-ensurepip=no --with-pkg-config=no \
    --with-builtin-hashlib-hashes=md5,sha1,sha2,sha3,blake2
# Literal Setup .a operands, not shared-default loose HACL object lists.
phase hacl-build "$MAKE" -j1 Modules/_hacl/libHacl_Hash_MD5.a \
    Modules/_hacl/libHacl_Hash_SHA1.a Modules/_hacl/libHacl_Hash_SHA2.a \
    Modules/_hacl/libHacl_Hash_SHA3.a Modules/_hacl/libHacl_Hash_BLAKE2.a \
    Modules/_hacl/libHacl_HMAC.a
# C1: the validated environment explicitly retains PYTHONSTRICTEXTENSIONBUILD=1.
phase python-build "$MAKE" -j1
phase python-install "$MAKE" -j1 altinstall DESTDIR=/work/stage COMPILEALL_OPTS=-j1
printf '%s\n' 'Build commands returned; retain /work. Original outputs/receipts still require independent review.'
