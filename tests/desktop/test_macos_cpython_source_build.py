"""Focused DATA/filesystem contracts; never launch a compiler/native/process test.

Run only through the admitted test owner. Synthetic archives are small ordinary
files in a test-owned TemporaryDirectory; no upstream archive, network, command,
tool/SDK discovery, source build or supplier activation occurs here.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch
import zlib


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILD = load("_mrk_darwin_build_test_data", "macos_cpython_source_build.py")
PROBE = load("_mrk_darwin_probe_test_data", "macos_cpython_source_probe.py")


@contextmanager
def scratch():
    with tempfile.TemporaryDirectory(prefix="mrk-darwin-source-data-") as name:
        path = Path(name)
        try:
            yield path
        finally:
            # Only this original test directory, never a project/cache path.
            for directory, children, _ in os.walk(path, followlinks=False):
                os.chmod(directory, 0o700)
                for child in children:
                    selected = Path(directory) / child
                    if not selected.is_symlink():
                        os.chmod(selected, 0o700)


def make_configuration(exe=".exe", multiarch="darwin", target=BUILD.ARM_TARGET):
    prefix, sdk = Path("/private/task/prefix"), Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")
    values = {
        "BUILDEXE": exe, "BUILDPYTHON": "python$(BUILDEXE)", "VERSION": "3.14", "MACHDEP": "darwin",
        "ABIFLAGS": "", "PY_ENABLE_SHARED": "0", "CC": "/Apple/clang", "PYTHON_FOR_REGEN": "/chosen/python3",
        "LIBEXPAT_A": "Modules/expat/libexpat.a", "MODULE_ZLIB_LDFLAGS": str(prefix / "lib/libz.a"),
        "CONFIGURE_CFLAGS": BUILD.compiler_flags(sdk, target), "CONFIGURE_CPPFLAGS": "",
        "CONFIGURE_LDFLAGS": BUILD.linker_flags(sdk, target) + " -L" + str(prefix / "lib"),
        "MACOSX_DEPLOYMENT_TARGET": "26.0",
        "MODBUILT_NAMES": " ".join(BUILD.BOOTSTRAP + BUILD.OPTIONAL), "MODSHARED_NAMES": "",
        "MODDISABLED_NAMES": " ".join(BUILD.DISABLED),
        "MODULE__CTYPES_CFLAGS": "-fno-strict-overflow -I" + str(sdk / "usr/include/ffi") + " -DUSING_APPLE_OS_LIBFFI=1 -DUSING_MALLOC_CLOSURE_DOT_C=1",
        "MODULE__CTYPES_LDFLAGS": "-lffi -ldl",
        "MODULE_PYEXPAT_CFLAGS": "-I$(srcdir)/Modules/expat",
        "MODULE_PYEXPAT_LDFLAGS": "-lm $(LIBEXPAT_A)",
        "MODULE__SCPROXY_LDFLAGS": "-framework SystemConfiguration -framework CoreFoundation",
        "MODULE__SSL_CFLAGS": "-I" + str(prefix / "include"),
        "MODULE__SSL_LDFLAGS": "-L" + str(prefix / "lib") + " -lssl -lcrypto", "MULTIARCH": multiarch,
    }
    required = "WITH_PYMALLOC HAVE_FORK HAVE_POSIX_SPAWN HAVE_SYS_RESOURCE_H HAVE_WAITPID HAVE_POLL HAVE_SOCKETPAIR HAVE_FFI_PREP_CIF_VAR HAVE_FFI_PREP_CLOSURE_LOC HAVE_FFI_CLOSURE_ALLOC".split()
    setup = (ROOT / "desktop/tools/macos_cpython_source_setup.local").read_bytes().replace(b"@MRK_PREFIX@", str(prefix).encode())
    names = BUILD.BOOTSTRAP + BUILD.INTRINSIC + BUILD.OPTIONAL
    files = {"Makefile": "".join(key + ("?=" if key == "PYTHON_FOR_REGEN" else "=") + value + "\n" for key, value in values.items()).encode(),
        "pyconfig.h": "".join("#define " + key + " 1\n" for key in required).encode(),
        "Modules/config.c": ("struct _inittab _PyImport_Inittab[] = {\n" +
            "".join('{"' + name + '", init_' + name + "},\n" for name in names) + "{0, 0}\n};\n").encode(),
        "Modules/Setup.local": setup}
    return files, prefix, sdk


def observed_arm_configuration():
    """Inert projection of authenticated configure DATA from Mac run37446199359.

    Contains every input inspected by python_configuration, not whole generated
    files or native evidence. Only four exact original path roles were replaced.
    """
    # Makefile original SHA256 69420c6d89d849fb1a9962612f3ea63aa219a0011da1a35a597e141816c073bb
    # pyconfig.h original SHA256 9c567e7631b61240ec54ad6c4c342e59cabbf5881b8b441c13041102aaa703c3
    # Modules/config.c original SHA256 e91b4ccd432e9be378ee78bb96c2b059e22671b5c41c568480720727426151e2
    # Modules/Setup.local original SHA256 6df2c728221d3941337531dfe9b048eaaf269d9a1046cc799014a0a514428796
    files = {
        'Makefile': b"""MODBUILT_NAMES=      _bisect  _heapq  _json  _random  _struct  math  binascii  zlib  fcntl  _posixsubprocess  select  unicodedata  _ctypes  _socket  _ssl  pyexpat  resource  _scproxy  _md5  _sha1  _sha2  _sha3  _blake2  _hmac  atexit  faulthandler  posix  _signal  _tracemalloc  _suggestions  _datetime  _codecs  _collections  errno  _io  itertools  _sre  _sysconfig  _thread  time  _types  _typing  _weakref  _abc  _functools  _locale  _opcode  _operator  _stat  _symtable  pwd
MODSHARED_NAMES=   
MODDISABLED_NAMES=   _asyncio  _bz2  _codecs_cn  _codecs_hk  _codecs_iso2022  _codecs_jp  _codecs_kr  _codecs_tw  _csv  _ctypes_test  _curses  _curses_panel  _dbm  _decimal  _elementtree  _gdbm  _hashlib  _interpchannels  _interpqueues  _interpreters  _lsprof  _lzma  _multibytecodec  _multiprocessing  _pickle  _posixshmem  _queue  _remote_debugging  _sqlite3  _statistics  _testbuffer  _testcapi  _testclinic  _testclinic_limited  _testimportmultiple  _testinternalcapi  _testlimitedcapi  _testmultiphase  _testsinglephase  _tkinter  _uuid  _xxtestfuzz  _zoneinfo  _zstd  array  cmath  grp  mmap  readline  syslog  termios  xxlimited  xxlimited_35  xxsubtype
VERSION=	3.14
CC=		/Apple/clang
ABIFLAGS=	
CONFIGURE_CFLAGS=	-O2 -g0 -fPIC -arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0
CONFIGURE_CPPFLAGS=	
CONFIGURE_LDFLAGS=	-arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk -mmacosx-version-min=26.0 -L/private/task/prefix/lib
MACHDEP=	darwin
MULTIARCH=	darwin
BUILDEXE=	.exe
MACOSX_DEPLOYMENT_TARGET=26.0
LIBEXPAT_A= Modules/expat/libexpat.a
MODULE__SCPROXY_LDFLAGS=-framework SystemConfiguration -framework CoreFoundation
MODULE_PYEXPAT_CFLAGS=-I$(srcdir)/Modules/expat
MODULE_PYEXPAT_LDFLAGS=-lm $(LIBEXPAT_A)
MODULE__CTYPES_CFLAGS=-fno-strict-overflow -I/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk/usr/include/ffi -DUSING_APPLE_OS_LIBFFI=1 -DUSING_MALLOC_CLOSURE_DOT_C=1
MODULE__CTYPES_LDFLAGS=-lffi -ldl
MODULE_ZLIB_LDFLAGS=/private/task/prefix/lib/libz.a
MODULE__SSL_CFLAGS=-I/private/task/prefix/include
MODULE__SSL_LDFLAGS=-L/private/task/prefix/lib  -lssl -lcrypto
PY_ENABLE_SHARED=	0
BUILDPYTHON=	python$(BUILDEXE)
PYTHON_FOR_REGEN?=/chosen/python3
""",
        'pyconfig.h': b"""#define HAVE_FFI_CLOSURE_ALLOC 1
#define HAVE_FFI_PREP_CIF_VAR 1
#define HAVE_FFI_PREP_CLOSURE_LOC 1
#define HAVE_FORK 1
#define HAVE_POLL 1
#define HAVE_POSIX_SPAWN 1
#define HAVE_SOCKETPAIR 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_WAITPID 1
/* #undef Py_DEBUG */
/* #undef Py_ENABLE_SHARED */
/* #undef Py_GIL_DISABLED */
/* #undef Py_TRACE_REFS */
/* #undef WITH_MIMALLOC */
#define WITH_PYMALLOC 1
""",
        'Modules/config.c': b"""struct _inittab _PyImport_Inittab[] = {

    {"_bisect", PyInit__bisect},
    {"_heapq", PyInit__heapq},
    {"_json", PyInit__json},
    {"_random", PyInit__random},
    {"_struct", PyInit__struct},
    {"math", PyInit_math},
    {"binascii", PyInit_binascii},
    {"zlib", PyInit_zlib},
    {"fcntl", PyInit_fcntl},
    {"_posixsubprocess", PyInit__posixsubprocess},
    {"select", PyInit_select},
    {"unicodedata", PyInit_unicodedata},
    {"_ctypes", PyInit__ctypes},
    {"_socket", PyInit__socket},
    {"_ssl", PyInit__ssl},
    {"pyexpat", PyInit_pyexpat},
    {"resource", PyInit_resource},
    {"_scproxy", PyInit__scproxy},
    {"_md5", PyInit__md5},
    {"_sha1", PyInit__sha1},
    {"_sha2", PyInit__sha2},
    {"_sha3", PyInit__sha3},
    {"_blake2", PyInit__blake2},
    {"_hmac", PyInit__hmac},
    {"atexit", PyInit_atexit},
    {"faulthandler", PyInit_faulthandler},
    {"posix", PyInit_posix},
    {"_signal", PyInit__signal},
    {"_tracemalloc", PyInit__tracemalloc},
    {"_suggestions", PyInit__suggestions},
    {"_datetime", PyInit__datetime},
    {"_codecs", PyInit__codecs},
    {"_collections", PyInit__collections},
    {"errno", PyInit_errno},
    {"_io", PyInit__io},
    {"itertools", PyInit_itertools},
    {"_sre", PyInit__sre},
    {"_sysconfig", PyInit__sysconfig},
    {"_thread", PyInit__thread},
    {"time", PyInit_time},
    {"_types", PyInit__types},
    {"_typing", PyInit__typing},
    {"_weakref", PyInit__weakref},
    {"_abc", PyInit__abc},
    {"_functools", PyInit__functools},
    {"_locale", PyInit__locale},
    {"_opcode", PyInit__opcode},
    {"_operator", PyInit__operator},
    {"_stat", PyInit__stat},
    {"_symtable", PyInit__symtable},
    {"pwd", PyInit_pwd},

/* -- ADDMODULE MARKER 2 -- */

    /* This module lives in marshal.c */
    {"marshal", PyMarshal_Init},

    /* This lives in import.c */
    {"_imp", PyInit__imp},

    /* This lives in Python/Python-ast.c */
    {"_ast", PyInit__ast},

    /* This lives in Python/Python-tokenize.c */
    {"_tokenize", PyInit__tokenize},

    /* These entries are here for sys.builtin_module_names */
    {"builtins", NULL},
    {"sys", NULL},

    /* This lives in gcmodule.c */
    {"gc", PyInit_gc},

    /* This lives in Python/_contextvars.c */
    {"_contextvars", PyInit__contextvars},

    /* This lives in _warnings.c */
    {"_warnings", _PyWarnings_Init},

    /* This lives in Objects/unicodeobject.c */
    {"_string", PyInit__string},

    /* Sentinel */
    {0, 0}
};
""",
        'Modules/Setup.local': b"""# CPython 3.14.7 / macOS 26 ARM64 or x86_64. Not an execution grant.
# 24 optional + 27 bootstrap + 10 intrinsic; no shared extensions.
# /private/task/prefix is replaced only by the fixed private build prefix.
*static*
_bisect _bisectmodule.c
_heapq _heapqmodule.c
_json _json.c
_random _randommodule.c
_struct _struct.c
math mathmodule.c
binascii binascii.c $(MODULE_BINASCII_CFLAGS) /private/task/prefix/lib/libz.a
zlib zlibmodule.c $(MODULE_ZLIB_CFLAGS) /private/task/prefix/lib/libz.a
fcntl fcntlmodule.c
_posixsubprocess _posixsubprocess.c
select selectmodule.c
unicodedata unicodedata.c
# No explicit flags: retain Darwin's SDK ffi flags and system -lffi.
_ctypes _ctypes/_ctypes.c _ctypes/callbacks.c _ctypes/callproc.c _ctypes/stgdict.c _ctypes/cfield.c _ctypes/malloc_closure.c
_socket socketmodule.c
# AX_CHECK_OPENSSL checks the static-only prefix; final operands are explicit.
_ssl _ssl.c $(MODULE__SSL_CFLAGS) /private/task/prefix/lib/libssl.a /private/task/prefix/lib/libcrypto.a
# Retain configured internal Expat and Darwin framework flags.
pyexpat pyexpat.c
resource resource.c
_scproxy _scproxy.c
_md5 md5module.c $(MODULE__MD5_CFLAGS) Modules/_hacl/libHacl_Hash_MD5.a
_sha1 sha1module.c $(MODULE__SHA1_CFLAGS) Modules/_hacl/libHacl_Hash_SHA1.a
_sha2 sha2module.c $(MODULE__SHA2_CFLAGS) Modules/_hacl/libHacl_Hash_SHA2.a
_sha3 sha3module.c $(MODULE__SHA3_CFLAGS) Modules/_hacl/libHacl_Hash_SHA3.a
_blake2 blake2module.c $(MODULE__BLAKE2_CFLAGS) Modules/_hacl/libHacl_Hash_BLAKE2.a
_hmac hmacmodule.c $(MODULE__HMAC_CFLAGS) Modules/_hacl/libHacl_HMAC.a
*disabled*
_asyncio
_bz2
_codecs_cn
_codecs_hk
_codecs_iso2022
_codecs_jp
_codecs_kr
_codecs_tw
_csv
_ctypes_test
_curses
_curses_panel
_dbm
_decimal
_elementtree
_gdbm
_hashlib
_interpchannels
_interpqueues
_interpreters
_lsprof
_lzma
_multibytecodec
_multiprocessing
_pickle
_posixshmem
_queue
_remote_debugging
_sqlite3
_statistics
_testbuffer
_testcapi
_testclinic
_testclinic_limited
_testimportmultiple
_testinternalcapi
_testlimitedcapi
_testmultiphase
_testsinglephase
_tkinter
_uuid
_xxtestfuzz
_zoneinfo
_zstd
array
cmath
grp
mmap
readline
syslog
termios
xxlimited
xxlimited_35
xxsubtype
""",
    }
    return files, Path("/private/task/prefix"), Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")


def mach_o(*, dylib=b"/usr/lib/libSystem.B.dylib", minimum=26 << 16, extra=b"",
           cpu=0x100000C, subtype=0):
    def named(command, header_size, name):
        size = (header_size + len(name) + 1 + 7) & ~7
        head = struct.pack("<III", command, size, header_size)
        return head + b"\0" * (header_size - len(head)) + name + b"\0" * (size - header_size - len(name))

    commands = [named(0xE, 12, b"/usr/lib/dyld"), named(0xC, 24, dylib),
        struct.pack("<IIIIII", 0x32, 24, 1, minimum, 26 << 16, 0),
        struct.pack("<IIQQ", 0x80000028, 24, 0, 0),
        struct.pack("<IIII", 0x1D, 16, 0, 0)]
    if extra:
        commands.append(extra)
    body = b"".join(commands)
    return struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, subtype, 2, len(commands), len(body), 0, 0) + body


def archive_fixture(component="zlib", *, trailer=b"", compression_trailer=b"", body=b"public source\n"):
    prefix, logical = "Fixture-1", "/work/inputs/sources/" + component + "/"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in (prefix, prefix + "/Lib"):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(item)
        item = tarfile.TarInfo(prefix + "/Lib/source with spaces.py")
        item.size, item.mode, item.mtime = len(body), 0o644, 1700000000
        archive.addfile(item, io.BytesIO(body))
    raw = buffer.getvalue() + trailer
    compressed = (lzma.compress(raw) if component == "cpython" else gzip.compress(raw, mtime=0)) + compression_trailer
    source = SimpleNamespace(component=component, size=len(compressed), sha256=BUILD.digest(compressed), original_prefix=logical)
    rows = {"Lib/source with spaces.py": {"path": logical + "Lib/source with spaces.py", "size": len(body),
                                            "sha256": BUILD.digest(body), "mode": 0o644}}
    provenance = {"archiveRoot": prefix, "archive": {"size": len(compressed), "sha256": source.sha256},
        "decodedTar": {"size": len(raw), "sha256": BUILD.digest(raw)},
        "directories": [{"path": logical.rstrip("/")}, {"path": logical + "Lib"}],
        "modeProjection": {"directories": {str(0o755): 0o755}, "files": {str(0o644): 0o644}}}
    return source, compressed, rows, provenance


def parser_instance(path, source, rows, provenance):
    instance = BUILD.Build.__new__(BUILD.Build)  # No native host/owner acquisition.
    instance.private = path
    (path / "archives").mkdir(mode=0o700)
    (path / "sources").mkdir(mode=0o700)
    instance.check = lambda: None
    instance.deadline = time.monotonic() + 10
    instance.source_rows = {source.component: rows}
    instance.source_trees = {}
    instance.provenance = {source.component: provenance}
    return instance


class MacPythonSourceBuildTests(unittest.TestCase):
    def test_configuration_keeps_darwin_ffi_scproxy_static_archives_and_generated_names(self):
        for target in (BUILD.ARM_TARGET, BUILD.INTEL_TARGET):
            for suffix, multiarch in ((".exe", "darwin"), ("", "")):
                files, prefix, sdk = make_configuration(suffix, multiarch, target)
                result = BUILD.python_configuration(files, prefix, sdk, "/Apple/clang", "/chosen/python3", target)
                self.assertEqual(result["executable"], "python" + suffix)
                self.assertEqual(result["generated"], ["_sysconfigdata__darwin_" + multiarch + ".py",
                    "_sysconfig_vars__darwin_" + multiarch + ".json", "build-details.json"])
                self.assertEqual(len(result["builtins"]), 61)
            other = BUILD.INTEL_TARGET if target == BUILD.ARM_TARGET else BUILD.ARM_TARGET
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.python_configuration(files, prefix, sdk, "/Apple/clang", "/chosen/python3", other)
        files, prefix, sdk = make_configuration()
        mutations = [
            ("Makefile", b"BUILDEXE=.exe", b"BUILDEXE=/other/python"),
            ("Makefile", b"MODSHARED_NAMES=", b"MODSHARED_NAMES=_ssl"),
            ("Makefile", b"-DUSING_APPLE_OS_LIBFFI=1", b"-DWRONG_FFI=1"),
            ("Makefile", b"-fno-strict-overflow -I", b"-fstrict-overflow -I"),
            ("Makefile", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl", b"MODULE__CTYPES_LDFLAGS=-lffi -ldl -lprivate"),
            ("Makefile", b"MACOSX_DEPLOYMENT_TARGET=26.0", b"MACOSX_DEPLOYMENT_TARGET=15.0"),
            ("Makefile", b"-lm $(LIBEXPAT_A)", b"-lexpat"),
            ("Makefile", b"-framework SystemConfiguration", b"-framework Unselected"),
            ("Makefile", b"PYTHON_FOR_REGEN?=/chosen/python3", b"PYTHON_FOR_REGEN?=python3"),
            ("pyconfig.h", b"#define HAVE_FFI_PREP_CIF_VAR 1", b"/* feature absent */"),
            ("Modules/Setup.local", b"/lib/libssl.a", b"/lib/libssl.dylib"),
            ("Modules/Setup.local", b"_ctypes/malloc_closure.c", b""),
        ]
        for name, old, new in mutations:
            with self.subTest(name=name, mutation=old):
                changed = {**files, name: files[name].replace(old, new)}
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration(changed, prefix, sdk, "/Apple/clang", "/chosen/python3")

        # All configuration predicates are exercised on the source-derived
        # native checkpoint, not a fixture manufactured from BUILD constants.
        observed, prefix, sdk = observed_arm_configuration()
        expected = BUILD.python_configuration(observed, prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        self.assertEqual(expected["executable"], "python.exe")
        self.assertEqual(expected["generated"], ["_sysconfigdata__darwin_darwin.py",
                                              "_sysconfig_vars__darwin_darwin.json", "build-details.json"])
        self.assertEqual(len(expected["builtins"]), 61)
        self.assertEqual(len(set(expected["builtins"])), 61)
        make = observed["Makefile"]
        self.assertEqual(make.count(b"PYTHON_FOR_REGEN?=/chosen/python3\n"), 1)
        self.assertEqual(BUILD.make_value(make, "PYTHON_FOR_REGEN"), "/chosen/python3")
        self.assertEqual(BUILD.make_value(make, "CC"), "/Apple/clang")
        self.assertEqual(BUILD.make_value(make, "CONFIGURE_CPPFLAGS"), "")
        original_regen = next(line for line in make.splitlines(keepends=True) if line.startswith(b"PYTHON_FOR_REGEN"))
        original_cc = next(line for line in make.splitlines(keepends=True) if line.startswith(b"CC" ) and line[2:3] in (b"=", b" ", b"\t"))
        for key, original, value, required_operator in (
                (b"PYTHON_FOR_REGEN", original_regen, b"/chosen/python3", b"?="),
                (b"CC", original_cc, b"/Apple/clang", b"=")):
            for operator in (b"=", b"?=", b":=", b"::=", b":::=", b"+=", b"!=", b"??="):
                declaration = key + operator + value + b"\n"
                with self.subTest(key=key, duplicate_operator=operator), self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration({**observed, "Makefile": make + declaration}, prefix, sdk,
                                               "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
                if operator != required_operator:
                    with self.subTest(key=key, replacement_operator=operator), self.assertRaises(BUILD.BuildRefused):
                        BUILD.python_configuration({**observed, "Makefile": make.replace(original, declaration)}, prefix, sdk,
                                                   "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            for modifier in (b" ", b"\t", b"override ", b"export ", b"private ", b"override export "):
                declaration = modifier + key + required_operator + value + b"\n"
                for changed in (make + declaration, make.replace(original, declaration)):
                    with self.subTest(key=key, modifier=modifier), self.assertRaises(BUILD.BuildRefused):
                        BUILD.python_configuration({**observed, "Makefile": changed}, prefix, sdk,
                                                   "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            for declaration in (b"define " + key + b"\n" + value + b"\nendef\n",
                                b"override define " + key + b" :=\n" + value + b"\nendef\n"):
                with self.subTest(key=key, definition=True), self.assertRaises(BUILD.BuildRefused):
                    BUILD.python_configuration({**observed, "Makefile": make + declaration}, prefix, sdk,
                                               "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
            with self.subTest(key=key, missing=True), self.assertRaises(BUILD.BuildRefused):
                BUILD.python_configuration({**observed, "Makefile": make.replace(original, b"")}, prefix, sdk,
                                           "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.python_configuration({**observed, "Makefile": make.replace(original_regen, b"PYTHON_FOR_REGEN?=python3\n")},
                                       prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.ARM_TARGET)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.python_configuration(observed, prefix, sdk, "/Apple/clang", "/chosen/python3", BUILD.INTEL_TARGET)
        # Conditional Make syntax is not authority to inherit a different tool.
        source = (ROOT / "desktop/tools/macos_cpython_source_build.py").read_text()
        prepare = source.split("    def prepare(self):", 1)[1].split("\n    def sources(", 1)[0]
        build = source.split("    def build_python(self):", 1)[1].split("\n    def project(", 1)[0]
        self.assertIn('CONFIG_SHELL=self.shell, PYTHON_FOR_REGEN=self.orchestrator,', prepare)
        self.assertIn('self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",', prepare)
        self.assertNotIn("os.environ", prepare)
        for name in ("MAKEFLAGS", "MAKEFILES", "MFLAGS"):
            self.assertNotIn(name, prepare + build)
        self.assertIn('make_args = [self.make, "-j2", "PYTHON_FOR_REGEN=" + self.orchestrator,', build)
        self.assertIn('"PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B"]', build)
        self.assertEqual(build.count('[*make_args,'), 2)
        self.assertIn('environment = {**self.environment, **self.orchestration_config,', build)
        self.assertNotIn('"-e"', build)

    def test_macho_refuses_foreign_deployment_loader_injection_and_truncation(self):
        self.assertEqual(PROBE.macho(mach_o())["architecture"], "arm64")
        for target, machine, cpu, subtype in ((BUILD.ARM_TARGET, "arm64", 0x100000C, 0),
                                              (BUILD.INTEL_TARGET, "x86_64", 0x1000007, 3)):
            options = {"cpu": cpu, "subtype": subtype}
            native = mach_o(**options)
            self.assertEqual(PROBE.macho(native, target)["architecture"], machine)
            foreign = mach_o(cpu=0x1000007, subtype=3) if target == BUILD.ARM_TARGET else mach_o()
            for body in (foreign, mach_o(cpu=cpu, subtype=subtype + 1),
                         mach_o(**options, minimum=25 << 16), mach_o(**options, dylib=b"@rpath/libssl.dylib"),
                         mach_o(**options, extra=struct.pack("<IIQ", 0x8000001C, 16, 0)), native[:-1],
                         b"\xca\xfe\xba\xbe" + native[4:]):
                with self.subTest(target=target, prefix=body[:12]), self.assertRaises(PROBE.ProbeRefused):
                    PROBE.macho(body, target)

    def test_paired_native_host_and_report_data_do_not_cross_target_or_translation(self):
        # These are scalar observations only: no ctypes/sysctl/process or
        # simulated native receipt is executed or admitted by this DATA test.
        for target, machine, openssl in ((BUILD.ARM_TARGET, "arm64", "darwin64-arm64-cc"),
                                         (BUILD.INTEL_TARGET, "x86_64", "darwin64-x86_64-cc")):
            host = {"sysname": "Darwin", "machine": machine, "returned": 0,
                    "observed_errno": errno.EACCES, "length": 4, "translated": 0}
            self.assertTrue(PROBE.native_host_data(target, **host))  # errno ignored on success.
            absent = {**host, "returned": -1, "observed_errno": errno.ENOENT,
                      "length": None, "translated": None}
            self.assertTrue(PROBE.native_host_data(target, **absent))
            self.assertTrue(PROBE.native_host_data(target, **{**absent, "length": 99, "translated": 1}))
            for change in ({"translated": 1}, {"translated": True}, {"length": 8}, {"length": True},
                           {"returned": True}, {"returned": 1}, {"returned": -1, "observed_errno": errno.EACCES},
                           {"returned": -1, "observed_errno": True}, {"sysname": "Linux"},
                           {"machine": "x86_64" if machine == "arm64" else "arm64"}):
                with self.subTest(target=target, change=change):
                    self.assertFalse(PROBE.native_host_data(target, **{**host, **change}))
            profile = BUILD.target_profile(target)
            workflow_ref = BUILD.REPOSITORY + "/" + profile["workflow"] + "@" + profile["reference"]
            self.assertEqual(BUILD.target_for_route(workflow_ref, profile["reference"]), target)
            self.assertEqual(BUILD.openssl_configuration(target), (openssl, *BUILD.OPENSSL_CONFIGURE[1:]))
            other = BUILD.INTEL_TARGET if target == BUILD.ARM_TARGET else BUILD.ARM_TARGET
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.target_for_route(workflow_ref, BUILD.target_profile(other)["reference"])
            context = {"target": target, "fixture": "DATA only"}
            self.assertEqual(PROBE.decode_context(BUILD.canonical(context), target), context)
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^native-probe-context-target$"):
                PROBE.decode_context(BUILD.canonical(context), other)
            report = {"schemaVersion": 1, "target": target, "role": "network",
                      "result": {"nativeHost": host, "errno": errno.EPERM}}
            self.assertEqual(BUILD.probe_result(BUILD.canonical(report), "network", target, PROBE), report["result"])
            for changed in ({**report, "target": other}, {**report, "role": "loader"},
                            {**report, "schemaVersion": True},
                            {**report, "result": {"nativeHost": {**host, "translated": 1}}},
                            {**report, "result": {"nativeHost": {**host, "extra": 0}}}):
                with self.assertRaises(BUILD.BuildRefused):
                    BUILD.probe_result(BUILD.canonical(changed), "network", target, PROBE)
        for unknown in ("arm64-apple-darwin", "x86_64-unknown-linux-gnu", True, None):
            self.assertFalse(PROBE.native_host_data(unknown, **host))
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.target_profile(unknown)
            context = {"schemaVersion": 1, "target": unknown, "payload": None, "checkout": None,
                       "builtins": [], "files": [], "sourceFiles": {}, "scratch": None, "sourceCommit": ""}
            with self.assertRaisesRegex(PROBE.ProbeRefused, "^probe-target$"):
                PROBE.configuration(context)  # Refuses before any filesystem access.

    def test_inventory_does_not_admit_aliases_modes_or_unbound_shapes(self):
        source = SimpleNamespace(original_prefix="/work/inputs/sources/cpython/")
        row = {"path": source.original_prefix + "Lib/source with spaces.py", "size": 1,
               "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o644}
        self.assertEqual(list(BUILD.inventory(BUILD.canonical({"files": [row]}), source)), ["Lib/source with spaces.py"])
        bad = [[{**row, "path": source.original_prefix + "../escape"}], [{**row, "mode": 0o777}],
               [{**row, "size": True}], [row, row], [row, {**row, "path": row["path"].upper()}]]
        for rows in bad:
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.inventory(BUILD.canonical({"files": rows}), source)
        with self.assertRaises(BUILD.BuildRefused):
            BUILD.decode(b'{"files":[],"files":[]}')

    def test_original_result_deadline_and_finality_are_not_success_defaults(self):
        self.assertEqual(BUILD.remaining(10.9, 5.2, 9), 5)
        for deadline, now in ((10.0, 10.0), (10.0, 9.1), (float("nan"), 1)):
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.remaining(deadline, now)
        argv = ["fixed", "argument"]
        self.assertTrue(BUILD.original_result(subprocess.CompletedProcess(argv, 0, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, False, b"", b""), argv))
        self.assertFalse(BUILD.original_result(subprocess.CompletedProcess(argv, 0, "", b""), argv))
        good = dict(failure=None, entered=2, returned=2, ledger={"complete": True, "fatal": False, "contained": True},
                    handlers="RESTORED", scratch_retired=True, data_finality=True)
        self.assertTrue(BUILD.public_eligible(**good))
        for changes in (dict(failure={"type": "earlier-failure"}), dict(returned=1), dict(entered=True),
                        dict(handlers="UNKNOWN"), dict(scratch_retired=False), dict(data_finality=False),
                        dict(ledger={"complete": 1, "fatal": False, "contained": True}),
                        dict(ledger={"complete": True, "fatal": False, "contained": None})):
            self.assertFalse(BUILD.public_eligible(**{**good, **changes}))
        state, closes, original = BUILD.DataFinality(), [], object()
        with self.assertRaises(ValueError):
            with state.acquiring(lambda: original, closes.append) as captured:
                self.assertIs(captured, original)
                self.assertFalse(state.known)
                raise ValueError("known failed read")
        self.assertTrue(state.known)
        self.assertEqual(closes, [original])

        def ambiguous_close(captured):
            self.assertIs(captured, original)
            raise OSError("injected original close failure")

        with self.assertRaises(OSError):
            with state.acquiring(lambda: original, ambiguous_close):
                pass
        state.close(lambda: closes.append("unrelated-close"))
        self.assertFalse(state.known)  # A later successful close cannot repair it.
        self.assertFalse(BUILD.public_eligible(**{**good, "data_finality": state.known}))
        lost = BUILD.DataFinality()

        def constructor_result_loss():
            self.assertFalse(lost.known)  # Armed before constructor dispatch.
            raise OSError("injected acquisition result loss")

        with self.assertRaises(OSError):
            with lost.acquiring(constructor_result_loss, closes.append):
                self.fail("unreturned acquisition entered body")
        with lost.acquiring(lambda: original, closes.append):
            pass
        self.assertFalse(lost.known)  # No repair by an independent acquisition.
        self.assertTrue(BUILD.DATA.known)  # Faults used separate inert DATA state.

    def test_input_admission_refusals_keep_exact_predicates_and_tool_roles(self):
        # Inert originals only. No real tool, descriptor, native call or file is
        # opened. Exercise actual read/close sequencing and contextual refusal.
        info = dict(st_dev=1, st_ino=2, st_mode=BUILD.stat.S_IFREG | 0o555,
                    st_uid=0, st_gid=0, st_nlink=1, st_size=3, st_mtime_ns=1, st_ctime_ns=1)
        self.assertEqual(BUILD.INPUT_BOUND_FAILURES,
                         ("ordinary-input-kind", "ordinary-input-links", "ordinary-input-size"))
        for change, reason in (({"st_mode": BUILD.stat.S_IFLNK | 0o777}, "ordinary-input-kind"),
                               ({"st_nlink": 2}, "ordinary-input-links"),
                               ({"st_nlink": 0}, "ordinary-input-links"),
                               ({"st_size": -1}, "ordinary-input-size"),
                               ({"st_size": 4}, "ordinary-input-size")):
            original = SimpleNamespace(**{**info, **change})
            selected = SimpleNamespace(lstat=lambda: original)
            with patch.object(BUILD.os, "open") as opened:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    BUILD.read(selected, 3)
                opened.assert_not_called()
            self.assertTrue(BUILD.DATA.known)

        original = SimpleNamespace(**info)
        selected = SimpleNamespace(lstat=lambda: original)
        with patch.object(BUILD.os, "open", return_value=713) as opened, \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]) as reads, \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "close") as closed:
            self.assertEqual(BUILD.read(selected, 3), b"abc")
            opened.assert_called_once_with(selected, BUILD.os.O_RDONLY | BUILD.os.O_NOFOLLOW
                                           | BUILD.os.O_CLOEXEC | BUILD.os.O_NONBLOCK)
            self.assertEqual(reads.call_args_list, [call(713, 3), call(713, 1)])
            closed.assert_called_once_with(713)
        self.assertTrue(BUILD.DATA.known)

        parent = SimpleNamespace(parents=(), stat=lambda: SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=0))
        class ToolPath:
            def resolve(self, *, strict):
                if strict is not True:
                    raise AssertionError("original strict resolution changed")
                return self
            def is_absolute(self):
                return True
            def lstat(self):
                return original
            def __str__(self):
                return "/usr/bin/synthetic-admission-only"
        ToolPath.parent = parent
        selected = ToolPath()
        owner = object.__new__(BUILD.Build)
        owner.tools = {}
        for role in BUILD.TOOL_ROLES:
            for reason in BUILD.INPUT_BOUND_FAILURES:
                with patch.object(BUILD, "read", side_effect=BUILD.BuildRefused(reason)) as reading:
                    with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-" + role + "-" + reason + "$"):
                        owner.protected_tool(selected, role=role)
                    reading.assert_called_once_with(selected, 512 * BUILD.MIB, expected_links=1)
                self.assertEqual(owner.tools, {})
        for role in (True, None, "unknown", "make/other"):
            with patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-diagnostic-role$"):
                    owner.protected_tool(selected, role=role)
                reading.assert_not_called()
        class OtherRefused(BUILD.BuildRefused):
            pass
        for error in (BUILD.BuildRefused("input-post-correspondence"),
                      OtherRefused("ordinary-input-links"), OSError("inert read failure")):
            with patch.object(BUILD, "read", side_effect=error):
                with self.assertRaises(type(error)) as caught:
                    owner.protected_tool(selected, role="make")
                self.assertIs(caught.exception, error)
            self.assertEqual(owner.tools, {})
        # Preserve each selected-original predicate and its short-circuit
        # result, while retaining finite scalar diagnostics without any path.
        for change, system, condition in (
                ({"st_mode": BUILD.stat.S_IFDIR | 0o755}, True, "kind"),
                ({"st_uid": 501}, True, "owner"),
                ({"st_uid": 502}, False, "owner"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o444}, True, "executable"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o575}, True, "mode"),
                ({"st_mode": BUILD.stat.S_IFREG | 0o557}, False, "mode")):
            original = SimpleNamespace(**{**info, **change})
            diagnostic = object.__new__(BUILD.Build)
            diagnostic.tools, diagnostic.evidence = {}, {}
            with patch.object(BUILD.os, "getuid", return_value=501), \
                    patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused,
                        "^tool-make-unprotected-selected-tool-" + condition + "$"):
                    diagnostic.protected_tool(selected, role="make", system=system)
                reading.assert_not_called()
            self.assertEqual(diagnostic.tools, {})
            self.assertEqual(set(diagnostic.evidence), {"tool-admission-failure.json"})
            detail = json.loads(diagnostic.evidence["tool-admission-failure.json"])
            self.assertEqual(detail, {"schemaVersion": 1, "role": "make", "condition": condition,
                "AppleSystem": system, "executableRequired": True, "uid": original.st_uid,
                "gid": original.st_gid, "mode": original.st_mode, "nlink": original.st_nlink,
                "hostUid": 501})
            self.assertNotIn(str(selected).encode(), diagnostic.evidence["tool-admission-failure.json"])

        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o444})
        diagnostic = object.__new__(BUILD.Build)
        diagnostic.tools, diagnostic.evidence = {}, {}
        with patch.object(BUILD, "read", return_value=b"abc") as reading:
            self.assertEqual(diagnostic.protected_tool(selected, role="sdk-settings", executable=False), str(selected))
            reading.assert_called_once_with(selected, 512 * BUILD.MIB, expected_links=1)
        self.assertEqual(diagnostic.evidence, {})

        # An accounting/shape failure is still a refusal, never tool authority.
        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o575})
        diagnostic = object.__new__(BUILD.Build)
        diagnostic.tools = {}
        diagnostic.evidence = {"tool-admission-failure.json": b"retained-original"}
        with patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^retained-evidence-bound$"):
                diagnostic.protected_tool(selected, role="make")
            reading.assert_not_called()
        self.assertEqual(diagnostic.tools, {})
        self.assertEqual(diagnostic.evidence, {"tool-admission-failure.json": b"retained-original"})
        original = SimpleNamespace(**{**info, "st_mode": BUILD.stat.S_IFREG | 0o575, "st_gid": True})
        diagnostic.evidence = {}
        with patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-diagnostic-scalar$"):
                diagnostic.protected_tool(selected, role="make")
            reading.assert_not_called()
        self.assertEqual(diagnostic.tools, {})
        self.assertEqual(diagnostic.evidence, {})
        self.assertTrue(BUILD.DATA.known)

    def test_protected_system_tool_pins_original_link_count_only_after_admission(self):
        # Synthetic original identities only: no link, tool, native call or real
        # descriptor is created. The same actual read/admission/recheck executes.
        values = dict(st_dev=1, st_ino=2, st_mode=BUILD.stat.S_IFREG | 0o555,
                      st_uid=0, st_gid=0, st_nlink=3, st_size=3, st_mtime_ns=1, st_ctime_ns=1)
        original = SimpleNamespace(**values)
        changed_count = SimpleNamespace(**{**values, "st_nlink": 4})
        protected_parent = SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=0)

        class ToolPath:
            def __init__(self, info=original, parent=protected_parent, text="/usr/bin/synthetic-links-only"):
                self.info, self.text = info, text
                self.parent = SimpleNamespace(parents=(), stat=lambda: parent)
            def resolve(self, *, strict):
                if strict is not True:
                    raise AssertionError("strict original resolution changed")
                return self
            def is_absolute(self):
                return self.text.startswith("/")
            def lstat(self):
                return self.info
            def __str__(self):
                return self.text

        selected = ToolPath()
        for expected in (0, -1, True, False, 3.0, None, "3", 1, 4):
            with self.subTest(expected=expected), patch.object(BUILD.os, "open") as opened:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^ordinary-input-links$"):
                    BUILD.read(selected, 3, expected_links=expected)
                opened.assert_not_called()
        with patch.object(BUILD.os, "open") as opened:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^ordinary-input-links$"):
                BUILD.read(selected, 3)  # Generic SOURCE/archive/output default stays1.
            opened.assert_not_called()

        def owner():
            result = object.__new__(BUILD.Build)
            result.tools, result.evidence = {}, {}
            return result

        admitted = owner()
        with patch.object(BUILD.os, "open", return_value=714) as opened, \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]) as reads, \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "close") as closed:
            self.assertEqual(admitted.protected_tool(selected, role="make"), str(selected))
            opened.assert_called_once_with(selected, BUILD.os.O_RDONLY | BUILD.os.O_NOFOLLOW
                                           | BUILD.os.O_CLOEXEC | BUILD.os.O_NONBLOCK)
            self.assertEqual(reads.call_args_list, [call(714, 3), call(714, 1)])
            closed.assert_called_once_with(714)
        row = admitted.tools[str(selected)]
        self.assertEqual(row, {"path": str(selected), "selectedPath": str(selected), "size": 3,
                              "sha256": BUILD.digest(b"abc"), "identity": BUILD.identity(original),
                              "AppleSystem": True, "executable": True})
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(BUILD, "read", return_value=b"abc") as reading:
            admitted.recheck_tools(full=True)
            reading.assert_called_once_with(selected, 3, expected_links=3)
        for delta in ({"st_nlink": 4}, {"st_uid": 501}, {"st_mode": BUILD.stat.S_IFREG | 0o575},
                      {"st_size": 4}, {"st_mtime_ns": 2}):
            selected.info = SimpleNamespace(**{**values, **delta})
            with self.subTest(delta=delta), patch.object(BUILD, "Path", return_value=selected), \
                    patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-changed$"):
                    admitted.recheck_tools(full=True)
                reading.assert_not_called()
        selected.info = original
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(BUILD, "read", return_value=b"xyz"):
            with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-content-changed$"):
                admitted.recheck_tools(full=True)
        with patch.object(BUILD, "Path", return_value=selected), \
                patch.object(selected, "resolve", return_value=ToolPath(text="/usr/bin/other")), \
                patch.object(BUILD, "read") as reading:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^original-tool-changed$"):
                admitted.recheck_tools(full=True)
            reading.assert_not_called()

        # Action/user-controlled tools do not inherit the system exception.
        non_system = owner()
        with patch.object(BUILD.os, "open") as opened:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^tool-orchestrator-ordinary-input-links$"):
                non_system.protected_tool(selected, role="orchestrator", system=False)
            opened.assert_not_called()
        self.assertEqual(non_system.tools, {})
        single = ToolPath(info=SimpleNamespace(**{**values, "st_nlink": 1}))
        with patch.object(BUILD, "read", return_value=b"abc") as reading:
            non_system.protected_tool(single, role="orchestrator", system=False)
            reading.assert_called_once_with(single, 512 * BUILD.MIB, expected_links=1)
        with patch.object(BUILD, "Path", return_value=single), \
                patch.object(BUILD, "read", return_value=b"abc") as reading:
            non_system.recheck_tools(full=True)
            reading.assert_called_once_with(single, 3, expected_links=1)

        for bad, reason in (
                (ToolPath(info=SimpleNamespace(**{**values, "st_uid": 501})), "tool-make-unprotected-selected-tool-owner"),
                (ToolPath(info=SimpleNamespace(**{**values, "st_mode": BUILD.stat.S_IFREG | 0o575})), "tool-make-unprotected-selected-tool-mode"),
                (ToolPath(parent=SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o777, st_uid=0)), "unprotected-Apple-tool-parent"),
                (ToolPath(parent=SimpleNamespace(st_mode=BUILD.stat.S_IFDIR | 0o755, st_uid=501)), "unprotected-Apple-tool-parent"),
                (ToolPath(text="/work/unprotected"), "non-Apple-tool-route")):
            rejected = owner()
            with self.subTest(reason=reason), patch.object(BUILD, "read") as reading:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    rejected.protected_tool(bad, role="make")
                reading.assert_not_called()
            self.assertEqual(rejected.tools, {})

        # Every observation stays bound to the original count, including inside
        # the consuming read. Late count changes must close only that original.
        for fstats, lstats, reads, reason in (
                ([changed_count], [original], [], "input-open-correspondence"),
                ([original, changed_count], [original], [b"abc", b""], "input-post-correspondence"),
                ([original, original], [original, changed_count], [b"abc", b""], "input-post-correspondence"),
                ([original], [original], [b"abc", b"x"], "input-post-correspondence")):
            with self.subTest(reason=reason), patch.object(selected, "lstat", side_effect=lstats), \
                    patch.object(BUILD.os, "open", return_value=714), \
                    patch.object(BUILD.os, "fstat", side_effect=fstats), \
                    patch.object(BUILD.os, "read", side_effect=reads), \
                    patch.object(BUILD.os, "close") as closed:
                with self.assertRaisesRegex(BUILD.BuildRefused, "^" + reason + "$"):
                    BUILD.read(selected, 3, expected_links=3)
                closed.assert_called_once_with(714)
            self.assertTrue(BUILD.DATA.known)
        with patch.object(BUILD.os, "open", return_value=714), \
                patch.object(BUILD.os, "fstat", return_value=original), \
                patch.object(BUILD.os, "read", side_effect=[b"abc", b""]), \
                patch.object(BUILD.os, "close") as closed:
            with self.assertRaisesRegex(BUILD.BuildRefused, "^input-byte-binding$"):
                BUILD.read(selected, 3, expected_links=3, expected=(3, BUILD.digest(b"xyz")))
            closed.assert_called_once_with(714)
        self.assertTrue(BUILD.DATA.known)

    def test_real_small_source_projection_preserves_bytes_modes_and_inventory(self):
        for component in ("cpython", "zlib"):
            source, compressed, rows, provenance = archive_fixture(component)
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                parser.extract(source, compressed)
                projected = root / "sources" / component / "Lib/source with spaces.py"
                self.assertEqual(projected.read_bytes(), b"public source\n")
                self.assertEqual(projected.stat().st_mode & 0o777, 0o444)
                self.assertEqual(projected.stat().st_mtime_ns, 1700000000 * 1000000000)
                self.assertEqual((projected.parent.stat().st_mode & 0o777), 0o555)

    def test_real_small_source_projection_refuses_crc_tail_and_body_mismatch(self):
        cases = [archive_fixture(compression_trailer=gzip.compress(b"unselected")),
                 archive_fixture(trailer=b"x" * 512), archive_fixture()]
        source, compressed, rows, provenance = cases[-1]
        cases[-1] = (source, compressed, {name: {**row, "sha256": "0" * 64} for name, row in rows.items()}, provenance)
        for source, compressed, rows, provenance in cases:
            with scratch() as root:
                parser = parser_instance(root, source, rows, provenance)
                with self.assertRaises((BUILD.BuildRefused, zlib.error)):
                    parser.extract(source, compressed)
        source, compressed, rows, provenance = archive_fixture()
        changed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
        source.size, source.sha256 = len(changed), BUILD.digest(changed)
        provenance["archive"] = {"size": len(changed), "sha256": source.sha256}
        with scratch() as root:
            with self.assertRaises(zlib.error):
                parser_instance(root, source, rows, provenance).extract(source, changed)

    def test_retained_tar_preserves_exact_supplier_modes_and_readback(self):
        with scratch() as root:
            supplier = root / "supplier"
            (supplier / "python/bin").mkdir(mode=0o700, parents=True)
            (supplier / "python/lib").mkdir(mode=0o700)
            rows = []
            for name, body, mode in (("python/bin/python3", b"not-executable-test-data", 0o555),
                                     ("python/lib/fixture.txt", b"public fixture", 0o444)):
                rows.append({"path": name, **BUILD.write(supplier / name, body, mode)})
            BUILD.seal(supplier)
            result = BUILD.supplier_tar(supplier, root / "supplier.tar", rows, deadline=time.monotonic() + 10)
            self.assertEqual(result["files"], 2)
            self.assertTrue(result["modePreservation"])
            self.assertEqual(BUILD.digest((root / "supplier.tar").read_bytes()), result["sha256"])
            self.assertEqual(list(BUILD.tree_rows(supplier, maximum=1024, max_files=3).values()), rows)

if __name__ == "__main__":
    unittest.main()
