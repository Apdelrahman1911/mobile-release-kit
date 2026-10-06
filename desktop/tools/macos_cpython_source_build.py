"""One fixed native Darwin CPython SOURCE build, using the existing MRK owner.

The accepted source recipe module is immutable DATA, not execution authority.
This entry is for the two reviewed, disposable, credential-free macOS26 workflows
only. It does not use a historical supplier, activate a consumer, install tools,
sign a public release, or run on a shared development machine.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import io
import json
import lzma
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zlib

MIB = 1024 * 1024
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REFERENCE = "refs/heads/verify/desktop-macos-cpython-source-build"
WORKFLOW = ".github/workflows/desktop-macos-cpython-source-build.yml"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
_TARGET_PROFILES = {
    ARM_TARGET: ("arm64", "ARM64", REFERENCE, WORKFLOW, "source-lock.json",
                 "darwin64-arm64-cc", "mrk-macos-cpython"),
    INTEL_TARGET: ("x86_64", "X64", "refs/heads/verify/desktop-macos-cpython-source-build-intel",
                   ".github/workflows/desktop-macos-cpython-source-build-intel.yml",
                   "source-lock-intel.json", "darwin64-x86_64-cc", "mrk-macos-cpython-intel"),
}
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
DEVELOPER = Path("/Library/Developer/CommandLineTools")
NETWORK_POLICY = "(version 1)(allow default)(deny network*)"
PROVENANCE = ("desktop/cpython-source-inputs/inventory-provenance.json", 99170,
              "8450bcb310de15c04a94aa354a5e700e523f02cd0308f059b93ee840d5bd0d91")
WORK_SECONDS, CLEANUP_SECONDS = 2700, 120
OUTPUT_LIMIT, EVIDENCE_LIMIT, EVIDENCE_FILES = 2 * MIB, 32 * MIB, 128
PAYLOAD_LIMIT, PAYLOAD_FILES = 464 * MIB, 2035
BOOTSTRAP = tuple("atexit faulthandler posix _signal _tracemalloc _suggestions _datetime "
    "_codecs _collections errno _io itertools _sre _sysconfig _thread time _types _typing "
    "_weakref _abc _functools _locale _opcode _operator _stat _symtable pwd".split())
INTRINSIC = tuple("marshal _imp _ast _tokenize builtins sys gc _contextvars _warnings _string".split())
OPTIONAL = tuple("_bisect _heapq _json _random _struct math binascii zlib fcntl _posixsubprocess "
    "select unicodedata _ctypes _socket _ssl pyexpat resource _scproxy _md5 _sha1 _sha2 _sha3 _blake2 _hmac".split())
DISABLED = tuple("_asyncio _bz2 _codecs_cn _codecs_hk _codecs_iso2022 _codecs_jp _codecs_kr _codecs_tw "
    "_csv _ctypes_test _curses _curses_panel _dbm _decimal _elementtree _gdbm _hashlib _interpchannels "
    "_interpqueues _interpreters _lsprof _lzma _multibytecodec _multiprocessing _pickle _posixshmem "
    "_queue _remote_debugging _sqlite3 _statistics _testbuffer _testcapi _testclinic _testclinic_limited "
    "_testimportmultiple _testinternalcapi _testlimitedcapi _testmultiphase _testsinglephase _tkinter "
    "_uuid _xxtestfuzz _zoneinfo _zstd array cmath grp mmap readline syslog termios xxlimited xxlimited_35 xxsubtype".split())
HACL = tuple("Modules/_hacl/libHacl_" + name + ".a" for name in (
    "Hash_MD5", "Hash_SHA1", "Hash_SHA2", "Hash_SHA3", "Hash_BLAKE2", "HMAC"))
PYTHON_CONFIGURE = ("--prefix=/mrk-python-not-installed", "--with-platlibdir=lib", "--disable-shared",
    "--without-mimalloc", "--with-pymalloc", "--with-lto=no", "--disable-optimizations",
    "--disable-test-modules", "--with-ensurepip=no", "--with-pkg-config=no", "--with-openssl-rpath=no")
OPENSSL_CONFIGURE = ("darwin64-arm64-cc", "no-shared", "no-module", "no-dso", "no-engine",
    "no-autoload-config", "no-apps", "no-tests", "no-docs", "no-legacy")
EVIDENCE_ROLES = ("build", "relocation", "modules", "loader", "tls", "cancellation", "notices")
TOOL_ROLES = ("sandbox", "xcrun", "shell", "make", "perl", "curl", "codesign", "ls", "orchestrator",
              "sdk-settings", "clang", "ar", "ranlib", "ld", "sysctl")
INPUT_BOUND_FAILURES = ("ordinary-input-kind", "ordinary-input-links", "ordinary-input-size")
SDK_INTERFACE_PATHS = (
    'System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd',
    'usr/lib/libdl.tbd',
    'usr/lib/libffi.tbd',
    'usr/lib/libm.tbd',
    'System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration.tbd',
    'usr/lib/libSystem.tbd',
    'usr/lib/system/libcommonCrypto.tbd',
    'usr/lib/system/libcompiler_rt.tbd',
    'usr/lib/system/libcopyfile.tbd',
    'usr/lib/system/libdyld.tbd',
    'usr/lib/system/libsystem_c.tbd',
    'usr/lib/system/libsystem_info.tbd',
    'usr/lib/system/libsystem_kernel.tbd',
    'usr/lib/system/libsystem_m.tbd',
    'usr/lib/system/libsystem_malloc.tbd',
    'usr/lib/system/libsystem_platform.tbd',
    'usr/lib/system/libsystem_pthread.tbd',
    'usr/lib/system/libsystem_trace.tbd',
)


class BuildRefused(ValueError):
    pass


class DataFinality:
    """Ordinary acquisition/close custody, never a native-owner verdict."""
    def __init__(self):
        self._known = True
        self._pending = 0

    @property
    def known(self):
        return self._known and self._pending == 0

    def unknown(self):
        self._known = False

    def close(self, closer, *args):
        try:
            closer(*args)
        except BaseException:
            self.unknown()
            raise

    @contextmanager
    def acquiring(self, constructor, closer, *args, **kwargs):
        original = None
        # Arm before constructor dispatch, including its result-publication gap.
        # A lost result is never discovered/adopted or closed by descriptor guess.
        self._pending += 1
        try:
            original = constructor(*args, **kwargs)
            need(original is not None, "data-constructor-no-original")
            yield original
        finally:
            if original is None:
                self.unknown()
            else:
                self.close(closer, original)
                self._pending -= 1  # Only this positively completed original close.

    @contextmanager
    def closing(self, resource):
        try:
            yield resource
        finally:
            self.close(resource.close)


DATA = DataFinality()
_DARWIN_XATTRS = None


def need(value, code):
    if not value:
        raise BuildRefused(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(body):
    return hashlib.sha256(body).hexdigest()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def custody(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def pairs(items):
    result = {}
    for name, value in items:
        need(name not in result, "duplicate-json-key")
        result[name] = value
    return result


def decode(body):
    return json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(BuildRefused("nonfinite-json")))


def remaining(deadline, now, maximum=WORK_SECONDS):
    need(type(deadline) in {float, int} and type(now) in {float, int}
         and math.isfinite(deadline) and math.isfinite(now), "deadline-shape")
    seconds = math.floor(deadline - now)
    need(seconds >= 1 and type(maximum) is int and maximum >= 1, "common-deadline-exhausted")
    return min(seconds, maximum)


def xattrs_absent(path, original_stat):
    """Query the same ordinary original; errors are never an empty-xattr result."""
    global _DARWIN_XATTRS
    path = Path(path)
    before = identity(original_stat)
    directory = stat.S_ISDIR(original_stat.st_mode)
    need(original_stat.st_uid == os.getuid() and (directory or (
         stat.S_ISREG(original_stat.st_mode) and original_stat.st_nlink == 1)), "xattr-original-kind")
    need(identity(path.lstat()) == before, "xattr-named-original")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    failure, absent = None, False
    try:
        with DATA.acquiring(os.open, os.close, path, flags) as fd:
            try:
                need(identity(os.fstat(fd)) == before and identity(path.lstat()) == before,
                     "xattr-open-correspondence")
                if sys.platform == "darwin":
                    if _DARWIN_XATTRS is None:
                        try:
                            import ctypes
                            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
                            call = library.flistxattr
                            call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                            call.restype = ctypes.c_ssize_t
                        except (ImportError, AttributeError, OSError) as error:
                            raise BuildRefused("xattr-api-unavailable") from error
                        _DARWIN_XATTRS = call
                    count = _DARWIN_XATTRS(fd, None, 0, 0)
                    absent = type(count) is int and count == 0
                elif sys.platform == "linux":
                    try:
                        call = os.listxattr
                    except AttributeError as error:
                        raise BuildRefused("xattr-api-unavailable") from error
                    attributes = call(fd)
                    absent = type(attributes) is list and not attributes
                else:
                    raise BuildRefused("xattr-host-unavailable")
                need(identity(os.fstat(fd)) == before and identity(path.lstat()) == before,
                     "xattr-post-correspondence")
            except BaseException as error:
                # Collect the operation error before consuming the original fd;
                # a close fault must poison DATA without replacing that error.
                failure = error
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure
    need(identity(path.lstat()) == before, "xattr-close-correspondence")
    return absent


def read(path, limit, *, expected=None, expected_links=1):
    need(type(expected_links) is int and expected_links >= 1, "ordinary-input-links")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "ordinary-input-kind")
    need(before.st_nlink == expected_links, "ordinary-input-links")
    need(0 <= before.st_size <= limit, "ordinary-input-size")
    with DATA.acquiring(os.open, os.close, path,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK) as fd:
        need(identity(os.fstat(fd)) == identity(before), "input-open-correspondence")
        blocks, count = [], 0
        while count < before.st_size:
            block = os.read(fd, min(65536, before.st_size - count))
            need(block, "input-short-read")
            blocks.append(block)
            count += len(block)
        need(not os.read(fd, 1) and identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before), "input-post-correspondence")
    body = b"".join(blocks)
    if expected is not None:
        need((len(body), digest(body)) == expected, "input-byte-binding")
    return body


def write(path, body, mode=0o600):
    need(type(body) is bytes, "output-body")
    with DATA.acquiring(os.open, os.close, path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode) as fd:
        original = os.fstat(fd)
        need(stat.S_ISREG(original.st_mode) and original.st_nlink == 1
             and original.st_uid == os.getuid(), "output-original")
        os.fchmod(fd, mode)
        cursor = 0
        while cursor < len(body):
            count = os.write(fd, body[cursor:cursor + 65536])
            need(count > 0, "output-short-write")
            cursor += count
        need(os.fstat(fd).st_size == len(body), "output-size")
    need(read(path, len(body)) == body and stat.S_IMODE(path.lstat().st_mode) == mode, "output-readback")
    return {"size": len(body), "sha256": digest(body), "mode": mode}


def directory_entries(path):
    # Close the actual original iterator before returning/yielding any entries.
    with DATA.acquiring(os.scandir, lambda stream: stream.close(), path) as stream:
        entries = []
        for entry in stream:
            need(len(entries) < 65536, "directory-entry-bound")
            entries.append(entry)
    return sorted(entries, key=lambda entry: entry.name)


def walk_tree(root):
    pending, count = [root], 0
    while pending:
        directory = pending.pop()
        names, files = [], []
        for entry in directory_entries(directory):
            (names if entry.is_dir(follow_symlinks=False) else files).append(entry.name)
        count += 1
        need(count <= 32768, "directory-census-bound")
        yield directory, names, files
        pending.extend(directory / name for name in reversed(names))


def source_name(value):
    need(type(value) is str and 0 < len(value) <= 4096 and not value.startswith("/")
         and "\\" not in value and all(32 <= ord(c) < 127 for c in value), "source-relative-name")
    parts = value.split("/")
    need(all(part not in {"", ".", ".."} for part in parts), "source-relative-name")
    return value


def inventory(body, source):
    value = decode(body)
    need(type(value) is dict and set(value) == {"files"} and type(value["files"]) is list
         and 0 < len(value["files"]) < 20000, "source-inventory-shape")
    rows, aliases, total = {}, set(), 0
    for row in value["files"]:
        need(type(row) is dict and set(row) == {"path", "size", "sha256", "mode"}
             and type(row["path"]) is str and row["path"].startswith(source.original_prefix)
             and type(row["size"]) is int and 0 <= row["size"] <= 64 * MIB
             and type(row["mode"]) is int and row["mode"] in {0o644, 0o755}
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
             "source-inventory-row")
        name = source_name(row["path"][len(source.original_prefix):])
        need(name not in rows and name.casefold() not in aliases, "source-inventory-collision")
        rows[name], total = row, total + row["size"]
        aliases.add(name.casefold())
    need(list(rows) == sorted(rows) and total <= 256 * MIB, "source-inventory-order-bound")
    return rows


def make_value(body, key):
    # This fixed upstream uses the ordinary TAB recipe prefix. Do not interpret
    # custom Make syntax or silently mistake a changed prefix for declarations.
    need(b".RECIPEPREFIX" not in body, "make-assignment-missing-or-repeated")
    operator = b"?=" if key == "PYTHON_FOR_REGEN" else b"="
    name = re.escape(key.encode("ascii"))
    modifiers = rb"[ \t]*(?:(?:override|export|private)[ \t]+)*"
    matches = list(re.finditer(rb"^(" + modifiers + rb")" + name + rb"[ \t]*([:+?!]*=)[ \t]*(.*)$", body, re.M))
    recipe_offsets = set()
    if key == "CC":
        # SOURCE-bound CPython 3.14.7 DTrace rules pass CC to the shell, not
        # to Make. TAB alone is insufficient: prove these exact rule contexts.
        contexts = (
            (b"Include/pydtrace_probes.h: $(srcdir)/Include/pydtrace.d\n\t$(MKDIR_P) Include\n",
             b'\tCC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -h -s $(srcdir)/Include/pydtrace.d\n\t: sed in-place edit with POSIX-only tools\n\tsed \'s/PYTHON_/PyDTrace_/\' $@ > $@.tmp\n\tmv $@.tmp $@\n'),
            (b"Python/pydtrace.o: $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)\n",
             b'\tCC="$(CC)" CFLAGS="$(CFLAGS)" $(DTRACE) $(DFLAGS) -o $@ -G -s $(srcdir)/Include/pydtrace.d $(DTRACE_DEPS)\n'),
        )
        for prefix, command in contexts:
            block = prefix + command
            start = body.find(block)
            if (start >= 0 and body.count(block) == 1
                    and (start == 0 or body[start - 1:start] == b"\n")
                    and (start < 2 or body[start - 2:start - 1] != b"\\")):
                recipe_offsets.add(start + len(prefix))
    values = [match.groups() for match in matches if match.start() not in recipe_offsets]
    defined = re.search(rb"^" + modifiers + rb"define[ \t]+" + name + rb"(?:[ \t:+?!=]|$)", body, re.M)
    # Every unmatched recipe-like line and all modified/duplicate declarations
    # remain counted. Missing DTrace blocks grant nothing, not an alternate value.
    need(defined is None and len(values) == 1 and values[0][0] == b"" and values[0][1] == operator,
         "make-assignment-missing-or-repeated")
    return values[0][2].decode("utf-8", "strict").strip()


def target_profile(target):
    need(type(target) is str and target in _TARGET_PROFILES, "fixed-producer-target")
    machine, arch, reference, workflow, lock, openssl, work = _TARGET_PROFILES[target]
    return {"machine": machine, "runnerArch": arch, "reference": reference, "workflow": workflow,
            "lock": "desktop/macos-cpython-source-inputs/" + lock, "openssl": openssl, "workPrefix": work}


def target_for_route(workflow_ref, reference):
    need(type(workflow_ref) is str and type(reference) is str, "fixed-producer-target-route")
    for target in _TARGET_PROFILES:
        profile = target_profile(target)
        if (reference == profile["reference"]
                and workflow_ref == REPOSITORY + "/" + profile["workflow"] + "@" + reference):
            return target
    raise BuildRefused("fixed-producer-target-route")


def compiler_flags(sdk, target=ARM_TARGET):
    return f"-O2 -g0 -fPIC -arch {target_profile(target)['machine']} -isysroot {sdk} -mmacosx-version-min=26.0"


def linker_flags(sdk, target=ARM_TARGET):
    return f"-arch {target_profile(target)['machine']} -isysroot {sdk} -mmacosx-version-min=26.0"


def openssl_configuration(target=ARM_TARGET):
    return (target_profile(target)["openssl"], *OPENSSL_CONFIGURE[1:])


def link_map_objects(body, prefix, build_root, sdk):
    """Interpret the complete object table, not opaque symbol/literal-string bytes."""
    need(type(body) is bytes and 0 < len(body) <= 8 * MIB, "native-link-map-bound")
    starts = list(re.finditer(rb"(?m)^# Object files:\n", body))
    ends = list(re.finditer(rb"(?m)^# Sections:\n", body))
    need(len(starts) == len(ends) == 1 and starts[0].end() < ends[0].start(), "native-link-map-objects")
    try:
        section = body[starts[0].end():ends[0].start()].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise BuildRefused("native-link-map-object-row") from error
    need(section.endswith("\n"), "native-link-map-object-row")
    interfaces = {str(sdk / name) for name in SDK_INTERFACE_PATHS}
    objects, components = [], set()
    for line in section[:-1].split("\n"):
        need(all(32 <= ord(character) < 127 for character in line), "native-link-map-object-row")
        match = re.fullmatch(r"\[\s*([0-9]+)\]\s+(.+)", line)
        need(match is not None, "native-link-map-object-row")
        ordinal, name = int(match[1]), match[2]
        need(ordinal == len(objects), "native-link-map-object-order")
        objects.append(name)
        if ordinal == 0:
            need(name == "linker synthesized", "native-link-map-synthesized")
            continue
        # These exact original-SDK interfaces are not redistributed static objects.
        # Keep them in complete object evidence; do not exempt arbitrary .tbd paths.
        if name in interfaces:
            continue
        selected_prefix, build_prefix = str(prefix / "lib") + "/", str(build_root) + "/"
        if name.startswith(build_prefix):
            name = name[len(build_prefix):]
        if name.startswith(selected_prefix + "libssl.a(") or name.startswith(selected_prefix + "libcrypto.a("):
            components.add("openssl")
        elif name.startswith(selected_prefix + "libz.a("):
            components.add("zlib")
        elif name.startswith("Modules/_hacl/"):
            components.add("hacl")
        elif name.startswith("Modules/expat/"):
            components.add("expat")
        elif name.startswith(("Programs/", "Modules/", "Objects/", "Parser/", "Python/", "libpython3.14.a(")):
            components.add("cpython")
        else:
            # No invented compiler-runtime redistribution or static-archive allowance.
            raise BuildRefused("native-unaccounted-static-object")
    need({"cpython", "openssl", "zlib", "hacl", "expat"} <= components, "native-incorporation-roster")
    return objects, sorted(components)


def probe_result(body, role, target, probe):
    target_profile(target)
    value = decode(body)
    need(type(value) is dict and set(value) == {"schemaVersion", "role", "target", "result"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["role"] == role and value["target"] == target
         and type(value["result"]) is dict, "native-probe-result")
    host = value["result"].get("nativeHost")
    need(type(host) is dict and set(host) == {"sysname", "machine", "returned", "observed_errno", "length", "translated"}
         and probe.native_host_data(target, **host), "native-probe-host-result")
    return value["result"]


def python_configuration(files, prefix, sdk, compiler, orchestrator, target=ARM_TARGET):
    make, header, config = (files[name] for name in ("Makefile", "pyconfig.h", "Modules/config.c"))
    need(make_value(make, "BUILDEXE") in {"", ".exe"}
         and make_value(make, "BUILDPYTHON") == "python$(BUILDEXE)", "python-build-executable")
    expected = {"VERSION": "3.14", "MACHDEP": "darwin", "ABIFLAGS": "", "PY_ENABLE_SHARED": "0",
                "CC": compiler, "LIBEXPAT_A": "Modules/expat/libexpat.a",
                "PYTHON_FOR_REGEN": orchestrator,
                "MACOSX_DEPLOYMENT_TARGET": "26.0",
                "CONFIGURE_CFLAGS": compiler_flags(sdk, target), "CONFIGURE_CPPFLAGS": "",
                "CONFIGURE_LDFLAGS": linker_flags(sdk, target) + " -L" + str(prefix / "lib"),
                "MODULE_ZLIB_LDFLAGS": str(prefix / "lib/libz.a")}
    for key, value in expected.items():
        need(make_value(make, key) == value, "python-material-configuration:" + key)
    for key, expected_names in (("MODBUILT_NAMES", set(BOOTSTRAP + OPTIONAL)),
                                ("MODSHARED_NAMES", set()), ("MODDISABLED_NAMES", set(DISABLED))):
        words = make_value(make, key).split()
        need(len(words) == len(expected_names) and set(words) == expected_names, "python-module-roster")
    table = re.search(rb"struct _inittab _PyImport_Inittab\[\] = \{(.*?)\n\};", config, re.S)
    need(table is not None, "python-generated-inittab")
    table_body = re.sub(rb"/\*.*?\*/", b"", table[1], flags=re.S)
    row = rb'\{\s*"([A-Za-z0-9_]+)"\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\},'
    names = [name.decode("ascii") for name in re.findall(row, table_body)]
    need(re.fullmatch(rb"\{\s*0\s*,\s*0\s*\}", re.sub(row, b"", table_body).strip())
         and len(names) == 61 and set(names) == set(BOOTSTRAP + INTRINSIC + OPTIONAL), "python-native-inittab-roster")
    for name in ("WITH_PYMALLOC", "HAVE_FORK", "HAVE_POSIX_SPAWN", "HAVE_SYS_RESOURCE_H",
                 "HAVE_WAITPID", "HAVE_POLL", "HAVE_SOCKETPAIR", "HAVE_FFI_PREP_CIF_VAR",
                 "HAVE_FFI_PREP_CLOSURE_LOC", "HAVE_FFI_CLOSURE_ALLOC"):
        need(re.findall(rb"^#define " + name.encode() + rb"[ \t]+(.*)$", header, re.M) == [b"1"],
             "python-required-platform-feature")
    for name in ("Py_GIL_DISABLED", "Py_DEBUG", "Py_TRACE_REFS", "WITH_MIMALLOC", "Py_ENABLE_SHARED"):
        need(re.search(rb"^#define " + name.encode() + rb"\b", header, re.M) is None, "python-unselected-abi")
    ffi = make_value(make, "MODULE__CTYPES_CFLAGS").split()
    need(ffi == ["-fno-strict-overflow", "-I" + str(sdk / "usr/include/ffi"), "-DUSING_APPLE_OS_LIBFFI=1",
                 "-DUSING_MALLOC_CLOSURE_DOT_C=1"]
         and make_value(make, "MODULE__CTYPES_LDFLAGS").split() in (["-lffi"], ["-lffi", "-ldl"])
         and b"_ctypes/malloc_closure.c" in files["Modules/Setup.local"], "python-apple-ffi-seam")
    need(make_value(make, "MODULE_PYEXPAT_CFLAGS").split() == ["-I$(srcdir)/Modules/expat"]
         and make_value(make, "MODULE_PYEXPAT_LDFLAGS").split() == ["-lm", "$(LIBEXPAT_A)"],
         "python-internal-expat-seam")
    need(make_value(make, "MODULE__SCPROXY_LDFLAGS").split()
         == ["-framework", "SystemConfiguration", "-framework", "CoreFoundation"], "python-scproxy-frameworks")
    need(make_value(make, "MODULE__SSL_CFLAGS").split() == ["-I" + str(prefix / "include")]
         and make_value(make, "MODULE__SSL_LDFLAGS").split()
         == ["-L" + str(prefix / "lib"), "-lssl", "-lcrypto"], "python-openssl-feature-check-seam")
    need(str(prefix / "lib/libssl.a").encode() in files["Modules/Setup.local"]
         and str(prefix / "lib/libcrypto.a").encode() in files["Modules/Setup.local"]
         and not any(flag in files["Modules/Setup.local"] for flag in (b"-l:", b"--exclude-libs", b"rpath")),
         "python-darwin-static-operands")
    multiarch = make_value(make, "MULTIARCH")
    need(re.fullmatch(r"[A-Za-z0-9_+\-]{0,128}", multiarch), "python-multiarch")
    stem = "_darwin_" + multiarch
    return {"executable": "python" + make_value(make, "BUILDEXE"), "builtins": sorted(names),
            "generated": ["_sysconfigdata_" + stem + ".py", "_sysconfig_vars_" + stem + ".json", "build-details.json"]}


def original_result(result, argv):
    return (type(result) is subprocess.CompletedProcess and type(result.args) is list
            and result.args == argv and type(result.returncode) is int
            and type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT)


def public_eligible(*, failure, entered, returned, ledger, handlers, scratch_retired, data_finality):
    """Inert finality predicate, not an ownership capability or cleanup grant."""
    return (failure is None and type(entered) is int and type(returned) is int and entered == returned
            and type(ledger) is dict and set(ledger) == {"complete", "fatal", "contained"}
            and all(type(value) is bool for value in ledger.values())
            and ledger == {"complete": True, "fatal": False, "contained": True}
            and handlers == "RESTORED" and scratch_retired is True and data_finality is True)


def load_module(name, path):
    need(name not in sys.modules, "source-module-already-imported")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    need(Path(module.__file__).absolute() == path, "source-module-route")
    return module


class Build:
    def __init__(self, root, work, source, owner, control, recipe, probe, target=ARM_TARGET):
        self.root, self.work, self.source = root, work, source
        self.owner, self.control, self.recipe, self.probe = owner, control, recipe, probe
        self.target, self.profile = target, target_profile(target)
        self.source_lock = recipe.source_binding(target)
        descriptor = recipe.target_description(target)
        need(self.source_lock["path"] == self.profile["lock"]
             and (descriptor.triple, descriptor.architecture, descriptor.openssl_target, descriptor.minimum_macos)
             == (target, self.profile["machine"], self.profile["openssl"], "26.0"), "producer-recipe-profile")
        self.started = time.monotonic()
        self.deadline = self.started + WORK_SECONDS
        self.private, self.public = work / "private", work / "public"
        self.work_identity = custody(work.lstat())
        self.private_identity = None
        self.guard, self.owns = control.cancellation_owner(None, BuildRefused, "producer-handler-finality")
        need(self.owns, "producer-original-cancellation-owner")
        self.entered = self.returned = 0
        self.inflight = False
        self.commands, self.evidence, self.tools = [], {}, {}
        self.phase, self.failure, self.cleanup_errors = "admission", None, []
        self.scratch_retired = False
        self.retained = None
        self.relocation_parent_identity = self.export_identity = None
        self.payload, self.files, self.notice_paths, self.native = None, None, None, {}
        self.environment = {}
        self.source_rows, self.source_trees, self.toolchain = {}, {}, {}

    def check(self):
        self.guard.check()
        remaining(self.deadline, time.monotonic())

    def final_check(self):
        need(DATA.known and custody(self.work.lstat()) == self.work_identity,
             "original-data-or-task-finality-unknown")
        remaining(self.deadline + CLEANUP_SECONDS, time.monotonic(), CLEANUP_SECONDS)

    def evidence_bytes(self, name, body):
        need(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,95}", name) and name not in self.evidence
             and len(self.evidence) < EVIDENCE_FILES and type(body) is bytes
             and sum(map(len, self.evidence.values())) + len(body) <= EVIDENCE_LIMIT, "retained-evidence-bound")
        self.evidence[name] = body
        return digest(body)

    def evidence_json(self, name, value):
        return self.evidence_bytes(name, canonical(value))

    def protected_tool(self, path, *, role, system=True, executable=True):
        need(type(role) is str and role in TOOL_ROLES, "tool-diagnostic-role")
        original_path = path
        resolved = path.resolve(strict=True)
        need(path.is_absolute(), "non-absolute-tool-route")
        if system:
            allowed = ("/usr/", "/bin/", "/sbin/", "/System/", str(DEVELOPER) + "/")
            need(str(path).startswith(allowed) and str(resolved).startswith(allowed), "non-Apple-tool-route")
            for route in (path, resolved):
                for parent in (route.parent, *route.parent.parents):
                    info = parent.stat()
                    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                         "unprotected-Apple-tool-parent")
        info = resolved.lstat()
        # Preserve the original admission order. Diagnostics do not turn a
        # failed predicate into an admitted tool or expose its filesystem path.
        condition = None
        if not stat.S_ISREG(info.st_mode):
            condition = "kind"
        elif info.st_uid not in ({0} if system else {0, os.getuid()}):
            condition = "owner"
        elif executable and not info.st_mode & 0o111:
            condition = "executable"
        elif info.st_mode & 0o022:
            condition = "mode"
        if condition is not None:
            scalars = {"uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode,
                       "nlink": info.st_nlink, "hostUid": os.getuid()}
            bounds = {"uid": 2**32, "gid": 2**32, "mode": 2**16, "nlink": 2**64, "hostUid": 2**32}
            need(all(type(value) is int and 0 <= value < bounds[name]
                     for name, value in scalars.items()), "tool-diagnostic-scalar")
            self.evidence_json("tool-admission-failure.json", {
                "schemaVersion": 1, "role": role, "condition": condition,
                "AppleSystem": bool(system), "executableRequired": bool(executable), **scalars})
            raise BuildRefused("tool-" + role + "-unprotected-selected-tool-" + condition)
        try:
            # Only the admitted protected system original may have multiple
            # names. Other inputs remain single-link; pin this original count.
            body = read(resolved, 512 * MIB, expected_links=info.st_nlink if system else 1)
        except BuildRefused as error:
            # Keep the exact original refusal. Only fixed roles/conditions may
            # refine diagnostics; no raw tool path or exception text is added.
            if type(error) is BuildRefused and str(error) in INPUT_BOUND_FAILURES:
                raise BuildRefused("tool-" + role + "-" + str(error)) from None
            raise
        row = {"path": str(resolved), "selectedPath": str(original_path), "size": len(body),
               "sha256": digest(body), "identity": identity(info), "AppleSystem": system,
               "executable": executable}
        self.tools[str(original_path)] = row
        # Preserve argv[0]-dependent Apple aliases (e.g. ar/ranlib), while the
        # canonical executable and each selected alias are independently pinned.
        return str(original_path)

    def recheck_tools(self, *, full=False):
        for row in self.tools.values():
            path = Path(row["path"])
            need(identity(path.lstat()) == tuple(row["identity"])
                 and Path(row["selectedPath"]).resolve(strict=True) == path, "original-tool-changed")
            # Original full9/alias is checked each phase, hashes at admission
            # and finality. No adversarial same-UID isolation is claimed for the
            # action-provided orchestration interpreter (which is not shipped).
            if full:
                # Never rebaseline the count from a later path observation.
                links = row["identity"][5] if row["AppleSystem"] else 1
                need(digest(read(path, row["size"], expected_links=links)) == row["sha256"],
                     "original-tool-content-changed")

    def run(self, role, argv, *, cwd=None, env=None, maximum=WORK_SECONDS, online=False):
        self.check()
        need(type(role) is str and re.fullmatch(r"[a-z0-9-]{1,64}", role)
             and role not in {row["role"] for row in self.commands}, "one-original-phase")
        self.phase = role
        # All build/probe commands inherit existing native network denial. Only
        # the four fixed curl acquisitions are online, with no credentials.
        selected = list(argv) if online else [self.sandbox, "-p", NETWORK_POLICY, *argv]
        self.recheck_tools()
        row = {"role": role, "argv": selected, "cwd": str(cwd or self.private),
               "environmentSha256": digest(canonical(env or self.environment)),
               "started": time.monotonic(), "returned": False}
        self.commands.append(row)
        self.entered += 1
        self.inflight = True
        try:
            result = self.owner.run_owned(selected, environ=env or self.environment, cwd=cwd or self.private,
                timeout=remaining(self.deadline, time.monotonic(), maximum), capture=True, text=False,
                output_limit=OUTPUT_LIMIT, cancellation=self.guard)
        except BaseException:
            verdict = self.guard.lifetime_ledger.verdict()
            # A typed/ledger-settled failure is still a failed phase. It only
            # allows task scratch retirement; it cannot count as a returned CP.
            self.inflight = not (verdict.complete and not verdict.fatal and verdict.contained)
            raise
        else:
            self.inflight = False
            self.returned += 1
            need(original_result(result, selected), "original-command-return-contract")
            row.update(returned=True, returncode=result.returncode, ended=time.monotonic(),
                stdoutSha256=self.evidence_bytes(role + ".stdout", result.stdout),
                stderrSha256=self.evidence_bytes(role + ".stderr", result.stderr))
            self.recheck_tools()
            need(result.returncode == 0 and b"(ignored)" not in result.stderr + result.stdout,
                 "original-command-failed")
            self.check()
            return result

    def prepare(self):
        self.private.mkdir(mode=0o700)
        self.private_identity = custody(self.private.lstat())
        for name in ("home", "tmp", "sources", "archives", "build", "prefix", "probe-scratch"):
            (self.private / name).mkdir(mode=0o700)
        prefix = self.private / "prefix"
        for name in ("include", "lib"):
            (prefix / name).mkdir(mode=0o700)
        self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.private / "home"),
            "TMPDIR": str(self.private / "tmp") + "/", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "DEVELOPER_DIR": str(DEVELOPER), "CONFIG_SITE": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1"}
        self.sandbox = self.protected_tool(Path("/usr/bin/sandbox-exec"), role="sandbox")
        self.xcrun = self.protected_tool(Path("/usr/bin/xcrun"), role="xcrun")
        self.shell = self.protected_tool(Path("/bin/sh"), role="shell")
        self.make = self.protected_tool(Path("/usr/bin/make"), role="make")
        self.perl = self.protected_tool(Path("/usr/bin/perl"), role="perl")
        self.curl = self.protected_tool(Path("/usr/bin/curl"), role="curl")
        self.codesign = self.protected_tool(Path("/usr/bin/codesign"), role="codesign")
        self.ls = self.protected_tool(Path("/bin/ls"), role="ls")
        self.orchestrator = self.protected_tool(Path(sys.executable), role="orchestrator", system=False)
        self.toolchain["orchestrator"] = {**self.tools[self.orchestrator], "version": sys.version, "shipped": False}
        sdk = self.run("sdk-path", [self.xcrun, "--sdk", "macosx", "--show-sdk-path"], maximum=30).stdout.decode().strip()
        self.sdk = Path(sdk).resolve(strict=True)
        need(self.sdk.is_relative_to(DEVELOPER / "SDKs") and " " not in str(self.sdk), "fixed-Apple-sdk")
        self.protected_tool(self.sdk / "SDKSettings.json", role="sdk-settings", executable=False)
        sdk_version = self.run("sdk-version", [self.xcrun, "--sdk", "macosx", "--show-sdk-version"], maximum=30).stdout.decode().strip()
        need(re.fullmatch(r"26\.[0-9]+(?:\.[0-9]+)?", sdk_version), "sdk-version")
        for name in ("clang", "ar", "ranlib", "ld"):
            path = self.run("tool-path-" + name, [self.xcrun, "--sdk", "macosx", "--find", name], maximum=30).stdout.decode().strip()
            setattr(self, name, self.protected_tool(Path(path), role=name))
        self.toolchain.update(sdk=str(self.sdk), sdkVersion=sdk_version,
            compilerVersion=self.run("compiler-version", [self.clang, "--version"], maximum=30).stdout.decode(),
            platform=platform.mac_ver()[0], architecture=os.uname().machine, target=self.target,
            descriptorLimits=self.descriptor_limits,
            systemLibffi="Apple SDK headers/system dylib; private source 3.4.8 not incorporated")
        self.environment.update(SDKROOT=str(self.sdk), MACOSX_DEPLOYMENT_TARGET="26.0",
            CC=self.clang, AR=self.ar, RANLIB=self.ranlib, LD=self.ld, MAKE=self.make,
            CONFIG_SHELL=self.shell, PYTHON_FOR_REGEN=self.orchestrator,
            CFLAGS=compiler_flags(self.sdk, self.target), CPPFLAGS="", LDFLAGS=linker_flags(self.sdk, self.target))
        probe_path = self.root / "desktop/tools/macos_cpython_source_probe.py"
        network_result = self.run("network-denial", [self.orchestrator, "-I", "-S", "-B", str(probe_path),
                                  "network", self.target], maximum=15,
                                  env={**self.environment, **self.orchestration_config})
        network = probe_result(network_result.stdout, "network", self.target, self.probe)
        need(type(network.get("errno")) is int and network["errno"] in {1, 13}, "network-denial-result")
        self.toolchain["nativeHost"] = network["nativeHost"]
        memory = self.run("physical-memory", [self.protected_tool(Path("/usr/sbin/sysctl"), role="sysctl"), "-n", "hw.memsize"], maximum=15)
        need(re.fullmatch(rb"[0-9]+\n", memory.stdout) and int(memory.stdout) >= 4 * 1024 * MIB
             and shutil.disk_usage(self.private).free >= 4 * 1024 * MIB, "build-capacity")
        self.toolchain["tools"] = list(self.tools.values())
        self.evidence_json("toolchain.json", self.toolchain)

    def sources(self):
        lock_path = self.root / self.source_lock["path"]
        self.lock_body = read(lock_path, self.source_lock["bytes"],
                              expected=(self.source_lock["bytes"], self.source_lock["sha256"]))
        self.inputs = self.recipe.source_nomination(self.lock_body, self.target)
        provenance = decode(read(self.root / PROVENANCE[0], PROVENANCE[1], expected=PROVENANCE[1:]))
        self.provenance = {row["id"]: row for row in provenance["sources"]}
        for source in self.inputs:
            self.check()
            body = read(self.root / source.inventory_path, source.inventory_size,
                        expected=(source.inventory_size, source.inventory_sha256))
            self.source_rows[source.component] = inventory(body, source)
            if source.component == "cpython":
                self.stdlib = self.recipe.stdlib_projection(self.lock_body, body, self.target)
            archive = self.private / "archives" / (source.component + ".archive")
            need(not archive.exists(), "source-acquisition-collision")
            self.run("download-" + source.component, [self.curl, "-q", "--fail", "--silent", "--show-error",
                "--location", "--max-redirs", "4", "--proto", "=https", "--proto-redir", "=https",
                "--proxy", "", "--noproxy", "*", "--connect-timeout", "20", "--max-time", "180",
                "--max-filesize", str(source.size), "--output", str(archive), source.url], maximum=190, online=True)
            compressed = read(archive, source.size, expected=(source.size, source.sha256))
            self.extract(source, compressed)
        self.evidence_json("source-inputs.json", {source.component: {"archiveSha256": source.sha256,
            "inventorySha256": source.inventory_sha256, "files": len(self.source_rows[source.component]),
            "incorporated": source.component != "libffi"} for source in self.inputs})

    def extract(self, source, compressed):
        expected = self.provenance[source.component]
        need(expected["archive"] == {"sha256": source.sha256, "size": source.size}, "source-provenance-archive")
        decoded = self.private / "archives" / (source.component + ".tar")
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * MIB) if source.component == "cpython" else zlib.decompressobj(31)
        total, hashed = 0, hashlib.sha256()
        with DATA.acquiring(os.open, os.close, decoded,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600) as fd:
            data = compressed
            while True:
                self.check()
                block = decoder.decompress(data, 65536)
                total += len(block)
                need(total <= expected["decodedTar"]["size"] and os.write(fd, block) == len(block), "decoded-source-bound")
                hashed.update(block)
                if decoder.eof:
                    need(not decoder.unused_data, "source-second-compression-stream")
                    break
                if source.component == "cpython":
                    need(not decoder.needs_input, "source-compression-short")
                    data = b""
                else:
                    data = decoder.unconsumed_tail
                    need(data, "source-compression-short")
            need((total, hashed.hexdigest()) == (expected["decodedTar"]["size"], expected["decodedTar"]["sha256"]),
                 "decoded-source-identity")
        root = self.private / "sources" / source.component
        root.mkdir(mode=0o700)
        rows = self.source_rows[source.component]
        directories = {row["path"][len(source.original_prefix):].rstrip("/") for row in expected["directories"]}
        # The provenance root path lacks the trailing slash in originalPrefix.
        directories.add("")
        seen, seen_directories, aliases = set(), set(), set()
        # The archive parser receives bounded bytes, not a second hidden file
        # descriptor whose constructor/close failure could lose custody.
        tar_body = read(decoded, expected["decodedTar"]["size"],
                        expected=(expected["decodedTar"]["size"], expected["decodedTar"]["sha256"]))
        with DATA.closing(tarfile.open(fileobj=io.BytesIO(tar_body), mode="r:")) as archive:
            for member in archive:
                self.check()
                full = member.name.rstrip("/")
                base = expected["archiveRoot"]
                need(full == base or full.startswith(base + "/"), "source-archive-root")
                name = full[len(base):].lstrip("/")
                if name:
                    source_name(name)
                need(member.isreg() or member.isdir(), "source-link-or-special")
                need(not member.sparse and not member.mode & 0o7000, "source-sparse-or-special-mode")
                need(name.casefold() not in aliases, "source-duplicate-or-case-alias")
                aliases.add(name.casefold())
                destination = root / name
                if member.isdir():
                    need(name in directories and name not in seen_directories
                         and expected["modeProjection"]["directories"].get(str(member.mode)) == 0o755,
                         "source-directory-roster")
                    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                    seen_directories.add(name)
                    continue
                need(name in rows and name not in seen and name not in seen_directories, "source-file-roster")
                row = rows[name]
                need(member.size == row["size"]
                     and expected["modeProjection"]["files"].get(str(member.mode)) == row["mode"], "source-size-mode")
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                need(stream is not None, "source-body-missing")
                with DATA.closing(stream):
                    body = stream.read(row["size"] + 1)
                    need(len(body) == row["size"] and not stream.read(1) and digest(body) == row["sha256"], "source-body-identity")
                write(destination, body, row["mode"] & 0o555)
                need(type(member.mtime) in {int, float} and math.isfinite(member.mtime)
                     and 0 <= member.mtime <= 4102444800, "source-mtime-bound")
                stamp = int(member.mtime * 1000000000)
                os.utime(destination, ns=(stamp, stamp), follow_symlinks=False)
                seen.add(name)
            end = archive.offset
        need(seen == set(rows) and seen_directories == directories, "complete-source-census")
        tail = tar_body[end:]
        need(len(tail) >= 1024 and len(tail) % 512 == 0 and not any(tail), "source-tar-zero-tail")
        for directory in sorted((root / name for name in directories), key=lambda path: len(path.parts), reverse=True):
            os.chmod(directory, 0o555)
        self.source_trees[source.component] = root
        self.recheck_source(source.component)

    def recheck_source(self, component):
        root, rows = self.source_trees[component], self.source_rows[component]
        actual = tree_rows(root, maximum=256 * MIB, max_files=10000, source=True, deadline=self.deadline)
        need(set(actual) == set(rows), "source-post-complete-roster")
        for name, row in rows.items():
            self.check()
            need(actual[name]["mode"] == row["mode"] & 0o555
                 and actual[name]["size"] == row["size"] and actual[name]["sha256"] == row["sha256"], "source-post-bytes-mode")

    def build_dependencies(self):
        prefix = self.private / "prefix"
        for component in ("zlib", "openssl"):
            directory = self.private / "build" / component
            directory.mkdir(mode=0o700)
            source = self.source_trees[component]
            if component == "zlib":
                self.run("zlib-configure", [self.shell, str(source / "configure"), "--static", "--prefix=" + str(prefix)], cwd=directory)
                self.run("zlib-build", [self.make, "-j2", "AR=" + self.ar, "ARFLAGS=rcs", "RANLIB=" + self.ranlib, "libz.a"], cwd=directory)
                for source_path, target in ((source / "zlib.h", prefix / "include/zlib.h"),
                    (directory / "zconf.h", prefix / "include/zconf.h"), (directory / "libz.a", prefix / "lib/libz.a")):
                    write(target, read(source_path, 64 * MIB), 0o444)
            else:
                self.run("openssl-configure", [self.perl, str(source / "Configure"), *openssl_configuration(self.target),
                    "--prefix=" + str(prefix), "--openssldir=/mrk-openssl-no-system-config"], cwd=directory)
                self.run("openssl-build", [self.make, "-j2", "build_libs"], cwd=directory)
                headers = {}
                for parent in (source / "include/openssl", directory / "include/openssl"):
                    for entry in directory_entries(parent):
                        if not entry.name.endswith(".h"):
                            continue
                        path = Path(entry.path)
                        need(path.name not in headers, "openssl-public-header-collision")
                        headers[path.name] = path
                need({"ssl.h", "crypto.h", "opensslconf.h", "configuration.h"} <= set(headers)
                     and len(headers) <= 256, "openssl-public-header-roster")
                (prefix / "include/openssl").mkdir(mode=0o700)
                for name, path in headers.items():
                    write(prefix / "include/openssl" / name, read(path, 2 * MIB), 0o444)
                for name in ("libssl.a", "libcrypto.a"):
                    body = read(directory / name, 128 * MIB)
                    need(body.startswith(b"!<arch>\n"), "openssl-static-archive")
                    write(prefix / "lib" / name, body, 0o444)
            self.recheck_source(component)

    def build_python(self):
        prefix, source = self.private / "prefix", self.source_trees["cpython"]
        directory = self.private / "build/cpython"
        directory.mkdir(mode=0o700)
        (directory / "Modules").mkdir(mode=0o700)
        setup = read(self.root / "desktop/tools/macos_cpython_source_setup.local", 16384)
        setup = setup.replace(b"@MRK_PREFIX@", str(prefix).encode("ascii"))
        need(b"@MRK_" not in setup, "python-template-token")
        write(directory / "Modules/Setup.local", setup, 0o444)
        environment = {**self.environment, **self.orchestration_config,
            "MODULE_BUILDTYPE": "static", "ZLIB_CFLAGS": "-I" + str(prefix / "include"),
            "ZLIB_LIBS": str(prefix / "lib/libz.a"),
            "LDFLAGS": self.environment["LDFLAGS"] + " -L" + str(prefix / "lib")}
        self.run("python-configure", [self.shell, str(source / "configure"), *PYTHON_CONFIGURE,
            "--with-openssl=" + str(prefix)], cwd=directory, env=environment)
        self.phase = "python-configuration-admission"
        names = ("Makefile", "pyconfig.h", "Modules/config.c", "Modules/Setup.local")
        configuration = {name: read(directory / name, 2 * MIB) for name in names}
        # Retain these bounded credential-free original generated inputs before
        # admission, so a refusal is diagnosable without another native build.
        self.evidence_json("python-configuration.json", {name: digest(body) for name, body in configuration.items()})
        for name, body in configuration.items():
            self.evidence_bytes("python-" + name.replace("/", "-").lower() + ".txt", body)
        need(configuration["Modules/Setup.local"] == setup, "python-setup-changed")
        self.configuration = python_configuration(configuration, prefix, self.sdk, self.clang, self.orchestrator, self.target)
        make_args = [self.make, "-j2", "PYTHON_FOR_REGEN=" + self.orchestrator,
                     "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B"]
        self.run("python-builtin-archives", [*make_args, *HACL, "Modules/expat/libexpat.a"], cwd=directory, env=environment)
        # NODIST avoids embedding a linker map option in installed extension
        # configuration; it affects only this interpreter link/build stage.
        linkflags = "LDFLAGS_NODIST=-Wl,-map," + str(directory / "python-link.map")
        self.run("python-build", [*make_args, linkflags, self.configuration["executable"], "pybuilddir.txt", "build-details.json"],
                 cwd=directory, env=environment)
        self.recheck_source("cpython")
        self.python_build = directory
        self.evidence_bytes("python-link.map", read(directory / "python-link.map", 8 * MIB))
        self.evidence_json("build.json", {"sourceCommit": self.source, "configuration": self.configuration,
            "linkMapSha256": digest(self.evidence["python-link.map"]), "pythonVersion": "3.14.7", "gil": True,
            "dependencies": {"openssl": "3.5.8 static", "zlib": "1.3.2 static", "libffi": "Apple system"}})

    def project(self):
        self.phase = "supplier-projection"
        self.payload = self.private / "supplier"
        self.payload.mkdir(mode=0o700)
        files = {}

        def add(name, body, mode=0o444):
            self.check()
            need(name.startswith("python/") and name not in files, "payload-projection-collision")
            source_name(name)
            path = self.payload / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            files[name] = {"path": name, **write(path, body, mode)}

        # Whole build tree inspection refuses unselected native outputs rather
        # than silently pruning them into an acceptable projection.
        for directory, subdirs, names in walk_tree(self.python_build):
            self.check()
            need(not any((Path(directory) / name).is_symlink() for name in subdirs + names), "python-build-alias")
            need(not any(name.endswith((".so", ".dylib", ".pyd", ".dll")) or ".so." in name for name in names),
                 "python-unselected-native-output")
        binary = read(self.python_build / self.configuration["executable"], 128 * MIB)
        # Linker normally ad-hoc signs ARM Mach-O already; always do one explicit
        # reproducible local signature before final binary/loader inventory.
        add("python/bin/python3", binary, 0o555)
        for row in self.stdlib:
            add(row.destination, read(self.source_trees["cpython"] / row.source, row.size,
                                      expected=(row.size, row.sha256)))
        generated = read(self.python_build / "pybuilddir.txt", 4096)
        need(re.fullmatch(rb"build/[A-Za-z0-9._+\-]+", generated), "python-generated-route")
        generated_root = self.python_build / generated.decode("ascii")
        names = {entry.name for entry in directory_entries(generated_root)}
        need(names == set(self.configuration["generated"]), "python-generated-complete-roster")
        for name in self.configuration["generated"]:
            add("python/lib/python3.14/" + name, read(generated_root / name, 2 * MIB))
        add("python/lib/python314.zip", b"PK\x05\x06" + b"\0" * 18)
        add("python/lib/python3.14/lib-dynload/README.mrk", b"All selected extension modules are built in.\n")
        notices = []
        lock = decode(self.lock_body)
        for ordinal, row in enumerate(lock["requiredPublicNoticeInputs"]):
            name = "python/licenses/" + row["component"] + "-" + row["path"].replace("/", "-")
            add(name, read(self.source_trees[row["component"]] / row["path"], row["bytes"],
                           expected=(row["bytes"], row["sha256"])))
            notices.append(name)
        # Retain original HACL source/header bytes rather than invent a license
        # that does not exist in this source release. The MIT notices are inside
        # the original headers, and all nominated HACL sources are covered.
        hacl = []
        for name, row in self.source_rows["cpython"].items():
            if name.startswith("Modules/_hacl/") and name.endswith((".c", ".h")):
                target = "python/licenses/hacl-source-" + name[len("Modules/_hacl/"):].replace("/", "-") + ".txt"
                add(target, read(self.source_trees["cpython"] / name, row["size"], expected=(row["size"], row["sha256"])))
                notices.append(target)
                hacl.append({"source": name, "sourceSha256": row["sha256"], "notice": target})
        need(hacl, "hacl-original-notices-missing")
        self.notice_paths = sorted(notices)
        self.notice_evidence = {"sixPublicInputs": lock["requiredPublicNoticeInputs"], "haclOriginals": hacl,
            "privateLibffi": "source-nominated/not-incorporated; LICENSE retained conservatively",
            "systemReferences": "Apple frameworks/system libffi are not bundled bytes"}
        executable = self.payload / "python/bin/python3"
        os.chmod(executable, 0o700)
        self.run("python-adhoc-sign", [self.codesign, "--force", "--sign", "-", "--timestamp=none",
                 "--identifier", "org.mobile-release-kit.python.source", str(executable)], maximum=60)
        os.chmod(executable, 0o555)
        self.run("python-signature-verify", [self.codesign, "--verify", "--strict", str(executable)], maximum=30)
        signed = read(executable, 128 * MIB)
        self.probe.macho(signed, self.target)
        files["python/bin/python3"].update(size=len(signed), sha256=digest(signed))
        self.files = sorted(files.values(), key=lambda row: row["path"])
        seal(self.payload)
        self.check_payload()

    def check_payload(self, *, deadline=None):
        actual = tree_rows(self.payload, maximum=PAYLOAD_LIMIT, max_files=PAYLOAD_FILES,
                          deadline=self.deadline if deadline is None else deadline)
        need(list(actual.values()) == self.files, "supplier-complete-byte-mode-correspondence")

    def _move_payload(self, role, *, deadline):
        """Move only the same sealed task payload; Darwin requires root write permission."""
        relocated_parent = self.private / "relocated parent with spaces"
        routes = {
            "relocation": (self.private / "supplier", relocated_parent / "release kit runtime",
                           self.private_identity, self.relocation_parent_identity),
            "retention": (relocated_parent / "release kit runtime", self.work / "retained-supplier",
                          self.relocation_parent_identity, self.work_identity),
            "export": (self.work / "retained-supplier", self.work / "export/supplier",
                       self.work_identity, self.export_identity),
        }
        need(role in routes, "supplier-move-role")
        source, destination, source_parent, destination_parent = routes[role]
        phase = "supplier-" + role
        self.phase = phase + "-admission"

        def bound(value, code):
            if not value:
                DATA.unknown()
                raise BuildRefused(code)

        verdict = self.guard.lifetime_ledger.verdict()
        need(DATA.known and not self.inflight and verdict.complete and not verdict.fatal and verdict.contained,
             "supplier-move-original-finality")
        bound(self.payload == source and custody(self.work.lstat()) == self.work_identity,
              "supplier-move-source-route")
        remaining(deadline, time.monotonic(), CLEANUP_SECONDS if role != "relocation" else WORK_SECONDS)
        self.check_payload(deadline=deadline)
        original = source.lstat()
        need(stat.S_ISDIR(original.st_mode) and original.st_uid == os.getuid()
             and stat.S_IMODE(original.st_mode) == 0o555, "supplier-move-sealed-root")
        specs = ((source.parent, source_parent), (destination.parent, destination_parent))
        before_parents = []
        for parent, expected in specs:
            current = parent.lstat()
            bound(custody(current) == expected and stat.S_ISDIR(current.st_mode)
                  and current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,
                  "supplier-move-parent-original")
            before_parents.append(current)

        failure = failure_phase = None
        # Private original exceptions only: never serialize their messages or
        # tracebacks. The fixed one-operation/three-close path bounds this list.
        self.payload_move_errors = []
        parent_fds, root_fd = [], None
        restore_required, mode_restored, move_post_known = False, False, False
        outcome = "not-entered"
        post_root, post_parents = None, None

        def remember(error):
            nonlocal failure, failure_phase
            if failure is None:
                failure, failure_phase = error, self.phase
            self.payload_move_errors.append((self.phase, error))

        def close_original(fd, label):
            self.phase = phase + "-close-" + label
            try:
                os.close(fd)
            except BaseException as error:
                # ExitStack still closes the other original descriptors. Keep
                # each error even if a later close changes its raised exception.
                remember(error)
                raise

        def absent(name, fd):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False

        def same_root(mode):
            current = os.fstat(root_fd)
            bound(custody(current) == (original.st_dev, original.st_ino,
                  stat.S_IFDIR | mode, original.st_uid, original.st_gid), "supplier-move-root-original")
            return current

        def same_parents():
            for (parent, expected), fd in zip(specs, parent_fds):
                held, named = os.fstat(fd), parent.lstat()
                bound(custody(held) == expected and identity(named) == identity(held),
                      "supplier-move-parent-post")

        def closed_originals():
            try:
                need(identity(destination.lstat()) == post_root
                     and all(identity(parent.lstat()) == expected
                             for (parent, _), expected in zip(specs, post_parents)), "supplier-move-closed-post")
            except BaseException:
                DATA.unknown()
                raise

        try:
            with ExitStack() as originals:
                try:
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                    for label, ((parent, _), before) in zip(
                            ("source-parent", "destination-parent"), zip(specs, before_parents)):
                        fd = originals.enter_context(DATA.acquiring(
                            os.open, lambda value, label=label: close_original(value, label), parent, flags))
                        parent_fds.append(fd)
                        bound(identity(os.fstat(fd)) == identity(before)
                              and identity(parent.lstat()) == identity(before), "supplier-move-parent-open")
                    root_fd = originals.enter_context(DATA.acquiring(
                        os.open, lambda value: close_original(value, "payload-root"),
                        source.name, flags, dir_fd=parent_fds[0]))
                    bound(identity(os.fstat(root_fd)) == identity(original)
                          and identity(os.stat(source.name, dir_fd=parent_fds[0], follow_symlinks=False))
                          == identity(original), "supplier-move-root-open")
                    need(absent(destination.name, parent_fds[1]), "supplier-move-destination-collision")
                    same_parents()
                    self.phase = phase + "-enable-root-write"
                    remaining(deadline, time.monotonic())
                    # Arm restoration before the syscall, including a lost successful result.
                    restore_required = True
                    os.fchmod(root_fd, 0o755)
                    same_root(0o755)
                    self.phase = phase + "-rename"
                    remaining(deadline, time.monotonic())
                    outcome = "unknown"
                    try:
                        os.rename(source.name, destination.name,
                                  src_dir_fd=parent_fds[0], dst_dir_fd=parent_fds[1])
                    except OSError as error:
                        remember(error)
                        # A failed rename is known only while the same original remains
                        # at the old name and the fixed destination is still absent.
                        self.phase = phase + "-failed-rename-post"
                        try:
                            if (identity(os.stat(source.name, dir_fd=parent_fds[0], follow_symlinks=False))
                                    == identity(same_root(0o755)) and absent(destination.name, parent_fds[1])):
                                same_parents()
                                outcome = "failed"
                        except BaseException as post_error:
                            DATA.unknown()
                            remember(post_error)
                        raise
                    self.payload = destination
                    outcome = "moved"
                except BaseException as error:
                    if not any(error is saved for _, saved in self.payload_move_errors):
                        remember(error)
                finally:
                    if outcome == "unknown":
                        DATA.unknown()
                    if restore_required:
                        self.phase = phase + "-restore-root-mode"
                        try:
                            os.fchmod(root_fd, 0o555)
                            same_root(0o555)
                            mode_restored = True
                        except BaseException as error:
                            DATA.unknown()
                            remember(error)
                    if root_fd is not None and outcome != "unknown":
                        self.phase = phase + "-named-post"
                        try:
                            held = same_root(0o555)
                            named = destination if outcome == "moved" else source
                            named_fd = parent_fds[1] if outcome == "moved" else parent_fds[0]
                            need(identity(os.stat(named.name, dir_fd=named_fd, follow_symlinks=False))
                                 == identity(held), "supplier-move-named-original")
                            if outcome == "moved":
                                need(absent(source.name, parent_fds[0]), "supplier-move-source-still-present")
                            same_parents()
                            post_root = identity(held)
                            post_parents = [identity(os.fstat(fd)) for fd in parent_fds]
                            move_post_known = True
                        except BaseException as error:
                            DATA.unknown()
                            remember(error)
                    self.phase = phase + "-close-originals"
        except BaseException as error:
            if not any(error is saved for _, saved in self.payload_move_errors):
                remember(error)
        finally:
            # Includes interruption of the unwind itself: an unfinished mode or
            # membership proof must not look known merely because fd closes ran.
            if restore_required and (not mode_restored or not move_post_known or outcome == "unknown"):
                DATA.unknown()
        if failure is not None:
            self.phase = failure_phase
            raise failure
        self.phase = phase + "-payload-post"
        need(DATA.known and outcome == "moved", "supplier-move-close-finality")
        remaining(deadline, time.monotonic())
        closed_originals()
        self.check_payload(deadline=deadline)
        closed_originals()
        remaining(deadline, time.monotonic())

    def native_probes(self):
        probe = str(self.root / "desktop/tools/macos_cpython_source_probe.py")
        hashes = {name: row["sha256"] for name, row in self.source_binding.items()}

        def run_set(label, roles):
            context = {"schemaVersion": 1, "target": self.target, "payload": str(self.payload), "checkout": str(self.root),
                "scratch": str(self.private / "probe-scratch"), "sourceCommit": self.source,
                "builtins": self.configuration["builtins"], "files": self.files, "sourceFiles": hashes}
            path = self.private / (label + "-probe-context.json")
            write(path, canonical(context), 0o444)
            results = {}
            clean = {key: self.environment[key] for key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ")}
            for role in roles:
                result = self.run(label + "-" + role, [str(self.payload / "python/bin/python3"), "-I", "-S", "-B",
                    probe, role, self.target, str(path)], env=clean, maximum=60)
                results[role] = probe_result(result.stdout, role, self.target, self.probe)
            self.phase = label + "-payload-post"
            self.check_payload()
            return results

        original = run_set("original", ("modules", "loader", "tls", "cancellation"))
        parent = self.private / "relocated parent with spaces"
        self.phase = "supplier-relocation-parent-create"
        parent.mkdir(mode=0o700)
        self.phase = "supplier-relocation-parent-post"
        self.relocation_parent_identity = custody(parent.lstat())
        old = self.payload
        self._move_payload("relocation", deadline=self.deadline)
        relocated = self.payload
        need(not old.exists() and not old.is_symlink(), "payload-original-not-retired")
        moved = run_set("relocated", ("modules", "loader", "tls"))
        self.native = {key: original[key] for key in ("modules", "loader", "tls", "cancellation")}
        self.native["relocation"] = {"original": str(old), "relocated": str(relocated),
            "originalAbsent": True, "modules": moved["modules"], "loader": moved["loader"], "tls": moved["tls"]}
        for role, result in self.native.items():
            self.evidence_json(role + ".json", {"sourceCommit": self.source, "inventorySha256": digest(canonical(self.files)),
                                                "result": result})
        directories = {self.payload}
        for row in self.files:
            directories.update(self.payload / parent for parent in PurePosixPath(row["path"]).parents)
        paths = [*sorted(directories), *(self.payload / row["path"] for row in self.files)]
        # macOS ls's '+' ACL marker and extended ACL rows are checked, not
        # assumed absent from listxattr (ACLs are a separate native facility).
        acl = self.run("supplier-no-acls", [self.ls, "-lde", *(str(path) for path in paths)], maximum=30)
        lines = acl.stdout.decode("utf-8", "strict").splitlines()
        need(len(lines) == len(paths) and all(re.fullmatch(r"[d-][rwxstST-]{9}", line.split()[0]) for line in lines),
             "supplier-extended-acl")

    def notices(self):
        self.phase = "incorporated-notices"
        objects, components = link_map_objects(
            self.evidence["python-link.map"], self.private / "prefix", self.python_build, self.sdk)
        self.notice_evidence.update(objects=objects, incorporated=sorted(components),
                                    linkMapSha256=digest(self.evidence["python-link.map"]))
        self.evidence_json("notices.json", self.notice_evidence)

    def cleanup(self):
        verdict = self.guard.lifetime_ledger.verdict()
        need(DATA.known and not self.inflight and verdict.complete and not verdict.fatal and verdict.contained,
             "original-command-finality-unknown")
        need(custody(self.work.lstat()) == self.work_identity, "original-task-root-changed")
        cleanup_deadline = min(self.deadline + CLEANUP_SECONDS, time.monotonic() + CLEANUP_SECONDS)
        if self.failure is None and self.payload is not None:
            self.retained = self.work / "retained-supplier"
            need(not self.retained.exists() and not self.retained.is_symlink(), "supplier-retention-collision")
            self._move_payload("retention", deadline=cleanup_deadline)
        if self.private_identity is not None:
            need(custody(self.private.lstat()) == self.private_identity, "original-private-root-changed")
            retire_tree(self.private, cleanup_deadline)
        self.scratch_retired = True

    def execute(self):
        scope = self.control.CleanupScope(self.guard, self.cleanup, owns_cancellation=True, first_primary=True)
        caught = None
        try:
            try:
                with scope:
                    self.guard.install()
                    self.guard.activate()
                    try:
                        self.prepare()
                        self.sources()
                        self.build_dependencies()
                        self.build_python()
                        self.project()
                        self.native_probes()
                        self.notices()
                        self.recheck_tools(full=True)
                        need(source_snapshot(self.root, self.target) == self.source_binding, "producer-source-post")
                        self.check()
                    except BaseException as error:
                        self.failure = {"phase": self.phase, "type": type(error).__name__,
                                        "reason": str(error) if type(error) is BuildRefused else "original-operation-failed"}
                        raise
            finally:
                scope.__exit__(*sys.exc_info())
        except BaseException as error:
            caught = error
            if self.failure is None:
                self.failure = {"phase": "cleanup", "type": type(error).__name__, "reason": "original-cleanup-failed"}
        self.cleanup_errors = [type(error).__name__ for error in scope._cleanup_errors]
        verdict = self.guard.lifetime_ledger.verdict()
        settled = DATA.known and not self.inflight and verdict.complete and not verdict.fatal and verdict.contained
        settled = settled and self.guard.handler_state == "RESTORED"
        # No public export while original processes/FDs/handlers might still be
        # live. A directory's existence is not used to infer any finality.
        if settled:
            self.publish(verdict)
        if caught is not None:
            raise caught

    def publish(self, verdict):
        self.final_check()
        self.evidence_json("source-binding.json", {"sourceCommit": self.source, "files": self.source_binding})
        self.evidence_json("commands.json", self.commands)
        state = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained}
        success = public_eligible(failure=self.failure, entered=self.entered, returned=self.returned,
            ledger=state, handlers=self.guard.handler_state, scratch_retired=self.scratch_retired,
            data_finality=DATA.known)
        success = success and not self.cleanup_errors
        report = {"schemaVersion": 1, "sourceCommit": self.source, "target": self.target,
            "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "state": "qualified-supplier" if success else "failed-no-supplier", "failure": self.failure,
            "commandsEntered": self.entered, "commandsReturned": self.returned, "lifetime": state,
            "handlers": self.guard.handler_state, "scratchRetired": self.scratch_retired,
            "dataFinality": "KNOWN" if DATA.known else "UNKNOWN",
            "cleanupErrors": self.cleanup_errors, "elapsedSeconds": round(time.monotonic() - self.started, 3)}
        self.evidence_json("run-result.json", report)
        export = self.work / "export"
        export.mkdir(mode=0o700)
        self.export_identity = custody(export.lstat())
        (export / "evidence").mkdir(mode=0o700)
        for name, body in self.evidence.items():
            self.final_check()
            write(export / "evidence" / name, body, 0o444)
        if not success:
            self.final_check()
            need(not self.public.exists() and not self.public.is_symlink(), "public-export-collision")
            export.rename(self.public)
            return
        need(set(EVIDENCE_ROLES) <= {Path(name).stem for name in self.evidence}, "supplier-required-evidence")
        supplier = export / "supplier"
        self._move_payload("export", deadline=self.deadline + CLEANUP_SECONDS)
        receipt = {"schemaVersion": 1, "kind": "mrk-macos-cpython-source-supplier-v1",
            "target": self.target, "pythonVersion": "3.14.7", "gil": True,
            "sourceLockSha256": self.source_lock["sha256"],
            "producerSourceSha256": self.source_binding["desktop/tools/macos_cpython_source_build.py"]["sha256"],
            "recipeSha256": digest(canonical({name: row["sha256"] for name, row in self.source_binding.items()})),
            "toolchainSha256": digest(self.evidence["toolchain.json"]),
            "inventorySha256": digest(canonical(self.files)), "files": self.files, "notices": self.notice_paths,
            "nativeEvidence": {role: digest(self.evidence[role + ".json"]) for role in EVIDENCE_ROLES}}
        need(len(canonical(receipt)) <= MIB, "supplier-receipt-bound")
        archive = export / "supplier.tar"
        archive_record = supplier_tar(supplier, archive, self.files, deadline=self.deadline + CLEANUP_SECONDS)
        write(export / "evidence/supplier-archive.json", canonical(archive_record), 0o444)
        self.check_payload(deadline=self.deadline + CLEANUP_SECONDS)
        # Receipt last. Workflow still requires the actual outer entry exit0;
        # these self-describing bytes never activate installed consumers.
        write(export / "supplier-receipt.json", canonical(receipt), 0o444)
        # Only a completed, closed export acquires the public path. Neither
        # partial receipt writes nor interrupted tar writers are uploadable.
        self.final_check()
        need(not self.public.exists() and not self.public.is_symlink(), "public-export-collision")
        export.rename(self.public)
        self.payload = self.public / "supplier"


def tree_rows(root, *, maximum, max_files, source=False, deadline=None):
    total, rows, aliases, seen_directories = 0, {}, set(), set()
    pending = [root]
    while pending:
        if deadline is not None:
            remaining(deadline, time.monotonic())
        directory = pending.pop()
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and stat.S_IMODE(info.st_mode) == 0o555, "readonly-directory")
        need(xattrs_absent(directory, info), "directory-extended-attributes")
        seen_directories.add(directory.relative_to(root).as_posix())
        with DATA.acquiring(os.scandir, lambda stream: stream.close(), directory) as entries:
            for entry in entries:
                if deadline is not None:
                    remaining(deadline, time.monotonic())
                info = entry.stat(follow_symlinks=False)
                name = source_name(Path(entry.path).relative_to(root).as_posix())
                need(name.casefold() not in aliases, "tree-case-alias")
                aliases.add(name.casefold())
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                         and xattrs_absent(Path(entry.path), info), "tree-ordinary-file")
                    mode = stat.S_IMODE(info.st_mode)
                    need(mode in {0o444, 0o555} if source else mode == (0o555 if name == "python/bin/python3" else 0o444),
                         "tree-file-mode")
                    total += info.st_size
                    need(total <= maximum and len(rows) < max_files, "tree-extent")
                    body = read(Path(entry.path), min(maximum, info.st_size))
                    rows[name] = {"path": name, "size": len(body), "sha256": digest(body), "mode": mode}
    required_directories = {"."}
    for name in rows:
        required_directories.update(str(parent) for parent in PurePosixPath(name).parents)
    if not source:
        need(seen_directories == required_directories, "unlisted-empty-payload-directory")
    return dict(sorted(rows.items()))


def seal(root):
    for directory, names, _ in reversed(list(walk_tree(root))):
        need(not any((Path(directory) / name).is_symlink() for name in names), "payload-directory-alias")
        os.chmod(directory, 0o555)


def retire_tree(root, deadline):
    original = custody(root.lstat())
    need(original[3] == os.getuid() and stat.S_ISDIR(original[2]) and stat.S_IMODE(original[2]) == 0o700,
         "task-cleanup-root")
    entries, total = 0, 0
    for directory, names, files in walk_tree(root):
        remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
        current = Path(directory)
        info = current.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "task-cleanup-directory")
        os.chmod(current, 0o700)
        for name in names + files:
            info = (current / name).lstat()
            entries, total = entries + 1, total + info.st_size
            need(entries <= 65536 and total <= 4 * 1024 * MIB and info.st_uid == os.getuid()
                 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) and info.st_nlink >= 1,
                 "task-cleanup-census")
    need(custody(root.lstat()) == original and shutil.rmtree.avoids_symlink_attacks, "task-cleanup-custody")
    try:
        shutil.rmtree(root)
    except BaseException:
        # rmtree owns internal directory descriptors. A compound cleanup error
        # does not prove their original closes; withhold public output rather
        # than retrying deletion or manufacturing a settled failed receipt.
        DATA.unknown()
        raise
    need(not root.exists() and not root.is_symlink(), "task-cleanup-postcondition")
    remaining(deadline, time.monotonic(), CLEANUP_SECONDS)


def supplier_tar(root, output, files, *, deadline):
    remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
    directories = sorted({str(parent) for row in files for parent in PurePosixPath(row["path"]).parents if str(parent) != "."})
    with DATA.acquiring(os.open, os.close, output,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444) as fd:
        with DATA.closing(os.fdopen(fd, "wb", closefd=False)) as stream:
            with DATA.closing(tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT)) as archive:
                for name in directories:
                    remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
                    item = tarfile.TarInfo(name)
                    item.type, item.mode, item.uid, item.gid, item.mtime = tarfile.DIRTYPE, 0o555, 0, 0, 0
                    archive.addfile(item)
                for row in files:
                    remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
                    body = read(root / row["path"], row["size"], expected=(row["size"], row["sha256"]))
                    item = tarfile.TarInfo(row["path"])
                    item.size, item.mode, item.uid, item.gid, item.mtime = len(body), row["mode"], 0, 0, 0
                    archive.addfile(item, io.BytesIO(body))
            stream.flush()
        need(os.fstat(fd).st_size <= PAYLOAD_LIMIT + 4 * MIB, "supplier-tar-bound")
    # Actual complete readback/close, including each retained regular body's
    # exact digest/mode. Later consumer extraction independently repeats admission.
    body = read(output, PAYLOAD_LIMIT + 4 * MIB)
    expected = {row["path"]: row for row in files}
    seen_files, seen_directories = set(), set()
    with DATA.closing(tarfile.open(fileobj=io.BytesIO(body), mode="r:")) as archive:
        for item in archive:
            remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
            need(item.uid == item.gid == item.mtime == 0, "supplier-tar-metadata")
            if item.isdir():
                need(item.name in directories and item.name not in seen_directories and item.mode == 0o555,
                     "supplier-tar-directory")
                seen_directories.add(item.name)
            else:
                need(item.isreg() and item.name in expected and item.name not in seen_files,
                     "supplier-tar-file")
                row = expected[item.name]
                need(item.size == row["size"] and item.mode == row["mode"], "supplier-tar-size-mode")
                stream = archive.extractfile(item)
                need(stream is not None, "supplier-tar-body")
                with DATA.closing(stream):
                    copied = stream.read(row["size"] + 1)
                    need(len(copied) == row["size"] and digest(copied) == row["sha256"]
                         and not stream.read(1), "supplier-tar-body-correspondence")
                seen_files.add(item.name)
        tail = body[archive.offset:]
        need(len(tail) >= 1024 and len(tail) % 512 == 0 and not any(tail), "supplier-tar-framing")
    need(seen_files == set(expected) and seen_directories == set(directories), "supplier-tar-complete-roster")
    remaining(deadline, time.monotonic(), CLEANUP_SECONDS)
    return {"path": "supplier.tar", "size": len(body), "sha256": digest(body),
            "files": len(files), "directories": len(directories), "modePreservation": True}


def source_snapshot(root, target=ARM_TARGET):
    profile = target_profile(target)
    fixed = {profile["workflow"], "desktop/tools/macos_cpython_source_build.py", "desktop/tools/macos_cpython_source_probe.py",
             "desktop/tools/macos_cpython_orchestrator.py",
             "desktop/tools/macos_cpython_source_setup.local", "desktop/tools/macos_cpython_source_recipe.py",
             "desktop/tools/macos_aqua_qualification.py", profile["lock"],
             PROVENANCE[0]}
    fixed.update("desktop/cpython-source-inputs/" + name + "-source-inventory.json" for name in ("cpython", "libffi", "openssl", "zlib"))
    fixed.update((directory / name).relative_to(root).as_posix()
                 for directory, _, names in walk_tree(root / "src/mobile_release") for name in names if name.endswith(".py"))
    fixed.update("desktop/src-tauri/tests/fixtures/github_tls/" + name for name in (
        "api-valid.pem", "root-ca.pem", "other-root-ca.pem", "server-key.pem"))
    need(len(fixed) <= 1024, "producer-source-count")
    result = {}
    for name in sorted(fixed):
        path = root / name
        body = read(path, 2 * MIB)
        result[name] = {"size": len(body), "sha256": digest(body), "identity": identity(path.lstat())}
    return result


def main():
    target = target_for_route(os.environ.get("GITHUB_WORKFLOW_REF"), os.environ.get("GITHUB_REF"))
    profile = target_profile(target)
    need(len(sys.argv) == 1 and sys.platform == "darwin" and os.uname().machine == profile["machine"]
         and platform.mac_ver()[0].startswith("26.") and sys.version_info[:3] == (3, 14, 7)
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(), "fixed-native-producer-host")
    source, run, attempt = (os.environ.get(key, "") for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    need(re.fullmatch(r"[0-9a-f]{40}", source) and source != "0" * 40
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)), "fixed-native-producer-run")
    route = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": profile["runnerArch"], "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": profile["reference"], "GITHUB_WORKFLOW_SHA": source, "GITHUB_JOB": "producer",
        "GITHUB_WORKFLOW_REF": REPOSITORY + "/" + profile["workflow"] + "@" + profile["reference"],
        "GITHUB_WORKSPACE": str(CHECKOUT), "RUNNER_TEMP": str(WORK_PARENT)}
    need(all(os.environ.get(key) == value for key, value in route.items()), "fixed-native-producer-route")
    need(read(CHECKOUT / ".git/HEAD", 41) == source.encode() + b"\n", "fixed-detached-source")
    original_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    need(original_limits[0] == resource.RLIM_INFINITY or original_limits[0] > 0,
         "fixed-native-descriptor-bound")
    if original_limits[0] == resource.RLIM_INFINITY or original_limits[0] > 1024:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, original_limits[1]))
    selected_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    need(0 < selected_limits[0] <= 1024 and selected_limits[1] == original_limits[1],
         "fixed-native-descriptor-bound")
    os.umask(0o077)
    before = source_snapshot(CHECKOUT, target)
    tools = CHECKOUT / "desktop/tools"
    orchestration = load_module("_mrk_macos_orchestration", tools / "macos_cpython_orchestrator.py")
    need(orchestration._BUILD is None, "orchestration-facade-already-bound")
    # Share this original DATA ledger; do not hide preparation-file FD finality
    # in a second imported copy of the builder before entering its native owner.
    orchestration._BUILD = sys.modules[__name__]
    orchestration_config = orchestration.build_entry_configuration()
    recipe = load_module("_mrk_macos_source_data", tools / "macos_cpython_source_recipe.py")
    probe = load_module("_mrk_macos_source_probe", tools / "macos_cpython_source_probe.py")
    qualification = load_module("_mrk_macos_source_qualification", tools / "macos_aqua_qualification.py")
    owner = qualification.load_owner(CHECKOUT)
    from mobile_release import cancellation
    work = WORK_PARENT / f"{profile['workPrefix']}-{source}-{run}-{attempt}"
    work.mkdir(mode=0o700)  # No adoption, reset, overwrite or retry of an existing task.
    build = Build(CHECKOUT, work, source, owner, cancellation, recipe, probe, target)
    build.orchestration_config = orchestration_config
    build.descriptor_limits = {"original": original_limits, "selected": selected_limits}
    build.source_binding = before
    try:
        build.execute()
    except BaseException:
        # The public directory, if present, was separately gated on known
        # process/FD/handler finality. No raw exception/credential text is printed.
        print("Fresh Darwin Python producer failed; retain only admitted evidence.", file=sys.stderr)
        raise SystemExit(1) from None
    print("Fresh Darwin Python supplier qualified; consumer activation is separate.")


if __name__ == "__main__":
    main()
