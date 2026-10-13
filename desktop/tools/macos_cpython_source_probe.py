"""Fixed Darwin qualification of the fresh SOURCE-built interpreter.

Import defines DATA/functions only. Native entry is invoked by the reviewed
producer through run_owned and the existing network-deny sandbox. It is not a
general process runner, supplier admission, installed-app or signing approval.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
_TARGETS = {
    ARM_TARGET: ("arm64", 0x100000C, 0),
    INTEL_TARGET: ("x86_64", 0x1000007, 3),
}

TLS_FILES = {
    "api-valid.pem": (786, "33f6acd10b8d466078525b80464a1c5938266b1084ea5aabf43b348bd7dca6f2"),
    "root-ca.pem": (761, "3d785e2a47139241c55b340b4d07a5de79aed18b9c28157f9dbe9f694b461025"),
    "other-root-ca.pem": (778, "69b4eda8770c518de6e83caa5037bcf5d38f9f9ec16ef3c1e7c11023627a018c"),
    # Deliberately public synthetic fixture, NOT a user/signing credential.
    "server-key.pem": (241, "33332bb26fd6e394d067f7e2df563d496f934e0a098de1e3039169fb8d4ee109"),
}
READY = b"mrk-native-child-ready\n"
CHILD = ("import os,sys,time; p=sys.argv[1]; "
         "f=os.open(p+'.writing',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); "
         "n=os.write(f,b'mrk-native-child-ready\\n'); os.close(f); "
         "assert n==23; os.rename(p+'.writing',p); time.sleep(30)")


class ProbeRefused(ValueError):
    pass


def need(value, code):
    if not value:
        raise ProbeRefused(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(body):
    return hashlib.sha256(body).hexdigest()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read(path, limit):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and 0 <= before.st_size <= limit, "probe-ordinary-input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(before), "probe-input-open-change")
        blocks, count = [], 0
        while count < before.st_size:
            block = os.read(fd, min(65536, before.st_size - count))
            need(block, "probe-input-short")
            blocks.append(block)
            count += len(block)
        need(not os.read(fd, 1) and identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before), "probe-input-post-change")
    finally:
        os.close(fd)
    return b"".join(blocks)


def target_description(target):
    need(type(target) is str and target in _TARGETS, "probe-target")
    return _TARGETS[target]


def native_host_data(target, *, sysname, machine, returned, observed_errno, length, translated):
    """Check native host observations, never query or emulate a host."""
    if (type(target) is not str or target not in _TARGETS
            or type(sysname) is not str or sysname != "Darwin"
            or type(machine) is not str or machine != _TARGETS[target][0]
            or type(returned) is not int):
        return False
    if returned == 0:
        # Like sysctl's native contract, errno is unspecified on success.
        return type(length) is int and length == 4 and type(translated) is int and translated == 0
    # An absent sysctl is the documented native, untranslated fallback. Failed
    # calls do not establish either output cell, so neither cell is consulted.
    return returned == -1 and type(observed_errno) is int and observed_errno == errno.ENOENT


def native_host(target):
    """Query only inside this already-owned native probe process."""
    import ctypes
    target_description(target)
    need(ctypes.sizeof(ctypes.c_int) == 4
         and ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_size_t) == 8,
         "native-host-abi")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    query = library.sysctlbyname
    query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                      ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    translated = ctypes.c_int(0)
    length = ctypes.c_size_t(ctypes.sizeof(translated))
    ctypes.set_errno(0)
    returned = query(b"sysctl.proc_translated", ctypes.byref(translated),
                     ctypes.byref(length), None, 0)
    observed_errno = ctypes.get_errno()
    observed = os.uname()
    result = {"sysname": observed.sysname, "machine": observed.machine,
              "returned": returned, "observed_errno": observed_errno,
              "length": length.value if returned == 0 else None,
              "translated": translated.value if returned == 0 else None}
    need(native_host_data(target, **result), "native-host-translation")
    return result


def macho(body, target=ARM_TARGET):
    """Bounded Mach-O DATA parser; rejects fat/foreign/extra-loader routes."""
    architecture, expected_cpu, expected_subtype = target_description(target)
    need(type(body) is bytes and 32 <= len(body) <= 128 * 1024 * 1024, "macho-bound")
    magic, cpu, subtype, kind, count, extent, flags, reserved = struct.unpack_from("<IiiIIIII", body)
    need((magic, cpu, subtype, kind, reserved) == (0xFEEDFACF, expected_cpu, expected_subtype, 2, 0)
         and 1 <= count <= 128 and 0 < extent <= 32768 and 32 + extent <= len(body),
         "macho-native-thin-executable")
    allowed = {0x19, 0x2, 0xB, 0xE, 0x1B, 0x24, 0x26, 0x29, 0x2A, 0x1D,
               0x80000022, 0x80000028, 0x80000033, 0x80000034, 0x32,
               0xC, 0x80000018}
    cursor, libraries, builds, dylinkers, observed = 32, [], [], [], []
    for _ in range(count):
        need(cursor + 8 <= 32 + extent, "macho-command-header")
        command, size = struct.unpack_from("<II", body, cursor)
        need(command in allowed and size >= 8 and size % 8 == 0
             and cursor + size <= 32 + extent, "macho-command-shape")
        chunk = body[cursor:cursor + size]
        observed.append(command)
        if command in {0xC, 0x80000018, 0xE}:
            minimum = 12 if command == 0xE else 24
            need(size >= minimum, "macho-loader-shape")
            offset = struct.unpack_from("<I", chunk, 8)[0]
            need(minimum <= offset < size and b"\0" in chunk[offset:], "macho-loader-name")
            name, padding = chunk[offset:].split(b"\0", 1)
            need(name and not any(padding), "macho-loader-padding")
            try:
                name = name.decode("ascii", "strict")
            except UnicodeError as error:
                raise ProbeRefused("macho-loader-name") from error
            need(".." not in name.split("/") and not any(ord(c) < 32 for c in name), "macho-loader-route")
            if command == 0xE:
                dylinkers.append(name)
            else:
                need(name.startswith(("/usr/lib/", "/System/Library/")), "macho-non-system-library")
                libraries.append(name)
        elif command == 0x32:
            need(size >= 24, "macho-build-shape")
            platform, minimum, sdk, tools = struct.unpack_from("<IIII", chunk, 8)
            need(platform == 1 and minimum == 26 << 16 and sdk >= 26 << 16
                 and tools <= 8 and size == 24 + tools * 8, "macho-macos-deployment")
            builds.append({"minimum": minimum, "sdk": sdk})
        elif command == 0x24:
            # The selected modern toolchain must emit LC_BUILD_VERSION, not a
            # second legacy minimum-OS claim.
            raise ProbeRefused("macho-legacy-deployment")
        cursor += size
    need(cursor == 32 + extent and len(builds) == 1 and dylinkers == ["/usr/lib/dyld"]
         and libraries and len(libraries) == len(set(libraries))
         and 0x80000028 in observed and 0x1D in observed, "macho-complete-load-commands")
    return {"architecture": architecture, "fileType": "MH_EXECUTE", "flags": flags,
            "build": builds[0], "libraries": sorted(libraries), "commands": observed}


def decode_context(body, target):
    target_description(target)
    context = json.loads(body)
    need(type(context) is dict and context.get("target") == target, "native-probe-context-target")
    return context


def configuration(context):
    need(type(context) is dict and set(context) == {"schemaVersion", "target", "payload", "checkout",
         "builtins", "files", "sourceFiles", "scratch", "sourceCommit"}
         and type(context["schemaVersion"]) is int and context["schemaVersion"] == 1, "probe-context-shape")
    target_description(context["target"])
    payload, checkout, scratch = (Path(context[key]) for key in ("payload", "checkout", "scratch"))
    need(all(path.is_absolute() and path == path.resolve(strict=True)
             for path in (payload, checkout, scratch)), "probe-context-routes")
    need(type(context["builtins"]) is list and len(context["builtins"]) == 61
         and context["builtins"] == sorted(set(context["builtins"])), "probe-builtin-context")
    need(type(context["files"]) is list and 0 < len(context["files"]) <= 2035
         and type(context["sourceFiles"]) is dict and len(context["sourceFiles"]) <= 1024,
         "probe-context-inventory")
    return payload, checkout, scratch


def modules(context):
    import ctypes
    import hashlib as hashes
    import hmac
    import importlib
    import io
    import plistlib
    import resource
    import subprocess
    import sysconfig
    import urllib.request
    import uuid
    import zipfile
    import zlib
    from xml.parsers import expat

    payload, _, _ = configuration(context)
    python = payload / "python"
    need(sys.version_info[:3] == (3, 14, 7) and sys._is_gil_enabled()
         and sysconfig.get_config_var("Py_GIL_DISABLED") in (None, 0)
         and sys.platform == "darwin" and os.uname().machine == target_description(context["target"])[0]
         and struct.calcsize("P") == 8, "native-version-gil-architecture")
    need(sorted(sys.builtin_module_names) == context["builtins"], "native-builtin-roster")
    for name in context["builtins"]:
        importlib.import_module(name)
    need(Path(sys.executable) == python / "bin/python3"
         and sys.prefix == sys.exec_prefix == sys.base_prefix == sys.base_exec_prefix == str(python),
         "native-relocated-prefix")
    expected_path = [str(python / "lib/python314.zip"), str(python / "lib/python3.14"),
                     str(python / "lib/python3.14/lib-dynload")]
    need(sys.path == expected_path, "native-no-external-import-path")
    rows = {row["path"]: row for row in context["files"]}
    need(len(rows) == len(context["files"]), "native-file-roster")
    origins = {}
    for name, module in tuple(sys.modules.items()):
        filename = getattr(module, "__file__", None)
        if filename is None or name == "__main__":
            continue
        path = Path(filename)
        need(path.is_absolute() and path.is_relative_to(python / "lib/python3.14"),
             "native-module-external-origin")
        relative = path.relative_to(payload).as_posix()
        need(relative in rows, "native-module-unlisted-origin")
        row = rows[relative]
        body = read(path, row["size"])
        need(len(body) == row["size"] and digest(body) == row["sha256"], "native-module-source-bytes")
        origins[name] = relative
    content = b"Mobile Release Kit native zlib/ZIP contract\0" * 128
    need(zlib.ZLIB_VERSION == zlib.ZLIB_RUNTIME_VERSION == "1.3.2"
         and zlib.decompress(zlib.compress(content)) == content, "native-zlib-roundtrip")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fixture/data.bin", content)
    with zipfile.ZipFile(io.BytesIO(buffer.getvalue()), "r") as archive:
        need(archive.namelist() == ["fixture/data.bin"] and archive.read("fixture/data.bin") == content
             and archive.testzip() is None, "native-zip-roundtrip")
    need(hashes.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
         and hmac.new(b"key", b"The quick brown fox jumps over the lazy dog", "sha256").hexdigest()
         == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
         "native-hash-hmac")
    value = {"bundle": "com.example.fixture", "build": 7, "enabled": True}
    need(all(plistlib.loads(plistlib.dumps(value, fmt=fmt)) == value
             for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML)), "native-plist-roundtrip")
    try:
        expat.ParserCreate().Parse(b"<invalid>", True)
    except expat.ExpatError:
        pass
    else:
        raise ProbeRefused("native-malformed-xml-accepted")
    need(uuid.uuid4().version == 4 and urllib.request.ProxyHandler({}).proxies == {}
         and subprocess._USE_POSIX_SPAWN is True and resource.getrlimit(resource.RLIMIT_NOFILE)[0] > 0,
         "native-core-primitives")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    libc.getpid.argtypes, libc.getpid.restype = [], ctypes.c_int
    need(libc.getpid() == os.getpid(), "native-ffi-call")
    libc.snprintf.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
    libc.snprintf.restype = ctypes.c_int
    text = ctypes.create_string_buffer(64)
    need(libc.snprintf(text, len(text), b"%d %.1f", ctypes.c_int(7), ctypes.c_double(2.5)) == 5
         and text.value == b"7 2.5", "native-ffi-apple-variadic-abi")
    compare_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    comparisons = []

    @compare_type
    def compare(left, right):
        a = ctypes.cast(left, ctypes.POINTER(ctypes.c_int))[0]
        b = ctypes.cast(right, ctypes.POINTER(ctypes.c_int))[0]
        comparisons.append((a, b))
        return (a > b) - (a < b)

    array = (ctypes.c_int * 5)(9, -4, 6, 0, 2)
    libc.qsort.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, compare_type]
    libc.qsort.restype = None
    libc.qsort(array, len(array), ctypes.sizeof(ctypes.c_int), compare)
    need(list(array) == [-4, 0, 2, 6, 9] and comparisons, "native-ffi-callback")
    return {"version": "3.14.7", "gil": True, "builtins": sorted(sys.builtin_module_names),
            "prefix": sys.prefix, "sysPath": sys.path, "moduleOrigins": origins,
            "zlib": "1.3.2", "ffi": "Apple-system-call-variadic-and-callback"}


def loader(context):
    import ctypes
    import urllib.request  # Exercise Darwin _scproxy/framework imports first.
    payload, _, _ = configuration(context)
    executable = payload / "python/bin/python3"
    binary = read(executable, 128 * 1024 * 1024)
    static = macho(binary, context["target"])
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    count, name = libc._dyld_image_count, libc._dyld_get_image_name
    count.argtypes, count.restype = [], ctypes.c_uint32
    name.argtypes, name.restype = [ctypes.c_uint32], ctypes.c_char_p
    total = count()
    need(1 <= total <= 1024, "native-dyld-image-bound")
    images = []
    for index in range(total):
        raw = name(index)
        need(raw is not None and 0 < len(raw) <= 4096, "native-dyld-image-name")
        path = raw.decode("utf-8", "strict")
        need(path == str(executable) or path.startswith(("/usr/lib/", "/System/Library/")),
             "native-dyld-non-system-image")
        need(".." not in path.split("/") and "\n" not in path, "native-dyld-image-route")
        images.append(path)
    need(total == count() and len(images) == len(set(images)) and str(executable) in images
         and any(path.startswith("/usr/lib/libffi") and path.endswith(".dylib") for path in images),
         "native-dyld-complete-system-ffi")
    return {"binarySha256": digest(binary), "machO": static, "images": sorted(images)}


def tls(context):
    import ssl
    _, checkout, _ = configuration(context)
    fixtures = checkout / "desktop/src-tauri/tests/fixtures/github_tls"
    originals = {}
    for name, (size, expected) in TLS_FILES.items():
        body = read(fixtures / name, size)
        need(len(body) == size and digest(body) == expected, "native-public-tls-fixture")
        originals[name] = expected
    need(re.fullmatch(r"OpenSSL 3\.5\.8(?: [A-Za-z0-9 ]+)?", ssl.OPENSSL_VERSION), "native-openssl-version")

    def handshake(host, ca):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(str(fixtures / "api-valid.pem"), str(fixtures / "server-key.pem"))
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        client_context.load_verify_locations(cafile=str(fixtures / ca))
        need(client_context.check_hostname and client_context.verify_mode == ssl.CERT_REQUIRED,
             "native-tls-verification-enabled")
        ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
        client = client_context.wrap_bio(ci, co, server_side=False, server_hostname=host)
        server = server_context.wrap_bio(si, so, server_side=True)
        complete = [False, False]
        for _ in range(100):
            for index, peer in enumerate((client, server)):
                if not complete[index]:
                    try:
                        peer.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                    else:
                        complete[index] = True
            if co.pending:
                si.write(co.read())
            if so.pending:
                ci.write(so.read())
            if all(complete):
                need(client.version() in {"TLSv1.2", "TLSv1.3"}, "native-tls-protocol")
                request, response = b"mrk-memory-only-request", b"mrk-memory-only-response"
                need(client.write(request) == len(request), "native-tls-client-write")
                si.write(co.read())
                need(server.read(128) == request and server.write(response) == len(response), "native-tls-server-data")
                ci.write(so.read())
                need(client.read(128) == response, "native-tls-client-data")
                return client.version()
        raise ProbeRefused("native-tls-handshake-bound")

    version = handshake("api.github.com", "root-ca.pem")
    refusals = {}
    for key, host, ca, codes in (
        ("hostname", "not-api.invalid", "root-ca.pem", {62}),
        ("trust", "api.github.com", "other-root-ca.pem", {20, 21}),
    ):
        try:
            handshake(host, ca)
        except ssl.SSLCertVerificationError as error:
            need(error.verify_code in codes, "native-tls-wrong-refusal-reason")
            refusals[key] = error.verify_code
        else:
            raise ProbeRefused("native-tls-negative-accepted")
    for name, expected in originals.items():
        need(digest(read(fixtures / name, TLS_FILES[name][0])) == expected, "native-tls-fixture-post")
    return {"openssl": ssl.OPENSSL_VERSION, "protocol": version, "memoryOnly": True,
            "chainAndHostname": True, "applicationBytes": True, "refusals": refusals,
            "publicFixtures": originals}


def network():
    import socket
    denied = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(("127.0.0.1", 9))
    except OSError as error:
        denied = error.errno
    need(denied in {errno.EPERM, errno.EACCES}, "native-network-denial-not-established")
    return {"operation": "loopback-connect", "errno": denied}


def descriptor_snapshot():
    import fcntl
    import resource
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    need(0 < soft <= 1024, "native-fd-bound")
    result = {}
    for fd in range(soft):
        try:
            info = os.fstat(fd)
        except OSError as error:
            need(error.errno == errno.EBADF, "native-fd-observation")
        else:
            result[fd] = (info.st_dev, info.st_ino, info.st_mode, info.st_rdev,
                          fcntl.fcntl(fd, fcntl.F_GETFD))
    return result


def _negative_lifecycle(kind, guard, scope, begin, invoke, process_error, sent, errors):
    """Observe a negative original only after its same cleanup scope has exited.

    The caller retains the guard, scope, watcher, command and all native custody.
    This synchronous boundary creates no owner and cannot repair its verdict.
    """
    observed = None
    interruption = None
    try:
        try:
            with scope:
                begin()
                try:
                    invoke()
                except process_error as error:
                    need(kind == "timeout" and error.dispatched is True and error.contained is True
                         and error.cleanup_complete is True and not error.fatal,
                         "native-timeout-lifetime")
                    observed = "typed-timeout"
                except KeyboardInterrupt as error:
                    # first_primary must see this original, not a normal exit.
                    interruption = error
                    raise
                else:
                    raise ProbeRefused("native-lifecycle-negative-returned")
        finally:
            scope.__exit__(*sys.exc_info())
    except KeyboardInterrupt as error:
        if error is not interruption:
            raise
        need(kind == "cancellation" and guard.cancelled, "native-cancellation-kind")
        observed = "original-interruption"
    verdict = guard.lifetime_ledger.verdict()
    need(observed is not None and verdict.complete and not verdict.fatal and verdict.contained
         and verdict.cleanup_complete and verdict.commands == 1
         and verdict.command_dispatched is True and guard.handler_state == "RESTORED"
         and not errors and (kind == "timeout" or sent == [True]), "native-original-lifecycle-finality")
    return observed, verdict


def _invoke_lifecycle_original(owner, executable, ready, environment, scratch, guard):
    """One fixed negative original; its startup and target share the same endpoint."""
    return owner.run_owned([executable, "-I", "-S", "-B", "-c", CHILD, str(ready)],
        environ=environment, cwd=scratch, timeout=12,
        capture=True, text=False, output_limit=4096, cancellation=guard)


def cancellation(context):
    import importlib.util
    import signal
    import threading
    payload, checkout, scratch = configuration(context)
    module_path = checkout / "desktop/tools/macos_aqua_qualification.py"
    spec = importlib.util.spec_from_file_location("_mrk_source_probe_owner", module_path)
    qualification = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = qualification
    spec.loader.exec_module(qualification)
    owner = qualification.load_owner(checkout)
    from mobile_release import cancellation as control

    before_fds = descriptor_snapshot()
    before_threads = tuple(threading.enumerate())
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    executable = str(payload / "python/bin/python3")
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(scratch),
                   "TMPDIR": str(scratch) + "/", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    results = {}
    for kind in ("timeout", "cancellation"):
        ready = scratch / (kind + ".ready")
        need(not ready.exists() and not ready.is_symlink(), "native-ready-collision")
        guard, owns = control.cancellation_owner(None, ProbeRefused, "native-probe-handler-finality")
        need(owns, "native-probe-original-guard")
        stop = threading.Event()
        watch = None
        watch_attempted = False
        sent, errors = [], []
        started = time.monotonic()

        def observe_ready():
            try:
                while not stop.wait(0.02):
                    need(time.monotonic() - started < 8, "native-ready-deadline")
                    try:
                        body = read(ready, len(READY))
                    except FileNotFoundError:
                        continue
                    need(body == READY, "native-ready-bytes")
                    # This thread keeps this exact parent alive; no other task's
                    # process ID is discovered, adopted or signalled.
                    os.kill(os.getpid(), signal.SIGINT)
                    sent.append(True)
                    return
            except BaseException as error:
                errors.append(type(error).__name__)

        def settle_watch():
            nonlocal watch_attempted
            stop.set()
            if watch is not None and not watch_attempted:
                watch_attempted = True
                watch.join(timeout=2)
                need(not watch.is_alive(), "native-watcher-not-joined")

        def begin_original():
            nonlocal watch
            guard.install()
            guard.activate()
            if kind == "cancellation":
                watch = threading.Thread(target=observe_ready, name="mrk-source-cancel", daemon=False)
                watch.start()

        def invoke_original():
            return _invoke_lifecycle_original(owner, executable, ready, environment, scratch, guard)

        scope = control.CleanupScope(guard, settle_watch, owns_cancellation=True, first_primary=True)
        try:
            observed, verdict = _negative_lifecycle(kind, guard, scope, begin_original,
                                                   invoke_original, owner.ProcessError, sent, errors)
            need(read(ready, len(READY)) == READY, "native-target-did-not-run")
            ready.unlink()
            results[kind] = {"outcome": observed, "targetReady": True, "commands": verdict.commands,
                             "contained": verdict.contained, "cleanupComplete": verdict.cleanup_complete,
                             "handlers": guard.handler_state, "elapsedSeconds": round(time.monotonic() - started, 3)}
        finally:
            # No rmtree/adoption/extra stop here. Unknown native custody keeps
            # scratch and prevents this process from publishing a passing result.
            if watch is not None and not watch_attempted:
                settle_watch()
    need(tuple(threading.enumerate()) == before_threads and descriptor_snapshot() == before_fds
         and all(signal.getsignal(sig) is handler for sig, handler in handlers.items()),
         "native-fd-thread-handler-postcondition")
    imported = {}
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            path = Path(module.__file__)
            relative = path.relative_to(checkout).as_posix()
            need(relative in context["sourceFiles"] and digest(read(path, 512 * 1024))
                 == context["sourceFiles"][relative], "native-owner-import-correspondence")
            imported[name] = relative
    return {"cases": results, "fdsUnchanged": True, "threadsUnchanged": True,
            "handlersRestored": True, "ownerOrigins": imported}


def main():
    need(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0
         and os.getgid() == os.getegid()
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         "native-probe-host")
    need(len(sys.argv) in {3, 4}, "native-probe-entry")
    role, target = sys.argv[1:3]
    target_description(target)
    need((role == "network" and len(sys.argv) == 3)
         or (role in {"modules", "loader", "tls", "cancellation"} and len(sys.argv) == 4),
         "native-probe-role")
    host = native_host(target)
    if role == "network":
        result = network()
    else:
        context = decode_context(read(Path(sys.argv[3]), 2 * 1024 * 1024), target)
        result = {"modules": modules, "loader": loader, "tls": tls, "cancellation": cancellation}[role](context)
    need(type(result) is dict and "nativeHost" not in result, "native-probe-result-shape")
    result["nativeHost"] = host
    raw = canonical({"schemaVersion": 1, "role": role, "target": target, "result": result}) + b"\n"
    need(len(raw) <= 512 * 1024 and sys.stdout.buffer.write(raw) == len(raw), "native-probe-output")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
