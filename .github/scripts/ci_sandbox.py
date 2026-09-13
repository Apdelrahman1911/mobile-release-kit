"""Small, fail-closed execution boundary for disposable GitHub-hosted CI VMs.

This is controller code, not an application API.  Never use it on a shared host.
The root controller supplies fixed commands and immutable inputs.  No receipt,
output string, discovered PID, or previous run grants process ownership.
"""

from __future__ import annotations

import dataclasses
import errno
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time


MiB = 1024 * 1024
CAPTURE_TOTAL = 256 * MiB
DISK_RESERVE = (4 * 1024 + 512) * MiB
JAVA_LIMITS = (
    "-Xms32m -Xmx256m -XX:MaxMetaspaceSize=256m "
    "-XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m"
)
_HOME_READ_BYTES = b"MRK_SYNTHETIC_HOME_READ\n"
_ANCESTOR_READ_BYTES = b"MRK_SYNTHETIC_ANCESTOR_READ\n"
_HOME_SOCKET_BYTES = b"MRK_SYNTHETIC_HOME_SOCKET\n"
_CENSUS_PASSES = 8
_CENSUS_PAUSE = 0.01
_PYTHON_FULL_FSIZE = (1 << 32) + MiB
_PYTHON_FULL_WORK_TMPFS = (("tmp", 640 * MiB), *((name, 16 * MiB) for name in (
    "home", "config", "cache", "gem-cache", "bundle-config", "bundle-home", "checks")))
_PYTHON_FULL_PRIVATE_TMPFS = (("/run", 16 * MiB), ("/tmp", 128 * MiB), ("/dev/shm", 16 * MiB))
_USERNS_PATH = Path("/proc/sys/user/max_user_namespaces")
_COMPATIBILITY_ROLES = ("python312", "python313", "python314")
_NATIVE_PHASES = ("source", "wheel")
_NATIVE_PROFILES = frozenset("native-authority-" + phase for phase in _NATIVE_PHASES)
_NATIVE_LEAVES = ("home", "tmp", "config", "cache", "probes")
_NATIVE_CONTROL_CASES = ("mach-baseline", "mach-ordinary", "mach-authority", "mach-nonexpand",
                         "aia-prepare", "aia-evaluate", "aia-offline-baseline")
_NATIVE_TRUST_SERVICES = ("com.apple.trustd", "com.apple.trustd.agent")
_NATIVE_OTHER_SERVICE = "com.apple.cfprefsd.daemon"
_NATIVE_WRITE_OUTER = b"MRK_NATIVE_WRITE_OUTER\n"
_NATIVE_WRITE_INNER = b"MRK_NATIVE_WRITE_INNER\n"
_NATIVE_WRITE_STDERR = _NATIVE_WRITE_OUTER + _NATIVE_WRITE_INNER
_NATIVE_STARTUP_CASES = ("startup-true", "startup-python")
# Deliberately literal, not code generated from a changing import inventory.
# Test-only AST checks bind every statement to this module's actual imports.
_NATIVE_STARTUP_PYTHON = '''from __future__ import annotations
print("MRK_NATIVE_PYTHON_BOOT", flush=True)
print("MRK_NATIVE_IMPORT_01_BEFORE", flush=True)
import dataclasses
print("MRK_NATIVE_IMPORT_01_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_02_BEFORE", flush=True)
import errno
print("MRK_NATIVE_IMPORT_02_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_03_BEFORE", flush=True)
import grp
print("MRK_NATIVE_IMPORT_03_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_04_BEFORE", flush=True)
import hashlib
print("MRK_NATIVE_IMPORT_04_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_05_BEFORE", flush=True)
import importlib.util
print("MRK_NATIVE_IMPORT_05_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_06_BEFORE", flush=True)
import json
print("MRK_NATIVE_IMPORT_06_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_07_BEFORE", flush=True)
import math
print("MRK_NATIVE_IMPORT_07_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_08_BEFORE", flush=True)
import os
print("MRK_NATIVE_IMPORT_08_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_09_BEFORE", flush=True)
from pathlib import Path
print("MRK_NATIVE_IMPORT_09_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_10_BEFORE", flush=True)
import pwd
print("MRK_NATIVE_IMPORT_10_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_11_BEFORE", flush=True)
import re
print("MRK_NATIVE_IMPORT_11_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_12_BEFORE", flush=True)
import resource
print("MRK_NATIVE_IMPORT_12_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_13_BEFORE", flush=True)
import secrets
print("MRK_NATIVE_IMPORT_13_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_14_BEFORE", flush=True)
import selectors
print("MRK_NATIVE_IMPORT_14_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_15_BEFORE", flush=True)
import signal
print("MRK_NATIVE_IMPORT_15_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_16_BEFORE", flush=True)
import socket
print("MRK_NATIVE_IMPORT_16_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_17_BEFORE", flush=True)
import stat
print("MRK_NATIVE_IMPORT_17_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_18_BEFORE", flush=True)
import subprocess
print("MRK_NATIVE_IMPORT_18_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_19_BEFORE", flush=True)
import sys
print("MRK_NATIVE_IMPORT_19_AFTER", flush=True)
print("MRK_NATIVE_IMPORT_20_BEFORE", flush=True)
import time
print("MRK_NATIVE_IMPORT_20_AFTER", flush=True)
print("MRK_NATIVE_PYTHON_DONE", flush=True)
'''
_NATIVE_STARTUP_STDOUT = b'''MRK_NATIVE_PYTHON_BOOT
MRK_NATIVE_IMPORT_01_BEFORE
MRK_NATIVE_IMPORT_01_AFTER
MRK_NATIVE_IMPORT_02_BEFORE
MRK_NATIVE_IMPORT_02_AFTER
MRK_NATIVE_IMPORT_03_BEFORE
MRK_NATIVE_IMPORT_03_AFTER
MRK_NATIVE_IMPORT_04_BEFORE
MRK_NATIVE_IMPORT_04_AFTER
MRK_NATIVE_IMPORT_05_BEFORE
MRK_NATIVE_IMPORT_05_AFTER
MRK_NATIVE_IMPORT_06_BEFORE
MRK_NATIVE_IMPORT_06_AFTER
MRK_NATIVE_IMPORT_07_BEFORE
MRK_NATIVE_IMPORT_07_AFTER
MRK_NATIVE_IMPORT_08_BEFORE
MRK_NATIVE_IMPORT_08_AFTER
MRK_NATIVE_IMPORT_09_BEFORE
MRK_NATIVE_IMPORT_09_AFTER
MRK_NATIVE_IMPORT_10_BEFORE
MRK_NATIVE_IMPORT_10_AFTER
MRK_NATIVE_IMPORT_11_BEFORE
MRK_NATIVE_IMPORT_11_AFTER
MRK_NATIVE_IMPORT_12_BEFORE
MRK_NATIVE_IMPORT_12_AFTER
MRK_NATIVE_IMPORT_13_BEFORE
MRK_NATIVE_IMPORT_13_AFTER
MRK_NATIVE_IMPORT_14_BEFORE
MRK_NATIVE_IMPORT_14_AFTER
MRK_NATIVE_IMPORT_15_BEFORE
MRK_NATIVE_IMPORT_15_AFTER
MRK_NATIVE_IMPORT_16_BEFORE
MRK_NATIVE_IMPORT_16_AFTER
MRK_NATIVE_IMPORT_17_BEFORE
MRK_NATIVE_IMPORT_17_AFTER
MRK_NATIVE_IMPORT_18_BEFORE
MRK_NATIVE_IMPORT_18_AFTER
MRK_NATIVE_IMPORT_19_BEFORE
MRK_NATIVE_IMPORT_19_AFTER
MRK_NATIVE_IMPORT_20_BEFORE
MRK_NATIVE_IMPORT_20_AFTER
MRK_NATIVE_PYTHON_DONE
'''
_ENV_KEYS = frozenset("""
PATH LANG LC_ALL TZ HOME USER LOGNAME TMPDIR TMP TEMP XDG_CONFIG_HOME
XDG_CACHE_HOME CI TERM PYTHONSAFEPATH PYTHONDONTWRITEBYTECODE PYTHONNOUSERSITE
PYTHONUTF8 PYTHONHASHSEED PIP_CONFIG_FILE PIP_NO_INDEX PIP_FIND_LINKS PIP_NO_CACHE_DIR
PIP_DISABLE_PIP_VERSION_CHECK PIP_NO_INPUT PIP_REQUIRE_VIRTUALENV PIP_CACHE_DIR
VIRTUAL_ENV GEM_HOME GEM_PATH GEM_SPEC_CACHE GEMRC BUNDLE_GEMFILE BUNDLE_PATH
BUNDLE_USER_HOME BUNDLE_USER_CACHE BUNDLE_USER_CONFIG BUNDLE_FROZEN
BUNDLE_DEPLOYMENT BUNDLE_DISABLE_SHARED_GEMS BUNDLE_IGNORE_CONFIG BUNDLE_CACHE_PATH
BUNDLE_APP_CONFIG BUNDLE_RETRY BUNDLE_VERSION
GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_TERMINAL_PROMPT GIT_ATTR_NOSYSTEM
GIT_CONFIG_COUNT GIT_OPTIONAL_LOCKS
FASTLANE_SKIP_UPDATE_CHECK FASTLANE_HIDE_CHANGELOG FASTLANE_OPT_OUT_USAGE
FASTLANE_SKIP_DOCS FASTLANE_DISABLE_COLORS FASTLANE_SKIP_REPORTING
MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS MOBILE_RELEASE_TEST_PYTHON
MOBILE_RELEASE_TEST_PROCESS_OBSERVER
DEVELOPER_DIR JAVA_HOME JAVA_TOOL_OPTIONS
""".split())


class SessionError(RuntimeError):
    """The attempt cannot admit another command or consume mutable outputs."""


class DeadlineExpired(SessionError):
    """An owning, never renewed absolute budget expired."""


class _CensusUnstable(SessionError):
    """An incomplete Linux pass; only finality may discard it and resnapshot."""


def _native_startup_stage(data: bytes) -> str:
    """Exact complete-line progress only; neither an import cause nor a pass."""
    if type(data) is not bytes or len(data) > len(_NATIVE_STARTUP_STDOUT):
        return "unclassified"
    if not data:
        return "no-body-marker"
    prefix = b""
    for index, line in enumerate(_NATIVE_STARTUP_STDOUT.splitlines(keepends=True)):
        prefix += line
        if data == prefix:
            if index == 0:
                return "body"
            if index == 41:
                return "imports-finished"
            return f"{'before' if index % 2 else 'after'}-import-{(index + 1) // 2:02d}"
    return "unclassified"


class _NativeExitIdentity(SessionError):
    """Exact-sized original-child metadata contradicted its held identity."""


_NATIVE_EXIT_BINDING = None
_NATIVE_EXIT_LIBRARY = None  # OS-runtime binding is retained for this controller's lifetime.
_NATIVE_EXIT_NAMESPACES = {2: "SIGNAL", 3: "CODESIGNING", 6: "DYLD", 7: "LIBXPC", 9: "EXEC",
                           18: "LIBSYSTEM", 23: "GUARD", 25: "SANDBOX", 26: "SECURITY",
                           35: "LIBIGNITION", 36: "BOOTMOUNT", 47: "SECINIT"}
_NATIVE_EXIT_DYLD_CODES = {1: "DYLIB_MISSING", 2: "WRONG_ARCH", 3: "WRONG_VERSION", 4: "SYMBOL_MISSING",
                          5: "CODE_SIGNATURE", 6: "FILE_SYSTEM_SANDBOX", 7: "MALFORMED_MACHO",
                          9: "OTHER", 10: "DLSYM_BLOCKED"}


def _native_exit_runtime():
    """One fixed original-parent library binding; no helper process or dlclose."""
    global _NATIVE_EXIT_BINDING, _NATIVE_EXIT_LIBRARY
    if _NATIVE_EXIT_BINDING is not None:
        return _NATIVE_EXIT_BINDING or None
    _NATIVE_EXIT_BINDING = False  # A failed capability lookup does not authorize retries.
    if sys.platform != "darwin" or sys.byteorder != "little":
        return None
    native = os.uname()
    if (native.sysname != "Darwin" or native.machine not in {"arm64", "x86_64"}
            or re.fullmatch(r"25\.[0-9]+\.[0-9]+", native.release) is None):
        return None
    try:
        import ctypes
        if (ctypes.sizeof(ctypes.c_void_p), ctypes.sizeof(ctypes.c_int),
                ctypes.sizeof(ctypes.c_uint32), ctypes.sizeof(ctypes.c_uint64)) != (8, 4, 4, 8):
            return None
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        _NATIVE_EXIT_LIBRARY = library  # Retain even if symbol/capability binding fails afterward.
        operation = library.proc_pidinfo
        operation.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        operation.restype = ctypes.c_int
        _NATIVE_EXIT_BINDING = (ctypes, library, operation)
    except (AttributeError, ImportError, OSError, TypeError):
        return None
    return _NATIVE_EXIT_BINDING


def _native_exit_query(binding, pid: int, *, basic: bool = False) -> tuple[bytes | None, int | None]:
    if type(pid) is not int or not 1 < pid < (1 << 31) or type(basic) is not bool:
        return None, None
    ctypes, _library, operation = binding
    size = 24 if basic else 136
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    # BASIC25 is private XNU12377-family provenance when absent from SDK headers;
    # its actual packed layout and public BSD3 layout are pinned in the admitted C observer.
    returned = operation(pid, 25 if basic else 3, 0 if basic else 1, ctypes.byref(buffer), size)
    number = ctypes.get_errno()
    if type(returned) is not int or returned != size:
        return None, number if type(returned) is int and returned == 0 and type(number) is int and 0 < number < 4096 else None
    raw = buffer.raw
    return (raw, None) if type(raw) is bytes and len(raw) == size else (None, None)


def _native_exit_bsd(raw: bytes, *, pid: int, parent: int, uid: int, gid: int) -> dict | None:
    """SDK-pinned bytes, not a wait result, image authentication or PID authority."""
    if type(raw) is not bytes or len(raw) != 136:
        return None
    flags, status, xstatus, found_pid, ppid, eu, eg, ru, rg, su, sg = (
        int.from_bytes(raw[offset:offset + 4], "little") for offset in range(0, 44, 4))
    if (found_pid != pid or ppid != parent or (ru, eu, su) != (uid,) * 3 or (rg, eg, sg) != (gid,) * 3
            or flags & (0x00000002 | 0x00002000)):  # TRACED or PSUGID contradicts this exclusive owner.
        raise _NativeExitIdentity("original-parent BSD identity/credentials changed")
    if status not in {1, 2, 3, 4, 5} or not flags & 0x00000010:  # SDK LP64, not an unknown-flags mask.
        return None
    comm, name = raw[48:64], raw[64:96]
    if b"\0" not in comm or b"\0" not in name:
        return None
    if status != 5:
        return {"status": "transition" if flags & 0x00000004 or status == 1 else "live",
                "expected": None, "reported_name_hint": "unavailable"}
    try:
        expected = os.waitstatus_to_exitcode(xstatus & 0xffff)
    except (ValueError, OverflowError):
        return None
    reported = name.split(b"\0", 1)[0] or comm.split(b"\0", 1)[0]
    hint = ({b"python": "python", b"python3": "python", b"python3.11": "python", b"Python": "python",
             b"sandbox-exec": "sandbox-exec", b"true": "true"}).get(reported, "other")
    return {"status": "terminal", "expected": expected, "reported_name_hint": hint}


def _native_exit_basic(raw: bytes) -> dict | None:
    if type(raw) is not bytes or len(raw) != 24:
        return None
    row = {key: int.from_bytes(raw[offset:offset + size], "little") for key, offset, size in (
        ("namespace", 0, 4), ("code", 4, 8), ("flags", 12, 8), ("reason_buffer_size", 20, 4))}
    # Closed source-family labels are hints only; no kcdata, names, paths or inferred grants.
    if row["namespace"] in _NATIVE_EXIT_NAMESPACES:
        row["namespace_label"] = _NATIVE_EXIT_NAMESPACES[row["namespace"]]
    if row["namespace"] == 6 and row["code"] in _NATIVE_EXIT_DYLD_CODES:
        row["code_label"] = _NATIVE_EXIT_DYLD_CODES[row["code"]]
    return row


class _NativeAbortIssue(Exception):
    """Private optional diagnostic failure; never a subject result or authority."""

    def __init__(self, status: str, code: str, *, number: int | None = None,
                 close_failed: bool = False, retry: bool = False):
        super().__init__(code)
        self.status, self.code = status, code
        self.number = number if type(number) is int and 0 < number < 4096 else None
        self.close_failed, self.retry = close_failed, retry


_NATIVE_ABORT_SYSTEM_IMAGES = {
    "/usr/lib/dyld": "dyld",
    "/usr/lib/system/libsystem_secinit.dylib": "libsystem-secinit",
    "/usr/lib/system/libsystem_kernel.dylib": "libsystem-kernel",
    "/usr/lib/system/libsystem_c.dylib": "libsystem-c",
    "/usr/lib/system/libdispatch.dylib": "libdispatch",
}
_NATIVE_ABORT_PUBLIC_PATHS = frozenset({
    "/dev/null", "/dev/random", "/dev/urandom", "/dev/fd/0", "/dev/fd/1", "/dev/fd/2",
    "/usr/bin/sandbox-exec", *_NATIVE_ABORT_SYSTEM_IMAGES,
})
_NATIVE_ABORT_FRAMES = {
    "abort": "abort", "__abort_with_payload": "abort-with-payload", "_os_crash": "os-crash",
    "Py_FatalError": "python-fatal-error", "_libsecinit_appsandbox": "libsecinit-initialize",
    "_libsecinit_initializer": "libsecinit-initialize",
    "dyld4::halt(char const*, dyld4::StructuredError const*)": "dyld-halt",
}
_NATIVE_ABORT_OPERATIONS = frozenset({
    "file-read-data", "file-read-metadata", "file-read-xattr", "file-write-data", "file-write-create",
    "mach-lookup", "sysctl-read", "process-exec",
})


def _native_abort_time(value: object) -> tuple[int, int]:
    """Precision-only rounding/truncation interval, in half-nanoseconds."""
    if not isinstance(value, str) or len(value) > 80:
        raise _NativeAbortIssue("unavailable", "CLOCK_BINDING")
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})"
                         r"(?:\.(\d{1,9}))? ?([+-])(\d{2}):?(\d{2})", value, flags=re.ASCII)
    if match is None:
        raise _NativeAbortIssue("unavailable", "CLOCK_BINDING")
    # Optional controller parsing only: no new unconditional subject startup import.
    import datetime
    try:
        parts = [int(match[n]) for n in range(1, 7)]
        hour, minute = int(match[9]), int(match[10])
        if hour > 23 or minute > 59:
            raise ValueError
        delta = datetime.datetime(*parts) - datetime.datetime(1970, 1, 1)
        offset = (hour * 3600 + minute * 60) * (1 if match[8] == "+" else -1)
        fraction = match[7] or ""
        instant = ((delta.days * 86400 + delta.seconds - offset) * 1_000_000_000
                   + int(fraction.ljust(9, "0")))
        unit = 10 ** (9 - len(fraction))
    except (ValueError, OverflowError) as exc:
        raise _NativeAbortIssue("unavailable", "CLOCK_BINDING") from exc
    return 2 * instant - unit, 2 * instant + 2 * unit


def _native_abort_window(abort: dict) -> tuple[int, int, int]:
    before, after, waited = (abort.get(key) for key in ("wall_before", "wall_after", "wall_wait"))
    if (any(type(t) is not int or not 0 < t < (1 << 63) for t in (before, after, waited))
            or not before <= after <= waited or waited - before > 18_000_000_000
            or type(abort.get("pid")) is not int or not 0 < abort["pid"] < (1 << 31)
            or type(abort.get("uid")) is not int or not 0 < abort["uid"] < (1 << 32)):
        raise _NativeAbortIssue("unavailable", "CLOCK_BINDING")
    return before, after, waited


def _native_abort_json(raw: bytes, *, maximum: int, depth: int, code: str):
    """Strict bounded JSON with a nesting check before the recursive decoder."""
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise _NativeAbortIssue("limit", "LIMIT")
    try:
        data = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise _NativeAbortIssue("malformed", code) from exc
    level, quoted, escaped = 0, False, False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            level += 1
            if level > depth:
                raise _NativeAbortIssue("limit", "LIMIT")
        elif char in "]}":
            level -= 1

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError
        return number

    def nonfinite(_value):
        raise ValueError

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_float=finite, parse_constant=nonfinite)
    except json.JSONDecodeError as exc:
        # A missing terminal value/delimiter may be an incompletely arrived IPS.
        raise _NativeAbortIssue("malformed", code, retry=exc.pos == len(data.rstrip())) from exc
    except (ValueError, RecursionError, OverflowError) as exc:
        raise _NativeAbortIssue("malformed", code) from exc


def _native_abort_ips_record(raw: bytes, abort: dict) -> dict | None:
    before, after, waited = _native_abort_window(abort)
    if not isinstance(raw, bytes) or len(raw) > MiB:
        raise _NativeAbortIssue("limit", "LIMIT")
    header, separator, body = raw.partition(b"\n")
    if not separator:
        raise _NativeAbortIssue("malformed", "IPS_IO", retry=not raw)
    metadata = _native_abort_json(header, maximum=MiB, depth=64, code="IPS_IO")
    report = _native_abort_json(body, maximum=MiB, depth=64, code="IPS_IO")
    if type(metadata) is not dict or type(report) is not dict:
        raise _NativeAbortIssue("malformed", "IPS_IO")
    bug = metadata.get("bug_type")
    exception = report.get("exception")
    path = report.get("procPath")
    if (not (type(bug) is int and bug == 309 or type(bug) is str and bug == "309")
            or type(report.get("pid")) is not int or report["pid"] != abort["pid"]
            or type(report.get("userID")) is not int or report["userID"] != abort["uid"]
            or not isinstance(path, str) or path not in abort["images"]
            or type(exception) is not dict or exception.get("type") != "EXC_CRASH"
            or exception.get("signal") != "SIGABRT"):
        return None
    try:
        launch_lo, launch_hi = _native_abort_time(report.get("procLaunch"))
        capture_lo, capture_hi = _native_abort_time(report.get("captureTime"))
    except _NativeAbortIssue:
        return None
    if not (launch_lo <= 2 * after and launch_hi > 2 * before
            and capture_lo <= 2 * waited and capture_hi > 2 * before and capture_hi > launch_lo):
        return None
    termination = report.get("termination")
    namespace, code = "ABSENT", None
    if type(termination) is dict:
        given = termination.get("namespace")
        namespace = (given if isinstance(given, str) and given in
                     {"SIGNAL", "DYLD", "LIBSYSTEM", "SANDBOX", "CODESIGNING"}
                     else "ABSENT" if given is None else "OTHER")
        candidate = termination.get("code")
        if type(candidate) is int and 0 <= candidate < (1 << 64):
            code = candidate
    fault_role, roles = "absent", []
    index, threads, images = report.get("faultingThread"), report.get("threads"), report.get("usedImages")
    if type(index) is int and type(threads) is list and 0 <= index < len(threads):
        thread = threads[index]
        frames = thread.get("frames") if type(thread) is dict else None
        if type(frames) is list:
            for n, frame in enumerate(frames[:64]):
                if type(frame) is not dict:
                    continue
                image_index = frame.get("imageIndex")
                if n == 0 and type(images) is list and type(image_index) is int and 0 <= image_index < len(images):
                    image = images[image_index]
                    image_path = image.get("path") if type(image) is dict else None
                    if isinstance(image_path, str):
                        fault_role = abort["images"].get(image_path, _NATIVE_ABORT_SYSTEM_IMAGES.get(image_path, "other"))
                symbol = frame.get("symbol")
                role = _NATIVE_ABORT_FRAMES.get(symbol) if isinstance(symbol, str) else None
                if role is not None and role not in roles and len(roles) < 8:
                    roles.append(role)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "image_role": abort["images"][path],
            "exception": "EXC_CRASH", "signal": "SIGABRT", "termination_namespace": namespace,
            "termination_code": code, "fault_image_role": fault_role, "frame_roles": roles}


def _native_abort_log_records(raw: bytes, abort: dict) -> list[dict]:
    """PID/name/time-correlated denials only; emitter UID/PID is not subject identity."""
    before, _after, waited = _native_abort_window(abort)
    records = _native_abort_json(raw, maximum=2 * MiB, depth=32, code="LOG_PARSE")
    if type(records) is not list:
        raise _NativeAbortIssue("malformed", "LOG_PARSE")
    if len(records) > 64:
        raise _NativeAbortIssue("limit", "LIMIT")
    names = {Path(path).name for path in abort["images"]}
    producers = {"/kernel": "kernel", "/System/Library/Kernels/kernel": "kernel",
                 "/usr/libexec/sandboxd": "sandboxd"}
    denials = []
    for record in records:
        if type(record) is not dict:
            raise _NativeAbortIssue("malformed", "LOG_PARSE")
        declared, path = record.get("process"), record.get("processImagePath")
        producer = producers.get(path) if isinstance(path, str) else None
        if (declared is not None and declared not in ("kernel", "sandboxd")
                or "processImagePath" in record and producer is None
                or declared is None and producer is None
                or declared is not None and producer is not None and declared != producer):
            continue
        try:
            lo, hi = _native_abort_time(record.get("timestamp"))
        except _NativeAbortIssue:
            continue
        if lo > 2 * waited or hi <= 2 * before:
            continue
        message = record.get("eventMessage")
        if not isinstance(message, str) or len(message) > 8192:
            continue
        match = re.fullmatch(r"Sandbox: ([A-Za-z0-9_.-]{1,128})\(([1-9][0-9]{0,9})\) "
                             r"deny\([0-9]{1,10}\) ([a-z][a-z0-9-]{0,63}) ([^\r\n\x00]{1,4096})", message)
        if match is None or match[1] not in names or int(match[2]) != abort["pid"]:
            continue
        operation, resource = match[3], match[4]
        row = {"operation": operation if operation in _NATIVE_ABORT_OPERATIONS else "other",
               "resource_role": "redacted"}
        if resource in _NATIVE_ABORT_PUBLIC_PATHS:
            row["public_path"] = resource
            row["resource_role"] = ("stdio-device" if resource.startswith("/dev/")
                                    else "admitted-system-image" if resource == "/usr/bin/sandbox-exec"
                                    else "public-os")
        elif abort["images"].get(resource) in {"python-selected", "python-framework"}:
            row["resource_role"] = "admitted-python"
        elif (isinstance(abort.get("control_root"), str) and resource.startswith(abort["control_root"] + "/")
              and ".." not in Path(resource).parts):
            row["resource_role"] = "owned-control"
        if row not in denials and len(denials) < 8:
            denials.append(row)
    return denials


_DIAGNOSTIC_OPERATIONS = frozenset({"process-groups-linux", "kernel-groups-library",
                                    "kernel-groups-count", "kernel-groups-fill",
                                    "mac-original-credentials", "cleanup-batch",
                                    "network-tcp4", "network-udp4", "network-tcp6", "network-udp6"})
_TOOL_DIAGNOSTIC_ROLES = frozenset({"python", "ruby", "sudo", "true", "sandbox-exec", "ps",
                                    "compiler", "linker", "signature-tool", "unspecified", *_COMPATIBILITY_ROLES})


def _observer_error_fields(value: object) -> dict | None:
    """Closed diagnostic schema only; no observer result is accepted here."""
    if not isinstance(value, dict) or set(value) != {"code", "errno", "library_close_failed"}:
        return None
    code, number, closed = value["code"], value["errno"], value["library_close_failed"]
    if not isinstance(code, str) or type(closed) is not bool:
        return None
    if code in {"INPUT", "CALLER_IDENTITY", "SELF_QUERY", "SELF_IDENTITY", "QUERY", "SIZE", "GROUP_LIBRARY"}:
        if number is not None or closed:
            return None
    elif code in {"GROUP_SYMBOL", "GROUP_COUNT", "GROUP_BOUND", "GROUP_READ",
                  "GROUP_CHANGED", "GROUP_IDENTITY", "GROUP_CLOSE"}:
        if type(number) is not int or not 0 <= number < 4096:
            return None
        if code not in {"GROUP_COUNT", "GROUP_READ"} and number != 0:
            return None
        if code == "GROUP_CLOSE" and not closed:
            return None
    else:
        return None
    return {"code": code, "errno": number, "library_close_failed": closed}


def _observer_error_note(data: bytes) -> dict | None:
    """Recognize one exact fixed C error line; never publish stdout or a PID."""
    if not isinstance(data, bytes) or len(data) > 128:
        return None
    match = re.fullmatch(rb"MRK_PROCESS_V1 error ([A-Z_]+)(?:_(0|[1-9][0-9]{0,3})(_AND_CLOSE)?)?\n", data)
    if match is None:
        return None
    code = match[1].decode("ascii")
    if code == "GROUP_CLOSE" and match[3] is not None:
        return None
    return _observer_error_fields({"code": code, "errno": None if match[2] is None else int(match[2]),
                                   "library_close_failed": match[3] is not None or code == "GROUP_CLOSE"})


def _exception_notes(error: BaseException) -> list[dict]:
    """Bounded classes/own-source lines/errno/operation, never messages."""
    notes, pending, seen = [], [error], set()
    while pending and len(notes) < 32:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        lines, tb, inspected = [], current.__traceback__, 0
        while tb is not None and inspected < 64:
            if os.path.basename(tb.tb_frame.f_code.co_filename) == "ci_sandbox.py":
                lines.append(tb.tb_lineno)
            tb, inspected = tb.tb_next, inspected + 1
        name = type(current).__name__
        row = {"exception": name if name.isascii() and name.isidentifier() and len(name) <= 80 else "Exception",
               "lines": sorted(set(lines))[:16]}
        number = current.errno if isinstance(current, OSError) else None
        if type(number) is int and 0 < number < 4096:
            row["errno"] = number
        operation = getattr(current, "_ci_operation", None)
        if isinstance(operation, str) and operation in _DIAGNOSTIC_OPERATIONS:
            row["operation"] = operation
        observation = getattr(current, "_ci_observation", None)
        if observation is not None:
            row["observation"] = observation
        notes.append(row)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions[:32])
        elif current.__cause__ is not None:
            pending.append(current.__cause__)
    return notes


def _child_exception_notes(data: bytes) -> list[dict]:
    """Extract only our bounded diagnostic fields; never publish stderr."""
    notes = []
    for line in data[-16384:].splitlines():
        if not line.startswith(b"MRK_SANDBOX_ERROR="):
            continue
        try:
            rows = json.loads(line[len(b"MRK_SANDBOX_ERROR="):])
        except (ValueError, UnicodeError):
            continue
        if not isinstance(rows, list):
            continue
        for row in rows[:32]:
            if not isinstance(row, dict):
                continue
            name, lines = row.get("exception"), row.get("lines")
            if (isinstance(name, str) and name.isascii() and name.isidentifier() and len(name) <= 80
                    and isinstance(lines, list) and len(lines) <= 16
                    and all(type(n) is int and 0 < n < 1_000_000 for n in lines)):
                note = {"exception": name, "lines": lines}
                number, operation = row.get("errno"), row.get("operation")
                if type(number) is int and 0 < number < 4096:
                    note["errno"] = number
                if isinstance(operation, str) and operation in _DIAGNOSTIC_OPERATIONS:
                    note["operation"] = operation
                observation = row.get("observation")
                if isinstance(observation, dict):
                    observer_error = _observer_error_fields(observation.get("observer_error"))
                    if observer_error is not None:
                        note["observation"] = {"observer_error": observer_error}
                notes.append(note)
        if len(notes) >= 32:
            break
    return notes[:32]


def _launcher_error(data: bytes, python: Path, script: Path) -> dict | None:
    """Recognize only exact CPython errors for these two admitted own paths.

    No byte-count guess, arbitrary substring, raw path, or stderr is published.
    Unknown/localized errors remain unclassified, never silently successful.
    """
    for number, message in ((errno.ENOENT, "No such file or directory"),
                            (errno.EACCES, "Permission denied")):
        expected = f"{python}: can't open file '{script}': [Errno {number}] {message}\n".encode()
        if data == expected:
            return {"code": "python-script-open", "errno": number}
    return None


def _native_aia_launch_text(result: CapturedRun, python: Path, helper: Path) -> dict | None:
    """Closed lexical hints from one complete failed capture, never its cause.

    Prefixes and words can occur in displayed source or other reported text.
    They neither authenticate the emitter nor prove an OS/compiler operation.
    No original string, path, PID or arbitrary identifier enters the result.
    """
    if (type(result) is not CapturedRun or type(result.returncode) is not int
            or not -128 <= result.returncode <= 255 or result.returncode == 0
            or type(result.stdout) is not bytes or result.stdout != b""
            or type(result.stderr) is not bytes or not 0 < len(result.stderr) <= 4096
            or any(value is not True for value in (result.waited, result.stdout_eof,
                                                   result.stderr_eof, result.domain_finality))
            or result.timed_out is not False or result.cancelled is not False
            or type(result.cleanup_errors) is not tuple or result.cleanup_errors
            or type(result.primary_error) is not str
            or result.primary_error != f"command exited {result.returncode}"
            or type(result.persisted) is not tuple or len(result.persisted) != 2
            or any(type(count) is not int for count in result.persisted)
            or result.persisted != (0, len(result.stderr))):
        return None
    data = result.stderr
    if (not data.endswith(b"\n") or not 1 <= data.count(b"\n") <= 32
            or any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in data)):
        return None
    if data.startswith(b"sandbox-exec: "):
        prefix = "sandbox-exec"
    elif data.startswith(str(python).encode("ascii") + b": "):
        prefix = "python"
    elif re.match(rb"dyld(?:\[[0-9]{1,10}\])?: ", data):
        prefix = "dyld"
    elif data.startswith(b"MRK_NATIVE_CONTROL_FAILED="):
        prefix = "native-helper-note"
    else:
        prefix = "unrecognized"
    literals = ("address", "argument", "arguments", "compile", "compiling", "filter", "illegal",
                "invalid", "ip", "network-outbound", "number", "opening", "operation", "port",
                "profile", "reading", "remote", "require-all", "sandbox_apply", "sandbox_compile",
                "sandbox_compile_file", "sandbox_compile_string", "sandbox_init", "socket",
                "string", "symbol", "syntax", "tcp", "udp", "unbound", "undefined", "unknown",
                "variable", "execvp")
    phrases = (("can't open file", "cant-open-file"), ("permission denied", "permission-denied"),
               ("operation not permitted", "operation-not-permitted"),
               ("no such file or directory", "no-such-file"),
               ("library not loaded", "library-not-loaded"), ("symbol not found", "symbol-not-found"))
    lower = data.lower()
    tokens = sorted({label for literal, label in (*((word, word) for word in literals), *phrases)
                     if re.search(rb"(?<![a-z0-9_-])" + re.escape(literal.encode("ascii"))
                                  + rb"(?![a-z0-9_-])", lower)})
    note = {"schema": 1, "semantics": "reported-stderr-tokens-only", "diagnosis": "unresolved",
            "prefix": prefix, "tokens": tokens}
    exact = _launcher_error(data, python, helper)
    if exact is not None:
        note["exact_python_open"] = exact
    return note


def _ruby_launch_error(result: CapturedRun, ruby: Path) -> dict | None:
    """Exact fixed-launch failure diagnosis, never a substitute accepted result."""
    if (result.returncode != 71 or result.stdout or not result.waited
            or not result.stdout_eof or not result.stderr_eof or not result.domain_finality
            or result.timed_out or result.cancelled or result.cleanup_errors
            or result.primary_error != "command exited 71"
            or result.persisted != (0, len(result.stderr))):
        return None
    for number, message in ((errno.EPERM, "Operation not permitted"),
                            (errno.EACCES, "Permission denied"),
                            (errno.ENOENT, "No such file or directory"),
                            (errno.ENOEXEC, "Exec format error"),
                            (errno.ENOMEM, "Cannot allocate memory"),
                            (errno.E2BIG, "Argument list too long"),
                            (errno.ETXTBSY, "Text file busy")):
        expected = f"sandbox-exec: execvp() of '{ruby}' failed: {message}\n".encode()
        if result.stderr == expected:
            return {"operation": "sandbox-execvp", "role": "ruby", "errno": number}
    return None  # No byte-count guess, sandbox_apply guess, or raw stderr.


def _ruby_startup_error(result: CapturedRun, ruby: Path) -> dict | None:
    """Closed tokens from an owned failed capture, not native-cause evidence.

    This never resolves/reads a provider path, runs Ruby again, or changes the
    failed result. Unknown surrounding text is not an understood stack trace.
    """
    if (type(result.returncode) is not int or result.returncode != 1
            or type(result.stdout) is not bytes or result.stdout != b""
            or type(result.stderr) is not bytes or result.waited is not True
            or result.stdout_eof is not True or result.stderr_eof is not True
            or result.domain_finality is not True or result.timed_out is not False
            or result.cancelled is not False or type(result.cleanup_errors) is not tuple or result.cleanup_errors
            or result.primary_error != "command exited 1"
            or type(result.persisted) is not tuple or len(result.persisted) != 2
            or any(type(n) is not int for n in result.persisted)
            or result.persisted != (0, len(result.stderr))):
        return None
    note = {"semantics": "stderr-tokens-only", "classification": "unclassified"}
    data = result.stderr
    if not 0 < len(data) <= 16 * 1024 or not data.endswith(b"\n"):
        return note
    try:
        # The fixed clean locale and admitted paths use this finite grammar;
        # unsupported encodings/formatting remain unclassified, never forwarded.
        raw = data.decode("ascii")
    except UnicodeDecodeError:
        return note
    lines = raw[:-1].split("\n")
    if (not 1 <= len(lines) <= 64 or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in raw)
            or any("\t" in line and (index == 0 or not line.startswith("\tfrom ") or "\t" in line[1:])
                   for index, line in enumerate(lines))):
        return note

    # Only these portable Darwin errno values; never infer one from message text
    # or use a Linux-specific number for a differently numbered native error.
    errnos = {"Errno::EPERM": 1, "Errno::ENOENT": 2, "Errno::ENOEXEC": 8,
              "Errno::ENOMEM": 12, "Errno::EACCES": 13, "Errno::ENOTDIR": 20}
    classes = set(errnos) | {"LoadError", "ArgumentError", "RuntimeError", "ThreadError",
                            "SecurityError", "SyntaxError", "NameError", "TypeError", "NoMemoryError"}
    library = ruby.parent.parent / "lib/ruby/3.3.0"  # The workflow's fixed Ruby3.3 provider.
    sources = {str(library / name): role for name, role in (
        ("rubygems.rb", "rubygems"), ("rubygems/defaults.rb", "rubygems-defaults"),
        ("rubygems/path_support.rb", "rubygems-path-support"),
        ("rubygems/core_ext/kernel_require.rb", "rubygems-kernel-require"),
        ("bundled_gems.rb", "bundled-gems"))}
    sources.update({"<internal:gem_prelude>": "gem-prelude", "<internal:prelude>": "ruby-prelude",
                    f"<internal:{library / 'rubygems/core_ext/kernel_require.rb'}>": "rubygems-kernel-require",
                    "-e": "numerical-probe"})

    def fixed_frame(line: str, *, header: bool = False) -> tuple[dict, str] | None:
        for source, role in sources.items():
            prefix = source + ":"
            if not line.startswith(prefix):
                continue
            pattern = r"([1-9][0-9]{0,5})(?::in [`'][^`'\t\n]{1,128}')?"
            if header:
                pattern += r": (.*)"
            match = re.fullmatch(pattern, line[len(prefix):])
            if match is None or role == "numerical-probe" and int(match[1]) != 1:
                return None
            return {"role": role, "line": int(match[1])}, match[2] if header else ""
        return None

    body, frames, bare = lines[0], [], True
    first = fixed_frame(body, header=True)
    if first is not None:
        frames.append(first[0])
        body, bare = first[1], False
    else:
        for prefix in (str(ruby) + ": ", ruby.name + ": "):
            if body.startswith(prefix):
                body, bare = body[len(prefix):], False
                break
    match = re.fullmatch(r"(.+) \(([^()]+)\)", body)
    if match is None or match[2] not in classes:
        return note
    exception, message = match[2], match[1]
    if bare:
        # Ruby can fail before a source frame exists. Admit only this exact
        # native-error spelling, not a class-looking suffix in arbitrary text.
        messages = {"Errno::EPERM": "Operation not permitted", "Errno::ENOENT": "No such file or directory",
                    "Errno::ENOEXEC": "Exec format error", "Errno::ENOMEM": "Cannot allocate memory",
                    "Errno::EACCES": "Permission denied", "Errno::ENOTDIR": "Not a directory"}
        prefix = messages.get(exception, "") + " @ rb_check_realpath_internal - "
        if exception not in messages or not message.startswith(prefix) or not message[len(prefix):]:
            return note
    note.update(classification="recognized", exception=exception, frames=frames)
    if exception in errnos:
        note["errno"] = errnos[exception]
    if re.search(r" @ rb_check_realpath_internal - .+", message):
        note["operation"] = "rb_check_realpath_internal"
    for line in lines[1:]:
        if not line.startswith("\tfrom "):
            continue
        frame = fixed_frame(line[len("\tfrom "):])
        if frame is not None and frame[0] not in frames:
            frames.append(frame[0])
            if len(frames) == 8:
                break
    return note


@dataclasses.dataclass(frozen=True)
class CapturedRun:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    waited: bool
    stdout_eof: bool
    stderr_eof: bool
    domain_finality: bool
    timed_out: bool
    cancelled: bool
    duration: float
    primary_error: str | None
    cleanup_errors: tuple[str, ...]
    persisted: tuple[int | None, int | None]

    @property
    def ok(self) -> bool:
        return (self.waited and self.returncode == 0 and self.stdout_eof
                and self.stderr_eof and self.domain_finality
                and not self.timed_out and not self.cancelled
                and self.primary_error is None and not self.cleanup_errors)

    @property
    def status(self) -> int | None:
        return self.returncode

    @property
    def finality(self) -> bool:
        return self.domain_finality


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _canonical(value: str | Path) -> Path:
    p = Path(value)
    if (not p.is_absolute() or p != p.resolve(strict=True)
            or any(not 32 <= ord(c) < 127 for c in str(p))):
        raise SessionError("noncanonical or absent controller path")
    return p


def _runtime_prefix_roles(platform: str, python: Path, python_prefix: Path, ruby: Path,
                          tool_prefixes: tuple[Path, ...],
                          compatibility_runtimes: tuple[tuple[Path, Path], ...]) -> tuple[tuple[str, Path], ...]:
    """Pure closed-role reconciliation; canonical metadata belongs to admission.

    Normal QA007 CI supplies all three additional minors. The empty shape keeps
    the existing bounded owner controls usable; it cannot omit CLI/catalog gates.
    Actual minor identities are checked by owned isolated interpreter captures,
    never inferred from a pathname or an out-of-owner discovery subprocess.
    """
    if (platform not in {"linux", "darwin"} or type(tool_prefixes) is not tuple
            or type(compatibility_runtimes) is not tuple or len(compatibility_runtimes) not in (0, 3)
            or any(type(row) is not tuple or len(row) != 2 for row in compatibility_runtimes)):
        raise SessionError("selected provider prefix roles are incomplete or ambiguous")
    paths = (python, python_prefix, ruby, *tool_prefixes,
             *(path for row in compatibility_runtimes for path in row))
    if any(not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
           or path == Path("/") or len(str(path)) > 4096
           or any(not 32 <= ord(c) < 127 for c in str(path)) for path in paths):
        raise SessionError("selected provider path shape is unsupported")
    if (python.parent.name != "bin" or ruby.parent.name != "bin" or not _under(python, python_prefix)
            or any(executable.parent.name != "bin" or executable.parent.parent != prefix
                   for executable, prefix in compatibility_runtimes)):
        raise SessionError("selected executable does not have its exact provider prefix")
    ruby_prefix = ruby.parent.parent
    extras = tuple((role, pair[1]) for role, pair in zip(_COMPATIBILITY_ROLES, compatibility_runtimes))
    selected = (python_prefix, ruby_prefix, *(prefix for _, prefix in extras))
    if len(set(tool_prefixes)) != len(tool_prefixes) or any(prefix not in tool_prefixes for prefix in selected):
        raise SessionError("selected provider prefix roles are incomplete or ambiguous")
    remaining = tuple(prefix for prefix in tool_prefixes if prefix not in selected)
    if len(remaining) != (1 if platform == "linux" else 0):
        raise SessionError("selected provider prefix roles are incomplete or ambiguous")
    roles = (("python", python_prefix), ("ruby", ruby_prefix))
    if platform == "linux":
        roles += (("jdk", remaining[0]),)
    roles += extras
    roots = tuple(prefix for _, prefix in roles)
    if (len(roots) != len(tool_prefixes) or any(_under(a, b) or _under(b, a)
            for index, a in enumerate(roots) for b in roots[index + 1:])):
        raise SessionError("selected provider prefix roles overlap")
    return roles


def _private_file(path: Path, data: bytes, mode: int = 0o600, *, root_owned: bool = False) -> None:
    if type(root_owned) is not bool:
        raise SessionError("invalid fixed controller-file ownership option")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    errors = []
    try:
        if root_owned:
            # Darwin inherits the directory's group, even for root creation.
            os.fchown(fd, 0, 0)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise SessionError("short controller-file write")
            view = view[n:]
        os.fsync(fd)
        os.fchmod(fd, mode)  # Exact immutable/public-bootstrap mode despite umask.
        if root_owned:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid) != (0, 0)
                    or stat.S_IMODE(info.st_mode) != mode or info.st_size != len(data)
                    or os.get_inheritable(fd)):
                raise SessionError("root-owned controller-file postcondition differs")
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(fd)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("controller file write/close failure", errors)


def _remaining(deadline: float) -> float:
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise SessionError("invalid owning absolute deadline")
    left = deadline - time.monotonic()
    if left <= 0:
        raise DeadlineExpired("owning absolute deadline expired")
    return left


def _native_file_key(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _native_file(path: Path, *, deadline: float, uid: int, gid: int,
                 root_owned: bool = True, maximum: int = 16 * MiB) -> tuple[bytes, tuple]:
    """Finite no-follow immutable input binding, with independent owned close.

    These bytes and modes describe a file, not an executing platform-status bit.
    The original Apple codesign launch still relies on the expressly admitted OS
    provider/launch TCB premise. No file is copied, resigned or substituted here.
    """
    fd, errors, chunks, total = None, [], [], 0
    try:
        _remaining(deadline)
        if _canonical(path) != path:
            raise SessionError("native role input has a noncanonical alias")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum or before.st_uid == uid
                or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o002)
                or before.st_gid == gid and before.st_mode & 0o020
                or root_owned and (before.st_uid, before.st_gid) != (0, 0)
                or os.get_inheritable(fd)):
            raise SessionError("native role input type/ownership/mode/size differs")
        while True:
            _remaining(deadline)
            part = os.read(fd, min(65536, maximum - total + 1))
            if not part:
                break
            total += len(part)
            if total > maximum:
                raise SessionError("native role input exceeds its byte bound")
            chunks.append(part)
        if (_native_file_key(before) != _native_file_key(os.fstat(fd))
                or _native_file_key(before) != _native_file_key(path.lstat()) or total != before.st_size):
            raise SessionError("native role input changed during its original read")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if fd is not None:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native input observation/owned close failed", errors)
    return b"".join(chunks), _native_file_key(before)


def _python_full_command(root: Path, deadline: float) -> list[str]:
    """One source-defined command, never an arbitrary large-file executor."""
    return [str(root / "work/source-venv/bin/python"), "-I", "-B",
            str(root / "source/.github/scripts/ci_checks.py"), "--check", "python-full",
            "--source-root", str(root / "source"), "--work-root", str(root / "work/checks"),
            "--deadline", repr(deadline)]


def _python_full_memory(*, deadline: float) -> None:
    """Bounded kernel headroom admission, not a whole-process-tree memory cap."""
    fd, raw, errors = None, bytearray(), []
    try:
        _remaining(deadline)
        fd = os.open(Path("/proc/meminfo"), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        for _ in range(128):
            _remaining(deadline)
            chunk = os.read(fd, min(4096, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 65536:
                raise SessionError("memory headroom metadata exceeds byte bound")
        else:
            raise SessionError("memory headroom metadata exceeds read bound")
        values = []
        for line in raw.splitlines():
            if line.startswith(b"MemAvailable:"):
                match = re.fullmatch(rb"MemAvailable:[ \t]+([0-9]{1,12})[ \t]+kB", line)
                if match is None:
                    raise SessionError("memory headroom metadata has malformed availability")
                values.append(int(match[1]) * 1024)
        if len(values) != 1 or values[0] < 1536 * MiB:
            raise SessionError("fixed Python profile requires at least1536MiB MemAvailable")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if fd is not None:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("Python profile memory observation/close failed", errors)


def _userns_read(fd: int, *, deadline: float | None = None) -> int:
    """Read the one pinned kernel value, with a fixed byte/operation bound."""
    if deadline is not None:
        _remaining(deadline)
    if os.lseek(fd, 0, os.SEEK_SET) != 0:
        raise SessionError("user-namespace value did not seek to its fixed start")
    if deadline is not None:
        _remaining(deadline)
    raw = os.read(fd, 22)
    if deadline is not None:
        _remaining(deadline)
    extra = os.read(fd, 1)
    if deadline is not None:
        _remaining(deadline)
    if extra or re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})\n", raw) is None:
        raise SessionError("user-namespace value is not one bounded canonical decimal")
    value = int(raw)
    if value > (1 << 64) - 1:
        raise SessionError("user-namespace value exceeds the fixed integer bound")
    return value


def _userns_node(fd: int, *, deadline: float | None = None):
    """The fixed proc name and owned uninherited descriptor must be one node."""
    if deadline is not None:
        _remaining(deadline)
    pinned = os.fstat(fd)
    if deadline is not None:
        _remaining(deadline)
    named = os.stat(_USERNS_PATH, follow_symlinks=False)
    if deadline is not None:
        _remaining(deadline)
    same = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)
    if (same(pinned) != same(named) or not stat.S_ISREG(pinned.st_mode)
            or (pinned.st_uid, pinned.st_gid) != (0, 0)
            or stat.S_IMODE(pinned.st_mode) not in {0o600, 0o644}
            or os.get_inheritable(fd)):
        raise SessionError("user-namespace pin/name ownership, mode or descriptor custody differs")
    if deadline is not None:
        _remaining(deadline)
    return pinned


def _userns_zero(*, deadline: float | None = None) -> None:
    """Read-only entry assertion; the outside Session alone owns preparation."""
    fd, errors = None, []
    try:
        if sys.platform != "linux":
            raise SessionError("user-namespace entry assertion requires native Linux")
        if deadline is not None:
            _remaining(deadline)
        fd = os.open(_USERNS_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = _userns_node(fd, deadline=deadline)
        if _userns_read(fd, deadline=deadline) != 0:
            raise SessionError("user-namespace entry assertion did not observe zero")
        after = _userns_node(fd, deadline=deadline)
        if _home_node(before) != _home_node(after) or before.st_mode != after.st_mode:
            raise SessionError("user-namespace entry node changed during observation")
    except BaseException as exc:
        errors.append(exc)
    if fd is not None:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    if deadline is not None:
        try:
            _remaining(deadline)
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("user-namespace entry observation/close failed", errors)


def _tool_stat_note(info, uid: int, gid: int, *, role: str) -> dict:
    """One supplied stat observation; POSIX bits are not ACL/sandbox authority."""
    kind = next((name for name, check in (("regular", stat.S_ISREG), ("directory", stat.S_ISDIR),
                                         ("symlink", stat.S_ISLNK), ("fifo", stat.S_ISFIFO),
                                         ("socket", stat.S_ISSOCK), ("character", stat.S_ISCHR),
                                         ("block", stat.S_ISBLK)) if check(info.st_mode)), "other")
    return {"role": role if isinstance(role, str) and role in _TOOL_DIAGNOSTIC_ROLES else "unspecified",
            "kind": kind, "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "root_owned": info.st_uid == 0, "subject_owned": info.st_uid == uid,
            "subject_group": info.st_gid == gid, "setuid": bool(info.st_mode & stat.S_ISUID),
            "setgid": bool(info.st_mode & stat.S_ISGID), "owner_execute": bool(info.st_mode & 0o100),
            "group_execute": bool(info.st_mode & 0o010), "other_execute": bool(info.st_mode & 0o001)}


def _home_node(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IFMT(info.st_mode)


def _home_paths(home: Path, root: Path) -> tuple[Path, Path]:
    """Only two session-derived synthetic names, never a caller-selected reader."""
    if (not home.is_absolute() or not root.is_absolute() or ".." in home.parts
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", root.name)):
        raise SessionError("invalid fixed HOME fixture binding")
    canary, endpoint = (home / f".{root.name}-home-{suffix}" for suffix in ("read", "socket"))
    if len(os.fsencode(endpoint)) >= 104:
        raise SessionError("fixed HOME socket pathname exceeds native bound")
    return canary, endpoint


def _ruby_ancestor_paths(home: Path, ruby_prefix: Path) -> tuple[Path, ...]:
    """Pure, bounded strict ancestors; native identity checks belong to admission."""
    for path in (home, ruby_prefix):
        if (not path.is_absolute() or ".." in path.parts or path == Path("/")
                or any(not 32 <= ord(c) < 127 for c in str(path)) or len(str(path).encode()) > 4096):
            raise SessionError("invalid fixed Ruby ancestor binding")
    if ruby_prefix == home or not _under(ruby_prefix, home):
        raise SessionError("selected Ruby prefix must lie strictly beneath HOME")
    ancestors, current = [], ruby_prefix.parent
    while True:
        ancestors.append(current)
        if len(ancestors) > 16:
            raise SessionError("selected Ruby ancestor inventory exceeds fixed bound")
        if current == home:
            break
        current = current.parent
    return tuple(reversed(ancestors))


def _ruby_sibling_path(home: Path, ruby_prefix: Path, root: Path) -> Path:
    """One synthetic sibling beneath every literal, outside the Ruby prefix."""
    ancestors = _ruby_ancestor_paths(home, ruby_prefix)
    if (not root.is_absolute() or ".." in root.parts
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", root.name)):
        raise SessionError("invalid fixed Ruby sibling binding")
    sibling = ancestors[-1] / f".{root.name}-ancestor-read"
    if len(str(sibling).encode()) > 4096:
        raise SessionError("fixed Ruby sibling pathname exceeds bound")
    return sibling


def _admit_executable(path: Path, uid: int, gid: int, *, root_owned: bool = False,
                      non_set_id: bool = True, role: str = "unspecified") -> dict:
    """Check a fixed provider/system executable, not a subject-selected tool."""
    try:
        info = path.stat()
    except BaseException as exc:
        exc._ci_observation = {"tool_stat_failure": {
            "role": role if isinstance(role, str) and role in _TOOL_DIAGNOSTIC_ROLES else "unspecified",
            "observed": False}}
        raise  # Original identity, errno and cause; no replacement stat or inode.
    note = _tool_stat_note(info, uid, gid, role=role)
    note["failed_predicates"] = [name for name, failed in (
        ("not-regular", not stat.S_ISREG(info.st_mode)),
        ("no-execute-bit", not info.st_mode & 0o111),
        ("subject-owned", info.st_uid == uid),
        ("world-writable", bool(info.st_mode & 0o002)),
        ("subject-group-writable", info.st_gid == gid and bool(info.st_mode & 0o020)),
        ("root-role-not-root-owned", root_owned and info.st_uid != 0),
        ("root-role-group-or-world-writable", root_owned and bool(info.st_mode & 0o022)),
        ("set-id-forbidden", non_set_id and bool(info.st_mode & (stat.S_ISUID | stat.S_ISGID)))) if failed]
    if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111
            or info.st_uid == uid or info.st_mode & 0o002
            or info.st_gid == gid and info.st_mode & 0o020
            or root_owned and (info.st_uid != 0 or info.st_mode & 0o022)
            or non_set_id and info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        failure = SessionError("fixed executable permission/identity contract failed")
        failure._ci_observation = {"tool": note}
        raise failure
    return note


def _linux_native_process_toolchain(uid: int, gid: int, *, deadline: float) -> dict:
    """Read-only binding of the one distribution ABI-fixture compiler.

    Compilation/version observation belongs to ordinary Session captures, with
    fixed /usr/bin:/bin PATH. No package installation, command lookup, provider
    permission mutation or execution occurs here.
    """
    _remaining(deadline)
    if sys.platform != "linux" or os.geteuid() != 0 or os.uname().machine != "x86_64":
        raise SessionError("ABI fixture compiler requires the supported hosted Linux owner")
    compiler = Path("/usr/bin/x86_64-linux-gnu-gcc-13")
    for parent in reversed(compiler.parents):
        _remaining(deadline)
        _canonical(parent)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SessionError("fixed distribution compiler ancestry is writable or unowned")
    _canonical(compiler)
    before = compiler.lstat()
    # Validate the SAME metadata used as the opened-file baseline. A discarded
    # earlier stat admission cannot authorize adopting a different later node.
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or not before.st_mode & 0o111
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)):
        raise SessionError("fixed distribution compiler permission/identity contract failed")
    identity = lambda value: (_home_node(value), value.st_mode, value.st_size,
                              value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if not 0 < before.st_size <= 16 * MiB:
        raise SessionError("fixed distribution compiler size is unsupported")
    total, digest = 0, hashlib.sha256()
    with compiler.open("rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise SessionError("fixed distribution compiler opened a different node")
        while chunk := stream.read(65536):
            _remaining(deadline)
            total += len(chunk)
            if total > before.st_size:
                raise SessionError("fixed distribution compiler changed during binding")
            digest.update(chunk)
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise SessionError("fixed distribution compiler changed during read")
    _remaining(deadline)
    if total != before.st_size or identity(compiler.lstat()) != identity(before):
        raise SessionError("fixed distribution compiler lost its original binding")
    _canonical(compiler)
    _remaining(deadline)
    return {"gcc": compiler, "evidence": {"gcc_sha256": digest.hexdigest(),
            "provider": "ubuntu-24.04-distribution", "compiler_family": "gcc-13"}}


def _small_command(argv: list[str], seconds: float = 10.0,
                   *, user: int | None = None, group: int | None = None,
                   return_pid: bool = False, expected_code: int = 0,
                   detached: bool = True, deadline: float | None = None) -> bytes | tuple[bytes, int]:
    """Bounded, original-parent collection of fixed trusted OS metadata tools."""
    kwargs = {} if user is None else {"user": user, "group": group, "extra_groups": []}
    child = sel = None
    result = [bytearray(), bytearray()]
    eof, waited, code = [False, False], False, None
    if type(seconds) not in (int, float) or not 0 < seconds <= 3300:
        raise SessionError("invalid trusted metadata time allowance")
    cutoff = time.monotonic() + seconds
    if deadline is not None:
        _remaining(deadline)
        cutoff = min(cutoff, deadline)
    errors = []
    try:
        _remaining(cutoff)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True,
                                 env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                                 start_new_session=detached, **kwargs)
        _remaining(cutoff)
        sel = selectors.DefaultSelector()
        for i, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, i)
        while sel.get_map() or child.poll() is None:
            for key, _ in sel.select(min(0.05, _remaining(cutoff))):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    eof[key.data] = True
                    sel.unregister(key.fileobj)
                    continue
                result[key.data].extend(chunk)
                if sum(map(len, result)) > 2 * MiB:
                    raise SessionError("trusted metadata output limit")
        code = child.wait(timeout=_remaining(cutoff))
        waited = True
        _remaining(cutoff)
        if code != expected_code or result[1]:
            raise SessionError("trusted metadata tool failed or emitted diagnostics")
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            # This handle has no other owner.  No discovered-PID signal.
            if child.poll() is None:
                child.kill()
        except BaseException as exc:
            errors.append(exc)
        try:
            code = child.wait(timeout=max(0.0, min(2, cutoff - time.monotonic())))
            waited = True
        except BaseException as exc:
            errors.append(exc)
    for owned in (sel, child.stdout if child is not None else None,
                  child.stderr if child is not None else None):
        if owned is None:
            continue
        try:
            owned.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(cutoff)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        failure = BaseExceptionGroup("trusted metadata invocation/cleanup failure", errors)
        failure._ci_observation = {"returncode": code, "waited": waited, "stdout_eof": eof[0],
                                   "stderr_eof": eof[1], "stdout_bytes": len(result[0]),
                                   "stderr_bytes": len(result[1]), "error_count": len(errors),
                                   "exceptions": _child_exception_notes(bytes(result[1]))}
        observer_error = _observer_error_note(bytes(result[0]))
        if observer_error is not None:
            failure._ci_observation["observer_error"] = observer_error
        raise failure
    out = bytes(result[0])
    return (out, child.pid) if return_pid else out


def _nss_absent(uid: int) -> None:
    name = f"mrk-ci-{uid}"
    users, groups = pwd.getpwall(), grp.getgrall()
    if len(users) > 65536 or len(groups) > 65536:
        raise SessionError("NSS inventory limit")
    if any(p.pw_uid == uid or p.pw_gid == uid or p.pw_name == name for p in users):
        raise SessionError("NSS user/primary-group collision")
    if any(g.gr_gid == uid or g.gr_name == name for g in groups):
        raise SessionError("NSS group collision")
    for lookup, value in ((pwd.getpwuid, uid), (pwd.getpwnam, name),
                          (grp.getgrgid, uid), (grp.getgrnam, name)):
        try:
            lookup(value)
        except KeyError:
            continue
        raise SessionError("direct NSS lookup collision")


def _linux_snapshot(*, deadline: float | None = None) -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    """Complete bounded process AND thread credentials, including fs IDs."""
    if deadline is not None:
        _remaining(deadline)
    root = Path("/proc")
    pids = sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal())
    if len(pids) > 32768:
        raise SessionError("process census size")
    rows = {}
    for pid in pids:
        if deadline is not None:
            _remaining(deadline)
        task = root / str(pid) / "task"
        try:
            tids = sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal())
            if not tids:
                raise _CensusUnstable("enumerated process has no observable threads")
            if len(rows) + len(tids) > 131072:
                raise SessionError("thread census size")
            for tid in tids:
                if deadline is not None:
                    _remaining(deadline)
                base = task / str(tid)
                before = (base / "stat").read_bytes()
                raw = (base / "status").read_bytes()
                after = (base / "stat").read_bytes()
                if max(len(before), len(raw), len(after)) > 65536:
                    raise SessionError("process metadata size")
                # stat field22 follows the final ')' of the command field.
                # Validate BOTH identities and credentials before classifying a
                # difference. Malformed data can never be retried as absence.
                births = []
                for entry in (before, after):
                    marker = entry.rfind(b") ")
                    tail = entry[marker + 2:].split() if marker >= 0 else []
                    if len(tail) <= 19 or not tail[19].isdigit():
                        raise SessionError("malformed process birth metadata")
                    birth = int(tail[19])
                    if birth >= 2**64:
                        raise SessionError("process birth metadata exceeds unsigned64")
                    births.append(birth)
                fields = {}
                for line in raw.splitlines():
                    if b":" not in line:
                        continue
                    key, value = line.split(b":", 1)
                    if key in {b"Uid", b"Gid"}:
                        if key in fields:
                            raise SessionError("duplicate process credentials")
                        fields[key] = value.split()
                if (set(fields) != {b"Uid", b"Gid"}
                        or any(len(values) != 4 or any(not v.isdigit() for v in values)
                               for values in fields.values())):
                    raise SessionError("incomplete or malformed process credentials")
                uids, gids = (tuple(int(v) for v in fields[key]) for key in (b"Uid", b"Gid"))
                if any(value >= 2**32 for values in (uids, gids) for value in values):
                    raise SessionError("process credentials exceed unsigned32")
                if births[0] != births[1]:
                    raise _CensusUnstable("process identity changed during census")
                rows[(pid, tid)] = (uids, gids, births[0])
            if tids != sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal()):
                raise _CensusUnstable("thread churn during complete census")
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
            # Only a path beneath an already enumerated PID/TID may disappear.
            # Root enumeration failures below remain fatal, never empty passes.
            raise _CensusUnstable("enumerated process metadata disappeared") from exc
    if pids != sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal()):
        raise _CensusUnstable("process churn during complete census")
    if deadline is not None:
        _remaining(deadline)
    return rows


def _mac_snapshot(*, deadline: float | None = None) -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    # Unsupported Darwin fields/visibility are a failure, not an invented ABI.
    raw, owned_ps = _small_command(["/bin/ps", "-axo", "pid=,ruid=,uid=,svuid=,rgid=,gid=,svgid=,rss=,stat="],
                                  return_pid=True, deadline=deadline)
    rows = {}
    for line in raw.splitlines():
        if deadline is not None:
            _remaining(deadline)
        fields = line.split()
        if len(fields) != 9 or not all(s.isdigit() for s in fields[:8]):
            raise SessionError("unsupported/incomplete Darwin process fields")
        pid, ru, eu, su, rg, eg, sg, rss = map(int, fields[:8])
        if pid < 0 or (pid, pid) in rows or not fields[8]:
            raise SessionError("duplicate/invalid Darwin process row")
        if pid == owned_ps:
            continue  # This exact trusted observer was genuinely waited above.
        rows[(pid, pid)] = ((ru, eu, su), (rg, eg, sg), rss * 1024)
    if not rows or len(rows) > 32768:
        raise SessionError("empty/oversized Darwin process census")
    if deadline is not None:
        _remaining(deadline)
    return rows


def _snapshot(platform: str, *, deadline: float | None = None, retry_churn: bool = False):
    if platform != "linux":
        return _mac_snapshot(deadline=deadline)  # Darwin observation is unchanged.
    if not retry_churn:
        return _linux_snapshot(deadline=deadline)
    if deadline is None:
        raise SessionError("finality resnapshot requires its original finite cutoff")
    for attempt in range(_CENSUS_PASSES):
        _remaining(deadline)
        try:
            rows = _linux_snapshot(deadline=deadline)
        except _CensusUnstable:
            if attempt == _CENSUS_PASSES - 1:
                raise
            time.sleep(min(_CENSUS_PAUSE, _remaining(deadline)))
        else:
            _remaining(deadline)
            return rows


def _domain(platform: str, uid: int, *, collision: bool = False, deadline: float | None = None) -> set[int]:
    """Two full passes; no missing/truncated/unknown row is silently ignored."""
    occupied = set()
    for _ in range(2):
        if deadline is not None:
            _remaining(deadline)
        for (pid, _), (uids, gids, _) in _snapshot(platform, deadline=deadline, retry_churn=not collision).items():
            if uid in uids or (collision and uid in gids):
                occupied.add(pid)
    if deadline is not None:
        _remaining(deadline)
    return occupied


def _observe_original_credentials(pid: int, uid: int, gid: int, *, deadline: float) -> None:
    """Root observes its still-unreaped original handle; this is NOT signal authority."""
    try:
        if os.geteuid() != 0 or type(pid) is not int or pid <= 1:
            raise SessionError("original credential observation requires its outside root owner")
        _remaining(deadline)
        row = _mac_snapshot(deadline=deadline).get((pid, pid))
        _remaining(deadline)
        if row is None or row[:2] != ((uid, uid, uid), (gid, gid, gid)):
            raise SessionError("original unreaped child lacks exact real/effective/saved identities")
    except BaseException as exc:
        exc._ci_operation = "mac-original-credentials"
        raise


def _readonly_tree(root: Path) -> None:
    root = _canonical(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        for p in (Path(current), *(Path(current) / n for n in dirs + files)):
            s = p.lstat()
            if stat.S_ISLNK(s.st_mode) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
                raise SessionError("nonordinary immutable input")
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise SessionError("immutable input is not root-owned/read-only to subject")


def _observer_artifact(path: Path, uid: int, gid: int, *, deadline: float) -> tuple[bytes, int]:
    """Read only AFTER producer finality; never follow/adopt a mutable name."""
    fd = None
    errors, chunks = [], []
    size = 0
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                        s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        _remaining(deadline)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid) != (uid, gid)
                or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
                or not before.st_mode & 0o111 or not 0 < before.st_size <= 16 * MiB):
            raise SessionError("observer producer artifact identity/mode/size failed")
        while True:
            _remaining(deadline)
            chunk = os.read(fd, min(65536, 16 * MiB - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 16 * MiB:
                raise SessionError("observer producer artifact exceeds fixed bound")
        if fields(before) != fields(os.fstat(fd)) or fields(before) != fields(path.lstat()) or size != before.st_size:
            raise SessionError("observer producer artifact changed during observation")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if fd is not None:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer artifact observation/close failed", errors)
    return b"".join(chunks), stat.S_IMODE(before.st_mode)


def _observer_toolchain(uid: int, gid: int, *, deadline: float) -> dict:
    """Bind only the selected provider installation; no PATH/config discovery."""
    def marked(error: BaseException, phase: str, role: str, index: int, *, info=None,
               predicates: tuple[str, ...] | list[str] = (), tool: dict | None = None):
        # Every caller supplies a fixed phase/role/bounded traversal index. No
        # path, message, ACL or replacement stat enters this observation.
        note = {"phase": phase, "role": role, "index": index, "observed": info is not None or tool is not None}
        if info is not None or tool is not None:
            state = _tool_stat_note(info, uid, gid, role=role) if tool is None else tool
            note.update({key: state[key] for key in ("kind", "mode", "root_owned", "subject_owned", "subject_group")})
            note["failed_predicates"] = list(predicates)
        error._ci_observation = {"provider": note}
        return error

    def canonical(path: Path, role: str, *, resolve_link: bool = False) -> Path:
        try:
            _remaining(deadline)
            value = _canonical(path.resolve(strict=True) if resolve_link else path)
            _remaining(deadline)
            return value
        except BaseException as exc:
            raise marked(exc, "canonical", role, 0)

    def checked(path: Path, *, phase: str, role: str, index: int = 0,
                directory: bool = False, entry: bool = False):
        try:
            _remaining(deadline)
            info = path.lstat() if entry else path.stat()
        except BaseException as exc:
            raise marked(exc, phase, role, index)
        link = entry and stat.S_ISLNK(info.st_mode)
        # Symlink mode0777 is not permission to replace a name. Its owner,
        # checked parent and checked canonical target retain the real custody.
        predicates = [name for name, failed in (
            ("subject-owned", info.st_uid == uid),
            ("world-writable", not link and bool(info.st_mode & 0o002)),
            ("subject-group-writable", not link and info.st_gid == gid and bool(info.st_mode & 0o020)),
            ("not-ordinary", not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or link)),
            ("not-directory", directory and not stat.S_ISDIR(info.st_mode))) if failed]
        if predicates:
            raise marked(SessionError("selected compiler/SDK provider permission/type contract failed"),
                         phase, role, index, info=info, predicates=predicates)
        _remaining(deadline)
        return info

    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                           s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    xcode = canonical(Path("/Applications/Xcode_26.3.app/Contents/Developer"), "xcode")
    ancestors = (xcode, *xcode.parents)
    for index, path in enumerate(ancestors):
        checked(path, phase="ancestor", role="xcode", index=index, directory=True)
    intermediate = set(ancestors)

    def checked_chain(path: Path, role: str) -> None:
        """Protect names through canonical parents, not just a link's target."""
        _remaining(deadline)
        if not _under(path, xcode):
            raise marked(SessionError("selected provider parent is outside Xcode"), "intermediate", role, 0)
        chain, current = [], path
        while current != xcode:
            if len(chain) >= 64 or not _under(current, xcode):
                raise marked(SessionError("selected provider parent chain exceeds its fixed bound"),
                             "intermediate", role, 64)
            chain.append(current)
            current = current.parent
        for current in reversed(chain):
            if current in intermediate:
                continue
            index = len(intermediate)
            if index >= 300000:
                raise marked(SessionError("selected provider parent inventory exceeds its fixed bound"),
                             "intermediate", role, 300000)
            try:
                _remaining(deadline)
                if current.resolve(strict=True) != current:
                    raise SessionError("selected provider parent has a noncanonical alias")
                _remaining(deadline)
            except BaseException as exc:
                raise marked(exc, "intermediate", role, index)
            checked(current, phase="intermediate", role=role, index=index, directory=True)
            intermediate.add(current)  # Only successful canonical/directory checks are cached.

    toolchain = canonical(xcode / "Toolchains/XcodeDefault.xctoolchain", "toolchain")
    sdk_alias = xcode / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    checked_chain(sdk_alias.parent, "sdk")
    alias = checked(sdk_alias, phase="entry", role="sdk", entry=True)
    sdk = canonical(sdk_alias, "sdk", resolve_link=True)
    if not _under(sdk, xcode):
        raise marked(SessionError("selected SDK resolves outside fixed Xcode installation"),
                     "entry", "sdk", 0, info=alias, predicates=["outside-provider"])
    alias_after = checked(sdk_alias, phase="entry", role="sdk", entry=True)
    if identity(alias) != identity(alias_after):
        raise marked(SessionError("selected SDK alias changed during binding"), "entry", "sdk", 0,
                     info=alias_after, predicates=["identity-changed"])
    # Include both inventory roots and the fixed alias's own parents even if
    # its canonical target is another internal branch of the installation.
    for role, root in (("toolchain", toolchain), ("sdk", sdk)):
        checked_chain(root, role)
    # Follow only canonical provider links within Xcode, visiting each directory
    # once.  This includes headers/runtime files, not merely the clang pathname.
    pending, visited, count = [(toolchain, "toolchain"), (sdk, "sdk")], set(), 0
    while pending:
        current, role = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        directory_info = checked(current, phase="directory", role=role, index=count, directory=True)
        try:
            for item in current.iterdir():
                count += 1
                if count > 300000:
                    raise marked(SessionError("selected compiler/SDK inventory exceeds fixed bound"),
                                 "directory", role, 300000, info=directory_info, predicates=["inventory-bound"])
                entry_info = checked(item, phase="entry", role=role, index=count, entry=True)
                try:
                    _remaining(deadline)
                    target = item.resolve(strict=True)
                    _remaining(deadline)
                except BaseException as exc:
                    raise marked(exc, "target", role, count)
                if not _under(target, xcode):
                    raise marked(SessionError("selected compiler/SDK link escapes provider installation"),
                                 "entry", role, count, info=entry_info, predicates=["outside-provider"])
                if target != xcode:  # Xcode's own complete ancestor chain was checked first.
                    checked_chain(target.parent, role)
                info = checked(target, phase="target", role=role, index=count)
                entry_after = checked(item, phase="entry", role=role, index=count, entry=True)
                if identity(entry_info) != identity(entry_after):
                    raise marked(SessionError("selected provider entry changed during binding"),
                                 "entry", role, count, info=entry_after, predicates=["identity-changed"])
                if stat.S_ISDIR(info.st_mode):
                    pending.append((target, role))
        except BaseException as exc:
            if not isinstance(getattr(exc, "_ci_observation", None), dict) or "provider" not in exc._ci_observation:
                marked(exc, "directory", role, min(count, 300000))
            raise
    clang = canonical(toolchain / "usr/bin/clang", "compiler", resolve_link=True)
    linker = canonical(toolchain / "usr/bin/ld", "linker", resolve_link=True)
    for index, (role, path) in enumerate((("compiler", clang), ("linker", linker))):
        if not _under(path, toolchain):
            raise marked(SessionError("compiler/linker resolves outside selected toolchain"),
                         "canonical", role, index)

    for index, (role, path) in enumerate((("compiler", clang), ("linker", linker),
                                         ("signature-tool", Path("/usr/bin/codesign")))):
        try:
            # Fixed provider-owned clang/ld may have unrelated-group write,
            # just like the trusted provider inventory. U has no such group.
            _admit_executable(path, uid, gid, root_owned=role == "signature-tool", role=role)
        except BaseException as exc:
            original = getattr(exc, "_ci_observation", {})
            tool = original.get("tool") if isinstance(original, dict) else None
            raise marked(exc, "executable", role, index, tool=tool,
                         predicates=tool["failed_predicates"] if tool is not None else ())

    def digest(path: Path, maximum: int, role: str) -> str:
        before = checked(path, phase="digest-before", role=role)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise marked(SessionError("fixed provider file size/type unsupported"), "digest-before", role, 0,
                         info=before, predicates=["digest-size-or-type"])
        total, result = 0, hashlib.sha256()
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    _remaining(deadline)
                    total += len(chunk)
                    if total > maximum:
                        raise SessionError("fixed provider digest exceeds bound")
                    result.update(chunk)
        except BaseException as exc:
            raise marked(exc, "digest-before", role, 0)
        after = checked(path, phase="digest-after", role=role)
        if identity(before) != identity(after) or total != before.st_size:
            raise marked(SessionError("fixed provider file changed during binding"), "digest-after", role, 0,
                         info=after, predicates=["identity-changed"])
        return result.hexdigest()

    settings = sdk / "SDKSettings.json"
    settings_hash = digest(settings, MiB, "sdk")
    try:
        _remaining(deadline)
        with settings.open("rb") as stream:
            raw = stream.read(MiB + 1)
        _remaining(deadline)
        if len(raw) > MiB or hashlib.sha256(raw).hexdigest() != settings_hash:
            raise SessionError("selected SDK settings changed")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise SessionError("selected SDK settings do not contain an object")
        version, sdk_identity = data.get("Version"), data.get("CanonicalName")
        if (not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}", version)
                or sdk_identity != "macosx" + version):
            raise SessionError("selected SDK identity/version is unsupported")
        _remaining(deadline)
    except BaseException as exc:
        raise marked(exc, "settings", "sdk", 0)
    return {"clang": clang, "linker": linker, "sdk": sdk, "toolchain": toolchain,
            "evidence": {"xcode": "26.3", "clang_sha256": digest(clang, 512 * MiB, "compiler"),
                         "linker_sha256": digest(linker, 512 * MiB, "linker"), "sdk": sdk_identity,
                         "sdk_settings_sha256": settings_hash, "provider_entries": count}}


def _observer_signature_metadata(stdout: bytes, stderr: bytes, path: Path, arch: str) -> dict:
    """Strict fixed codesign display contract; no failed/empty display inference."""
    if stdout or not 0 < len(stderr) <= 16384 or not stderr.endswith(b"\n"):
        raise SessionError("observer signature display is incomplete")
    text = stderr.decode("ascii", "strict")
    if "\r" in text or "\0" in text or arch not in {"arm64", "x86_64"}:
        raise SessionError("observer signature display format unsupported")
    required = {f"Executable={path}", f"Identifier={path.name}", f"Format=Mach-O thin ({arch})",
                "Signature=adhoc", "TeamIdentifier=not set"}
    ordinary = {"Info.plist=not bound", "Sealed Resources=none", "Internal requirements=none",
                "Internal requirements count=0 size=12", "Hash type=sha256 size=32",
                "Hash choices=sha256", "CMSDigestType=2", "Executable Segment base=0",
                "Executable Segment flags=0x1", "Page size=4096", "Page size=16384"}
    seen, keys, flags = set(), set(), None
    for line in text.splitlines():
        key = ("CodeDirectory" if line.startswith("CodeDirectory ") else
               "Internal requirements" if line.startswith("Internal requirements") else line.split("=", 1)[0])
        if key in keys:
            raise SessionError("duplicate observer signature field")
        keys.add(key)
        seen.add(line)
        if line in required or line in ordinary:
            continue
        match = re.fullmatch(r"CodeDirectory v=([0-9]+) size=([0-9]+) flags=0x([0-9a-f]+)\(([^()]*)\) hashes=([0-9]+)\+([0-9]+) location=embedded", line)
        if match:
            if flags is not None:
                raise SessionError("duplicate observer CodeDirectory")
            flags = int(match[3], 16)
            if (flags not in {2, 0x20002} or match[4] != ("adhoc" if flags == 2 else "adhoc,linker-signed")
                    or not 20001 <= int(match[1]) <= 99999 or not 0 < int(match[2]) <= 16 * MiB
                    or not 0 < int(match[5]) <= 65536 or not 0 <= int(match[6]) <= 32):
                raise SessionError("observer signature has unsupported signing flags/layout")
            continue
        if (re.fullmatch(r"(?:CandidateCDHash sha256|CDHash)=[0-9a-f]{40}", line)
                or re.fullmatch(r"(?:CandidateCDHashFull sha256|CMSDigest)=[0-9a-f]{64}", line)
                or re.fullmatch(r"Executable Segment limit=[0-9]{1,10}", line)):
            continue
        # Authority, nonempty TeamIdentifier, CS platform identifier and every
        # unknown diagnostic/state are deliberately outside this finite grammar.
        failure = SessionError("observer signature display contains unknown or privileged metadata")
        known = {"Executable", "Identifier", "Format", "Signature", "TeamIdentifier", "Authority",
                 "Platform identifier", "Runtime Version", "CodeDirectory", "Internal requirements"}
        failure._ci_observation = {"signature_field": key if key in known else "unclassified"}
        raise failure
    if not required <= seen or flags is None:
        failure = SessionError("observer signature lacks positive ordinary ad-hoc evidence")
        failure._ci_observation = {"signature_fields_missing": sorted(line.split("=", 1)[0] for line in required - seen),
                                   "code_directory_missing": flags is None}
        raise failure
    return {"signature": "adhoc", "flags": flags, "architecture": arch}


def _observer_build_notes(data: bytes, source: Path) -> list[dict]:
    """Only reviewed C source positions/severity, never compiler message text."""
    pattern = re.compile(re.escape(str(source).encode()) + rb":([1-9][0-9]{0,6}):([1-9][0-9]{0,6}): (fatal error|error|warning):")
    notes = []
    for line in data[:65536].splitlines()[:512]:
        match = pattern.match(line)
        if match:
            notes.append({"file": ".github/scripts/ci_process_observer.c", "line": int(match[1]),
                          "column": int(match[2]), "severity": match[3].decode("ascii")})
        elif line.startswith(b"clang: error:"):
            notes.append({"category": "clang-driver"})
        if len(notes) == 16:
            break
    return notes or ([{"category": "unclassified-compiler-diagnostics"}] if data else [])


class Session:
    """One VM attempt, one reserved numeric identity, one aggregate deadline."""

    def __init__(self, platform: str, root: str | Path, *, python: str | Path,
                 ruby: str | Path, runner_home: str | Path, runner_temp: str | Path,
                 tool_prefixes: tuple[str | Path, ...] | list[str | Path], deadline: float,
                 compatibility_runtimes: tuple[tuple[str | Path, str | Path], ...] = ()):
        if platform not in {"linux", "darwin"} or sys.platform != platform or os.geteuid() != 0:
            raise SessionError("requires root controller on the selected disposable hosted VM")
        if not isinstance(deadline, (int, float)) or not 0 < deadline - time.monotonic() <= 3300:
            raise SessionError("invalid original aggregate deadline")
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise SessionError("another aggregate timer already owns this process")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise SessionError("original-parent ownership requires default SIGCHLD disposition")
        self.platform, self.root, self.deadline = platform, _canonical(root), deadline
        self.python, self.ruby = _canonical(python), _canonical(ruby)
        self.runner_home, self.runner_temp = _canonical(runner_home), _canonical(runner_temp)
        self.tool_prefixes = tuple(_canonical(p) for p in tool_prefixes)
        if (type(compatibility_runtimes) is not tuple or len(compatibility_runtimes) not in (0, 3)
                or any(type(pair) is not tuple or len(pair) != 2 for pair in compatibility_runtimes)):
            raise SessionError("three fixed compatibility runtime pairs are required")
        self.compatibility_runtimes = tuple((_canonical(executable), _canonical(prefix))
                                           for executable, prefix in compatibility_runtimes)
        if self.compatibility_runtimes:
            # Bind the complete expanded scope before reservations, HOME or any
            # provider effects. The old empty shape has no compatibility gates.
            _runtime_prefix_roles(platform, self.python, _canonical(sys.base_prefix), self.ruby,
                                  self.tool_prefixes, self.compatibility_runtimes)
        self.source, self.inputs = self.root / "source", self.root / "inputs"
        self.work, self.control, self.bootstrap = (self.root / n for n in ("work", "control", "bootstrap"))
        self.uid = self.gid = 60000 + secrets.randbelow(5000)  # One selection; never retry/adopt.
        self.failure = None
        self.cleanup_errors: list[str] = []
        self.admitted = self.closed = self.cancelled = self._busy = False
        self._admitting = False
        self.domain_finality = False
        self.persisted_bytes = self._run_number = 0
        self.admission_results: list[dict[str, object]] = []
        self.process_observer: Path | None = None
        self._native_process_toolchain_binding: dict | None = None
        self._home_state: dict | None = None
        self._userns_state: dict | None = None
        self._native_authority: dict[str, dict] = {}
        self._native_preparing: str | None = None
        self._native_control: dict | None = None
        self._handlers = {}
        self._timer_finished = False
        self._active: subprocess.Popen | None = None
        self._direct_producer_pending = False
        if self.root.parent != Path("/private/tmp" if platform == "darwin" else "/tmp"):
            raise SessionError("task root must be a fresh canonical direct child of platform tmp")
        parent_state = self.root.parent.stat()
        if parent_state.st_uid != 0 or not parent_state.st_mode & stat.S_ISVTX:
            raise SessionError("platform temporary parent lacks root-owned sticky-directory protection")
        rs = self.root.stat()
        if rs.st_uid != 0 or stat.S_IMODE(rs.st_mode) != 0o755:
            raise SessionError("task root must be root-owned0755")
        if not self.tool_prefixes or len(self.tool_prefixes) > 16:
            raise SessionError("finite trusted runtime prefixes required")
        for p in self.tool_prefixes:
            if _under(self.root, p) or _under(p, self.root) or p == Path("/"):
                raise SessionError("runtime prefix overlaps controller or mutable roots")
        for tool in (self.python, self.ruby):
            if not any(_under(tool, p) for p in self.tool_prefixes):
                raise SessionError("runtime outside admitted tool prefixes")
        if platform == "darwin":
            # Policy publication is exclusive and happens before HOME effects.
            # Bind its one finite metadata allowance now; never rewrite policy.
            self._bind_ruby_ancestors()
        # Claim the sole job-wide reservation with create-only ordinary APIs.
        self.reservation = self.root.parent / "mrk-ci-identity-reservation"
        self.reservation.mkdir(mode=0o700)
        self.reservation.chmod(0o700)
        _private_file(self.reservation / "identity.json", json.dumps({"uid": self.uid, "gid": self.gid}).encode())
        for path, mode in ((self.control, 0o700), (self.work, 0o700), (self.bootstrap, 0o755)):
            path.mkdir(mode=mode)
            path.chmod(mode)
        self.entry = self.bootstrap / "ci_sandbox.py"
        _private_file(self.entry, Path(__file__).read_bytes(), 0o444)
        _private_file(self.control / "denied", b"synthetic admission control\n")
        _private_file(self.bootstrap / "readonly", b"synthetic immutable input\n", 0o444)
        self.fixture_controls = self.root / "fixture-controls"
        self.fixture_controls.mkdir(mode=0o755)
        self.fixture_controls.chmod(0o755)
        self.outside_write = self.fixture_controls / "outside-write"
        _private_file(self.outside_write, b"not yet writable by the subject\n")
        self.policy, self.cleanup_policy = self.bootstrap / "subject.sb", self.bootstrap / "cleanup.sb"
        self.write_policy = self.bootstrap / "write-positive.sb"
        if platform == "darwin":
            self._write_policy()
        try:
            for sig in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
                self._handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._interrupted)
            # The timer is armed once, before data acquisition, and never renewed.
            signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
            self._guard()
            _readonly_tree(self.source)
        except BaseException as original:
            self._fail("controller initialization failed")
            self.closed = True
            try:
                self.finish()
            except SessionError as cleanup:
                if self.cleanup_errors:
                    raise BaseExceptionGroup("controller initialization and timer cleanup failed", [original, cleanup])
            raise

    def _fail(self, reason: str) -> None:
        if self.failure is None:
            self.failure = reason

    def fail(self, reason: str) -> None:
        """Latch a controller parser/provenance failure; there is no reset API."""
        self._fail(reason)

    @property
    def native_process_toolchain(self) -> dict:
        """Successful original admission only; callers cannot mutate custody."""
        self._guard()
        if not self.admitted or self._native_process_toolchain_binding is None:
            raise SessionError("native process toolchain has no successful admission")
        self.ensure_idle()
        tools = self._native_process_toolchain_binding
        return {**tools, "evidence": dict(tools["evidence"])}

    def _interrupted(self, signum: int, _frame) -> None:
        if signum == signal.SIGALRM:
            self._fail("original aggregate deadline expired")
            raise DeadlineExpired(self.failure)
        self.cancelled = True
        self._fail("controller cancellation")

    def _guard(self, *, allow_failure: bool = False) -> None:
        if time.monotonic() >= self.deadline:
            self._fail("original aggregate deadline expired")
        if self.closed or (self.failure and not allow_failure):
            raise SessionError(self.failure or "session already closed")

    def _bind_ruby_ancestors(self) -> None:
        """Canonical selected runtime ancestry, with no subject-writable member."""
        if self.platform != "darwin":
            raise SessionError("Ruby ancestor binding belongs only to the native Mac policy")
        prefix = self.ruby.parent.parent
        if [p for p in self.tool_prefixes if _under(self.ruby, p)] != [prefix]:
            raise SessionError("selected Ruby prefix is missing or ambiguous")
        ancestors = _ruby_ancestor_paths(self.runner_home, prefix)
        _remaining(self.deadline)
        if _canonical(prefix) != prefix:
            raise SessionError("selected Ruby prefix changed its canonical binding")
        states = []
        for path in ancestors:
            _remaining(self.deadline)
            before = path.lstat()
            _remaining(self.deadline)
            _canonical(path)
            _remaining(self.deadline)
            after = path.lstat()
            _remaining(self.deadline)
            mode = stat.S_IMODE(after.st_mode)
            if (not stat.S_ISDIR(after.st_mode) or after.st_uid == self.uid or after.st_gid == self.gid
                    or mode & 0o002 or not mode & 0o001 and not (path == self.runner_home and mode == 0o750)
                    or _home_node(before) != _home_node(after) or stat.S_IMODE(before.st_mode) != mode):
                raise SessionError("selected Ruby ancestor identity/traversal/mode is unsafe")
            states.append(after)
        self.ruby_prefix, self.ruby_ancestors = prefix, ancestors
        self._ruby_ancestor_states = tuple(states)

    def _check_ruby_ancestors(self, *, home_mode: int | None = None) -> None:
        """No policy/runtime ancestry drift; HOME's sole owned mode change is known."""
        if (self.ruby_ancestors != _ruby_ancestor_paths(self.runner_home, self.ruby_prefix)
                or len(self._ruby_ancestor_states) != len(self.ruby_ancestors)):
            raise SessionError("selected Ruby ancestor inventory lost its binding")
        for path, original in zip(self.ruby_ancestors, self._ruby_ancestor_states):
            _remaining(self.deadline)
            _canonical(path)
            _remaining(self.deadline)
            current = path.lstat()
            mode = home_mode if path == self.runner_home and home_mode is not None else stat.S_IMODE(original.st_mode)
            if _home_node(current) != _home_node(original) or stat.S_IMODE(current.st_mode) != mode:
                raise SessionError("selected Ruby ancestor identity/mode drifted")
            _remaining(self.deadline)

    def _write_policy(self) -> None:
        # JSON ASCII string escaping is also a valid SBPL string literal.
        q = lambda p: json.dumps(str(p), ensure_ascii=True)
        exclusions = "\n  ".join(f"(require-not (subpath {q(p)}))" for p in self.tool_prefixes)
        private = " ".join(f"(subpath {q(p)})" for p in (self.runner_home, self.runner_temp, self.control))
        common = ("(version 1)\n(allow default)\n(deny network*)\n(deny mach-lookup)\n"
                  f"(deny file-read* (require-all (require-any {private})\n  {exclusions}))\n")
        metadata = "".join(f"(allow file-read-metadata (literal {q(p)}))\n" for p in self.ruby_ancestors)
        subject = (common + metadata + "(deny signal (require-not (target same-sandbox)))\n"
                   f"(deny file-write* (require-all (require-not (subpath {q(self.work)})) "
                   '(require-not (literal "/dev/null"))))\n')
        # Fixed trusted cleanup runs as U.  No same-sandbox rule prevents its
        # kernel-authorized U-only cleanup; it has no network/Mach/write role.
        cleanup = common + '(deny file-write* (require-not (literal "/dev/null")))\n'
        write_positive = (common + f"(deny file-write* (require-all (require-not (literal {q(self.outside_write)})) "
                          '(require-not (literal "/dev/null"))))\n')
        _private_file(self.policy, subject.encode(), 0o444)
        _private_file(self.cleanup_policy, cleanup.encode(), 0o444)
        _private_file(self.write_policy, write_positive.encode(), 0o444)

    def _environment(self, values: dict[str, str]) -> dict[str, str]:
        if not isinstance(values, dict) or set(values) - _ENV_KEYS:
            raise SessionError("unapproved environment key")
        if any(not isinstance(v, str) or "\0" in v or len(v) > 32768 for v in values.values()):
            raise SessionError("invalid environment value")
        fixed = {"HOME": str(self.work / "home"), "USER": f"mrk-ci-{self.uid}",
                 "LOGNAME": f"mrk-ci-{self.uid}", "TMPDIR": str(self.work / "tmp"),
                 "TMP": str(self.work / "tmp"), "TEMP": str(self.work / "tmp"),
                 "XDG_CONFIG_HOME": str(self.work / "config"), "XDG_CACHE_HOME": str(self.work / "cache"),
                 "PYTHONSAFEPATH": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                 "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1", "PIP_NO_INPUT": "1",
                 "PIP_NO_CACHE_DIR": "1", "GEMRC": "/dev/null", "BUNDLE_RETRY": "0",
                 "BUNDLE_VERSION": "4.0.16", "BUNDLE_DISABLE_SHARED_GEMS": "1", "BUNDLE_FROZEN": "1",
                 "PIP_DISABLE_PIP_VERSION_CHECK": "1", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "BUNDLE_IGNORE_CONFIG": "1",
                 "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        observer_key = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"
        observer = getattr(self, "process_observer", None)
        if observer is not None:
            if self.platform != "darwin" or observer != self.bootstrap / "process-observer":
                raise SessionError("process observer selector lost its fixed owner binding")
            fixed[observer_key] = str(observer)
        elif observer_key in values:
            raise SessionError("process observer has not completed native admission")
        if any(k in values and values[k] != v for k, v in fixed.items()):
            raise SessionError("caller attempted to alter fixed clean-environment boundary")
        if "JAVA_TOOL_OPTIONS" in values and values["JAVA_TOOL_OPTIONS"] != JAVA_LIMITS:
            raise SessionError("only the reviewed literal JVM resource options are admitted")
        result = {"PATH": ":".join([str(self.python.parent), str(self.ruby.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
                  "LANG": "C.UTF-8" if self.platform == "linux" else "en_US.UTF-8",
                  "LC_ALL": "C.UTF-8" if self.platform == "linux" else "en_US.UTF-8", "TZ": "UTC", "CI": "true"}
        result.update(values)
        result.update(fixed)
        if "GEM_PATH" in result and ":" in result["GEM_PATH"]:
            raise SessionError("fixed Ruby caller admits one private GEM_PATH, not a search list")
        for key in ("VIRTUAL_ENV", "PIP_CACHE_DIR", "GEM_HOME", "GEM_PATH", "GEM_SPEC_CACHE",
                    "BUNDLE_PATH", "BUNDLE_APP_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_USER_CACHE",
                    "BUNDLE_USER_CONFIG", "MOBILE_RELEASE_TEST_PYTHON"):
            if key in result and (not Path(result[key]).is_absolute() or ".." in Path(result[key]).parts
                                  or not _under(Path(result[key]), self.work)):
                raise SessionError("mutable environment path outside private work")
        for key, wanted in (("PIP_FIND_LINKS", self.inputs / "python"),
                            ("BUNDLE_CACHE_PATH", self.inputs / "gems"),
                            ("BUNDLE_GEMFILE", self.source / "Gemfile")):
            if key in result and result[key] != str(wanted):
                raise SessionError("offline input environment path differs from immutable input")
        for component in result["PATH"].split(":"):
            p = Path(component)
            if not p.is_absolute() or ".." in p.parts or not any(
                _under(p, x) for x in (*self.tool_prefixes, self.work, Path("/usr"), Path("/bin"), Path("/sbin"))
            ):
                raise SessionError("untrusted executable PATH component")
        return result

    def _native_deadline(self, deadline: float) -> float:
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline <= self.deadline):
            raise SessionError("native authority needs its original tighter absolute cutoff")
        try:
            _remaining(deadline)
        except DeadlineExpired:
            self._fail("native authority original cutoff expired")
            raise
        return deadline

    def _native_command(self, phase: str) -> list[str]:
        if type(phase) is not str or phase not in _NATIVE_PHASES:
            raise SessionError("unknown fixed native authority phase")
        return [str(self.work / f"{phase}-venv/bin/python"), "-I", "-S", "-B",
                str(self.source / "tests/workflow/run_native_profile_checks.py"), "--authority",
                *(["--installed-wheel"] if phase == "wheel" else [])]

    def _native_initial_command(self, deadline: float) -> list[str]:
        """One source-only initial-application positive, never a caller command."""
        return [str(self.python), "-I", "-S", "-B", str(self.bootstrap / "ci_native_authority.py"),
                "--mach-initial", str(self.bootstrap / "native-authority-source.sb"), repr(deadline)]

    def _native_initial_binding(self, state: dict, argv: list[str], *, policy: Path,
                                cwd: Path, seconds: int) -> None:
        if self.cancelled:
            self._fail("controller cancellation")
        self._guard()
        if (self.platform != "darwin" or not self.admitted or self._admitting
                or self._native_preparing != "source" or self._native_authority.get("source") is not state
                or state.get("phase") != "source" or state.get("prepared") or state.get("started")
                or state.get("closed") or state.get("completed")
                or state.get("control_seen") != list(_NATIVE_CONTROL_CASES[:3])
                or type(argv) is not list or argv != self._native_initial_command(state["deadline"])
                or policy != self.bootstrap / "native-authority-source.sb" or policy != state["policy"]
                or cwd != state["cwd"] / "probes" or type(seconds) is not int or seconds != 30):
            raise SessionError("initial native application lacks its one fixed source-control binding")
        self._native_state_binding(state)
        self._native_deadline(state["deadline"])

    def _native_aia_baseline_command(self, deadline: float) -> list[str]:
        """One immutable, source-only full-chain comparison; no caller arguments."""
        return [str(self.python), "-I", "-S", "-B", str(self.bootstrap / "ci_native_authority.py"),
                "--aia-offline-baseline", repr(deadline)]

    def _native_freeze_baseline(self, state: dict, originals: tuple[bytes, bytes, bytes]) -> None:
        """Snapshot only the original parent's three public DER values at idle.

        The original U-owned probes directory and its pins are never changed.
        Partial creations remain in this failed VM; no retry or adoption follows.
        """
        if self.cancelled:
            self._fail("controller cancellation")
        self._guard()
        if (type(state) is not dict or self.platform != "darwin" or not self.admitted or self._admitting
                or self.process_observer is None or self._native_preparing != "source"
                or self._native_authority.get("source") is not state or state.get("phase") != "source"
                or state.get("prepared") or state.get("started") or state.get("completed") or state.get("closed")
                or self._native_control is not None or self._busy or self._active is not None
                or self._direct_producer_pending or state.get("control_seen") != list(_NATIVE_CONTROL_CASES[:6])
                or state.get("baseline_attempted", False) is not False
                or state.get("baseline_ready", False) is not False):
            raise SessionError("native baseline snapshot lacks its original one-shot source owner")
        if (type(originals) is not tuple or len(originals) != 3
                or any(type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024 or not raw.startswith(b"\x30")
                       for raw in originals) or len(set(originals)) != 3):
            raise SessionError("native baseline snapshot is not the fixed original DER triple")
        self._native_state_binding(state)
        self._native_deadline(state["deadline"])
        self.ensure_idle(deadline=state["deadline"])
        self._native_check_inputs(state)
        if self.cancelled:
            self._fail("controller cancellation")
        self._guard()
        self._native_deadline(state["deadline"])
        state["baseline_attempted"], state["baseline_ready"] = True, False
        state["baseline_der"] = originals  # Retain the original immutable tuple before any creation.
        try:
            for role, raw in zip(("leaf", "issuer", "root"), originals):
                if self.cancelled:
                    self._fail("controller cancellation")
                self._guard()
                self._native_deadline(state["deadline"])
                path = self.bootstrap / f"native-aia-baseline-{role}.der"
                _private_file(path, raw, 0o444, root_owned=True)
                if self._native_add_file(state, path, root_owned=True, maximum=16 * 1024) != raw:
                    raise SessionError("native baseline immutable snapshot differs from original bytes")
            self._native_check_inputs(state)
            if self.cancelled:
                self._fail("controller cancellation")
            self._guard()
            self._native_deadline(state["deadline"])
            state["baseline_ready"] = True
        except BaseException:
            state["baseline_ready"] = False
            self._fail("native baseline immutable snapshot failed")
            raise

    def _native_aia_baseline_binding(self, state: dict, argv: list[str], *, policy: Path,
                                     cwd: Path, seconds: int) -> None:
        if self.cancelled:
            self._fail("controller cancellation")
        self._guard()
        if (type(state) is not dict or self.platform != "darwin" or not self.admitted or self._admitting
                or self.process_observer is None or self._native_preparing != "source"
                or self._native_authority.get("source") is not state or state.get("phase") != "source"
                or state.get("prepared") or state.get("started") or state.get("closed") or state.get("completed")
                or self._busy or self._active is not None or self._direct_producer_pending
                or state.get("control_seen") != list(_NATIVE_CONTROL_CASES)
                or state.get("baseline_attempted") is not True or state.get("baseline_ready") is not True
                or type(argv) is not list or argv != self._native_aia_baseline_command(state["deadline"])
                or policy != self.bootstrap / "native-aia-source.sb"
                or cwd != state["cwd"] / "probes" or type(seconds) is not int or seconds != 120):
            raise SessionError("native baseline lacks its exact fixed source-control binding")
        originals = state.get("baseline_der")
        if (type(originals) is not tuple or len(originals) != 3
                or any(type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024 or not raw.startswith(b"\x30")
                       for raw in originals) or len(set(originals)) != 3):
            raise SessionError("native baseline lost the original DER triple")
        for role, raw in zip(("leaf", "issuer", "root"), originals):
            row = state["files"].get(self.bootstrap / f"native-aia-baseline-{role}.der")
            if (type(row) is not dict or row.get("root_owned") is not True or row.get("maximum") != 16 * 1024
                    or row.get("sha256") != hashlib.sha256(raw).hexdigest()
                    or type(row.get("identity")) is not tuple or len(row["identity"]) != 9
                    or row["identity"][6] != len(raw)):
                raise SessionError("native baseline snapshot has no original immutable input binding")
        self._native_state_binding(state)
        self._native_deadline(state["deadline"])

    def _native_environment(self, state: dict) -> dict[str, str]:
        """No caller hooks or previous ordinary HOME/configuration are imported."""
        root = state["cwd"]
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
                "LC_ALL": "en_US.UTF-8", "TZ": "UTC", "CI": "true",
                "HOME": str(root / "home"), "USER": f"mrk-ci-{self.uid}",
                "LOGNAME": f"mrk-ci-{self.uid}",
                "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
                "XDG_CONFIG_HOME": str(root / "config"), "XDG_CACHE_HOME": str(root / "cache"),
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
                "DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer"}

    def _native_pin(self, state: dict, path: Path, *, owner: tuple[int, int] = (0, 0),
                    modes: tuple[int, ...] = (0o555, 0o755)) -> None:
        """Retain original no-follow directory custody, never a pathname receipt."""
        if any(pin["path"] == path for pin in state["pins"]):
            return
        _remaining(state["deadline"])
        _canonical(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pin = {"path": path, "fd": fd, "node": None}
        state["pins"].append(pin)  # Custody precedes the first fallible observation.
        info = os.fstat(fd)
        named = path.lstat()
        node = (*_home_node(info), stat.S_IMODE(info.st_mode))
        if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != owner
                or stat.S_IMODE(info.st_mode) not in modes or os.get_inheritable(fd)
                or node != (*_home_node(named), stat.S_IMODE(named.st_mode))):
            raise SessionError("native authority directory custody/type/mode differs")
        pin["node"] = node
        _remaining(state["deadline"])

    def _native_add_file(self, state: dict, path: Path, *, root_owned: bool = True,
                         maximum: int = 16 * MiB) -> bytes:
        raw, identity = _native_file(path, deadline=state["deadline"], uid=self.uid, gid=self.gid,
                                     root_owned=root_owned, maximum=maximum)
        record = {"identity": identity, "sha256": hashlib.sha256(raw).hexdigest(),
                  "root_owned": root_owned, "maximum": maximum}
        if path in state["files"] and state["files"][path] != record:
            raise SessionError("native authority immutable file binding changed")
        state["files"][path] = record
        if len(state["files"]) > 1024 or sum(row["identity"][6] for row in state["files"].values()) > 128 * MiB:
            raise SessionError("native authority immutable input inventory exceeds fixed bounds")
        return raw

    def _native_tree(self, state: dict, root: Path, *, binding: bool) -> tuple[str, ...]:
        """Bound the complete read-granted first-party tree, not just imports."""
        names = []
        def walk_error(error):
            raise error
        for current, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
            _remaining(state["deadline"])
            current = Path(current)
            if len(current.relative_to(root).parts) > 32:
                raise SessionError("native authority input tree depth exceeds bound")
            if binding:
                self._native_pin(state, current, modes=(0o555,))
            for name in sorted(directories + files):
                _remaining(state["deadline"])
                path = current / name
                info = path.lstat()
                if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                        or (info.st_uid, info.st_gid) != (0, 0)
                        or stat.S_IMODE(info.st_mode) not in (0o444, 0o555)):
                    raise SessionError("native authority input tree is not ordinary and frozen")
                names.append(path.relative_to(root).as_posix())
                if len(names) > 1024:
                    raise SessionError("native authority input tree inventory exceeds bound")
                if binding and stat.S_ISREG(info.st_mode):
                    self._native_add_file(state, path)
        _remaining(state["deadline"])
        return tuple(sorted(names))

    def _native_bind_inputs(self, state: dict) -> None:
        deadline, phase = state["deadline"], state["phase"]
        # make_layout() has already permanently protected the work top level.
        # Admission's earlier U-owned0700 directory is NOT sufficient here.
        for path in (self.root, self.work, self.bootstrap):
            self._native_pin(state, path, modes=(0o755,))
        for path in (self.source, self.source / ".github", self.source / ".github/scripts"):
            self._native_pin(state, path, modes=(0o555,))
        venv = self.work / f"{phase}-venv"
        package = (self.work / "source-build/src/mobile_release" if phase == "source"
                   else venv / "lib/python3.11/site-packages/mobile_release")
        state["package"] = package
        for target in (venv / "bin", package.parent):
            paths, current = [], target
            while current != self.work:
                if not _under(current, self.work) or len(paths) > 32:
                    raise SessionError("native authority fixed input ancestry differs")
                paths.append(current)
                current = current.parent
            for path in reversed(paths):
                self._native_pin(state, path, modes=(0o555,))
        for root in (package, self.source / "tests"):
            state["trees"][root] = self._native_tree(state, root, binding=True)
        for path in (self.entry, self.source / ".github/scripts/ci_checks.py", self.source / "pyproject.toml"):
            self._native_add_file(state, path)
        original = self._native_add_file(state, self.python, root_owned=False, maximum=32 * MiB)
        selected = Path(self._native_command(phase)[0])
        if self._native_add_file(state, selected, maximum=32 * MiB) != original:
            raise SessionError("native authority interpreter is not the frozen selected provider copy")
        if stat.S_IMODE(state["files"][selected]["identity"][2]) != 0o555:
            raise SessionError("native authority interpreter mode is not frozen0555")
        _admit_executable(selected, self.uid, self.gid, root_owned=True, role="python")
        config = self._native_add_file(state, venv / "pyvenv.cfg")
        rows = {}
        for line in config.decode("utf-8", "strict").splitlines():
            key, separator, value = line.partition(" = ")
            if not separator or key in rows:
                raise SessionError("native authority venv configuration is ambiguous")
            rows[key] = value
        if (set(rows) != {"home", "include-system-site-packages", "version", "executable", "command"}
                or rows["home"] != str(self.python.parent) or rows["executable"] != str(self.python)
                or rows["include-system-site-packages"] != "false"
                or rows["version"] != sys.version.split()[0]
                or rows["command"] != f"{self.python} -m venv --copies {venv}"):
            raise SessionError("native authority venv runtime origin differs from its fixed provider")
        tools = {}
        for role, path in (("signature-tool", Path("/usr/bin/codesign")), ("true", Path("/usr/bin/true")),
                           ("sandbox-exec", Path("/usr/bin/sandbox-exec"))):
            _remaining(deadline)
            metadata = _admit_executable(path, self.uid, self.gid, root_owned=True, role=role)
            self._native_add_file(state, path)
            tools[role] = {"sha256": state["files"][path]["sha256"], "metadata": metadata}
        state["tools"] = tools
        # req's original command has no -config override. Bind only the two
        # documented public OS configuration locations, not all of private/etc.
        configs = (Path("/private/etc/ssl/openssl.cnf"), Path("/System/Library/OpenSSL/openssl.cnf"))
        for path in configs:
            _remaining(deadline)
            try:
                before = path.lstat()
            except FileNotFoundError:
                continue  # No compatibility claim: a missing actual dependency fails natively.
            actual = path.resolve(strict=True)
            if actual not in configs or _native_file_key(before) != _native_file_key(path.lstat()):
                raise SessionError("fixed OpenSSL public configuration alias changed or escaped")
            self._native_add_file(state, actual, maximum=MiB)
        _remaining(deadline)

    def _native_policy_bytes(self, state: dict, *, kind: str, port: int | None = None) -> bytes:
        """Separate finite policies. The ordinary _write_policy is untouched."""
        if kind not in {"authority", "mach-baseline", "aia", "write-positive"}:
            raise SessionError("unknown native fixed policy kind")
        if ((kind == "aia" and not (type(port) is int and 1024 <= port <= 65535))
                or kind != "aia" and port is not None):
            raise SessionError("native AIA policy lacks its original owned responder port")
        q = lambda value: json.dumps(str(value), ensure_ascii=True)
        runtime = (*self.tool_prefixes, Path("/Applications/Xcode_26.3.app/Contents/Developer"),
                   *(Path(p) for p in ("/System/Library", "/usr/lib", "/usr/share", "/usr/bin", "/bin", "/usr/sbin", "/sbin")))
        reads = [f"(subpath {q(path)})" for path in (*runtime, state["package"], self.source / "tests",
                                                    *(state["cwd"] / name for name in _NATIVE_LEAVES))]
        literals = (self.entry, self.bootstrap / "ci_native_authority.py", self.policy,
                    self.bootstrap / "native-authority-source.sb", state["policy"],
                    self.bootstrap / "readonly", self.source / "pyproject.toml",
                    self.source / ".github/scripts/ci_checks.py", Path(state["argv"][0]),
                    self.work / f"{state['phase']}-venv/pyvenv.cfg",
                    Path("/private/etc/ssl/openssl.cnf"), Path("/System/Library/OpenSSL/openssl.cnf"),
                    *(Path(p) for p in ("/dev/null", "/dev/random", "/dev/urandom",
                                       "/private/etc/localtime", "/private/etc/passwd", "/private/etc/group")))
        reads.extend(f"(literal {q(path)})" for path in literals)
        # Unchanged ios_profiles BOOTSTRAP uses FileFinder on package.parent.
        # Listing exactly this immutable directory is not reading its sibling
        # file/subdirectory bytes. Never grant a parent subpath here.
        reads.append(f"(literal {q(state['package'].parent)})")
        metadata = {p for path in (*runtime, *literals, state["package"], self.source / "tests", state["cwd"])
                    for p in (path.parent, *path.parents)} | set(self.ruby_ancestors) | {state["outside_write"], state["cwd"]}
        if len(metadata) > 256:
            raise SessionError("native authority metadata ancestry exceeds fixed bound")
        services = (*_NATIVE_TRUST_SERVICES, _NATIVE_OTHER_SERVICE) if kind == "mach-baseline" else _NATIVE_TRUST_SERVICES
        mach = " ".join(f"(global-name {q(name)})" for name in services)
        allowed_write = ([f"(literal {q(state['outside_write'])})"] if kind == "write-positive"
                         else [f"(subpath {q(state['cwd'] / name)})" for name in _NATIVE_LEAVES])
        # Native startup opens the public root directory. Admit its data (entry
        # names), not descendants or the general file-read* operation class.
        text = ("(version 1)\n(allow default)\n(deny network*)\n"
                f"(deny mach-lookup (require-not (require-any {mach})))\n"
                "(deny signal (require-not (target same-sandbox)))\n"
                f"(deny file-read* (require-not (require-any {' '.join(reads)})))\n"
                '(allow file-read-data (literal "/"))\n'
                + "".join(f"(allow file-read-metadata (literal {q(path)}))\n" for path in sorted(metadata))
                + f"(deny file-write* (require-not (require-any {' '.join(allowed_write)} (literal \"/dev/null\"))))\n")
        # AIA evaluation keeps this direct-network denial. Its fixed trust-service
        # route must still pass the real online/mutant fetch controls, or fail.
        return text.encode("ascii")

    def _native_check_inputs(self, state: dict) -> None:
        _remaining(state["deadline"])
        for pin in state["pins"]:
            _remaining(state["deadline"])
            if pin["fd"] is None or pin["node"] is None or os.get_inheritable(pin["fd"]):
                raise SessionError("native authority lost original directory descriptor custody")
            for current in (os.fstat(pin["fd"]), pin["path"].lstat()):
                if (*_home_node(current), stat.S_IMODE(current.st_mode)) != pin["node"]:
                    raise SessionError("native authority pinned directory/name changed")
        for root, wanted in state["trees"].items():
            if self._native_tree(state, root, binding=False) != wanted:
                raise SessionError("native authority immutable tree inventory changed")
        for path, expected in state["files"].items():
            raw, identity = _native_file(path, deadline=state["deadline"], uid=self.uid, gid=self.gid,
                                         root_owned=expected["root_owned"], maximum=expected["maximum"])
            if identity != expected["identity"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise SessionError("native authority bound input/policy bytes changed")
        if sorted(p.name for p in state["cwd"].iterdir()) != sorted(_NATIVE_LEAVES):
            raise SessionError("native authority scratch root lost its exclusive leaf inventory")
        _remaining(state["deadline"])

    def _native_close_pins(self, state: dict) -> list[str]:
        errors = []
        fd, state["outside_fd"] = state.get("outside_fd"), None
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as exc:
                errors.append(f"native authority outside fixture close {type(exc).__name__}")
        for pin in reversed(state["pins"]):
            fd, pin["fd"] = pin["fd"], None  # Ambiguous close is never retried.
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(f"native authority owned directory close {type(exc).__name__}")
        state["closed"] = True
        return errors

    def prepare_native_authority(self, phase: str, *, deadline: float) -> dict:
        """Owner-only finite preparation; no ordinary-subject request interface.

        A phase has one attempt. Genuine idle, immutable inputs and all native
        controls precede publication. Failed or ambiguous effects are retained
        in this VM; neither a second preparation nor an adopted directory exists.
        """
        self._guard()
        if (type(phase) is not str or phase not in _NATIVE_PHASES or self.platform != "darwin"
                or not self.admitted or self._admitting or self.process_observer is None
                or getattr(self, "_native_preparing", None) is not None
                or getattr(self, "_native_control", None) is not None):
            raise SessionError("native authority preparation state/platform/phase differs")
        deadline = self._native_deadline(deadline)
        if deadline - time.monotonic() > 900 or phase in self._native_authority:
            raise SessionError("native authority preparation has a renewed or duplicate phase")
        if phase == "wheel":
            previous = self._native_authority.get("source")
            if (not previous or not previous.get("completed") or not previous.get("closed")
                    or not previous.get("native_controls")):
                raise SessionError("wheel authority requires the completed original source authority")
        self.ensure_idle(deadline=deadline)
        state = {"phase": phase, "deadline": deadline, "cwd": self.work / ("native-authority-" + phase),
                 "policy": self.bootstrap / ("native-authority-" + phase + ".sb"),
                 "argv": self._native_command(phase), "pins": [], "files": {}, "trees": {},
                 "prepared": False, "started": False, "completed": False, "closed": False,
                 "control_seen": [], "startup_seen": [], "control_notes": {}, "native_controls": None, "outside_fd": None,
                 "outside_write": self.fixture_controls / f"native-authority-{phase}-outside-write",
                 "outside_read": self.work / "home" / f"native-authority-{phase}-read",
                 "sibling_read": self.work / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py"}
        self._native_authority[phase] = state  # Record attempt before any owned effects.
        self._native_preparing = phase
        note = {"name": "native-authority-" + phase + "-preparation", "ok": False}
        self.admission_results.append(note)
        try:
            self._native_bind_inputs(state)
            raw = self._native_add_file(state, self.source / ".github/scripts/ci_native_authority.py")
            helper = self.bootstrap / "ci_native_authority.py"
            if phase == "source":
                _private_file(helper, raw, 0o444)
            if self._native_add_file(state, helper) != raw:
                raise SessionError("native authority bootstrap helper differs from immutable source")
            _remaining(deadline)
            state["cwd"].mkdir(mode=0o755)
            state["cwd"].chmod(0o755)
            self._native_pin(state, state["cwd"], modes=(0o755,))
            for name in _NATIVE_LEAVES:
                _remaining(deadline)
                leaf = state["cwd"] / name
                leaf.mkdir(mode=0o700)
                os.chown(leaf, self.uid, self.gid)
                leaf.chmod(0o700)
                self._native_pin(state, leaf, owner=(self.uid, self.gid), modes=(0o700,))
            _private_file(state["outside_read"], b"MRK_NATIVE_PREVIOUS_SCRATCH\n", 0o444, root_owned=True)
            self._native_add_file(state, state["sibling_read"])
            self._native_pin(state, self.fixture_controls, modes=(0o755,))
            _private_file(state["outside_write"], b"MRK_NATIVE_OUTSIDE_INITIAL\n")
            state["outside_fd"] = os.open(state["outside_write"], os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            fd = state["outside_fd"]
            original = os.fstat(fd)
            if (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1
                    or (original.st_uid, original.st_gid) != (0, 0)
                    or stat.S_IMODE(original.st_mode) != 0o600 or os.get_inheritable(fd)
                    or _native_file_key(original) != _native_file_key(state["outside_write"].lstat())):
                raise SessionError("native authority outside positive fixture custody differs")
            os.fchown(fd, self.uid, self.gid)
            state["outside_node"] = _home_node(os.fstat(fd))
            _private_file(state["policy"], self._native_policy_bytes(state, kind="authority"), 0o444)
            self._native_add_file(state, state["policy"])
            positive = self.bootstrap / f"native-write-positive-{phase}.sb"
            _private_file(positive, self._native_policy_bytes(state, kind="write-positive"), 0o444)
            self._native_add_file(state, positive)
            state["write_policy"] = positive
            self._native_boundary_controls(state)
            if phase == "source":
                baseline = self.bootstrap / "native-mach-baseline.sb"
                _private_file(baseline, self._native_policy_bytes(state, kind="mach-baseline"), 0o444)
                self._native_add_file(state, baseline)
                state["mach_policy"] = baseline
                spec = importlib.util.spec_from_file_location("_mrk_native_authority_controls", helper)
                if spec is None or spec.loader is None:
                    raise SessionError("fixed native control helper is unavailable")
                backend = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(backend)  # Reviewed inert controller definitions only.
                state["backend"] = backend
                state["native_controls"] = backend.admit_controls(
                    lambda case, *, port=None: self._native_backend_capture(state, case, port=port),
                    lambda: self.ensure_idle(deadline=deadline), state["cwd"] / "probes", deadline=deadline,
                    policy_sha256=state["files"][state["policy"]]["sha256"],
                    freeze_baseline=lambda originals: self._native_freeze_baseline(state, originals))
                if state["control_seen"] != list(_NATIVE_CONTROL_CASES):
                    raise SessionError("native authority control inventory is incomplete")
                for case in _NATIVE_CONTROL_CASES:
                    state["control_notes"][case]["ok"] = True
            else:
                # Same literal service rule and probe-only oracle; the actual
                # wheel policy still receives its own direct native boundaries.
                state["native_controls"] = self._native_authority["source"]["native_controls"]
            self.ensure_idle(deadline=deadline)
            self._native_check_inputs(state)
            note.update({"phase": phase, "tools": state["tools"],
                         "input_files": len(state["files"]), "controls": state["native_controls"],
                         "service_controls_from": "source", "boundary_controls": "this-phase"})
            _remaining(deadline)
            if self.cancelled:
                self._fail("controller cancellation")
            self._guard()  # Final input/control work cannot publish after cancellation.
            state["prepared"] = True
            note["ok"] = True
            return {"schema": 1, "phase": phase, "prepared": True, "input_files": len(state["files"]),
                    "tools": state["tools"], "controls": state["native_controls"]}
        except BaseException as original:
            state["prepared"] = False
            note["ok"] = False
            self._fail("native authority preparation failed")
            errors = self._native_close_pins(state)
            self.cleanup_errors.extend(errors)
            note.update({"exceptions": _exception_notes(original), "cleanup_errors": len(errors)})
            if errors:
                raise BaseExceptionGroup("native authority preparation/owned close failed",
                                         [original, SessionError("native authority owned close failed")])
            raise
        finally:
            self._native_control = None
            self._native_preparing = None

    def _native_abort_error(self, abort: dict, error: BaseException, code: str) -> _NativeAbortIssue:
        if isinstance(error, _NativeAbortIssue):
            issue = error
        elif isinstance(error, DeadlineExpired):
            issue = _NativeAbortIssue("deadline", "DEADLINE")
        elif isinstance(error, KeyboardInterrupt):
            self.cancelled = True
            issue = _NativeAbortIssue("cancelled", "CANCELLED")
        else:
            issue = _NativeAbortIssue("unavailable", code,
                                      number=error.errno if isinstance(error, OSError) else None)
        note = {"code": issue.code, "producer_pending": bool(self._direct_producer_pending)}
        if issue.number is not None:
            note["errno"] = issue.number
        if "diagnostic_error" not in abort or issue.close_failed or self._direct_producer_pending:
            abort["diagnostic_error"] = note
        return issue

    def _native_abort_guard(self, abort: dict) -> None:
        # A latched subject failure permits this bounded observation, not a new
        # subject command. This cutoff never feeds back into the original run.
        if abort["close_failed"]:
            raise _NativeAbortIssue("unavailable", "IPS_CLOSE", close_failed=True)
        if self.cancelled:
            raise _NativeAbortIssue("cancelled", "CANCELLED")
        if self.closed or self._direct_producer_pending:
            raise _NativeAbortIssue("unavailable", "LOG_COLLECTOR")
        if time.monotonic() >= abort["deadline"]:
            raise _NativeAbortIssue("deadline", "DEADLINE")

    def _native_abort_close(self, abort: dict, owned, *, iterator: bool = False) -> None:
        """Caller retires the original handle first; never retry an uncertain close."""
        try:
            owned.close() if iterator else os.close(owned)
        except BaseException as exc:
            abort["close_failed"] = True
            self.cleanup_errors.append("native abort diagnostic readonly close failed")
            self._fail("native abort diagnostic readonly cleanup failed")
            issue = _NativeAbortIssue("unavailable", "IPS_CLOSE", close_failed=True,
                                      number=exc.errno if isinstance(exc, OSError) else None)
            self._native_abort_error(abort, issue, "IPS_CLOSE")
            # Readonly handles are not producers of reserved-identity processes.
            # Do not alter pending or independently established domain finality.
            raise issue from exc

    def _native_abort_read(self, abort: dict, path: Path, *, maximum: int,
                           directory_fd: int | None = None, fresh: bool = False) -> tuple[bytes, tuple]:
        fd, problem, chunks, total = None, None, [], 0
        try:
            self._native_abort_guard(abort)
            if (directory_fd is not None and (path.is_absolute() or len(path.parts) != 1)
                    or directory_fd is None and _canonical(path) != path):
                raise _NativeAbortIssue("unavailable", "IPS_IO")
            named = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory_fd)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_mode & (0o002 | stat.S_ISUID | stat.S_ISGID)
                    or before.st_gid == self.gid and before.st_mode & 0o020 or os.get_inheritable(fd)
                    or _native_file_key(named) != _native_file_key(before)):
                raise _NativeAbortIssue("unavailable", "IPS_IO")
            if not 0 <= before.st_size <= maximum:
                raise _NativeAbortIssue("limit", "LIMIT")
            if not fresh and not before.st_mode & 0o111:
                raise _NativeAbortIssue("unavailable", "LOG_ADMISSION")
            birth = None
            if fresh:
                launch, _after, waited = _native_abort_window(abort)
                now = time.time_ns()
                birth = getattr(before, "st_birthtime_ns", None)
                if birth is None:
                    displayed = getattr(before, "st_birthtime", None)
                    if type(displayed) not in (int, float) or not math.isfinite(displayed):
                        raise _NativeAbortIssue("unavailable", "IPS_IO")
                    birth = int(displayed * 1_000_000_000)
                if (type(now) is not int or now < waited or type(birth) is not int
                        or not launch <= birth <= now or not launch <= before.st_mtime_ns <= now):
                    raise _NativeAbortIssue("unavailable", "IPS_IO")
            budget_key, budget = ("ips_bytes", 4 * MiB) if fresh else ("binding_bytes", 32 * MiB)
            if abort[budget_key] + before.st_size > budget:
                raise _NativeAbortIssue("limit", "LIMIT")
            while True:
                self._native_abort_guard(abort)
                part = os.read(fd, min(65536, maximum - total + 1, budget - abort[budget_key] + 1))
                if not part:
                    break
                total += len(part)
                abort[budget_key] += len(part)
                if total > maximum or abort[budget_key] > budget:
                    raise _NativeAbortIssue("limit", "LIMIT")
                chunks.append(part)
            after = os.fstat(fd)
            final_name = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
            if (_native_file_key(before) != _native_file_key(after)
                    or _native_file_key(before) != _native_file_key(final_name) or total != before.st_size
                    or fresh and (getattr(before, "st_birthtime_ns", None), getattr(before, "st_birthtime", None)) !=
                                 (getattr(after, "st_birthtime_ns", None), getattr(after, "st_birthtime", None))):
                raise _NativeAbortIssue("unavailable", "IPS_IO")
            self._native_abort_guard(abort)
        except BaseException as exc:
            problem = self._native_abort_error(abort, exc, "IPS_IO")
        if fd is not None:
            owned, fd = fd, None
            try:
                self._native_abort_close(abort, owned)
            except _NativeAbortIssue as exc:
                problem = exc
        if problem is not None:
            raise problem
        self._native_abort_guard(abort)
        return b"".join(chunks), _native_file_key(before)

    def _native_abort_prepare(self, state: dict) -> dict:
        # Private known admitted images only. This table does not enlarge inputs,
        # tool roles, native policy or subject authority.
        abort = {"deadline": min(state["deadline"], self.deadline, time.monotonic() + 10),
                 "phase": state["phase"], "case": "outside-write-positive", "uid": self.uid,
                 "pid": None, "wall_before": None, "wall_after": None, "wall_wait": None,
                 "images": {str(self.python): "python-selected", "/usr/bin/sandbox-exec": "sandbox-exec"},
                 "bindings": {}, "binding_bytes": 0, "ips_bytes": 0, "candidates": 0,
                 "attempted": False, "log_attempted": False, "close_failed": False,
                 "control_root": str(self.control)}
        try:
            self._native_abort_guard(abort)
            prefixes = [prefix for prefix in self.tool_prefixes if _under(self.python, prefix)]
            original = getattr(sys, "orig_argv", None)
            if (len(prefixes) != 1 or type(original) is not list or not original
                    or not isinstance(original[0], str) or not Path(original[0]).is_absolute()):
                return abort
            candidate = Path(original[0]).resolve(strict=True)
            self._native_abort_guard(abort)
            if candidate in (self.python, Path("/usr/bin/sandbox-exec")) or not _under(candidate, prefixes[0]):
                return abort
            raw, identity = self._native_abort_read(abort, candidate, maximum=16 * MiB)
            abort["bindings"][str(candidate)] = {"identity": identity, "sha256": hashlib.sha256(raw).hexdigest()}
            abort["images"][str(candidate)] = "python-framework"
        except BaseException as exc:
            issue = self._native_abort_error(abort, exc, "IPS_IO")
            if issue.status in {"deadline", "cancelled"} or issue.close_failed:
                abort["disabled"] = issue.status
            # Cleanly unavailable optional framework image is simply omitted.
        return abort

    def _native_abort_stamp(self, abort: dict | None, key: str) -> None:
        if abort is None:
            return
        try:
            abort[key] = time.time_ns()
        except BaseException as exc:
            abort[key] = None
            self._native_abort_error(abort, exc, "CLOCK_BINDING")

    def _native_abort_ips(self, abort: dict) -> tuple[str, dict | None]:
        directory = Path("/Library/Logs/DiagnosticReports")
        prefixes = tuple(Path(path).name + separator for path in abort["images"] for separator in ("-", "_"))
        for attempt in range(2):
            fd = iterator = None
            problem, matches, issues, contradicted = None, [], [], False
            try:
                self._native_abort_guard(abort)
                named = os.stat(directory, follow_symlinks=False)
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002
                        or info.st_gid == self.gid and info.st_mode & 0o020
                        or os.get_inheritable(fd) or _home_node(named) != _home_node(info)
                        or named.st_mode != info.st_mode):
                    raise _NativeAbortIssue("unavailable", "IPS_IO")
                iterator = os.scandir(fd)  # Actual iterator owns a separate duplicated descriptor.
                for _ in range(256):
                    self._native_abort_guard(abort)
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        break
                    if not (entry.name.endswith(".ips") and entry.name.startswith(prefixes)):
                        continue
                    if abort["candidates"] >= 8:
                        raise _NativeAbortIssue("limit", "LIMIT")
                    abort["candidates"] += 1
                    try:
                        raw, _identity = self._native_abort_read(abort, Path(entry.name), maximum=MiB,
                                                               directory_fd=fd, fresh=True)
                        self._native_abort_guard(abort)
                        record = _native_abort_ips_record(raw, abort)
                        self._native_abort_guard(abort)
                        if record is not None:
                            matches.append(record)
                        else:
                            contradicted = True
                    except _NativeAbortIssue as exc:
                        if exc.close_failed or exc.status in {"deadline", "cancelled", "limit"}:
                            raise
                        issues.append(exc)
                else:
                    raise _NativeAbortIssue("limit", "LIMIT")
                # Log arrival can change directory times, not its original identity/mode.
                final_name = os.stat(directory, follow_symlinks=False)
                if _home_node(final_name) != _home_node(info) or final_name.st_mode != info.st_mode:
                    raise _NativeAbortIssue("unavailable", "IPS_IO")
            except FileNotFoundError:
                issues.append(_NativeAbortIssue("absent", "IPS_IO", retry=True))
            except BaseException as exc:
                problem = self._native_abort_error(abort, exc, "IPS_IO")
            if iterator is not None:
                owned, iterator = iterator, None
                try:
                    self._native_abort_close(abort, owned, iterator=True)
                except _NativeAbortIssue as exc:
                    problem = exc
            if fd is not None:
                owned, fd = fd, None
                try:
                    self._native_abort_close(abort, owned)
                except _NativeAbortIssue as exc:
                    problem = exc
            if problem is not None:
                raise problem
            self._native_abort_guard(abort)
            if len(matches) > 1 or matches and issues:
                return "ambiguous", None
            if matches:
                record = matches[0]
                hint = (record["termination_namespace"] in {"DYLD", "LIBSYSTEM", "SANDBOX", "CODESIGNING"}
                        or record["fault_image_role"] in {"dyld", "libsystem-secinit"}
                        or any(role in {"python-fatal-error", "dyld-halt", "libsecinit-initialize"}
                               for role in record["frame_roles"]))
                return ("matched" if hint else "matched-no-hint"), record
            retry = not contradicted and all(issue.retry for issue in issues)
            status = issues[0].status if issues else "unavailable" if contradicted else "absent"
            if attempt or not retry:
                if issues:
                    self._native_abort_error(abort, issues[0], "IPS_IO")
                return status, None
            self._native_abort_guard(abort)
            time.sleep(min(1.0, max(0.0, abort["deadline"] - time.monotonic())))
        raise AssertionError("bounded diagnostic scan did not terminate")

    def _native_abort_log(self, abort: dict) -> dict:
        result = {"log_status": "unavailable"}
        if abort["log_attempted"]:
            return result
        abort["log_attempted"] = True
        try:
            self._native_abort_guard(abort)
            before, _after, waited = _native_abort_window(abort)
            tool = Path("/usr/bin/log")
            raw, identity = self._native_abort_read(abort, tool, maximum=16 * MiB)
            abort["bindings"][str(tool)] = {"identity": identity, "sha256": hashlib.sha256(raw).hexdigest()}
            import datetime
            epoch = datetime.datetime(1970, 1, 1)
            start = (epoch + datetime.timedelta(seconds=before // 1_000_000_000)).strftime("%Y-%m-%d %H:%M:%S+0000")
            end = (epoch + datetime.timedelta(seconds=(waited + 999_999_999) // 1_000_000_000)).strftime("%Y-%m-%d %H:%M:%S+0000")
            predicate = f'(process == "kernel" OR process == "sandboxd") AND eventMessage CONTAINS "({abort["pid"]})"'
            argv = [str(tool), "show", "--style", "json", "--start", start, "--end", end,
                    "--timezone", "UTC", "--no-pager", "--predicate", predicate]
            self._native_abort_guard(abort)
            if identity != _native_file_key(os.stat(tool, follow_symlinks=False)):
                raise _NativeAbortIssue("unavailable", "LOG_ADMISSION")
            seconds = min(5.0, abort["deadline"] - time.monotonic())
            if seconds <= 0:
                raise _NativeAbortIssue("deadline", "DEADLINE")
        except BaseException as exc:
            issue = self._native_abort_error(abort, exc, "LOG_ADMISSION")
            result["log_status"] = issue.status if issue.status in {"deadline", "cancelled", "limit"} else "unavailable"
            return result
        self._direct_producer_pending = True
        self.domain_finality = False
        try:
            collected = _small_command(argv, seconds=seconds, deadline=abort["deadline"])
        except BaseException as exc:
            self.cleanup_errors.append("native abort diagnostic metadata collector did not release custody")
            self._fail("native abort diagnostic metadata collector cleanup failed")
            # Even waited/code0/bothEOF in exception observations are not a normal
            # collector return. Preserve actual producer uncertainty until VM disposal.
            self._native_abort_error(abort, _NativeAbortIssue("collector-error", "LOG_COLLECTOR",
                number=exc.errno if isinstance(exc, OSError) else None), "LOG_COLLECTOR")
            return {"log_status": "collector-error"}
        self._direct_producer_pending = False  # Genuine normal return only; no finality assertion here.
        result["log_sha256"] = hashlib.sha256(collected).hexdigest()
        try:
            self._native_abort_guard(abort)
            denials = _native_abort_log_records(collected, abort)
            self._native_abort_guard(abort)
            result.update({"log_status": "matched-denial" if denials else "no-record", "denials": denials})
        except BaseException as exc:
            result["log_status"] = self._native_abort_error(abort, exc, "LOG_PARSE").status
        return result

    def _native_abort_attach(self, abort: dict, result: CapturedRun) -> dict | None:
        if (self.platform != "darwin" or abort.get("phase") != "source"
                or abort.get("case") != "outside-write-positive" or abort["attempted"]
                or result.returncode != -signal.SIGABRT or not result.waited
                or not result.stdout_eof or not result.stderr_eof or not result.domain_finality
                or result.stderr != _NATIVE_WRITE_OUTER or result.timed_out or result.cancelled):
            return None
        abort["attempted"] = True
        row = {"schema": 1, "subject": "source-outside-write-positive", "ips_status": "unavailable",
               "log_status": "unavailable"}
        try:
            self._native_abort_guard(abort)
            _native_abort_window(abort)
            status, ips = self._native_abort_ips(abort)
            row["ips_status"] = status
            if ips is not None:
                row["ips"] = ips
            self._native_abort_guard(abort)
            if status == "matched":
                row["log_status"] = "not-needed"
            else:
                row.update(self._native_abort_log(abort))
        except BaseException as exc:
            issue = self._native_abort_error(abort, exc, "IPS_IO")
            row["ips_status"] = issue.status
            row["log_status"] = issue.status if issue.status in {"deadline", "cancelled"} else "unavailable"
            if not issue.close_failed and issue.status not in {"deadline", "cancelled"}:
                row.update(self._native_abort_log(abort))
        if "diagnostic_error" in abort:
            row["diagnostic_error"] = dict(abort["diagnostic_error"], producer_pending=bool(self._direct_producer_pending))
        if len(json.dumps(row, separators=(",", ":"), allow_nan=False).encode()) > 4096:
            return {"schema": 1, "subject": "source-outside-write-positive", "ips_status": "limit",
                    "log_status": "limit", "diagnostic_error": {"code": "LIMIT",
                    "producer_pending": bool(self._direct_producer_pending)}}
        return row

    def _native_exit_prepare(self, state: dict) -> dict | None:
        control = self._native_control
        if (self.platform != "darwin" or state["phase"] != "source" or control is None
                or control["state"] is not state or control["case"] != "startup-true"
                or control["argv"] != ["/usr/bin/true"] or self.process_observer is None):
            return None
        _remaining(state["deadline"])
        if os.geteuid() != 0 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise _NativeExitIdentity("original-parent runtime ownership invariant changed")
        parent = os.getpid()
        if type(parent) is not int or not 1 < parent < (1 << 31):
            raise _NativeExitIdentity("original controller PID is unavailable")
        context = {"runtime": None, "child": None, "pid": None, "parent": parent,
                   "uid": self.uid, "gid": self.gid, "deadline": None, "retired": True,
                   "samples": 0, "basic_attempted": False, "expected": None,
                   "reported_name_hint": "unavailable", "reason": None, "status": "unavailable",
                   "mismatch": False}
        try:
            if self.cancelled:
                self._fail("controller cancellation")
                context["status"] = "cancelled"
                return context
            context["runtime"] = _native_exit_runtime()
            context["retired"] = context["runtime"] is None
            _remaining(state["deadline"])
        except KeyboardInterrupt:
            self.cancelled = True
            self._fail("controller cancellation")
            context["retired"], context["status"] = True, "cancelled"
        except DeadlineExpired:
            context["retired"], context["status"] = True, "deadline"
        except Exception:
            self._native_exit_retire(context, "unavailable")
        return context

    def _native_exit_retire(self, context: dict | None, status: str | None = None) -> None:
        if context is not None and not context["retired"]:
            context["retired"] = True  # Irreversible, including when the following original poll returns None.
            if status is not None:
                context["status"] = status

    def _native_exit_owned(self, context: dict, child) -> None:
        if (child is not context["child"] or child.pid != context["pid"] or os.getpid() != context["parent"]
                or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            self._native_exit_retire(context, "identity-error")
            raise _NativeExitIdentity("original-parent diagnostic custody changed")

    def _native_exit_sample(self, context: dict, child, *, cutoff: float) -> str:
        if context["retired"]:
            return "retired"
        try:
            self._native_exit_owned(context, child)
            if context["deadline"] != cutoff:
                raise _NativeExitIdentity("original-parent diagnostic cutoff changed")
            if self.cancelled:
                self._native_exit_retire(context, "cancelled")
                return "retired"
            if time.monotonic() >= cutoff:
                self._native_exit_retire(context, "deadline")
                return "retired"
            if context["samples"] >= 64:
                self._native_exit_retire(context, "limit")
                return "retired"
            if getattr(child, "returncode", None) is not None:
                self._native_exit_retire(context, "unavailable")
                return "retired"
            context["samples"] += 1
            raw, _number = _native_exit_query(context["runtime"], context["pid"])
            observed = _native_exit_bsd(raw, pid=context["pid"], parent=context["parent"],
                                        uid=context["uid"], gid=context["gid"])
            if observed is None:
                self._native_exit_retire(context, "unavailable")
                return "retired"
            if observed["status"] == "terminal":
                context.update({"expected": observed["expected"], "reported_name_hint": observed["reported_name_hint"],
                                "status": "terminal"})
                return "terminal"  # The collector must latch nonzero BEFORE any optional BASIC call.
            if self.cancelled or time.monotonic() >= cutoff:
                self._native_exit_retire(context, "cancelled" if self.cancelled else "deadline")
                return "retired"
            return "live"  # A live/transition sample must NOT be followed by a consuming poll.
        except _NativeExitIdentity:
            self._native_exit_retire(context, "identity-error")
            raise
        except KeyboardInterrupt:
            self.cancelled = True
            self._native_exit_retire(context, "cancelled")
        except DeadlineExpired:
            self._native_exit_retire(context, "deadline")
        except Exception:
            self._native_exit_retire(context, "unavailable")
        return "retired"

    def _native_exit_reason(self, context: dict, child) -> None:
        if context["retired"] or context["basic_attempted"] or context["expected"] in (None, 0):
            return
        try:
            self._native_exit_owned(context, child)
            if self.cancelled or time.monotonic() >= context["deadline"]:
                self._native_exit_retire(context, "cancelled" if self.cancelled else "deadline")
                return
            if getattr(child, "returncode", None) is not None:
                self._native_exit_retire(context, "unavailable")
                return
            context["basic_attempted"] = True
            # The already-latched terminal failure is expected here. It is not
            # permission for another process, another budget, or a later retry.
            raw, number = _native_exit_query(context["runtime"], context["pid"], basic=True)
            reason = _native_exit_basic(raw)
            context["reason"] = reason
            context["status"] = "observed" if reason is not None else "absent" if number == errno.ENOENT else "unavailable"
        except _NativeExitIdentity:
            self._native_exit_retire(context, "identity-error")
            raise
        except KeyboardInterrupt:
            self.cancelled = True
            self._native_exit_retire(context, "cancelled")
        except DeadlineExpired:
            self._native_exit_retire(context, "deadline")
        except Exception:
            self._native_exit_retire(context, "unavailable")

    def _native_exit_compare(self, context: dict | None, code: int | None) -> bool:
        if (context is None or context["expected"] is None or code is None
                or context["expected"] == code or context["mismatch"]):
            return False
        context["mismatch"] = True
        context["status"] = "wait-mismatch"
        return True  # Only the caller holding the real wait latches this additional failure.

    def _native_exit_attach(self, context: dict | None, result: CapturedRun) -> dict | None:
        if context is None or result.ok:
            return None
        row = {"schema": 1, "status": context["status"], "reported_name_hint": context["reported_name_hint"]}
        if context["expected"] is not None:
            row["expected_wait_code"] = context["expected"]
        if context["reason"] is not None:
            row.update(context["reason"])
        if len(json.dumps(row, separators=(",", ":"), allow_nan=False).encode()) > 2048:
            return {"schema": 1, "status": "limit", "reported_name_hint": "unavailable"}
        return row

    def _native_control_capture(self, state: dict, case: str, argv: list[str], *, policy: Path,
                                cwd: Path, seconds: int) -> CapturedRun:
        """Only the fixed internal catalogs below construct these arguments."""
        if (self._native_preparing != state["phase"] or self._native_control is not None
                or state["closed"] or state["started"]):
            raise SessionError("native admission capture lacks its original preparation owner")
        self._native_state_binding(state)
        policies = {"mach-baseline": self.bootstrap / "native-mach-baseline.sb", "mach-ordinary": self.policy,
                    "mach-authority": state["policy"], "mach-nonexpand": self.policy,
                    "aia-prepare": state["policy"],
                    "aia-evaluate": self.bootstrap / "native-aia-source.sb",
                    "aia-offline-baseline": self.bootstrap / "native-aia-source.sb",
                    "outside-write-positive": self.bootstrap / f"native-write-positive-{state['phase']}.sb",
                    "outside-read-positive": self.policy, "native-isolation": state["policy"]}
        bounds = {"aia-prepare": 300, "aia-evaluate": 120, "aia-offline-baseline": 120,
                  "outside-write-positive": 10, "outside-read-positive": 10}
        helper = self.bootstrap / "ci_native_authority.py" if case in _NATIVE_CONTROL_CASES else self.entry
        expected_cwd = state["cwd"] / "probes" if case in _NATIVE_CONTROL_CASES else state["cwd"]
        if case in _NATIVE_STARTUP_CASES:
            seen = state.get("startup_seen")
            if (self.platform != "darwin" or state["phase"] != "source" or state["prepared"]
                    or not self.admitted or self._admitting or self.process_observer is None
                    or self._busy or self._active is not None or self._direct_producer_pending
                    or self._native_authority.get("source") is not state
                    or type(seen) is not list or len(seen) >= len(_NATIVE_STARTUP_CASES)
                    or seen != list(_NATIVE_STARTUP_CASES[:len(seen)])
                    or case != _NATIVE_STARTUP_CASES[len(seen)]
                    or seen and state["control_notes"].get("startup-true", {}).get("ok") is not True):
                raise SessionError("native startup control lacks its original source-only ordered owner")
            command = (["/usr/bin/true"] if case == "startup-true" else
                       [str(self.python), "-I", "-S", "-B", "-c", _NATIVE_STARTUP_PYTHON])
            if (type(argv) is not list or argv != command or type(seconds) is not int or seconds != 10
                    or cwd != state["cwd"] or policy != self.bootstrap / "native-write-positive-source.sb"
                    or policy != state.get("write_policy")):
                raise SessionError("native startup control differs from its two fixed vectors/policy/bounds")
            self._native_deadline(state["deadline"])
            if self.cancelled:
                self._fail("controller cancellation")
            self._guard()
            seen.append(case)  # Consume before acquisition; even an exception cannot replay this case.
        elif (case not in policies or policy != policies[case] or seconds != bounds.get(case, 30)
                or cwd != expected_cwd or argv[:5] != [str(self.python), "-I", "-S", "-B", str(helper)]):
            raise SessionError("native control differs from its finite immutable helper/policy catalog")
        if case == "mach-authority":
            self._native_initial_binding(state, argv, policy=policy, cwd=cwd, seconds=seconds)
        elif "--mach-initial" in argv:
            raise SessionError("initial native application is not available to another control")
        if case == "aia-offline-baseline":
            self._native_aia_baseline_binding(state, argv, policy=policy, cwd=cwd, seconds=seconds)
        elif "--aia-offline-baseline" in argv:
            raise SessionError("native baseline is not available to another control")
        aia_text_case = state["phase"] == "source" and case == "aia-evaluate"
        self._native_control = {"state": state, "case": case, "argv": argv, "policy": policy,
                                "cwd": cwd, "seconds": seconds}
        exit_reason = None
        try:
            abort = None
            if self.platform == "darwin" and state["phase"] == "source" and case == "startup-true":
                exit_reason = self._native_exit_prepare(state)
                self._native_control["exit_reason"] = exit_reason
            if self.platform == "darwin" and state["phase"] == "source" and case == "outside-write-positive":
                abort = self._native_abort_prepare(state)
                self._native_control["abort"] = abort
            result = self._run(argv, cwd=cwd, env={}, seconds=seconds, output_limit=MiB,
                               cpu_seconds=180, latch=True, profile="native-control",
                               absolute_deadline=state["deadline"])
            row = self._note_capture("native-authority-" + state["phase"] + "-" + case, result,
                                     parse_child_notes=case not in {"mach-authority", "mach-nonexpand", "aia-offline-baseline"}
                                     and not aia_text_case)
            state["control_notes"][case] = row
            if case in _NATIVE_STARTUP_CASES:
                expected = b"" if case == "startup-true" else _NATIVE_STARTUP_STDOUT
                row["ok"] = (result.ok and type(result.stdout) is bytes and result.stdout == expected
                             and type(result.stderr) is bytes and not result.stderr and not self.cancelled
                             and self.failure is None and time.monotonic() < state["deadline"])
                if not row["ok"]:
                    self._fail(result.primary_error or "native startup control did not complete")
                    if case == "startup-python":
                        row["native_startup_stage"] = _native_startup_stage(result.stdout)
            if exit_reason is not None and not row["ok"]:
                attachment = self._native_exit_attach(exit_reason, result)
                if attachment is not None:
                    row["native_exit_reason"] = attachment
            if (case == "outside-write-positive" and (not result.ok
                    or result.stdout != b"MRK_OUTSIDE_WRITE_POSITIVE\n" or result.stderr != _NATIVE_WRITE_STDERR)):
                row["native_write_startup"] = _native_write_prefix(result.stderr)
            if abort is not None:
                attachment = self._native_abort_attach(abort, result)
                if attachment is not None:
                    row["native_abort_diagnostic"] = attachment
            if not result.ok and case in _NATIVE_CONTROL_CASES:
                # Diagnostic-only closed fields; never replace the failed
                # capture, its original EOF/wait/finality or missing execution.
                role = ("mach-initial" if case == "mach-authority" else
                        "mach" if case in {"mach-baseline", "mach-ordinary"} else case)
                if time.monotonic() < state["deadline"]:
                    diagnostic = state["backend"].parse_failure(result.stderr, role)
                    if diagnostic is not None:
                        row["native_control_error"] = diagnostic
                    else:
                        row["native_control_diagnostics_unavailable"] = True
                    if aia_text_case:
                        launch_text = _native_aia_launch_text(result, self.python, helper)
                        if launch_text is not None:
                            row["native_aia_launch_text"] = launch_text
                else:
                    row["native_control_diagnostics_unavailable"] = True
            return result  # Genuine original wait/EOF/finality/persisted facts.
        finally:
            self._native_exit_retire(exit_reason)  # Also covers preparation failures before the collector's try.
            self._native_control = None

    def _native_backend_capture(self, state: dict, case: str, *, port: int | None = None) -> CapturedRun:
        index = len(state["control_seen"])
        if (state["phase"] != "source" or type(case) is not str or index >= len(_NATIVE_CONTROL_CASES)
                or case != _NATIVE_CONTROL_CASES[index]):
            raise SessionError("native backend case is absent, duplicated or out of order")
        _remaining(state["deadline"])
        helper = self.bootstrap / "ci_native_authority.py"
        base = [str(self.python), "-I", "-S", "-B", str(helper)]
        if case.startswith("mach-"):
            if port is not None:
                raise SessionError("Mach lookup control has no network port input")
            policies = {"mach-baseline": state["mach_policy"], "mach-ordinary": self.policy,
                        "mach-authority": state["policy"], "mach-nonexpand": self.policy}
            policy = policies[case]
            command = ([*base, "--mach-nonexpand", str(self.bootstrap / "native-authority-source.sb"),
                        repr(state["deadline"])] if case == "mach-nonexpand"
                       else self._native_initial_command(state["deadline"]) if case == "mach-authority"
                       else [*base, "--mach", repr(state["deadline"])])
            seconds = 30
        elif case == "aia-offline-baseline":
            if port is not None or state.get("baseline_ready") is not True:
                raise SessionError("native baseline requires its immutable snapshot and has no port input")
            originals = state.get("baseline_der")
            command = self._native_aia_baseline_command(state["deadline"])
            policy = self.bootstrap / "native-aia-source.sb"  # Binding only; never a policy-off switch.
            seconds = 120
        else:
            if type(port) is not int or not 1024 <= port <= 65535:
                raise SessionError("AIA control lacks the original owned responder port")
            policy = self.bootstrap / "native-aia-source.sb"
            if case == "aia-prepare":
                if "aia_port" in state:
                    raise SessionError("AIA original responder binding was already attempted")
                state["aia_port"] = port
                _private_file(policy, self._native_policy_bytes(state, kind="aia", port=port), 0o444)
                self._native_add_file(state, policy)
            elif port != state.get("aia_port"):
                raise SessionError("AIA responder port changed after fixture preparation")
            command = [*base, "--" + case, str(port), repr(state["deadline"])]
            seconds = 300 if case == "aia-prepare" else 120
            if case == "aia-prepare":
                policy = state["policy"]  # Fixture creation has no network requirement.
        state["control_seen"].append(case)  # No retry after ambiguous launch or collection.
        result = self._native_control_capture(state, case, command, policy=policy,
                                              cwd=state["cwd"] / "probes", seconds=seconds)
        if case == "aia-offline-baseline" and result.ok:
            try:
                self.ensure_idle(deadline=state["deadline"])
                self._native_check_inputs(state)
                if self.cancelled:
                    self._fail("controller cancellation")
                self._guard()
                self._native_deadline(state["deadline"])
                if state.get("baseline_der") is not originals or result.stderr != b"":
                    raise SessionError("native baseline original inputs or closed output differ")
                observation = state["backend"].baseline_comparison_note(result.stdout, originals)
                if self.cancelled:
                    self._fail("controller cancellation")
                self._guard()
                self._native_deadline(state["deadline"])
                if state.get("baseline_der") is not originals:
                    raise SessionError("native baseline original tuple changed during projection")
                state["control_notes"][case]["aia_baseline"] = observation
            except BaseException:
                self._fail("native baseline comparison/finality failed")
                raise
        return result  # Negative trust data cannot change the original capture or AIA oracle.

    def _native_boundary_controls(self, state: dict) -> None:
        """Real positives/negatives under EACH phase's actual authority policy."""
        deadline, listeners, endpoints, errors = state["deadline"], [], [], []
        base = [str(self.python), "-I", "-S", "-B", str(self.entry)]
        try:
            if state["phase"] == "source":
                for case, command in (("startup-true", ["/usr/bin/true"]),
                                      ("startup-python", [str(self.python), "-I", "-S", "-B", "-c", _NATIVE_STARTUP_PYTHON])):
                    self._native_control_capture(state, case, command,
                        policy=state["write_policy"], cwd=state["cwd"], seconds=10)
                    row = state["control_notes"][case]  # This original capture, not a reconstructed receipt.
                    if row["ok"] is not True:
                        raise SessionError("native startup boundary control failed")
                    try:
                        self.ensure_idle(deadline=deadline)
                        _remaining(deadline)
                        if self.cancelled:
                            self._fail("controller cancellation")
                        self._guard()
                    except BaseException:
                        row["ok"] = False
                        raise
            positive = self._native_control_capture(state, "outside-write-positive",
                [*base, "--native-write-control", str(state["outside_write"])],
                policy=state["write_policy"], cwd=state["cwd"], seconds=10)
            if (not positive.ok or positive.stdout != b"MRK_OUTSIDE_WRITE_POSITIVE\n"
                    or positive.stderr != _NATIVE_WRITE_STDERR):
                raise SessionError("native authority outside-write positive did not complete")
            self.ensure_idle(deadline=deadline)
            fd = state["outside_fd"]
            current = os.fstat(fd)
            if (_home_node(current) != state["outside_node"] or current.st_nlink != 1
                    or stat.S_IMODE(current.st_mode) != 0o600 or os.get_inheritable(fd)
                    or _native_file_key(current) != _native_file_key(state["outside_write"].lstat())):
                raise SessionError("native authority writable canary changed its original custody")
            os.lseek(fd, 0, os.SEEK_SET)
            if os.read(fd, 64) != b"MRK_POSITIVE_WRITE\n" or os.read(fd, 1):
                raise SessionError("native authority outside-write positive did not persist exact bytes")
            positive = self._native_control_capture(state, "outside-read-positive",
                [*base, "--native-read-control", state["phase"], repr(deadline)],
                policy=self.policy, cwd=state["cwd"], seconds=10)
            if not positive.ok or positive.stdout != b"MRK_NATIVE_OUTSIDE_READ_OK\n" or positive.stderr:
                raise SessionError("native authority known previous/sibling read positive failed")
            self.ensure_idle(deadline=deadline)
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    _remaining(deadline)
                    listener = socket.socket(family, kind)
                    listeners.append(listener)
                    listener.settimeout(min(1, _remaining(deadline)))
                    listener.bind((host, 0))
                    address = listener.getsockname()
                    if kind == socket.SOCK_STREAM:
                        listener.listen(8)
                    _outside_network_control(listener, deadline=deadline)
                    endpoints.append([int(family), int(kind), host, address[1]])
            canary, home_socket = _home_paths(self.runner_home, self.root)
            data = {"uid": self.uid, "gid": self.gid, "platform": "darwin",
                    "work": str(self.work), "probe_scratch": str(state["cwd"] / "probes"),
                    "source": str(self.source), "readonly": str(self.bootstrap / "readonly"),
                    "control": str(self.control / "denied"), "outside_write": str(state["outside_write"]),
                    "outside_reads": [str(state["outside_read"]), str(state["sibling_read"])],
                    "runner_home": str(self.runner_home), "runner_temp": str(self.runner_temp),
                    "home_canary": str(canary), "home_socket": str(home_socket),
                    "ruby_prefix": str(self.ruby_prefix), "ruby_executable": str(self.ruby),
                    "home_sibling": str(_ruby_sibling_path(self.runner_home, self.ruby_prefix, self.root)),
                    "endpoints": endpoints}
            result = self._native_control_capture(state, "native-isolation", [*base, "--probe", json.dumps(data)],
                policy=state["policy"], cwd=state["cwd"], seconds=30)
            if not result.ok or result.stdout != b"MRK_NATIVE_ISOLATION_OK\n" or result.stderr:
                raise SessionError("native authority real identity/FD/files/network inheritance controls failed")
            self.ensure_idle(deadline=deadline)
            _outside_network_empty(listeners, deadline=deadline)
            _home_socket_empty(self._home_state["listener"], deadline=deadline)
            self._native_signal_control(state)
            self.ensure_idle(deadline=deadline)
            current = os.fstat(fd)
            if (_home_node(current) != state["outside_node"] or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1
                    or _native_file_key(current) != _native_file_key(state["outside_write"].lstat())):
                raise SessionError("native authority canary revocation lost its original finality/custody")
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o400)
            after = os.fstat(fd)
            if ((after.st_uid, after.st_gid) != (0, 0) or stat.S_IMODE(after.st_mode) != 0o400
                    or after.st_dev != current.st_dev or after.st_ino != current.st_ino
                    or _native_file_key(after) != _native_file_key(state["outside_write"].lstat())):
                raise SessionError("native authority outside grant revocation postcondition failed")
            _remaining(deadline)
        except BaseException as exc:
            errors.append(exc)
        finally:
            for listener in listeners:
                try:
                    listener.close()
                except BaseException as exc:
                    errors.append(exc)
            try:
                _remaining(deadline)
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native authority boundary/owned listener cleanup failed", errors)
        for case in ("outside-write-positive", "outside-read-positive", "native-isolation"):
            state["control_notes"][case]["ok"] = True

    def _native_signal_control(self, state: dict) -> None:
        """Fixed same-UID outside sentinel, never a discovered service/process."""
        deadline = state["deadline"]
        self.ensure_idle(deadline=deadline)
        sentinel, errors, subject_done, sentinel_waited = None, [], False, False
        self.domain_finality = False
        self._direct_producer_pending = True
        try:
            _remaining(deadline)
            sentinel = subprocess.Popen(self._trusted_entry(self.cleanup_policy, ["--sentinel"]),
                cwd=state["cwd"], env=self._native_environment(state), user=self.uid,
                group=self.gid, extra_groups=[], close_fds=True, start_new_session=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self._active = sentinel
            _observe_original_credentials(sentinel.pid, self.uid, self.gid, deadline=deadline)
            if _ready_line(sentinel.stdout, 5, deadline=deadline) != b"MRK_SENTINEL_READY\n":
                raise SessionError("native authority outside signal sentinel did not become ready")
            raw = _small_command(self._trusted_entry(state["policy"], ["--signal-case", str(sentinel.pid)]),
                                 10, user=self.uid, group=self.gid, deadline=deadline)
            subject_done = True  # Only the genuine original collector's normal return releases custody.
            if raw != b"MRK_SIGNAL_BOUNDARY_OK\n":
                raise SessionError("native authority actual signal control failed")
            out, err = sentinel.communicate(b"q", timeout=min(2, _remaining(deadline)))
            sentinel_waited = True
            if sentinel.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
                raise SessionError("native authority outside sentinel received a signal or failed")
        except BaseException as exc:
            errors.append(exc)
        finally:
            if sentinel is not None:
                try:
                    if sentinel.poll() is None:
                        sentinel.kill()  # Original synthetic handle only.
                except BaseException as exc:
                    errors.append(exc)
                try:
                    sentinel.wait(timeout=max(0.0, min(2, deadline - time.monotonic())))
                    sentinel_waited = True
                except BaseException as exc:
                    errors.append(exc)
                for stream in (sentinel.stdin, sentinel.stdout, sentinel.stderr):
                    try:
                        stream.close()
                    except BaseException as exc:
                        errors.append(exc)
            if sentinel_waited:
                self._active = None
            if subject_done and sentinel_waited:
                self._direct_producer_pending = False
            try:
                _remaining(deadline)
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native authority original signal controls/cleanup failed", errors)
        self.ensure_idle(deadline=deadline)
        self.admission_results.append({"name": "native-authority-" + state["phase"] + "-signal", "ok": True})

    def _native_state_binding(self, state: dict) -> None:
        phase = state.get("phase")
        if (type(phase) is not str or phase not in _NATIVE_PHASES
                or state.get("cwd") != self.work / ("native-authority-" + phase)
                or state.get("policy") != self.bootstrap / ("native-authority-" + phase + ".sb")
                or state.get("argv") != self._native_command(phase)
                or state.get("package") != (self.work / "source-build/src/mobile_release" if phase == "source"
                    else self.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")):
            raise SessionError("native authority lost its exact fixed phase/path/policy binding")

    def _native_request(self, argv: list[str], *, cwd: Path, env: dict, seconds: float,
                        output_limit: int, cpu_seconds: int, latch: bool, cancel_after: float | None,
                        profile: str, absolute_deadline: float | None) -> dict:
        if (self.platform != "darwin" or not self.admitted or self._admitting or not latch
                or cancel_after is not None or type(env) is not dict or env
                or type(cpu_seconds) is not int or cpu_seconds != 180 or type(output_limit) is not int
                or type(seconds) not in (int, float) or not math.isfinite(seconds)
                or self.process_observer is None):
            raise SessionError("native role invocation differs from its admitted fixed owner")
        if profile == "native-control":
            control = self._native_control
            if control is None or self._native_preparing != control["state"]["phase"]:
                raise SessionError("native control has no original private preparation owner")
            state = control["state"]
            if (argv != control["argv"] or cwd != control["cwd"] or seconds != control["seconds"]
                    or output_limit != MiB or state["prepared"] or state["started"] or state["closed"]):
                raise SessionError("native admission command/cwd/bounds differ from its fixed catalog")
        else:
            phase = profile.removeprefix("native-authority-")
            state = self._native_authority.get(phase)
            if (state is None or not state["prepared"] or state["started"] or state["completed"]
                    or state["closed"] or self._native_preparing is not None or self._native_control is not None
                    or argv != self._native_command(phase) or argv != state["argv"] or cwd != state["cwd"]
                    or seconds != 900 or output_limit != 8 * MiB or not state["native_controls"]):
                raise SessionError("native authority command/phase/cwd/bounds differ from its prepared one-shot role")
        if absolute_deadline != state["deadline"]:
            raise SessionError("native authority original cutoff was changed or renewed")
        self._native_state_binding(state)
        self._native_deadline(absolute_deadline)
        return state

    def _native_scratch_inventory(self, state: dict) -> dict:
        """Only observe bounded ordinary task outputs after actual finality.

        Private scratch is retained for the existing successful controller's
        symlink-safe disposal; a failed or unknown attempt is left to VM disposal.
        No output pathname grants authority to delete a foreign/shared resource.
        """
        count = total = 0
        def walk_error(error):
            raise error
        for leaf in _NATIVE_LEAVES:
            root = state["cwd"] / leaf
            for current, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
                _remaining(state["deadline"])
                if len(Path(current).relative_to(root).parts) > 32:
                    raise SessionError("native scratch output depth exceeds bound")
                for name in directories + files:
                    _remaining(state["deadline"])
                    info = (Path(current) / name).lstat()
                    if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                            or (info.st_uid, info.st_gid) != (self.uid, self.gid)
                            or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022)
                            or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                        raise SessionError("native scratch output has unsafe type/ownership/mode/link state")
                    count += 1
                    total += info.st_size if stat.S_ISREG(info.st_mode) else 0
                    if count > 4096 or total > 128 * MiB:
                        raise SessionError("native scratch outputs exceed fixed inventory/byte bounds")
        _remaining(state["deadline"])
        return {"entries": count, "bytes": total, "private_retained": True}

    def _native_finish_run(self, state: dict, result: CapturedRun) -> CapturedRun:
        start, errors, expired = time.monotonic(), [], False
        note = {"name": "native-authority-" + state["phase"] + "-postconditions", "ok": False}
        self.admission_results.append(note)
        try:
            if result.ok:
                self.ensure_idle(deadline=state["deadline"])
                self._native_check_inputs(state)
                note["outputs"] = self._native_scratch_inventory(state)
            else:
                self._fail("native authority capture did not succeed")
        except BaseException as exc:
            expired = isinstance(exc, DeadlineExpired)
            errors.append(f"native authority postconditions {type(exc).__name__}")
            note["exceptions"] = _exception_notes(exc)
        finally:
            errors.extend(self._native_close_pins(state))
            finished = time.monotonic()
            if finished >= state["deadline"]:
                expired = True
                errors.append("native authority postconditions exceeded original cutoff")
        cancelled = result.cancelled or self.cancelled
        if self.cancelled and not result.cancelled:
            self._fail("controller cancellation")
            errors.append("native authority postconditions observed late controller cancellation")
        elif self.failure and result.ok:
            errors.append("native authority postconditions observed latched session failure")
        state["completed"] = result.ok and not errors and not cancelled and self.failure is None
        note.update({"ok": state["completed"], "cleanup_errors": len(errors)})
        if errors:
            self._fail(result.primary_error or "native authority postconditions failed")
            self.cleanup_errors.extend(errors)
        # Extend THIS actual capture's own postconditions; never invent a
        # combined capture, original wait, EOF, output bytes or successful phase.
        return dataclasses.replace(result, primary_error=result.primary_error or
                                   (self.failure if errors else None),
                                   cleanup_errors=(*result.cleanup_errors, *errors),
                                   timed_out=result.timed_out or expired,
                                   cancelled=cancelled,
                                   duration=result.duration + max(0.0, finished - start))

    def _argv(self, argv: list[str], cpu: int, *, profile: str = "ordinary") -> tuple[list[str], dict]:
        if type(profile) is not str or profile not in {"ordinary", "python-full", "native-control", *_NATIVE_PROFILES}:
            raise SessionError("unknown fixed command profile")
        if profile == "python-full" and (self.platform != "linux" or cpu != 300
                                          or argv != _python_full_command(self.root, self.deadline)):
            raise SessionError("fixed Python profile command/platform differs")
        role = "--enter-python-full" if profile == "python-full" else "--enter"
        policy = self.policy
        if profile in _NATIVE_PROFILES:
            phase = profile.removeprefix("native-authority-")
            state = getattr(self, "_native_authority", {}).get(phase)
            if (self.platform != "darwin" or cpu != 180 or state is None or not state["prepared"]
                    or state["started"] or state["closed"] or argv != self._native_command(phase)
                    or self._native_preparing is not None or self._native_control is not None):
                raise SessionError("native authority argv lacks its fixed original preparation")
            self._native_state_binding(state)
            policy = state["policy"]
        elif profile == "native-control":
            control = getattr(self, "_native_control", None)
            if (self.platform != "darwin" or cpu != 180 or control is None
                    or self._native_preparing != control["state"]["phase"] or argv != control["argv"]):
                raise SessionError("native control argv lacks its private fixed catalog owner")
            policy = control["policy"]
        if "--mach-initial" in argv:
            if profile != "native-control" or control.get("case") != "mach-authority":
                raise SessionError("initial native application is not a public or alternate command role")
            self._native_initial_binding(control["state"], argv, policy=policy,
                                         cwd=control["cwd"], seconds=control["seconds"])
        if "--aia-offline-baseline" in argv:
            if profile != "native-control" or control.get("case") != "aia-offline-baseline":
                raise SessionError("native baseline is not a public or alternate command role")
            self._native_aia_baseline_binding(control["state"], argv, policy=policy,
                                               cwd=control["cwd"], seconds=control["seconds"])
        entry = [str(self.python), "-I", "-S", "-B", str(self.entry), role, self.platform,
                 str(self.uid), str(self.gid), str(cpu), str(policy), *argv]
        if self.platform == "darwin":
            return entry, {"user": self.uid, "group": self.gid, "extra_groups": []}
        cmd = ["/usr/bin/bwrap", "--assert-userns-disabled", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
               "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP"]
        mounted = []
        for p in [Path(n) for n in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc") if Path(n).exists()]:
            if _under(self.root, p) or any(_under(q, p) for q in (self.runner_home, self.runner_temp, self.control)):
                raise SessionError("broad OS bind would expose a private controller root")
            cmd += ["--ro-bind", str(p), str(p)]
            mounted.append(p)
        cmd += ["--proc", "/proc", "--dev", "/dev"]
        if profile == "python-full":
            for path, capacity in _PYTHON_FULL_PRIVATE_TMPFS:
                if path == "/dev/shm":
                    cmd += ["--dir", path]
                cmd += ["--size", str(capacity), "--perms", "01777", "--tmpfs", path]
        else:
            cmd += ["--tmpfs", "/run", "--tmpfs", "/tmp", "--dir", "/dev/shm", "--tmpfs", "/dev/shm"]
        # bubblewrap0.9 bind operations can auto-create ancestors0700.  This is
        # an empty namespace-local directory, NOT a bind of the owner task root;
        # its control/fixture directories remain absent from the subject view.
        cmd += ["--perms", "0755", "--dir", str(self.root)]
        for p in (*self.tool_prefixes, self.source, self.inputs, self.bootstrap):
            if not any(_under(p, existing) for existing in mounted):
                cmd += ["--ro-bind", str(p), str(p)]
                mounted.append(p)
        cmd += ["--ro-bind" if profile == "python-full" else "--bind", str(self.work), str(self.work)]
        if profile == "python-full":
            for name, capacity in _PYTHON_FULL_WORK_TMPFS:
                cmd += ["--size", str(capacity), "--perms", "01777", "--tmpfs", str(self.work / name)]
        cmd += ["--", "/usr/bin/setpriv", "--reuid", str(self.uid), "--regid", str(self.gid),
                "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                "--bounding-set=-all", "--", *entry]
        return cmd, {}

    def _check_python_full_inputs(self) -> None:
        """The higher logical limit belongs only to frozen source test inputs."""
        _remaining(self.deadline)
        python = _canonical(self.work / "source-venv/bin/python")
        _remaining(self.deadline)
        _admit_executable(python, self.uid, self.gid, root_owned=True, role="python")
        _remaining(self.deadline)
        checks = _canonical(self.source / ".github/scripts/ci_checks.py")
        _remaining(self.deadline)
        info = checks.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SessionError("fixed Python profile check source is not immutable controller input")
        _remaining(self.deadline)

    def _headroom(self) -> None:
        info = os.statvfs(self.root)
        if info.f_bavail * info.f_frsize < DISK_RESERVE:
            raise SessionError("private verification disk headroom exhausted")

    def ensure_idle(self, *, deadline: float | None = None) -> None:
        """Required BEFORE any copy/hash/chmod/delete of task-produced paths."""
        self._guard()
        cutoff = self.deadline
        if deadline is not None:
            if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                    or not 0 < deadline <= self.deadline):
                raise SessionError("invalid tighter idle-observation deadline")
            cutoff = deadline
        if self._busy or self._active is not None or getattr(self, "_direct_producer_pending", False):
            self.domain_finality = False
            self._fail("attempted mutable-output access while a producer is owned")
            raise SessionError(self.failure)
        try:
            _remaining(cutoff)
            if _domain(self.platform, self.uid, deadline=cutoff):
                raise SessionError("reserved identity still has a process or zombie")
            _remaining(cutoff)
            self.domain_finality = True
        except BaseException:
            self.domain_finality = False
            self._fail("reserved-identity finality is unknown or false")
            raise
        self._headroom()
        _remaining(cutoff)

    def _cleanup(self, *, deadline: float | None = None) -> list[str]:
        errors = []
        if self.platform == "darwin":
            try:
                # Root observes only; kernel-authorized signalling stays in U.
                # One cutoff covers all censuses, batches, waits and sleeps.
                cutoff = min(self.deadline, time.monotonic() + 4)
                if deadline is not None:
                    _remaining(deadline)
                    cutoff = min(cutoff, deadline)
                kind = "TERM"
                while True:
                    targets = sorted(_domain("darwin", self.uid, deadline=cutoff))
                    if not targets:
                        break  # Actual root census, not a helper receipt.
                    if len(targets) > 4096:
                        raise SessionError("numerical cleanup batch exceeds fixed bound")
                    data = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry),
                                           "--enter", "darwin", str(self.uid), str(self.gid), "10",
                                           str(self.cleanup_policy), str(self.python), "-I", "-S", "-B",
                                           str(self.entry), "--cleanup-batch", str(self.uid), str(self.gid),
                                           kind, json.dumps(targets), repr(cutoff)],
                                          4, user=self.uid, group=self.gid, deadline=cutoff)
                    if data != b"MRK_CLEANUP_BATCH_ATTEMPTED\n":
                        raise SessionError("trusted numerical cleanup batch lacked its exact result")
                    time.sleep(min(0.1, _remaining(cutoff)))
                    kind = "KILL"
            except BaseException as exc:
                errors.append(f"numerical cleanup {type(exc).__name__}")
                if getattr(self, "_admitting", False):
                    self.admission_results.append({"name": "cleanup-exception", "ok": False,
                                                   "exceptions": _exception_notes(exc)})
        return errors

    def run(self, argv: list[str], *, cwd: str | Path, env: dict[str, str], seconds: float,
            output_limit: int = 8 * MiB, cpu_seconds: int = 180, profile: str = "ordinary",
            absolute_deadline: float | None = None) -> CapturedRun:
        self._guard()
        if not self.admitted:
            raise SessionError("native admission has not completed")
        if self.platform == "darwin" and self.process_observer is None:
            raise SessionError("macOS process observer admission is missing")
        if profile == "native-control":
            raise SessionError("private native admission roles are not public run profiles")
        try:
            return self._run(argv, cwd=cwd, env=env, seconds=seconds,
                             output_limit=output_limit, cpu_seconds=cpu_seconds, latch=True, profile=profile,
                             absolute_deadline=absolute_deadline)
        except BaseException:
            if type(profile) is str and profile in _NATIVE_PROFILES:
                self._fail("native authority invocation failed before a complete capture")
                state = self._native_authority.get(profile.removeprefix("native-authority-"))
                if state is not None:
                    state["prepared"] = False
                    self.cleanup_errors.extend(self._native_close_pins(state))
            raise

    def _run(self, argv: list[str], *, cwd: str | Path, env: dict[str, str], seconds: float,
             output_limit: int = 8 * MiB, cpu_seconds: int = 180, latch: bool,
             cancel_after: float | None = None, profile: str = "ordinary",
             absolute_deadline: float | None = None) -> CapturedRun:
        self._guard()
        bound = self.deadline
        if absolute_deadline is not None:
            if (type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline)
                    or not 0 < absolute_deadline <= self.deadline):
                raise SessionError("invalid tighter absolute command deadline")
            bound = absolute_deadline
            try:
                _remaining(bound)
            except DeadlineExpired:
                self._fail("original absolute command deadline expired before preparation")
                raise
        if self._busy or not isinstance(argv, list) or not argv or not Path(argv[0]).is_absolute():
            raise SessionError("invalid/reentrant fixed command")
        if any(not isinstance(a, str) or "\0" in a for a in argv):
            raise SessionError("invalid fixed command argument")
        cwd = _canonical(cwd)
        if not (_under(cwd, self.work) or _under(cwd, self.source)):
            raise SessionError("command cwd outside source/private work")
        if not 0 < seconds <= 3300 or not 0 < output_limit <= 16 * MiB or not 0 < cpu_seconds <= 300:
            raise SessionError("unbounded command resource request")
        if type(profile) is not str or profile not in {"ordinary", "python-full", "native-control", *_NATIVE_PROFILES}:
            raise SessionError("unknown fixed command profile")
        if profile == "python-full" and (self.platform != "linux" or not self.admitted or self._admitting
                or not latch or cancel_after is not None or cwd != self.work or seconds != 900
                or cpu_seconds != 300 or output_limit != 8 * MiB
                or argv != _python_full_command(self.root, self.deadline)):
            raise SessionError("fixed Python profile invocation differs from its one admitted gate")
        native_state = None
        if profile in _NATIVE_PROFILES or profile == "native-control":
            native_state = self._native_request(argv, cwd=cwd, env=env, seconds=seconds,
                output_limit=output_limit, cpu_seconds=cpu_seconds, latch=latch, cancel_after=cancel_after,
                profile=profile, absolute_deadline=absolute_deadline)
            child_env = self._native_environment(native_state)
        else:
            if (getattr(self, "_native_preparing", None) is not None
                    or any(not state["closed"] for state in getattr(self, "_native_authority", {}).values())):
                raise SessionError("ordinary launch cannot overlap an unresolved native authority phase")
            child_env = self._environment(env)
        command, kwargs = self._argv(argv, cpu_seconds, profile=profile)
        try:
            _remaining(bound)
            if absolute_deadline is None:
                self.ensure_idle()
            else:
                self.ensure_idle(deadline=bound)
        except DeadlineExpired:
            self._fail("original absolute command deadline expired during preparation")
            raise
        self._headroom()
        if native_state is not None:
            try:
                self._native_check_inputs(native_state)
            except BaseException:
                self._fail("native authority immutable inputs failed before capture")
                native_state["prepared"] = False
                self.cleanup_errors.extend(self._native_close_pins(native_state))
                raise
        if profile == "python-full":
            self._check_python_full_inputs()
            _python_full_memory(deadline=self.deadline)
        try:
            _remaining(bound)
        except DeadlineExpired:
            self._fail("original absolute command deadline expired before capture")
            raise
        if profile in _NATIVE_PROFILES:
            native_state["started"] = True  # A failed acquisition cannot authorize another attempt.
        abort = (self._native_control.get("abort") if profile == "native-control"
                 and self._native_control is not None else None)
        exit_reason = (self._native_control.get("exit_reason") if profile == "native-control"
                       and self._native_control is not None else None)
        initial_application = (profile == "native-control" and self._native_control is not None
                               and self._native_control.get("case") == "mach-authority")
        offline_baseline = (profile == "native-control" and self._native_control is not None
                            and self._native_control.get("case") == "aia-offline-baseline")
        if initial_application or offline_baseline:
            if self.cancelled:
                self._fail("controller cancellation")
            self._guard()  # Input checks cannot authorize a cancelled acquisition.
        self._busy = True
        self.domain_finality = False
        self._run_number += 1
        start, failure, errors = time.monotonic(), None, []
        cutoff = min(bound, start + seconds)
        outputs, fds, paths, eof, persisted = [bytearray(), bytearray()], [], [], [False, False], [0, 0]
        overflowed = [False, False]
        code = None
        waited = timed_out = cancelled = finality = False
        child = None
        sel = None
        stop_at = None
        terminate_sent = kill_sent = cleanup_done = False
        last_monitor = start

        def fail(message: str) -> None:
            nonlocal failure, stop_at
            if failure is None:
                failure, stop_at = message, time.monotonic()
                if latch:
                    self._fail(message)
            else:
                errors.append(message)

        try:
            sel = selectors.DefaultSelector()
            for suffix in ("stdout", "stderr"):
                p = self.control / f"run-{self._run_number:04d}.{suffix}"
                paths.append(p)
                fds.append(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
            if self.platform == "linux":
                self._assert_userns_boundary()
            _remaining(cutoff)  # Capture acquisition may not buy a later spawn.
            self._native_abort_stamp(abort, "wall_before")
            if abort is not None or exit_reason is not None or initial_application or offline_baseline:
                # Neither observations nor capture acquisition may authorize a
                # late/cancelled launch. Recheck the ORIGINAL subject cutoff.
                _remaining(cutoff)
                if self.cancelled or self.failure is not None:
                    cancelled = self.cancelled
                    fail(self.failure or "command cancellation")
                    raise SessionError("prelaunch observation found a stopped controller")
            child = subprocess.Popen(command, cwd=cwd, env=child_env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      close_fds=True, start_new_session=True, **kwargs)
            self._active = child
            if exit_reason is not None:
                exit_reason.update({"child": child, "pid": child.pid, "deadline": cutoff})
            self._native_abort_stamp(abort, "wall_after")
            if abort is not None:
                abort["pid"] = child.pid
            if self.platform == "darwin":
                # Keep both strong references and do not poll/wait first.  Even
                # an exited original retains its reserved PID/credentials here.
                _observe_original_credentials(child.pid, self.uid, self.gid, deadline=cutoff)
            for i, stream in enumerate((child.stdout, child.stderr)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, i)
            while True:
                now = time.monotonic()
                poll_original = True
                if exit_reason is not None and not exit_reason["retired"]:
                    if failure is not None:
                        self._native_exit_retire(exit_reason)
                    else:
                        try:
                            observed = self._native_exit_sample(exit_reason, child, cutoff=cutoff)
                            if observed == "live":
                                poll_original = False
                            elif observed == "terminal":
                                expected = exit_reason["expected"]
                                if expected != 0:
                                    fail(f"command exited {expected}")  # Before optional BASIC and before pipe EOF.
                                    self._native_exit_reason(exit_reason, child)
                                self._native_exit_retire(exit_reason)
                        except _NativeExitIdentity:
                            fail("native original-parent observation identity mismatch")
                            raise
                # A nonzero original wait is latched BEFORE waiting for pipe EOF.
                if poll_original:
                    self._native_exit_retire(exit_reason)
                    code = child.poll()
                else:
                    code = None  # Nonreaping live/transition observation supplies no wait result.
                if code is not None:
                    first_wait = not waited
                    waited = True
                    if code != 0 and failure is None:
                        fail(f"command exited {code}")
                    if self._native_exit_compare(exit_reason, code):
                        fail("native terminal status disagrees with original wait")
                    if first_wait:
                        self._native_abort_stamp(abort, "wall_wait")
                if exit_reason is not None:
                    now = time.monotonic()  # Optional metadata cannot conceal elapsed original command time.
                if now >= cutoff and failure is None:
                    timed_out = True
                    fail("command/original aggregate deadline expired")
                if (self.cancelled or (cancel_after is not None and now - start >= cancel_after)) and failure is None:
                    cancelled = True
                    fail("command cancellation")
                if failure is not None:
                    if now >= min(bound, stop_at + 8):
                        if not all(eof):
                            errors.append("stream EOF unavailable at bounded cleanup cutoff")
                        break
                    if code is None and not terminate_sent:
                        self._native_exit_retire(exit_reason)
                        child.terminate()
                        terminate_sent = True
                    if code is None and now - stop_at >= 1 and not kill_sent:
                        self._native_exit_retire(exit_reason)
                        child.kill()
                        kill_sent = True
                    if code is not None and not cleanup_done:
                        errors.extend(self._cleanup(deadline=min(bound, stop_at + 8)))
                        cleanup_done = True
                    if now - stop_at >= 8:
                        if not all(eof):
                            errors.append("stream EOF unavailable at bounded cleanup cutoff")
                        break
                if code is not None and all(eof):
                    break
                if now - last_monitor >= 0.5 and failure is None:
                    self._headroom()
                    if self.platform == "darwin" and any(
                        self.uid in uids and rss > 2 * 1024 * MiB
                        for uids, _gids, rss in _mac_snapshot(deadline=cutoff).values()
                    ):
                        fail("subject per-process RSS limit exceeded")
                    last_monitor = now
                poll_cutoff = cutoff if stop_at is None else min(bound, stop_at + 8)
                for key, _ in sel.select(max(0.0, min(0.05, poll_cutoff - time.monotonic()))):
                    i = key.data
                    try:
                        size = 65536 if overflowed[i] else min(65536, output_limit - len(outputs[i]) + 1)
                        data = os.read(key.fd, size)
                    except BlockingIOError:
                        continue
                    if not data:
                        eof[i] = True
                        sel.unregister(key.fileobj)
                        continue
                    if overflowed[i]:
                        continue  # Drain bounded failed output to genuine EOF, never persist more.
                    allowed = min(len(data), output_limit - len(outputs[i]), CAPTURE_TOTAL - self.persisted_bytes)
                    piece = data[:max(0, allowed)]
                    outputs[i].extend(piece)
                    view = memoryview(piece)
                    while view:
                        count = os.write(fds[i], view)
                        if count <= 0:
                            raise SessionError("capture write made no progress")
                        persisted[i] += count
                        self.persisted_bytes += count
                        view = view[count:]
                    if allowed != len(data):
                        fail("per-stream or whole-attempt persisted-output limit")
                        overflowed[i] = True
        except BaseException as exc:
            self._native_exit_retire(exit_reason)
            if isinstance(exc, DeadlineExpired):
                timed_out = True
            if isinstance(exc, KeyboardInterrupt):
                cancelled = True
            if getattr(self, "_admitting", False):
                self.admission_results.append({"name": "collector-exception", "ok": False,
                                               "exceptions": _exception_notes(exc)})
            fail(f"collection {type(exc).__name__}")
        finally:
            self._native_exit_retire(exit_reason)  # Before every finally poll, internally polling signal, or wait.
            # A successful command may not buy more metadata time at finality.
            # Failed-command cleanup uses its original stop timestamp, not a
            # fresh allowance; neither path extends the aggregate endpoint.
            final_cutoff = min(bound, stop_at + 8) if stop_at is not None else cutoff
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()  # Still-owned original Popen only.
                except BaseException as exc:
                    errors.append(f"original child stop {type(exc).__name__}")
                try:
                    code = child.wait(timeout=max(0.0, min(2, final_cutoff - time.monotonic())))
                    first_wait = not waited
                    waited = True
                    if self._native_exit_compare(exit_reason, code):
                        fail("native terminal status disagrees with original wait")
                    if first_wait:
                        self._native_abort_stamp(abort, "wall_wait")
                except BaseException as exc:
                    errors.append(f"original child wait {type(exc).__name__}")
                if failure is not None and not cleanup_done:
                    errors.extend(self._cleanup(deadline=final_cutoff))
                for stream in (child.stdout, child.stderr):
                    try:
                        stream.close()
                    except BaseException as exc:
                        errors.append(f"stream close {type(exc).__name__}")
            try:
                if sel is not None:
                    sel.close()
            except BaseException as exc:
                errors.append(f"selector close {type(exc).__name__}")
            for i, fd in enumerate(fds):
                try:
                    os.fsync(fd)
                except BaseException as exc:
                    errors.append(f"capture fsync {type(exc).__name__}")
                try:
                    actual = os.fstat(fd).st_size
                    # Diagnostic length is actual persisted state, not a forged
                    # successful-write count after an interrupted system call.
                    self.persisted_bytes += actual - persisted[i]
                    persisted[i] = actual
                    if actual != len(outputs[i]):
                        errors.append("capture persisted length differs from returned bytes")
                except BaseException as exc:
                    persisted[i] = None
                    errors.append(f"capture persist {type(exc).__name__}")
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(f"capture close {type(exc).__name__}")
            self._active = child if child is not None and not waited else None
            self._busy = False
            try:
                finality = waited and not _domain(self.platform, self.uid, deadline=final_cutoff)
                self.domain_finality = finality
                if not finality:
                    errors.append("reserved identity did not reach finality")
            except BaseException as exc:
                self.domain_finality = False
                errors.append(f"reserved identity census {type(exc).__name__}")
            if self.cancelled:
                cancelled = True
                fail("late controller cancellation")
            if time.monotonic() >= cutoff and failure is None:
                timed_out = True
                fail("finality exceeded original command cutoff")
            if not waited or not all(eof):
                fail("original wait or complete stream EOF missing")
            if errors and failure is None:
                fail("late capture/cleanup/finality error")
            if latch and failure is not None:
                self._fail(failure)
                self.cleanup_errors.extend(errors)
        result = CapturedRun(bytes(outputs[0]), bytes(outputs[1]), code, waited, *eof,
                             finality, timed_out, cancelled, time.monotonic() - start,
                             failure, tuple(errors), tuple(persisted))
        return self._native_finish_run(native_state, result) if profile in _NATIVE_PROFILES else result

    def admit(self) -> None:
        self._guard()
        if self.admitted or self._busy:
            raise SessionError("duplicate/reentrant native admission")
        self._admitting = True
        try:
            _readonly_tree(self.source)
            _readonly_tree(self.inputs)
            self._headroom()
            raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--nss", str(self.uid)],
                                 deadline=self.deadline)
            if raw != b"MRK_NSS_ABSENT\n" or _domain(self.platform, self.uid, collision=True, deadline=self.deadline):
                raise SessionError("numeric identity collision or incomplete admission")
            if self.platform == "linux":
                self._prepare_userns_boundary()
                self._prepare_provider_runtime()
            tools = {}
            tools_note = {"name": "fixed-entry-tools", "ok": False, "tools": tools}
            self.admission_results.append(tools_note)
            roles = [("python", self.python, {}),
                     ("sudo", Path("/usr/bin/sudo"), {"root_owned": True, "non_set_id": False}),
                     ("true", Path("/usr/bin/true"), {"root_owned": True})]
            roles += [(role, pair[0], {}) for role, pair in zip(_COMPATIBILITY_ROLES, self.compatibility_runtimes)]
            if self.platform == "darwin":
                # Only root's census executes this original system ps.  Record
                # actual image metadata without presuming why sandboxed exec failed.
                roles += [("sandbox-exec", Path("/usr/bin/sandbox-exec"), {"root_owned": True}),
                          ("ps", Path("/bin/ps"), {"root_owned": True, "non_set_id": False})]
            for role, path, options in roles:
                try:
                    tools[role] = _admit_executable(path, self.uid, self.gid, role=role, **options)
                except BaseException as exc:
                    tools_note["failed_role"] = role
                    # Admission's own rejection carries the same successful stat,
                    # never a replacement read or invented metadata on stat error.
                    observation = getattr(exc, "_ci_observation", None)
                    if isinstance(exc, SessionError) and isinstance(observation, dict) and set(observation) == {"tool"}:
                        tools[role] = observation["tool"]
                    raise
            tools_note["ok"] = True
            if self.platform == "linux" and self.compatibility_runtimes:
                self._native_process_toolchain_binding = _linux_native_process_toolchain(
                    self.uid, self.gid, deadline=self.deadline)
                self.admission_results.append({"name": "native-process-toolchain", "ok": True,
                                               **self._native_process_toolchain_binding["evidence"]})
            os.chown(self.work, self.uid, self.gid)
            for name in ("home", "tmp", "config", "cache"):
                p = self.work / name
                p.mkdir(mode=0o700)
                os.chown(p, self.uid, self.gid)
            if self.platform == "darwin":
                self._prepare_home_boundary()
            self._preflight()
            self.ensure_idle()
            if self.platform == "darwin":
                self._admit_process_observer()
                self.ensure_idle()
            self.admitted = True
        except BaseException as exc:
            # Preparation may already have passed its own native controls, but
            # the final outer admission boundary still owns publication.  Keep
            # those subcontrol facts and revoke this attempt's aggregate claim.
            self.admitted = False
            self.process_observer = None
            self._native_process_toolchain_binding = None
            for row in self.admission_results:
                if row["name"] in {"process-observer", "native-process-toolchain"}:
                    row["ok"] = False
            self.admission_results.append({"name": "native-admission-failure", "ok": False,
                                           "exceptions": _exception_notes(exc)})
            self._fail("native isolation admission failed; no product command permitted")
            raise
        finally:
            self._admitting = False

    def _check_userns_pin(self) -> None:
        state = self._userns_state
        if state is None or state["fd"] is None or state["original_node"] is None:
            raise SessionError("user-namespace boundary has no original descriptor identity")
        current = _userns_node(state["fd"], deadline=self.deadline)
        original = state["original_node"]
        if _home_node(current) != _home_node(original) or current.st_mode != original.st_mode:
            raise SessionError("user-namespace boundary original node changed")

    def _prepare_userns_boundary(self) -> None:
        """One fixed hosted-VM setting, owned before every numerical launch."""
        if (self.platform != "linux" or sys.platform != "linux" or os.geteuid() != 0
                or self._userns_state is not None):
            raise SessionError("invalid or repeated user-namespace boundary preparation")
        self.ensure_idle()
        note = {"name": "linux-userns-preparation", "ok": False, "change_attempted": False,
                "changed": False, "already_zero": False, "zero_observed": False, "owner_assertions": 0}
        state = {"fd": None, "original_node": None, "original": None, "change_attempted": False,
                 "prepared": False, "restore_attempted": False, "closed": False, "assertions": 0,
                 "note": note}
        self._userns_state = state
        self.admission_results.append(note)
        try:
            _remaining(self.deadline)
            state["fd"] = os.open(_USERNS_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            state["original_node"] = _userns_node(state["fd"], deadline=self.deadline)
            state["original"] = _userns_read(state["fd"], deadline=self.deadline)
            self._check_userns_pin()
            note["already_zero"] = state["original"] == 0
            if state["original"] != 0:
                # A failing/short write may already have an effect. Retain this
                # fact before the seek/write; never retry that uncertain effect.
                state["change_attempted"] = note["change_attempted"] = True
                _remaining(self.deadline)
                if os.lseek(state["fd"], 0, os.SEEK_SET) != 0:
                    raise SessionError("user-namespace preparation did not seek to its fixed start")
                _remaining(self.deadline)
                if os.write(state["fd"], b"0\n") != 2:
                    raise SessionError("user-namespace preparation write was incomplete")
                _remaining(self.deadline)
            self._check_userns_pin()
            if _userns_read(state["fd"], deadline=self.deadline) != 0:
                raise SessionError("user-namespace preparation did not observe actual zero")
            self._check_userns_pin()
            state["prepared"] = note["zero_observed"] = True
            note["changed"] = state["change_attempted"]
            note["ok"] = True
        except BaseException as exc:
            self._fail("owned Linux user-namespace preparation failed")
            note["exceptions"] = _exception_notes(exc)
            raise

    def _assert_userns_boundary(self) -> None:
        """Same original node/current zero immediately before each U launch."""
        state = self._userns_state
        try:
            if (self.platform != "linux" or sys.platform != "linux" or os.geteuid() != 0
                    or state is None or not state["prepared"] or state["closed"]
                    or getattr(self, "_direct_producer_pending", False)):
                raise SessionError("Linux launch lacks its prepared owned user-namespace boundary")
            self._check_userns_pin()
            if _userns_read(state["fd"], deadline=self.deadline) != 0:
                raise SessionError("owned Linux launch assertion did not observe zero")
            self._check_userns_pin()
            state["assertions"] += 1
            state["note"]["owner_assertions"] = state["assertions"]
        except BaseException as exc:
            self._fail("owned Linux user-namespace launch assertion failed")
            if state is not None:
                state["note"]["ok"] = False
                state["note"].setdefault("assertion_failure", _exception_notes(exc))
            raise

    def _close_userns_boundary(self) -> list[BaseException]:
        """Finality-gated one-shot original-value restore; release FD separately."""
        state = getattr(self, "_userns_state", None)
        if state is None or state["closed"]:
            return []
        state["closed"] = True
        errors = []
        note = {"name": "linux-userns-finalization", "ok": False, "restore_attempted": False,
                "restored": False, "unchanged_zero": False}
        self.admission_results.append(note)
        try:
            if state["fd"] is not None:
                _remaining(self.deadline)
                if (self._busy or self._active is not None or not self.domain_finality
                        or getattr(self, "_direct_producer_pending", False)
                        or _domain(self.platform, self.uid, deadline=self.deadline)):
                    raise SessionError("user-namespace restoration lacks genuine producer/domain finality")
                if type(state["original"]) is not int or not 0 <= state["original"] <= (1 << 64) - 1:
                    raise SessionError("user-namespace restoration lacks its exact original value")
                self._check_userns_pin()
                if _userns_read(state["fd"], deadline=self.deadline) != 0:
                    raise SessionError("user-namespace restoration vetoed by current-value drift")
                self._check_userns_pin()
                if state["change_attempted"]:
                    if state["restore_attempted"]:
                        raise SessionError("user-namespace restoration cannot retry an uncertain effect")
                    # prepared=True authorizes launches, not recovery. Even a
                    # failed preparation can have an owned verified-zero effect;
                    # finality and the original pin/value above govern restore.
                    state["restore_attempted"] = note["restore_attempted"] = True
                    _remaining(self.deadline)
                    if os.lseek(state["fd"], 0, os.SEEK_SET) != 0:
                        raise SessionError("user-namespace restoration did not seek to its fixed start")
                    _remaining(self.deadline)
                    raw = str(state["original"]).encode("ascii") + b"\n"
                    if os.write(state["fd"], raw) != len(raw):
                        raise SessionError("user-namespace restoration write was incomplete")
                    _remaining(self.deadline)
                    self._check_userns_pin()
                    if _userns_read(state["fd"], deadline=self.deadline) != state["original"]:
                        raise SessionError("user-namespace restoration readback differs from its original value")
                    self._check_userns_pin()
                    note["restored"] = True
                elif state["original"] == 0:
                    note["unchanged_zero"] = True
                else:
                    raise SessionError("user-namespace restoration has no prior mutation custody")
            elif state["change_attempted"]:
                raise SessionError("user-namespace restoration lost its owned descriptor")
        except BaseException as exc:
            errors.append(exc)
        # Descriptor custody ends exactly once, even on deadline, unknown
        # finality, identity drift or a restoration error after an effect.
        fd, state["fd"] = state["fd"], None
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as exc:
                errors.append(exc)
        try:
            _remaining(self.deadline)
        except BaseException as exc:
            errors.append(exc)
        note["ok"] = not errors
        if errors:
            note["exceptions"] = _exception_notes(BaseExceptionGroup("Linux user-namespace finalization failed", errors))
        return errors

    def _prepare_provider_runtime(self) -> None:
        """Root-only selected Linux provider preparation; no child module import."""
        if self.platform != "linux" or sys.platform != "linux" or os.geteuid() != 0:
            raise SessionError("provider preparation requires the native root owner")
        self.ensure_idle()
        _remaining(self.deadline)
        prefixes = _runtime_prefix_roles(self.platform, self.python, _canonical(sys.base_prefix), self.ruby,
                                        self.tool_prefixes, self.compatibility_runtimes)
        # Only this root admission method loads the immutable provider-only
        # source. The one-file copied bootstrap and every child role stay intact.
        report = {"name": "provider-runtime-permissions", "ok": False}
        self.admission_results.append(report)
        try:
            import importlib.util
            name = "_mrk_ci_provider_runtime"
            if name in sys.modules:
                raise SessionError("provider preparation module already has an owner")
            spec = importlib.util.spec_from_file_location(name, self.source / ".github/scripts/ci_provider_runtime.py")
            if spec is None or spec.loader is None:
                raise SessionError("immutable provider preparation module unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            _remaining(self.deadline)
            module.protect_selected_runtimes(prefixes, uid=self.uid, gid=self.gid,
                                            deadline=self.deadline, report=report)
            _remaining(self.deadline)
            if report.get("ok") is not True:
                raise SessionError("selected provider preparation did not complete")
        except BaseException:
            report["ok"] = False  # Preserve module counts, revoke any late aggregate claim.
            raise

    def _check_home_pin(self, mode: int) -> None:
        state = self._home_state
        _remaining(self.deadline)
        pinned = os.fstat(state["pin"])
        _remaining(self.deadline)
        named = self.runner_home.lstat()
        if (state["original"] is None or _home_node(pinned) != _home_node(state["original"])
                or _home_node(named) != _home_node(pinned)
                or stat.S_IMODE(pinned.st_mode) != mode or stat.S_IMODE(named.st_mode) != mode):
            raise SessionError("owned HOME pin/path identity or mode drifted")
        _remaining(self.deadline)

    def _check_ruby_sibling_pin(self, home_mode: int) -> None:
        """Separate parent-FD custody, even when the sibling's parent is HOME."""
        state = self._home_state
        parent = self.ruby_ancestors[-1]
        _remaining(self.deadline)
        _canonical(parent)
        _remaining(self.deadline)
        pinned = os.fstat(state["sibling_pin"])
        _remaining(self.deadline)
        named = parent.lstat()
        mode = home_mode if parent == self.runner_home else state["sibling_parent_mode"]
        if (state["sibling_parent_original"] is None
                or _home_node(pinned) != _home_node(state["sibling_parent_original"])
                or _home_node(named) != _home_node(pinned)
                or stat.S_IMODE(pinned.st_mode) != mode or stat.S_IMODE(named.st_mode) != mode):
            raise SessionError("owned Ruby sibling parent pin/path identity or mode drifted")
        _remaining(self.deadline)

    def _prepare_home_boundary(self) -> None:
        """One disposable-VM HOME search bit; retain all custody before effects."""
        if (self.platform != "darwin" or sys.platform != "darwin" or os.geteuid() != 0
                or self._home_state is not None):
            raise SessionError("invalid or repeated HOME preparation")
        if not _under(self.ruby, self.runner_home):
            raise SessionError("reviewed HOME preparation requires selected Ruby beneath HOME")
        self.ensure_idle()
        self._check_ruby_ancestors()
        canary, endpoint = _home_paths(self.runner_home, self.root)
        sibling = _ruby_sibling_path(self.runner_home, self.ruby_prefix, self.root)
        if any(_under(p, prefix) for p in (canary, endpoint, sibling) for prefix in self.tool_prefixes):
            raise SessionError("synthetic HOME controls overlap a runtime exclusion")
        state = {"pin": None, "original": None, "change_attempted": False, "prepared": False,
                 "expected_mode": None, "canary_fd": None, "canary_name": canary.name,
                 "canary_create_attempted": False, "canary_identity": None, "canary_mode": 0o600,
                 "listener": None, "socket_name": endpoint.name, "socket_bind_attempted": False,
                 "socket_identity": None, "socket_mode": None, "sibling_pin": None,
                 "sibling_parent_original": None, "sibling_parent_mode": None,
                 "sibling_fd": None, "sibling_name": sibling.name, "sibling_create_attempted": False,
                 "sibling_identity": None, "sibling_mode": 0o600, "closed": False}
        self._home_state = state
        note = {"name": "home-search-preparation", "ok": False, "change_attempted": False,
                "change_verified": False}
        self.admission_results.append(note)
        _remaining(self.deadline)
        before = self.runner_home.lstat()
        _remaining(self.deadline)
        state["pin"] = os.open(self.runner_home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _remaining(self.deadline)
        original = os.fstat(state["pin"])
        state["original"] = original
        _remaining(self.deadline)
        mode = stat.S_IMODE(original.st_mode)
        if (not stat.S_ISDIR(original.st_mode) or original.st_uid == self.uid or original.st_gid == self.gid
                or mode not in {0o750, 0o751, 0o755} or _home_node(before) != _home_node(original)
                or stat.S_IMODE(before.st_mode) != mode):
            raise SessionError("configured HOME does not match the reviewed pinned directory state")
        note["original_mode"] = format(mode, "04o")
        state["expected_mode"] = 0o751 if mode == 0o750 else mode
        self._check_home_pin(mode)
        if mode == 0o750:
            state["change_attempted"] = note["change_attempted"] = True
            os.fchmod(state["pin"], 0o751)
        self._check_home_pin(state["expected_mode"])
        state["prepared"] = True
        note["change_verified"] = state["change_attempted"]
        note["prepared_mode"] = format(state["expected_mode"], "04o")

        # An independent descriptor owns this parent. Never alias HOME's FD or
        # change an ancestor mode to make the new synthetic control usable.
        self._check_ruby_ancestors(home_mode=state["expected_mode"])
        parent = self.ruby_ancestors[-1]
        _remaining(self.deadline)
        before = parent.lstat()
        _remaining(self.deadline)
        state["sibling_pin"] = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _remaining(self.deadline)
        pinned = os.fstat(state["sibling_pin"])
        state["sibling_parent_original"] = pinned
        state["sibling_parent_mode"] = stat.S_IMODE(pinned.st_mode)
        _remaining(self.deadline)
        expected_parent = self._ruby_ancestor_states[-1]
        expected_mode = state["expected_mode"] if parent == self.runner_home else stat.S_IMODE(expected_parent.st_mode)
        if (not stat.S_ISDIR(pinned.st_mode) or _home_node(pinned) != _home_node(expected_parent)
                or _home_node(before) != _home_node(pinned) or stat.S_IMODE(before.st_mode) != expected_mode
                or state["sibling_parent_mode"] != expected_mode):
            raise SessionError("synthetic Ruby sibling parent lost its admitted identity/mode")
        self._check_ruby_sibling_pin(state["expected_mode"])

        _remaining(self.deadline)
        state["canary_create_attempted"] = True
        state["canary_fd"] = os.open(canary.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=state["pin"])
        _remaining(self.deadline)
        created = os.fstat(state["canary_fd"])
        _remaining(self.deadline)
        # Darwin may inherit HOME's ordinary group; preserve it, never adopt U.
        if (not stat.S_ISREG(created.st_mode) or created.st_uid != 0 or created.st_gid == self.gid
                or created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != 0o600 or created.st_size):
            raise SessionError("new synthetic HOME file lacks exclusive creation identity")
        state["canary_identity"] = created
        if os.write(state["canary_fd"], _HOME_READ_BYTES) != len(_HOME_READ_BYTES):
            raise SessionError("synthetic HOME file write was incomplete")
        _remaining(self.deadline)
        os.fsync(state["canary_fd"])
        _remaining(self.deadline)
        state["canary_mode"] = None
        os.fchmod(state["canary_fd"], 0o444)
        _remaining(self.deadline)
        current = os.fstat(state["canary_fd"])
        _remaining(self.deadline)
        if (_home_node(current) != _home_node(created) or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o444 or current.st_size != len(_HOME_READ_BYTES)):
            raise SessionError("synthetic HOME file persistence/mode is not verified")
        state["canary_mode"] = 0o444
        self._check_home_pin(state["expected_mode"])

        self._check_ruby_sibling_pin(state["expected_mode"])
        _remaining(self.deadline)
        state["sibling_create_attempted"] = True
        state["sibling_fd"] = os.open(sibling.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=state["sibling_pin"])
        _remaining(self.deadline)
        created = os.fstat(state["sibling_fd"])
        _remaining(self.deadline)
        if (not stat.S_ISREG(created.st_mode) or created.st_uid != 0 or created.st_gid == self.gid
                or created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != 0o600 or created.st_size):
            raise SessionError("new synthetic Ruby sibling lacks exclusive creation identity")
        state["sibling_identity"] = created
        if os.write(state["sibling_fd"], _ANCESTOR_READ_BYTES) != len(_ANCESTOR_READ_BYTES):
            raise SessionError("synthetic Ruby sibling write was incomplete")
        _remaining(self.deadline)
        os.fsync(state["sibling_fd"])
        _remaining(self.deadline)
        state["sibling_mode"] = None
        os.fchmod(state["sibling_fd"], 0o444)
        _remaining(self.deadline)
        current = os.fstat(state["sibling_fd"])
        _remaining(self.deadline)
        if (_home_node(current) != _home_node(created) or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o444 or current.st_size != len(_ANCESTOR_READ_BYTES)):
            raise SessionError("synthetic Ruby sibling persistence/mode is not verified")
        state["sibling_mode"] = 0o444
        self._check_ruby_sibling_pin(state["expected_mode"])

        state["listener"] = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        state["listener"].settimeout(min(2, _remaining(self.deadline)))
        _remaining(self.deadline)
        state["socket_bind_attempted"] = True
        state["listener"].bind(str(endpoint))  # No unlink, adoption or conflict retry.
        _remaining(self.deadline)
        node = os.stat(endpoint.name, dir_fd=state["pin"], follow_symlinks=False)
        _remaining(self.deadline)
        if not stat.S_ISSOCK(node.st_mode) or node.st_uid != 0 or node.st_gid == self.gid or node.st_nlink != 1:
            raise SessionError("new synthetic HOME listener lacks its own node identity")
        state["socket_identity"] = node
        state["socket_mode"] = stat.S_IMODE(node.st_mode)
        self._check_home_pin(state["expected_mode"])
        state["socket_mode"] = None
        os.chmod(endpoint, 0o666, follow_symlinks=False)  # Only this created synthetic socket, never HOME.
        _remaining(self.deadline)
        after = os.stat(endpoint.name, dir_fd=state["pin"], follow_symlinks=False)
        _remaining(self.deadline)
        if _home_node(after) != _home_node(node) or after.st_nlink != 1 or stat.S_IMODE(after.st_mode) != 0o666:
            raise SessionError("synthetic HOME listener node changed")
        state["socket_mode"] = 0o666
        state["listener"].listen(8)
        _remaining(self.deadline)
        _private_file(self.bootstrap / "home-control.json", json.dumps({"home": str(self.runner_home),
                      "ruby_prefix": str(self.ruby_prefix),
                      "uid": self.uid, "gid": self.gid, "deadline": self.deadline}).encode(), 0o444)
        _remaining(self.deadline)
        note["ok"] = True  # Preparation only; genuine mandatory controls still follow.

    def _home_positive_control(self) -> None:
        """Trusted fixed U code outside policy proves DAC is not the negative."""
        state = self._home_state
        if (state is None or not state["prepared"] or state["listener"] is None
                or state["sibling_identity"] is None or state["sibling_mode"] != 0o444):
            raise SessionError("owned HOME controls are not prepared")
        self.ensure_idle()
        self._check_ruby_ancestors(home_mode=state["expected_mode"])
        self._check_home_pin(state["expected_mode"])
        self._check_ruby_sibling_pin(state["expected_mode"])
        self.domain_finality = False
        self._direct_producer_pending = True
        raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--home-positive"],
                             10, user=self.uid, group=self.gid, deadline=self.deadline)
        self._direct_producer_pending = False
        if raw != b"MRK_HOME_POSITIVE_OK\n":
            raise SessionError("fixed HOME DAC positive did not complete")
        self.ensure_idle()
        accepted, errors, data = None, [], bytearray()
        try:
            state["listener"].settimeout(min(2, _remaining(self.deadline)))
            accepted, _ = state["listener"].accept()
            while True:
                accepted.settimeout(min(2, _remaining(self.deadline)))
                chunk = accepted.recv(len(_HOME_SOCKET_BYTES) + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > len(_HOME_SOCKET_BYTES):
                    raise SessionError("synthetic HOME positive delivery exceeds literal bound")
            if bytes(data) != _HOME_SOCKET_BYTES:
                raise SessionError("synthetic HOME positive delivery was not observed")
        except BaseException as exc:
            errors.append(exc)
        if accepted is not None:
            try:
                accepted.close()
            except BaseException as exc:
                errors.append(exc)
        try:
            _remaining(self.deadline)
        except BaseException as exc:
            errors.append(exc)
        if errors:
            raise BaseExceptionGroup("fixed HOME positive/accepted-connection close failed", errors)
        self.admission_results.append({"name": "home-DAC-and-delivery-positive", "ok": True})

    def _close_home_boundary(self) -> list[BaseException]:
        """Finality-gated exact restore/removal; close every owned handle once."""
        state = getattr(self, "_home_state", None)
        if state is None or state["closed"]:
            return []
        state["closed"] = True
        errors = []
        note = {"name": "home-boundary-finalization", "ok": False, "restored": False,
                "canary_removed": False, "socket_removed": False, "sibling_removed": False,
                "unverified_creation": []}
        self.admission_results.append(note)
        for kind, attempt_key, identity_key in (
                ("canary", "canary_create_attempted", "canary_identity"),
                ("socket", "socket_bind_attempted", "socket_identity"),
                ("sibling", "sibling_create_attempted", "sibling_identity")):
            if state[attempt_key] and state[identity_key] is None:
                note["unverified_creation"].append(kind)
                errors.append(SessionError("synthetic HOME creation after-effect lacks owned identity"))
        eligible = False
        try:
            _remaining(self.deadline)
            if (self._busy or self._active is not None or not self.domain_finality
                    or getattr(self, "_direct_producer_pending", False)
                    or _domain(self.platform, self.uid, deadline=self.deadline)):
                raise SessionError("HOME restoration has no genuine producer/domain finality")
            if not state["prepared"]:
                raise SessionError("HOME preparation after-effect is not verified")
            self._check_home_pin(state["expected_mode"])
            eligible = True
        except BaseException as exc:
            errors.append(exc)
        if eligible:
            final_mode = state["expected_mode"]
            try:
                if state["change_attempted"]:
                    _remaining(self.deadline)
                    os.fchmod(state["pin"], stat.S_IMODE(state["original"].st_mode))
                    self._check_home_pin(stat.S_IMODE(state["original"].st_mode))
                    final_mode = stat.S_IMODE(state["original"].st_mode)
                    note["restored"] = True
            except BaseException as exc:
                eligible = False  # Uncertain restoration cannot authorize another path mutation.
                errors.append(exc)
        if eligible:
            for kind, identity_key, mode_key, name_key in (
                    ("canary", "canary_identity", "canary_mode", "canary_name"),
                    ("socket", "socket_identity", "socket_mode", "socket_name")):
                if state[identity_key] is None:
                    continue
                try:
                    self._check_home_pin(final_mode)
                    current = os.stat(state[name_key], dir_fd=state["pin"], follow_symlinks=False)
                    _remaining(self.deadline)
                    if (_home_node(current) != _home_node(state[identity_key]) or current.st_nlink != 1
                            or state[mode_key] is None or stat.S_IMODE(current.st_mode) != state[mode_key]):
                        raise SessionError("synthetic HOME node replacement/mode forbids removal")
                    os.unlink(state[name_key], dir_fd=state["pin"])
                    note[kind + "_removed"] = True
                    _remaining(self.deadline)
                except BaseException as exc:
                    errors.append(exc)
            if state["sibling_identity"] is not None:
                try:
                    self._check_home_pin(final_mode)
                    self._check_ruby_sibling_pin(final_mode)
                    current = os.stat(state["sibling_name"], dir_fd=state["sibling_pin"], follow_symlinks=False)
                    _remaining(self.deadline)
                    if (_home_node(current) != _home_node(state["sibling_identity"]) or current.st_nlink != 1
                            or state["sibling_mode"] is None or stat.S_IMODE(current.st_mode) != state["sibling_mode"]):
                        raise SessionError("synthetic Ruby sibling replacement/mode forbids removal")
                    os.unlink(state["sibling_name"], dir_fd=state["sibling_pin"])
                    note["sibling_removed"] = True
                    _remaining(self.deadline)
                except BaseException as exc:
                    errors.append(exc)
        # Local resource closure is always safe, even when no path mutation is.
        for key in ("listener", "sibling_fd", "canary_fd", "sibling_pin", "pin"):
            owned, state[key] = state[key], None
            if owned is None:
                continue
            try:
                owned.close() if key == "listener" else os.close(owned)
            except BaseException as exc:
                errors.append(exc)
        try:
            _remaining(self.deadline)
        except BaseException as exc:
            errors.append(exc)
        note["ok"] = not errors
        if errors:
            note["exceptions"] = _exception_notes(BaseExceptionGroup("HOME owned finalization failed", errors))
        return errors

    def _admit_process_observer(self) -> None:
        """Prepare as U only after base native controls; publish last, once."""
        if self.platform != "darwin" or self.process_observer is not None:
            raise SessionError("duplicate/unsupported process observer preparation")
        self.ensure_idle()
        tools = _observer_toolchain(self.uid, self.gid, deadline=self.deadline)
        arch = os.uname().machine
        if arch not in {"arm64", "x86_64"}:
            raise SessionError("unsupported native observer architecture")
        source = self.source / ".github/scripts/ci_process_observer.c"
        source_bytes = source.read_bytes()
        if not 0 < len(source_bytes) <= 65536:
            raise SessionError("immutable observer C source exceeds fixed bound")
        output, frozen = self.work / "process-observer", self.bootstrap / "process-observer"
        for path in (output, frozen):
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise SessionError("observer output would overwrite an existing name")

        def checked_run(name: str, argv: list[str], seconds: int = 15) -> tuple[CapturedRun, dict]:
            result = self._run(argv, cwd=self.work,
                               env={"DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer"},
                               seconds=seconds, cpu_seconds=60, output_limit=65536, latch=False)
            note = self._note_capture(name, result)
            if name == "process-observer-build":
                note["compiler_diagnostics"] = _observer_build_notes(result.stderr, source)
            if not result.ok:
                raise SessionError("observer preparation command lacks genuine successful finality")
            self.ensure_idle()
            _remaining(self.deadline)
            return result, note  # Semantic acceptance belongs to the caller below.

        version, version_note = checked_run("process-observer-compiler", [str(tools["clang"]), "--no-default-config", "--version"])
        version_lines = version.stdout.decode("ascii", "strict").splitlines()
        if (version.stderr or not 1 <= len(version_lines) <= 8
                or not re.fullmatch(r"Apple clang version [A-Za-z0-9 ._()+-]{1,160}", version_lines[0])
                or any(len(line) > 1024 or any(ord(c) < 32 for c in line) for line in version_lines)):
            raise SessionError("selected compiler version evidence is unsupported")
        version_note["ok"] = True
        command = [str(tools["clang"]), "--no-default-config", "-fno-modules", "-std=c11",
                   "-D_DARWIN_C_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror", "-arch", arch,
                   "-isysroot", str(tools["sdk"]), "-B", str(tools["toolchain"] / "usr/bin"),
                   "-Wl,-adhoc_codesign", str(source), "-lproc", "-o", str(output)]
        compiled, build_note = checked_run("process-observer-build", command, 120)
        if compiled.stdout or compiled.stderr:
            raise SessionError("fixed observer compiler emitted unexpected diagnostics")
        # No produced file is opened before the compiler's actual finality.
        binary, producer_mode = _observer_artifact(output, self.uid, self.gid, deadline=self.deadline)
        build_note["ok"] = True
        verified, validity_note = checked_run("process-observer-signature-validity", ["/usr/bin/codesign", "--verify", "--strict", str(output)])
        if verified.stdout or verified.stderr:
            raise SessionError("observer signature verification emitted diagnostics")
        validity_note["ok"] = True
        display, display_note = checked_run("process-observer-signature-display", ["/usr/bin/codesign", "--display", "--verbose=2", str(output)])
        signing = _observer_signature_metadata(display.stdout, display.stderr, output, arch)
        display_note["ok"] = True
        entitlements, entitlement_note = checked_run("process-observer-entitlements", ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(output)])
        if entitlements.stdout or entitlements.stderr not in (b"", f"Executable={output}\n".encode()):
            raise SessionError("observer has entitlements or unsupported extraction diagnostics")
        entitlement_note["ok"] = True
        # The documented empty display means none only after actual successful
        # strict validation/display, own waits, both EOFs and outside finality.
        self.ensure_idle()
        if _observer_artifact(output, self.uid, self.gid, deadline=self.deadline) != (binary, producer_mode):
            raise SessionError("observer bytes/mode changed across read-only signature validation")
        _remaining(self.deadline)
        _readonly_tree(self.bootstrap)
        _private_file(frozen, binary, 0o555)
        os.chown(frozen, 0, 0)
        frozen_bytes, frozen_mode = _observer_artifact(frozen, 0, 0, deadline=self.deadline)
        if frozen_bytes != binary or frozen_mode != 0o555:
            raise SessionError("observer immutable bootstrap copy differs")
        _readonly_tree(self.bootstrap)
        self._observer_native_controls(frozen)
        self.ensure_idle()
        _remaining(self.deadline)
        self.process_observer = frozen  # No caller-selected or pre-admission path.
        self._native_process_toolchain_binding = {**tools, "evidence": dict(tools["evidence"])}
        self.admission_results.append({"name": "process-observer", "ok": True,
                                       "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                                       "binary_sha256": hashlib.sha256(binary).hexdigest(),
                                       "compiler_version": version_lines[0], "tools": tools["evidence"],
                                       "producer_mode": format(producer_mode, "04o"), "mode": "0555",
                                       **signing, "entitlements": "none"})

    def _observer_native_controls(self, candidate: Path) -> None:
        """Root owns only its fixed foreign sentinel; it never runs the reader."""
        if candidate != self.bootstrap / "process-observer":
            raise SessionError("native observer candidate is not the fixed bootstrap file")
        cutoff = min(self.deadline, time.monotonic() + 30)
        sentinel, errors = None, []
        try:
            _remaining(cutoff)
            sentinel = subprocess.Popen([str(self.python), "-I", "-S", "-B", str(self.entry), "--sentinel"],
                                        cwd=self.work, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        close_fds=True, start_new_session=True, bufsize=0)
            if _ready_line(sentinel.stdout, min(5, _remaining(cutoff))) != b"MRK_SENTINEL_READY\n":
                raise SessionError("owned foreign observer control did not become ready")
            _observe_original_credentials(sentinel.pid, 0, os.getgid(), deadline=cutoff)
            probe_cutoff = min(cutoff, time.monotonic() + 20)
            result = self._run([str(self.python), "-I", "-S", "-B", str(self.entry),
                                "--observer-probe", str(candidate), str(sentinel.pid), repr(probe_cutoff)],
                               cwd=self.work, env={}, seconds=_remaining(probe_cutoff), latch=False)
            note = self._note_capture("process-observer-native", result)
            if not result.ok or result.stdout != b"MRK_PROCESS_OBSERVER_OK\n" or result.stderr:
                raise SessionError("native process observer controls failed")
            self.ensure_idle()
            out, err = sentinel.communicate(b"q", timeout=min(2, _remaining(cutoff)))
            if sentinel.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
                raise SessionError("owned foreign observer control did not close genuinely")
            _remaining(cutoff)
        except BaseException as exc:
            errors.append(exc)
        if sentinel is not None:
            try:
                if sentinel.poll() is None:
                    sentinel.kill()  # This original root handle only, never a census PID.
            except BaseException as exc:
                errors.append(exc)
            try:
                if type(sentinel.wait(timeout=max(0.0, min(2, cutoff - time.monotonic())))) is not int:
                    raise SessionError("owned foreign observer control has no original cleanup wait")
            except BaseException as exc:
                errors.append(exc)
            for stream in (sentinel.stdin, sentinel.stdout, sentinel.stderr):
                try:
                    stream.close()
                except BaseException as exc:
                    errors.append(exc)
        try:
            self.ensure_idle()
            _remaining(cutoff)
        except BaseException as exc:
            errors.append(exc)
        if errors:
            raise BaseExceptionGroup("observer native controls/owned foreign cleanup failed", errors)
        note["ok"] = True  # Includes every original wait/EOF/close and final cutoff.

    def _note_capture(self, name: str, result: CapturedRun, *, parse_child_notes: bool = True) -> dict:
        # Raw nested Mach stderr belongs only to its strict native parser, not
        # to the generic child-note format. Actual capture/error facts stay intact.
        row = {"name": name, "ok": False, "subject_ok": result.ok,
               "returncode": result.returncode, "waited": result.waited,
               "stdout_eof": result.stdout_eof, "stderr_eof": result.stderr_eof,
               "domain_finality": result.domain_finality, "timed_out": result.timed_out,
               "cancelled": result.cancelled, "persisted": list(result.persisted),
               "error_count": len(result.cleanup_errors) + (result.primary_error is not None),
               "exceptions": _child_exception_notes(result.stderr) if parse_child_notes else []}
        launcher_error = _launcher_error(result.stderr, self.python, self.entry)
        if launcher_error is not None:
            row["launcher_error"] = launcher_error
        if self.platform == "darwin" and name == "ruby-numerical-identity":
            ruby_error = _ruby_launch_error(result, self.ruby)
            if ruby_error is not None:
                row["launcher_error"] = ruby_error
            startup_error = _ruby_startup_error(result, self.ruby)
            if startup_error is not None:
                row["ruby_startup_error"] = startup_error
        self.admission_results.append(row)
        return row

    def _ruby_path_metadata(self) -> None:
        """Observe the already-canonical provider path; grant no access or launch."""
        row = {"name": "ruby-path-metadata", "ok": False,
               "semantics": "posix-mode-bits-only", "entries": []}
        self.admission_results.append(row)
        _remaining(self.deadline)
        parents = tuple(self.ruby.parents)
        if len(parents) > 32:
            raise SessionError("fixed Ruby ancestor metadata exceeds bound")
        for index, path in enumerate((self.ruby, *parents)):
            row["unobserved_index"] = index
            _remaining(self.deadline)
            info = path.stat()
            row["entries"].append({"index": index, **_tool_stat_note(info, self.uid, self.gid, role="ruby")})
            del row["unobserved_index"]
            _remaining(self.deadline)
        row["ok"] = True

    def _preflight(self) -> None:
        self.ensure_idle()
        listeners, addresses = [], []
        failures = []
        try:
            if self.platform == "darwin":
                self._home_positive_control()
            # This grant is AFTER complete numerical collision admission.  It
            # is a single synthetic UID-owned0600 file, not a group capability.
            os.chown(self.outside_write, self.uid, self.gid)
            positive = self._trusted_entry(self.write_policy, ["--write-control", str(self.outside_write)])
            if self.platform == "linux":
                self._assert_userns_boundary()
            self.domain_finality = False
            self._direct_producer_pending = True
            out = _small_command(positive, 10, user=self.uid, group=self.gid, deadline=self.deadline)
            self._direct_producer_pending = False  # Only a genuine normal collector return releases custody.
            if out != b"MRK_OUTSIDE_WRITE_POSITIVE\n":
                raise SessionError("outside-policy numerical write positive failed")
            self.ensure_idle()
            if self.outside_write.read_bytes() != b"MRK_POSITIVE_WRITE\n":
                raise SessionError("outside-policy positive did not actually persist its write")
            self.admission_results.append({"name": "outside-work-write-positive", "ok": True})
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    listener = socket.socket(family, kind)
                    listeners.append(listener)
                    listener.settimeout(1)
                    listener.bind((host, 0))
                    address = listener.getsockname()
                    if kind == socket.SOCK_STREAM:
                        listener.listen(8)
                    # Outside-domain positive: these exact owned endpoints work.
                    with socket.socket(family, kind) as positive:
                        positive.settimeout(1)
                        if kind == socket.SOCK_STREAM:
                            positive.connect(address)
                            accepted, _ = listener.accept()
                            accepted.close()
                        else:
                            positive.sendto(b"owned-control", address)
                            if listener.recv(64) != b"owned-control":
                                raise SessionError("outside-domain UDP control failed")
                    addresses.append((int(family), int(kind), host, address[1]))
            data = {"uid": self.uid, "gid": self.gid, "platform": self.platform,
                    "work": str(self.work), "source": str(self.source),
                    "readonly": str(self.bootstrap / "readonly"), "control": str(self.control / "denied"),
                    "outside_write": str(self.outside_write),
                    "runner_home": str(self.runner_home), "runner_temp": str(self.runner_temp),
                    "endpoints": addresses}
            if self.platform == "linux":
                data["host_net"] = os.readlink("/proc/self/ns/net")
                data["host_pid"] = os.readlink("/proc/self/ns/pid")
                data["runtime_executables"] = [str(self.python), str(self.ruby)]
            else:
                canary, endpoint = _home_paths(self.runner_home, self.root)
                data["home_canary"], data["home_socket"] = str(canary), str(endpoint)
                data["ruby_prefix"], data["ruby_executable"] = str(self.ruby_prefix), str(self.ruby)
                data["home_sibling"] = str(_ruby_sibling_path(self.runner_home, self.ruby_prefix, self.root))
            base = [str(self.python), "-I", "-S", "-B", str(self.entry)]
            good = self._run([*base, "--probe", json.dumps(data)], cwd=self.work, env={}, seconds=30, latch=False)
            native_note = self._note_capture("native-isolation", good)
            if not good.ok or good.stdout != b"MRK_NATIVE_ISOLATION_OK\n":
                raise SessionError("native credentials/files/FD/network inheritance preflight failed")
            self.ensure_idle()
            _outside_network_empty(listeners, deadline=self.deadline)
            if self.platform == "darwin":
                _home_socket_empty(self._home_state["listener"], deadline=self.deadline)
            # Revoke this synthetic positive grant before any product command.
            # Failed/unknown writers never reach this filesystem postcondition.
            os.chown(self.outside_write, 0, 0)
            self.outside_write.chmod(0o400)
            native_note["ok"] = True
            self._ruby_path_metadata()  # Observation only; the actual probe still decides.
            ruby = self._run([str(self.ruby), "-e", f"abort unless Process.uid == {self.uid} && Process.gid == {self.gid}; puts 'MRK_RUBY_NUMERIC_OK'"],
                             cwd=self.work, env={}, seconds=10, latch=False)
            ruby_note = self._note_capture("ruby-numerical-identity", ruby)
            if not ruby.ok or ruby.stdout != b"MRK_RUBY_NUMERIC_OK\n":
                raise SessionError("Ruby is incompatible with the admitted numerical identity")
            ruby_note["ok"] = True
            if self.platform == "darwin":
                self._signal_preflight()
            cases = (("positive", 0, False), ("nonzero", 7, False),
                     ("missing-footer", 0, False), ("streams", 0, False),
                     ("over-limit", None, False), ("timeout", None, True),
                     ("cancel", None, False), ("held-pipe", None, False))
            for name, expected, timeout in cases:
                result = self._run([*base, "--fixture", name], cwd=self.work, env={},
                                   seconds=0.4 if name in {"timeout", "held-pipe"} else 10,
                                   output_limit=1024, latch=False,
                                   cancel_after=0.15 if name == "cancel" else None)
                capture_note = self._note_capture(name, result)
                basic = result.waited and result.domain_finality and not result.cleanup_errors
                if expected is not None:
                    basic = basic and result.returncode == expected and result.stdout_eof and result.stderr_eof
                if name == "positive":
                    basic = basic and result.ok and result.stdout == b"PASS\n"
                elif name == "nonzero":
                    basic = basic and not result.ok and result.stdout == b"PASS\n"
                elif name == "missing-footer":
                    basic = basic and result.ok and result.stdout != b"PASS\n"
                elif name == "streams":
                    basic = basic and result.ok and result.stdout == b"out\n" and result.stderr == b"err\n"
                elif name == "over-limit":
                    basic = basic and not result.ok and "output limit" in (result.primary_error or "") and result.persisted[0] == 1024
                elif name == "timeout":
                    basic = basic and not result.ok and result.timed_out
                elif name == "cancel":
                    basic = basic and not result.ok and result.cancelled
                elif name == "held-pipe":
                    # Linux may dispose its whole PID namespace on leader exit;
                    # that is genuine outer EOF/finality, not a product cleanup claim.
                    basic = basic and (not result.ok or (self.platform == "linux" and result.stdout_eof and result.stderr_eof))
                if not basic:
                    raise SessionError(f"collector admission case failed: {name}")
                capture_note["ok"] = True
            self._owner_loss_preflight()
        except BaseException as exc:
            failures.append(exc)
        finally:
            for listener in listeners:
                try:
                    listener.close()
                except BaseException as exc:
                    failures.append(exc)
        if failures:
            raise BaseExceptionGroup("native admission and owned listener cleanup failed", failures)

    def _trusted_entry(self, policy: Path, tail: list[str]) -> list[str]:
        return [str(self.python), "-I", "-S", "-B", str(self.entry), "--enter", self.platform,
                str(self.uid), str(self.gid), "10", str(policy), str(self.python), "-I", "-S", "-B",
                str(self.entry), *tail]

    def _signal_preflight(self) -> None:
        """Only these original owned synthetic U processes are signal targets."""
        self.ensure_idle()
        sentinel = subprocess.Popen(self._trusted_entry(self.cleanup_policy, ["--sentinel"]),
                                    cwd=self.work, env=self._environment({}), user=self.uid,
                                    group=self.gid, extra_groups=[], close_fds=True,
                                    start_new_session=True, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        errors = []
        try:
            if _ready_line(sentinel.stdout, 5) != b"MRK_SENTINEL_READY\n":
                raise SessionError("owned outside-sandbox signal control did not become ready")
            self.domain_finality = False
            self._direct_producer_pending = True
            raw = _small_command(self._trusted_entry(self.policy, ["--signal-case", str(sentinel.pid)]),
                                 10, user=self.uid, group=self.gid, deadline=self.deadline)
            self._direct_producer_pending = False
            if raw != b"MRK_SIGNAL_BOUNDARY_OK\n":
                raise SessionError("native signal boundary did not pass its actual controls")
            out, err = sentinel.communicate(b"q", timeout=2)
            # This fixed trusted sentinel emits at most these two literal lines;
            # no project output is collected using communicate().
            if sentinel.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
                raise SessionError("outside-sandbox sentinel received a signal or failed")
        except BaseException as exc:
            errors.append(exc)
        try:
            if sentinel.poll() is None:
                sentinel.kill()
            sentinel.wait(timeout=2)
        except BaseException as exc:
            errors.append(exc)
        for stream in (sentinel.stdin, sentinel.stdout, sentinel.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native signal control/cleanup failure", errors)
        self.ensure_idle()
        self.admission_results.append({"name": "same-UID-native-signal-boundary", "ok": True})

    def _owner_loss_preflight(self) -> None:
        """A deliberately lost synthetic parent is a FAILED separate subject.

        Its child's status is never reconstructed as an original wait.  The
        outside parent genuinely waits the failed owner, then observes bounded
        platform cleanup; no unknown process identity is signalled by root.
        """
        self.ensure_idle()
        command, kwargs = self._argv([str(self.python), "-I", "-S", "-B", str(self.entry),
                                     "--loss-subject"], 10)
        if self.platform == "linux":
            self._assert_userns_boundary()
        # A failed root owner helper can still be capable of a later U
        # launch even when the current U census is empty. No diagnostic
        # waited field can release this conservative outside-owner veto.
        self.domain_finality = False
        self._direct_producer_pending = True
        raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--loss-owner",
                              json.dumps({"command": command, "kwargs": kwargs,
                                          "cwd": str(self.work), "env": self._environment({})})],
                             10, expected_code=23, deadline=self.deadline)
        self._direct_producer_pending = False
        fields = raw.split()
        if len(fields) != 2 or fields[0] != b"MRK_OWNER_LOST" or not fields[1].isdigit():
            raise SessionError("lost-owner negative control has no genuine owner observation")
        observed_child = int(fields[1])  # Observation only; never signal authority.
        errors = self._cleanup()
        # Observation may raise next; never lose earlier independent cleanup
        # diagnostics or copy them again at the ordinary unsuccessful tail.
        self.cleanup_errors.extend(errors)
        cutoff = min(self.deadline, time.monotonic() + 5)
        while time.monotonic() < cutoff:
            rows = _snapshot(self.platform, deadline=cutoff, retry_churn=True)
            if all(pid != observed_child for pid, _ in rows) and not _domain(self.platform, self.uid, deadline=cutoff):
                break
            time.sleep(min(0.05, _remaining(cutoff)))
        else:
            reason = "lost-owner platform cleanup remained unknown or incomplete"
            errors.append(reason)
            self.cleanup_errors.append(reason)
        if errors:
            raise SessionError("lost-owner native admission cleanup failed")
        self.admission_results.append({"name": "supervisor-loss", "ok": True,
                                       "subject_owner_exit": 23, "subject_child_wait": "unavailable",
                                       "outer_domain_finality": True})

    def close(self, *, keep_timer: bool = False) -> None:
        """End command/producer ownership; optionally retain publication budget."""
        if self.closed:
            if not keep_timer:
                self.finish()
            if self.failure:
                raise SessionError(self.failure)
            return
        try:
            self._guard(allow_failure=True)
            if self._active is not None or self._busy or getattr(self, "_direct_producer_pending", False):
                self._fail("controller closed with an active producer")
                if self._active is not None:
                    try:
                        if self._active.poll() is None:
                            self._active.kill()
                        self._active.wait(timeout=2)
                        self._active = None
                    except BaseException as exc:
                        self.cleanup_errors.append(f"close original owned child {type(exc).__name__}")
            try:
                self.domain_finality = (not self._busy and self._active is None
                                        and not getattr(self, "_direct_producer_pending", False)
                                        and not _domain(self.platform, self.uid, deadline=self.deadline))
                if not self.domain_finality:
                    self.cleanup_errors.append("close did not establish reserved-identity finality")
                    self._fail("close did not establish reserved-identity finality")
            except BaseException as exc:
                self.domain_finality = False
                self.cleanup_errors.append(f"close census {type(exc).__name__}")
                self._fail("close reserved-identity census is unknown")
            # Failed/unknown state is deliberately NOT walked, deleted, adopted
            # or reset.  The reservation survives until this one VM is disposed.
        finally:
            for state in getattr(self, "_native_authority", {}).values():
                try:
                    if not state["completed"]:
                        self._fail("native authority phase was left incomplete at terminal close")
                    errors = self._native_close_pins(state)
                    if errors:
                        self.cleanup_errors.extend(errors)
                        self._fail("native authority owned finalization failed")
                except BaseException as exc:
                    self.cleanup_errors.append(f"native authority terminal finalization {type(exc).__name__}")
                    self._fail("native authority owned finalization failed")
            try:
                userns_errors = self._close_userns_boundary()
                if userns_errors:
                    self.cleanup_errors.extend(f"Linux user-namespace finalization {type(exc).__name__}" for exc in userns_errors)
                    self._fail("owned Linux user-namespace finalization failed")
            except BaseException as exc:
                self.cleanup_errors.append(f"Linux user-namespace finalization {type(exc).__name__}")
                self._fail("owned Linux user-namespace finalization failed")
            try:
                home_errors = self._close_home_boundary()
                if home_errors:
                    self.cleanup_errors.extend(f"HOME finalization {type(exc).__name__}" for exc in home_errors)
                    self._fail("owned HOME finalization failed")
            except BaseException as exc:
                self.cleanup_errors.append(f"HOME finalization {type(exc).__name__}")
                self._fail("owned HOME finalization failed")
            self.closed = True
            if not keep_timer:
                self.finish()
        if self.failure:
            raise SessionError(self.failure)

    def finish(self) -> None:
        """Release owned timer/handlers once, AFTER terminal publication work.

        Each release is attempted independently; no late error or prior failure
        is cleared.  A failed close can still release these controller resources.
        """
        if not self.closed:
            self._fail("terminal close is required before releasing the original timer")
            raise SessionError(self.failure)
        if self._timer_finished:
            if self.failure:
                raise SessionError(self.failure)
            return
        self._timer_finished = True
        errors = []
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except BaseException as exc:
            errors.append(f"aggregate timer release {type(exc).__name__}")
        for sig, previous in self._handlers.items():
            try:
                signal.signal(sig, previous)
            except BaseException as exc:
                errors.append(f"owned signal handler restore {sig} {type(exc).__name__}")
        self.cleanup_errors.extend(errors)
        if errors:
            self._fail("original timer/handler cleanup failed")
        if time.monotonic() >= self.deadline:
            self._fail("original aggregate deadline expired")
        if self.failure:
            raise SessionError(self.failure)


def _limits(platform: str, cpu: int, *, profile: str = "ordinary") -> None:
    if (platform not in {"linux", "darwin"} or type(cpu) is not int or not 0 < cpu <= 300
            or type(profile) is not str or profile not in {"ordinary", "python-full"}
            or profile == "python-full" and (platform != "linux" or cpu != 300)):
        raise SessionError("unsupported fixed resource profile")
    fsize = _PYTHON_FULL_FSIZE if profile == "python-full" else 512 * MiB
    limits = [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 1024),
              (resource.RLIMIT_NPROC, 256), (resource.RLIMIT_FSIZE, fsize),
              (resource.RLIMIT_CPU, cpu)]
    if platform == "linux":
        limits.append((resource.RLIMIT_AS, 4 * 1024 * MiB))
    for which, target in limits:
        _soft, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY and hard < target:
            raise SessionError("provider resource ceiling is below required profile")
        resource.setrlimit(which, (target, target))
        if resource.getrlimit(which) != (target, target):
            raise SessionError("resource limit did not take effect")


def _native_initial_entry(argv: list[str]) -> None:
    """Admit only the fixed unprivileged first-application control after limits.

    The helper must apply the immutable policy before any probe. An ordinary
    sandboxed process invoking this entry does not lose its inherited policy.
    """
    if (type(argv) is not list or len(argv) != 14 or any(type(arg) is not str for arg in argv)
            or sys.platform != "darwin" or not 0 < len(argv[-1]) <= 64):
        raise SessionError("invalid initial native application entry")
    uid = os.getuid()
    if (not 60000 <= uid < 65000 or (os.geteuid(), os.getgid(), os.getegid()) != (uid,) * 3
            or _process_groups("darwin") != [uid]):
        raise SessionError("initial native application lacks its reserved numerical credentials")
    entry = Path(__file__).resolve(strict=True)
    root = entry.parent.parent
    python = Path(sys.executable).resolve(strict=True)
    if (root.parent != Path("/private/tmp") or entry != root / "bootstrap/ci_sandbox.py"
            or python.parent.name != "bin"):
        raise SessionError("initial native application lacks its fixed entry/provider paths")
    literal = argv[-1]
    deadline = int(literal) if re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", literal) else float(literal)
    _remaining(deadline)
    policy = str(root / "bootstrap/native-authority-source.sb")
    command = [str(python), "-I", "-S", "-B", str(root / "bootstrap/ci_native_authority.py"),
               "--mach-initial", policy, repr(deadline)]
    expected = ["--enter", "darwin", str(uid), str(uid), "180", policy, *command]
    flags = sys.flags
    # The framework launcher may replace only orig_argv[0]; the original
    # isolated suffix and canonical sys.executable must still match exactly.
    if (argv != expected or type(sys.orig_argv) is not list
            or sys.orig_argv[1:] != ["-I", "-S", "-B", str(entry), *expected]
            or (flags.isolated, flags.no_site, flags.dont_write_bytecode,
                flags.ignore_environment, flags.no_user_site, flags.safe_path) != (1, 1, 1, 1, 1, True)):
        raise SessionError("initial native application entry differs from its one fixed vector")
    _remaining(deadline)


def _native_aia_baseline_entry(argv: list[str]) -> None:
    """Validate only the fixed trusted offline comparison after resource limits.

    The policy pathname is a binding field, not an application claim. This
    entry never removes an inherited sandbox and admits no caller-selected code.
    """
    if (type(argv) is not list or len(argv) != 13 or any(type(arg) is not str for arg in argv)
            or sys.platform != "darwin" or not 0 < len(argv[-1]) <= 64):
        raise SessionError("invalid fixed native baseline entry")
    uid = os.getuid()
    if (not 60000 <= uid < 65000 or (os.geteuid(), os.getgid(), os.getegid()) != (uid,) * 3
            or _process_groups("darwin") != [uid]):
        raise SessionError("native baseline lacks its reserved numerical credentials")
    entry = Path(__file__).resolve(strict=True)
    root = entry.parent.parent
    python = Path(sys.executable).resolve(strict=True)
    cwd = Path.cwd()
    if (root.parent != Path("/private/tmp") or entry != root / "bootstrap/ci_sandbox.py"
            or python.parent.name != "bin" or cwd != root / "work/native-authority-source/probes"
            or cwd != cwd.resolve(strict=True)):
        raise SessionError("native baseline lacks its fixed entry/provider/cwd paths")
    literal = argv[-1]
    deadline = int(literal) if re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", literal) else float(literal)
    _remaining(deadline)
    policy = str(root / "bootstrap/native-aia-source.sb")
    command = [str(python), "-I", "-S", "-B", str(root / "bootstrap/ci_native_authority.py"),
               "--aia-offline-baseline", repr(deadline)]
    expected = ["--enter", "darwin", str(uid), str(uid), "180", policy, *command]
    flags = sys.flags
    if (argv != expected or type(sys.orig_argv) is not list
            or sys.orig_argv[1:] != ["-I", "-S", "-B", str(entry), *expected]
            or (flags.isolated, flags.no_site, flags.dont_write_bytecode,
                flags.ignore_environment, flags.no_user_site, flags.safe_path) != (1, 1, 1, 1, 1, True)):
        raise SessionError("native baseline entry differs from its one fixed vector")
    _remaining(deadline)


def _native_write_checkpoint(argv: list[str], *, outer: bool) -> None:
    """Two exact fixed-command checkpoints, never an execution authority."""
    if (type(outer) is not bool or type(argv) is not list
            or any(type(arg) is not str for arg in argv) or sys.platform != "darwin"):
        raise SessionError("invalid native write checkpoint invocation")
    uid = os.getuid()
    if not 60000 <= uid < 65000 or (os.geteuid(), os.getgid(), os.getegid()) != (uid,) * 3:
        raise SessionError("native write checkpoint lacks original numerical credentials")
    entry = Path(__file__).resolve(strict=True)
    root = entry.parent.parent
    python = Path(sys.executable).resolve(strict=True)
    if (root.parent != Path("/private/tmp") or entry != root / "bootstrap/ci_sandbox.py"
            or python.parent.name != "bin"):
        raise SessionError("native write checkpoint lacks its fixed entry/provider paths")
    base = [str(python), "-I", "-S", "-B", str(entry)]
    expected = []
    for phase in _NATIVE_PHASES:
        tail = ["--native-write-control", str(root / "fixture-controls" / f"native-authority-{phase}-outside-write")]
        expected.append(["--enter", "darwin", str(uid), str(uid), "180",
                         str(root / "bootstrap" / f"native-write-positive-{phase}.sb"), *base, *tail]
                        if outer else tail)
    # CPython3.11's framework launcher replaces argv[0] with Python.app,
    # preserves the suffix, and supplies the original sys.executable through
    # __PYVENV_LAUNCHER__. Do not mistake those two spellings for a new caller.
    flags = sys.flags
    if (argv not in expected or type(sys.orig_argv) is not list
            or sys.orig_argv[1:] != [*base[1:], *argv]
            or (flags.isolated, flags.no_site, flags.dont_write_bytecode,
                flags.ignore_environment, flags.no_user_site, flags.safe_path) != (1, 1, 1, 1, 1, True)):
        raise SessionError("native write checkpoint command differs from its fixed phase")
    data = _NATIVE_WRITE_OUTER if outer else _NATIVE_WRITE_INNER
    if os.write(2, data) != len(data):
        raise SessionError("native write checkpoint was not completely written")


def _native_write_prefix(data: bytes) -> str:
    """Failure-only attribution; malformed/extra bytes are never stage proof."""
    if type(data) is not bytes or len(data) > len(_NATIVE_WRITE_STDERR):
        return "unclassified"
    return {b"": "none", _NATIVE_WRITE_OUTER: "outer",
            _NATIVE_WRITE_STDERR: "outer-and-inner"}.get(data, "unclassified")


def _write_control(path: Path, *, native: bool = False) -> None:
    parent = Path(__file__).resolve().parent.parent / "fixture-controls"
    expected = ({parent / f"native-authority-{phase}-outside-write" for phase in _NATIVE_PHASES}
                if native else {parent / "outside-write"})
    if (path not in expected or native and sys.platform != "darwin"
            or os.getuid() != os.geteuid() or not 60000 <= os.geteuid() < 65000):
        raise SessionError("invalid fixed numerical write control")
    if native:
        _native_write_checkpoint(["--native-write-control", str(path)], outer=False)
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    errors = []
    try:
        state = os.fstat(fd)
        if (state.st_uid != os.geteuid() or state.st_nlink != 1
                or not stat.S_ISREG(state.st_mode) or stat.S_IMODE(state.st_mode) != 0o600):
            raise SessionError("synthetic outside-work write control lost its exact DAC state")
        os.ftruncate(fd, 0)
        data = b"MRK_POSITIVE_WRITE\n"
        if os.write(fd, data) != len(data):
            raise SessionError("synthetic outside-work positive write was incomplete")
        os.fsync(fd)
        if os.fstat(fd).st_size != len(data):
            raise SessionError("synthetic outside-work positive persisted length differs")
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(fd)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic write control and close failed", errors)
    print("MRK_OUTSIDE_WRITE_POSITIVE", flush=True)


def _native_read_control(phase: str, deadline: float) -> None:
    """Two fixed public/synthetic reads prove later negatives are not absence."""
    if (sys.platform != "darwin" or phase not in _NATIVE_PHASES
            or not 60000 <= os.getuid() < 65000
            or (os.getuid(), os.getgid(), os.getegid()) != (os.geteuid(),) * 3):
        raise SessionError("invalid fixed native read positive role")
    root = Path(__file__).resolve().parent.parent
    _remaining(deadline)
    canary, _ = _native_file(root / "work/home" / f"native-authority-{phase}-read",
                              deadline=deadline, uid=os.getuid(), gid=os.getgid(), maximum=64)
    sibling, _ = _native_file(root / "work" / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py",
                               deadline=deadline, uid=os.getuid(), gid=os.getgid())
    if canary != b"MRK_NATIVE_PREVIOUS_SCRATCH\n" or not sibling:
        raise SessionError("fixed native outside/sibling read did not return its actual public bytes")
    _remaining(deadline)
    print("MRK_NATIVE_OUTSIDE_READ_OK", flush=True)


def _home_positive() -> None:
    """Fixed unprivileged synthetic HOME controls; no command/path arguments."""
    if (sys.platform != "darwin" or not 60000 <= os.getuid() < 65000
            or os.getuid() != os.geteuid() or os.getgid() != os.getuid() or os.getegid() != os.getgid()):
        raise SessionError("invalid fixed HOME positive role")
    _limits("darwin", 10)
    bootstrap = Path(__file__).resolve().parent
    fds, peer, errors, deadline = [], None, [], None
    try:
        fd = os.open(bootstrap / "home-control.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        fds.append(fd)
        state = os.fstat(fd)
        if (not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_gid != 0
                or state.st_nlink != 1 or stat.S_IMODE(state.st_mode) != 0o444 or not 0 < state.st_size <= 16384):
            raise SessionError("fixed HOME manifest is not immutable bounded control")
        raw = os.read(fd, 16385)
        if len(raw) != state.st_size or os.read(fd, 1):
            raise SessionError("fixed HOME manifest read is incomplete")
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"home", "ruby_prefix", "uid", "gid", "deadline"}
                or type(data["uid"]) is not int or type(data["gid"]) is not int
                or (data["uid"], data["gid"]) != (os.getuid(), os.getgid())
                or not isinstance(data["home"], str) or not isinstance(data["ruby_prefix"], str)
                or _process_groups("darwin") != [os.getgid()]):
            raise SessionError("fixed HOME manifest lacks numerical owner binding")
        deadline = data["deadline"]
        _remaining(deadline)
        home = _canonical(data["home"])
        _remaining(deadline)
        prefix = _canonical(data["ruby_prefix"])
        _remaining(deadline)
        canary, endpoint = _home_paths(home, bootstrap.parent)
        sibling = _ruby_sibling_path(home, prefix, bootstrap.parent)
        for path, expected in ((canary, _HOME_READ_BYTES), (sibling, _ANCESTOR_READ_BYTES)):
            _remaining(deadline)
            named = os.stat(path, follow_symlinks=False)  # Genuine known-name metadata positive.
            _remaining(deadline)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            fds.append(fd)  # Custody precedes every subsequent fallible operation.
            _remaining(deadline)
            state = os.fstat(fd)
            _remaining(deadline)
            if (not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_gid == os.getgid()
                    or state.st_nlink != 1 or stat.S_IMODE(state.st_mode) != 0o444
                    or state.st_size != len(expected) or _home_node(named) != _home_node(state)
                    or named.st_nlink != 1 or stat.S_IMODE(named.st_mode) != 0o444 or named.st_size != len(expected)):
                raise SessionError("synthetic HOME/sibling file lacks exact DAC-positive state")
            if os.read(fd, len(expected) + 1) != expected or os.read(fd, 1):
                raise SessionError("synthetic HOME/sibling file was not genuinely read")
            _remaining(deadline)
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(min(2, _remaining(deadline)))
        peer.connect(str(endpoint))
        peer.settimeout(min(2, _remaining(deadline)))
        peer.sendall(_HOME_SOCKET_BYTES)
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if peer is not None:
        try:
            peer.close()
        except BaseException as exc:
            errors.append(exc)
    for fd in reversed(fds):
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    if deadline is not None:
        try:
            _remaining(deadline)
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("fixed HOME positive/owned close failed", errors)
    print("MRK_HOME_POSITIVE_OK", flush=True)


def _ready_line(stream, seconds: float, *, deadline: float | None = None) -> bytes:
    """Read one bounded fixed trusted-control line; no mutable readiness file."""
    cutoff, data = time.monotonic() + seconds, bytearray()
    if deadline is not None:
        _remaining(deadline)
        cutoff = min(cutoff, deadline)
    with selectors.DefaultSelector() as sel:
        sel.register(stream, selectors.EVENT_READ)
        while time.monotonic() < cutoff:
            if not sel.select(min(0.1, max(0, cutoff - time.monotonic()))):
                continue
            chunk = os.read(stream.fileno(), 256 - len(data))
            if not chunk:
                raise SessionError("owned control stream closed before readiness")
            data.extend(chunk)
            if b"\n" in data:
                if deadline is not None:
                    _remaining(cutoff)
                return bytes(data)
            if len(data) == 256:
                raise SessionError("owned control line exceeds bound")
    raise SessionError("owned control readiness deadline")


def _signal_subject(target: int) -> None:
    child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                              "--signal-target"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, bufsize=0)
    errors = []
    try:
        if _ready_line(child.stdout, 3) != b"MRK_SIGNAL_READY\n":
            raise SessionError("same-sandbox signal positive did not become ready")
        child.send_signal(signal.SIGUSR1)  # Own original handle, not a discovered PID.
        out, err = child.communicate(timeout=2)
        if child.returncode != 0 or out != b"MRK_SIGNAL_RECEIVED\n" or err:
            raise SessionError("same-sandbox positive signal was not actually delivered")
        try:
            os.kill(target, signal.SIGUSR1)
        except PermissionError:
            pass
        else:
            raise SessionError("signal to owned same-UID outside-sandbox sentinel was allowed")
    except BaseException as exc:
        errors.append(exc)
    try:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    except BaseException as exc:
        errors.append(exc)
    for stream in (child.stdout, child.stderr):
        try:
            stream.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native signal subject/cleanup failure", errors)
    print("MRK_SIGNAL_BOUNDARY_OK", flush=True)


def _signal_target(outside: bool) -> None:
    received = []
    signal.signal(signal.SIGUSR1, lambda signum, frame: received.append(signum))
    print("MRK_SENTINEL_READY" if outside else "MRK_SIGNAL_READY", flush=True)
    if outside:
        if os.read(0, 1) != b"q" or received:
            raise SessionError("outside-sandbox control received an unexpected signal or close")
        print("MRK_SENTINEL_CLOSED", flush=True)
    else:
        cutoff = time.monotonic() + 3
        while not received and time.monotonic() < cutoff:
            time.sleep(0.01)
        if received != [signal.SIGUSR1]:
            raise SessionError("same-sandbox control did not receive exactly one owned signal")
        print("MRK_SIGNAL_RECEIVED", flush=True)


def _observer_query(observer: Path, pid: int, group: int | None, *, deadline: float,
                    kernel_denied: bool = False) -> str:
    """Fixed native-control parser; arbitrary product or ps text is not accepted."""
    if sys.platform != "darwin" or os.getuid() == 0:
        raise SessionError("native reader may never execute as root or on a substitute platform")
    raw = _small_command([str(observer), str(pid)], 3, expected_code=2 if kernel_denied else 0,
                         deadline=deadline)
    if len(raw) > 512 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SessionError("native observer record size/framing failed")
    if kernel_denied:
        if raw not in {f"MRK_PROCESS_V1 denied {pid} kernel {number}\n".encode()
                       for number in (errno.EPERM, errno.EACCES)}:
            raise SessionError("foreign native observer result is not actual kernel denial")
        _remaining(deadline)
        return "denied"
    if raw == f"MRK_PROCESS_V1 absent {pid}\n".encode():
        _remaining(deadline)
        return "absent"
    fields = raw[:-1].split(b" ")
    if (len(fields) != 13 or fields[:2] != [b"MRK_PROCESS_V1", b"present"]
            or any(not re.fullmatch(rb"0|[1-9][0-9]{0,9}", part) for part in fields[2:12])):
        raise SessionError("native observer record grammar failed")
    observed, pgid, ru, eu, su, rg, eg, sg, status, exiting = map(int, fields[2:12])
    if (observed != pid or not 1 < pgid < 2**31 or group is not None and pgid != group
            or (ru, eu, su) != (os.getuid(),) * 3 or (rg, eg, sg) != (os.getgid(),) * 3
            or not 0 <= status < 2**32 or exiting not in {0, 1}):
        raise SessionError("native observer record identity/status failed")
    wanted = "zombie" if status == 5 else "live" if status in {2, 3, 4} and not exiting else "indeterminate"
    if fields[12] != wanted.encode():
        raise SessionError("native observer record contradicts BSD state")
    _remaining(deadline)
    return wanted


def _observer_control_eof(child, *, deadline: float) -> None:
    """Drain original fixture pipes WITHOUT reaping its deliberately held zombie."""
    sel, errors = None, []
    data = [bytearray(), bytearray()]
    try:
        sel = selectors.DefaultSelector()
        for i, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, i)
        while sel.get_map():
            for key, _ in sel.select(min(0.05, _remaining(deadline))):
                try:
                    chunk = os.read(key.fd, 512 - len(data[key.data]) + 1)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)  # Actual EOF, not a closed local read end.
                    continue
                data[key.data].extend(chunk)
                if len(data[key.data]) > 512:
                    raise SessionError("observer fixture output exceeds fixed bound")
        if data != [bytearray(b"MRK_OBSERVER_FAMILY_RELEASED\n"), bytearray()]:
            raise SessionError("observer fixture lacks complete release/EOF evidence")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if sel is not None:
        try:
            sel.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer fixture EOF/selector cleanup failed", errors)


def _observer_family(deadline: float) -> None:
    """U fixture is its grandchild's original parent and waits before exiting."""
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SessionError("observer family must remain a native unprivileged fixture")
    child, errors = None, []
    try:
        _remaining(deadline)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--sentinel"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, bufsize=0)
        if _ready_line(child.stdout, min(3, _remaining(deadline))) != b"MRK_SENTINEL_READY\n":
            raise SessionError("owned observer descendant was not genuinely ready")
        print(f"MRK_OBSERVER_FAMILY {child.pid}", flush=True)
        with selectors.DefaultSelector() as sel:
            sel.register(0, selectors.EVENT_READ)
            if not sel.select(_remaining(deadline)) or os.read(0, 1) != b"q":
                raise SessionError("observer family lost its owned release channel")
        out, err = child.communicate(b"q", timeout=min(3, _remaining(deadline)))
        if child.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
            raise SessionError("observer descendant was not actually waited/drained")
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            if child.poll() is None:
                child.kill()  # Own original child only.
        except BaseException as exc:
            errors.append(exc)
        try:
            if type(child.wait(timeout=max(0.0, min(2, deadline - time.monotonic())))) is not int:
                raise SessionError("observer descendant has no original cleanup wait")
        except BaseException as exc:
            errors.append(exc)
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer descendant original custody/cleanup failed", errors)
    print("MRK_OBSERVER_FAMILY_RELEASED", flush=True)


def _observer_probe(observer: Path, foreign_pid: int, deadline: float) -> None:
    """All reader invocations are U-owned; a printed PID grants no signal route."""
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid() or not 1 < foreign_pid < 2**31
            or observer != Path(__file__).resolve().parent / "process-observer"):
        raise SessionError("invalid native observer probe role")
    child, errors = None, []
    try:
        _remaining(deadline)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                  "--observer-family", repr(deadline)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, start_new_session=True, bufsize=0)
        ready = _ready_line(child.stdout, min(5, _remaining(deadline)))
        match = re.fullmatch(rb"MRK_OBSERVER_FAMILY ([1-9][0-9]{0,9})\n", ready)
        if match is None:
            raise SessionError("observer family has no actual readiness/control evidence")
        descendant = int(match[1])
        if not 1 < descendant < 2**31 or descendant in {child.pid, foreign_pid, os.getpid()}:
            raise SessionError("observer descendant control identity is invalid")
        for pid in (child.pid, descendant):
            while True:
                state = _observer_query(observer, pid, child.pid, deadline=deadline)
                if state == "live":
                    break
                if state != "indeterminate":
                    raise SessionError("observer live control stopped before observation")
                time.sleep(min(0.01, _remaining(deadline)))
        _observer_query(observer, foreign_pid, None, deadline=deadline, kernel_denied=True)
        if os.write(child.stdin.fileno(), b"q") != 1:
            raise SessionError("observer release write was incomplete")
        child.stdin.close()
        _observer_control_eof(child, deadline=deadline)
        # Keep the strong original Popen handle.  Neither pipe EOF nor launching
        # a separate reader polls/waits this child; its zombie PID stays reserved.
        while True:
            state = _observer_query(observer, child.pid, child.pid, deadline=deadline)
            if state == "zombie":
                break
            if state == "absent":
                raise SessionError("owned child disappeared before actual original reap")
            time.sleep(min(0.01, _remaining(deadline)))
        if child.wait(timeout=_remaining(deadline)) != 0:
            raise SessionError("observer original zombie did not yield genuine successful wait")
        if _observer_query(observer, child.pid, child.pid, deadline=deadline) != "absent":
            raise SessionError("observer original child was not absent after actual reap")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            if child.poll() is None:
                child.kill()  # Strongly held original fixture, not returned metadata.
        except BaseException as exc:
            errors.append(exc)
        try:
            if type(child.wait(timeout=max(0.0, min(2, deadline - time.monotonic())))) is not int:
                raise SessionError("observer fixture has no original cleanup wait")
        except BaseException as exc:
            errors.append(exc)
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer native original-custody/cleanup controls failed", errors)
    print("MRK_PROCESS_OBSERVER_OK", flush=True)


def _loss_owner(data: dict) -> None:
    if os.geteuid() != 0:
        raise SessionError("fixed synthetic owner role requires outside subject identity")
    if sys.platform == "linux":
        # This root fixture cannot inherit the Session's CLOEXEC pin. Its
        # original outside caller holds that custody and bounds this read.
        _userns_zero()
    child = subprocess.Popen(data["command"], **data["kwargs"], cwd=data["cwd"], env=data["env"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True, bufsize=0)
    try:
        if _ready_line(child.stdout, 5) != b"MRK_LOSS_SUBJECT_READY\n":
            raise SessionError("synthetic lost-owner subject did not become ready")
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()
        raise
    # Deliberately missing child wait; the caller expects 23, NEVER success.
    os.write(1, f"MRK_OWNER_LOST {child.pid}\n".encode("ascii"))
    os._exit(23)


def _process_groups(platform: str) -> list[int]:
    """Observe actual process groups, not Darwin's NSS user-access-group API.

    Modern Darwin CPython os.getgroups() resolves the extended libc alias,
    which queries passwd/directory membership and is not changed by setgroups.
    The public unversioned POSIX getgroups uses gid_t (uint32) and returns the
    kernel list, including its mandatory first effective-GID entry.  No NSS,
    Mach service, named account, runtime discovery, or observation fallback.
    """
    if platform not in {"linux", "darwin"}:
        raise SessionError("unsupported process-group observation platform")
    operation = "process-groups-linux" if platform == "linux" else "kernel-groups-library"
    try:
        if platform == "linux":
            return os.getgroups()
        # Local import: Linux and pure caller setup need not load any library.
        import ctypes
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        getgroups = library.getgroups
        getgroups.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
        getgroups.restype = ctypes.c_int
        operation = "kernel-groups-count"
        ctypes.set_errno(0)
        count = getgroups(0, None)
        if count < 0:
            raise OSError(ctypes.get_errno(), "kernel group-count observation failed")
        if not 1 <= count <= 256:
            raise SessionError("native group-count bound is unsupported")
        groups = (ctypes.c_uint32 * count)()
        operation = "kernel-groups-fill"
        ctypes.set_errno(0)
        filled = getgroups(count, groups)
        if filled < 0:
            raise OSError(ctypes.get_errno(), "kernel group-list observation failed")
        if filled != count:
            raise SessionError("native group count changed during observation")
        return list(groups)
    except BaseException as exc:
        exc._ci_operation = operation
        raise


def _probe_network(platform: str, endpoints: list) -> None:
    """Probe only owned loopback endpoints; UDP enqueue is not delivery."""
    expected = {(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"),
                (socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
                (socket.AF_INET6, socket.SOCK_STREAM, "::1"),
                (socket.AF_INET6, socket.SOCK_DGRAM, "::1")}
    if (platform not in {"linux", "darwin"} or not isinstance(endpoints, list) or len(endpoints) != 4
            or any(not isinstance(row, (list, tuple)) or len(row) != 4
                   or not isinstance(row[0], int) or not isinstance(row[1], int) or not isinstance(row[2], str)
                   or type(row[3]) is not int or not 0 < row[3] <= 65535 for row in endpoints)
            or {(row[0], row[1], row[2]) for row in endpoints} != expected):
        raise SessionError("incomplete fixed outside network endpoints")
    if platform == "linux":
        interfaces = socket.if_nameindex()
        if (len(interfaces) != 1 or len(interfaces[0]) != 2
                or type(interfaces[0][0]) is not int or interfaces[0][0] <= 0
                or interfaces[0][1] != "lo"):
            raise SessionError("isolated network namespace has unexpected interfaces")
    for family, kind, host, port in endpoints:
        stream = None
        failures = []
        operation = "network-" + ("tcp" if kind == socket.SOCK_STREAM else "udp") + ("4" if family == socket.AF_INET else "6")
        try:
            stream = socket.socket(family, kind)
            stream.settimeout(0.5)
            if kind == socket.SOCK_STREAM:
                stream.connect((host, port))
                raise SessionError("outside-domain TCP connection was permitted")
            sent = stream.sendto(b"must-not-escape", (host, port))
            if platform != "linux" or sent != len(b"must-not-escape"):
                raise SessionError("outside-domain datagram was not denied or fully enqueued locally")
            # Linux's separate stack/loopback can accept this datagram locally.
            # The outside original owner must separately prove no delivery.
        except OSError as exc:
            allowed = {errno.EACCES, errno.EPERM} if platform == "darwin" else {
                errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED}
            if exc.errno not in allowed:
                failures.append(exc)
        except BaseException as exc:
            failures.append(exc)
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            error = BaseExceptionGroup("fixed network probe/close failed", failures)
            error._ci_operation = operation
            raise error


def _outside_network_control(listener, *, deadline: float) -> None:
    """One real owned loopback endpoint, and independent positive socket closes."""
    positive = accepted = None
    errors = []
    try:
        _remaining(deadline)
        if (listener.family not in (socket.AF_INET, socket.AF_INET6)
                or listener.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM)):
            raise SessionError("unexpected fixed outside listener kind")
        address = listener.getsockname()
        if address[0] != ("127.0.0.1" if listener.family == socket.AF_INET else "::1"):
            raise SessionError("outside positive listener is not its owned loopback address")
        positive = socket.socket(listener.family, listener.type)
        listener.settimeout(min(1, _remaining(deadline)))
        positive.settimeout(min(1, _remaining(deadline)))
        if listener.type == socket.SOCK_STREAM:
            positive.connect(address)
            listener.settimeout(min(1, _remaining(deadline)))
            accepted, _ = listener.accept()
        else:
            if positive.sendto(b"owned-control", address) != len(b"owned-control"):
                raise SessionError("outside UDP positive did not send its exact synthetic bytes")
            listener.settimeout(min(1, _remaining(deadline)))
            if listener.recv(64) != b"owned-control":
                raise SessionError("outside UDP positive did not actually receive its exact bytes")
    except BaseException as exc:
        errors.append(exc)
    for stream in (accepted, positive):
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("outside owned network positive/independent close failed", errors)


def _outside_network_empty(listeners: list, *, deadline: float) -> None:
    """Original owner checks all four receivers AFTER wait, EOF and UID finality."""
    expected = {(family, kind) for family in (socket.AF_INET, socket.AF_INET6)
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)}
    if len(listeners) != 4 or {(s.family, s.type) for s in listeners} != expected:
        raise SessionError("incomplete owned outside receiver inventory")
    failures = []
    for listener in listeners:
        accepted = None
        try:
            _remaining(deadline)
            listener.setblocking(False)
            try:
                if listener.type == socket.SOCK_STREAM:
                    accepted, _address = listener.accept()
                else:
                    listener.recv(1)  # A zero-length datagram is also delivery.
                raise SessionError("owned outside receiver observed prohibited delivery")
            except BlockingIOError as exc:
                if exc.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
        except BaseException as exc:
            failures.append(exc)
        if accepted is not None:
            try:
                accepted.close()
            except BaseException as exc:
                failures.append(exc)
        if failures and isinstance(failures[-1], DeadlineExpired):
            break
    try:
        _remaining(deadline)
    except BaseException as exc:
        failures.append(exc)
    if failures:
        raise BaseExceptionGroup("outside receiver observation/close failed", failures)


def _home_socket_empty(listener, *, deadline: float) -> None:
    """Only the original synthetic HOME listener, after child wait/EOF/finality."""
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise SessionError("wrong owned HOME listener type")
    accepted, errors = None, []
    try:
        _remaining(deadline)
        listener.setblocking(False)
        try:
            accepted, _ = listener.accept()
            raise SessionError("synthetic HOME listener observed prohibited delivery")
        except BlockingIOError as exc:
            if exc.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                raise
    except BaseException as exc:
        errors.append(exc)
    if accepted is not None:
        try:
            accepted.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic HOME non-delivery/accepted close failed", errors)


def _probe_provider_boundaries(data: dict) -> None:
    """Fixed runtime/HOME controls, without generic missing-fixture allowances."""
    if data["platform"] == "linux":
        targets = data["runtime_executables"]
        if not isinstance(targets, list) or len(targets) != 2 or any(not Path(p).is_absolute() for p in targets):
            raise SessionError("incomplete fixed provider writer-control inventory")
        for target in targets:
            fd, errors = None, []
            try:
                fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                raise SessionError("selected provider executable is writable by the subject")
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EPERM, errno.EROFS}:
                    errors.append(exc)  # Missing fixture and ETXTBSY are not protection evidence.
            except BaseException as exc:
                errors.append(exc)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise BaseExceptionGroup("fixed provider write-open control/close failed", errors)
        return
    if data["platform"] != "darwin":
        raise SessionError("unsupported fixed provider boundary platform")
    home, prefix = Path(data["runner_home"]), Path(data["ruby_prefix"])
    ancestors = _ruby_ancestor_paths(home, prefix)
    ruby = Path(data["ruby_executable"])
    if not ruby.is_absolute() or ".." in ruby.parts or ruby.parent.parent != prefix:
        raise SessionError("Ruby metadata control lost the selected executable binding")
    root = Path(data["work"]).parent
    canary, endpoint = _home_paths(home, root)
    sibling = _ruby_sibling_path(home, prefix, root)
    if (data["home_canary"], data["home_socket"], data["home_sibling"]) != (str(canary), str(endpoint), str(sibling)):
        raise SessionError("HOME boundary controls differ from fixed session names")
    # Each literal must actually permit its one directory inode's metadata.
    # Neither fake Ruby receipts nor successful denied-file opens can stand in
    # for these positives in the original/fork-exec/detached native routes.
    for ancestor in ancestors:
        state = os.stat(ancestor, follow_symlinks=False)
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid == data["uid"] or state.st_gid == data["gid"]
                or state.st_mode & 0o002 or not state.st_mode & 0o001):
            raise SessionError("literal Ruby ancestor metadata/traversal positive failed")
    if ruby.resolve(strict=True) != ruby:
        raise SessionError("selected Ruby path did not resolve strictly under the final policy")
    for target, expected in ((canary, _HOME_READ_BYTES), (sibling, _ANCESTOR_READ_BYTES)):
        for operation in ("read", "metadata"):
            fd, errors = None, []
            try:
                if operation == "read":
                    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    os.read(fd, len(expected) + 1)
                else:
                    os.stat(target, follow_symlinks=False)
                raise SessionError("synthetic HOME/sibling known-path access was permitted")
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EPERM}:
                    errors.append(exc)
            except BaseException as exc:
                errors.append(exc)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise BaseExceptionGroup("known-path HOME/sibling denial/owned close failed", errors)
    peer, errors = None, []
    try:
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(0.5)
        try:
            peer.connect(str(endpoint))
            raise SessionError("synthetic HOME pathname socket was reachable")
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise
    except BaseException as exc:
        errors.append(exc)
    if peer is not None:
        try:
            peer.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("HOME named-socket denial/owned close failed", errors)


def _sudo_denial() -> None:
    """Only the pre-admitted fixed noninteractive command is a denial oracle."""
    try:
        child = subprocess.Popen(["/usr/bin/sudo", "-n", "-u", "root", "/usr/bin/true"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as exc:
        if exc.errno in {errno.EPERM, errno.EACCES}:
            return  # A real permission denial before an original child exists.
        raise
    failures = []
    try:
        result = child.wait(timeout=3)
        if type(result) is not int or result == 0:
            raise SessionError("subject has usable or unobserved sudo authority")
    except BaseException as exc:
        failures.append(exc)
    try:
        if child.poll() is None:
            child.kill()
    except BaseException as exc:
        failures.append(exc)
    try:
        if type(child.wait(timeout=2)) is not int:
            raise SessionError("fixed sudo denial has no original cleanup wait")
    except BaseException as exc:
        failures.append(exc)
    if failures:
        raise BaseExceptionGroup("fixed sudo denial/cleanup failed", failures)


def _probe_leaf(data: dict) -> None:
    uid, gid = data["uid"], data["gid"]
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
        raise SessionError("numerical credentials differ")
    # CPython clears groups before setregid/setreuid.  Darwin stores EGID as
    # groups[0], so primary-only[gid] (not []) proves no additional groups.
    if _process_groups(data["platform"]) != ([] if data["platform"] == "linux" else [gid]):
        raise SessionError("process retains unexpected groups")
    # Check before opening any probe descriptors.  No inherited socket or extra FD.
    for fd in range(1024):
        try:
            mode = os.fstat(fd).st_mode
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        if fd > 2 or stat.S_ISSOCK(mode):
            raise SessionError("unexpected inherited descriptor")
    if data["platform"] == "linux":
        root = Path(data["work"]).parent
        state = root.stat()
        if (state.st_uid != 0 or stat.S_IMODE(state.st_mode) != 0o755
                or set(os.listdir(root)) != {"source", "inputs", "bootstrap", "work"}):
            raise SessionError("namespace task root has unexpected ownership/mode/topology")
        if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
            raise SessionError("saved numerical credentials differ")
        status = Path("/proc/self/status").read_text()
        fields = dict(s.split(":", 1) for s in status.splitlines() if ":" in s)
        if any(int(fields[n].strip(), 16) for n in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) or fields["NoNewPrivs"].strip() != "1":
            raise SessionError("capability/no-new-privileges drop failed")
        if any(os.readlink(f"/proc/self/ns/{n}") == data[f"host_{n}"] for n in ("net", "pid")):
            raise SessionError("required namespace was not separated")
    # Darwin saved IDs were observed by the real root parent on its original,
    # still-unreaped Popen PID.  Fork and the admitted non-set-ID exec chain
    # preserve them; sandboxed ps is not an appropriate metadata dependency.
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise SessionError("subject could regain root")
    _probe_provider_boundaries(data)
    extra_reads, scratch_root = [], Path(data["work"])
    if "probe_scratch" in data:
        scratch_root = Path(data["probe_scratch"])
        phase = scratch_root.parent.name.removeprefix("native-authority-")
        work = Path(data["work"])
        wanted = [str(work / "home" / f"native-authority-{phase}-read"),
                  str(work / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py")]
        if (data["platform"] != "darwin" or phase not in _NATIVE_PHASES
                or scratch_root != work / ("native-authority-" + phase) / "probes"
                or data.get("outside_reads") != wanted):
            raise SessionError("native authority probe lost its fixed scratch/read controls")
        extra_reads = [(path, "read") for path in wanted]
    for target, operation in ((data["control"], "read"), (data["runner_home"], "list"),
                              (data["runner_temp"], "list"), (data["readonly"], "write"),
                              (data["outside_write"], "write"),
                              (str(Path(data["source"]) / "pyproject.toml"), "write"), *extra_reads):
        try:
            if operation == "read":
                Path(target).read_bytes()
            elif operation == "list":
                os.listdir(target)
            else:
                fd = os.open(target, os.O_WRONLY)
                os.close(fd)  # Opening alone never modifies golden evidence.
        except OSError as exc:
            allowed = {errno.EACCES, errno.EPERM, errno.EROFS}
            if data["platform"] == "linux":
                allowed.add(errno.ENOENT)  # The outside host path is not mounted.
            if exc.errno in allowed:
                continue
            raise SessionError("protected-file denial had an unknown cause") from exc
        raise SessionError("protected-file boundary ineffective")
    if not (Path(data["source"]) / "pyproject.toml").read_bytes():
        raise SessionError("golden source is unavailable")
    scratch = scratch_root / f"probe-{os.getpid()}"
    scratch.write_bytes(b"private scratch")
    if scratch.read_bytes() != b"private scratch":
        raise SessionError("private scratch is not usable")
    scratch.unlink()
    # The product legitimately uses local IPC; network denial must not be
    # credited by making its required anonymous local channel unusable.
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        a.settimeout(0.5)
        b.settimeout(0.5)
        a.sendall(b"private-ipc")
        if b.recv(32) != b"private-ipc":
            raise SessionError("required anonymous local IPC failed")
    finally:
        a.close()
        b.close()
    _probe_network(data["platform"], data["endpoints"])


def _probe(data: dict, *, grandchild: bool = False) -> None:
    _probe_leaf(data)
    base = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())]
    # Each intermediate is its child's original parent and genuinely waits.
    roles = ("--leaf",) if grandchild else ("--leaf", "--grandchild")
    for role in roles:
        raw = _small_command([*base, role, json.dumps(data)], 10, detached=role == "--grandchild")
        if raw != b"MRK_LEAF_OK\n":
            raise SessionError("fork/exec/detached-grandchild admission failed")
    if not grandchild:
        _sudo_denial()
    print("MRK_LEAF_OK" if grandchild else "MRK_NATIVE_ISOLATION_OK", flush=True)


def _cleanup_numeric(uid: int, gid: int, kind: str, targets: list[int], deadline: float) -> None:
    """Fixed U-only signal batch.  Root, never this helper, observes finality."""
    try:
        _remaining(deadline)
        if (sys.platform != "darwin" or type(uid) is not int or type(gid) is not int
                or not 60000 <= uid < 65000 or gid != uid
                or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid)
                or _process_groups("darwin") != [gid]):
            raise SessionError("cleanup batch lacks its reserved unprivileged credentials")
        if (not isinstance(kind, str) or kind not in {"TERM", "KILL"}
                or not isinstance(targets, list) or not 1 <= len(targets) <= 4096
                or any(type(pid) is not int or not 1 < pid < 2**31 or pid == os.getpid() for pid in targets)
                or len(set(targets)) != len(targets)):
            raise SessionError("invalid fixed numerical cleanup batch")
        signum = signal.SIGTERM if kind == "TERM" else signal.SIGKILL
        for pid in targets:
            _remaining(deadline)
            try:
                os.kill(pid, signum)  # U-only; kernel rechecks even a recycled PID.
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise  # Foreign UID EPERM and unknown errors are failures.
        _remaining(deadline)
        print("MRK_CLEANUP_BATCH_ATTEMPTED", flush=True)
    except BaseException as exc:
        exc._ci_operation = "cleanup-batch"
        raise


def _fixture(name: str) -> int:
    if name in {"positive", "nonzero"}:
        print("PASS", flush=True)
        return 7 if name == "nonzero" else 0
    if name == "missing-footer":
        return 0
    if name == "streams":
        os.write(1, b"out\n")
        os.write(2, b"err\n")
        return 0
    if name == "over-limit":
        os.write(1, b"x" * 1025)
        return 0
    if name == "held-pipe":
        subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--fixture", "timeout"],
                         close_fds=True, start_new_session=True)
        return 0
    if name in {"timeout", "cancel"}:
        time.sleep(30)
        return 0
    raise SessionError("unknown fixed collector control")


def _main(argv: list[str]) -> int:
    if not argv:
        raise SessionError("this module has only fixed internal entry roles")
    if argv[0] in {"--enter", "--enter-python-full"} and len(argv) >= 7:
        platform, uid, gid, cpu, policy = argv[1:6]
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (int(uid), int(uid), int(gid), int(gid)):
            raise SessionError("trusted entry did not receive dropped numerical credentials")
        command = argv[6:]
        if argv[0] == "--enter-python-full":
            if (platform != "linux" or sys.platform != "linux" or not 60000 <= int(uid) < 65000
                    or uid != str(int(uid)) or gid != uid or cpu != "300"):
                raise SessionError("fixed Python profile has incompatible native identity/platform/CPU")
            entry = Path(__file__).resolve(strict=True)
            root = entry.parent.parent
            if (root.parent != Path("/tmp") or entry != root / "bootstrap/ci_sandbox.py"
                    or policy != str(root / "bootstrap/subject.sb") or len(command) != 12
                    or not 0 < len(command[-1]) <= 64):
                raise SessionError("fixed Python profile entry binding differs from its one source command")
            literal = command[-1]
            deadline = int(literal) if re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", literal) else float(literal)
            if command != _python_full_command(root, deadline) or _remaining(deadline) > 3300:
                raise SessionError("fixed Python profile command/deadline differs from its exact binding")
            _userns_zero(deadline=deadline)
            _limits(platform, int(cpu), profile="python-full")
        else:
            if platform == "linux":
                _userns_zero()
            _limits(platform, int(cpu))
        if "--mach-initial" in command and "--aia-offline-baseline" in command:
            raise SessionError("fixed native entry markers cannot be combined")
        if "--mach-initial" in command:
            _native_initial_entry(argv)
        elif "--aia-offline-baseline" in command:
            _native_aia_baseline_entry(argv)
        elif platform == "darwin":
            if len(command) == 7 and command[5] == "--native-write-control":
                _native_write_checkpoint(argv, outer=True)
            command = ["/usr/bin/sandbox-exec", "-f", policy, *command]
        elif platform != "linux":
            raise SessionError("unsupported platform")
        os.execve(command[0], command, dict(os.environ))
    if argv[0] == "--nss" and len(argv) == 2 and os.geteuid() == 0:
        _nss_absent(int(argv[1]))
        print("MRK_NSS_ABSENT", flush=True)
        return 0
    if argv[0] in {"--probe", "--leaf", "--grandchild"} and len(argv) == 2:
        if sys.platform == "linux":
            _userns_zero()
        data = json.loads(argv[1])
        if argv[0] == "--leaf":
            _probe_leaf(data)
            print("MRK_LEAF_OK", flush=True)
        else:
            _probe(data, grandchild=argv[0] == "--grandchild")
        return 0
    if argv[0] == "--cleanup-batch" and len(argv) == 6:
        if len(argv[4]) > 65536:
            raise SessionError("cleanup batch argument exceeds fixed bound")
        _cleanup_numeric(int(argv[1]), int(argv[2]), argv[3], json.loads(argv[4]), float(argv[5]))
        return 0
    if argv[0] == "--fixture" and len(argv) == 2:
        if sys.platform == "linux":
            _userns_zero()
        return _fixture(argv[1])
    if argv[0] in {"--write-control", "--native-write-control"} and len(argv) == 2:
        if sys.platform == "linux":
            _userns_zero()
        if argv[0] == "--native-write-control":
            _write_control(Path(argv[1]), native=True)
        else:
            _write_control(Path(argv[1]))
        return 0
    if argv[0] == "--native-read-control" and len(argv) == 3:
        _native_read_control(argv[1], float(argv[2]))
        return 0
    if argv == ["--home-positive"]:
        _home_positive()
        return 0
    if argv == ["--sentinel"] or argv == ["--signal-target"]:
        _signal_target(argv[0] == "--sentinel")
        return 0
    if argv[0] == "--observer-probe" and len(argv) == 4:
        _observer_probe(Path(argv[1]), int(argv[2]), float(argv[3]))
        return 0
    if argv[0] == "--observer-family" and len(argv) == 2:
        _observer_family(float(argv[1]))
        return 0
    if argv[0] == "--signal-case" and len(argv) == 2:
        _signal_subject(int(argv[1]))
        return 0
    if argv == ["--loss-subject"]:
        if sys.platform == "linux":
            _userns_zero()
        print("MRK_LOSS_SUBJECT_READY", flush=True)
        time.sleep(30)
        return 0
    if argv[0] == "--loss-owner" and len(argv) == 2:
        _loss_owner(json.loads(argv[1]))
    raise SessionError("unknown fixed internal entry role")


if __name__ == "__main__":
    try:
        status = _main(sys.argv[1:])
    except BaseException as exc:
        print("MRK_SANDBOX_ERROR=" + json.dumps(_exception_notes(exc), separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(status)
