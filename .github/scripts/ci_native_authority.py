"""Finite macOS admission controls; importing this module performs no probes.

Only the original hosted owner may select these immutable child roles. This is
not an application API, an arbitrary IPC client, or a network-enabled test runner.
The actual authority and ordinary policies keep their network denial. trustd's
autonomous system maintenance remains part of the OS TCB, not a task-owned worker.
"""
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace


TRUST_SERVICES = ("com.apple.trustd", "com.apple.trustd.agent")
OTHER_SERVICE = "com.apple.cfprefsd.daemon"
MACH_SERVICES = (*TRUST_SERVICES, OTHER_SERVICE)
MACH_PREFIX = b"MRK_NATIVE_MACH="
MACH_APPLY_PREFIX = b"MRK_NATIVE_MACH_APPLY="
AIA_PREFIX = b"MRK_NATIVE_AIA="
AIA_BASELINE_PREFIX = b"MRK_NATIVE_AIA_BASELINE="
_DENIED = (1100, 1102)  # NOT_PRIVILEGED / UNKNOWN_SERVICE; needs an outside positive.
_CASES = ("online", "offline", "mutant", "product-offline")
_CONTRAST_CASE = "online-full-chain-offline"
_ISSUER_ROOT_CONTRAST_CASE = "online-issuer-root-offline"
_LEAF_ISSUER_CONTRAST_CASE = "online-leaf-issuer-offline"
_AIA_BASELINE_CASE = "online-full-chain-offline-baseline"
_SIGNATURE_CASES = ("leaf-by-issuer", "issuer-by-root", "root-by-root", "issuer-signature-mutant")
_MAX_DER = 16 * 1024
_FAILURE_PREFIX = b"MRK_NATIVE_CONTROL_FAILED="
_FAILURE_ROLES = frozenset(("mach", "mach-initial", "mach-nonexpand", "aia-prepare", "aia-evaluate",
                           "aia-offline-baseline", "invalid"))
_FAILURE_CATEGORIES = frozenset(("NativeControlError", "TimeoutExpired", "KeyboardInterrupt", "SystemExit",
                               "MemoryError", "OSError", "ValueError", "TypeError", "AttributeError",
                               "AssertionError", "RuntimeError", "Exception", "BaseException"))
_REPORTED_CHILD_ERRORS = {
    b"sandbox-exec: sandbox_apply: Operation not permitted\n": ("sandbox-apply", "operation-not-permitted"),
    b"sandbox-exec: sandbox_init: Operation not permitted\n": ("sandbox-init", "operation-not-permitted"),
    b"sandbox-exec: sandbox_apply: Permission denied\n": ("sandbox-apply", "permission-denied"),
    b"sandbox-exec: sandbox_init: Permission denied\n": ("sandbox-init", "permission-denied"),
}


class NativeControlError(RuntimeError):
    """A fixed native control or its independently owned cleanup failed."""


def _valid_child_returncode(value: object) -> bool:
    return type(value) is int and -128 <= value <= 255 and value != 0


def _failure_note(error: BaseException, argv: list[str]) -> dict:
    """Closed diagnostic attribution, never messages, paths, arguments or authority.

    error_count counts reported leaf errors only. A truncated note is explicitly
    incomplete; it cannot stand in for any original capture/finality fact.
    """
    roles = {"--mach": (2, "mach"), "--mach-initial": (3, "mach-initial"),
             "--mach-nonexpand": (3, "mach-nonexpand"),
             "--aia-prepare": (3, "aia-prepare"), "--aia-evaluate": (3, "aia-evaluate"),
             "--aia-offline-baseline": (2, "aia-offline-baseline")}
    shape = roles.get(argv[0]) if type(argv) is list and argv and type(argv[0]) is str else None
    role = shape[1] if shape is not None and len(argv) == shape[0] else "invalid"
    categories = ((NativeControlError, "NativeControlError"), (subprocess.TimeoutExpired, "TimeoutExpired"),
                  (KeyboardInterrupt, "KeyboardInterrupt"), (SystemExit, "SystemExit"),
                  (MemoryError, "MemoryError"), (OSError, "OSError"), (ValueError, "ValueError"),
                  (TypeError, "TypeError"), (AttributeError, "AttributeError"),
                  (AssertionError, "AssertionError"), (RuntimeError, "RuntimeError"),
                  (Exception, "Exception"), (BaseException, "BaseException"))
    notes, pending, inspected, truncated, child_statuses = [], [error], 0, False, []
    while pending and inspected < 64 and len(notes) < 16:
        current = pending.pop()
        inspected += 1
        if isinstance(current, BaseExceptionGroup):
            space = max(0, 64 - inspected - len(pending))
            truncated |= len(current.exceptions) > space
            pending.extend(reversed(current.exceptions[:space]))
            continue
        lines, tb, frames = [], current.__traceback__, 0
        while tb is not None and frames < 64:
            if tb.tb_frame.f_code.co_filename == __file__:
                if type(tb.tb_lineno) is int and 0 < tb.tb_lineno < 10000:
                    lines.append(tb.tb_lineno)
                else:
                    truncated = True
            tb, frames = tb.tb_next, frames + 1
        lines = sorted(set(lines))
        truncated |= tb is not None or len(lines) > 8
        category = next(name for kind, name in categories if isinstance(current, kind))
        notes.append({"exception": category, "lines": lines[:8]})
        if isinstance(current, NativeControlError) and "_child_returncode" in current.__dict__:
            child_statuses.append(current.__dict__["_child_returncode"])
    result = {"schema": 1, "role": role, "error_count": len(notes),
              "truncated": bool(truncated or pending), "exceptions": notes}
    # Incomplete or multiple observations cannot identify one completed child.
    if (role == "mach-nonexpand" and not result["truncated"] and len(child_statuses) == 1
            and _valid_child_returncode(child_statuses[0])):
        result["child_returncode"] = child_statuses[0]
    return result


def _require(value: bool, message: str) -> None:
    if not value:
        raise NativeControlError(message)


def _remaining(deadline: float) -> float:
    _require(type(deadline) in (int, float) and math.isfinite(deadline), "invalid native cutoff")
    left = deadline - time.monotonic()
    _require(0 < left <= 3300, "native control cutoff expired or invalid")
    return left


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate native control field")
        result[key] = value
    return result


def _parse(data: bytes, prefix: bytes) -> dict:
    _require(type(data) is bytes and 0 < len(data) <= 4096 and data.startswith(prefix)
             and data.endswith(b"\n") and data.count(b"\n") == 1, "native control framing differs")
    try:
        value = json.loads(data[len(prefix):-1].decode("ascii"), object_pairs_hook=_object)
    except (ValueError, UnicodeError) as exc:
        raise NativeControlError("invalid native control JSON") from exc
    _require(type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1,
             "native control schema differs")
    return value


def parse_failure(data: bytes, role: str) -> dict | None:
    """One fully bounded failed-child note, never execution or success evidence."""
    if (type(role) is not str or role not in _FAILURE_ROLES
            or type(data) is not bytes or not 0 < len(data) <= 4096):
        return None
    reported = None
    if role == "mach-nonexpand":
        if data.count(_FAILURE_PREFIX) != 1:
            return None
        offset = data.find(_FAILURE_PREFIX)
        preceding, data = data[:offset], data[offset:]
        if preceding:
            reported = _REPORTED_CHILD_ERRORS.get(preceding)
            if reported is None:
                return None
    try:
        value = _parse(data, _FAILURE_PREFIX)
    except (NativeControlError, ValueError, UnicodeError, RecursionError):
        return None
    fields = {"schema", "role", "error_count", "truncated", "exceptions"}
    if role == "mach-nonexpand" and "child_returncode" in value:
        fields.add("child_returncode")
    if (set(value) != fields
            or value["role"] != role or type(value["truncated"]) is not bool
            or type(value["error_count"]) is not int or not 0 <= value["error_count"] <= 16
            or type(value["exceptions"]) is not list or len(value["exceptions"]) != value["error_count"]
            or value["error_count"] == 0 and not value["truncated"]):
        return None
    notes = []
    for row in value["exceptions"]:
        if type(row) is not dict or set(row) != {"exception", "lines"}:
            return None
        category, lines = row["exception"], row["lines"]
        if (type(category) is not str or category not in _FAILURE_CATEGORIES
                or type(lines) is not list or len(lines) > 8
                or any(type(line) is not int or not 0 < line < 10000 for line in lines)
                or lines != sorted(set(lines))):
            return None
        notes.append({"exception": category, "lines": list(lines)})
    result = {"schema": 1, "role": role, "error_count": len(notes),
              "truncated": value["truncated"], "exceptions": notes}
    if "child_returncode" in value:
        if (not _valid_child_returncode(value["child_returncode"]) or value["truncated"]
                or not any(row["exception"] == "NativeControlError" for row in notes)):
            return None
        result["child_returncode"] = value["child_returncode"]
    if reported is not None:
        # These labels classify reported text only, not a stage or kernel refusal.
        result["reported_child_stage"], result["reported_child_text"] = reported
    return result


def _mach_object(value: dict) -> dict:
    _require(type(value) is dict and set(value) == {"schema", "codes", "released"}
             and type(value["schema"]) is int and value["schema"] == 1, "Mach record fields differ")
    codes, released = value["codes"], value["released"]
    _require(type(codes) is list and type(released) is list and len(codes) == len(released) == 3,
             "Mach record inventory differs")
    for code, closed in zip(codes, released):
        _require(type(code) is int and code in (0, *_DENIED) and type(closed) is bool
                 and closed == (code == 0), "Mach result or owned-port release is unknown")
    return value


def parse_mach(data: bytes) -> dict:
    return _mach_object(_parse(data, MACH_PREFIX))


def _policy_digest(value: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             "fixed native policy digest differs")
    return value


def parse_mach_application(data: bytes, role: str) -> dict:
    _require(type(role) is str and role in {"mach-initial", "mach-nonexpand"},
             "fixed native application role differs")
    value = _parse(data, MACH_APPLY_PREFIX)
    fields = {"schema", "role", "policy_sha256", "application", "after"}
    if role == "mach-nonexpand":
        fields.update(("before", "child"))
    _require(set(value) == fields and value["role"] == role, "native application fields differ")
    _policy_digest(value["policy_sha256"])
    application = value["application"]
    _require(type(application) is dict and set(application) == {"returned", "errno"}
             and type(application["returned"]) is int, "native apply observation differs")
    returned, number = application["returned"], application["errno"]
    _require(returned == 0 and number is None
             or role == "mach-nonexpand" and returned == -1 and type(number) is int and number == errno.EPERM,
             "native apply outcome is not qualified")
    for name in ("after",) if role == "mach-initial" else ("before", "after", "child"):
        _mach_object(value[name])
    return value


def require_mach_controls(positive: dict, ordinary: dict, authority: dict, nonexpand: dict,
                          *, policy_sha256: str) -> None:
    # UNKNOWN_SERVICE is not independently denial evidence. A corresponding
    # successful same-attempt outside lookup is mandatory before any negative.
    _policy_digest(policy_sha256)
    records = [_mach_object(row) for row in (positive, ordinary)]
    applied = [parse_mach_application(MACH_APPLY_PREFIX + json.dumps(row, allow_nan=False).encode("ascii") + b"\n", role)
               for row, role in ((authority, "mach-initial"), (nonexpand, "mach-nonexpand"))]
    _require(all(row["policy_sha256"] == policy_sha256 for row in applied),
             "native applications do not match the original owner policy")
    outside, plain = [row["codes"] for row in records]
    allowed = applied[0]["after"]["codes"]
    nested = [applied[1][name]["codes"] for name in ("before", "after", "child")]
    _require(outside[2] == 0 and 0 in outside[:2], "required outside Mach positive is unavailable")
    _require(all(code in _DENIED for codes in (plain, *nested) for code in codes),
             "ordinary or nested policy expanded Mach authority")
    _require(allowed[2] in _DENIED, "authority admitted an unallowed Mach service")
    for index in range(2):
        _require(allowed[index] == outside[index], "trust-service availability changed or is denied")


def _mach_api():
    import ctypes as C

    library = C.CDLL("/usr/lib/libSystem.B.dylib")
    lookup = library.bootstrap_look_up
    lookup.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
    lookup.restype = C.c_int
    deallocate = library.mach_port_deallocate
    deallocate.argtypes, deallocate.restype = [C.c_uint32, C.c_uint32], C.c_int
    bootstrap = C.c_uint32.in_dll(library, "bootstrap_port").value
    own_task = C.c_uint32.in_dll(library, "mach_task_self_").value
    _require(bootstrap != 0 and own_task != 0, "native lookup ports are unavailable")

    def query(name):
        port = C.c_uint32()
        status = lookup(bootstrap, name.encode("ascii"), C.byref(port))
        return status, port.value

    return SimpleNamespace(lookup=query, release=lambda port: deallocate(own_task, port))


def mach_probe(deadline: float) -> dict:
    """Lookup only the three literals; never send a service request payload."""
    _remaining(deadline)
    _require(sys.platform == "darwin", "Mach controls require real macOS")
    api = _mach_api()
    codes, released, errors = [], [], []
    for name in MACH_SERVICES:
        port, status = 0, None
        try:
            _remaining(deadline)
            status, port = api.lookup(name)
            _require(status in (0, *_DENIED) and bool(port) == (status == 0),
                     "unexpected native lookup status or output right")
            codes.append(status)
        except BaseException as exc:
            errors.append(exc)
        finally:
            # Only successful lookups confer custody of this send right. An
            # invalid error output is not authority to deallocate another name.
            if status == 0 and port:
                try:
                    _require(api.release(port) == 0, "native lookup port release failed")
                    released.append(True)
                except BaseException as exc:
                    errors.append(exc)
            elif status in _DENIED and not port:
                released.append(False)
        if errors:
            raise BaseExceptionGroup("fixed Mach lookup/cleanup failed", errors)
    _remaining(deadline)
    return {"schema": 1, "codes": codes, "released": released}


def _command(arguments: list[str], deadline: float, *, capture: bool = False) -> bytes:
    """Only literal internally constructed fixture/non-expansion commands call this."""
    child, errors, output = None, [], b""
    try:
        _remaining(deadline)
        cutoff = min(deadline, time.monotonic() + 30.0)
        # Captured Mach stderr reuses the outer Session's private bounded pipe.
        child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                 stderr=None if capture else subprocess.DEVNULL, close_fds=True)
        left = _remaining(cutoff)  # Popen time cannot renew the original allowance.
        if capture:
            # The sole captured child is the finite three-lookup helper, not a
            # caller command. Its framing is checked by parse_mach afterwards.
            output, _ = child.communicate(timeout=left)
        else:
            child.wait(timeout=left)
        returncode = child.returncode
        try:
            _require(returncode == 0, "fixed native child failed")
        except NativeControlError as exc:
            if capture and _valid_child_returncode(returncode):
                exc._child_returncode = returncode
            raise
        _remaining(cutoff)
    except BaseException as exc:
        errors.append(exc)
    finally:
        if child is not None and child.returncode is None:
            try:
                child.kill()  # This original child only; never a discovered PID/group.
            except BaseException as exc:
                errors.append(exc)
            try:
                child.wait(timeout=max(0.0, min(2.0, cutoff - time.monotonic())))
            except BaseException as exc:
                errors.append(exc)
        if child is not None and child.stdout is not None:
            try:
                child.stdout.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise BaseExceptionGroup("fixed native child/cleanup failed", errors)
    _remaining(cutoff)
    return output


def _sandbox_api():
    """Fixed verification-only private SPI; missing current-image support fails."""
    import ctypes as C

    _require(sys.platform == "darwin" and C.sizeof(C.c_void_p) == 8 and C.sizeof(C.c_int) == 4,
             "native sandbox SPI requires the reviewed Darwin pointer/integer ABI")
    # Apple OS/dyld premise, not a filesystem hash for a shared-cache image.
    library = C.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
    P = C.c_void_p

    def bind(name, result, arguments):
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
        return function

    return SimpleNamespace(
        create_params=bind("sandbox_create_params", P, []),
        compile_string=bind("sandbox_compile_string", P, [C.c_char_p, P, C.POINTER(P)]),
        apply=bind("sandbox_apply", C.c_int, [P]),
        free_profile=bind("sandbox_free_profile", None, [P]),
        free_params=bind("sandbox_free_params", None, [P]),
        free_error=bind("sandbox_free_error", None, [P]),
        new_error=P, error_argument=C.byref, set_errno=C.set_errno, get_errno=C.get_errno)


def _opaque_pointer(value: object) -> bool:
    return type(value) is int and 0 < value < 2**64


def _apply_policy(raw: bytes, deadline: float, *, initial: bool) -> dict:
    """Apply a genuinely compiled profile; every original pointer is retired."""
    _remaining(deadline)
    _require(type(initial) is bool and type(raw) is bytes and 0 < len(raw) <= 1024 * 1024
             and raw.isascii() and b"\0" not in raw, "fixed native policy source differs")
    api, params, profile, error, application, errors = None, None, None, None, None, []
    try:
        api = _sandbox_api()
        _remaining(deadline)
        error = api.new_error()
        _require(error.value is None, "compiler error output is not initially empty")
        params = api.create_params()
        _require(_opaque_pointer(params), "native sandbox parameter creation failed")
        _remaining(deadline)
        profile = api.compile_string(raw, params, api.error_argument(error))
        _require(_opaque_pointer(profile) and error.value is None,
                 "native sandbox compilation did not return one complete profile")
        _remaining(deadline)
        api.set_errno(0)
        returned = api.apply(profile)
        number = api.get_errno()  # Before any clock, release or other native call.
        _require(type(returned) is int and returned in (0, -1), "native sandbox apply returned unknown status")
        if returned == 0:
            application = {"returned": 0, "errno": None}  # errno is unspecified on success.
        else:
            _require(not initial and type(number) is int and number == errno.EPERM,
                     "native sandbox application was not a qualified permission refusal")
            application = {"returned": -1, "errno": number}
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    finally:
        # Expiry is retained, never an excuse to skip a known pointer's release.
        try:
            _remaining(deadline)
        except BaseException as exc:
            errors.append(exc)
        for name, pointer in (("free_profile", profile), ("free_error", error), ("free_params", params)):
            try:
                value = pointer.value if name == "free_error" and pointer is not None else pointer
                if value is not None:
                    _require(_opaque_pointer(value), "native sandbox cleanup pointer is unknown")
                    getattr(api, name)(value)
            except BaseException as exc:
                errors.append(exc)
            finally:
                try:
                    _remaining(deadline)
                except BaseException as exc:
                    errors.append(exc)
    if errors:
        raise BaseExceptionGroup("fixed native sandbox application/cleanup failed", errors)
    _require(application is not None, "native sandbox application did not complete")
    return application


def _mach_policy(policy: Path, deadline: float) -> bytes:
    _remaining(deadline)
    _require(sys.platform == "darwin", "native policy application requires real macOS")
    entry = Path(__file__).resolve(strict=True)
    wanted = entry.parent / "native-authority-source.sb"
    _require(entry.name == "ci_native_authority.py" and entry.parent.name == "bootstrap"
             and entry.parent.parent.parent == Path("/private/tmp")
             and policy == wanted and policy.resolve(strict=True) == wanted,
             "native application policy is not the fixed owner input")
    raw = _read_public(policy, 1024 * 1024, immutable_policy=True)
    _require(raw.isascii() and b"\0" not in raw, "native policy source is not complete ASCII")
    _remaining(deadline)
    return raw


def mach_initial(policy: Path, deadline: float) -> dict:
    # The sole initial-role entry applies before any service or product probe.
    raw = _mach_policy(policy, deadline)
    application = _apply_policy(raw, deadline, initial=True)
    after = _mach_object(mach_probe(deadline))
    _remaining(deadline)
    return {"schema": 1, "role": "mach-initial", "policy_sha256": hashlib.sha256(raw).hexdigest(),
            "application": application, "after": after}


def mach_nonexpand(policy: Path, deadline: float) -> dict:
    raw = _mach_policy(policy, deadline)
    before = _mach_object(mach_probe(deadline))
    _require(all(code in _DENIED for code in before["codes"]), "initial ordinary Mach authority differs")
    application = _apply_policy(raw, deadline, initial=False)
    after = _mach_object(mach_probe(deadline))
    _require(all(code in _DENIED for code in after["codes"]), "native application expanded Mach authority")
    # This actual exec-child inherits the result; it does not retry application.
    result = _command([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve(strict=True)),
                       "--mach", repr(deadline)], deadline, capture=True)
    child = parse_mach(result)
    _require(all(code in _DENIED for code in child["codes"]), "inherited child expanded Mach authority")
    _remaining(deadline)
    return {"schema": 1, "role": "mach-nonexpand", "policy_sha256": hashlib.sha256(raw).hexdigest(),
            "application": application, "before": before, "after": after, "child": child}


def _port(value: int) -> int:
    _require(type(value) is int and 1024 <= value <= 65535, "invalid owned loopback port")
    return value


def _read_public(path: Path, maximum: int = _MAX_DER, *, immutable_policy: bool = False) -> bytes:
    """Bounded no-follow read after the Session's original wait/UID finality."""
    _require(type(immutable_policy) is bool, "unknown fixed native read role")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    errors, result = [], b""
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not stat.S_IMODE(before.st_mode) & 0o022 and 0 < before.st_size <= maximum,
                 "synthetic public fixture type/mode/size differs")
        if immutable_policy:
            _require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, 0, 0o444),
                     "fixed native policy descriptor ownership/mode differs")
        result = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        _require(0 < len(result) == before.st_size <= maximum
                 and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 "synthetic public fixture changed during read")
        if immutable_policy:
            fields = ("st_mode", "st_uid", "st_gid", "st_nlink")
            _require(all(getattr(before, name) == getattr(after, name) for name in fields),
                     "fixed native policy descriptor custody changed during read")
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic fixture read/close failed", errors)
    return result


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    errors = []
    try:
        _require(os.write(fd, data) == len(data), "synthetic fixture write was incomplete")
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic fixture write/close failed", errors)


def _scratch(path: Path) -> Path:
    _require(path.is_absolute() and path == path.resolve(strict=True) and path.name == "probes"
             and path.parent.name == "native-authority-source" and path.parent.parent.name == "work"
             and path.parent.parent.parent.parent == Path("/private/tmp"), "native control scratch differs")
    state = path.lstat()
    _require(stat.S_ISDIR(state.st_mode) and stat.S_IMODE(state.st_mode) == 0o700
             and 60000 <= state.st_uid < 65000 and state.st_gid == state.st_uid,
             "native control scratch custody differs")
    return path


def _route(nonce: str, case: str) -> str:
    _require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None and case in _CASES,
             "synthetic issuer path differs")
    return f"/mrk-aia/{nonce}/{case}.der"


def prepare_aia(port: int, deadline: float) -> None:
    """Four independent tiny RSA chains; no trust API evaluates them here."""
    _port(port)
    _remaining(deadline)
    work = _scratch(Path.cwd())
    _require(not tuple(work.iterdir()), "native fixture scratch is not fresh and empty")
    rows = []
    for case in _CASES:
        _remaining(deadline)
        nonce = secrets.token_hex(16)
        url = f"http://127.0.0.1:{port}" + _route(nonce, case)
        config = work / f"{case}.cnf"
        _write_new(config, ("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=unused\n"
                           "[root]\nbasicConstraints=critical,CA:true,pathlen:1\n"
                           "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                           "[issuer]\nbasicConstraints=critical,CA:true,pathlen:0\n"
                           "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                           "authorityKeyIdentifier=keyid:always\n[leaf]\n"
                           "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n"
                           "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                           f"authorityInfoAccess=caIssuers;URI:{url}\n").encode("ascii"))
        temporary = [config]
        for index, role in enumerate(("root", "issuer", "leaf")):
            stem = work / f"{case}-{role}"
            key, pem, csr = Path(str(stem) + ".key"), Path(str(stem) + ".pem"), Path(str(stem) + ".csr")
            temporary.extend((key, pem))
            subject = f"/CN=MRK synthetic {role} {nonce}"
            args = ["/usr/bin/openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                    "-config", str(config), "-subj", subject, "-keyout", str(key)]
            if role == "root":
                args += ["-x509", "-days", "1", "-set_serial", "1", "-extensions", "root", "-out", str(pem)]
            else:
                args += ["-out", str(csr)]
                temporary.append(csr)
            _command(args, deadline)
            if role != "root":
                parent = work / f"{case}-{'root' if role == 'issuer' else 'issuer'}"
                _command(["/usr/bin/openssl", "x509", "-req", "-in", str(csr), "-CA", str(parent) + ".pem",
                          "-CAkey", str(parent) + ".key", "-set_serial", str(index + 1), "-days", "1", "-sha256",
                          "-extfile", str(config), "-extensions", role, "-out", str(pem)], deadline)
            _command(["/usr/bin/openssl", "x509", "-in", str(pem), "-outform", "DER",
                      "-out", str(stem) + ".der"], deadline)
        # A malformed negative fixture must not masquerade as missing-issuer
        # evidence. This check does not populate Security.framework's caches.
        _command(["/usr/bin/openssl", "verify", "-CAfile", str(work / f"{case}-root.pem"),
                  "-untrusted", str(work / f"{case}-issuer.pem"), str(work / f"{case}-leaf.pem")], deadline)
        rows.append({"case": case, "nonce": nonce, **{
            role: hashlib.sha256(_read_public(work / f"{case}-{role}.der")).hexdigest()
            for role in ("root", "issuer", "leaf")}})
        # The fresh exclusive scratch and every original completed fixed child
        # establish these precise outputs as ours. Keep only public DER/manifest.
        errors = []
        for path in temporary:
            try:
                state = path.lstat()
                _require(stat.S_ISREG(state.st_mode) and state.st_nlink == 1 and state.st_uid == os.getuid(),
                         "synthetic temporary output custody differs")
                path.unlink()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("synthetic temporary output cleanup failed", errors)
    _write_new(work / "aia.json", json.dumps({"schema": 1, "port": port, "cases": rows},
                                            sort_keys=True, separators=(",", ":")).encode("ascii"))
    _remaining(deadline)


def _fixtures(work: Path, port: int, deadline: float) -> list[dict]:
    _scratch(work)
    _port(port)
    _remaining(deadline)
    try:
        manifest = json.loads(_read_public(work / "aia.json", 4096).decode("ascii"), object_pairs_hook=_object)
    except (ValueError, UnicodeError) as exc:
        raise NativeControlError("synthetic fixture manifest is invalid") from exc
    _require(type(manifest) is dict and set(manifest) == {"schema", "port", "cases"}
             and type(manifest["schema"]) is int and manifest["schema"] == 1
             and type(manifest["port"]) is int and manifest["port"] == port
             and type(manifest["cases"]) is list and len(manifest["cases"]) == 4,
             "synthetic fixture manifest contract differs")
    records, hashes, nonces = [], set(), set()
    for name, row in zip(_CASES, manifest["cases"]):
        _remaining(deadline)
        _require(type(row) is dict and set(row) == {"case", "nonce", "root", "issuer", "leaf"}
                 and row["case"] == name, "synthetic fixture inventory differs")
        route = _route(row["nonce"], name)
        _require(row["nonce"] not in nonces, "synthetic issuer path was reused")
        nonces.add(row["nonce"])
        record = {"case": name, "route": route}
        for role in ("root", "issuer", "leaf"):
            data = _read_public(work / f"{name}-{role}.der")
            digest = hashlib.sha256(data).hexdigest()
            _require(data.startswith(b"\x30") and row[role] == digest and digest not in hashes,
                     "synthetic chain bytes changed or were reused")
            hashes.add(digest)
            record[role] = data
        records.append(record)
    _remaining(deadline)
    return records


def _baseline_tuple(originals: tuple) -> tuple[bytes, bytes, bytes]:
    """One ordered public-DER triple, not caller-selected paths or trust authority."""
    _require(type(originals) is tuple and len(originals) == 3
             and all(type(raw) is bytes and 0 < len(raw) <= _MAX_DER and raw.startswith(b"\x30")
                     for raw in originals) and len(set(originals)) == 3,
             "native baseline original DER inventory differs")
    return originals


def _baseline_der(deadline: float) -> tuple[bytes, bytes, bytes]:
    """Read only the original owner's three immutable fixed bootstrap snapshots."""
    _remaining(deadline)
    entry = Path(__file__)
    _require(entry.is_absolute() and entry == entry.resolve(strict=True)
             and entry.name == "ci_native_authority.py" and entry.parent.name == "bootstrap"
             and entry.parent.parent.parent == Path("/private/tmp"), "native baseline helper origin differs")

    def identity(path):
        _remaining(deadline)
        info = path.lstat()
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    originals, pins = [], []
    for path in (entry.parent.parent, entry.parent, entry):
        node = identity(path)
        regular = path == entry
        _require((stat.S_ISREG(node[2]) if regular else stat.S_ISDIR(node[2]))
                 and node[3:5] == (0, 0) and stat.S_IMODE(node[2]) == (0o444 if regular else 0o755)
                 and (not regular or node[5] == 1), "native baseline immutable origin custody differs")
        pins.append((path, node))
    for role in ("leaf", "issuer", "root"):
        path = entry.parent / f"native-aia-baseline-{role}.der"
        _remaining(deadline)
        _require(path == path.resolve(strict=True), "native baseline snapshot has an alias")
        node = identity(path)
        _require(stat.S_ISREG(node[2]) and node[3:5] == (0, 0) and stat.S_IMODE(node[2]) == 0o444
                 and node[5] == 1 and 0 < node[6] <= _MAX_DER, "native baseline snapshot custody differs")
        _remaining(deadline)
        raw = _read_public(path, immutable_policy=True)
        _remaining(deadline)
        _require(identity(path) == node, "native baseline snapshot name changed during read")
        originals.append(raw)
    for path, node in pins:
        _require(identity(path) == node, "native baseline immutable origin changed during read")
    _remaining(deadline)
    return _baseline_tuple(tuple(originals))


def _signature_envelope(raw: bytes) -> tuple[bytes, bytes]:
    """Extract original signed bytes for the fixed generated RSA/SHA256 profile.

    Later TBSCertificate fields remain opaque. This is not a general certificate
    parser or a validity oracle; the original native evaluations parse the DER.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_DER, "synthetic signature envelope size differs")

    def field(start: int, tag: int, limit: int) -> tuple[int, int]:
        _require(0 <= start < limit <= len(raw) and start + 2 <= limit and raw[start] == tag,
                 "synthetic signature envelope tag or bound differs")
        size, content = raw[start + 1], start + 2
        if size & 0x80:
            count = size & 0x7f
            _require(count in (1, 2) and content + count <= limit and raw[content] != 0,
                     "synthetic signature envelope length differs")
            size = int.from_bytes(raw[content:content + count], "big")
            _require(size >= 128 and (count == 1 or size >= 256),
                     "synthetic signature envelope length is not minimal")
            content += count
        _require(content + size <= limit, "synthetic signature envelope crosses its enclosing bound")
        return content, content + size

    body, end = field(0, 0x30, len(raw))
    _require(end == len(raw), "synthetic signature envelope has trailing bytes")
    tbs, tbs_end = field(body, 0x30, end)
    version = b"\xa0\x03\x02\x01\x02"
    _require(tbs + len(version) <= tbs_end and raw[tbs:tbs + len(version)] == version,
             "synthetic signature envelope version differs")
    serial, serial_end = field(tbs + len(version), 0x02, tbs_end)
    value = raw[serial:serial_end]
    _require(0 < len(value) <= 20 and not value[0] & 0x80 and any(value)
             and (len(value) == 1 or value[0] != 0 or value[1] & 0x80),
             "synthetic signature envelope serial differs")
    algorithm = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
    _require(serial_end + len(algorithm) <= tbs_end
             and raw[serial_end:serial_end + len(algorithm)] == algorithm
             and tbs_end + len(algorithm) <= end and raw[tbs_end:tbs_end + len(algorithm)] == algorithm,
             "synthetic signature envelope algorithm differs")
    signature, signature_end = field(tbs_end + len(algorithm), 0x03, end)
    _require(signature_end == end and signature_end - signature == 257 and raw[signature] == 0,
             "synthetic signature envelope bit string differs")
    return raw[body:tbs_end], raw[signature + 1:signature_end]


class _Trust:
    """One fresh real BasicX509 trust object, with explicit CF reference custody."""

    def __init__(self, leaf: bytes, root: bytes, *, issuer: bytes | None = None):
        import ctypes as C

        self.C, self.owned = C, []
        security = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        foundation = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.security, self.foundation = security, foundation
        self.error_observation = {"status": "unavailable", "code": None}
        P = C.c_void_p

        def bind(library, name, result, arguments):
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            return function

        self.release = bind(foundation, "CFRelease", None, [P])
        self.data_create = bind(foundation, "CFDataCreate", P, [P, P, C.c_long])
        self.data_length = bind(foundation, "CFDataGetLength", C.c_long, [P])
        self.data_bytes = bind(foundation, "CFDataGetBytePtr", P, [P])
        self.array_create = bind(foundation, "CFArrayCreate", P, [P, P, C.c_long, P])
        self.array_count = bind(foundation, "CFArrayGetCount", C.c_long, [P])
        self.array_item = bind(foundation, "CFArrayGetValueAtIndex", P, [P, C.c_long])
        self.cert_create = bind(security, "SecCertificateCreateWithData", P, [P, P])
        self.cert_data = bind(security, "SecCertificateCopyData", P, [P])
        policy_create = bind(security, "SecPolicyCreateBasicX509", P, [])
        trust_create = bind(security, "SecTrustCreateWithCertificates", C.c_int32, [P, P, C.POINTER(P)])
        anchors = bind(security, "SecTrustSetAnchorCertificates", C.c_int32, [P, P])
        anchors_only = bind(security, "SecTrustSetAnchorCertificatesOnly", C.c_int32, [P, C.c_ubyte])
        self.network_set = bind(security, "SecTrustSetNetworkFetchAllowed", C.c_int32, [P, C.c_ubyte])
        self.keychains_set = bind(security, "SecTrustSetKeychainsAllowed", C.c_int32, [P, C.c_ubyte])
        self.network_get = bind(security, "SecTrustGetNetworkFetchAllowed", C.c_int32, [P, C.POINTER(C.c_ubyte)])
        self.keychains_get = bind(security, "SecTrustGetKeychainsAllowed", C.c_int32, [P, C.POINTER(C.c_ubyte)])
        self.native_evaluate = bind(security, "SecTrustEvaluateWithError", C.c_bool, [P, C.POINTER(P)])
        self.trust_result = bind(security, "SecTrustGetTrustResult", C.c_int32, [P, C.POINTER(C.c_uint32)])
        self.copy_chain = bind(security, "SecTrustCopyCertificateChain", P, [P])
        try:
            policy = self._own(policy_create())
            # All four original cases present only the leaf. A separate
            # post-original offline contrast supplies the complete same chain.
            certificates = [self._certificate(leaf)]
            if issuer is not None:
                certificates.extend((self._certificate(issuer), self._certificate(root)))
            presented = self._array(certificates)
            pointer = P()
            try:
                status = trust_create(presented, policy, C.byref(pointer))
            finally:
                if pointer.value:
                    self.owned.append(pointer.value)
            _require(status == 0 and bool(pointer.value), "native trust creation failed")
            self.trust = pointer.value
            _require(anchors(self.trust, self._array([self._certificate(root)])) == 0
                     and anchors_only(self.trust, 1) == 0, "native synthetic anchor settings failed")
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup("native trust creation/cleanup failed", [original, cleanup])
            raise

    def _own(self, value):
        _require(bool(value), "native CF allocation failed")
        self.owned.append(value)
        return value

    def _certificate(self, raw):
        return self._own(self.cert_create(None, self._own(self.data_create(None, raw, len(raw)))))

    def _array(self, values):
        return self._own(self.array_create(None, (self.C.c_void_p * len(values))(*values), len(values), None))

    def set_network(self, allowed: bool) -> None:
        _require(self.network_set(self.trust, int(allowed)) == 0, "native network setter failed")

    def set_keychains(self, allowed: bool) -> None:
        _require(self.keychains_set(self.trust, int(allowed)) == 0, "native keychain setter failed")

    def get_network(self) -> bool:
        return self._get(self.network_get)

    def get_keychains(self) -> bool:
        return self._get(self.keychains_get)

    def _get(self, getter) -> bool:
        value = self.C.c_ubyte(2)
        _require(getter(self.trust, self.C.byref(value)) == 0 and value.value in (0, 1),
                 "native trust getter failed")
        return bool(value.value)

    def _error_observation(self, error) -> dict:
        """Public scalars from the original owned CFError, never trust authority."""
        if not error:
            return {"status": "no-error", "code": None}
        unavailable = {"status": "unavailable", "code": None}
        try:
            C, foundation = self.C, self.foundation
            P = C.c_void_p
            # Get-rule domain and the public pointer-valued constant are borrowed.
            # Resolve lazily so unavailable diagnostics do not fail a native result.
            domain_get = foundation.CFErrorGetDomain
            domain_get.restype, domain_get.argtypes = P, [P]
            equal = foundation.CFEqual
            equal.restype, equal.argtypes = C.c_ubyte, [P, P]
            domain = domain_get(error)
            osstatus = P.in_dll(foundation, "kCFErrorDomainOSStatus").value
            if not domain or not osstatus:
                return unavailable
            matches = equal(domain, osstatus)
            if type(matches) is not int or matches not in (0, 1):
                return unavailable
            if not matches:
                return {"status": "other-domain", "code": None}
            code_get = foundation.CFErrorGetCode
            code_get.restype, code_get.argtypes = C.c_long, [P]
            code = code_get(error)
            if type(code) is not int or not -(2**31) <= code < 2**31:
                return unavailable
            return {"status": "osstatus", "code": code}
        except Exception:
            # Cancellation/SystemExit still reaches the original CF cleanup owner.
            return unavailable

    def _signature_observation(self, fixture: dict) -> dict:
        """Finite public-key checks, not trust-service or certificate-path authority."""
        unavailable = {"available": False, "keys": None, "checks": None}
        try:
            _require(fixture["case"] == "online", "native signature fixture differs")
            envelopes = {role: _signature_envelope(fixture[role]) for role in ("leaf", "issuer", "root")}
            C, security = self.C, self.security
            P = C.c_void_p

            def bind(name, result, arguments):
                function = getattr(security, name)
                function.restype, function.argtypes = result, arguments
                return function

            copy_key = bind("SecCertificateCopyKey", P, [P])
            block_size = bind("SecKeyGetBlockSize", C.c_size_t, [P])
            supported = bind("SecKeyIsAlgorithmSupported", C.c_ubyte, [P, C.c_long, P])
            verify = bind("SecKeyVerifySignature", C.c_ubyte, [P, P, P, P, C.POINTER(P)])
            algorithm = P.in_dll(security, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256").value
            _require(_opaque_pointer(algorithm), "native signature algorithm is unavailable")
            keys, pointers, checks = [], {}, []
            for name in ("issuer", "root"):
                key = copy_key(self._certificate(fixture[name]))
                _require(key is None or _opaque_pointer(key), "native copied key shape differs")
                if key is None:
                    keys.append({"key": name, "present": False, "block_bytes": None, "verify_supported": None})
                    continue
                self._own(key)
                size = block_size(key)
                _require(type(size) is int and 0 <= size <= _MAX_DER, "native key block size differs")
                allowed = supported(key, 1, algorithm)  # Public kSecKeyOperationTypeVerify.
                _require(type(allowed) is int and allowed in (0, 1), "native signature support shape differs")
                keys.append({"key": name, "present": True, "block_bytes": size, "verify_supported": bool(allowed)})
                if size == 256 and allowed == 1:
                    pointers[name] = key
            for case, role, name in zip(_SIGNATURE_CASES, ("leaf", "issuer", "root", "issuer"),
                                        ("issuer", "root", "root", "root")):
                if name not in pointers:
                    checks.append({"case": case, "executed": False, "accepted": None, "error": None,
                                   "trust_error": None})
                    continue
                message, signature = envelopes[role]
                if case == "issuer-signature-mutant":
                    signature = signature[:-1] + bytes((signature[-1] ^ 1,))
                message_data = self._own(self.data_create(None, message, len(message)))
                signature_data = self._own(self.data_create(None, signature, len(signature)))
                error = P()
                try:
                    accepted = verify(pointers[name], algorithm, message_data, signature_data, C.byref(error))
                finally:
                    # Copy/Create outputs and after-effect error outputs remain
                    # in the original trust owner until its independent close.
                    if error.value:
                        self.owned.append(error.value)
                _require(type(accepted) is int and accepted in (0, 1), "native signature result shape differs")
                checks.append({"case": case, "executed": True, "accepted": bool(accepted),
                               "error": bool(error.value), "trust_error": self._error_observation(error.value)})
            return {"available": True, "keys": keys, "checks": checks}
        except Exception:
            # Do not overwrite the original evaluation's error observation.
            # Cancellation/SystemExit and actual eventual close errors propagate.
            return unavailable

    def evaluate(self) -> dict:
        error = self.C.c_void_p()
        try:
            accepted = self.native_evaluate(self.trust, self.C.byref(error))
        finally:
            if error.value:
                self.owned.append(error.value)
        result = self.C.c_uint32()
        _require(self.trust_result(self.trust, self.C.byref(result)) == 0, "native trust result is unavailable")
        chain = self._own(self.copy_chain(self.trust))
        count = self.array_count(chain)
        _require(1 <= count <= 3, "native synthetic chain length differs")
        hashes = []
        for index in range(count):
            certificate = self.array_item(chain, index)
            _require(bool(certificate), "native synthetic chain item is unavailable")
            raw = self._own(self.cert_data(certificate))
            size, location = self.data_length(raw), self.data_bytes(raw)
            _require(0 < size <= _MAX_DER and bool(location), "native synthetic chain encoding differs")
            hashes.append(hashlib.sha256(self.C.string_at(location, size)).hexdigest())
        self.error_observation = self._error_observation(error.value)
        return {"accepted": bool(accepted), "error": bool(error.value), "result": result.value, "chain": hashes}

    def close(self) -> None:
        errors = []
        while self.owned:
            value = self.owned.pop()
            try:
                self.release(value)
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native CF reference cleanup failed", errors)


def _evaluate_case(fixture: dict, deadline: float, observations: list[dict] | None = None) -> dict:
    trust, errors, row = None, [], None
    case = fixture["case"]
    _require(case in _CASES, "unknown fixed AIA case")
    try:
        _remaining(deadline)
        trust = _Trust(fixture["leaf"], fixture["root"])
        # BasicX509 itself defaults offline. R2 deliberately establishes the
        # SAME enabled baseline for all four, never a mutant-only enabling call.
        trust.set_network(True)
        _require(trust.get_network() is True, "native AIA enabled baseline failed")
        keys = case != "product-offline"
        trust.set_keychains(keys)
        if case in ("offline", "product-offline"):
            trust.set_network(False)
        # The mutant omits only that final disable; not a product-default claim.
        network, keychains = trust.get_network(), trust.get_keychains()
        _require(network is (case in ("online", "mutant")) and keychains is keys,
                 "native AIA final getter differs")
        _remaining(deadline)
        result = trust.evaluate()
        _remaining(deadline)
        row = {"case": case, "baseline_network": True, "network": network, "keychains": keychains, **result}
    except BaseException as exc:
        errors.append(exc)
    finally:
        if trust is not None:
            try:
                trust.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native AIA evaluation/cleanup failed", errors)
    _remaining(deadline)
    if observations is not None:
        # Only detached Python values survive close; no getter uses a retired ref.
        observations.append({"case": case, **trust.error_observation})
    return row


def _evaluate_offline_contrast(fixture: dict, deadline: float, *, role: str = "full") -> tuple[dict, dict | None]:
    """Fixed fresh offline comparisons, strictly after all original case closes."""
    _require(fixture["case"] == "online" and type(role) is str and role in ("full", "issuer-root", "leaf-issuer"),
             "native offline contrast fixture or role differs")
    trust, errors, result, crypto = None, [], None, None
    try:
        _remaining(deadline)
        if role == "full":
            trust = _Trust(fixture["leaf"], fixture["root"], issuer=fixture["issuer"])
        elif role == "issuer-root":
            trust = _Trust(fixture["issuer"], fixture["root"])
        else:
            trust = _Trust(fixture["leaf"], fixture["issuer"])
        trust.set_network(False)
        trust.set_keychains(False)
        network, keychains = trust.get_network(), trust.get_keychains()
        _require(network is False and keychains is False, "native full-chain contrast getters differ")
        _remaining(deadline)
        result = trust.evaluate()
        _remaining(deadline)
        if role == "full":
            crypto = trust._signature_observation(fixture)
            _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    finally:
        if trust is not None:
            try:
                trust.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native full-chain contrast/cleanup failed", errors)
    _remaining(deadline)
    case = {"full": _CONTRAST_CASE, "issuer-root": _ISSUER_ROOT_CONTRAST_CASE,
            "leaf-issuer": _LEAF_ISSUER_CONTRAST_CASE}[role]
    return ({"case": case,
             "network": network, "keychains": keychains, **result,
             "trust_error": dict(trust.error_observation)}, crypto)


def evaluate_aia(port: int, deadline: float) -> dict:
    fixtures = _fixtures(Path.cwd(), port, deadline)
    observations = []
    cases = [_evaluate_case(fixture, deadline, observations) for fixture in fixtures]
    contrast, crypto = _evaluate_offline_contrast(fixtures[0], deadline)
    issuer_contrast, _ = _evaluate_offline_contrast(fixtures[0], deadline, role="issuer-root")
    leaf_contrast, _ = _evaluate_offline_contrast(fixtures[0], deadline, role="leaf-issuer")
    return {"schema": 1, "cases": cases, "error_observations": observations,
            "chain_observations": {"contrasts": [contrast, issuer_contrast, leaf_contrast], "crypto": crypto}}


def evaluate_aia_baseline(deadline: float) -> dict:
    """One fixed full-chain observation; never replay originals, signatures or sockets."""
    leaf, issuer, root = _baseline_der(deadline)
    trust, errors, result = None, [], None
    try:
        _remaining(deadline)
        trust = _Trust(leaf, root, issuer=issuer)
        trust.set_network(False)
        trust.set_keychains(False)
        network, keychains = trust.get_network(), trust.get_keychains()
        _require(network is False and keychains is False, "native baseline getters differ")
        _remaining(deadline)
        result = trust.evaluate()
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    finally:
        if trust is not None:
            try:
                trust.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native baseline evaluation/cleanup failed", errors)
    _remaining(deadline)
    return {"schema": 1, "case": _AIA_BASELINE_CASE, "network": network, "keychains": keychains,
            **result, "trust_error": dict(trust.error_observation)}


def _aia_record(data: bytes) -> tuple[dict, list[dict], dict | None]:
    """Recognize only closed optional diagnostic extensions, not new authority."""
    record = _parse(data, AIA_PREFIX)
    observations = [{"case": case, "status": "unavailable", "code": None} for case in _CASES]
    if "error_observations" in record:
        observations = record.pop("error_observations")
        _require(type(observations) is list and len(observations) == len(_CASES),
                 "native AIA diagnostic inventory differs")
        for case, row in zip(_CASES, observations):
            _require(type(row) is dict and set(row) == {"case", "status", "code"}
                     and type(row["case"]) is str and row["case"] == case
                     and type(row["status"]) is str
                     and row["status"] in {"no-error", "osstatus", "other-domain", "unavailable"},
                     "native AIA diagnostic fields differ")
            _require(type(row["code"]) is int and -(2**31) <= row["code"] < 2**31
                     if row["status"] == "osstatus" else row["code"] is None,
                     "native AIA diagnostic code differs")
    chains = None
    if "chain_observations" in record:
        chains = record.pop("chain_observations")
        _require(type(chains) is dict and set(chains) == {"contrasts", "crypto"}
                 and type(chains["contrasts"]) is list and len(chains["contrasts"]) == 3,
                 "native AIA chain diagnostic inventory differs")

        def check_error(error):
            _require(type(error) is dict and set(error) == {"status", "code"}
                     and type(error["status"]) is str
                     and error["status"] in {"no-error", "osstatus", "other-domain", "unavailable"},
                     "native AIA contrast error fields differ")
            _require(type(error["code"]) is int and -(2**31) <= error["code"] < 2**31
                     if error["status"] == "osstatus" else error["code"] is None,
                     "native AIA contrast error code differs")

        for case, row, maximum in zip((_CONTRAST_CASE, _ISSUER_ROOT_CONTRAST_CASE, _LEAF_ISSUER_CONTRAST_CASE),
                                     chains["contrasts"], (3, 2, 2)):
            bools = ("network", "keychains", "accepted", "error")
            _require(type(row) is dict and set(row) == {"case", *bools, "result", "chain", "trust_error"}
                     and type(row["case"]) is str and row["case"] == case
                     and all(type(row[key]) is bool for key in bools)
                     and type(row["result"]) is int and 0 <= row["result"] <= 0xffffffff
                     and type(row["chain"]) is list and 1 <= len(row["chain"]) <= maximum
                     and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                             for value in row["chain"]), "native AIA contrast observation differs")
            check_error(row["trust_error"])
        crypto = chains["crypto"]
        _require(type(crypto) is dict and set(crypto) == {"available", "keys", "checks"}
                 and type(crypto["available"]) is bool, "native signature observation fields differ")
        if not crypto["available"]:
            _require(crypto["keys"] is None and crypto["checks"] is None, "unavailable native signature observation differs")
        else:
            _require(type(crypto["keys"]) is list and len(crypto["keys"]) == 2
                     and type(crypto["checks"]) is list and len(crypto["checks"]) == 4,
                     "native signature observation inventory differs")
            eligible = {}
            for name, row in zip(("issuer", "root"), crypto["keys"]):
                _require(type(row) is dict and set(row) == {"key", "present", "block_bytes", "verify_supported"}
                         and type(row["key"]) is str and row["key"] == name and type(row["present"]) is bool,
                         "native key observation fields differ")
                if row["present"]:
                    _require(type(row["block_bytes"]) is int and 0 <= row["block_bytes"] <= _MAX_DER
                             and type(row["verify_supported"]) is bool, "native key observation shape differs")
                else:
                    _require(row["block_bytes"] is None and row["verify_supported"] is None,
                             "absent native key observation differs")
                eligible[name] = row["present"] and row["block_bytes"] == 256 and row["verify_supported"]
            for case, name, row in zip(_SIGNATURE_CASES, ("issuer", "root", "root", "root"), crypto["checks"]):
                _require(type(row) is dict and set(row) == {"case", "executed", "accepted", "error", "trust_error"}
                         and type(row["case"]) is str and row["case"] == case and type(row["executed"]) is bool
                         and row["executed"] is eligible[name], "native signature check fields or eligibility differ")
                if row["executed"]:
                    _require(type(row["accepted"]) is bool and type(row["error"]) is bool,
                             "executed native signature result differs")
                    check_error(row["trust_error"])
                else:
                    _require(row["accepted"] is None and row["error"] is None and row["trust_error"] is None,
                             "unexecuted native signature result differs")
    return record, observations, chains


def require_aia_controls(data: bytes, fixtures: list[dict], requests: list[tuple[str, str]]) -> dict:
    record, _observations, _chains = _aia_record(data)
    _require(set(record) == {"schema", "cases"} and type(record["cases"]) is list
             and len(record["cases"]) == len(fixtures) == 4, "native AIA result inventory differs")
    expected_requests, counts = [], []
    for case, row, fixture in zip(_CASES, record["cases"], fixtures):
        _require(type(row) is dict and set(row) == {"case", "baseline_network", "network", "keychains",
                                                   "accepted", "error", "result", "chain"}
                 and row["case"] == fixture["case"] == case, "native AIA result fields differ")
        for key in ("baseline_network", "network", "keychains", "accepted", "error"):
            _require(type(row[key]) is bool, "native AIA boolean result differs")
        online = case in ("online", "mutant")
        chain = [hashlib.sha256(fixture[role]).hexdigest()
                 for role in (("leaf", "issuer", "root") if online else ("leaf",))]
        _require(row["baseline_network"] and row["network"] is online
                 and row["keychains"] is (case != "product-offline") and row["accepted"] is online
                 and row["error"] is not online and type(row["result"]) is int
                 and row["result"] == (4 if online else 5) and row["chain"] == chain,
                 "native AIA acceptance, missing issuer, getter or exact chain differs")
        if online:
            expected_requests.append((fixture["route"], hashlib.sha256(fixture["issuer"]).hexdigest()))
        counts.append(sum(route == fixture["route"] for route, _digest in requests))
    _require(requests == expected_requests, "native AIA exact issuer requests/responses differ")
    return {"cases": record["cases"], "request_counts": counts, "final_disable_mutation_detected": True}


def _aia_comparison_note(data: bytes, fixtures: list[dict], requests: list[tuple[str, str]]) -> dict:
    """Closed observations from original in-memory inputs, never acceptance authority."""
    unavailable = {"schema": 1, "control": "aia-comparison",
                   "semantics": "comparison-observation-only", "available": False}
    try:
        record, errors, chains = _aia_record(data)
        _require(set(record) == {"schema", "cases"} and type(record["cases"]) is list
                 and type(fixtures) is list and len(record["cases"]) == len(fixtures) == 4
                 and type(requests) is list and len(requests) <= 8, "AIA diagnostic inventory differs")
        cases, originals, expected_requests = [], {}, []
        bools = ("baseline_network", "network", "keychains", "accepted", "error")
        for case, row, fixture, error in zip(_CASES, record["cases"], fixtures, errors):
            _require(type(fixture) is dict and set(fixture) == {"case", "route", "root", "issuer", "leaf"}
                     and type(fixture["case"]) is str and fixture["case"] == case
                     and type(fixture["route"]) is str and len(fixture["route"]) <= 96
                     and re.fullmatch(rf"/mrk-aia/[0-9a-f]{{32}}/{case}\.der", fixture["route"]) is not None
                     and all(type(fixture[role]) is bytes and 0 < len(fixture[role]) <= _MAX_DER
                             and fixture[role].startswith(b"\x30") for role in ("root", "issuer", "leaf")),
                     "AIA diagnostic fixture differs")
            _require(type(row) is dict and set(row) == {"case", *bools, "result", "chain"}
                     and type(row["case"]) is str and row["case"] == case
                     and all(type(row[key]) is bool for key in bools)
                     and type(row["result"]) is int and 0 <= row["result"] <= 0xffffffff
                     and type(row["chain"]) is list and 1 <= len(row["chain"]) <= 3
                     and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                             for value in row["chain"]), "AIA diagnostic result differs")
            online = case in ("online", "mutant")
            expected_chain = [hashlib.sha256(fixture[role]).hexdigest()
                              for role in (("leaf", "issuer", "root") if online else ("leaf",))]
            roles = {hashlib.sha256(fixture[role]).hexdigest(): role for role in ("leaf", "issuer", "root")}
            issuer = hashlib.sha256(fixture["issuer"]).hexdigest()
            originals[fixture["route"]] = (case, issuer)
            if online:
                expected_requests.append((fixture["route"], issuer))
            cases.append({"case": case, **{key: row[key] for key in bools}, "result": row["result"],
                          "chain_count": len(row["chain"]), "chain_matches": row["chain"] == expected_chain,
                          "chain_roles": [roles.get(digest, "other") for digest in row["chain"]],
                          "trust_error": {"status": error["status"], "code": error["code"]},
                          "request_count": 0})
        observed_requests = []
        for request in requests:
            _require(type(request) is tuple and len(request) == 2 and all(type(value) is str for value in request)
                     and len(request[0]) <= 96 and re.fullmatch(
                         r"/mrk-aia/[0-9a-f]{32}/(?:online|offline|mutant|product-offline)\.der", request[0]) is not None
                     and re.fullmatch(r"[0-9a-f]{64}", request[1]) is not None, "AIA diagnostic request differs")
            case, issuer = originals.get(request[0], ("unknown", None))
            observed_requests.append({"case": case, "issuer_matches": request[1] == issuer})
            for row in cases:
                if row["case"] == case:
                    row["request_count"] += 1
        contrasts, crypto = [], {"available": False, "keys": None, "checks": None}
        if chains is not None:
            fixture = fixtures[0]
            roles = {hashlib.sha256(fixture[role]).hexdigest(): role for role in ("leaf", "issuer", "root")}
            for row, expected_roles in zip(chains["contrasts"], (("leaf", "issuer", "root"),
                                                               ("issuer", "root"), ("leaf", "issuer"))):
                expected_chain = [hashlib.sha256(fixture[role]).hexdigest() for role in expected_roles]
                contrasts.append({"available": True, "case": row["case"],
                                  **{key: row[key] for key in ("network", "keychains", "accepted", "error", "result")},
                                  "chain_count": len(row["chain"]), "chain_matches": row["chain"] == expected_chain,
                                  "chain_roles": [roles.get(digest, "other") for digest in row["chain"]],
                                  "trust_error": dict(row["trust_error"])})
            observed = chains["crypto"]
            if observed["available"]:
                crypto = {"available": True, "keys": [dict(row) for row in observed["keys"]],
                          "checks": [{**row, "trust_error": None if row["trust_error"] is None
                                      else dict(row["trust_error"])} for row in observed["checks"]]}
        return {**unavailable, "available": True, "cases": cases, "requests": observed_requests,
                "contrasts": contrasts, "crypto": crypto, "requests_match": requests == expected_requests}
    except (NativeControlError, ValueError, TypeError, KeyError, RecursionError):
        return unavailable


def baseline_comparison_note(data: bytes, originals: tuple) -> dict:
    """Strict original-byte projection; only the owner supplies capture/finality facts."""
    originals = _baseline_tuple(originals)
    try:
        row = _parse(data, AIA_BASELINE_PREFIX)
        bools = ("network", "keychains", "accepted", "error")
        _require(set(row) == {"schema", "case", *bools, "result", "chain", "trust_error"}
                 and type(row["case"]) is str and row["case"] == _AIA_BASELINE_CASE
                 and all(type(row[key]) is bool for key in bools)
                 and row["network"] is False and row["keychains"] is False
                 and type(row["result"]) is int and 0 <= row["result"] <= 0xffffffff
                 and type(row["chain"]) is list and 1 <= len(row["chain"]) <= 3
                 and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                         for value in row["chain"]), "native baseline result fields differ")
        error = row["trust_error"]
        _require(type(error) is dict and set(error) == {"status", "code"}
                 and type(error["status"]) is str
                 and error["status"] in {"no-error", "osstatus", "other-domain", "unavailable"},
                 "native baseline trust error fields differ")
        _require(type(error["code"]) is int and -(2**31) <= error["code"] < 2**31
                 if error["status"] == "osstatus" else error["code"] is None,
                 "native baseline trust error code differs")
        expected = [hashlib.sha256(raw).hexdigest() for raw in originals]
        roles = dict(zip(expected, ("leaf", "issuer", "root")))
        return {"schema": 1, "control": "aia-offline-baseline", "semantics": "comparison-observation-only",
                "available": True, "case": _AIA_BASELINE_CASE, **{key: row[key] for key in bools},
                "result": row["result"], "chain_count": len(row["chain"]), "chain_matches": row["chain"] == expected,
                "chain_roles": [roles.get(digest, "other") for digest in row["chain"]], "trust_error": dict(error)}
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise NativeControlError("native baseline comparison is malformed") from exc


class _Responder:
    """One original owner's finite HTTP responder; no service requests or proxies."""

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.listener = self.thread = None
        self.start_attempted = False
        self.stop = threading.Event()
        self.responses, self.requests, self.errors = {}, [], []
        _remaining(deadline)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener  # Custody precedes any fallible configuration.
        try:
            listener.settimeout(0.1)
            listener.bind(("127.0.0.1", 0))
            self.port = _port(listener.getsockname()[1])
            listener.listen(8)
        except BaseException as original:
            try:
                listener.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup("responder setup/close failed", [original, cleanup])
            raise

    def start(self, responses: dict[str, bytes]) -> None:
        _remaining(self.deadline)
        _require(self.thread is None and len(responses) == len(_CASES), "responder inventory differs")
        _require(all(type(route) is str and re.fullmatch(r"/mrk-aia/[0-9a-f]{32}/(?:online|offline|mutant|product-offline)\.der", route)
                     and type(body) is bytes and 0 < len(body) <= _MAX_DER and body.startswith(b"\x30")
                     for route, body in responses.items()), "responder contains non-fixture data")
        self.responses = dict(responses)
        self.thread = threading.Thread(target=self._serve, name="mrk-owned-aia-responder", daemon=False)
        _remaining(self.deadline)
        self.start_attempted = True  # Thread.start can raise after acquiring a native worker.
        self.thread.start()
        _remaining(self.deadline)

    def _serve(self) -> None:
        try:
            while not self.stop.is_set():
                self.listener.settimeout(min(0.1, _remaining(self.deadline)))
                try:
                    connection, address = self.listener.accept()
                except socket.timeout:
                    continue
                errors = []
                try:
                    _require(address[0] == "127.0.0.1" and len(self.requests) < 8,
                             "unexpected responder client or request bound")
                    request = b""
                    while b"\r\n\r\n" not in request:
                        _require(len(request) < 4096, "issuer request exceeds fixed bound")
                        connection.settimeout(min(1.0, _remaining(self.deadline)))
                        part = connection.recv(min(4096 - len(request), 1024))
                        _require(bool(part), "issuer request ended prematurely")
                        request += part
                        _remaining(self.deadline)
                    first, _ = request.split(b"\r\n", 1)
                    pieces = first.decode("ascii").split(" ")
                    _require(len(pieces) == 3 and pieces[0] == "GET"
                             and pieces[2] in ("HTTP/1.0", "HTTP/1.1")
                             and pieces[1] in self.responses, "unexpected issuer request")
                    route = pieces[1]
                    body = self.responses[route]
                    response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\n"
                                b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: "
                                + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
                    connection.settimeout(min(1.0, _remaining(self.deadline)))
                    connection.sendall(response)
                    self.requests.append((route, hashlib.sha256(body).hexdigest()))
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    try:
                        connection.close()
                    except BaseException as exc:
                        errors.append(exc)
                if errors:
                    raise BaseExceptionGroup("owned issuer request/close failed", errors)
        except BaseException as exc:
            self.errors.append(exc)

    def close(self) -> None:
        errors, joined = [], False
        try:
            self.stop.set()
        except BaseException as exc:
            errors.append(exc)
        # The accept timeout and each accepted socket's deadline let the worker
        # exit before its listener is closed. A failed join is never acceptance.
        if self.start_attempted:
            try:
                _require(self.thread is not None, "owned responder thread custody is unknown")
                self.thread.join(timeout=max(0.0, min(2.0, self.deadline - time.monotonic())))
                _require(not self.thread.is_alive(), "owned issuer responder did not join")
                joined = True
            except BaseException as exc:
                errors.append(exc)
        if self.listener is not None:
            if joined:
                pending = None
                try:
                    self.listener.settimeout(0)
                    pending, _address = self.listener.accept()
                    errors.append(NativeControlError("issuer request remained queued after native finality"))
                except BlockingIOError:
                    pass
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    if pending is not None:
                        try:
                            pending.close()
                        except BaseException as exc:
                            errors.append(exc)
            try:
                self.listener.close()
            except BaseException as exc:
                errors.append(exc)
        errors.extend(self.errors)
        if errors:
            raise BaseExceptionGroup("owned responder cleanup failed", errors)


def admit_controls(launch, ensure_idle, scratch: Path, *, deadline: float, policy_sha256: str,
                   freeze_baseline) -> dict:
    """Original owner only. The seven-case callback returns real Session captures.

    Session fixes source/bootstrap/argv/identity/cwd/environment/policy and keeps
    every original capture. No receipt, callback from U, or caller URL grants a
    launch. The listener is never inherited by a subject.
    """
    _remaining(deadline)
    _policy_digest(policy_sha256)
    _require(callable(freeze_baseline), "native baseline snapshot lacks its original owner")
    ensure_idle()
    _scratch(scratch)

    def run(case, *, port=None):
        result, errors = None, []
        try:
            _remaining(deadline)
            result = launch(case, port=port)
        except BaseException as exc:
            errors.append(exc)
        finally:
            try:
                ensure_idle()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native control capture/finality failed", errors)
        _remaining(deadline)
        _require(result is not None and result.ok is True, "native control capture did not succeed")
        return result.stdout

    rows = [parse_mach(run(case)) for case in ("mach-baseline", "mach-ordinary")]
    rows.extend(parse_mach_application(run(case), role) for case, role in
                (("mach-authority", "mach-initial"), ("mach-nonexpand", "mach-nonexpand")))
    require_mach_controls(*rows, policy_sha256=policy_sha256)
    responder, errors, aia = None, [], None
    try:
        _remaining(deadline)
        responder = _Responder(deadline)
        prepared = run("aia-prepare", port=responder.port)
        _require(prepared == b"MRK_AIA_PREPARED\n", "native fixture preparation did not complete")
        ensure_idle()  # No fixture reads while a previous producer remains unknown.
        fixtures = _fixtures(scratch, responder.port, deadline)
        responder.start({row["route"]: row["issuer"] for row in fixtures})
        output = run("aia-evaluate", port=responder.port)
    except BaseException as exc:
        errors.append(exc)
    finally:
        if responder is not None:
            try:
                responder.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native AIA controls/owned responder cleanup failed", errors)
    _remaining(deadline)
    ensure_idle()
    # This is structural admission of a preplanned observation, not an early
    # acceptance decision or a branch selected by a failed trust verdict.
    structural = _aia_comparison_note(output, fixtures, responder.requests)
    _require(structural.get("available") is True and len(structural.get("contrasts", ())) == 3,
             "native baseline requires complete original comparison structure")
    _remaining(deadline)
    _require(_fixtures(scratch, responder.port, deadline) == fixtures,
             "native baseline original fixture bytes changed")
    originals = _baseline_tuple(tuple(fixtures[0][role] for role in ("leaf", "issuer", "root")))
    _remaining(deadline)
    _require(freeze_baseline(originals) is None, "native baseline snapshot returned an unexpected value")
    _remaining(deadline)
    baseline_comparison_note(run("aia-offline-baseline"), originals)
    _remaining(deadline)
    try:
        aia = require_aia_controls(output, fixtures, responder.requests)
    except NativeControlError as original:
        # Only this completed original comparison may expose a closed note.
        # Earlier capture/finality/cutoff/close failures never reach this seam.
        try:
            original._ci_observation = _aia_comparison_note(output, fixtures, responder.requests)
        except BaseException:
            pass  # Even diagnostic construction/attachment failure retains the original error.
        raise
    ensure_idle()
    _remaining(deadline)
    return {"schema": 1, "mach": {name: row for name, row in zip(
        ("baseline", "ordinary", "authority", "nonexpand"), rows)}, "aia": aia, "cleanup_ok": True}


def _main(argv: list[str]) -> int:
    _require(sys.platform == "darwin", "native controls require real macOS")
    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    _require(len(set(identity)) == 1 and 60000 <= identity[0] < 65000,
             "native helper did not receive admitted numerical identity")
    entry = Path(__file__).resolve(strict=True)
    _require(entry.name == "ci_native_authority.py" and entry.parent.name == "bootstrap"
             and entry.parent.parent.parent == Path("/private/tmp"), "native helper origin differs")
    _require(type(argv) is list and len(argv) in (2, 3) and all(type(arg) is str for arg in argv)
             and 0 < len(argv[-1]) <= 64, "invalid fixed native helper role")
    deadline = float(argv[-1])
    _remaining(deadline)
    if argv[0] == "--mach" and len(argv) == 2:
        prefix, result = MACH_PREFIX, mach_probe(deadline)
    elif argv[0] == "--mach-initial" and len(argv) == 3:
        prefix, result = MACH_APPLY_PREFIX, mach_initial(Path(argv[1]), deadline)
    elif argv[0] == "--mach-nonexpand" and len(argv) == 3:
        prefix, result = MACH_APPLY_PREFIX, mach_nonexpand(Path(argv[1]), deadline)
    elif argv[0] in ("--aia-prepare", "--aia-evaluate") and len(argv) == 3:
        _require(re.fullmatch(r"[1-9][0-9]{3,4}", argv[1]) is not None, "invalid native fixture port")
        port = _port(int(argv[1]))
        if argv[0] == "--aia-prepare":
            prepare_aia(port, deadline)
            print("MRK_AIA_PREPARED", flush=True)
            return 0
        prefix, result = AIA_PREFIX, evaluate_aia(port, deadline)
    elif argv[0] == "--aia-offline-baseline" and len(argv) == 2:
        prefix, result = AIA_BASELINE_PREFIX, evaluate_aia_baseline(deadline)
    else:
        raise NativeControlError("unknown fixed native helper role")
    _remaining(deadline)
    line = prefix.decode("ascii") + json.dumps(result, separators=(",", ":"), sort_keys=True, allow_nan=False)
    _require(len(line) < 4096, "native control output exceeds bound")
    print(line, flush=True)
    return 0


if __name__ == "__main__":
    try:
        code = _main(sys.argv[1:])
    except BaseException as error:
        # Nested synthetic stderr uses the Session's bounded private collector.
        # This note and its published projection exclude raw paths/messages/keys;
        # inherited child text never authorizes success or replaces parent facts.
        print(_FAILURE_PREFIX.decode("ascii") + json.dumps(_failure_note(error, sys.argv[1:]),
                                                        separators=(",", ":")), file=sys.stderr, flush=True)
        code = 1
    raise SystemExit(code)
