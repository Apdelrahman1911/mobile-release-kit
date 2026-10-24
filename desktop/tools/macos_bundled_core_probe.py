#!/usr/bin/env python3
"""One direct bundled-core discriminator, NOT native/app qualification.

Run only after the retained Git27 job's fresh install/readback/eject returned0.
No app launch, project input, installation repair or alternate interpreter. The
workflow must skip app cases: this read can warm the installed runtime's cache.
Import is inert. Only fixed shape/counts and process measurements are emitted.
"""
from pathlib import Path
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time


SOURCE = "216a2d3a559dd562164e852ea78b7235916e7c3a"
RUNTIME = Path("/Library/Application Support/MobileReleaseKit/versions/macos26-arm64-desktop-03/runtime")
ARGV = (str(RUNTIME / "python/bin/python3"), "-I", "-S", "-B",
        str(RUNTIME / "engine_bootstrap.py"), str(RUNTIME / "core.zip"))
REQUEST_ID = "direct-bundled-core"
REQUEST = b'{"protocol":1,"id":"direct-bundled-core","method":"capabilities","params":{}}\n'
WORK_SECONDS = 10.0
CLEANUP_SECONDS = 2.0
CAPTURE_LIMIT = 64 * 1024  # Per unlinked file, not a product protocol change.
SCOPE = "direct-bundled-core-only-not-native-app-qualification"


def _need(value):
    if not value:
        raise ValueError("direct-core-refused")


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result)
        result[key] = value
    return result


def _constant(_):
    raise ValueError("direct-core-json")


def _text(value):
    return (type(value) is str and 0 < len(value.encode("utf-8")) <= 1600
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def response_shape(raw):
    """Closed protocol/CapabilitiesResult shape; never return child strings."""
    try:
        _need(0 < len(raw) < CAPTURE_LIMIT and raw.endswith(b"\n"))
        body = raw[:-1]
        _need(body.startswith(b"{") and body.endswith(b"}")
              and b"\n" not in body and b"\r" not in body)
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        _need(type(value) is dict and type(value.get("protocol")) is int
              and value["protocol"] == 1 and value.get("id") == REQUEST_ID
              and type(value.get("ok")) is bool)
        if not value["ok"]:
            _need(set(value) == {"protocol", "id", "ok", "error"})
            error = value["error"]
            _need(type(error) is dict and set(error) == {"code", "message", "retryable"}
                  and type(error["code"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", error["code"])
                  and _text(error["message"]) and error["retryable"] is False)
            return "core-refusal", None, None
        _need(set(value) == {"protocol", "id", "ok", "result"})
        result = value["result"]
        _need(type(result) is dict and set(result) == {
            "coreVersion", "apiVersion", "hostPlatform", "mode", "methods", "actions", "limitations"})
        _need(result["coreVersion"] == "0.3.0" and type(result["apiVersion"]) is int
              and result["apiVersion"] == 1 and result["hostPlatform"] == "macos"
              and result["mode"] == "read-only-foundation")
        for key, identity in (("methods", "method"), ("actions", "id")):
            rows = result[key]
            _need(type(rows) is list)
            names = set()
            for row in rows:
                _need(type(row) is dict and set(row) == {identity, "available", "reason"}
                      and _text(row[identity]) and row[identity] not in names
                      and type(row["available"]) is bool and _text(row["reason"])
                      and (key != "actions" or row["available"] is False))
                names.add(row[identity])
        _need(type(result["limitations"]) is list
              and all(_text(item) for item in result["limitations"]))
        return "capabilities", len(result["methods"]), len(result["actions"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return "invalid", None, None


def _child_limits():
    # Child-only, before exec; no parent/global limit change or credential input.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAPTURE_LIMIT, CAPTURE_LIMIT))


def _result():
    return {"schemaVersion": 1, "scope": SCOPE, "outcome": "refused",
            "elapsedSeconds": None, "exitCode": None, "responseShape": "not-read",
            "methodCount": None, "actionCount": None, "stderrBytes": None}


def probe(uid, work):
    """One launch/communicate; private files avoid output-pipe deadlocks.

    Elapsed includes creation and cleanup. The10s endpoint is sampled before
    Popen, never renewed after it returns; stdlib cannot interrupt Popen's own
    synchronous creation call. No bounded-native-creation claim is made here.
    """
    _need(type(uid) is int and uid > 0)
    report = _result()
    # TemporaryFile creates0600 unlinked files. RLIMIT_FSIZE bounds both actual
    # child writes; parent reads at most64KiB and never reads stderr contents.
    with tempfile.TemporaryFile(dir=work) as out, tempfile.TemporaryFile(dir=work) as err:
        child = None
        started = time.monotonic()
        end = started + WORK_SECONDS
        try:
            child = subprocess.Popen(ARGV, stdin=subprocess.PIPE, stdout=out, stderr=err,
                cwd=RUNTIME, env={"LC_ALL": "C", "LANG": "C", "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"},
                close_fds=True, restore_signals=True, preexec_fn=_child_limits)
            # communicate owns the one request write AND closes stdin for EOF.
            child.communicate(input=REQUEST, timeout=max(0.0, end - time.monotonic()))
            report["outcome"] = "returned" if time.monotonic() < end else "timeout"
        except subprocess.TimeoutExpired:
            report["outcome"] = "timeout"
        except Exception:
            report["outcome"] = "launch-error" if child is None else "process-error"
        finally:
            if child is not None:
                if child.returncode is None:
                    cleanup_end = min(time.monotonic(), end) + CLEANUP_SECONDS
                    try:
                        child.kill()  # This exact child once; no PID discovery/group kill.
                    except OSError:
                        pass
                    try:
                        child.wait(timeout=max(0.0, cleanup_end - time.monotonic()))
                    except (subprocess.TimeoutExpired, OSError):
                        report["outcome"] = "cleanup-unknown"
                if child.stdin is not None:
                    try:
                        child.stdin.close()
                    except OSError:
                        report["outcome"] = "process-error" if child.returncode is not None else "cleanup-unknown"
                report["exitCode"] = child.returncode
        if child is not None and child.returncode is not None:
            out_size, err_size = os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size
            report["stderrBytes"] = err_size
            if out_size >= CAPTURE_LIMIT or err_size >= CAPTURE_LIMIT:
                report["responseShape"] = "capture-limit"  # A full file may be truncated.
            elif report["outcome"] == "returned":
                out.seek(0)
                shape, methods, actions = response_shape(out.read(CAPTURE_LIMIT))
                report.update(responseShape=shape, methodCount=methods, actionCount=actions)
            if report["outcome"] == "returned":
                report["outcome"] = ("passed" if child.returncode == 0 and err_size == 0
                    and report["responseShape"] == "capabilities" else "refused")
        report["elapsedSeconds"] = round(time.monotonic() - started, 6)
    return report


def admitted_context():
    """Reuse the current retained route/user checks, not Installer authority."""
    _need(not sys.argv[1:] and os.environ.get("MRK_MACOS_BUNDLED_CORE_DIAGNOSTIC") == "true"
          and os.environ.get("MRK_CANDIDATE_MODE") == "install-retained-git-observer"
          and os.environ.get("MRK_CANDIDATE_SOURCE") == SOURCE)
    path = Path(__file__).absolute().with_name("macos_identity_current_runtime.py")
    spec = importlib.util.spec_from_file_location("_mrk_direct_core_context", path)
    _need(spec is not None and spec.loader is not None)
    context = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(context)
    _, _, _, work = context.retained_context(os.environ, context.TARGET)
    uid, _, _, _ = context._native_user(os.environ, retained=True)
    # Actual previous workflow return0 is also a required step condition. This
    # bounded status read does NOT recreate install/readback/eject evidence.
    fd = os.open(work / "retained-observer-install.status", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _need(stat.S_ISREG(os.fstat(fd).st_mode) and os.read(fd, 3) == b"0\n")
    finally:
        os.close(fd)
    return uid, work


def main():
    report = _result()
    try:
        report = probe(*admitted_context())
    except Exception:
        pass  # Never emit exception prose, filenames or partial private output.
    print(json.dumps(report, separators=(",", ":"), allow_nan=False))
    return 0 if report["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
