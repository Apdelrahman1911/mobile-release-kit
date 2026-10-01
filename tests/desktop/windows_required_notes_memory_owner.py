"""Separate one-use owner for exactly 63 reviewed Notes Python memory contracts.

The trusted interpreter's stdlib (including ctypes' own initialization) is
loaded BEFORE fixture admission. Thereafter the fixtures may use ctypes DATA
memory, never a DLL loader, foreign function/callback, filesystem, process,
thread, network or real bootstrap capability. This is a regression guard for
the pinned reviewed source, not a sandbox for arbitrary hostile Python.
The existing Python85 import-denial owner is not imported or modified.
"""
from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock

# Trusted stdlib startup only. No candidate module is imported here. Preload
# lazy standard-library dependencies so post-admission imports need no disk IO.
for _name in (
    "argparse", "ast", "base64", "binascii", "bisect", "collections", "collections.abc", "contextlib", "copy",
    "csv", "ctypes", "ctypes.wintypes", "dataclasses", "datetime", "decimal", "email", "email.message",
    "encodings.utf_16_le",  # Required Notes UTF-16LE spelling DATA; never lazy disk fallback.
    "enum", "errno", "functools", "hashlib", "heapq", "hmac", "inspect", "io", "itertools",
    "logging", "math", "ntpath", "os", "pickle", "platform", "posixpath", "queue", "random",
    "re", "secrets", "shlex", "shutil", "signal", "socket", "ssl", "stat", "string", "struct",
    "subprocess", "tempfile", "textwrap", "threading", "tomllib", "traceback", "typing",
    "unicodedata", "urllib.parse", "uuid", "warnings", "weakref", "zipfile", "zlib", "concurrent.futures",
):
    importlib.import_module(_name)

import ctypes
import io
import os
import random
import secrets
import socket
import ssl
import subprocess
import threading
import _thread

sys.path.insert(0, str(Path(__file__).absolute().parents[2] / "desktop/tools"))
import ci_windows_required_notes as driver


class MemoryGuardRefused(RuntimeError):
    pass


def main() -> int:
    original_clock, original_trace = time.monotonic, sys.settrace
    original_stdout, original_stderr = sys.stdout.write, sys.stderr.write
    stdout_flush, stderr_flush = sys.stdout.flush, sys.stderr.flush
    state = driver.context(create=False, retention_only=True)
    root, source = Path(state["root"]), Path(state["source"])
    driver.compiled_gate(state)
    selected = driver.source_contract(state)
    require = driver.require
    request = driver.data(root / "python-owner-request.json")
    expected = driver.receipt(state, "python-owner", started=True,
        compileChecks=driver.record(root / "compile-checks.json", 4 << 20),
        contract=driver.record(source / driver.CONTRACT, 256 << 10))
    require(request == expected, "Notes Python owner request is not original/source-bound")
    require(driver.data(root / "windows-required-notes-contracts-started.json")
            == driver.receipt(state, "windows-required-notes-contracts", started=True),
            "Notes Python owner lacks its fixed parent phase claim")
    driver.write(root / "python-owner-started.json", request)  # exclusive; failure consumes this owner
    contents, filenames, packages = {}, {}, set()
    for row in state["sourceFiles"]:
        path = row["path"]
        if not (path.startswith("src/mobile_release/") and path.endswith(".py")):
            continue
        tail = path[len("src/"):-3].replace("/", ".")
        name = tail[:-len(".__init__")] if tail.endswith(".__init__") else tail
        if tail.endswith(".__init__"):
            packages.add(name)
        require(name not in contents and len(contents) < 768, "Notes Python source module is duplicated/overbound")
        raw = driver.read(source / path, 2 << 20)
        require(len(raw) == row["size"] and driver.hashlib.sha256(raw).hexdigest() == row["sha256"],
                "Notes Python original source changed during owner capture")
        contents[name], filenames[name] = raw, str(source / path)
    require("mobile_release" in contents and sum(map(len, contents.values())) <= 16 << 20,
            "Notes Python core source inventory differs")
    for part in selected["python"]:
        name, path = part["module"], part["path"]
        require(name not in contents, "Notes Python test module collides")
        contents[name], filenames[name] = driver.read(source / path, 128 << 10), str(source / path)
    contents["desktop.config_edit_bootstrap"] = driver.read(source / "desktop/config_edit_bootstrap.py", 64 << 10)
    filenames["desktop.config_edit_bootstrap"] = str(source / "desktop/config_edit_bootstrap.py")
    require(not any(name in sys.modules for name in contents), "Notes fixture module was imported before guarded admission")
    # Root and src are both reviewed import domains. The custom memory loader
    # below supplies their bytes; its closed finder prevents disk fallback.
    sys.path[:0] = [str(source), str(source / "src")]
    desktop = types.ModuleType("desktop")
    desktop.__path__ = [str(source / "desktop")]
    desktop.__package__ = "desktop"
    desktop.__spec__ = importlib.util.spec_from_loader("desktop", loader=None, is_package=True)
    require("desktop" not in sys.modules, "Notes bootstrap namespace was already imported")
    sys.modules["desktop"] = desktop

    violations = []
    enabled = False
    memory_depth = 0
    deadline = original_clock() + 120
    line_events = 0

    def refuse(label):
        if not violations:
            violations.append(label)
        raise MemoryGuardRefused("Notes scripted-memory capability refused")

    def denied(*args, **kwargs):
        return refuse("capability")

    class NoLoader:
        def __getattr__(self, name):
            return denied

        def __call__(self, *args, **kwargs):
            return denied(*args, **kwargs)

    class Loader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in contents:
                return importlib.util.spec_from_loader(fullname, self, origin=filenames[fullname],
                                                      is_package=fullname in packages)
            return refuse("unselected-import")

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            name = module.__name__
            require(name in contents, "Notes memory module is not selected source")
            module.__file__ = filenames[name]
            if name in packages:
                module.__path__ = [str(Path(filenames[name]).parent)]
            # Candidate code is executed only here, after all original compile
            # gates, from held/pinned memory and under the installed IO guard.
            code = compile(contents[name], filenames[name], "exec", dont_inherit=True, optimize=0)
            exec(code, module.__dict__)

    def audit(event, arguments):
        if not enabled:
            return
        if (event == "open" or event.startswith(("socket.", "subprocess.", "winreg.", "os.", "shutil."))
                or event in {"ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle",
                             "os.system", "os.posix_spawn", "pty.spawn", "_thread.start_new_thread"}):
            return refuse("io-or-loader-audit")
        if event == "ctypes.call_function" and not memory_depth:
            return refuse("foreign-call")
        # Trusted memory constructors may emit cdata/addressof/string_at events.
        # They confer no loader/function pointer/callback admission.

    def memory(function, *, counted=False):
        def invoke(*args, **kwargs):
            nonlocal memory_depth
            if counted:
                count = args[-1] if args else None
                if type(count) is not int or not 0 <= count <= 1 << 20:
                    return refuse("memory-extent")
            memory_depth += 1
            try:
                return function(*args, **kwargs)
            finally:
                memory_depth -= 1
        return invoke

    # Real ctypes memory objects are needed by the reviewed scripted pointer
    # frames. No CFUNCTYPE/WINFUNCTYPE/PYFUNCTYPE fixture is selected.
    for name in ("CDLL", "WinDLL", "OleDLL", "PyDLL", "LibraryLoader", "CFUNCTYPE", "WINFUNCTYPE", "PYFUNCTYPE"):
        if hasattr(ctypes, name):
            setattr(ctypes, name, denied)
    for name in ("cdll", "windll", "oledll", "pydll", "pythonapi", "_CFuncPtr"):
        if hasattr(ctypes, name):
            setattr(ctypes, name, NoLoader())
    for name in ("cast", "pointer", "byref", "addressof", "sizeof", "alignment",
                 "create_string_buffer", "create_unicode_buffer"):
        setattr(ctypes, name, memory(getattr(ctypes, name)))
    for name in ("memmove", "memset", "string_at", "wstring_at", "resize"):
        setattr(ctypes, name, memory(getattr(ctypes, name), counted=True))

    for name in ("open", "fdopen", "close", "closerange", "read", "write", "readv", "writev", "lseek",
                 "pipe", "pipe2", "dup", "dup2", "fsync", "fdatasync", "truncate", "ftruncate",
                 "mkdir", "makedirs", "remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace",
                 "link", "symlink", "chmod", "chown", "utime", "chdir", "fchdir", "chroot", "listdir",
                 "scandir", "stat", "lstat", "readlink", "system", "popen", "startfile", "kill", "killpg",
                 "fork", "forkpty", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp", "execvpe",
                 "spawnv", "spawnve", "spawnvp", "spawnvpe", "putenv", "unsetenv", "urandom"):
        if hasattr(os, name):
            setattr(os, name, denied)
    for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
        setattr(subprocess, name, denied)
    for name in ("socket", "socketpair", "create_connection", "create_server", "getaddrinfo",
                 "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        if hasattr(socket, name):
            setattr(socket, name, denied)
    for name in ("wrap_socket", "get_server_certificate"):
        if hasattr(ssl, name):
            setattr(ssl, name, denied)
    _thread.start_new_thread = denied
    if hasattr(_thread, "start_joinable_thread"):
        _thread.start_joinable_thread = denied
    threading.Thread.start = denied
    time.sleep = denied
    builtins.open = io.open = denied
    random._urandom = denied
    for name in ("token_bytes", "token_hex", "token_urlsafe", "randbelow", "choice"):
        setattr(secrets, name, denied)

    original_import = builtins.__import__
    forbidden = {"_ctypes", "_winapi", "_overlapped", "_socket", "_ssl", "winreg", "msvcrt", "multiprocessing"}

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.split(".", 1)[0] in forbidden:
            return refuse("native-provider-import")
        return original_import(name, globals, locals, fromlist, level)

    def trace(frame, event, argument):
        nonlocal line_events
        if event == "line":
            line_events += 1
            if line_events > 8000000 or (line_events % 2048 == 0 and original_clock() >= deadline):
                return refuse("original-owner-bound")
        return trace

    class Quiet:
        def write(self, text):
            if text:
                return refuse("fixture-output")
            return 0

        def flush(self):
            return None

    sys.meta_path.insert(0, Loader())
    builtins.__import__ = guarded_import
    sys.addaudithook(audit)
    original_trace(trace)
    sys.settrace = sys.setprofile = denied
    sys.stdout = sys.stderr = Quiet()
    enabled = True
    try:
        cases, identifiers = [], []
        for part in selected["python"]:
            module = importlib.import_module(part["module"])
            for selection in part["selectors"]:
                cls = module.__dict__.get(selection["class"])
                require(isinstance(cls, type) and issubclass(cls, unittest.TestCase)
                        and cls.__module__ == part["module"] and not getattr(cls, "__unittest_skip__", False),
                        "Notes selected Python class is not its active original")
                method = cls.__dict__.get(selection["test"])
                require(isinstance(method, types.FunctionType) and method.__module__ == part["module"]
                        and method.__name__ == selection["test"] and method.__code__.co_filename == filenames[part["module"]]
                        and not getattr(method, "__unittest_skip__", False)
                        and not getattr(method, "__unittest_expecting_failure__", False),
                        "Notes selected Python test is missing, ignored, inherited or foreign")
                case = cls(selection["test"])
                identifiers.append(case.id())
                cases.append(case)
        require(len(cases) == len(set(identifiers)) == 63, "Notes guarded Python selected count differs")
        observed_ids = []

        class Result(unittest.TestResult):
            def startTest(self, test):
                observed_ids.append(test.id())
                super().startTest(test)

        result = Result()
        unittest.TestSuite(cases).run(result)
        require(observed_ids == identifiers and result.testsRun == 63 and not result.shouldStop
                and not any((result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccess))
                and not violations and original_clock() < deadline,
                "Notes original guarded Python contracts did not pass")
    except BaseException:
        original_trace(None)  # Capability audit stays installed even on a failed fixture.
        original_stderr("Notes scripted-memory owner failed; no native or shipping success is implied.\n")
        stderr_flush()
        return 1
    original_trace(None)  # Keep the capability audit installed through original process exit.
    # The bootstrap fixture DOES call bootstrap.main(), with sys/os/time,
    # capture, supplier and engine replaced by Python fixtures. Nothing here
    # authorizes unmocked main, a real descriptor, DLL load or child process.
    output = {**request, "phase": "python-owner-return", "status": "passed", "passed": 63, "failed": 0, "ignored": 0,
              "guard": "pinned-source-scripted-ctypes-memory-only-v1"}
    raw = "MRK_WINDOWS_NOTES_MEMORY_CONTRACTS=" + json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
    require(original_stdout(raw) == len(raw), "Notes Python original result write is incomplete")
    stdout_flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        sys.__stderr__.write("Notes Python owner setup failed; no candidate success is implied.\n")
        raise SystemExit(1)
