"""Pure hosted-owner regressions, not native isolation or process evidence.

Only inert definitions are loaded. Collection uses synthetic paths, in-memory
files, original-child doubles, a bounded fake clock and a fake selector. No
Session construction resource effect or native entry point is executed.
The helper's OS/process/signal namespaces are replaced, not shared stdlib APIs.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager, redirect_stdout
import dataclasses
import errno
import functools
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]


@functools.lru_cache(maxsize=1)
def sandbox_module():
    spec = importlib.util.spec_from_file_location(
        "_mrk_pure_ci_sandbox", ROOT / ".github/scripts/ci_sandbox.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required hosted-owner helper is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclass annotation lookup, not a CLI role.
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def session_double(module, platform="linux"):
    """Bypass construction completely; these paths are never created/resolved."""
    session = object.__new__(module.Session)
    session.platform = platform
    session.root = Path("/private/tmp" if platform == "darwin" else "/tmp") / "mrk-pure-fixture"
    for name in ("source", "inputs", "work", "control", "bootstrap"):
        setattr(session, name, session.root / name)
    session.python = Path("/fixture-tools/python/bin/python")
    session.ruby = Path("/fixture-tools/ruby/bin/ruby")
    session.tool_prefixes = (session.python.parent.parent, session.ruby.parent.parent)
    session.runner_home = Path("/home/runner")
    session.runner_temp = Path("/home/runner/work/_temp")
    session.ruby_prefix = session.ruby.parent.parent
    session.ruby_ancestors = ()  # Bound explicitly in tests that exercise the Mac-only metadata role.
    session._ruby_ancestor_states = ()
    session.entry = session.bootstrap / "ci_sandbox.py"
    session.policy = session.bootstrap / "subject.sb"
    session.cleanup_policy = session.bootstrap / "cleanup.sb"
    session.fixture_controls = session.root / "fixture-controls"
    session.outside_write = session.fixture_controls / "outside-write"
    session.write_policy = session.bootstrap / "write-positive.sb"
    session.uid = session.gid = 60001
    session.deadline = 100.0
    session.failure = None
    session.cleanup_errors = []
    session.admitted = True
    session.closed = session.cancelled = session._busy = False
    session._admitting = session._timer_finished = False
    session.domain_finality = False
    session.persisted_bytes = session._run_number = 0
    session.admission_results = []
    session._handlers = {}
    session._active = None
    session._home_state = None
    session._userns_state = None
    session._native_authority = {}
    session._native_preparing = None
    session._native_control = None
    session._direct_producer_pending = False
    session.process_observer = session.bootstrap / "process-observer" if platform == "darwin" else None
    return session


def native_state_double(session, phase="source", *, deadline=1.0):
    """Inert prepared-role state, never a native admission receipt or a path."""
    state = dict(phase=phase, deadline=deadline, cwd=session.work / f"native-authority-{phase}",
        policy=session.bootstrap / f"native-authority-{phase}.sb", argv=session._native_command(phase),
        package=session.work / ("source-build/src/mobile_release" if phase == "source" else
                                "wheel-venv/lib/python3.11/site-packages/mobile_release"),
        pins=[], files={}, trees={}, prepared=True, started=False, completed=False, closed=False,
        control_seen=[], startup_seen=[], control_notes={}, native_controls={"synthetic-inert-fixture": True}, outside_fd=None,
        outside_write=session.fixture_controls / f"native-authority-{phase}-outside-write",
        outside_read=session.work / "home" / f"native-authority-{phase}-read",
        sibling_read=session.work / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py")
    session._native_authority[phase] = state
    return state


def native_abort_double(session, *, deadline=1.0):
    """Private synthetic correlation only; never process or image admission."""
    wall = 1_789_029_600_000_000_000  # 2026-09-10 08:40:00 UTC, integer nanoseconds.
    return dict(deadline=deadline, uid=session.uid, pid=4242,
        images={str(session.python): "python-selected", "/usr/bin/sandbox-exec": "sandbox-exec"},
        bindings={}, binding_bytes=0, ips_bytes=0, candidates=0, attempted=False, log_attempted=False,
        close_failed=False, phase="source", case="outside-write-positive",
        wall_before=wall + 125_000_000, wall_after=wall + 126_000_000, wall_wait=wall + 2_500_000_000)


def native_abort_ips_bytes(abort, *, metadata=None, body=None):
    """Two in-memory JSON objects, with deliberate private redaction canaries."""
    header = {"bug_type": "309", "timestamp": "2026-09-10 08:40:02.5000 +0000"}
    report = {"pid": abort["pid"], "userID": abort["uid"],
        "procPath": next(path for path, role in abort["images"].items() if role == "python-selected"),
        "procLaunch": "2026-09-10 08:40:00.1255 +0000", "captureTime": "2026-09-10 08:40:02.4999 +0000",
        "exception": {"type": "EXC_CRASH", "signal": "SIGABRT"},
        "termination": {"namespace": "LIBSYSTEM", "code": 1}, "faultingThread": 0,
        "threads": [{"frames": [{"imageIndex": 0, "symbol": "__abort_with_payload"}]}],
        "usedImages": [{"path": "/usr/lib/system/libsystem_kernel.dylib"}],
        "asi": {"private": ["/Users/private-user/secrets.txt", "PRIVATE-DIAGNOSTIC-CANARY"]},
        "environment": {"PRIVATE_TOKEN": "PRIVATE-DIAGNOSTIC-CANARY"}}
    header.update(metadata or {})
    report.update(body or {})
    return (json.dumps(header, separators=(",", ":")) + "\n" + json.dumps(report, separators=(",", ":")) + "\n").encode()


def native_exit_bsd_bytes(session, *, status=5, expected_status=6, pid=4242, parent=4000, **changes):
    """Synthetic fixed-layout bytes only; no SDK, kernel or image receipt."""
    raw = bytearray(136)
    fields = {"flags": (0, 0x10), "status": (4, status), "xstatus": (8, expected_status), "pid": (12, pid),
        "ppid": (16, parent), "uid": (20, session.uid), "gid": (24, session.gid), "ruid": (28, session.uid),
        "rgid": (32, session.gid), "svuid": (36, session.uid), "svgid": (40, session.gid)}
    for key, (offset, value) in fields.items():
        raw[offset:offset + 4] = changes.get(key, value).to_bytes(4, "little")
    for key, offset, size in (("comm", 48, 16), ("name", 64, 32)):
        value = changes.get(key, b"true\0")
        raw[offset:offset + size] = value.ljust(size, b"\0")[:size]
    return bytes(raw)


class _Stream:
    def __init__(self, rig, index):
        self.rig, self.index = rig, index

    def fileno(self):
        return 10 + self.index

    def close(self):
        self.rig.events.append(("stream-close", self.index))
        if self.index in self.rig.stream_close_errors:
            raise OSError("synthetic stream close")


class _Child:
    def __init__(self, rig):
        self.rig = rig
        self.pid = 4242  # Inert identity: never passed to a real process API.
        self.stdout, self.stderr = _Stream(rig, 0), _Stream(rig, 1)
        self.stopped = None

    def poll(self):
        if self.rig.unreapable:
            result = None
        else:
            result = self.stopped if self.stopped is not None else (
                self.rig.exitcode if self.rig.now >= self.rig.exit_at else None
            )
        self.rig.events.append(("poll", result))
        return result

    def terminate(self):
        self.rig.events.append(("terminate-original",))
        if self.rig.terminate_exits:
            self.stopped = -15

    def kill(self):
        self.rig.events.append(("kill-original",))
        self.stopped = -9

    def wait(self, *, timeout):
        self.rig.events.append(("wait-original", timeout))
        self.rig.events.append(("wait-budget", timeout, self.rig.now))
        if self.rig.unreapable:
            raise TimeoutError("synthetic unknown original wait")
        if self.rig.wait_error:
            raise OSError("synthetic original wait error")
        result = self.poll()
        if result is None:
            raise AssertionError("fake wait requires an already completed original child")
        return result


class _Selector:
    def __init__(self, rig):
        self.rig, self.keys = rig, {}

    def register(self, stream, _events, index):
        self.keys[index] = SimpleNamespace(data=index, fd=stream.fileno(), fileobj=stream)

    def unregister(self, stream):
        del self.keys[stream.index]
        self.rig.events.append(("unregister-eof", stream.index))

    def get_map(self):
        return self.keys

    def select(self, timeout):
        self.rig.select_calls += 1
        if self.rig.select_calls > 512:
            raise AssertionError("fake selector's finite iteration budget exhausted")
        self.rig.now += min(timeout, 0.05)
        return [(key, 1) for key in tuple(self.keys.values())]

    def close(self):
        self.rig.events.append(("selector-close",))
        if self.rig.selector_close_error:
            raise OSError("synthetic selector close")


class _Collection:
    """Small in-memory substitute for every effect reachable by Session._run."""
    def __init__(self, module, session=None, *, stdout=(b"PASS\n",), stderr=()):
        self.module = module
        self.session = session if session is not None else session_double(module)
        self.chunks = [list(stdout), list(stderr)]
        self.now, self.clock_calls, self.select_calls = 0.0, 0, 0
        self.exit_at, self.exitcode = 0.08, 0
        self.events, self.captures, self.opened = [], {}, []
        self.hold = set()
        self.write_step = 65536
        self.after_write_error = None
        self.stream_close_errors, self.fsync_errors = set(), set()
        self.fstat_errors, self.fd_close_errors = set(), set()
        self.selector_close_error = self.wait_error = self.unreapable = False
        self.selector_error = None
        self.terminate_exits = True
        self.cleanup_diagnostics = []
        self.domain_calls, self.final_domain = 0, {}
        self.cancel_at = self.final_time = None
        self.cancel_on_finality = False
        self.snapshot_rows = self.snapshot_error = None
        self.snapshot_advance = 0.0
        self.child, self.selector = _Child(self), _Selector(self)

    def monotonic(self):
        self.clock_calls += 1
        if self.clock_calls > 4096:
            raise AssertionError("fake clock's finite call budget exhausted")
        value = self.now
        self.now += 0.001
        if self.cancel_at is not None and value >= self.cancel_at:
            self.session.cancelled = True
        return value

    def domain(self, platform, uid, *, collision=False, deadline=None):
        if (platform, uid) != (self.session.platform, self.session.uid):
            raise AssertionError("wrong synthetic identity domain")
        self.domain_calls += 1
        self.events.append(("domain", self.domain_calls))
        self.events.append(("domain-deadline", self.domain_calls, deadline))
        if deadline is not None:
            self.module._remaining(deadline)
        if self.domain_calls == 1:
            return {}
        if self.cancel_on_finality:
            self.session.cancelled = True
        if self.final_time is not None:
            self.now = self.final_time
        if deadline is not None:
            self.module._remaining(deadline)
        if isinstance(self.final_domain, BaseException):
            raise self.final_domain
        return self.final_domain

    def mac_snapshot(self, *, deadline=None):
        self.events.append(("root-snapshot", deadline, self.session._active))
        self.now += self.snapshot_advance
        if self.snapshot_error is not None:
            raise self.snapshot_error
        if self.snapshot_rows is None:
            raise AssertionError("native census is forbidden; this case needs explicit synthetic rows")
        return self.snapshot_rows

    def popen(self, command, **kwargs):
        self.events.append(("popen", tuple(command), kwargs))
        return self.child

    def make_selector(self):
        self.events.append(("selector-acquire",))
        if self.selector_error is not None:
            raise self.selector_error
        return self.selector

    def open(self, path, flags, mode):
        required = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        if Path(path).parent != self.session.control or flags != required or mode != 0o600:
            raise AssertionError("capture creation escaped the exact private-file contract")
        fd = 100 + len(self.opened)
        self.opened.append(Path(path))
        self.captures[fd] = bytearray()
        self.events.append(("capture-open", fd))
        return fd

    def read(self, fd, size):
        index = fd - 10
        self.events.append(("read", index, size, self.session.failure))
        if size <= 0:
            raise AssertionError("zero-sized read cannot prove EOF")
        if not self.chunks[index]:
            if index in self.hold:
                raise BlockingIOError("synthetic held pipe")
            return b""
        data = self.chunks[index].pop(0)
        if len(data) > size:
            self.chunks[index].insert(0, data[size:])
        return data[:size]

    def write(self, fd, view):
        count = min(len(view), self.write_step)
        self.captures[fd].extend(view[:count])
        self.events.append(("capture-write", fd, count))
        if fd - 100 == self.after_write_error:
            raise OSError("synthetic write changed state before reporting failure")
        return count

    def fsync(self, fd):
        self.events.append(("capture-fsync", fd))
        if fd - 100 in self.fsync_errors:
            raise OSError("synthetic fsync")

    def fstat(self, fd):
        self.events.append(("capture-fstat", fd))
        if fd - 100 in self.fstat_errors:
            raise OSError("synthetic fstat")
        return SimpleNamespace(st_size=len(self.captures[fd]))

    def close(self, fd):
        self.events.append(("capture-close", fd))
        if fd - 100 in self.fd_close_errors:
            raise OSError("synthetic capture close")

    def cleanup(self, *, deadline=None):
        self.events.append(("cleanup",))
        self.events.append(("cleanup-deadline", deadline))
        return list(self.cleanup_diagnostics)

    @contextmanager
    def scope(self):
        # Deliberately no fallback to real OS/process/signal attributes.
        constants = {k: getattr(os, k) for k in (
            "O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC",
        )}
        fake_os = SimpleNamespace(**constants, open=self.open, read=self.read,
                                  write=self.write, fsync=self.fsync, fstat=self.fstat,
                                  close=self.close, set_blocking=lambda *_: None,
                                  geteuid=lambda: 0,
                                  path=SimpleNamespace(basename=os.path.basename))
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(
                self.module, os=fake_os,
                subprocess=SimpleNamespace(Popen=self.popen, DEVNULL=-3, PIPE=-1),
                selectors=SimpleNamespace(DefaultSelector=self.make_selector, EVENT_READ=1),
                time=SimpleNamespace(monotonic=self.monotonic,
                    time_ns=lambda: 1_789_029_600_000_000_000 + int(self.now * 1_000_000_000)), signal=SimpleNamespace(),
                _domain=self.domain, _canonical=Path,
                _small_command=Mock(side_effect=AssertionError("native metadata is forbidden")),
                _mac_snapshot=self.mac_snapshot,
            ))
            stack.enter_context(patch.object(self.session, "_headroom", Mock()))
            stack.enter_context(patch.object(self.session, "_cleanup", self.cleanup))
            # Dedicated fixed-node tests exercise the real Linux boundary with
            # in-memory I/O. The collector rig must never inspect host sysctls.
            stack.enter_context(patch.object(self.session, "_assert_userns_boundary", Mock()))
            stack.enter_context(patch.object(self.session, "_argv", return_value=(["/synthetic/entry"], {})))
            yield

    def collect(self, *, seconds=1.0, output_limit=64, latch=True, absolute_deadline=None):
        with self.scope():
            kwargs = dict(cwd=self.session.work, env={}, seconds=seconds, output_limit=output_limit)
            if absolute_deadline is not None:
                kwargs["absolute_deadline"] = absolute_deadline
            if latch:
                return self.session.run([str(self.session.python), "--synthetic"], **kwargs)
            return self.session._run([str(self.session.python), "--synthetic"], latch=False, **kwargs)


class _UsernsFile:
    """One entirely in-memory fixed node; no proc, descriptor or kernel effects.

    Every OS callable belongs to this double, with no stdlib fallback. Hooks
    inject before/after-effect faults while the real owner/checker code runs.
    """
    def __init__(self, module, session=None, raw=b"12345\n", *, access=os.O_RDWR):
        self.module, self.session, self.raw = module, session, raw
        self.access, self.fd, self.cursor, self.now = access, 602, 0, 0.0
        self.node = SimpleNamespace(st_dev=17, st_ino=91, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644)
        self.named = None
        self.events, self.counts = [], {}
        self.before = self.after = lambda *_: None
        self.inheritable = self.closed = False
        self.short_write = None
        self.domain_state = {}

    def event(self, name, *args):
        self.counts[name] = self.counts.get(name, 0) + 1
        if self.counts[name] > 128:
            raise AssertionError("in-memory node's finite operation budget exhausted")
        self.events.append((name, *args))
        self.before(name, *args)

    def descriptor(self, fd):
        if fd != self.fd or self.closed:
            raise AssertionError("operation escaped the original fake descriptor's custody")

    def open(self, path, flags):
        expected = self.access | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if (path, flags) != (Path("/proc/sys/user/max_user_namespaces"), expected):
            raise AssertionError("only the fixed nofollow uninherited proc-node contract is allowed")
        self.event("open", flags)
        if self.counts["open"] != 1:
            raise AssertionError("the original owner may acquire its fixed descriptor only once")
        self.after("open", flags)
        return self.fd

    def fstat(self, fd):
        self.descriptor(fd)
        self.event("fstat")
        result = SimpleNamespace(**vars(self.node))
        self.after("fstat")
        return result

    def stat(self, path, *, follow_symlinks):
        if (path, follow_symlinks) != (Path("/proc/sys/user/max_user_namespaces"), False):
            raise AssertionError("fixed-node metadata must not follow a link or inspect another path")
        self.event("stat")
        result = SimpleNamespace(**vars(self.named if self.named is not None else self.node))
        self.after("stat")
        return result

    def get_inheritable(self, fd):
        self.descriptor(fd)
        self.event("inheritable")
        return self.inheritable

    def lseek(self, fd, position, whence):
        self.descriptor(fd)
        if (position, whence) != (0, os.SEEK_SET):
            raise AssertionError("only one bounded seek-to-zero operation is permitted")
        self.event("seek")
        self.cursor = 0
        self.after("seek")
        return 0

    def read(self, fd, count):
        self.descriptor(fd)
        if count not in {1, 22}:
            raise AssertionError("fixed-node read exceeded its strict per-operation bound")
        self.event("read", count)
        value = self.raw[self.cursor:self.cursor + count]
        self.cursor += len(value)
        self.after("read", count)
        return value

    def write(self, fd, raw):
        self.descriptor(fd)
        if self.access != os.O_RDWR or not isinstance(raw, bytes) or not 2 <= len(raw) <= 21 or self.cursor != 0:
            raise AssertionError("write escaped fixed original-owner access/seek/byte bounds")
        self.event("write", raw)
        if self.counts["write"] > 2:
            raise AssertionError("no retry of an ambiguous preparation or restoration is permitted")
        count = len(raw) if self.short_write is None else self.short_write
        self.raw, self.cursor = raw[:count], count
        self.after("write", raw)
        return count

    def close(self, fd):
        self.descriptor(fd)
        self.event("close")
        self.closed = True  # A reported close error must not authorize a retry.
        self.after("close")

    def domain(self, platform, uid, *, deadline, **kwargs):
        if self.session is None or (platform, uid, deadline) != ("linux", self.session.uid, self.session.deadline):
            raise AssertionError("only this fake reserved identity's original deadline may be observed")
        self.event("domain")
        self.module._remaining(deadline)
        if isinstance(self.domain_state, BaseException):
            raise self.domain_state
        return self.domain_state

    @contextmanager
    def scope(self):
        constants = {name: getattr(os, name) for name in
                     ("O_RDONLY", "O_RDWR", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "SEEK_SET")}
        fake_os = SimpleNamespace(**constants, open=self.open, fstat=self.fstat, stat=self.stat,
            get_inheritable=self.get_inheritable, lseek=self.lseek, read=self.read, write=self.write, close=self.close,
            geteuid=lambda: 0, getuid=lambda: 0, getgid=lambda: 0, getegid=lambda: 0,
            path=SimpleNamespace(basename=os.path.basename))
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(self.module, os=fake_os, sys=SimpleNamespace(platform="linux"),
                time=SimpleNamespace(monotonic=lambda: self.now), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                signal=SimpleNamespace(), resource=SimpleNamespace(), selectors=SimpleNamespace(), _domain=self.domain,
                _small_command=Mock(side_effect=AssertionError("fixed-node fake may not start a process"))))
            for method in ("open", "stat", "lstat", "read_bytes", "read_text", "write_bytes", "chmod", "unlink"):
                stack.enter_context(patch.object(Path, method, side_effect=AssertionError("fixed-node fake may not access host files")))
            if self.session is not None:
                stack.enter_context(patch.object(self.session, "_headroom", Mock()))
            yield


class CISandboxPureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = sandbox_module()

    def test_result_requires_all_success_facts_and_is_immutable(self):
        result = self.module.CapturedRun(b"PASS\n", b"", 0, True, True, True,
                                         True, False, False, 0.1, None, (), (5, 0))
        self.assertTrue(result.ok)
        self.assertEqual(result.status, 0)
        self.assertTrue(result.finality)
        bad_fields = dict(returncode=7, waited=False, stdout_eof=False, stderr_eof=False,
                          domain_finality=False, timed_out=True, cancelled=True,
                          primary_error="late failure", cleanup_errors=("close failed",))
        for field, value in bad_fields.items():
            with self.subTest(field=field):
                self.assertFalse(dataclasses.replace(result, **{field: value}).ok)
        self.assertFalse(dataclasses.replace(result, returncode=None).ok)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.waited = False

    def test_first_failure_and_original_aggregate_guard_never_reset(self):
        session = session_double(self.module)
        with patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 0.0)):
            session.fail("first parser/provenance failure")
            session.fail("later failure")
            self.assertEqual(session.failure, "first parser/provenance failure")
            with self.assertRaisesRegex(self.module.SessionError, "first parser/provenance"):
                session._guard()
        session = session_double(self.module)
        with patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: session.deadline)):
            with self.assertRaisesRegex(self.module.SessionError, "original aggregate deadline"):
                session._guard()
        with patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 0.0)):
            with self.assertRaisesRegex(self.module.SessionError, "original aggregate deadline"):
                session._guard()
        self.assertEqual(session.deadline, 100.0)
        with patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            self.assertEqual(self.module._remaining(10.25), 0.25)
            with self.assertRaises(self.module.DeadlineExpired):
                self.module._remaining(10.0)
            for invalid in (None, True, float("nan"), float("inf")):
                with self.subTest(deadline=invalid), self.assertRaises(self.module.SessionError):
                    self.module._remaining(invalid)

    def test_constructor_rejects_early_guards_before_allocation_or_timer_ownership(self):
        kwargs = dict(platform="linux", root=Path("/tmp/mrk-pure-fixture"),
                      python="/fixture-tools/python/bin/python", ruby="/fixture-tools/ruby/bin/ruby",
                      runner_home="/home/runner", runner_temp="/home/runner/work/_temp",
                      tool_prefixes=("/fixture-tools/python", "/fixture-tools/ruby"), deadline=20.0)
        cases = (
            ({"platform": "darwin"}, 0, (0.0, 0.0), 0),
            ({}, 1000, (0.0, 0.0), 0),
            ({"deadline": 0.0}, 0, (0.0, 0.0), 0),
            ({"deadline": 3301.0}, 0, (0.0, 0.0), 0),
            ({}, 0, (1.0, 0.0), 0),
            ({}, 0, (0.0, 0.0), 1),  # Ignored SIGCHLD cannot retain wait ownership.
            ({}, 0, (0.0, 0.0), object()),  # Nor may an external reaper handler.
        )
        for changed, euid, timer, disposition in cases:
            with self.subTest(changed=changed, euid=euid, timer=timer, disposition=disposition):
                canonical = Mock(side_effect=AssertionError("resource path must not be entered"))
                fake_signal = SimpleNamespace(ITIMER_REAL=0, getitimer=Mock(return_value=timer),
                                              setitimer=Mock(), signal=Mock(), SIGCHLD=17, SIG_DFL=0,
                                              getsignal=Mock(return_value=disposition))
                with patch.multiple(self.module, _canonical=canonical,
                                    os=SimpleNamespace(geteuid=lambda: euid),
                                    sys=SimpleNamespace(platform="linux"), signal=fake_signal,
                                    time=SimpleNamespace(monotonic=lambda: 0.0)):
                    with self.assertRaises(self.module.SessionError) as caught:
                        self.module.Session(**(kwargs | changed))
                    if disposition != 0:
                        self.assertIn("default SIGCHLD", str(caught.exception))
                canonical.assert_not_called()
                fake_signal.setitimer.assert_not_called()
                fake_signal.signal.assert_not_called()
        for changed, owner, mode, parent_owner, parent_mode, reason in (
            ({"root": "/var/mrk-pure-fixture"}, 0, 0o755, 0, 0o1777, "direct child of platform tmp"),
            ({}, 0, 0o755, 1, 0o1777, "sticky-directory protection"),
            ({}, 0, 0o755, 0, 0o755, "sticky-directory protection"),
            ({}, 1, 0o755, 0, 0o1777, "task root must be root-owned0755"),
            ({}, 0, 0o700, 0, 0o1777, "task root must be root-owned0755"),
            ({"tool_prefixes": ("/tmp/mrk-pure-fixture",)}, 0, 0o755, 0, 0o1777, "runtime prefix overlaps"),
            ({"tool_prefixes": ("/",)}, 0, 0o755, 0, 0o1777, "runtime prefix overlaps"),
            ({"python": "/unapproved/python"}, 0, 0o755, 0, 0o1777, "runtime outside admitted tool prefixes"),
        ):
            with self.subTest(changed=changed, owner=owner, mode=mode, reason=reason):
                root = Path(changed.get("root", kwargs["root"]))

                def path_state(path):
                    if path == root.parent:
                        return SimpleNamespace(st_uid=parent_owner, st_mode=stat.S_IFDIR | parent_mode)
                    if path == root:
                        return SimpleNamespace(st_uid=owner, st_mode=stat.S_IFDIR | mode)
                    raise AssertionError("unexpected constructor stat outside the two synthetic roots")

                fake_signal = SimpleNamespace(ITIMER_REAL=0, getitimer=lambda _: (0.0, 0.0),
                                              setitimer=Mock(), signal=Mock(), SIGCHLD=17, SIG_DFL=0,
                                              getsignal=Mock(return_value=0))
                with patch.multiple(self.module, _canonical=Path,
                                    os=SimpleNamespace(geteuid=lambda: 0),
                                    sys=SimpleNamespace(platform="linux"), signal=fake_signal,
                                    time=SimpleNamespace(monotonic=lambda: 0.0),
                                    secrets=SimpleNamespace(randbelow=lambda _: 1)), \
                     patch.object(Path, "stat", path_state), \
                     patch.object(Path, "mkdir", side_effect=AssertionError("allocation forbidden")) as mkdir, \
                     patch.object(Path, "chmod", side_effect=AssertionError("permission changes forbidden")) as chmod, \
                     patch.object(self.module, "_private_file", side_effect=AssertionError("write forbidden")) as write:
                    with self.assertRaisesRegex(self.module.SessionError, reason):
                        self.module.Session(**(kwargs | changed))
                mkdir.assert_not_called()
                chmod.assert_not_called()
                write.assert_not_called()
                fake_signal.setitimer.assert_not_called()
                fake_signal.signal.assert_not_called()

        uid = gid = 60001
        for owner, group, mode, root_owned, non_set_id, kind, rejected in (
            (1001, 1001, 0o755, False, True, stat.S_IFREG, ()),  # Provider Python need not be root-owned.
            (0, 0, 0o755, True, True, stat.S_IFREG, ()),  # Fixed sandbox-exec/true role.
            (uid, 0, 0o755, False, True, stat.S_IFREG, ("subject-owned",)),
            (0, gid, 0o775, False, True, stat.S_IFREG, ("subject-group-writable",)),
            (0, 0, 0o757, False, True, stat.S_IFREG, ("world-writable",)),
            (0, 0, 0o644, False, True, stat.S_IFREG, ("no-execute-bit",)),
            (0, 0, 0o4755, True, True, stat.S_IFREG, ("set-id-forbidden",)),
            (0, 0, 0o2755, False, True, stat.S_IFREG, ("set-id-forbidden",)),
            (1001, 0, 0o755, True, True, stat.S_IFREG, ("root-role-not-root-owned",)),
            (0, 0, 0o775, True, True, stat.S_IFREG, ("root-role-group-or-world-writable",)),
            (0, 0, 0o4755, True, False, stat.S_IFREG, ()),  # Negative sudo role may be set-ID.
            (0, 0, 0o755, True, True, stat.S_IFDIR, ("not-regular",)),
            (uid, gid, 0o6666, True, True, stat.S_IFIFO,
             ("not-regular", "no-execute-bit", "subject-owned", "world-writable", "subject-group-writable",
              "root-role-not-root-owned", "root-role-group-or-world-writable", "set-id-forbidden")),
        ):
            snapshot = SimpleNamespace(st_uid=owner, st_gid=group, st_mode=kind | mode)
            expected = {"role": "python", "kind": {stat.S_IFREG: "regular", stat.S_IFDIR: "directory", stat.S_IFIFO: "fifo"}[kind],
                        "mode": format(mode, "04o"), "root_owned": owner == 0, "subject_owned": owner == uid,
                        "subject_group": group == gid, "setuid": bool(mode & stat.S_ISUID), "setgid": bool(mode & stat.S_ISGID),
                        "owner_execute": bool(mode & 0o100), "group_execute": bool(mode & 0o010),
                        "other_execute": bool(mode & 0o001), "failed_predicates": list(rejected)}
            with self.subTest(executable=(owner, group, mode, root_owned, non_set_id, kind)), \
                 patch.object(Path, "stat", side_effect=[snapshot, AssertionError("no diagnostic restat may replace the decision")]) as query:
                if not rejected:
                    flags = self.module._admit_executable(Path("/synthetic/tool"), uid, gid,
                                                         root_owned=root_owned, non_set_id=non_set_id, role="python")
                    self.assertEqual(flags, expected)
                else:
                    with self.assertRaisesRegex(self.module.SessionError, "permission/identity contract") as caught:
                        self.module._admit_executable(Path("/synthetic/tool"), uid, gid,
                                                     root_owned=root_owned, non_set_id=non_set_id, role="python")
                    self.assertEqual(caught.exception._ci_observation, {"tool": expected})
                    self.assertNotIn("/synthetic/tool", json.dumps(self.module._exception_notes(caught.exception)))
                    self.assertNotIn(str(uid), json.dumps(caught.exception._ci_observation))
                query.assert_called_once_with()

        for kind, label in ((stat.S_IFREG, "regular"), (stat.S_IFDIR, "directory"), (stat.S_IFLNK, "symlink"),
                            (stat.S_IFIFO, "fifo"), (stat.S_IFSOCK, "socket"), (stat.S_IFCHR, "character"),
                            (stat.S_IFBLK, "block"), (0, "other")):
            snapshot = SimpleNamespace(st_uid=0, st_gid=0, st_mode=kind | 0o755)
            note = self.module._tool_stat_note(snapshot, uid, gid, role="ruby")
            self.assertEqual((note["role"], note["kind"], note["mode"]), ("ruby", label, "0755"))
            self.assertEqual(set(note), {"role", "kind", "mode", "root_owned", "subject_owned", "subject_group",
                                        "setuid", "setgid", "owner_execute", "group_execute", "other_execute"})
            self.assertTrue(all(type(value) is bool for key, value in note.items() if key not in {"role", "kind", "mode"}))
        snapshot = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o755)
        for role in ("python", "ruby", "sudo", "true", "sandbox-exec", "ps", "compiler", "linker", "signature-tool", "unspecified"):
            self.assertEqual(self.module._tool_stat_note(snapshot, uid, gid, role=role)["role"], role)
        for invalid_role in ("synthetic-private-role-canary", None, 7):
            self.assertEqual(self.module._tool_stat_note(snapshot, uid, gid, role=invalid_role)["role"], "unspecified")
        for role in ("python", "compiler", "synthetic-private-role-canary"):
            original = OSError(errno.EACCES, "synthetic-private-stat-message", "/synthetic/private-stat-canary")
            cause = ValueError("synthetic-private-original-cause")
            original.__cause__ = cause
            original_args = original.args
            with patch.object(Path, "stat", side_effect=original) as query:
                with self.assertRaises(OSError) as caught:
                    self.module._admit_executable(Path("/synthetic/private-stat-canary"), uid, gid, role=role)
            self.assertIs(caught.exception, original)
            self.assertIs(original.__cause__, cause)
            self.assertEqual((original.args, original.errno, original.filename),
                             (original_args, errno.EACCES, "/synthetic/private-stat-canary"))
            query.assert_called_once_with()
            observation = {"tool_stat_failure": {"role": role if role in {"python", "compiler"} else "unspecified", "observed": False}}
            self.assertEqual(original._ci_observation, observation)  # No successful stat, so no fabricated inode.
            notes = self.module._exception_notes(original)
            self.assertEqual((notes[0]["exception"], notes[0]["errno"], notes[0]["observation"]),
                             ("PermissionError", errno.EACCES, observation))
            self.assertNotIn("synthetic-private", json.dumps(notes))

        # The actual admission caller must select the different fixed roles,
        # retain each original stat incrementally, and never present a later
        # tool's refusal as though earlier metadata had not been observed.

        class GrantBoundary(RuntimeError):
            pass

        admit_executable = self.module._admit_executable
        for case in ("grant-boundary", "later-rejection", "later-stat-error"):
            with self.subTest(incremental_tools=case):
                session = session_double(self.module, "darwin")
                session.admitted = False
                session.process_observer = None
                expected_roles = {session.python: {"role": "python"},
                                  Path("/usr/bin/sudo"): {"role": "sudo", "root_owned": True, "non_set_id": False},
                                  Path("/usr/bin/true"): {"role": "true", "root_owned": True},
                                  Path("/usr/bin/sandbox-exec"): {"role": "sandbox-exec", "root_owned": True},
                                  Path("/bin/ps"): {"role": "ps", "root_owned": True, "non_set_id": False}}
                seen = []
                original = OSError(errno.EACCES, "synthetic-private-stat-message", "/synthetic/private-stat-canary")

                def tool_state(path):
                    self.assertIn(path, expected_roles)
                    row = next(n for n in session.admission_results if n["name"] == "fixed-entry-tools")
                    self.assertFalse(row["ok"])
                    self.assertEqual(list(row["tools"]), [expected_roles[p]["role"] for p in seen])
                    seen.append(path)
                    if case == "later-stat-error" and path == Path("/usr/bin/sudo"):
                        raise original
                    owner = 1001 if path == session.python else 0
                    mode = 0o4755 if path in {Path("/usr/bin/sudo"), Path("/bin/ps")} else 0o755
                    if case == "later-rejection" and path == Path("/usr/bin/true"):
                        mode = 0o777
                    return SimpleNamespace(st_uid=owner, st_gid=0, st_mode=stat.S_IFREG | mode)

                chown = Mock(side_effect=GrantBoundary)
                with patch.multiple(self.module, _readonly_tree=Mock(), _domain=Mock(return_value=set()),
                                    _small_command=Mock(return_value=b"MRK_NSS_ABSENT\n"),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: 0.0),
                                    os=SimpleNamespace(chown=chown, path=SimpleNamespace(basename=os.path.basename))), \
                     patch.object(session, "_headroom", Mock()), patch.object(Path, "stat", tool_state), \
                     patch.object(session, "_prepare_home_boundary", Mock()), \
                     patch.object(Path, "mkdir", side_effect=AssertionError("no admission allocation is permitted")), \
                     patch.object(self.module, "_admit_executable", wraps=admit_executable) as tools:
                    expected_error = GrantBoundary if case == "grant-boundary" else OSError if case == "later-stat-error" else self.module.SessionError
                    with self.assertRaises(expected_error) as caught:
                        session.admit()
                count = {"grant-boundary": 5, "later-rejection": 3, "later-stat-error": 2}[case]
                self.assertEqual(seen, list(expected_roles)[:count])  # No second stat or skipped fixed role.
                self.assertEqual({c.args[0]: c.kwargs for c in tools.call_args_list}, dict(list(expected_roles.items())[:count]))
                row = next(n for n in session.admission_results if n["name"] == "fixed-entry-tools")
                self.assertEqual(row["ok"], case == "grant-boundary")
                self.assertEqual(row["tools"]["python"]["mode"], "0755")
                self.assertFalse(row["tools"]["python"]["root_owned"])
                self.assertFalse(session.admitted)
                self.assertIsNone(session.process_observer)
                self.assertEqual(session.failure, "native isolation admission failed; no product command permitted")
                if case == "grant-boundary":
                    chown.assert_called_once_with(session.work, session.uid, session.gid)
                    self.assertNotIn("failed_role", row)
                else:
                    chown.assert_not_called()
                    self.assertEqual(row["failed_role"], "true" if case == "later-rejection" else "sudo")
                    if case == "later-rejection":
                        self.assertEqual(row["tools"]["true"], caught.exception._ci_observation["tool"])
                        self.assertEqual(row["tools"]["true"]["failed_predicates"],
                                         ["world-writable", "root-role-group-or-world-writable"])
                    else:
                        self.assertIs(caught.exception, original)
                        self.assertEqual(list(row["tools"]), ["python"])
                        self.assertEqual(original._ci_observation, {"tool_stat_failure": {"role": "sudo", "observed": False}})
                self.assertNotIn("synthetic-private", json.dumps(session.admission_results))

        # Ruby's pre-probe metadata is bounded observation only: even unusable
        # POSIX bits or a nonregular type cannot introduce a new permission gate.
        for case in ("regular", "permissive-bits", "nonregular", "maximum-depth", "too-deep", "stat-error", "initial-expiry", "late-stat"):
            with self.subTest(ruby_metadata=case):
                session = session_double(self.module)
                session.admitted = False
                session.ruby = Path("/synthetic/private-ruby-canary/bin/ruby")
                if case in {"maximum-depth", "too-deep"}:
                    session.ruby = Path("/").joinpath(*(f"p{i}" for i in range(31 if case == "maximum-depth" else 32)), "ruby")
                session.deadline = 1.0
                paths = [session.ruby, *session.ruby.parents]
                seen, clock = [], SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                original = OSError(errno.EACCES, "synthetic-private-ruby-message", "/synthetic/private-ruby-canary")

                def observed(path):
                    self.assertLess(len(seen), 33)
                    self.assertEqual(path, paths[len(seen)])
                    seen.append(path)
                    if case == "stat-error" and len(seen) == 2:
                        raise original
                    if case == "late-stat" and len(seen) == 2:
                        clock.now = 1.0
                    owner, group, mode = (session.uid, session.gid, 0o6666) if case == "permissive-bits" else (0, 0, 0o755)
                    kind = stat.S_IFIFO if case == "nonregular" else stat.S_IFREG if path == session.ruby else stat.S_IFDIR
                    return SimpleNamespace(st_uid=owner, st_gid=group, st_mode=kind | mode)

                no_launch = Mock(side_effect=AssertionError("metadata observation grants no process role"))
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now),
                                    _admit_executable=Mock(side_effect=AssertionError("Ruby metadata is not new tool admission"))), \
                     patch.object(session, "_run", no_launch), patch.object(Path, "stat", observed), \
                     patch.object(Path, "resolve", side_effect=AssertionError("constructor already supplied the canonical path")), \
                     patch.object(Path, "iterdir", side_effect=AssertionError("no provider enumeration is permitted")):
                    if case in {"regular", "permissive-bits", "nonregular", "maximum-depth"}:
                        session._ruby_path_metadata()
                    else:
                        with self.assertRaises(OSError if case == "stat-error" else self.module.SessionError) as caught:
                            session._ruby_path_metadata()
                        if case == "stat-error":
                            self.assertIs(caught.exception, original)
                        if "expiry" in case or case == "late-stat":
                            self.assertIsInstance(caught.exception, self.module.DeadlineExpired)
                no_launch.assert_not_called()
                self.assertEqual(len(session.admission_results), 1)
                row = session.admission_results[0]
                self.assertEqual((row["name"], row["semantics"]), ("ruby-path-metadata", "posix-mode-bits-only"))
                self.assertEqual(row["ok"], case in {"regular", "permissive-bits", "nonregular", "maximum-depth"})
                self.assertEqual(seen, paths[:0 if case in {"too-deep", "initial-expiry"} else 2 if case in {"stat-error", "late-stat"} else len(paths)])
                self.assertEqual(len(row["entries"]), len(seen) - (case == "stat-error"))
                for index, item in enumerate(row["entries"]):
                    self.assertEqual((item["index"], item["role"]), (index, "ruby"))
                    self.assertEqual(set(item), {"index", "role", "kind", "mode", "root_owned", "subject_owned", "subject_group",
                                                "setuid", "setgid", "owner_execute", "group_execute", "other_execute"})
                    if case == "permissive-bits":
                        self.assertEqual(item["mode"], "6666")
                        self.assertTrue(item["subject_owned"] and item["subject_group"] and item["setuid"] and item["setgid"])
                        self.assertFalse(item["owner_execute"] or item["group_execute"] or item["other_execute"])
                if case == "stat-error":
                    self.assertEqual(row["unobserved_index"], 1)
                else:
                    self.assertNotIn("unobserved_index", row)
                self.assertFalse(session.admitted)
                self.assertIsNone(session.failure)
                self.assertEqual(session.deadline, 1.0)
                self.assertNotIn("private-ruby-canary", json.dumps(row))

    def test_environment_never_inherits_ambient_or_overrides_fixed_boundaries(self):
        session = session_double(self.module)
        ambient = {"GH_TOKEN": "synthetic-not-a-secret", "HTTP_PROXY": "http://synthetic.invalid",
                   "PYTHONPATH": "/ambient", "RUBYOPT": "-rambient", "LD_PRELOAD": "/ambient.so"}
        with patch.object(self.module, "os", SimpleNamespace(environ=ambient)):
            result = session._environment({"JAVA_TOOL_OPTIONS": self.module.JAVA_LIMITS})
        self.assertFalse(set(result) & set(ambient))
        self.assertEqual(result["HOME"], str(session.work / "home"))
        self.assertEqual(result["USER"], f"mrk-ci-{session.uid}")
        self.assertEqual(result["TMPDIR"], str(session.work / "tmp"))
        for key, wanted in {"PIP_NO_INDEX": "1", "PIP_CONFIG_FILE": "/dev/null",
                            "BUNDLE_IGNORE_CONFIG": "1", "GEMRC": "/dev/null",
                            "GIT_CONFIG_COUNT": "0", "GIT_CONFIG_GLOBAL": "/dev/null"}.items():
            self.assertEqual(result[key], wanted)
            with self.subTest(fixed=key), self.assertRaises(self.module.SessionError):
                session._environment({key: "changed"})
        invalid = [{k: v} for k, v in ambient.items()]
        invalid += [{"HOME": "/other"}, {"LANG": "x\0y"}, {"TERM": 7},
                    {"TERM": "x" * 32769}, {"JAVA_TOOL_OPTIONS": "-Dunreviewed=true"}]
        for values in invalid:
            with self.subTest(values=list(values)), self.assertRaises(self.module.SessionError):
                session._environment(values)

        observer_key = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"
        for platform in ("linux", "darwin"):
            session = session_double(self.module, platform)
            session.process_observer = None
            fixed_path = session.bootstrap / "process-observer"
            with patch.object(self.module, "os", SimpleNamespace(environ={observer_key: "/ambient/observer"})):
                self.assertNotIn(observer_key, session._environment({}))
                with self.assertRaises(self.module.SessionError):
                    session._environment({observer_key: str(fixed_path)})
            if platform == "darwin":
                # Even a malformed admitted object cannot downgrade a public
                # product call to system ps when the owner selector is missing.
                with patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 0.0)), \
                     patch.object(session, "_run", side_effect=AssertionError("missing admission must forbid launch")) as run:
                    with self.assertRaisesRegex(self.module.SessionError, "observer admission is missing"):
                        session.run([str(session.python)], cwd=session.work, env={}, seconds=1)
                    run.assert_not_called()
                session.process_observer = fixed_path
                self.assertEqual(session._environment({})[observer_key], str(fixed_path))
                self.assertEqual(session._environment({observer_key: str(fixed_path)})[observer_key], str(fixed_path))
                for value in ("/ambient/observer", str(session.work / "process-observer"), ""):
                    with self.assertRaises(self.module.SessionError):
                        session._environment({observer_key: value})
            session.process_observer = session.work / "unreviewed-observer"
            with self.assertRaisesRegex(self.module.SessionError, "fixed owner binding"):
                session._environment({})

    def test_environment_search_and_input_paths_cannot_cross_domains(self):
        session = session_double(self.module)
        allowed = {"VIRTUAL_ENV": str(session.work / "venv"), "GEM_PATH": str(session.work / "gems"),
                   "PIP_FIND_LINKS": str(session.inputs / "python"),
                   "BUNDLE_CACHE_PATH": str(session.inputs / "gems"),
                   "BUNDLE_GEMFILE": str(session.source / "Gemfile")}
        self.assertTrue(allowed.items() <= session._environment(allowed).items())
        invalid = ({"GEM_PATH": str(session.work / "gems") + ":/home/runner/private"},
                   {"VIRTUAL_ENV": str(session.work) + "-other/venv"},
                   {"GEM_HOME": str(session.work / ".." / "control")},
                   {"MOBILE_RELEASE_TEST_PYTHON": "/bin/python"},
                   {"BUNDLE_USER_HOME": "relative"}, {"PIP_FIND_LINKS": str(session.work)},
                   {"BUNDLE_CACHE_PATH": str(session.inputs / "other")},
                   {"BUNDLE_GEMFILE": str(session.work / "Gemfile")},
                   {"PATH": "/usr/bin:"}, {"PATH": ".:/usr/bin"},
                   {"PATH": "/home/runner/bin:/usr/bin"},
                   {"PATH": str(session.work / ".." / "control")})
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(self.module.SessionError):
                session._environment(values)

    def test_linux_namespace_setup_precedes_numeric_drop_without_popen_demotion(self):
        session = session_double(self.module)
        umask = Mock(side_effect=AssertionError("namespace modes must not change controller umask"))
        with patch.object(Path, "exists", return_value=True), \
             patch.object(self.module, "os", SimpleNamespace(umask=umask)):
            argv, kwargs = session._argv([str(session.python), "--synthetic"], 180)
        umask.assert_not_called()
        self.assertEqual(kwargs, {})
        self.assertEqual(argv[0], "/usr/bin/bwrap")
        self.assertNotIn("--unshare-user", argv)
        self.assertNotIn("--disable-userns", argv)
        drop = argv.index("/usr/bin/setpriv")
        for flag in ("--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
                     "--new-session", "--die-with-parent", "--assert-userns-disabled", "--proc", "--dev", "--tmpfs"):
            self.assertLess(argv.index(flag), drop)
        self.assertEqual(argv.count("--assert-userns-disabled"), 1)
        self.assertEqual(argv[drop:drop + 12], ["/usr/bin/setpriv", "--reuid", str(session.uid),
                         "--regid", str(session.gid), "--clear-groups", "--no-new-privs",
                         "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--", str(session.python)])
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"],
                         ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"])
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        # bwrap's implicit bind-parent creation need not make a traversable
        # directory; set the synthetic namespace root's mode explicitly AFTER
        # the fresh /tmp mount and BEFORE binding any task inputs beneath it.
        root_mode = argv.index("--perms")
        self.assertEqual(argv[root_mode:root_mode + 4], ["--perms", "0755", "--dir", str(session.root)])
        self.assertEqual(argv.count("--perms"), 1)
        tmp_mount = next(i for i, arg in enumerate(argv) if arg == "--tmpfs" and argv[i + 1] == "/tmp")
        self.assertLess(tmp_mount, root_mode)
        for source in (session.source, session.inputs, session.bootstrap):
            bind = next(i for i, arg in enumerate(argv) if arg == "--ro-bind" and argv[i + 1] == str(source))
            self.assertLess(root_mode, bind)
            self.assertLess(bind, drop)
        writable = [tuple(argv[i + 1:i + 3]) for i, a in enumerate(argv) if a == "--bind"]
        self.assertEqual(writable, [(str(session.work), str(session.work))])
        for denied in (session.control, session.runner_home, session.runner_temp):
            self.assertNotIn(str(denied), argv)

        # Only the complete fixed Linux Python invocation receives larger
        # logical files, coupled to an entirely read-only host work tree and
        # independent, bounded namespace scratch. This renders argv only.
        python_full = [str(session.work / "source-venv/bin/python"), "-I", "-B",
                       str(session.source / ".github/scripts/ci_checks.py"), "--check", "python-full",
                       "--source-root", str(session.source), "--work-root", str(session.work / "checks"),
                       "--deadline", repr(session.deadline)]
        with patch.object(Path, "exists", return_value=True), \
             patch.multiple(self.module, os=SimpleNamespace(umask=umask), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace()):
            isolated, special_kwargs = session._argv(python_full, 300, profile="python-full")
        self.assertEqual(special_kwargs, {})
        self.assertNotIn("--bind", isolated)
        self.assertNotIn("--unshare-user", isolated)
        self.assertNotIn("--disable-userns", isolated)
        self.assertEqual(isolated.count("--assert-userns-disabled"), 1)
        ro_work = next(i for i, arg in enumerate(isolated) if arg == "--ro-bind" and isolated[i + 1] == str(session.work))
        self.assertEqual(isolated[ro_work:ro_work + 3], ["--ro-bind", str(session.work), str(session.work)])
        expected_mounts = {"/run": 16, "/tmp": 128, "/dev/shm": 16,
                           str(session.work / "tmp"): 640,
                           **{str(session.work / name): 16 for name in
                              ("home", "config", "cache", "gem-cache", "bundle-config", "bundle-home", "checks")}}
        actual_mounts = {}
        for i, token in enumerate(isolated):
            if token != "--tmpfs":
                continue
            self.assertEqual(isolated[i - 4:i - 3], ["--size"])
            self.assertEqual(isolated[i - 2:i], ["--perms", "01777"])
            target, capacity = isolated[i + 1], int(isolated[i - 3])
            self.assertNotIn(target, actual_mounts)
            actual_mounts[target] = capacity
            if Path(target).parent == session.work:
                self.assertGreater(i, ro_work)
        self.assertEqual(actual_mounts, {path: size * self.module.MiB for path, size in expected_mounts.items()})
        self.assertEqual(sum(actual_mounts.values()), 912 * self.module.MiB)  # File-data capacity, not a total-RAM cap.
        self.assertEqual(isolated.count("--size"), len(expected_mounts))
        special_drop = isolated.index("/usr/bin/setpriv")
        self.assertEqual(isolated[special_drop:special_drop + 12], argv[drop:drop + 12])
        entry_role = isolated.index("--enter-python-full")
        self.assertEqual(isolated[entry_role:entry_role + 6],
                         ["--enter-python-full", "linux", str(session.uid), str(session.gid), "300", str(session.policy)])
        self.assertEqual(isolated[entry_role + 6:], python_full)
        for flag in ("--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--new-session", "--die-with-parent",
                     "--assert-userns-disabled"):
            self.assertLess(isolated.index(flag), special_drop)
        self.assertEqual([isolated[i + 1] for i, arg in enumerate(isolated) if arg == "--cap-add"],
                         ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"])
        for denied in (session.control, session.runner_home, session.runner_temp):
            self.assertNotIn(str(denied), isolated)
        self.assertNotIn("--size", argv)  # Ordinary/admission/installer/Ruby profile was not broadened.
        umask.assert_not_called()
        session.runner_home = Path("/opt/runner-private")
        with patch.object(Path, "exists", return_value=True), self.assertRaisesRegex(
            self.module.SessionError, "broad OS bind",
        ):
            session._argv([str(session.python)], 180)

    def test_python_full_profile_is_exact_and_admits_inputs_and_memory_before_collection(self):
        cases = ("valid", "ordinary", "unknown-profile", "wrong-platform", "not-admitted", "admitting", "wrong-cwd", "wrong-seconds",
                 "wrong-cpu", "wrong-output-limit", "unlatched", "cancel-control", "extra-argument",
                 "argument-0", "argument-1", "argument-3", "argument-5", "argument-7", "argument-9", "argument-11",
                 "input-failure", "memory-failure")
        for case in cases:
            with self.subTest(fixed_python_profile=case):
                session = session_double(self.module, "darwin" if case == "wrong-platform" else "linux")
                rig = _Collection(self.module, session)
                command = [str(session.work / "source-venv/bin/python"), "-I", "-B",
                           str(session.source / ".github/scripts/ci_checks.py"), "--check", "python-full",
                           "--source-root", str(session.source), "--work-root", str(session.work / "checks"),
                           "--deadline", repr(session.deadline)]
                self.assertEqual(self.module._python_full_command(session.root, session.deadline), command)
                if case.startswith("argument-"):
                    command[int(case.split("-")[1])] += "-not-the-fixed-role"
                if case == "extra-argument":
                    command.append("--unapproved-reader")
                session.admitted = case != "not-admitted"
                session._admitting = case == "admitting"
                kwargs = dict(cwd=session.work, env={}, seconds=900, output_limit=8 * self.module.MiB,
                              cpu_seconds=300, profile="ordinary" if case == "ordinary" else "python-full")
                changes = {"wrong-cwd": {"cwd": session.source}, "wrong-seconds": {"seconds": 899},
                           "wrong-cpu": {"cpu_seconds": 299}, "wrong-output-limit": {"output_limit": self.module.MiB},
                           "unknown-profile": {"profile": "caller-selected-profile"}}
                kwargs.update(changes.get(case, {}))
                input_error = self.module.SessionError("synthetic fixed profile input refusal")
                memory_error = self.module.SessionError("synthetic fixed profile memory refusal")

                def inputs():
                    self.assertEqual(rig.domain_calls, 1)
                    self.assertFalse(any(e[0] in {"popen", "capture-open"} for e in rig.events))
                    rig.events.append(("profile-inputs",))
                    if case == "input-failure":
                        raise input_error

                def memory(*, deadline):
                    self.assertEqual(deadline, session.deadline)
                    self.assertIn(("profile-inputs",), rig.events)
                    self.assertFalse(any(e[0] in {"popen", "capture-open"} for e in rig.events))
                    rig.events.append(("profile-memory",))
                    if case == "memory-failure":
                        raise memory_error

                with rig.scope(), patch.object(session, "_check_python_full_inputs", side_effect=inputs) as input_check, \
                     patch.object(self.module, "_python_full_memory", side_effect=memory) as memory_check, \
                     patch.object(Path, "stat", side_effect=AssertionError("profile caller must delegate its fixed input observation")), \
                     patch.object(Path, "open", side_effect=AssertionError("profile caller must delegate its bounded memory observation")):
                    if case in {"valid", "ordinary"}:
                        result = session.run(command, **kwargs)
                        self.assertTrue(result.ok, result)
                    else:
                        with self.assertRaises(self.module.SessionError) as caught:
                            if case in {"unlatched", "cancel-control"}:
                                session._run(command, **kwargs, latch=case != "unlatched",
                                             cancel_after=0.01 if case == "cancel-control" else None)
                            else:
                                session.run(command, **kwargs)
                        if case in {"input-failure", "memory-failure"}:
                            self.assertIs(caught.exception, input_error if case == "input-failure" else memory_error)
                    if case in {"valid", "ordinary", "input-failure", "memory-failure"}:
                        session._argv.assert_called_once_with(command, 300, profile=kwargs["profile"])
                    else:
                        session._argv.assert_not_called()
                if case in {"valid", "input-failure", "memory-failure"}:
                    input_check.assert_called_once_with()
                    self.assertEqual(memory_check.call_count, int(case != "input-failure"))
                else:
                    input_check.assert_not_called()
                    memory_check.assert_not_called()
                if case not in {"valid", "ordinary"}:
                    self.assertFalse(any(e[0] in {"popen", "capture-open"} for e in rig.events))
                    self.assertIsNone(session._active)
                    self.assertFalse(session._busy)
                if case not in {"valid", "ordinary", "input-failure", "memory-failure"}:
                    self.assertEqual(rig.domain_calls, 0)
                self.assertEqual(session.deadline, 100.0)

        session = session_double(self.module)
        python, checks = session.work / "source-venv/bin/python", session.source / ".github/scripts/ci_checks.py"
        for case in ("valid", "python-owner", "python-setid", "python-alias", "checks-owner", "checks-writable", "checks-link", "expired"):
            with self.subTest(frozen_profile_inputs=case):
                events = []

                def resolved(path, *, strict):
                    self.assertIn(path, (python, checks))
                    self.assertTrue(strict)
                    events.append(("resolve", path))
                    return path.with_name("other-python") if case == "python-alias" and path == python else path

                def python_state(path):
                    self.assertEqual(path, python)
                    events.append(("stat", path))
                    return SimpleNamespace(st_uid=session.uid if case == "python-owner" else 0, st_gid=0,
                        st_mode=stat.S_IFREG | (0o4755 if case == "python-setid" else 0o755))

                def checks_state(path):
                    self.assertEqual(path, checks)
                    events.append(("lstat", path))
                    return SimpleNamespace(st_uid=session.uid if case == "checks-owner" else 0, st_gid=0,
                        st_mode=(stat.S_IFLNK if case == "checks-link" else stat.S_IFREG) |
                                (0o446 if case == "checks-writable" else 0o444))

                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: 100.0 if case == "expired" else 0.0)), \
                     patch.object(Path, "resolve", resolved), patch.object(Path, "stat", python_state), \
                     patch.object(Path, "lstat", checks_state), \
                     patch.object(Path, "open", side_effect=AssertionError("fixed input admission reads only metadata")):
                    if case == "valid":
                        session._check_python_full_inputs()
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session._check_python_full_inputs()
                if case == "valid":
                    self.assertEqual(events, [("resolve", python), ("stat", python), ("resolve", checks), ("lstat", checks)])
                elif case == "expired":
                    self.assertEqual(events, [])
                self.assertEqual(session.deadline, 100.0)

    def test_python_full_memory_and_entry_limits_are_bounded_without_host_effects(self):
        threshold_kib = 1536 * 1024
        base = f"MemTotal: 8388608 kB\nMemAvailable: {threshold_kib} kB\n".encode()
        cases = ("valid", "low", "missing", "duplicate", "wrong-unit", "invalid-number", "oversized", "read-bound",
                 "open-error", "read-error", "close-error", "read-and-close-error", "initial-expiry", "read-expiry")
        for case in cases:
            with self.subTest(profile_memory_admission=case):
                raw = {"low": base.replace(str(threshold_kib).encode(), str(threshold_kib - 1).encode()),
                       "missing": b"MemTotal: 8388608 kB\n", "duplicate": base + base,
                       "wrong-unit": base.replace(b"kB", b"MiB"), "invalid-number": base.replace(str(threshold_kib).encode(), b"unknown"),
                       "oversized": base + b"x" * 65537, "read-bound": base + b"x" * 200}.get(case, base)
                events, cursor = [], 0
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                body_error = OSError(errno.EIO, "synthetic private memory observation failure", "/synthetic/private-memory")
                close_error = OSError(errno.EIO, "synthetic memory descriptor close failure")

                def opened(path, flags):
                    self.assertEqual((path, flags), (Path("/proc/meminfo"),
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK))
                    events.append(("open",))
                    if case == "open-error":
                        raise body_error
                    return 601

                def read(fd, count):
                    nonlocal cursor
                    self.assertEqual(fd, 601)
                    self.assertTrue(0 < count <= 4096)
                    self.assertLess(sum(e[0] == "read" for e in events), 128)
                    events.append(("read", count))
                    if case in {"read-error", "read-and-close-error"}:
                        raise body_error
                    if case == "read-expiry":
                        clock.now = 1.0
                    size = 1 if case == "read-bound" else count
                    chunk = raw[cursor:cursor + size]
                    cursor += len(chunk)
                    return chunk

                def close(fd):
                    self.assertEqual(fd, 601)
                    events.append(("close",))
                    if case in {"close-error", "read-and-close-error"}:
                        raise close_error

                constants = {key: getattr(os, key) for key in ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, open=opened, read=read, close=close),
                                    subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "open", side_effect=AssertionError("memory admission owns only its bounded descriptor")), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("memory admission must not perform unbounded reads")), \
                     patch.object(Path, "stat", side_effect=AssertionError("no host memory metadata query")):
                    if case == "valid":
                        self.module._python_full_memory(deadline=1.0)
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)) as caught:
                            self.module._python_full_memory(deadline=1.0)
                        failures = caught.exception.exceptions if isinstance(caught.exception, BaseExceptionGroup) else (caught.exception,)
                        if case in {"open-error", "read-error", "read-and-close-error"}:
                            self.assertIn(body_error, failures)
                        if case in {"close-error", "read-and-close-error"}:
                            self.assertIn(close_error, failures)
                self.assertEqual(events.count(("close",)), int(case not in {"initial-expiry", "open-error"}))
                self.assertLessEqual(cursor, 65537)

        # Resource APIs below are a closed in-memory table, never resource's
        # process-wide setters. All original ordinary/Mac ceilings are retained.
        for platform, profile in (("linux", "ordinary"), ("darwin", "ordinary"), ("linux", "python-full")):
            with self.subTest(profile_resource_limits=(platform, profile)):
                expected = {0: 0, 1: 1024, 2: 256,
                            3: (1 << 32) + self.module.MiB if profile == "python-full" else 512 * self.module.MiB,
                            4: 300}
                if platform == "linux":
                    expected[5] = 4 * 1024 * self.module.MiB
                limits, applied = {}, []

                def get_limit(which):
                    self.assertIn(which, expected)
                    return limits.get(which, (0, -1))

                def set_limit(which, pair):
                    self.assertEqual(pair, (expected[which], expected[which]))
                    applied.append(which)
                    limits[which] = pair

                fake_resource = SimpleNamespace(RLIMIT_CORE=0, RLIMIT_NOFILE=1, RLIMIT_NPROC=2, RLIMIT_FSIZE=3,
                    RLIMIT_CPU=4, RLIMIT_AS=5, RLIM_INFINITY=-1, getrlimit=get_limit, setrlimit=set_limit)
                with patch.multiple(self.module, resource=fake_resource, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                    socket=SimpleNamespace(), signal=SimpleNamespace()):
                    self.module._limits(platform, 300, profile=profile)
                self.assertEqual(applied, list(expected))
                self.assertEqual(limits, {which: (limit, limit) for which, limit in expected.items()})

        for case in ("hard-ceiling", "not-applied"):
            limits, calls = {}, []

            def get_limit(which):
                if which == 3 and case == "hard-ceiling":
                    return 0, 512 * self.module.MiB
                if which == 3 and case == "not-applied":
                    return 0, -1
                return limits.get(which, (0, -1))

            def set_limit(which, pair):
                calls.append(which)
                limits[which] = pair

            fake_resource = SimpleNamespace(RLIMIT_CORE=0, RLIMIT_NOFILE=1, RLIMIT_NPROC=2, RLIMIT_FSIZE=3,
                RLIMIT_CPU=4, RLIMIT_AS=5, RLIM_INFINITY=-1, getrlimit=get_limit, setrlimit=set_limit)
            with self.subTest(profile_limit_refusal=case), \
                 patch.multiple(self.module, resource=fake_resource, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                socket=SimpleNamespace(), signal=SimpleNamespace()), self.assertRaises(self.module.SessionError):
                self.module._limits("linux", 300, profile="python-full")
            self.assertEqual(calls, [0, 1, 2] if case == "hard-ceiling" else [0, 1, 2, 3])
        with patch.multiple(self.module, resource=SimpleNamespace(), os=SimpleNamespace(), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace()):
            for platform, profile in (("darwin", "python-full"), ("linux", "unknown")):
                with self.subTest(profile_limit_platform=(platform, profile)), self.assertRaises(self.module.SessionError):
                    self.module._limits(platform, 300, profile=profile)

        # Fixed child dispatch is tested through its real validation body. The
        # process-wide limits and exec are inert and cannot call the host APIs.
        class ExecBoundary(Exception):
            pass

        cases = ("valid", "ordinary-linux", "ordinary-mac", "wrong-native-platform", "wrong-platform", "foreign-uid", "different-gid",
                 "wrong-cpu", "wrong-policy", "wrong-root", "wrong-command", "extra-argument", "expired", "infinite",
                 "excess-deadline", "limit-failure", "boundary-failure", "ordinary-boundary-failure")
        for case in cases:
            with self.subTest(profile_entry=case):
                session = session_double(self.module, "darwin" if case == "ordinary-mac" else "linux")
                command = self.module._python_full_command(session.root, session.deadline)
                entry = session.entry if case != "wrong-root" else Path("/unapproved/mrk-pure-fixture/bootstrap/ci_sandbox.py")
                kind = "--enter" if case.startswith("ordinary-") else "--enter-python-full"
                platform = "darwin" if case in {"ordinary-mac", "wrong-platform"} else "linux"
                gid = 60002 if case == "different-gid" else session.gid
                arguments = [kind, platform, str(session.uid), str(gid), "299" if case == "wrong-cpu" else "300",
                             str(session.policy) if case != "wrong-policy" else "/unapproved/profile.sb", *command]
                if case == "wrong-command":
                    arguments[6] = "/unapproved/python"
                if case == "extra-argument":
                    arguments.append("--unapproved-argument")
                if case in {"expired", "infinite", "excess-deadline"}:
                    arguments[-1] = {"expired": "0.0", "infinite": "inf", "excess-deadline": "3302.0"}[case]
                events = []

                def zero_boundary(**options):
                    self.assertEqual(events, [])
                    self.assertEqual(options, {} if kind == "--enter" else {"deadline": session.deadline})
                    events.append("zero")
                    if case in {"boundary-failure", "ordinary-boundary-failure"}:
                        raise self.module.SessionError("synthetic required fixed-zero refusal")

                def apply_limits(*_args, **_options):
                    self.assertEqual(events, [] if platform == "darwin" else ["zero"])
                    events.append("limits")
                    if case == "limit-failure":
                        raise self.module.SessionError("synthetic required resource ceiling refusal")

                limits, userns = Mock(side_effect=apply_limits), Mock(side_effect=zero_boundary)
                executed = Mock(side_effect=ExecBoundary)

                def resolve_entry(path, **kwargs):
                    self.assertEqual(path, entry)
                    self.assertIn(kwargs, ({}, {"strict": True}))
                    return entry

                fake_os = SimpleNamespace(getuid=lambda: 0 if case == "foreign-uid" else session.uid,
                    geteuid=lambda: 0 if case == "foreign-uid" else session.uid, getgid=lambda: gid, getegid=lambda: gid,
                    execve=executed, environ={"FIXED_SYNTHETIC_ENV": "1"})
                with patch.multiple(self.module, __file__=str(entry), os=fake_os,
                                    sys=SimpleNamespace(platform="darwin" if case in {"ordinary-mac", "wrong-native-platform"} else "linux"),
                                    subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(),
                                    resource=SimpleNamespace(), _limits=limits, _userns_zero=userns,
                                    time=SimpleNamespace(monotonic=lambda: 1.0)), \
                     patch.object(Path, "resolve", resolve_entry), \
                     patch.object(Path, "stat", side_effect=AssertionError("fixed entry may not query the host")), \
                     patch.object(Path, "open", side_effect=AssertionError("fixed entry may not open host files")):
                    with self.assertRaises(ExecBoundary if case in {"valid", "ordinary-linux", "ordinary-mac"} else self.module.SessionError):
                        self.module._main(arguments)
                if case == "ordinary-mac":
                    limits.assert_called_once_with("darwin", 300)
                    expected = ["/usr/bin/sandbox-exec", "-f", str(session.policy), *command]
                    executed.assert_called_once_with(expected[0], expected, {"FIXED_SYNTHETIC_ENV": "1"})
                elif case in {"valid", "ordinary-linux"}:
                    limits.assert_called_once_with("linux", 300, **({"profile": "python-full"} if case == "valid" else {}))
                    executed.assert_called_once_with(command[0], command, {"FIXED_SYNTHETIC_ENV": "1"})
                else:
                    executed.assert_not_called()
                    self.assertEqual(limits.call_count, int(case == "limit-failure"))
                self.assertEqual(userns.call_count, int(case in {"valid", "ordinary-linux", "limit-failure", "boundary-failure",
                                                              "ordinary-boundary-failure"}))

    def test_fixed_userns_node_reader_and_child_assertion_have_closed_bounded_custody(self):
        good = ((b"0\n", 0), (b"12345\n", 12345), (b"18446744073709551615\n", (1 << 64) - 1))
        bad = (b"", b"0", b"00\n", b"01\n", b"-1\n", b"+1\n", b" 1\n", b"1 \n", b"1\r\n",
               b"1\n\n", b"1\nextra", b"18446744073709551616\n", b"1" * 22 + b"\n", b"\xff\n")
        for raw, expected in (*good, *((value, None) for value in bad)):
            with self.subTest(fixed_decimal=raw):
                rig = _UsernsFile(self.module, raw=raw, access=os.O_RDONLY)
                with rig.scope():
                    if expected is None:
                        with self.assertRaises(self.module.SessionError):
                            self.module._userns_read(rig.fd, deadline=1.0)
                    else:
                        self.assertEqual(self.module._userns_read(rig.fd, deadline=1.0), expected)
                self.assertEqual(rig.events, [("seek",), ("read", 22), ("read", 1)])
                self.assertNotIn("open", rig.counts)  # This low-level reader must not invent FD ownership.

        changes = {"subject-owner": {"st_uid": 60001}, "nonroot-owner": {"st_uid": 1001},
                   "nonroot-group": {"st_gid": 20}, "group-write": {"st_mode": stat.S_IFREG | 0o664},
                   "world-write": {"st_mode": stat.S_IFREG | 0o646}, "execute": {"st_mode": stat.S_IFREG | 0o744},
                   "setid": {"st_mode": stat.S_IFREG | 0o4644}, "symlink": {"st_mode": stat.S_IFLNK | 0o644},
                   "directory": {"st_mode": stat.S_IFDIR | 0o644}}
        for case in ("valid644", "valid600", *changes, "different-node", "different-mode", "inheritable", "expired", "late-stat"):
            with self.subTest(fixed_node=case):
                rig = _UsernsFile(self.module)
                vars(rig.node).update(changes.get(case, {}))
                if case == "valid600":
                    rig.node.st_mode = stat.S_IFREG | 0o600
                if case in {"different-node", "different-mode"}:
                    rig.named = SimpleNamespace(**vars(rig.node))
                    if case == "different-node":
                        rig.named.st_ino += 1
                    else:
                        rig.named.st_mode = stat.S_IFREG | 0o600
                rig.inheritable = case == "inheritable"
                rig.now = 1.0 if case == "expired" else 0.0

                def after(name, *_args):
                    if case == "late-stat" and name == "stat":
                        rig.now = 1.0

                rig.after = after
                with rig.scope():
                    if case.startswith("valid"):
                        observed = self.module._userns_node(rig.fd, deadline=1.0)
                        self.assertEqual(vars(observed), vars(rig.node))
                    else:
                        with self.assertRaises(self.module.SessionError):
                            self.module._userns_node(rig.fd, deadline=1.0)
                self.assertEqual(rig.counts.get("fstat", 0), int(case != "expired"))
                self.assertEqual(rig.counts.get("stat", 0), int(case != "expired"))
                self.assertNotIn("read", rig.counts)
                self.assertNotIn("write", rig.counts)

        cases = ("valid", "without-fresh-deadline", "not-zero", "wrong-platform", "open-error", "read-error", "seek-error",
                 "close-error", "read-and-close-error", "node-drift", "initial-expiry", "read-expiry", "close-expiry")
        for case in cases:
            with self.subTest(fixed_entry_assertion=case):
                rig = _UsernsFile(self.module, raw=b"1\n" if case == "not-zero" else b"0\n", access=os.O_RDONLY)
                rig.now = 1.0 if case == "initial-expiry" else 0.0
                original = OSError(errno.EIO, "synthetic private fixed-node observation")
                close_error = OSError(errno.EIO, "synthetic fixed-node close")

                def before(name, *_args):
                    if ((case == "open-error" and name == "open") or
                            (case in {"read-error", "read-and-close-error"} and name == "read") or
                            (case == "seek-error" and name == "seek")):
                        raise original
                    if case == "node-drift" and name == "fstat" and rig.counts[name] == 2:
                        rig.node.st_ino += 1

                def after(name, *_args):
                    if case == "read-expiry" and name == "read" or case == "close-expiry" and name == "close":
                        rig.now = 1.0
                    if case in {"close-error", "read-and-close-error"} and name == "close":
                        raise close_error

                rig.before, rig.after = before, after
                with rig.scope(), patch.object(self.module.sys, "platform", "darwin" if case == "wrong-platform" else "linux"):
                    options = {} if case == "without-fresh-deadline" else {"deadline": 1.0}
                    if case in {"valid", "without-fresh-deadline"}:
                        self.module._userns_zero(**options)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._userns_zero(**options)
                        if case in {"open-error", "read-error", "read-and-close-error", "seek-error"}:
                            self.assertIs(caught.exception.exceptions[0], original)
                        if case in {"close-error", "read-and-close-error"}:
                            self.assertIn(close_error, caught.exception.exceptions)
                self.assertEqual(rig.counts.get("open", 0), int(case not in {"wrong-platform", "initial-expiry"}))
                self.assertEqual(rig.counts.get("close", 0), int(case not in {"wrong-platform", "initial-expiry", "open-error"}))
                self.assertNotIn("write", rig.counts)
                self.assertNotIn("domain", rig.counts)
                if case in {"valid", "without-fresh-deadline"}:
                    self.assertEqual(rig.counts["fstat"], 2)
                    self.assertEqual(rig.counts["stat"], 2)
                    self.assertEqual(rig.counts["inheritable"], 2)
                    self.assertEqual([e for e in rig.events if e[0] == "read"], [("read", 22), ("read", 1)])

    def test_owned_userns_preparation_and_real_close_preserve_finality_and_uncertain_effects(self):
        for case in ("wrong-platform", "wrong-native-platform", "not-root", "duplicate", "prior-failure", "busy",
                     "active", "nonempty-domain", "unknown-domain", "expired"):
            with self.subTest(userns_prepare_guard=case):
                session = session_double(self.module)
                session.admitted = False
                rig = _UsernsFile(self.module, session)
                if case == "wrong-platform":
                    session.platform = "darwin"
                if case == "duplicate":
                    session._userns_state = {"owned-before-test": True}
                original_state = session._userns_state
                if case == "prior-failure":
                    session.fail("earlier immutable failure")
                session._busy = case == "busy"
                session._active = object() if case == "active" else None
                if case in {"nonempty-domain", "unknown-domain"}:
                    rig.domain_state = {4242} if case == "nonempty-domain" else OSError(errno.EIO, "synthetic unknown identity census")
                rig.now = session.deadline if case == "expired" else 0.0
                with rig.scope(), patch.object(self.module.sys, "platform", "darwin" if case == "wrong-native-platform" else "linux"), \
                     patch.object(self.module.os, "geteuid", return_value=1001 if case == "not-root" else 0):
                    with self.assertRaises((self.module.SessionError, OSError)):
                        session._prepare_userns_boundary()
                self.assertIs(session._userns_state, original_state)
                self.assertNotIn("open", rig.counts)
                self.assertNotIn("write", rig.counts)
                self.assertFalse(session.admission_results)

        cases = ("restore", "already-zero", "maximum-original", "prior-command-failure",
                 "prep-open-error", "prep-stat-error", "prep-read-error", "prep-malformed", "prep-short-write",
                 "prep-write-before-error", "prep-write-after-error", "prep-readback-error", "prep-nonzero-readback", "prep-expired",
                 "assert-value-drift", "assert-node-drift", "assert-mode-drift", "assert-read-error", "assert-expired", "assert-not-prepared",
                 "close-value-drift", "close-node-drift", "close-mode-drift", "close-busy", "close-active", "close-active-waited",
                 "close-unknown-domain", "close-nonempty-domain", "close-second-census-error", "close-second-census-nonempty", "close-expired",
                 "close-restore-before-error", "close-restore-after-error", "close-short-restore", "close-readback-error", "close-readback-different",
                 "close-fd-error", "close-restore-and-fd-error", "close-restore-home-and-fd-error", "close-home-error")
        success_cases = {"restore", "already-zero", "maximum-original"}
        preparation_cases = {case for case in cases if case.startswith("prep-")}
        for case in cases:
            with self.subTest(userns_owned_lifecycle=case):
                session = session_double(self.module)
                session.admitted = False
                original_value = 0 if case == "already-zero" else (1 << 64) - 1 if case == "maximum-original" else 12345
                raw = b"01\n" if case == "prep-malformed" else str(original_value).encode() + b"\n"
                rig = _UsernsFile(self.module, session, raw=raw)
                phase = "prepare"
                primary = OSError(errno.EIO, "synthetic private fixed-node primary")
                restore_error = OSError(errno.EIO, "synthetic private restoration error")
                descriptor_error = OSError(errno.EIO, "synthetic private descriptor close error")
                home_error = OSError(errno.EIO, "synthetic separate HOME close error")
                captured_cleanup, close_domain_start = [], None
                if case == "prep-short-write":
                    rig.short_write = 1

                def before(name, *args):
                    state = session._userns_state
                    if name == "open":
                        self.assertEqual(rig.events[0], ("domain",))
                        self.assertIsNotNone(state)
                        self.assertFalse(state["prepared"])
                    if name == "write":
                        self.assertIsNotNone(state["original_node"])
                        self.assertEqual(state["original"], original_value)
                        self.assertTrue(state["change_attempted"])
                        if phase == "prepare":
                            self.assertFalse(state["prepared"] or state["restore_attempted"] or state["closed"])
                            self.assertTrue(state["note"]["change_attempted"])
                            self.assertEqual(args, (b"0\n",))
                        else:
                            self.assertEqual(phase, "close")
                            self.assertTrue(state["closed"] and state["restore_attempted"] and session.domain_finality)
                            self.assertIsNone(session._active)
                            self.assertFalse(session._busy)
                            self.assertTrue(session.admission_results[-1]["restore_attempted"])
                            self.assertEqual(args, (str(original_value).encode() + b"\n",))
                    if phase == "prepare":
                        if (case == "prep-open-error" and name == "open" or
                                case == "prep-stat-error" and name == "fstat" or
                                case == "prep-read-error" and name == "read" or
                                case == "prep-write-before-error" and name == "write" or
                                case == "prep-readback-error" and name == "read" and rig.counts.get("write", 0) == 1):
                            raise primary
                    elif phase == "assert" and case == "assert-read-error" and name == "read":
                        raise primary
                    elif phase == "close":
                        if name == "domain" and rig.counts[name] - close_domain_start == 2:
                            if case == "close-second-census-error":
                                raise restore_error
                            if case == "close-second-census-nonempty":
                                rig.domain_state = {4242}
                        if case == "close-restore-before-error" and name == "write":
                            raise restore_error
                        if case == "close-readback-error" and name == "read" and rig.counts.get("write", 0) == 2:
                            raise restore_error

                def after(name, *_args):
                    if phase == "prepare" and name == "write":
                        if case == "prep-write-after-error":
                            raise primary  # Zero has actually changed, but preparation never reports success.
                        if case == "prep-nonzero-readback":
                            rig.raw = b"7\n"
                        if case == "prep-expired":
                            rig.now = session.deadline
                    if phase == "close":
                        if name == "write" and case in {"close-restore-after-error", "close-restore-and-fd-error", "close-restore-home-and-fd-error"}:
                            raise restore_error
                        if name == "write" and case == "close-readback-different":
                            rig.raw = b"777\n"
                        if name == "close" and case in {"close-fd-error", "close-restore-and-fd-error", "close-restore-home-and-fd-error"}:
                            raise descriptor_error

                rig.before, rig.after = before, after
                actual_close = session._close_userns_boundary

                def userns_close():
                    errors = actual_close()
                    captured_cleanup.extend(errors)
                    return errors

                def home_close():
                    rig.event("home-close")
                    return [home_error] if case in {"close-home-error", "close-restore-home-and-fd-error"} else []

                with rig.scope(), patch.object(session, "_close_userns_boundary", side_effect=userns_close) as closing, \
                     patch.object(session, "_close_home_boundary", side_effect=home_close) as home:
                    if case in preparation_cases:
                        with self.assertRaises((OSError, self.module.SessionError)) as caught:
                            session._prepare_userns_boundary()
                        if case in {"prep-open-error", "prep-stat-error", "prep-read-error", "prep-write-before-error",
                                    "prep-write-after-error", "prep-readback-error"}:
                            self.assertIs(caught.exception, primary)
                        self.assertEqual(session.failure, "owned Linux user-namespace preparation failed")
                        state = session._userns_state
                        self.assertFalse(state["prepared"] or state["note"]["ok"] or state["note"]["zero_observed"])
                        before_rejected_assertion = list(rig.events)
                        with self.assertRaises(self.module.SessionError):
                            session._assert_userns_boundary()
                        self.assertEqual(rig.events, before_rejected_assertion)
                    else:
                        session._prepare_userns_boundary()
                        state = session._userns_state
                        self.assertEqual(state["original"], original_value)
                        self.assertEqual(state["fd"], rig.fd)
                        self.assertTrue(state["prepared"])
                        self.assertEqual(state["note"], {"name": "linux-userns-preparation", "ok": True,
                            "change_attempted": original_value != 0, "changed": original_value != 0,
                            "already_zero": original_value == 0, "zero_observed": True, "owner_assertions": 0})
                        phase = "assert"
                        if case == "assert-value-drift":
                            rig.raw = b"8\n"
                        if case == "assert-node-drift":
                            rig.node.st_ino += 1
                        if case == "assert-mode-drift":
                            rig.node.st_mode = stat.S_IFREG | 0o600
                        if case == "assert-expired":
                            rig.now = session.deadline
                        if case == "assert-not-prepared":
                            state["prepared"] = False
                        if case.startswith("assert-"):
                            with self.assertRaises((OSError, self.module.SessionError)):
                                session._assert_userns_boundary()
                            self.assertEqual(session.failure, "owned Linux user-namespace launch assertion failed")
                            self.assertFalse(state["note"]["ok"])
                            self.assertEqual(state["assertions"], 0)
                        else:
                            session._assert_userns_boundary()
                            self.assertEqual((state["assertions"], state["note"]["owner_assertions"]), (1, 1))
                    self.assertEqual(session.deadline, 100.0)
                    self.assertNotIn("close", rig.counts)
                    phase = "close"
                    close_domain_start = rig.counts.get("domain", 0)
                    if case == "prior-command-failure":
                        session.fail("earlier immutable command failure")
                    initial_failure = session.failure
                    if case == "close-value-drift":
                        rig.raw = b"9\n"
                    if case == "close-node-drift":
                        rig.node.st_dev += 1
                    if case == "close-mode-drift":
                        rig.node.st_mode = stat.S_IFREG | 0o600
                    if case == "close-busy":
                        session._busy = True
                    owned_child = None
                    if case in {"close-active", "close-active-waited"}:
                        def waited(*, timeout):
                            self.assertEqual(timeout, 2)
                            rig.event("original-wait")
                            if case == "close-active":
                                raise primary
                            return 0

                        owned_child = SimpleNamespace(poll=Mock(return_value=None), kill=Mock(), wait=Mock(side_effect=waited))
                        session._active = owned_child
                    if case == "close-unknown-domain":
                        rig.domain_state = primary
                    if case == "close-nonempty-domain":
                        rig.domain_state = {4242}
                    if case == "close-expired":
                        rig.now = session.deadline
                    rig.short_write = 1 if case == "close-short-restore" else None
                    if case in success_cases:
                        session.close(keep_timer=True)
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                    self.assertTrue(session.closed and state["closed"])
                    self.assertFalse(session._timer_finished)
                    self.assertIsNone(state["fd"])
                    self.assertEqual(rig.counts.get("close", 0), int(case != "prep-open-error"))
                    closing.assert_called_once_with()
                    home.assert_called_once_with()
                    if case != "prep-open-error":
                        self.assertLess(rig.events.index(("close",)), rig.events.index(("home-close",)))
                    if initial_failure is not None:
                        self.assertEqual(session.failure, initial_failure)
                    if owned_child is not None:
                        owned_child.kill.assert_called_once_with()
                        owned_child.wait.assert_called_once_with(timeout=2)
                        if case == "close-active":
                            self.assertIs(session._active, owned_child)
                        else:
                            self.assertIsNone(session._active)
                    terminal = next(n for n in session.admission_results if n["name"] == "linux-userns-finalization")
                    restored = case in {"restore", "maximum-original", "prior-command-failure", "prep-write-after-error",
                                        "prep-readback-error", "assert-read-error", "assert-not-prepared", "close-active-waited",
                                        "close-fd-error", "close-home-error"}
                    self.assertEqual(terminal["restored"], restored)
                    self.assertEqual(terminal["unchanged_zero"], case == "already-zero")
                    attempted = restored or case in {"close-restore-before-error", "close-restore-after-error", "close-short-restore",
                        "close-readback-error", "close-readback-different", "close-restore-and-fd-error", "close-restore-home-and-fd-error"}
                    self.assertEqual((state["restore_attempted"], terminal["restore_attempted"]), (attempted, attempted))
                    self.assertEqual(terminal["ok"], not captured_cleanup)
                    if restored:
                        self.assertEqual(rig.raw, str(original_value).encode() + b"\n")
                    if case in {"prep-write-after-error", "prep-readback-error"}:
                        self.assertFalse(state["prepared"] or state["note"]["ok"])
                        self.assertEqual([e for e in rig.events if e[0] == "write"], [("write", b"0\n"), ("write", b"12345\n")])
                        self.assertFalse(session.admitted)
                    if case in {"close-restore-before-error", "close-restore-after-error", "close-readback-error",
                                "close-restore-and-fd-error", "close-restore-home-and-fd-error", "close-second-census-error"}:
                        self.assertIn(restore_error, captured_cleanup)
                    if case in {"close-fd-error", "close-restore-and-fd-error", "close-restore-home-and-fd-error"}:
                        self.assertIn(descriptor_error, captured_cleanup)
                    if case in {"close-restore-and-fd-error", "close-restore-home-and-fd-error"}:
                        self.assertEqual(captured_cleanup, [restore_error, descriptor_error])
                    if case in {"close-home-error", "close-restore-home-and-fd-error"}:
                        self.assertIn("HOME finalization OSError", session.cleanup_errors)
                    before_repeat = list(rig.events)
                    self.assertEqual(actual_close(), [])
                    if case in success_cases:
                        session.close(keep_timer=True)
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                    self.assertEqual(rig.events, before_repeat)
                    self.assertEqual(closing.call_count, 1)
                    self.assertEqual(home.call_count, 1)
                self.assertNotIn("synthetic private", json.dumps(session.admission_results))
                self.assertNotIn("/proc/", json.dumps(session.admission_results))

    def test_userns_assertions_precede_collection_direct_controls_and_each_linux_entry(self):
        for case in ("valid", "value-drift", "node-drift"):
            with self.subTest(userns_real_collection_boundary=case):
                session = session_double(self.module)
                session.admitted = False
                node = _UsernsFile(self.module, session)
                with node.scope():
                    session._prepare_userns_boundary()
                session.admitted = True
                if case == "value-drift":
                    node.raw = b"1\n"
                if case == "node-drift":
                    node.node.st_ino += 1
                rig, actual_assertion = _Collection(self.module, session), session._assert_userns_boundary

                def checked():
                    self.assertFalse(any(event[0] == "popen" for event in rig.events))
                    self.assertIsNone(session._active)
                    self.assertEqual(len(rig.opened), 2)
                    rig.events.append(("userns-assertion",))
                    # Nested, closed fake namespace only for the real boundary;
                    # restoration returns collection to its own fake streams.
                    with node.scope():
                        actual_assertion()

                with rig.scope(), patch.object(session, "_assert_userns_boundary", side_effect=checked) as boundary:
                    result = session.run([str(session.python), "--synthetic"], cwd=session.work, env={}, seconds=1)
                boundary.assert_called_once_with()
                self.assertEqual(result.ok, case == "valid")
                if case == "valid":
                    self.assertLess(rig.events.index(("userns-assertion",)), next(i for i, e in enumerate(rig.events) if e[0] == "popen"))
                    self.assertEqual(session._userns_state["assertions"], 1)
                else:
                    self.assertFalse(any(event[0] == "popen" for event in rig.events))
                    self.assertEqual(session.failure, "owned Linux user-namespace launch assertion failed")
                    self.assertEqual(result.primary_error, "collection SessionError")
                    self.assertEqual(result.persisted, (0, 0))
                    self.assertFalse(result.waited or result.stdout_eof or result.stderr_eof or result.finality)
                with node.scope():
                    if case == "valid":
                        session.close(keep_timer=True)
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                self.assertEqual(node.counts["close"], 1)

        class BeforeNative(RuntimeError):
            pass

        for platform, route in ((p, r) for p in ("linux", "darwin") for r in ("write-positive", "owner-loss")):
            for case in ("valid", "collector-error", "waited-diagnostic", *(["assertion-failure"] if platform == "linux" else [])):
                with self.subTest(direct_owned_route=(platform, route, case)):
                    session, events = session_double(self.module, platform), []
                    node = _UsernsFile(self.module, session) if platform == "linux" else None
                    if node is not None:
                        with node.scope():
                            session._prepare_userns_boundary()
                    stopped = BeforeNative("stop at the inert native invocation boundary")
                    original = self.module.SessionError("synthetic owned fixed-zero refusal")
                    unresolved = ExceptionGroup("synthetic original control kill/wait remained unresolved",
                                                [OSError(errno.EIO, "synthetic original kill failure"),
                                                 TimeoutError("synthetic unknown original wait")])
                    unresolved._ci_observation = {"waited": case == "waited-diagnostic"}

                    def assertion():
                        self.assertEqual(events, ["idle"])
                        events.append("assert")
                        if case == "assertion-failure":
                            raise original

                    def metadata(argv, *_args, **kwargs):
                        self.assertEqual(events, ["idle", "assert"] if platform == "linux" else ["idle"])
                        self.assertTrue(session._direct_producer_pending)
                        self.assertFalse(session.domain_finality)
                        self.assertEqual(kwargs["deadline"], session.deadline)
                        if route == "owner-loss":
                            self.assertIn("--loss-owner", argv)
                            rendered = json.loads(argv[-1])["command"]
                            if platform == "linux":
                                self.assertEqual(rendered[0], "/usr/bin/bwrap")
                                self.assertIn("--assert-userns-disabled", rendered)
                            else:
                                self.assertIn("--enter", rendered)
                                self.assertNotIn("/usr/bin/bwrap", rendered)
                            self.assertNotIn("--unshare-user", rendered)
                            self.assertNotIn("--disable-userns", rendered)
                        else:
                            self.assertIn("--write-control", argv)
                            self.assertEqual((kwargs["user"], kwargs["group"]), (session.uid, session.gid))
                        events.append("native-boundary")
                        if case in {"collector-error", "waited-diagnostic"}:
                            raise unresolved
                        return b"MRK_OWNER_LOST 4242\n" if route == "owner-loss" else b"MRK_OUTSIDE_WRITE_POSITIVE\n"

                    def after_normal_collection():
                        self.assertFalse(session._direct_producer_pending)
                        self.assertEqual(events, ["idle", "assert", "native-boundary"] if platform == "linux" else ["idle", "native-boundary"])
                        raise stopped  # No probe/listener/census/cleanup process is entered.

                    def idle():
                        if not events:
                            self.assertFalse(session._direct_producer_pending)
                            events.append("idle")
                            return
                        after_normal_collection()

                    with patch.multiple(self.module, os=SimpleNamespace(chown=Mock()), subprocess=SimpleNamespace(),
                                        signal=SimpleNamespace(), socket=SimpleNamespace(),
                                        time=SimpleNamespace(monotonic=lambda: 0.0), _small_command=Mock(side_effect=metadata)), \
                         patch.object(Path, "exists", return_value=True), \
                         patch.object(Path, "read_bytes", side_effect=AssertionError("stopped control may not inspect files")), \
                         patch.object(session, "ensure_idle", side_effect=idle), \
                         patch.object(session, "_cleanup", side_effect=after_normal_collection), \
                         patch.object(session, "_home_positive_control", Mock()), \
                         patch.object(session, "_assert_userns_boundary", side_effect=assertion) as boundary:
                        with self.assertRaises(BaseExceptionGroup if route == "write-positive" else
                                               BeforeNative if case == "valid" else self.module.SessionError if case == "assertion-failure"
                                               else ExceptionGroup) as caught:
                            session._preflight() if route == "write-positive" else session._owner_loss_preflight()
                        error = caught.exception.exceptions[0] if route == "write-positive" else caught.exception
                        self.assertIs(error, stopped if case == "valid" else original if case == "assertion-failure" else unresolved)
                        self.assertEqual(self.module._small_command.call_count, int(case != "assertion-failure"))
                    self.assertEqual(boundary.call_count, int(platform == "linux"))
                    pending = case in {"collector-error", "waited-diagnostic"}
                    self.assertEqual(session._direct_producer_pending, pending)
                    # The direct collector exception itself is not a cleanup
                    # receipt, even if its diagnostic claims a completed wait.
                    # Retain the original admission/command failure while the
                    # actual close gate sees an otherwise empty U domain.
                    session.fail("original direct-control collection failure")
                    domain = Mock(return_value={})
                    with ExitStack() as scope:
                        if node is not None:
                            scope.enter_context(node.scope())
                        else:
                            scope.enter_context(patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                socket=SimpleNamespace(), signal=SimpleNamespace(), _domain=domain,
                                time=SimpleNamespace(monotonic=lambda: 0.0)))
                        if pending:
                            before_idle = list(node.events) if node is not None else domain.call_count
                            with self.assertRaises(self.module.SessionError):
                                session.ensure_idle()
                            self.assertFalse(session.domain_finality)
                            if node is not None:
                                with self.assertRaises(self.module.SessionError):
                                    session._assert_userns_boundary()
                            self.assertEqual(node.events if node is not None else domain.call_count, before_idle)
                            self.assertTrue(session._direct_producer_pending)
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                    self.assertEqual(session.failure, "original direct-control collection failure")
                    self.assertEqual(session.domain_finality, not pending)
                    self.assertEqual(session._direct_producer_pending, pending)
                    if node is not None:
                        self.assertEqual(node.counts["close"], 1)
                        self.assertIsNone(session._userns_state["fd"])
                        self.assertEqual(node.raw, b"0\n" if pending else b"12345\n")
                        self.assertEqual(session._userns_state["restore_attempted"], not pending)
                        final_note = next(n for n in session.admission_results if n["name"] == "linux-userns-finalization")
                        self.assertEqual(final_note["restored"], not pending)
                    else:
                        self.assertEqual(domain.call_count, int(not pending))

        for case in ("valid", "collector-error", "waited-diagnostic", "pending-at-entry"):
            with self.subTest(direct_signal_control=case):
                session = session_double(self.module, "darwin")
                session._direct_producer_pending = case == "pending-at-entry"
                session.domain_finality = True
                original = ExceptionGroup("synthetic independent signal-helper wait/kill ambiguity",
                                          [OSError(errno.EIO, "synthetic original kill error"), TimeoutError("synthetic original wait ambiguity")])
                original._ci_observation = {"waited": case == "waited-diagnostic"}
                child = SimpleNamespace(pid=4242, returncode=0, stdin=SimpleNamespace(close=Mock()),
                    stdout=SimpleNamespace(close=Mock()), stderr=SimpleNamespace(close=Mock()),
                    poll=Mock(return_value=0), kill=Mock(), wait=Mock(return_value=0),
                    communicate=Mock(return_value=(b"MRK_SENTINEL_CLOSED\n", b"")))

                def launch(argv, **kwargs):
                    self.assertFalse(session._direct_producer_pending)
                    self.assertTrue(session.domain_finality)
                    self.assertEqual(argv[-1], "--sentinel")
                    self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (session.uid, session.gid, []))
                    self.assertTrue(kwargs["close_fds"])
                    self.assertNotIn("pass_fds", kwargs)
                    return child

                def control(argv, seconds, **kwargs):
                    self.assertTrue(session._direct_producer_pending)
                    self.assertFalse(session.domain_finality)
                    self.assertEqual(argv[-2:], ["--signal-case", str(child.pid)])
                    self.assertEqual((seconds, kwargs), (10, {"user": session.uid, "group": session.gid, "deadline": session.deadline}))
                    if case != "valid":
                        raise original
                    return b"MRK_SIGNAL_BOUNDARY_OK\n"

                popen, metadata, domain = Mock(side_effect=launch), Mock(side_effect=control), Mock(return_value={})
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(Popen=popen, PIPE=-1),
                                    socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace(),
                                    _domain=domain, _small_command=metadata, _ready_line=Mock(return_value=b"MRK_SENTINEL_READY\n"),
                                    time=SimpleNamespace(monotonic=lambda: 0.0)), patch.object(session, "_headroom", Mock()):
                    if case == "valid":
                        session._signal_preflight()
                    elif case == "pending-at-entry":
                        with self.assertRaises(self.module.SessionError):
                            session._signal_preflight()
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            session._signal_preflight()
                        self.assertEqual(caught.exception.exceptions, (original,))
                self.assertEqual(session._direct_producer_pending, case != "valid")
                self.assertEqual(session.domain_finality, case == "valid")
                self.assertEqual(domain.call_count, 2 if case == "valid" else 0 if case == "pending-at-entry" else 1)
                self.assertEqual(popen.call_count, int(case != "pending-at-entry"))
                self.assertEqual(metadata.call_count, int(case != "pending-at-entry"))
                child.kill.assert_not_called()
                self.assertEqual(child.wait.call_count, int(case != "pending-at-entry"))
                self.assertEqual(child.communicate.call_count, int(case == "valid"))
                for stream in (child.stdin, child.stdout, child.stderr):
                    self.assertEqual(stream.close.call_count, int(case != "pending-at-entry"))
                self.assertEqual(session.admission_results, [{"name": "same-UID-native-signal-boundary", "ok": True}] if case == "valid" else [])

        # Real internal dispatcher, but every role body, process API, file API,
        # resource API and sleep is absent or inert. A refusal precedes all work.
        roles = ("--probe", "--leaf", "--grandchild", "--fixture", "--write-control", "--loss-subject")
        for role in roles:
            for case in ("linux", "darwin", "assertion-failure"):
                with self.subTest(userns_direct_entry=(role, case)):
                    events, output = [], io.StringIO()
                    original = self.module.SessionError("synthetic direct fixed-zero refusal")

                    def zero():
                        self.assertEqual(events, [])
                        events.append("zero")
                        if case == "assertion-failure":
                            raise original

                    def body(*_args, **_kwargs):
                        self.assertEqual(events, [] if case == "darwin" else ["zero"])
                        events.append("body")
                        return 17 if role == "--fixture" else None

                    userns, work = Mock(side_effect=zero), Mock(side_effect=body)
                    arguments = [role] if role == "--loss-subject" else [role, "{}" if role in {"--probe", "--leaf", "--grandchild"} else "synthetic"]
                    with patch.multiple(self.module, sys=SimpleNamespace(platform="darwin" if case == "darwin" else "linux"),
                        os=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(), socket=SimpleNamespace(),
                        resource=SimpleNamespace(), time=SimpleNamespace(sleep=work), _userns_zero=userns,
                        _probe=work, _probe_leaf=work, _fixture=work, _write_control=work), redirect_stdout(output):
                        if case == "assertion-failure":
                            with self.assertRaises(self.module.SessionError) as caught:
                                self.module._main(arguments)
                            self.assertIs(caught.exception, original)
                        else:
                            self.assertEqual(self.module._main(arguments), 17 if role == "--fixture" else 0)
                    self.assertEqual(userns.call_count, int(case != "darwin"))
                    self.assertEqual(work.call_count, int(case != "assertion-failure"))
                    if case == "assertion-failure":
                        self.assertEqual(output.getvalue(), "")

    def test_kernel_group_api_is_bounded_typed_and_never_falls_back_to_nss(self):
        uid = gid = 60001
        cases = ((1, 1, [gid], None), (2, 2, [gid, gid + 1], None),
                 (-1, None, [], OSError), (0, None, [], self.module.SessionError),
                 (257, None, [], self.module.SessionError),
                 (1, -1, [], OSError), (2, 1, [gid], self.module.SessionError))
        for count, filled, groups, failure in cases:
            with self.subTest(count=count, filled=filled):
                arrays = []

                class UInt32:
                    def __mul__(self, size):
                        def allocate():
                            array = [0] * size
                            arrays.append(array)
                            return array
                        return allocate

                def getgroups(size, array):
                    if array is None:
                        self.assertEqual(size, 0)
                        return count
                    self.assertEqual(size, count)
                    self.assertIs(array, arrays[0])
                    array[:len(groups)] = groups
                    return filled

                getter = Mock(side_effect=getgroups)
                library = SimpleNamespace(getgroups=getter)
                scalar, integer, pointer = UInt32(), object(), object()
                fake_ctypes = SimpleNamespace(CDLL=Mock(return_value=library), c_uint32=scalar,
                                              c_int=integer, POINTER=Mock(return_value=pointer),
                                              set_errno=Mock(), get_errno=Mock(return_value=22))
                nss = Mock(side_effect=AssertionError("Darwin must not call NSS-backed os.getgroups"))
                with patch.dict(sys.modules, {"ctypes": fake_ctypes}), \
                     patch.object(self.module, "os", SimpleNamespace(getgroups=nss)):
                    if failure is None:
                        self.assertEqual(self.module._process_groups("darwin"), groups)
                    else:
                        with self.assertRaises(failure) as caught:
                            self.module._process_groups("darwin")
                        self.assertEqual(caught.exception._ci_operation,
                                         "kernel-groups-fill" if 1 <= count <= 256 else "kernel-groups-count")
                        if failure is OSError:
                            self.assertEqual(caught.exception.errno, 22)
                            fake_ctypes.get_errno.assert_called_once_with()
                fake_ctypes.CDLL.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
                fake_ctypes.POINTER.assert_called_once_with(scalar)
                self.assertEqual(getter.argtypes, [integer, pointer])
                self.assertIs(getter.restype, integer)
                self.assertEqual(getter.call_args_list[0].args, (0, None))
                admitted_count = 1 <= count <= 256
                self.assertEqual(len(arrays), int(admitted_count))
                self.assertEqual(getter.call_count, 2 if admitted_count else 1)
                self.assertEqual([c.args for c in fake_ctypes.set_errno.call_args_list],
                                 [(0,)] * getter.call_count)
                nss.assert_not_called()

        for missing in ("module", "library", "symbol"):
            with self.subTest(missing=missing):
                loader = Mock(side_effect=OSError(2, "synthetic unavailable library")) if missing == "library" else Mock(return_value=SimpleNamespace())
                fake_ctypes = None if missing == "module" else SimpleNamespace(CDLL=loader)
                nss = Mock(side_effect=AssertionError("no NSS or alternate-library fallback"))
                expected = {"module": ModuleNotFoundError, "library": OSError, "symbol": AttributeError}[missing]
                with patch.dict(sys.modules, {"ctypes": fake_ctypes}), \
                     patch.object(self.module, "os", SimpleNamespace(getgroups=nss)):
                    with self.assertRaises(expected) as caught:
                        self.module._process_groups("darwin")
                    self.assertEqual(caught.exception._ci_operation, "kernel-groups-library")
                nss.assert_not_called()
                if missing == "module":
                    loader.assert_not_called()
                else:
                    loader.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)

        nss = Mock(return_value=[])
        loader = Mock(side_effect=AssertionError("Linux must not load the Darwin library"))
        with patch.dict(sys.modules, {"ctypes": SimpleNamespace(CDLL=loader)}), \
             patch.object(self.module, "os", SimpleNamespace(getgroups=nss)):
            self.assertEqual(self.module._process_groups("linux"), [])
            with self.assertRaises(self.module.SessionError):
                self.module._process_groups("unsupported")
        nss.assert_called_once_with()
        loader.assert_not_called()

        # Exercise only the early credential branch of the real probe body.
        # A private exception stops even valid cases before their first FD
        # observation; every later OS/socket/process API is absent, not real.
        class DescriptorBoundary(RuntimeError):
            pass

        for platform, groups, admitted in (("linux", [], True), ("linux", [gid], False),
                                          ("darwin", [gid], True), ("darwin", [], False),
                                          ("darwin", [gid, gid + 1], False), ("darwin", [gid, gid], False)):
            with self.subTest(platform=platform, groups=groups):
                fstat = Mock(side_effect=DescriptorBoundary)
                fake_os = SimpleNamespace(getuid=lambda: uid, geteuid=lambda: uid,
                                          getgid=lambda: gid, getegid=lambda: gid, fstat=fstat)
                with patch.dict(sys.modules, {"ctypes": None}), \
                     patch.multiple(self.module, os=fake_os, socket=SimpleNamespace(),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    _small_command=Mock(side_effect=AssertionError("no native metadata invocation"))), \
                     patch.object(self.module, "_process_groups", return_value=groups) as query:
                    with self.assertRaises(DescriptorBoundary if admitted else self.module.SessionError):
                        self.module._probe_leaf({"platform": platform, "uid": uid, "gid": gid})
                query.assert_called_once_with(platform)
                if admitted:
                    fstat.assert_called_once_with(0)
                else:
                    fstat.assert_not_called()

    def test_macos_numeric_launch_and_literal_policies_keep_distinct_write_roles(self):
        session = session_double(self.module, "darwin")
        session.runner_home = Path('/Users/runner"quote\n')
        session.ruby = session.runner_home / "tools/ruby/bin/ruby"
        session.ruby_prefix = session.ruby.parent.parent
        session.tool_prefixes = (session.python.parent.parent, session.ruby_prefix)
        # This is deliberately a pure escaping/renderer input, not canonical
        # admission. The actual ancestor binding has its own metadata tests.
        session.ruby_ancestors = (session.runner_home, session.ruby_prefix.parent)
        argv, kwargs = session._argv([str(session.ruby), "--synthetic"], 120)
        self.assertEqual(kwargs, {"user": session.uid, "group": session.gid, "extra_groups": []})
        self.assertEqual(argv[:7], [str(session.python), "-I", "-S", "-B", str(session.entry), "--enter", "darwin"])
        with patch.object(self.module, "_private_file") as write:
            session._write_policy()
        self.assertEqual(write.call_count, 3)
        subject_path, subject_bytes, mode = write.call_args_list[0].args
        cleanup_path, cleanup_bytes, cleanup_mode = write.call_args_list[1].args
        positive_path, positive_bytes, positive_mode = write.call_args_list[2].args
        self.assertEqual((subject_path, cleanup_path, positive_path, mode, cleanup_mode, positive_mode),
                         (session.policy, session.cleanup_policy, session.write_policy, 0o444, 0o444, 0o444))
        subject, cleanup = subject_bytes.decode("ascii"), cleanup_bytes.decode("ascii")
        positive = positive_bytes.decode("ascii")
        for policy in (subject, cleanup, positive):
            self.assertTrue(policy.startswith("(version 1)\n(allow default)\n"))
            self.assertIn("(deny network*)\n(deny mach-lookup)", policy)
            self.assertIn("(deny file-read* (require-all (require-any ", policy)
            for private in (session.runner_home, session.runner_temp, session.control):
                self.assertIn("(subpath " + json.dumps(str(private), ensure_ascii=True) + ")", policy)
            for prefix in session.tool_prefixes:
                self.assertIn("(require-not (subpath " + json.dumps(str(prefix)) + "))", policy)
        self.assertIn("(deny signal (require-not (target same-sandbox)))", subject)
        self.assertIn("(require-not (subpath " + json.dumps(str(session.work)) + "))", subject)
        self.assertIn('(require-not (literal "/dev/null"))', subject)
        self.assertNotIn(str(session.work), cleanup)
        self.assertNotIn("(deny signal", cleanup)
        self.assertIn('(deny file-write* (require-not (literal "/dev/null")))', cleanup)
        self.assertIn("(deny file-write* (require-all (require-not (literal "
                      + json.dumps(str(session.outside_write)) + "))", positive)
        self.assertNotIn(str(session.work), positive)
        self.assertNotIn(str(session.outside_write), subject)
        self.assertNotIn(str(session.outside_write), cleanup)
        self.assertNotIn("(subpath " + json.dumps(str(session.fixture_controls)), positive)
        self.assertNotIn(str(session.runner_home), subject)  # Escaped literal, never raw policy text.
        q = lambda value: json.dumps(str(value), ensure_ascii=True)
        exclusions = "\n  ".join(f"(require-not (subpath {q(path)}))" for path in session.tool_prefixes)
        private = " ".join(f"(subpath {q(path)})" for path in (session.runner_home, session.runner_temp, session.control))
        common = ("(version 1)\n(allow default)\n(deny network*)\n(deny mach-lookup)\n"
                  f"(deny file-read* (require-all (require-any {private})\n  {exclusions}))\n")
        old_subject = (common + "(deny signal (require-not (target same-sandbox)))\n"
                       f"(deny file-write* (require-all (require-not (subpath {q(session.work)})) "
                       '(require-not (literal "/dev/null"))))\n')
        self.assertEqual(cleanup, common + '(deny file-write* (require-not (literal "/dev/null")))\n')
        self.assertEqual(positive, common + f"(deny file-write* (require-all (require-not (literal {q(session.outside_write)})) "
                         '(require-not (literal "/dev/null"))))\n')
        for ancestor in session.ruby_ancestors:
            clause = f"(allow file-read-metadata (literal {q(ancestor)}))\n"
            self.assertEqual(subject.count(clause), 1)
            subject = subject.replace(clause, "")
            self.assertNotIn(clause, cleanup)
            self.assertNotIn(clause, positive)
        self.assertEqual(subject, old_subject)  # No other widening or changed write/signal/network role.

    def test_native_authority_policy_and_environment_are_fixed_separate_and_nonexpanding(self):
        session = session_double(self.module, "darwin")
        with patch.object(self.module, "_private_file") as write:
            session._write_policy()
        ordinary = tuple(call.args for call in write.call_args_list)
        self.assertEqual(len(ordinary), 3)
        for phase in ("source", "wheel"):
            with self.subTest(native_policy_phase=phase):
                cwd = session.work / f"native-authority-{phase}"
                package = (session.work / "source-build/src/mobile_release" if phase == "source" else
                           session.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
                expected_argv = [str(session.work / f"{phase}-venv/bin/python"), "-I", "-S", "-B",
                    str(session.source / "tests/workflow/run_native_profile_checks.py"), "--authority",
                    *(["--installed-wheel"] if phase == "wheel" else [])]
                self.assertEqual(session._native_command(phase), expected_argv)
                state = dict(phase=phase, cwd=cwd, package=package, argv=expected_argv,
                             policy=session.bootstrap / f"native-authority-{phase}.sb", outside_write=session.outside_write)
                expected_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
                    "TZ": "UTC", "CI": "true", "USER": "mrk-ci-60001", "LOGNAME": "mrk-ci-60001",
                    "HOME": str(cwd / "home"), "TMPDIR": str(cwd / "tmp"), "TMP": str(cwd / "tmp"), "TEMP": str(cwd / "tmp"),
                    "XDG_CONFIG_HOME": str(cwd / "config"), "XDG_CACHE_HOME": str(cwd / "cache"),
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
                    "DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer"}
                with patch.object(self.module, "os", SimpleNamespace(environ={"PYTHONPATH": "/synthetic/poison",
                        "HOME": "/synthetic/old-home", "MOBILE_RELEASE_NATIVE_ROLE": "arbitrary"})):
                    self.assertEqual(session._native_environment(state), expected_env)
                q = lambda path: json.dumps(str(path), ensure_ascii=True)
                authority = session._native_policy_bytes(state, kind="authority").decode("ascii")
                self.assertIn("(deny network*)\n", authority)
                self.assertNotIn("(allow network", authority)
                self.assertIn('(deny mach-lookup (require-not (require-any (global-name "com.apple.trustd") '
                              '(global-name "com.apple.trustd.agent"))))\n', authority)
                self.assertNotIn("com.apple.cfprefsd.daemon", authority)
                self.assertIn("(deny signal (require-not (target same-sandbox)))\n", authority)
                self.assertIn("(subpath " + q(package) + ")", authority)
                self.assertIn("(literal " + q(package.parent) + ")", authority)
                self.assertNotIn("(subpath " + q(package.parent) + ")", authority)
                for previous in (session.work, session.work / "home", session.work / "tmp", session.source,
                                 session.control, session.runner_home, session.runner_temp):
                    self.assertNotIn("(subpath " + q(previous) + ")", authority)
                for leaf in ("home", "tmp", "config", "cache", "probes"):
                    self.assertIn("(subpath " + q(cwd / leaf) + ")", authority)
                baseline = session._native_policy_bytes(state, kind="mach-baseline").decode("ascii")
                self.assertIn('(global-name "com.apple.cfprefsd.daemon")', baseline)
                self.assertNotIn("(allow network", baseline)
                aia = session._native_policy_bytes(state, kind="aia", port=12345).decode("ascii")
                self.assertEqual(aia, authority + '(allow network-outbound (remote tcp "127.0.0.1:12345"))\n')
                positive = session._native_policy_bytes(state, kind="write-positive").decode("ascii")
                self.assertIn('(deny file-write* (require-not (require-any (literal ' + q(session.outside_write) + ")", positive)
                for kind, policy in (("authority", authority), ("mach-baseline", baseline), ("aia", aia), ("write-positive", positive)):
                    with self.subTest(native_cwd_metadata=(phase, kind)):
                        exact = f"(allow file-read-metadata (literal {q(cwd)}))"
                        self.assertEqual([line for line in policy.splitlines() if q(cwd) in line], [exact])
                        data_rule = next(line for line in policy.splitlines() if line.startswith("(deny file-read* "))
                        self.assertNotIn("(literal " + q(cwd) + ")", data_rule)
                        self.assertNotIn("(subpath " + q(cwd) + ")", policy)
                        root_data = '(allow file-read-data (literal "/"))'
                        root_metadata = '(allow file-read-metadata (literal "/"))'
                        lines = policy.splitlines()
                        self.assertEqual([line for line in lines if '(literal "/")' in line],
                                         [root_data, root_metadata])
                        self.assertEqual(lines[lines.index(data_rule) + 1], root_data)
                        self.assertNotIn('(literal "/")', data_rule)
                        self.assertNotIn('(subpath "/")', policy)
                        self.assertNotIn('(allow file-read* (literal "/"))', policy)
                for kind, port in (("arbitrary-services", None), ("authority", 12345), ("aia", None),
                                   ("aia", True), ("aia", 1023), ("aia", 65536)):
                    with self.assertRaises(self.module.SessionError):
                        session._native_policy_bytes(state, kind=kind, port=port)
        with patch.object(self.module, "_private_file") as write:
            session._write_policy()
        self.assertEqual(tuple(call.args for call in write.call_args_list), ordinary)
        for invalid in (None, ["source"], "other", "native-authority-source"):
            with self.assertRaises(self.module.SessionError):
                session._native_command(invalid)

    def test_native_write_startup_is_exact_ordered_and_never_substitutes_for_capture_or_readback(self):
        outer, inner = b"MRK_NATIVE_WRITE_OUTER\n", b"MRK_NATIVE_WRITE_INNER\n"
        self.assertEqual((self.module._NATIVE_WRITE_OUTER, self.module._NATIVE_WRITE_INNER,
                          self.module._NATIVE_WRITE_STDERR), (outer, inner, outer + inner))

        class ExecBoundary(Exception):
            pass

        for case in ("source", "wheel", "framework-argv0", "ordinary", "unknown", "limits-error", "outer-error", "outer-short", "inner-error", "inner-short"):
            with self.subTest(fixed_native_startup=case):
                session = session_double(self.module, "darwin")
                phase = "wheel" if case == "wheel" else "source"
                canary = session.fixture_controls / ("outside-write" if case == "ordinary" else f"native-authority-{phase}-outside-write")
                policy = session.bootstrap / f"native-write-positive-{phase}.sb"
                base = [str(session.python), "-I", "-S", "-B", str(session.entry)]
                role = "--write-control" if case == "ordinary" else "--unknown-control" if case == "unknown" else "--native-write-control"
                command = [*base, role, str(canary)]
                args = ["--enter", "darwin", str(session.uid), str(session.gid), "180", str(policy), *command]
                events, raw, output = [], bytearray(), io.StringIO()
                original = OSError("synthetic fixed startup write failure")
                flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1, ignore_environment=1, no_user_site=1, safe_path=True)
                fake_sys = SimpleNamespace(platform="darwin", executable=str(session.python), orig_argv=[*base, *args], flags=flags)
                if case == "framework-argv0":
                    fake_sys.orig_argv[0] = "/fixture-tools/python/Resources/Python.app/Contents/MacOS/Python"

                def limits(platform, cpu):
                    self.assertEqual((platform, cpu, events), ("darwin", 180, []))
                    events.append("limits")
                    if case == "limits-error":
                        raise original

                def write(fd, data):
                    if fd == 2:
                        self.assertIn(data, (outer, inner))
                        marker = "outer" if data == outer else "inner"
                        events.append(marker)
                        if case == marker + "-error":
                            raise original
                        return len(data) - int(case == marker + "-short")
                    self.assertEqual((fd, data), (614, b"MRK_POSITIVE_WRITE\n"))
                    events.append("data-write")
                    raw.extend(data)
                    return len(data)

                def open_canary(path, flags):
                    self.assertEqual((path, flags), (canary, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
                    events.append("open")
                    return 614

                def execve(executable, argv, env):
                    self.assertEqual((executable, argv, env), ("/usr/bin/sandbox-exec", ["/usr/bin/sandbox-exec", "-f", str(policy), *command], {}))
                    events.append("exec")
                    fake_sys.orig_argv = list(command)  # The second fixed interpreter invocation, not a real exec.
                    if case == "framework-argv0":
                        fake_sys.orig_argv[0] = "/fixture-tools/python/Resources/Python.app/Contents/MacOS/Python"
                    self.assertEqual(self.module._main(command[5:]), 0)
                    raise ExecBoundary

                def fd_effect(label, fd, *args):
                    self.assertEqual(fd, 614)
                    self.assertEqual(args, (0,) if label == "truncate" else ())
                    events.append(label)

                constants = {name: getattr(os, name) for name in ("O_WRONLY", "O_NOFOLLOW", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, getuid=lambda: session.uid, geteuid=lambda: session.uid,
                    getgid=lambda: session.gid, getegid=lambda: session.gid, environ={}, execve=execve, write=write, open=open_canary,
                    fstat=lambda fd: SimpleNamespace(st_uid=session.uid, st_nlink=1, st_mode=stat.S_IFREG | 0o600, st_size=len(raw)),
                    ftruncate=lambda fd, size: fd_effect("truncate", fd, size), fsync=lambda fd: fd_effect("fsync", fd),
                    close=lambda fd: fd_effect("close", fd))
                with patch.multiple(self.module, __file__=str(session.entry), sys=fake_sys, os=fake_os, _limits=limits,
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace()), \
                     patch.object(Path, "resolve", lambda path, **_kwargs: path), \
                     patch.object(Path, "open", side_effect=AssertionError("startup contract owns only an in-memory FD")), \
                     patch.object(Path, "stat", side_effect=AssertionError("startup contract has no native metadata role")), redirect_stdout(output):
                    expected = ExecBoundary if case in {"source", "wheel", "framework-argv0", "ordinary"} else OSError if case.endswith("error") else self.module.SessionError
                    with self.assertRaises(expected) as caught:
                        self.module._main(args)
                    if case.endswith("error"):
                        self.assertIs(caught.exception, original)
                completed = case in {"source", "wheel", "framework-argv0", "ordinary"}
                expected_events = (["limits", "exec"] if case in {"ordinary", "unknown"} else
                                   ["limits"] if case == "limits-error" else
                                   ["limits", "outer"] if case.startswith("outer-") else ["limits", "outer", "exec", "inner"])
                if completed:
                    expected_events += ["open", "truncate", "data-write", "fsync", "close"]
                self.assertEqual(events, expected_events)
                self.assertEqual(bytes(raw), b"MRK_POSITIVE_WRITE\n" if completed else b"")
                self.assertEqual(output.getvalue(), "MRK_OUTSIDE_WRITE_POSITIVE\n" if completed else "")

        # Each mismatch must fail before touching the existing stderr descriptor.
        for outer_role in (True, False):
            cases = ("native-platform", "root-identity", "effective-uid", "different-gid", "entry-root", "provider",
                     "runtime-flags", "origin-flags", "origin-tail", "canary-phase", "extra", "unknown")
            for case in (*cases, *(("declared-platform", "uid-spelling", "cpu", "policy-phase", "inner-executable", "inner-flags", "inner-entry") if outer_role else ())):
                with self.subTest(native_startup_binding=(outer_role, case)):
                    session = session_double(self.module, "darwin")
                    entry = Path("/unapproved/native/bootstrap/ci_sandbox.py") if case == "entry-root" else session.entry
                    python = Path("/unapproved/python") if case == "provider" else session.python
                    base = [str(python), "-I", "-S", "-B", str(entry)]
                    tail = ["--native-write-control", str(session.fixture_controls / "native-authority-source-outside-write")]
                    if case == "canary-phase":
                        tail[-1] = str(session.fixture_controls / "native-authority-other-outside-write")
                    elif case == "unknown":
                        tail[0] = "--unknown-control"
                    args = ["--enter", "darwin", str(session.uid), str(session.gid), "180",
                            str(session.bootstrap / "native-write-positive-source.sb"), *base, *tail] if outer_role else tail
                    if case == "extra":
                        args.append("--extra")
                    changes = {"declared-platform": (1, "linux"), "uid-spelling": (2, "060001"), "cpu": (4, "179"),
                               "policy-phase": (5, str(session.bootstrap / "native-write-positive-wheel.sb")),
                               "inner-executable": (6, "/unapproved/bin/python"), "inner-flags": (8, "-s"),
                               "inner-entry": (10, str(session.source / "ci_sandbox.py"))}
                    if case in changes:
                        index, value = changes[case]
                        args[index] = value
                    origin = [*base, *args]
                    if case == "origin-flags":
                        origin[2] = "-s"
                    elif case == "origin-tail":
                        origin.append("--extra")
                    written = Mock(side_effect=AssertionError("mismatched entry may not publish a startup checkpoint"))
                    flags = SimpleNamespace(isolated=1, no_site=0 if case == "runtime-flags" else 1,
                                            dont_write_bytecode=1, ignore_environment=1, no_user_site=1, safe_path=True)
                    with patch.multiple(self.module, __file__=str(entry),
                            sys=SimpleNamespace(platform="linux" if case == "native-platform" else "darwin", executable=str(python), orig_argv=origin, flags=flags),
                            os=SimpleNamespace(getuid=lambda: 0 if case == "root-identity" else session.uid,
                                geteuid=lambda: 0 if case == "effective-uid" else session.uid,
                                getgid=lambda: session.gid + int(case == "different-gid"), getegid=lambda: session.gid, write=written),
                            subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace()), \
                         patch.object(Path, "resolve", lambda path, **_kwargs: path):
                        with self.assertRaises(self.module.SessionError):
                            self.module._native_write_checkpoint(args, outer=outer_role)
                    written.assert_not_called()

        observations = ((b"", "none"), (outer, "outer"), (outer + inner, "outer-and-inner"),
            (inner, "unclassified"), (inner + outer, "unclassified"), (outer + inner + b"extra\n", "unclassified"),
            (outer[:-1], "unclassified"), (b"unknown\n", "unclassified"))
        captures = [(stderr, prefix, code, b"MRK_OUTSIDE_WRITE_POSITIVE\n" if code == 0 else b"")
                    for stderr, prefix in observations for code in (-6, 0)]
        captures.append((outer + inner, "outer-and-inner", 0, b"wrong stdout\n"))
        for stderr, expected_prefix, code, stdout in captures:
            with self.subTest(native_startup_capture=(expected_prefix, code), stdout=stdout, stderr=stderr):
                session = session_double(self.module, "darwin")
                state = native_state_double(session)
                state["prepared"], session._native_preparing = False, "source"
                result = self.module.CapturedRun(stdout, stderr, code, True, True, True, True, False, False,
                    0.01, "command exited -6" if code != 0 else None,
                    ("original cleanup diagnostic",) if code != 0 else (), (len(stdout), len(stderr)))
                if code != 0:
                    session.fail(result.primary_error)
                session.persisted_bytes = len(stdout) + len(stderr)
                command = [str(session.python), "-I", "-S", "-B", str(session.entry), "--native-write-control", str(state["outside_write"])]
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: 0.0)), \
                     patch.object(session, "_run", return_value=result) as capture, \
                     patch.object(session, "_native_abort_prepare", return_value=native_abort_double(session)), \
                     patch.object(session, "_native_abort_attach", return_value={"schema": 1,
                        "subject": "source-outside-write-positive", "ips_status": "unavailable", "log_status": "unavailable"}):
                    self.assertIs(session._native_control_capture(state, "outside-write-positive", command,
                        policy=session.bootstrap / "native-write-positive-source.sb", cwd=state["cwd"], seconds=10), result)
                    self.assertEqual(self.module._native_write_prefix(stderr), expected_prefix)
                row = state["control_notes"]["outside-write-positive"]
                if code == 0 and stdout == b"MRK_OUTSIDE_WRITE_POSITIVE\n" and stderr == outer + inner:
                    self.assertNotIn("native_write_startup", row)
                else:
                    self.assertEqual(row["native_write_startup"], expected_prefix)
                self.assertFalse(row["ok"])  # Transport success cannot accept a semantic or incomplete native control.
                self.assertEqual((row["subject_ok"], result.ok), (code == 0, code == 0))
                self.assertEqual((row["returncode"], row["persisted"], row["error_count"]),
                                 (code, [len(stdout), len(stderr)], 2 if code != 0 else 0))
                self.assertTrue(row["waited"] and row["stdout_eof"] and row["stderr_eof"] and row["domain_finality"])
                self.assertEqual((session.failure, session.persisted_bytes),
                                 ("command exited -6" if code != 0 else None, len(stdout) + len(stderr)))
                self.assertIsNone(session._native_control)
                capture.assert_called_once()
                self.assertNotIn("MRK_NATIVE_WRITE", repr(row))  # Closed classification, never raw diagnostics.

        class BeforeNextControl(Exception):
            pass

        for case in ("source", "wheel", "empty", "outer-only", "reordered", "extra", "failed-capture", "missing-stdout", "wrong-readback"):
            with self.subTest(native_startup_positive_acceptance=case):
                session = session_double(self.module, "darwin")
                phase = "wheel" if case == "wheel" else "source"
                state = native_state_double(session, phase)
                state["write_policy"] = session.bootstrap / f"native-write-positive-{phase}.sb"
                state["outside_fd"] = 614
                info = SimpleNamespace(st_dev=7, st_ino=91, st_uid=session.uid, st_gid=session.gid, st_nlink=1,
                    st_mode=stat.S_IFREG | 0o600, st_size=len(b"MRK_POSITIVE_WRITE\n"), st_mtime_ns=11, st_ctime_ns=12)
                state["outside_node"] = self.module._home_node(info)
                stderr = {"empty": b"", "outer-only": outer, "reordered": inner + outer, "extra": outer + inner + b"extra\n"}.get(case, outer + inner)
                stdout = b"" if case == "missing-stdout" else b"MRK_OUTSIDE_WRITE_POSITIVE\n"
                result = self.module.CapturedRun(stdout, stderr, -6 if case == "failed-capture" else 0,
                    True, True, True, True, False, False, 0.01, "command exited -6" if case == "failed-capture" else None,
                    (), (len(stdout), len(stderr)))
                stopped = BeforeNextControl("stop before unrelated native read/network/signal controls")
                seen, raw = [], io.BytesIO(b"wrong\n" if case == "wrong-readback" else b"MRK_POSITIVE_WRITE\n")

                def capture(current, selected, argv, *, policy, cwd, seconds):
                    self.assertIs(current, state)
                    self.assertEqual((cwd, seconds), (state["cwd"], 10))
                    seen.append(selected)
                    if selected in {"startup-true", "startup-python"}:
                        self.assertEqual(phase, "source")
                        expected_command = ["/usr/bin/true"] if selected == "startup-true" else [
                            str(session.python), "-I", "-S", "-B", "-c", self.module._NATIVE_STARTUP_PYTHON]
                        expected_output = b"" if selected == "startup-true" else self.module._NATIVE_STARTUP_STDOUT
                        self.assertEqual((argv, policy), (expected_command, state["write_policy"]))
                        state["control_notes"][selected] = {"ok": True}
                        return self.module.CapturedRun(expected_output, b"", 0, True, True, True, True,
                            False, False, 0.01, None, (), (len(expected_output), 0))
                    if selected == "outside-read-positive":
                        raise stopped
                    self.assertEqual((selected, policy, argv), ("outside-write-positive", state["write_policy"],
                        [str(session.python), "-I", "-S", "-B", str(session.entry), "--native-write-control", str(state["outside_write"])]))
                    return result

                def read(fd, count):
                    self.assertEqual(fd, 614)
                    self.assertIn(count, (64, 1))
                    return raw.read(count)

                reader, observe = Mock(side_effect=read), Mock(return_value=info)
                with patch.multiple(self.module, os=SimpleNamespace(fstat=observe, get_inheritable=lambda _fd: False,
                        lseek=Mock(), SEEK_SET=os.SEEK_SET, read=reader), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: 0.0)), \
                     patch.object(session, "_native_control_capture", side_effect=capture), patch.object(session, "ensure_idle") as idle, \
                     patch.object(Path, "lstat", return_value=info):
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        session._native_boundary_controls(state)
                    self.assertEqual(len(caught.exception.exceptions), 1)
                    if case in {"source", "wheel"}:
                        self.assertIs(caught.exception.exceptions[0], stopped)
                    else:
                        self.assertIsInstance(caught.exception.exceptions[0], self.module.SessionError)
                reached_readback = case in {"source", "wheel", "wrong-readback"}
                startup_cases = [] if phase == "wheel" else ["startup-true", "startup-python"]
                self.assertEqual(seen, startup_cases + (["outside-write-positive", "outside-read-positive"]
                    if case in {"source", "wheel"} else ["outside-write-positive"]))
                self.assertEqual((idle.call_count, observe.call_count), (len(startup_cases) + int(reached_readback), int(reached_readback)))
                self.assertEqual(reader.call_count, 2 if case in {"source", "wheel"} else int(case == "wrong-readback"))
                self.assertEqual(state["control_notes"], {selected: {"ok": True} for selected in startup_cases})
                # Successful startup controls never imply the later original boundary sequence passed.

    def test_native_startup_literal_ast_and_exact_prefixes_bind_current_imports_without_executing_code(self):
        # Parse only. Neither this hardcoded diagnostic nor any mutated string
        # is compiled/evaluated, imported, or passed to a process in this test.
        helper = (ROOT / ".github/scripts/ci_sandbox.py").read_text(encoding="utf-8")
        imports = ("import dataclasses", "import errno", "import grp", "import hashlib", "import importlib.util",
            "import json", "import math", "import os", "from pathlib import Path", "import pwd", "import re",
            "import resource", "import secrets", "import selectors", "import signal", "import socket", "import stat",
            "import subprocess", "import sys", "import time")
        future = "from __future__ import annotations"
        tokens = ["MRK_NATIVE_PYTHON_BOOT", *(f"MRK_NATIVE_IMPORT_{index:02}_{edge}"
            for index in range(1, 21) for edge in ("BEFORE", "AFTER")), "MRK_NATIVE_PYTHON_DONE"]
        expected = "".join(token + "\n" for token in tokens).encode("ascii")

        def shape(node):
            return ast.dump(node, include_attributes=False)

        def literal_contract(program, actual_helper):
            self.assertIs(type(program), str)
            source_tree, program_tree = ast.parse(actual_helper), ast.parse(program)
            actual_imports = [node for node in source_tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
            fixed_imports = ast.parse(future + "\n" + "\n".join(imports)).body
            self.assertEqual([shape(node) for node in actual_imports], [shape(node) for node in fixed_imports])
            self.assertEqual(len(program_tree.body), 63)
            self.assertEqual(shape(program_tree.body[0]), shape(fixed_imports[0]))
            prints = [program_tree.body[1], *(node for index in range(20)
                for node in (program_tree.body[2 + 3 * index], program_tree.body[4 + 3 * index])), program_tree.body[-1]]
            self.assertEqual([shape(program_tree.body[3 + 3 * index]) for index in range(20)],
                             [shape(node) for node in fixed_imports[1:]])
            for node, token in zip(prints, tokens, strict=True):
                self.assertEqual(shape(node), shape(ast.parse(f'print("{token}", flush=True)').body[0]))

        program = self.module._NATIVE_STARTUP_PYTHON
        literal_contract(program, helper)
        self.assertEqual(self.module._NATIVE_STARTUP_CASES, ("startup-true", "startup-python"))
        self.assertEqual(self.module._NATIVE_STARTUP_STDOUT, expected)
        self.assertEqual(len(expected.splitlines()), 42)
        self.assertLess(len(expected), 2048)
        assignments = {node.targets[0].id: node.value for node in ast.parse(helper).body
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
        for name, value in (("_NATIVE_STARTUP_PYTHON", program), ("_NATIVE_STARTUP_STDOUT", expected)):
            self.assertIsInstance(assignments[name], ast.Constant)  # Hardcoded authority, not AST-derived/generated executable text.
            self.assertEqual(assignments[name].value, value)

        program_mutations = (
            program.replace("import errno\n", "import errno as renamed\n", 1),
            program.replace("from pathlib import Path\n", "import pathlib\n", 1),
            program.replace(future, "from __future__ import generator_stop", 1),
            program.replace("import dataclasses\n", "import errno\n", 1),
            program + "import decimal\n",
            program + 'open("/synthetic/not-opened", "w")\n',
            program.replace("MRK_NATIVE_PYTHON_BOOT", "MRK_NATIVE_PYTHON_OTHER", 1),
            program.replace("flush=True", "flush=False", 1),
        )
        for number, mutated in enumerate(program_mutations):
            with self.subTest(native_startup_program_mutation=number):
                self.assertNotEqual(mutated, program)
                with self.assertRaises(AssertionError):
                    literal_contract(mutated, helper)
        for number, mutated in enumerate((helper.replace("import grp\n", "import grp as renamed\n", 1),
                helper.replace("from pathlib import Path\n", "import pathlib\n", 1),
                helper.replace(future, "from __future__ import generator_stop", 1),
                helper.replace("import dataclasses\nimport errno\n", "import errno\nimport dataclasses\n", 1),
                helper + "\nimport decimal\n")):
            with self.subTest(native_startup_helper_import_drift=number):
                self.assertNotEqual(mutated, helper)
                with self.assertRaises(AssertionError):
                    literal_contract(program, mutated)

        lines = expected.splitlines(keepends=True)
        stages = ["no-body-marker", "body", *(f"{edge}-import-{index:02}"
            for index in range(1, 21) for edge in ("before", "after")), "imports-finished"]
        self.assertEqual(len(stages), len(lines) + 1)
        for count, stage in enumerate(stages):
            with self.subTest(native_startup_exact_prefix=count):
                self.assertEqual(self.module._native_startup_stage(b"".join(lines[:count])), stage)
        for mutated in (None, True, expected.decode(), bytearray(expected), [expected], expected[:-1], expected + b"extra\n",
                        lines[0][:-1], b"".join(lines[1:]), b"".join([lines[0], lines[2], lines[1]]),
                        lines[0] * 2, lines[0] + b"PRIVATE-DIAGNOSTIC-CANARY\n", expected + b"x" * 2048):
            with self.subTest(native_startup_malformed_prefix=repr(mutated)[:70]):
                self.assertEqual(self.module._native_startup_stage(mutated), "unclassified")

    def test_native_startup_private_routes_consume_attempts_and_stop_on_semantic_or_lifecycle_failure(self):
        def configured(phase="source", platform="darwin"):
            session = session_double(self.module, platform)
            state = native_state_double(session, phase, deadline=20.0)
            state["prepared"], session._native_preparing = False, phase
            session.domain_finality = True
            state["write_policy"] = session.bootstrap / f"native-write-positive-{phase}.sb"
            return session, state

        def vector(session, selected):
            return ["/usr/bin/true"] if selected == "startup-true" else [
                str(session.python), "-I", "-S", "-B", "-c", self.module._NATIVE_STARTUP_PYTHON]

        invalid = ("linux", "wheel", "foreign-state", "owner-mismatch", "reentrant", "busy", "active-original", "direct-pending", "unadmitted", "admitting", "missing-observer",
            "prepared", "started", "closed", "cancelled", "expired", "latched-failure", "missing-order", "wrong-order-type",
            "out-of-order", "duplicate", "missing-prior-success", "failed-prior", "true-extra", "other-tool", "python-provider",
            "python-flags", "python-code", "python-extra", "tuple-vector", "policy", "state-policy", "cwd", "seconds")
        for case in invalid:
            with self.subTest(native_startup_refusal=case):
                session, state = configured("wheel" if case == "wheel" else "source", "linux" if case == "linux" else "darwin")
                selected = "startup-python" if case.startswith("python-") or case in {
                    "out-of-order", "missing-prior-success", "failed-prior"} else "startup-true"
                if selected == "startup-python" and case != "out-of-order":
                    state["startup_seen"] = ["startup-true"]
                    state["control_notes"]["startup-true"] = {"ok": case != "failed-prior"}
                    if case == "missing-prior-success":
                        state["control_notes"].clear()
                argv, policy, cwd, seconds = vector(session, selected), state["write_policy"], state["cwd"], 10
                if case == "foreign-state":
                    session._native_authority[state["phase"]] = dict(state)
                elif case == "owner-mismatch":
                    session._native_preparing = None
                elif case == "reentrant":
                    session._native_control = {"synthetic-already-owned": True}
                elif case == "busy":
                    session._busy = True
                elif case == "active-original":
                    session._active = SimpleNamespace(pid=4242)  # Inert original reference; no process operation.
                elif case == "direct-pending":
                    session._direct_producer_pending = True
                elif case == "unadmitted":
                    session.admitted = False
                elif case == "admitting":
                    session._admitting = True
                elif case == "missing-observer":
                    session.process_observer = None
                elif case in {"prepared", "started", "closed"}:
                    state[case] = True
                elif case == "cancelled":
                    session.cancelled = True
                elif case == "latched-failure":
                    session.fail("original prior failure")
                elif case == "missing-order":
                    del state["startup_seen"]
                elif case == "wrong-order-type":
                    state["startup_seen"] = ()
                elif case == "duplicate":
                    state["startup_seen"] = ["startup-true"]
                elif case == "true-extra":
                    argv.append("--extra")
                elif case == "other-tool":
                    argv[0] = "/usr/bin/false"
                elif case == "python-provider":
                    argv[0] = str(session.work / "source-venv/bin/python")
                elif case == "python-flags":
                    argv[2] = "-s"
                elif case == "python-code":
                    argv[-1] += "\nimport decimal\n"
                elif case == "python-extra":
                    argv.append("--extra")
                elif case == "tuple-vector":
                    argv = tuple(argv)
                elif case == "policy":
                    policy = session.policy
                elif case == "state-policy":
                    state["write_policy"] = session.policy
                elif case == "cwd":
                    cwd = session.work
                elif case == "seconds":
                    seconds = 9
                before = repr(state.get("startup_seen"))
                capture = Mock(side_effect=AssertionError("invalid startup binding must be refused before acquisition"))
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(), resource=SimpleNamespace(), _canonical=Path,
                        time=SimpleNamespace(monotonic=lambda: state["deadline"] if case == "expired" else 0.0)), \
                     patch.object(Path, "resolve", side_effect=AssertionError("rejected startup vector cannot inspect native paths")), \
                     patch.object(session, "_run", capture):
                    with self.assertRaises(self.module.SessionError):
                        session._native_control_capture(state, selected, argv, policy=policy, cwd=cwd, seconds=seconds)
                capture.assert_not_called()
                self.assertEqual(repr(state.get("startup_seen")), before)
                self.assertEqual(state["control_seen"], [])  # The six existing Mach/AIA cases retain separate custody.

        # The public native-control selector is rejected before even the fake
        # collector; ordinary execution cannot overlap private preparation.
        for selected in ("startup-true", "startup-python"):
            session, state = configured()
            with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                    signal=SimpleNamespace(), resource=SimpleNamespace(), _canonical=Path,
                    time=SimpleNamespace(monotonic=lambda: 0.0)), \
                 patch.object(session, "_argv", side_effect=AssertionError("public startup request cannot acquire a launcher")) as launcher:
                for profile in ("native-control", "ordinary"):
                    with self.subTest(native_startup_public=(selected, profile)), self.assertRaises(self.module.SessionError):
                        session.run(vector(session, selected), cwd=state["cwd"], env={}, seconds=10, profile=profile,
                            absolute_deadline=state["deadline"])
                launcher.assert_not_called()
            self.assertEqual(state["startup_seen"], [])

        class OriginalBoundaryReached(Exception):
            pass

        scenarios = ("source", "wheel", "true-nonzero", "true-stdout", "true-stderr", "true-acquisition", "python-acquisition",
            "python-prefix-failure", "python-empty-failure", "python-zero-prefix", "python-zero-malformed", "python-full-nonzero", "python-stderr", "python-finality", "python-close-error",
            "python-timeout", "true-late", "python-late", "true-cancelled", "python-cancelled", "idle-failure", "idle-expired", "idle-cancelled")
        for case in scenarios:
            with self.subTest(native_startup_sequence=case):
                session, state = configured("wheel" if case == "wheel" else "source")
                state["files"] = {state["write_policy"]: {"synthetic-immutable-policy": True}}
                state["tools"] = {"true": {"sha256": "0" * 64}, "python": {"sha256": "1" * 64}}
                original_inputs = repr((state["files"], state["tools"], state["policy"], state["write_policy"]))
                clock, events, captured = SimpleNamespace(now=0.0), [], {}
                original_capture = session._native_control_capture
                stop = OriginalBoundaryReached("stop before the original canary read or any native operation")
                acquisition = OSError("synthetic original acquisition failure")

                def collect(argv, *, cwd, env, seconds, output_limit, cpu_seconds, latch, profile, absolute_deadline):
                    selected = session._native_control["case"]
                    self.assertIn(selected, ("startup-true", "startup-python"))
                    self.assertEqual(state["startup_seen"], ["startup-true"] if selected == "startup-true" else ["startup-true", "startup-python"])
                    self.assertEqual(state["control_seen"], [])
                    self.assertEqual(argv, vector(session, selected))
                    self.assertEqual((cwd, env, seconds, output_limit, cpu_seconds, latch, profile, absolute_deadline),
                        (state["cwd"], {}, 10, self.module.MiB, 180, True, "native-control", state["deadline"]))
                    self.assertNotIn("abort", session._native_control)  # New controls do not broaden abort-diagnostic eligibility.
                    options = dict(cwd=cwd, env=env, seconds=seconds, output_limit=output_limit, cpu_seconds=cpu_seconds,
                                   latch=latch, cancel_after=None, profile=profile, absolute_deadline=absolute_deadline)
                    self.assertIs(session._native_request(argv, **options), state)
                    if case == "source":
                        for changed in ({"env": {"PYTHONPATH": "/synthetic/not-admitted"}}, {"seconds": 9}, {"output_limit": output_limit - 1},
                                        {"cpu_seconds": 179}, {"absolute_deadline": absolute_deadline + 1}, {"latch": False}, {"cancel_after": 1}):
                            with self.assertRaises(self.module.SessionError):
                                session._native_request(argv, **(options | changed))
                    routed, identity = session._argv(argv, cpu_seconds, profile=profile)
                    self.assertEqual(routed, [str(session.python), "-I", "-S", "-B", str(session.entry), "--enter", "darwin",
                        str(session.uid), str(session.gid), "180", str(state["write_policy"]), *argv])
                    self.assertEqual(identity, {"user": session.uid, "group": session.gid, "extra_groups": []})
                    native_env = session._native_environment(state)
                    self.assertEqual((native_env["HOME"], native_env["TMPDIR"]), (str(state["cwd"] / "home"), str(state["cwd"] / "tmp")))
                    self.assertNotIn("PYTHONPATH", native_env)
                    events.append(("capture", selected))
                    if (case, selected) in {("true-acquisition", "startup-true"), ("python-acquisition", "startup-python")}:
                        raise acquisition
                    stdout = b"" if selected == "startup-true" else self.module._NATIVE_STARTUP_STDOUT
                    stderr, code, finality, timeout, primary, cleanup = b"", 0, True, False, None, ()
                    if selected == "startup-true":
                        if case == "true-nonzero":
                            code, primary = 1, "command exited 1"
                        elif case == "true-stdout":
                            stdout = b"unexpected\n"
                        elif case == "true-stderr":
                            stderr = b"PRIVATE-DIAGNOSTIC-CANARY\n"
                    else:
                        if case == "python-prefix-failure":
                            stdout = b"".join(stdout.splitlines(keepends=True)[:10])
                            code, primary = -6, "command exited -6"
                        elif case == "python-empty-failure":
                            stdout, code, primary = b"", -6, "command exited -6"
                        elif case == "python-zero-prefix":
                            stdout = stdout.splitlines(keepends=True)[0]
                        elif case == "python-zero-malformed":
                            stdout = stdout.splitlines(keepends=True)[0] + b"PRIVATE-DIAGNOSTIC-CANARY\n"
                        elif case == "python-full-nonzero":
                            code, primary = -6, "command exited -6"
                        elif case == "python-stderr":
                            stderr = b"PRIVATE-DIAGNOSTIC-CANARY\n"
                        elif case == "python-finality":
                            finality, primary = False, "reserved identity did not reach finality"
                        elif case == "python-close-error":
                            primary, cleanup = "late capture/cleanup/finality error", ("original capture close failed",)
                        elif case == "python-timeout":
                            timeout, primary = True, "command/original aggregate deadline expired"
                    result = self.module.CapturedRun(stdout, stderr, code, True, True, True, finality, timeout, False, 0.125,
                                                    primary, cleanup, (len(stdout), len(stderr)))
                    captured[selected] = result
                    session.persisted_bytes += sum(result.persisted)
                    session.domain_finality = finality
                    if primary is not None:
                        session.fail(primary)
                        session.cleanup_errors.extend(cleanup)
                    if case == ("true-late" if selected == "startup-true" else "python-late"):
                        clock.now = state["deadline"] + 0.1
                    if case == ("true-cancelled" if selected == "startup-true" else "python-cancelled"):
                        session.cancelled = True
                    return result

                def capture(actual, selected, argv, *, policy, cwd, seconds):
                    self.assertIs(actual, state)
                    if selected == "outside-write-positive":
                        self.assertEqual((policy, cwd, seconds), (state["write_policy"], state["cwd"], 10))
                        self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry),
                            "--native-write-control", str(state["outside_write"])])
                        events.append(("original-boundary", selected))
                        raise stop
                    self.assertEqual(selected, "startup-true" if not state["startup_seen"] else "startup-python")
                    result = original_capture(actual, selected, argv, policy=policy, cwd=cwd, seconds=seconds)
                    self.assertIs(result, captured[selected])  # Strict semantic rejection cannot rewrite genuine transport facts.
                    return result

                def domain(platform, uid, *, deadline):
                    self.assertEqual((platform, uid, deadline), ("darwin", session.uid, state["deadline"]))
                    events.append(("idle", state["startup_seen"][-1]))
                    if case == "idle-failure":
                        raise OSError("synthetic original domain observation unavailable")
                    if case == "idle-expired":
                        clock.now = deadline
                    if case == "idle-cancelled":
                        session.cancelled = True
                    return {}

                collector = Mock(side_effect=collect)
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(), resource=SimpleNamespace(), _canonical=Path, _domain=domain,
                        time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", side_effect=AssertionError("fixed startup sequence fixture cannot resolve host paths")), \
                     patch.object(Path, "open", side_effect=AssertionError("fixed startup sequence fixture cannot open host files")), \
                     patch.object(session, "_headroom", Mock()), patch.object(session, "_run", collector), \
                     patch.object(session, "_native_exit_prepare", return_value=None), \
                     patch.object(session, "_native_control_capture", side_effect=capture):
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        session._native_boundary_controls(state)
                    if case in {"source", "wheel"}:
                        self.assertEqual(caught.exception.exceptions, (stop,))
                    elif case in {"true-acquisition", "python-acquisition"}:
                        self.assertIn(acquisition, caught.exception.exceptions)
                    else:
                        self.assertIsNotNone(session.failure)
                    calls_before = collector.call_count
                    for selected in ("startup-true", "startup-python"):
                        with self.assertRaises(self.module.SessionError):
                            original_capture(state, selected, vector(session, selected),
                                policy=state["write_policy"], cwd=state["cwd"], seconds=10)
                    self.assertEqual(collector.call_count, calls_before)  # Neither an exception nor failed row can buy replay/next case.
                reached_python = case == "source" or case.startswith("python-")
                expected_attempts = [] if case == "wheel" else ["startup-true", *(["startup-python"] if reached_python else [])]
                self.assertEqual(state["startup_seen"], expected_attempts)
                self.assertEqual([value for event, value in events if event == "capture"], expected_attempts)
                self.assertEqual([value for event, value in events if event == "original-boundary"],
                                 ["outside-write-positive"] if case in {"source", "wheel"} else [])
                expected_idle = ["startup-true", "startup-python"] if case == "source" else ["startup-true"] if (
                    reached_python or case.startswith("idle-")) else []
                self.assertEqual([value for event, value in events if event == "idle"], expected_idle)
                if case == "source":
                    self.assertEqual(events, [("capture", "startup-true"), ("idle", "startup-true"),
                        ("capture", "startup-python"), ("idle", "startup-python"), ("original-boundary", "outside-write-positive")])
                self.assertEqual(repr((state["files"], state["tools"], state["policy"], state["write_policy"])), original_inputs)
                self.assertEqual((state["control_seen"], state["deadline"], session.deadline), ([], 20.0, 100.0))
                self.assertIsNone(session._native_control)
                self.assertEqual(session.persisted_bytes, sum(sum(result.persisted) for result in captured.values()))
                for selected, result in captured.items():
                    row = state["control_notes"][selected]
                    self.assertEqual((row["subject_ok"], row["returncode"], row["waited"], row["stdout_eof"], row["stderr_eof"],
                        row["domain_finality"], row["timed_out"], row["cancelled"], row["persisted"]),
                        (result.ok, result.returncode, result.waited, result.stdout_eof, result.stderr_eof, result.domain_finality,
                         result.timed_out, result.cancelled, list(result.persisted)))
                    expected_ok = case == "source" or selected == "startup-true" and reached_python
                    self.assertEqual(row["ok"], expected_ok)
                    if selected == "startup-python" and not expected_ok:
                        expected_stage = {"python-prefix-failure": "before-import-05", "python-empty-failure": "no-body-marker",
                            "python-zero-prefix": "body", "python-zero-malformed": "unclassified"}.get(case, "imports-finished")
                        self.assertEqual(row["native_startup_stage"], expected_stage)
                    else:
                        self.assertNotIn("native_startup_stage", row)
                    self.assertNotIn("native_abort_diagnostic", row)
                    for private in ("MRK_NATIVE_PYTHON", "MRK_NATIVE_IMPORT", "PRIVATE-DIAGNOSTIC-CANARY", str(session.root), str(session.python)):
                        self.assertNotIn(private, repr(row))
                    if result.primary_error is not None:
                        self.assertEqual(session.failure, result.primary_error)

    def test_native_exit_sdk_pins_runtime_query_and_fixed_decoders_preserve_closed_abi_authority(self):
        # Source-only SDK contract: no C compiler, system header, dylib, native
        # entry point or numeric process lookup is used by this regression.
        source = (ROOT / ".github/scripts/ci_process_observer.c").read_text(encoding="utf-8")
        fields = [("proc_bsdinfo", name, str(offset), "uint32_t") for name, offset in (
            ("pbi_flags", 0), ("pbi_status", 4), ("pbi_xstatus", 8), ("pbi_pid", 12), ("pbi_ppid", 16),
            ("pbi_uid", 20), ("pbi_gid", 24), ("pbi_ruid", 28), ("pbi_rgid", 32), ("pbi_svuid", 36), ("pbi_svgid", 40))]
        fields += [("proc_exitreasonbasicinfo", name, str(offset), kind) for name, offset, kind in (
            ("beri_namespace", 0, "uint32_t"), ("beri_code", 4, "uint64_t"), ("beri_flags", 12, "uint64_t"),
            ("beri_reason_buf_size", 20, "uint32_t"))]

        def pin_contract(text):
            text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.DOTALL)
            compact = "".join(text.split())
            self.assertEqual(re.findall(r"MRK_NATIVE_ABI_FIELD\((\w+),(\w+),(\d+),(\w+)\);", compact), fields)
            for required in (
                "_Static_assert(CHAR_BIT==8&&sizeof(void*)==8&&sizeof(int)==4&&INT_MAX==2147483647&&INT_MIN==(-2147483647-1),",
                "_Static_assert(sizeof(uint32_t)==4&&sizeof(uint64_t)==8,",
                "_Generic((uid_t)0,uint32_t:1,default:0)&&_Generic((gid_t)0,uint32_t:1,default:0)&&_Generic((pid_t)0,int32_t:1,default:0)",
                "_Static_assert(_Generic(&proc_pidinfo,int(*)(int,int,uint64_t,void*,int):1,default:0),",
                "_Static_assert(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__,",
                "_Static_assert(offsetof(structrecord,field)==(offset)\\&&sizeof(((structrecord*)0)->field)==sizeof(type)\\&&_Generic(((structrecord*)0)->field,type:1,default:0),",
                "_Static_assert(sizeof(structproc_bsdinfo)==136,",
                "_Static_assert(offsetof(structproc_bsdinfo,pbi_comm)==48&&sizeof(((structproc_bsdinfo*)0)->pbi_comm)==16,",
                "_Static_assert(offsetof(structproc_bsdinfo,pbi_name)==64&&sizeof(((structproc_bsdinfo*)0)->pbi_name)==32,",
                "_Static_assert(sizeof(structproc_exitreasonbasicinfo)==24,",
                "_Static_assert(PROC_PIDTBSDINFO==3&&PROC_PIDTBSDINFO_SIZE==136,",
                "_Static_assert(SIDL==1&&SRUN==2&&SSLEEP==3&&SSTOP==4&&SZOMB==5,",
                "_Static_assert(PROC_FLAG_TRACED==2&&PROC_FLAG_INEXIT==4&&PROC_FLAG_LP64==0x10&&PROC_FLAG_PSUGID==0x2000,",
                "#ifdefPROC_PIDEXITREASONBASICINFO_Static_assert(PROC_PIDEXITREASONBASICINFO==25,",
            ):
                self.assertIn(required, compact)
            self.assertNotIn("#definePROC_PIDEXITREASONBASICINFO", compact)
            self.assertIn("proc_pidinfo(pid,PROC_PIDTBSDINFO,UINT64_C(1),info,(int)sizeof(*info))", compact)
            self.assertEqual(compact.count("proc_pidinfo("), 1)  # No external-parent BASIC query or new observer role.

        pin_contract(source)
        for name, changed in (("offset", source.replace("pbi_ppid, 16", "pbi_ppid, 20", 1)),
                ("width", source.replace("beri_code, 4, uint64_t", "beri_code, 4, uint32_t", 1)),
                ("size", source.replace("sizeof(struct proc_bsdinfo) == 136", "sizeof(struct proc_bsdinfo) == 128", 1)),
                ("signature", source.replace("int (*)(int, int, uint64_t, void *, int)", "int (*)(int, int, int, void *, int)", 1)),
                ("selector-provenance", "#define PROC_PIDEXITREASONBASICINFO 25\n" + source)):
            with self.subTest(native_exit_sdk_pin_mutation=name):
                self.assertNotEqual(changed, source)
                with self.assertRaises(AssertionError):
                    pin_contract(changed)

        for case in ("darwin-arm", "darwin-intel", "linux", "big-endian", "wrong-kernel", "wrong-machine", "pointer-width",
                     "integer-width", "missing-module", "missing-library", "missing-symbol"):
            with self.subTest(native_exit_runtime=case):
                pointer, integer, uint32, uint64 = object(), object(), object(), object()
                widths = {pointer: 4 if case == "pointer-width" else 8, integer: 8 if case == "integer-width" else 4, uint32: 4, uint64: 8}
                operation = Mock(side_effect=AssertionError("library binding must not query a numeric process"))
                library = SimpleNamespace() if case == "missing-symbol" else SimpleNamespace(proc_pidinfo=operation)
                loader = Mock(return_value=library, side_effect=OSError("synthetic unavailable library") if case == "missing-library" else None)
                ffi = SimpleNamespace(c_void_p=pointer, c_int=integer, c_uint32=uint32, c_uint64=uint64,
                                      sizeof=lambda kind: widths[kind], CDLL=loader)
                uname = SimpleNamespace(sysname="Darwin", machine="x86_64" if case == "darwin-intel" else "armv7" if case == "wrong-machine" else "arm64",
                                        release="24.6.0" if case == "wrong-kernel" else "25.6.0")
                with patch.dict(sys.modules, {"ctypes": None if case == "missing-module" else ffi}), \
                     patch.multiple(self.module, _NATIVE_EXIT_BINDING=None, _NATIVE_EXIT_LIBRARY=None,
                        os=SimpleNamespace(uname=lambda: uname), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(), resource=SimpleNamespace(),
                        sys=SimpleNamespace(platform="linux" if case == "linux" else "darwin", byteorder="big" if case == "big-endian" else "little")):
                    binding = self.module._native_exit_runtime()
                    self.assertIs(self.module._native_exit_runtime(), binding)  # Failed capability lookup is also once-only.
                    if case in {"darwin-arm", "darwin-intel"}:
                        self.assertEqual(binding, (ffi, library, operation))
                        self.assertEqual(operation.argtypes, [integer, integer, uint64, pointer, integer])
                        self.assertIs(operation.restype, integer)
                    else:
                        self.assertIsNone(binding)
                    retained = case in {"darwin-arm", "darwin-intel", "missing-symbol"}
                    self.assertIs(self.module._NATIVE_EXIT_LIBRARY, library if retained else None)
                    self.assertEqual(self.module._NATIVE_EXIT_BINDING is False, case not in {"darwin-arm", "darwin-intel"})
                operation.assert_not_called()
                if case in {"darwin-arm", "darwin-intel", "missing-library", "missing-symbol"}:
                    loader.assert_called_once_with("/usr/lib/libproc.dylib", use_errno=True)
                else:
                    loader.assert_not_called()

        for basic in (False, True):
            for case in ("exact", "zero", "negative", "short", "long", "bool-return", "false-return", "wrong-raw-type", "wrong-raw-size", "errno-bound", "bad-pid", "bad-selector"):
                with self.subTest(native_exit_fixed_query=(basic, case)):
                    size = 24 if basic else 136
                    raw = b"\0" * (size - int(case == "wrong-raw-size"))
                    buffer = SimpleNamespace(raw=bytearray(raw) if case == "wrong-raw-type" else raw)
                    returned = {"zero": 0, "negative": -1, "short": size - 1, "long": size + 1,
                                "bool-return": True, "false-return": False, "errno-bound": 0}.get(case, size)
                    operation = Mock(return_value=returned)
                    ffi = SimpleNamespace(create_string_buffer=Mock(return_value=buffer), byref=Mock(side_effect=lambda actual: actual),
                                          set_errno=Mock(), get_errno=Mock(return_value=4096 if case == "errno-bound" else errno.EINVAL))
                    binding = (ffi, object(), operation)
                    result = self.module._native_exit_query(binding, True if case == "bad-pid" else 4242,
                                                           basic=1 if case == "bad-selector" else basic)
                    self.assertEqual(result, (raw, None) if case == "exact" else (None, errno.EINVAL if case == "zero" else None))
                    if case in {"bad-pid", "bad-selector"}:
                        ffi.create_string_buffer.assert_not_called()
                        operation.assert_not_called()
                        ffi.set_errno.assert_not_called()
                    else:
                        ffi.create_string_buffer.assert_called_once_with(size)
                        ffi.byref.assert_called_once_with(buffer)
                        ffi.set_errno.assert_called_once_with(0)
                        ffi.get_errno.assert_called_once_with()
                        operation.assert_called_once_with(4242, 25 if basic else 3, 0 if basic else 1, buffer, size)

        session = session_double(self.module, "darwin")
        identity = dict(pid=4242, parent=4000, uid=session.uid, gid=session.gid)
        for status in range(1, 6):
            for flags in (0x10, 0x14):
                with self.subTest(native_exit_bsd_state=(status, flags)):
                    decode = Mock(return_value=-6)
                    with patch.object(self.module, "os", SimpleNamespace(waitstatus_to_exitcode=decode)):
                        result = self.module._native_exit_bsd(native_exit_bsd_bytes(session, status=status, flags=flags, expected_status=0xabcd0086), **identity)
                    self.assertEqual(result, {"status": "terminal" if status == 5 else "transition" if status == 1 or flags & 4 else "live",
                        "expected": -6 if status == 5 else None, "reported_name_hint": "true" if status == 5 else "unavailable"})
                    if status == 5:
                        decode.assert_called_once_with(0x86)  # Compare only the low16 wait bits, never substitute a BSD returncode.
                    else:
                        decode.assert_not_called()
        for field, value in (("pid", 4243), ("ppid", 4001), *((key, 60002) for key in ("uid", "gid", "ruid", "rgid", "svuid", "svgid")),
                             ("flags", 0x12), ("flags", 0x2010)):
            with self.subTest(native_exit_identity_contradiction=field), \
                 patch.object(self.module, "os", SimpleNamespace()), self.assertRaises(self.module._NativeExitIdentity):
                self.module._native_exit_bsd(native_exit_bsd_bytes(session, **{field: value}), **identity)
        for raw in (None, b"", b"\0" * 135, native_exit_bsd_bytes(session) + b"x", bytearray(native_exit_bsd_bytes(session)),
                    native_exit_bsd_bytes(session, status=0), native_exit_bsd_bytes(session, status=6),
                    native_exit_bsd_bytes(session, flags=0), native_exit_bsd_bytes(session, comm=b"x" * 16),
                    native_exit_bsd_bytes(session, name=b"x" * 32)):
            with self.subTest(native_exit_optional_unavailable=repr(raw)[:50]), patch.object(self.module, "os", SimpleNamespace()):
                self.assertIsNone(self.module._native_exit_bsd(raw, **identity))
        with patch.object(self.module, "os", SimpleNamespace(waitstatus_to_exitcode=Mock(side_effect=ValueError("synthetic invalid wait status")))):
            self.assertIsNone(self.module._native_exit_bsd(native_exit_bsd_bytes(session), **identity))
        for reported, hint in ((b"python", "python"), (b"Python", "python"), (b"python3", "python"), (b"python3.11", "python"),
                               (b"sandbox-exec", "sandbox-exec"), (b"true", "true"), (b"python-private", "other"),
                               (b"PRIVATE-DIAGNOSTIC-CANARY", "other"), (b"", "true")):
            with patch.object(self.module, "os", SimpleNamespace(waitstatus_to_exitcode=Mock(return_value=-6))):
                result = self.module._native_exit_bsd(native_exit_bsd_bytes(session, name=reported + b"\0"), **identity)
            self.assertEqual(result["reported_name_hint"], hint)
            self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", repr(result))

        for namespace, code, flags, size in ((6, 1, 0, 0), (18, 1, 2, 100), ((1 << 32) - 1, (1 << 64) - 1, (1 << 64) - 1, (1 << 32) - 1)):
            raw = namespace.to_bytes(4, "little") + code.to_bytes(8, "little") + flags.to_bytes(8, "little") + size.to_bytes(4, "little")
            expected = dict(namespace=namespace, code=code, flags=flags, reason_buffer_size=size)
            if namespace == 6:
                expected.update(namespace_label="DYLD", code_label="DYLIB_MISSING")
            elif namespace == 18:
                expected["namespace_label"] = "LIBSYSTEM"
            self.assertEqual(self.module._native_exit_basic(raw), expected)
            for malformed in (None, raw[:-1], raw + b"x", bytearray(raw)):
                self.assertIsNone(self.module._native_exit_basic(malformed))

    def test_native_exit_private_eligibility_bounded_sampling_and_one_shot_reason_never_supply_wait_authority(self):
        # Every process identity below is an inert object. The module's whole
        # native/effect namespaces are replaced, not individual stdlib APIs.
        for case in ("source", "linux", "wheel", "no-control", "foreign-state", "other-case", "other-vector", "no-observer",
                     "nonroot", "sigchld", "parent-bool", "parent-low", "parent-high", "cancelled", "unavailable"):
            with self.subTest(native_exit_eligibility=case):
                session = session_double(self.module, "linux" if case == "linux" else "darwin")
                state = native_state_double(session, "wheel" if case == "wheel" else "source")
                session._native_control = {"state": dict(state) if case == "foreign-state" else state,
                    "case": "startup-python" if case == "other-case" else "startup-true",
                    "argv": ["/usr/bin/false"] if case == "other-vector" else ["/usr/bin/true"]}
                if case == "no-control":
                    session._native_control = None
                if case == "no-observer":
                    session.process_observer = None
                session.cancelled = case == "cancelled"
                runtime = (object(), object(), object())
                binding = Mock(return_value=None if case == "unavailable" else runtime)
                parent = {"parent-bool": True, "parent-low": 1, "parent-high": 1 << 31}.get(case, 4000)
                with patch.multiple(self.module, os=SimpleNamespace(getpid=lambda: parent, geteuid=lambda: 1 if case == "nonroot" else 0),
                        signal=SimpleNamespace(SIGCHLD=20, SIG_DFL=0, getsignal=lambda _: 1 if case == "sigchld" else 0),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), resource=SimpleNamespace(),
                        time=SimpleNamespace(monotonic=lambda: 0.0), _native_exit_runtime=binding):
                    if case in {"nonroot", "sigchld", "parent-bool", "parent-low", "parent-high"}:
                        with self.assertRaises(self.module._NativeExitIdentity):
                            session._native_exit_prepare(state)
                        binding.assert_not_called()
                        continue
                    context = session._native_exit_prepare(state)
                if case in {"source", "cancelled", "unavailable"}:
                    self.assertEqual((context["parent"], context["uid"], context["gid"]), (4000, session.uid, session.gid))
                    self.assertEqual((context["child"], context["pid"], context["deadline"], context["samples"], context["expected"]),
                                     (None, None, None, 0, None))
                    self.assertEqual(context["retired"], case != "source")
                    self.assertEqual(context["status"], "cancelled" if case == "cancelled" else "unavailable")
                    self.assertIs(context["runtime"], runtime if case == "source" else None)
                    self.assertEqual(binding.call_count, int(case != "cancelled"))
                else:
                    self.assertIsNone(context)
                    binding.assert_not_called()

        def fixture():
            session = session_double(self.module, "darwin")
            child = SimpleNamespace(pid=4242, returncode=None)  # No consuming methods exist on this object.
            context = dict(runtime=(object(), object(), object()), child=child, pid=4242, parent=4000,
                uid=session.uid, gid=session.gid, deadline=1.0, retired=False, samples=0, basic_attempted=False,
                expected=None, reported_name_hint="unavailable", reason=None, status="unavailable", mismatch=False)
            clock = SimpleNamespace(now=0.0, parent=4000, disposition=0)
            return session, child, context, clock

        def scope(clock):
            return patch.multiple(self.module, os=SimpleNamespace(getpid=lambda: clock.parent,
                waitstatus_to_exitcode=Mock(return_value=-6)),
                signal=SimpleNamespace(SIGCHLD=20, SIG_DFL=0, getsignal=lambda _: clock.disposition),
                time=SimpleNamespace(monotonic=lambda: clock.now), subprocess=SimpleNamespace(),
                socket=SimpleNamespace(), resource=SimpleNamespace())

        for case in ("live", "terminal", "retired", "other-child", "changed-pid", "changed-parent", "changed-sigchld", "changed-cutoff",
                     "cancelled", "deadline", "sample-cap", "already-waited", "identity-bytes", "unavailable", "query-error",
                     "query-interrupt", "query-deadline", "cancelled-after-query", "deadline-after-query"):
            with self.subTest(native_exit_sample=case):
                session, child, context, clock = fixture()
                actual, cutoff = child, context["deadline"]
                if case == "retired":
                    context["retired"] = True
                elif case == "other-child":
                    actual = SimpleNamespace(pid=4242, returncode=None)
                elif case == "changed-pid":
                    child.pid += 1
                elif case == "changed-parent":
                    clock.parent += 1
                elif case == "changed-sigchld":
                    clock.disposition = 1
                elif case == "changed-cutoff":
                    cutoff = 0.9
                elif case == "cancelled":
                    session.cancelled = True
                elif case == "deadline":
                    clock.now = 1.0
                elif case == "sample-cap":
                    context["samples"] = 64
                elif case == "already-waited":
                    child.returncode = -6

                def query(runtime, pid, *, basic=False):
                    self.assertIs(runtime, context["runtime"])
                    self.assertEqual((pid, basic), (4242, False))
                    self.assertFalse(context["retired"])
                    if case == "query-error":
                        raise OSError("synthetic optional fixed read")
                    if case == "query-interrupt":
                        raise KeyboardInterrupt("synthetic optional fixed read")
                    if case == "query-deadline":
                        raise self.module.DeadlineExpired("synthetic original cutoff")
                    if case == "cancelled-after-query":
                        session.cancelled = True
                    if case == "deadline-after-query":
                        clock.now = 1.0
                    return (None, errno.EINVAL) if case == "unavailable" else (
                        native_exit_bsd_bytes(session, status=5 if case == "terminal" else 2,
                                              ppid=4001 if case == "identity-bytes" else 4000), None)

                operation = Mock(side_effect=query)
                contradictions = {"other-child", "changed-pid", "changed-parent", "changed-sigchld", "changed-cutoff", "identity-bytes"}
                queried = {"live", "terminal", "identity-bytes", "unavailable", "query-error", "query-interrupt",
                           "query-deadline", "cancelled-after-query", "deadline-after-query"}
                with scope(clock), patch.object(self.module, "_native_exit_query", operation):
                    if case in contradictions:
                        with self.assertRaises(self.module._NativeExitIdentity):
                            session._native_exit_sample(context, actual, cutoff=cutoff)
                        self.assertEqual(context["status"], "identity-error")
                    else:
                        self.assertEqual(session._native_exit_sample(context, actual, cutoff=cutoff),
                                         case if case in {"live", "terminal"} else "retired")
                    self.assertEqual(operation.call_count, int(case in queried))
                    self.assertEqual(context["retired"], case not in {"live", "terminal"})
                    self.assertEqual(context["expected"], -6 if case == "terminal" else None)
                    self.assertEqual(context["samples"], 64 if case == "sample-cap" else int(case in queried))
                    self.assertIsNone(session.failure)  # Pure observation cannot impersonate the collector's failure/wait.
                    if case in {"cancelled", "query-interrupt", "cancelled-after-query"}:
                        self.assertTrue(session.cancelled)
                        self.assertEqual(context["status"], "cancelled")
                    if case in {"deadline", "query-deadline", "deadline-after-query"}:
                        self.assertEqual(context["status"], "deadline")
                    if case == "sample-cap":
                        self.assertEqual(context["status"], "limit")
                    session._native_exit_retire(context)
                    status = context["status"]
                    session._native_exit_retire(context, "limit")
                    self.assertEqual(context["status"], status)  # Retirement is not a new query/status lifetime.
                    self.assertEqual(session._native_exit_sample(context, actual, cutoff=cutoff), "retired")
                    self.assertEqual(operation.call_count, int(case in queried))

        basic_bytes = (6).to_bytes(4, "little") + (1).to_bytes(8, "little") + (0).to_bytes(8, "little") + (0).to_bytes(4, "little")
        for case in ("observed", "absent", "unavailable", "retired", "already-attempted", "no-terminal", "terminal-zero", "cancelled",
                     "deadline", "already-waited", "changed-parent", "query-error", "query-interrupt", "query-deadline"):
            with self.subTest(native_exit_basic_once=case):
                session, child, context, clock = fixture()
                context.update(expected=-6, status="terminal", reported_name_hint="true")
                session.fail("original first failure")
                if case == "retired":
                    context["retired"] = True
                elif case == "already-attempted":
                    context["basic_attempted"] = True
                elif case == "no-terminal":
                    context["expected"] = None
                elif case == "terminal-zero":
                    context["expected"] = 0
                elif case == "cancelled":
                    session.cancelled = True
                elif case == "deadline":
                    clock.now = 1.0
                elif case == "already-waited":
                    child.returncode = -6
                elif case == "changed-parent":
                    clock.parent = 4001
                answer = (None, errno.ENOENT) if case == "absent" else (None, errno.EINVAL) if case == "unavailable" else (basic_bytes, None)
                error = {"query-error": OSError("synthetic optional BASIC"), "query-interrupt": KeyboardInterrupt("synthetic optional BASIC"),
                         "query-deadline": self.module.DeadlineExpired("synthetic original cutoff")}.get(case)
                operation = Mock(return_value=answer, side_effect=error)
                queried = case in {"observed", "absent", "unavailable", "query-error", "query-interrupt", "query-deadline"}
                with scope(clock), patch.object(self.module, "_native_exit_query", operation):
                    if case == "changed-parent":
                        with self.assertRaises(self.module._NativeExitIdentity):
                            session._native_exit_reason(context, child)
                    else:
                        session._native_exit_reason(context, child)
                    session._native_exit_reason(context, child)  # Failure, absence and exceptions never permit retry.
                    self.assertEqual(operation.call_count, int(queried))
                    if queried:
                        operation.assert_called_once_with(context["runtime"], 4242, basic=True)
                        self.assertTrue(context["basic_attempted"])
                    if case in {"observed", "absent", "unavailable"}:
                        self.assertEqual(context["status"], case)
                    self.assertEqual(session.failure, "original first failure")
                    self.assertEqual(context["reason"] is not None, case == "observed")

        session, child, context, clock = fixture()
        context.update(expected=-6, status="observed", reported_name_hint="true", reason=self.module._native_exit_basic(basic_bytes))
        failed = self.module.CapturedRun(b"", b"", -6, True, True, True, True, False, False, 0.1,
                                        "command exited -6", (), (0, 0))
        row = session._native_exit_attach(context, failed)
        self.assertEqual(row, {"schema": 1, "status": "observed", "reported_name_hint": "true", "expected_wait_code": -6,
                              "namespace": 6, "code": 1, "flags": 0, "reason_buffer_size": 0,
                              "namespace_label": "DYLD", "code_label": "DYLIB_MISSING"})
        self.assertLessEqual(len(json.dumps(row).encode()), 2048)
        for private in ("4242", "4000", str(session.root), str(session.python), "PRIVATE-DIAGNOSTIC-CANARY"):
            self.assertNotIn(private, json.dumps(row))
        success = dataclasses.replace(failed, returncode=0, primary_error=None)
        self.assertIsNone(session._native_exit_attach(context, success))
        self.assertIsNone(session._native_exit_attach(None, failed))
        context["reason"] = {"namespace_label": "x" * 4096}  # In-memory damaged-state limit, never a native payload.
        self.assertEqual(session._native_exit_attach(context, failed),
                         {"schema": 1, "status": "limit", "reported_name_hint": "unavailable"})
        self.assertFalse(session._native_exit_compare(None, -9))
        self.assertFalse(session._native_exit_compare(context, None))
        self.assertFalse(session._native_exit_compare(context, -6))
        self.assertTrue(session._native_exit_compare(context, -9))
        self.assertFalse(session._native_exit_compare(context, -9))
        self.assertFalse(session._native_exit_compare(context, -6))
        self.assertEqual((context["expected"], context["status"], context["mismatch"]), (-6, "wait-mismatch", True))
        self.assertEqual((failed.returncode, failed.waited, failed.finality, failed.primary_error),
                         (-6, True, True, "command exited -6"))

    def test_native_exit_original_parent_collector_retires_before_consumption_and_preserves_first_failure_and_finality(self):
        # Real private capture/collector/report integration over the existing
        # closed in-memory rig. Neither binding nor any process lookup is real.
        cases = ("live-terminal", "zero-terminal", "zero-finality-error", "binding-unavailable", "optional-unavailable", "live-fallback",
            "sample-limit", "deadline-live", "cancel-live", "query-error", "query-interrupt", "query-deadline", "identity",
            "basic-error", "basic-deadline", "basic-cancel", "basic-identity", "wait-mismatch", "wait-zero-mismatch",
            "late-wait-mismatch", "missing-wait", "held-eof", "cleanup-error", "capture-close-error", "persist-error",
            "read-error", "selector-error", "credentials-error", "binding-cancel", "binding-interrupt", "binding-deadline",
            "capture-cancel", "inputs-error")
        prelaunch = {"binding-cancel", "binding-interrupt", "binding-deadline", "capture-cancel", "inputs-error"}
        no_sample = prelaunch | {"binding-unavailable", "selector-error", "credentials-error"}
        one_sample = {"optional-unavailable", "deadline-live", "cancel-live", "query-error", "query-interrupt", "query-deadline",
                      "identity", "persist-error", "read-error"}
        expected_zero = {"zero-terminal", "zero-finality-error", "wait-zero-mismatch"}
        terminal_cases = set(cases) - no_sample - one_sample - {"live-fallback", "sample-limit"}
        basic_cases = terminal_cases - expected_zero - {"basic-identity"}
        payload = b"kept-original-output\n"
        basic_bytes = (6).to_bytes(4, "little") + (1).to_bytes(8, "little") + (0).to_bytes(8, "little") + (0).to_bytes(4, "little")

        for case in cases:
            with self.subTest(native_exit_original_collector=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session, deadline=50.0)
                state["prepared"], session._native_preparing = False, "source"
                state["write_policy"] = session.bootstrap / "native-write-positive-source.sb"
                empty_output = case in {"zero-terminal", "zero-finality-error"}
                rig = _Collection(self.module, session, stdout=() if empty_output else (payload,), stderr=())
                rig.snapshot_rows, rig.exit_at = {}, 50.0
                rig.exitcode = 0 if case in {"zero-terminal", "zero-finality-error"} else -9 if case == "wait-mismatch" else -6
                rig.unreapable = case == "missing-wait"
                if case in {"binding-unavailable", "optional-unavailable", "query-error"}:
                    rig.exit_at = 0.18
                elif case == "live-fallback":
                    rig.exit_at = 0.3
                elif case == "sample-limit":
                    rig.exit_at = 4.5
                if case in basic_cases or case == "basic-identity":
                    rig.hold = {1}  # Optional BASIC must observe an already-latched failure, not complete EOF.
                if case == "selector-error":
                    rig.selector_error = OSError("synthetic selector acquisition")
                elif case == "capture-close-error":
                    rig.fd_close_errors = {0}
                elif case == "persist-error":
                    rig.after_write_error = 0
                elif case == "cleanup-error":
                    rig.cleanup_diagnostics = ["synthetic numerical cleanup failure"]
                elif case == "zero-finality-error":
                    rig.final_domain = {4243: ((session.uid,), (session.gid,), 0)}
                originals, latches, cutoffs, consumed, waited_codes = [], [], [], [], []
                identity = SimpleNamespace(parent=4000)
                runtime = (object(), object(), object())
                real_prepare, real_fail = session._native_exit_prepare, session._fail

                def bind():
                    self.assertIsNone(session._active)
                    self.assertFalse(any(event[0] == "popen" for event in rig.events))
                    if case == "binding-cancel":
                        session.cancelled = True
                    elif case == "binding-interrupt":
                        raise KeyboardInterrupt("synthetic original-parent binding cancellation")
                    elif case == "binding-deadline":
                        rig.now = state["deadline"] + 0.1
                    return None if case == "binding-unavailable" else runtime

                def prepare(actual):
                    self.assertIs(actual, state)
                    self.assertEqual(session._native_control["case"], "startup-true")
                    context = real_prepare(actual)
                    originals.append(context)
                    return context

                def latch(message):
                    if session.failure is None:
                        latches.append((message, rig.now))
                    return real_fail(message)

                def credentials(pid, uid, gid, *, deadline):
                    self.assertEqual((pid, uid, gid), (rig.child.pid, session.uid, session.gid))
                    self.assertIs(session._active, rig.child)
                    self.assertIs(originals[0]["child"], rig.child)
                    self.assertEqual(originals[0]["deadline"], deadline)
                    cutoffs.append(deadline)
                    if case == "credentials-error":
                        raise self.module.SessionError("synthetic original credential observation failure")

                def query(binding, pid, *, basic=False):
                    context = originals[0]
                    self.assertIs(binding, runtime)
                    self.assertIs(context["child"], rig.child)
                    self.assertIs(session._active, rig.child)
                    self.assertEqual((pid, context["pid"], context["parent"], context["uid"], context["gid"]),
                                     (4242, 4242, 4000, session.uid, session.gid))
                    self.assertEqual((context["deadline"], state["deadline"], session.deadline), (cutoffs[0], 50.0, 100.0))
                    self.assertFalse(context["retired"])
                    self.assertFalse(consumed, "a genuine consuming operation must permanently end numeric observation")
                    self.assertLess(rig.now, context["deadline"])
                    if basic:
                        rig.events.append(("native-basic", rig.now))
                        self.assertTrue(context["basic_attempted"])
                        self.assertEqual(context["expected"], -6)
                        self.assertEqual(session.failure, "command exited -6")
                        self.assertEqual(latches[0][0], session.failure)
                        self.assertNotIn(("unregister-eof", 1), rig.events)
                        if case == "basic-error":
                            rig.hold.clear()
                            raise OSError("synthetic optional BASIC unavailability")
                        if case == "basic-deadline":
                            rig.now = context["deadline"] + 0.1
                        elif case == "basic-cancel":
                            session.cancelled = True
                        if case != "held-eof":
                            rig.hold.clear()
                        return basic_bytes, None
                    rig.events.append(("native-bsd", context["samples"], rig.now))
                    if case in {"optional-unavailable", "live-fallback"} and (case == "optional-unavailable" or context["samples"] == 2):
                        return None, errno.ESRCH
                    if case == "query-error":
                        raise OSError("synthetic optional BSD unavailability")
                    if case == "query-interrupt":
                        raise KeyboardInterrupt("synthetic optional BSD cancellation")
                    if case == "query-deadline":
                        rig.now = context["deadline"]
                        raise self.module.DeadlineExpired("synthetic original command deadline")
                    if case == "identity":
                        return native_exit_bsd_bytes(session, pid=4243), None
                    if case == "deadline-live":
                        rig.now = context["deadline"]
                    elif case == "cancel-live":
                        session.cancelled = True
                    if context["samples"] <= 2 or case == "sample-limit":
                        return native_exit_bsd_bytes(session, status=2 if context["samples"] == 1 else 1), None
                    rig.exit_at = rig.now  # A synthetic terminal record still requires the original fake child's actual wait.
                    if case == "basic-identity":
                        identity.parent = 4001
                    return native_exit_bsd_bytes(session, expected_status=0 if case in expected_zero else 6), None

                def consuming(name, original):
                    def consume(*args, **kwargs):
                        self.assertEqual(len(originals), 1)
                        self.assertTrue(originals[0]["retired"], name + " may itself reap; retire BEFORE entering it")
                        consumed.append((name, rig.now))
                        rig.events.append(("consume-original", name, rig.now))
                        if name in {"terminate", "kill"}:
                            rig.child.poll()  # Model Popen signalling's internal, potentially consuming poll.
                        answer = original(*args, **kwargs)
                        if name == "poll" and answer is not None:
                            rig.child.returncode = answer
                        if name == "wait":
                            if case == "late-wait-mismatch":
                                answer = -9
                            waited_codes.append(answer)
                        return answer
                    return consume

                def opened(path, flags, mode):
                    descriptor = rig.open(path, flags, mode)
                    if case == "capture-cancel" and len(rig.opened) == 2:
                        session.cancelled = True
                    return descriptor

                binding, operation = Mock(side_effect=bind), Mock(side_effect=query)
                capture = refused = None
                with rig.scope(), ExitStack() as effects:
                    effects.enter_context(patch.multiple(self.module, _native_exit_runtime=binding, _native_exit_query=operation,
                        _observe_original_credentials=credentials, sys=SimpleNamespace(orig_argv=[]),
                        signal=SimpleNamespace(SIGCHLD=20, SIG_DFL=0, getsignal=lambda _: 0),
                        socket=SimpleNamespace(), resource=SimpleNamespace()))
                    effects.enter_context(patch.object(self.module, "os", SimpleNamespace(**vars(self.module.os),
                        getpid=lambda: identity.parent, waitstatus_to_exitcode=lambda status: 0 if status == 0 else -6)))
                    effects.enter_context(patch.object(self.module.os, "open", side_effect=opened))
                    effects.enter_context(patch.object(Path, "resolve", side_effect=AssertionError("inert startup capture cannot resolve native paths")))
                    effects.enter_context(patch.object(session, "_native_check_inputs",
                        side_effect=self.module.SessionError("synthetic immutable input failure") if case == "inputs-error" else None))
                    effects.enter_context(patch.object(session, "_native_close_pins", return_value=[]))
                    effects.enter_context(patch.object(session, "_native_exit_prepare", side_effect=prepare))
                    effects.enter_context(patch.object(session, "_fail", side_effect=latch))
                    for name in ("poll", "wait", "terminate", "kill"):
                        effects.enter_context(patch.object(rig.child, name, side_effect=consuming(name, getattr(rig.child, name))))
                    if case == "read-error":
                        effects.enter_context(patch.object(self.module.os, "read", side_effect=OSError("synthetic original pipe read failure")))
                    try:
                        capture = session._native_control_capture(state, "startup-true", ["/usr/bin/true"],
                            policy=state["write_policy"], cwd=state["cwd"], seconds=10)
                    except self.module.SessionError as exc:
                        refused = exc
                binding.assert_called_once_with()
                self.assertEqual(len(originals), 1)
                context = originals[0]
                self.assertTrue(context["retired"])
                self.assertIsNone(session._native_control)
                self.assertFalse(session._busy or session._direct_producer_pending)
                self.assertEqual((state["deadline"], session.deadline, state["startup_seen"], state["control_seen"]),
                                 (50.0, 100.0, ["startup-true"], []))
                samples = [event for event in rig.events if event[0] == "native-bsd"]
                basics = [event for event in rig.events if event[0] == "native-basic"]
                self.assertEqual(len(samples), 0 if case in no_sample else 1 if case in one_sample else 2 if case == "live-fallback" else
                                 64 if case == "sample-limit" else 3)
                self.assertEqual(len(basics), int(case in basic_cases))
                self.assertEqual(context["samples"], len(samples))
                self.assertEqual(operation.call_count, len(samples) + len(basics))
                if case in prelaunch:
                    self.assertTrue(refused is not None or capture is not None and not capture.ok)
                    self.assertIsNotNone(session.failure)
                    self.assertEqual(session.cancelled, case in {"binding-cancel", "binding-interrupt", "capture-cancel"})
                    self.assertIsNone(context["child"])
                    self.assertIsNone(context["pid"])
                    self.assertIsNone(context["deadline"])
                    self.assertIsNone(session._active)
                    for name in ("popen", "poll", "wait-original", "terminate-original", "kill-original", "stream-close", "cleanup"):
                        self.assertNotIn(name, [event[0] for event in rig.events])
                    self.assertFalse(consumed or cutoffs or waited_codes)
                    self.assertEqual(session.persisted_bytes, 0)
                    if capture is not None:
                        self.assertFalse(capture.waited or capture.finality or capture.stdout_eof or capture.stderr_eof)
                    continue

                self.assertIsNone(refused)
                self.assertIsNotNone(capture)
                self.assertNotIn("AssertionError", repr((capture.primary_error, capture.cleanup_errors)))
                self.assertEqual(len(cutoffs), int(case != "selector-error"))
                if cutoffs:
                    self.assertGreater(cutoffs[0], 10.0)
                    self.assertLess(cutoffs[0], 10.1)
                    self.assertEqual(context["deadline"], cutoffs[0])
                    self.assertIs(context["child"], rig.child)
                if samples:
                    last_query_index = max(i for i, event in enumerate(rig.events) if event[0] in {"native-bsd", "native-basic"})
                    first_consume_index = next(i for i, event in enumerate(rig.events) if event[0] == "consume-original")
                    self.assertLess(last_query_index, first_consume_index)
                if case in {"binding-unavailable", "optional-unavailable", "live-fallback", "sample-limit", "query-error"}:
                    self.assertEqual(next(event for event in rig.events if event[0] == "poll"), ("poll", None))
                    self.assertEqual(context["status"], "limit" if case == "sample-limit" else "unavailable")
                if case in {"deadline-live", "query-deadline"}:
                    self.assertEqual(context["status"], "deadline")
                if case in {"cancel-live", "query-interrupt"}:
                    self.assertEqual(context["status"], "cancelled")
                if case in {"identity", "basic-identity"}:
                    self.assertEqual(context["status"], "identity-error")
                if case in {"wait-mismatch", "wait-zero-mismatch", "late-wait-mismatch"}:
                    self.assertEqual((context["status"], context["mismatch"]), ("wait-mismatch", True))
                    self.assertEqual(capture.cleanup_errors.count("native terminal status disagrees with original wait"), 1)
                failure = {"zero-terminal": None, "zero-finality-error": "late capture/cleanup/finality error",
                    "deadline-live": "command/original aggregate deadline expired", "query-deadline": "command/original aggregate deadline expired",
                    "cancel-live": "command cancellation", "query-interrupt": "command cancellation",
                    "identity": "native original-parent observation identity mismatch", "selector-error": "collection OSError",
                    "credentials-error": "collection SessionError", "persist-error": "collection OSError", "read-error": "collection OSError"}.get(case, "command exited -6")
                self.assertEqual((capture.primary_error, session.failure), (failure, failure))
                self.assertEqual(capture.ok, case == "zero-terminal")
                self.assertEqual(capture.timed_out, case in {"deadline-live", "query-deadline"})
                self.assertEqual(capture.cancelled, case in {"cancel-live", "query-interrupt", "basic-cancel"})
                self.assertEqual(capture.waited, case not in {"selector-error", "missing-wait"})
                self.assertEqual(capture.returncode, waited_codes[-1] if waited_codes else None)
                self.assertEqual(capture.returncode, None if case in {"selector-error", "missing-wait"} else
                    -15 if case in {"deadline-live", "query-deadline", "cancel-live", "query-interrupt"} else
                    -9 if case in {"credentials-error", "identity", "read-error", "persist-error", "wait-mismatch", "late-wait-mismatch"} else
                    0 if case in {"zero-terminal", "zero-finality-error"} else -6)
                if case == "missing-wait":
                    self.assertIs(session._active, rig.child)  # The BSD expectation cannot release the original producer.
                    self.assertFalse(capture.finality)
                    self.assertIn("original child wait TimeoutError", capture.cleanup_errors)
                else:
                    self.assertIsNone(session._active)
                if case in {"held-eof", "basic-deadline"}:
                    self.assertFalse(capture.stderr_eof or capture.finality)
                    self.assertIn("stream EOF unavailable at bounded cleanup cutoff", capture.cleanup_errors)
                if case == "zero-finality-error":
                    self.assertFalse(capture.domain_finality)
                    self.assertIn("reserved identity did not reach finality", capture.cleanup_errors)
                if case == "capture-close-error":
                    self.assertIn("capture close OSError", capture.cleanup_errors)
                if case == "cleanup-error":
                    self.assertIn("synthetic numerical cleanup failure", capture.cleanup_errors)
                if case in {"live-terminal", "zero-terminal", "binding-unavailable", "live-fallback", "sample-limit", "optional-unavailable"}:
                    self.assertTrue(capture.waited and capture.stdout_eof and capture.stderr_eof and capture.domain_finality)
                actual = tuple(bytes(rig.captures.get(fd, b"")) for fd in (100, 101))
                expected_output = b"" if empty_output or case in {"selector-error", "credentials-error", "identity", "read-error"} else payload
                self.assertEqual((capture.stdout, capture.stderr), (expected_output, b""))
                self.assertEqual((capture.stdout, capture.stderr), actual)
                self.assertEqual(capture.persisted, tuple(map(len, actual)))
                self.assertEqual(session.persisted_bytes, sum(capture.persisted))
                cleanup_cutoffs = [event[1] for event in rig.events if event[0] == "cleanup-deadline"]
                if cleanup_cutoffs:
                    self.assertEqual(len(cleanup_cutoffs), 1)
                    self.assertAlmostEqual(cleanup_cutoffs[0], min(state["deadline"], latches[0][1] + 8), delta=0.005)
                    self.assertTrue(all(event[2] <= cleanup_cutoffs[0] for event in rig.events if event[0] == "domain-deadline" and event[1] > 1))
                row = state["control_notes"]["startup-true"]
                self.assertEqual((row["ok"], row["subject_ok"], row["returncode"], row["waited"], row["stdout_eof"], row["stderr_eof"],
                    row["domain_finality"], row["timed_out"], row["cancelled"], row["persisted"]),
                    (capture.ok, capture.ok, capture.returncode, capture.waited, capture.stdout_eof, capture.stderr_eof,
                     capture.domain_finality, capture.timed_out, capture.cancelled, list(capture.persisted)))
                if case == "zero-terminal":
                    self.assertNotIn("native_exit_reason", row)
                else:
                    attachment = row["native_exit_reason"]
                    self.assertEqual(attachment["schema"], 1)
                    self.assertEqual(attachment["status"], context["status"])
                    self.assertEqual(attachment.get("expected_wait_code"), 0 if case in expected_zero else -6 if case in terminal_cases else None)
                    self.assertLessEqual(len(json.dumps(attachment).encode()), 2048)
                    self.assertLessEqual(set(attachment), {"schema", "status", "reported_name_hint", "expected_wait_code", "namespace", "code", "flags",
                                                          "reason_buffer_size", "namespace_label", "code_label"})
                    for private in ("4242", "4000", str(session.root), str(session.python), "PRIVATE-DIAGNOSTIC-CANARY"):
                        self.assertNotIn(private, json.dumps(attachment))
                self.assertNotIn("native_abort_diagnostic", row)

    def test_native_abort_ips_requires_strict_objects_original_identity_precise_time_and_closed_hints(self):
        session = session_double(self.module, "darwin")
        abort = native_abort_double(session)
        wall = 1_789_029_600_000_000_000
        for text, instant, unit in (("2026-09-10 08:40:00 +0000", wall, 1_000_000_000),
                ("2026-09-10 08:40:00.1255 +0000", wall + 125_500_000, 100_000),
                ("2026-09-10 11:10:00.1255 +0230", wall + 125_500_000, 100_000),
                ("2026-09-10 08:40:00.125500123 +0000", wall + 125_500_123, 1)):
            with self.subTest(native_abort_timestamp=text):
                self.assertEqual(self.module._native_abort_time(text), (2 * instant - unit, 2 * instant + 2 * unit))
        for value in (None, True, 1, "", "2026-09-10 08:40:00", "2026-02-29 08:40:00 +0000",
                      "2026-09-10 08:40:00 +2500", "2026-09-10 08:40:00.1234567890 +0000", "x" * 129):
            with self.subTest(native_abort_invalid_timestamp=value), self.assertRaises(self.module._NativeAbortIssue):
                self.module._native_abort_time(value)

        for bug_type in ("309", 309):
            raw = native_abort_ips_bytes(abort, metadata={"bug_type": bug_type})
            observed = self.module._native_abort_ips_record(raw, abort)
            self.assertEqual(observed, {"sha256": hashlib.sha256(raw).hexdigest(), "image_role": "python-selected",
                "exception": "EXC_CRASH", "signal": "SIGABRT", "termination_namespace": "LIBSYSTEM", "termination_code": 1,
                "fault_image_role": "libsystem-kernel", "frame_roles": ["abort-with-payload"]})
            encoded = json.dumps(observed)
            self.assertLessEqual(len(encoded.encode()), 4096)
            for private in ("PRIVATE-DIAGNOSTIC-CANARY", "PRIVATE_TOKEN", "/Users/", str(session.root), str(session.python), "__abort_with_payload"):
                self.assertNotIn(private, encoded)

        raw = native_abort_ips_bytes(abort)
        for field, value in (("pid", 4243), ("pid", "4242"), ("pid", True), ("userID", 60002), ("userID", "60001"),
                ("userID", True), ("procPath", "/unadmitted/bin/python"), ("procPath", None),
                ("procLaunch", "2026-09-10 08:40:00.0000 +0000"),
                ("procLaunch", "2026-09-10 08:39:59.9999 +0000"),
                ("captureTime", "2026-09-10 08:40:03.0000 +0000"),
                ("captureTime", "2026-09-10 08:39:59.9999 +0000"),
                ("exception", {"type": "EXC_BAD_ACCESS", "signal": "SIGABRT"}),
                ("exception", {"type": "EXC_CRASH", "signal": "SIGSEGV"})):
            with self.subTest(native_abort_identity=(field, value)):
                self.assertIsNone(self.module._native_abort_ips_record(native_abort_ips_bytes(abort, body={field: value}), abort))
        for field in ("pid", "userID", "procPath", "procLaunch", "captureTime", "exception"):
            header, body = [json.loads(line) for line in raw.splitlines()]
            del body[field]
            missing = (json.dumps(header) + "\n" + json.dumps(body)).encode()
            with self.subTest(native_abort_missing_identity=field):
                self.assertIsNone(self.module._native_abort_ips_record(missing, abort))
        for bug_type in (True, 309.0, "0309", "309.0", None):
            with self.subTest(native_abort_noncanonical_bug_type=bug_type):
                self.assertIsNone(self.module._native_abort_ips_record(native_abort_ips_bytes(abort, metadata={"bug_type": bug_type}), abort))

        # Coarse process time may overlap only through its displayed precision;
        # a precise contradicting value cannot borrow metadata time or slack.
        self.assertIsNotNone(self.module._native_abort_ips_record(native_abort_ips_bytes(abort,
            body={"procLaunch": "2026-09-10 08:40:00 +0000"}), abort))
        self.assertIsNone(self.module._native_abort_ips_record(native_abort_ips_bytes(abort,
            metadata={"timestamp": "2026-09-10 08:40:00.1255 +0000"}, body={"procLaunch": None}), abort))
        self.assertIsNone(self.module._native_abort_ips_record(native_abort_ips_bytes(abort, body={
            "procLaunch": "2026-09-10 08:40:00.1259 +0000", "captureTime": "2026-09-10 08:40:00.1251 +0000"}), abort))
        for changes in ({"wall_after": abort["wall_before"] - 1}, {"wall_wait": abort["wall_after"] - 1},
                        {"wall_wait": abort["wall_before"] + 18_000_000_001}, {"wall_before": float(abort["wall_before"])},
                        {"wall_before": -1}):
            with self.subTest(native_abort_clock_binding=changes), self.assertRaises(self.module._NativeAbortIssue) as caught:
                self.module._native_abort_ips_record(raw, abort | changes)
            self.assertEqual(caught.exception.code, "CLOCK_BINDING")

        header, body = raw.split(b"\n", 1)
        malformed = (b"\xff\n{}", header + body, header + b"\n[]", b"[]\n" + body,
                     raw + b"{}", raw[:-2], raw.replace(b'"bug_type":"309"', b'"bug_type":"309","bug_type":"309"', 1),
                     raw.replace(b'"pid":4242', b'"pid":4242,"pid":4242', 1),
                     raw.replace(b'"code":1', b'"code":NaN', 1), raw.replace(b'"code":1', b'"code":Infinity', 1))
        for value in malformed:
            with self.subTest(native_abort_strict_json=value[:70]), self.assertRaises(self.module._NativeAbortIssue) as caught:
                self.module._native_abort_ips_record(value, abort)
            self.assertEqual(caught.exception.status, "malformed")
        for value in (raw + b" " * self.module.MiB,
                      header + b'\n{"ignored":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"):
            with self.subTest(native_abort_bounded_json=len(value)), self.assertRaises(self.module._NativeAbortIssue) as caught:
                self.module._native_abort_ips_record(value, abort)
            self.assertEqual(caught.exception.status, "limit")
        decoder = Mock(side_effect=AssertionError("depth must be refused before the recursive JSON decoder"))
        with patch.object(self.module, "json", SimpleNamespace(loads=decoder, JSONDecodeError=json.JSONDecodeError)), \
             self.assertRaises(self.module._NativeAbortIssue) as caught:
            self.module._native_abort_json(b"[" * 65 + b"0" + b"]" * 65, maximum=self.module.MiB, depth=64, code="IPS_IO")
        self.assertEqual(caught.exception.status, "limit")
        decoder.assert_not_called()

        unknown = self.module._native_abort_ips_record(native_abort_ips_bytes(abort, body={
            "termination": {"namespace": "PRIVATE-DIAGNOSTIC-CANARY", "code": -1},
            "threads": [{"frames": [{"imageIndex": 0, "symbol": "PRIVATE-DIAGNOSTIC-CANARY"}]}],
            "usedImages": [{"path": "/Users/private-user/PRIVATE-DIAGNOSTIC-CANARY"}]}), abort)
        self.assertEqual((unknown["termination_namespace"], unknown["termination_code"], unknown["fault_image_role"], unknown["frame_roles"]),
                         ("OTHER", None, "other", []))
        self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", json.dumps(unknown))
        for changes in ({"faultingThread": True}, {"faultingThread": -1},
                        {"threads": [{"frames": [{"imageIndex": True}]}]},
                        {"threads": [{"frames": [{"imageIndex": -1}]}]}):
            observed = self.module._native_abort_ips_record(native_abort_ips_bytes(abort, body=changes), abort)
            self.assertEqual(observed["fault_image_role"], "absent")
        frames = [{"imageIndex": 0, "symbol": "abort"}] * 64 + [{"imageIndex": 0, "symbol": "Py_FatalError"}]
        observed = self.module._native_abort_ips_record(native_abort_ips_bytes(abort, body={"threads": [{"frames": frames}]}), abort)
        self.assertEqual(observed["frame_roles"], ["abort"])

    def test_native_abort_log_parser_matches_original_event_not_daemon_and_never_exports_private_text(self):
        session = session_double(self.module, "darwin")
        abort = native_abort_double(session)
        message = "Sandbox: python(4242) deny(1) file-read-data /dev/null"
        base = {"process": "kernel", "processImagePath": "/kernel", "processID": 0,
                "timestamp": "2026-09-10 08:40:01.250000+0000", "eventMessage": message,
                "PRIVATE_TOKEN": "PRIVATE-DIAGNOSTIC-CANARY"}
        expected = {"operation": "file-read-data", "resource_role": "stdio-device", "public_path": "/dev/null"}
        for additions in ({}, {"uid": session.uid}, {"userID": session.uid}, {"userIdentifier": session.uid},
                          {"uid": 0, "userID": 0, "userIdentifier": 0}, {"uid": session.uid + 1},
                          {"processID": 99999}, {"process": "sandboxd", "processImagePath": "/usr/libexec/sandboxd"}):
            with self.subTest(native_abort_log_identity=additions):
                self.assertEqual(self.module._native_abort_log_records(json.dumps([base | additions]).encode(), abort), [expected])
        self.assertEqual(self.module._native_abort_log_records(json.dumps([base, base]).encode(), abort), [expected])
        for changes in ({"process": "other"}, {"processImagePath": "/Users/private-user/kernel"},
                {"processImagePath": "/usr/libexec/sandboxd"},
                {"eventMessage": message.replace("(4242)", "(42421)"), "processID": 4242, "uid": session.uid},
                {"eventMessage": message.replace("(4242)", "(04242)")},
                {"eventMessage": message.replace("python(4242)", "other-python(4242)")},
                {"eventMessage": "unrelated prefix " + message}, {"eventMessage": message + "\n" + message},
                {"timestamp": "2026-09-10 08:40:03.000000+0000"},
                {"timestamp": "2026-09-10 08:40:00.000000+0000"}):
            with self.subTest(native_abort_unrelated_log=changes):
                self.assertEqual(self.module._native_abort_log_records(json.dumps([base | changes]).encode(), abort), [])
        unsupported = dict(base)
        unsupported.pop("process")
        unsupported.pop("processImagePath")
        unsupported["processName"] = "kernel"
        self.assertEqual(self.module._native_abort_log_records(json.dumps([unsupported]).encode(), abort), [])
        for resource, role in ((str(session.control / "denied"), "owned-control"),
                               (str(session.control) + "/../outside", "redacted"),
                               (str(session.control) + "-not-ours/denied", "redacted")):
            entry = base | {"eventMessage": f"Sandbox: python(4242) deny(1) file-read-data {resource}"}
            observed = self.module._native_abort_log_records(json.dumps([entry]).encode(), abort | {"control_root": str(session.control)})
            self.assertEqual(observed, [{"operation": "file-read-data", "resource_role": role}])

        operations = {"file-read-data", "file-read-metadata", "file-read-xattr", "file-write-data", "file-write-create",
                      "mach-lookup", "sysctl-read", "process-exec", "other"}
        resources = {"stdio-device", "admitted-python", "admitted-system-image", "owned-control", "public-os", "redacted"}
        public = {"/dev/null", "/dev/random", "/dev/urandom", "/dev/fd/0", "/dev/fd/1", "/dev/fd/2",
                  "/usr/lib/dyld", "/usr/bin/sandbox-exec", "/usr/lib/system/libsystem_secinit.dylib",
                  "/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_c.dylib", "/usr/lib/system/libdispatch.dylib"}
        for operation, resource in (("mach-lookup", "com.apple.PRIVATE-DIAGNOSTIC-CANARY"),
                ("file-read-data", "/Users/private-user/PRIVATE-DIAGNOSTIC-CANARY"),
                ("process-exec", str(session.python)), ("private-operation", "/Users/private-user/private"),
                ("file-read-metadata", "/usr/lib/dyld-extra"),
                *(("file-read-data", value) for value in sorted(public))):
            with self.subTest(native_abort_log_redaction=(operation, resource)):
                entry = base | {"eventMessage": f"Sandbox: python(4242) deny(1) {operation} {resource}"}
                observed = self.module._native_abort_log_records(json.dumps([entry]).encode(), abort)
                self.assertEqual(len(observed), 1)
                row = observed[0]
                self.assertEqual(set(row), {"operation", "resource_role", *(["public_path"] if resource in public else [])})
                self.assertEqual(row["operation"], operation if operation in operations else "other")
                self.assertIn(row["resource_role"], resources)
                if resource in public:
                    self.assertEqual(row["public_path"], resource)
                encoded = json.dumps(observed)
                self.assertLessEqual(len(encoded.encode()), 4096)
                for private in ("PRIVATE-DIAGNOSTIC-CANARY", "PRIVATE_TOKEN", "/Users/", str(session.python), str(session.root)):
                    self.assertNotIn(private, encoded)

        valid = json.dumps([base], separators=(",", ":")).encode()
        for value in (b"\xff", b"{}", valid + b"[]", valid[:-1], b'[null]',
                      valid.replace(b'"processID":0', b'"processID":0,"processID":0', 1),
                      valid.replace(b'"processID":0', b'"processID":NaN', 1)):
            with self.subTest(native_abort_strict_log_json=value[:70]), self.assertRaises(self.module._NativeAbortIssue) as caught:
                self.module._native_abort_log_records(value, abort)
            self.assertEqual(caught.exception.status, "malformed")
        for value in (json.dumps([base] * 65).encode(), b"[" * 33 + b"0" + b"]" * 33, valid + b" " * (2 * self.module.MiB)):
            with self.subTest(native_abort_bounded_log=len(value)), self.assertRaises(self.module._NativeAbortIssue) as caught:
                self.module._native_abort_log_records(value, abort)
            self.assertEqual(caught.exception.status, "limit")
        distinct = [base | {"eventMessage": f"Sandbox: python(4242) deny(1) {operation} /dev/null"}
                    for operation in sorted(operations)]
        observed = self.module._native_abort_log_records(json.dumps(distinct + distinct).encode(), abort)
        self.assertEqual(len(observed), 8)
        self.assertEqual(len({json.dumps(row, sort_keys=True) for row in observed}), 8)

    def test_native_abort_reads_and_scans_bound_and_close_only_original_readonly_resources(self):
        raw = b"synthetic bounded report bytes\n"
        wall = 1_789_029_600_000_000_000
        cases = ("valid", "float-birth", "atime-only", "admin-group-write", "bad-path", "expired", "cancelled", "named-stat-error", "fd-stat-error",
                 "subject-owner", "subject-group-write", "world-write", "hard-link", "raced-fifo", "inherited", "oversize", "aggregate", "grew", "short",
                 "renamed", "stale-birth", "future-mtime", "missing-birth", "read-error", "read-and-close-error", "close-error", "close-expired")
        for case in cases:
            with self.subTest(native_abort_read=case):
                session = session_double(self.module, "darwin")
                session.domain_finality = True
                session.fail("command exited -6")
                abort = native_abort_double(session)
                session.cancelled = case == "cancelled"
                if case == "aggregate":
                    abort["ips_bytes"] = 4 * self.module.MiB - len(raw) + 1
                clock, closed = SimpleNamespace(now=1.0 if case == "expired" else 0.0), []
                path = Path("nested/report.ips" if case == "bad-path" else "python_report.ips")
                before = SimpleNamespace(st_dev=7, st_ino=91, st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                    st_nlink=1, st_size=len(raw), st_mtime_ns=wall + 2_600_000_000, st_ctime_ns=wall + 2_600_000_000,
                    st_birthtime_ns=wall + 2_600_000_000, st_atime_ns=1)
                if case == "subject-owner":
                    before.st_uid = session.uid
                elif case in {"admin-group-write", "subject-group-write"}:
                    before.st_mode |= 0o020
                    before.st_gid = 80 if case == "admin-group-write" else session.gid
                elif case == "world-write":
                    before.st_mode |= 0o002
                elif case == "hard-link":
                    before.st_nlink = 2
                elif case == "oversize":
                    before.st_size += 1
                elif case == "stale-birth":
                    before.st_birthtime_ns = wall
                elif case == "future-mtime":
                    before.st_mtime_ns = wall + 4_000_000_000
                elif case in {"float-birth", "missing-birth"}:
                    del before.st_birthtime_ns
                    if case == "float-birth":
                        before.st_birthtime = (wall + 2_600_000_000) / 1_000_000_000
                named_calls, fd_calls = [], []
                data = io.BytesIO(raw + b"x" if case == "grew" else raw[:-1] if case == "short" else raw)

                def named(queried, *, dir_fd, follow_symlinks):
                    self.assertEqual((queried, dir_fd, follow_symlinks), (path, 501, False))
                    named_calls.append(queried)
                    if case == "named-stat-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    values = vars(before) | ({"st_ino": 92} if case == "renamed" and len(named_calls) > 1 else {})
                    return SimpleNamespace(**values)

                def descriptor(fd):
                    self.assertEqual(fd, 502)
                    fd_calls.append(fd)
                    if case == "fd-stat-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    values = vars(before) | ({"st_mode": stat.S_IFIFO | 0o600} if case == "raced-fifo" else {})
                    if case == "atime-only" and len(fd_calls) > 1:
                        values["st_atime_ns"] = 999
                    return SimpleNamespace(**values)

                def read(fd, count):
                    self.assertEqual(fd, 502)
                    self.assertTrue(0 < count <= 65536)
                    if case in {"read-error", "read-and-close-error"}:
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    return data.read(count)

                def close(fd):
                    self.assertEqual(fd, 502)  # Never the caller's directory FD501.
                    self.assertNotIn(fd, closed)
                    closed.append(fd)  # Simulate a close effect before a reported error.
                    if case in {"close-error", "read-and-close-error"}:
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    if case == "close-expired":
                        clock.now = 1.0

                opened, reader = Mock(return_value=502), Mock(side_effect=read)
                constants = {name: getattr(os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, open=opened, stat=named, fstat=descriptor,
                        read=reader, close=close, get_inheritable=lambda _fd: case == "inherited"),
                        time=SimpleNamespace(monotonic=lambda: clock.now, time_ns=lambda: wall + 3_000_000_000),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace()), \
                     patch.object(Path, "resolve", side_effect=AssertionError("relative diagnostic read cannot follow a host path")), \
                     patch.object(Path, "open", side_effect=AssertionError("diagnostic read owns only its fake original descriptor")):
                    if case in {"valid", "float-birth", "atime-only", "admin-group-write"}:
                        observed, identity = session._native_abort_read(abort, path, maximum=len(raw), directory_fd=501, fresh=True)
                        self.assertEqual((observed, identity), (raw, self.module._native_file_key(before)))
                    else:
                        with self.assertRaises(self.module._NativeAbortIssue) as caught:
                            session._native_abort_read(abort, path, maximum=len(raw), directory_fd=501, fresh=True)
                        if case in {"close-error", "read-and-close-error"}:
                            self.assertTrue(caught.exception.close_failed)
                            self.assertEqual(caught.exception.code, "IPS_CLOSE")
                            with self.assertRaises(self.module._NativeAbortIssue):
                                session._native_abort_read(abort, path, maximum=len(raw), directory_fd=501, fresh=True)
                        elif case in {"expired", "close-expired", "cancelled", "aggregate", "grew", "oversize"}:
                            self.assertEqual(caught.exception.status, "cancelled" if case == "cancelled" else
                                             "limit" if case in {"aggregate", "grew", "oversize"} else "deadline")
                acquired = case not in {"bad-path", "expired", "cancelled", "named-stat-error"}
                if acquired:
                    opened.assert_called_once_with(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=501)
                else:
                    opened.assert_not_called()
                self.assertEqual(closed, [502] if acquired else [])
                if case in {"raced-fifo", "fd-stat-error", "subject-owner", "subject-group-write", "world-write", "hard-link", "inherited", "oversize",
                            "stale-birth", "future-mtime", "missing-birth", "aggregate"} or not acquired:
                    reader.assert_not_called()
                self.assertTrue(session.domain_finality)
                self.assertFalse(session._direct_producer_pending)
                self.assertEqual(session.failure, "command exited -6")
                ambiguous_close = case in {"close-error", "read-and-close-error"}
                self.assertEqual((abort["close_failed"], len(session.cleanup_errors)), (ambiguous_close, int(ambiguous_close)))
                self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", repr(session.cleanup_errors) + repr(abort.get("diagnostic_error")))

        for case in ("valid-binding", "full-aggregate", "non-executable", "individual-bound", "aggregate-bound", "canonical-drift"):
            with self.subTest(native_abort_image_read=case):
                session = session_double(self.module, "darwin")
                abort = native_abort_double(session)
                image = b"synthetic executable image bytes\n"
                path = Path("/usr/bin/log")
                maximum = 16 * self.module.MiB
                node = SimpleNamespace(st_dev=7, st_ino=91, st_mode=stat.S_IFREG | (0o444 if case == "non-executable" else 0o555),
                    st_uid=0, st_gid=0, st_nlink=1, st_size=maximum + 1 if case == "individual-bound" else len(image),
                    st_mtime_ns=1, st_ctime_ns=2)
                abort["binding_bytes"] = 32 * self.module.MiB - len(image) + int(case == "aggregate-bound") if case in {
                    "full-aggregate", "aggregate-bound"} else 0
                data = io.BytesIO(image)
                opened, closed, reader = Mock(return_value=502), Mock(), Mock(side_effect=lambda fd, count: data.read(count))
                constants = {name: getattr(os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                named = Mock(return_value=node)
                with patch.multiple(self.module, os=SimpleNamespace(**constants, stat=named, open=opened, close=closed, read=reader,
                        fstat=Mock(return_value=node), get_inheritable=lambda fd: False), _canonical=Mock(
                            return_value=Path("/unadmitted/log") if case == "canonical-drift" else path),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace(),
                        time=SimpleNamespace(monotonic=lambda: 0.0)), \
                     patch.object(Path, "open", side_effect=AssertionError("image binding must use only an original fake descriptor")):
                    if case in {"valid-binding", "full-aggregate"}:
                        observed, identity = session._native_abort_read(abort, path, maximum=maximum)
                        self.assertEqual((observed, identity), (image, self.module._native_file_key(node)))
                        self.assertEqual(abort["binding_bytes"], len(image) if case == "valid-binding" else 32 * self.module.MiB)
                    else:
                        with self.assertRaises(self.module._NativeAbortIssue) as caught:
                            session._native_abort_read(abort, path, maximum=maximum)
                        self.assertEqual(caught.exception.status, "limit" if case in {"individual-bound", "aggregate-bound"} else "unavailable")
                self.assertEqual(abort["ips_bytes"], 0)  # Optional image bindings do not consume or enlarge the IPS budget.
                if case == "canonical-drift":
                    opened.assert_not_called()
                    closed.assert_not_called()
                    named.assert_not_called()
                else:
                    opened.assert_called_once_with(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=None)
                    closed.assert_called_once_with(502)
                if case not in {"valid-binding", "full-aggregate"}:
                    reader.assert_not_called()

        scan_cases = ("valid", "no-hint", "admin-group-write", "directory-time-only", "absent", "unrelated-name", "arrived",
            "incomplete-arrived", "incomplete-twice", "contradicted", "malformed", "multiple", "matched-and-malformed",
            "entries-limit", "candidates-limit", "byte-limit", "subject-owner", "subject-group-write", "world-write",
            "directory-fifo", "directory-name-drift", "directory-mode-drift", "directory-absent", "directory-stat-error",
            "directory-fstat-error", "inherited-directory", "iterator-error", "iterator-close-error", "directory-close-error",
            "file-iterator-directory-close-errors", "sleep-expired", "sleep-cancelled")
        for case in scan_cases:
            with self.subTest(native_abort_scan=case):
                session = session_double(self.module, "darwin")
                session.domain_finality = True
                session.fail("command exited -6")
                abort = native_abort_double(session, deadline=5.0)
                directory = Path("/Library/Logs/DiagnosticReports")
                clock = SimpleNamespace(now=0.0)
                events, passes, named_calls, original_iterators = [], [], [], []
                record_bytes = native_abort_ips_bytes(abort)
                node = SimpleNamespace(st_dev=7, st_ino=91, st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
                if case == "subject-owner":
                    node.st_uid = session.uid
                elif case in {"admin-group-write", "subject-group-write"}:
                    node.st_mode |= 0o020
                    node.st_gid = 80 if case == "admin-group-write" else session.gid
                elif case == "world-write":
                    node.st_mode |= 0o002
                elif case == "directory-fifo":
                    node.st_mode = stat.S_IFIFO | 0o755
                file_node = SimpleNamespace(st_dev=7, st_ino=92, st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                    st_nlink=1, st_size=len(record_bytes), st_mtime_ns=wall + 2_600_000_000,
                    st_ctime_ns=wall + 2_600_000_000, st_birthtime_ns=wall + 2_600_000_000)
                file_data = io.BytesIO(record_bytes)

                def named(queried, *, follow_symlinks, dir_fd=None):
                    self.assertFalse(follow_symlinks)
                    if dir_fd is not None:
                        self.assertEqual((queried, dir_fd), (Path("python_0.ips"), 501))
                        self.assertEqual(case, "file-iterator-directory-close-errors")
                        return SimpleNamespace(**vars(file_node))
                    self.assertEqual(queried, directory)
                    named_calls.append(queried)
                    if case == "directory-absent":
                        raise FileNotFoundError(errno.ENOENT, "PRIVATE-DIAGNOSTIC-CANARY")
                    if case == "directory-stat-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    change = {"st_mtime_ns": len(named_calls), "st_ctime_ns": len(named_calls)}
                    if len(named_calls) > 1 and case == "directory-name-drift":
                        change["st_ino"] = 99
                    if len(named_calls) > 1 and case == "directory-mode-drift":
                        change["st_mode"] = stat.S_IFDIR | 0o750
                    return SimpleNamespace(**(vars(node) | change))

                def opened(queried, flags, *, dir_fd=None):
                    if dir_fd is not None:
                        self.assertEqual((queried, dir_fd, flags), (Path("python_0.ips"), 501,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC))
                        events.append(("file-open", 502))
                        return 502
                    self.assertEqual((queried, flags), (directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
                    passes.append(len(passes) + 1)
                    events.append(("directory-open", passes[-1]))
                    return 501

                def descriptor(fd):
                    if fd == 502:
                        self.assertEqual(case, "file-iterator-directory-close-errors")
                        return SimpleNamespace(**vars(file_node))
                    self.assertEqual(fd, 501)
                    if case == "directory-fstat-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    return SimpleNamespace(**vars(node))

                def close(fd):
                    self.assertIn(fd, (501, 502))
                    event = ("descriptor-close", passes[-1], fd)
                    self.assertNotIn(event, events)
                    events.append(event)  # Original resource retired even if close reports an error after effect.
                    if case == "file-iterator-directory-close-errors" or case == "directory-close-error" and fd == 501:
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")

                def scandir(fd):
                    self.assertEqual(fd, 501)
                    self.assertEqual(len(original_iterators) + 1, len(passes))
                    names = ["python_0.ips"]
                    if case in {"absent", "sleep-expired", "sleep-cancelled"} or case == "arrived" and len(passes) == 1:
                        names = []
                    elif case == "unrelated-name":
                        names = ["other_report.ips", "pythonish_report.ips", "python_report.txt"]
                    elif case == "entries-limit":
                        names = ["ignored.txt"] * 257
                    elif case == "candidates-limit":
                        names = [f"python_{index}.ips" for index in range(9)]
                    elif case in {"multiple", "matched-and-malformed"}:
                        names = ["python_0.ips", "python_1.ips"]
                    owner, entries = self, iter(names)

                    class OriginalIterator:
                        def __init__(self):
                            self.number, self.next_calls, self.closed = len(passes), 0, False

                        def __next__(self):
                            owner.assertFalse(self.closed)
                            self.next_calls += 1
                            owner.assertLessEqual(self.next_calls, 256)
                            if case == "iterator-error":
                                raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                            return SimpleNamespace(name=next(entries))

                        def close(self):
                            owner.assertFalse(self.closed)
                            self.closed = True
                            events.append(("iterator-close", self.number))
                            if case in {"iterator-close-error", "file-iterator-directory-close-errors"}:
                                raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")

                    iterator = OriginalIterator()
                    original_iterators.append(iterator)  # Independent original handle, not the caller's descriptor501.
                    return iterator

                def read_report(actual, queried, *, maximum, directory_fd, fresh):
                    self.assertIs(actual, abort)
                    self.assertEqual((maximum, directory_fd, fresh), (self.module.MiB, 501, True))
                    self.assertEqual(len(queried.parts), 1)
                    if case == "byte-limit":
                        raise self.module._NativeAbortIssue("limit", "LIMIT")
                    if case in {"contradicted", "candidates-limit"}:
                        return native_abort_ips_bytes(abort, body={"pid": 4243}), ()
                    if case == "malformed" or case == "matched-and-malformed" and queried.name == "python_1.ips":
                        return b'{"bug_type":"309"}\n[]', ()
                    if case == "incomplete-twice" or case == "incomplete-arrived" and len(passes) == 1:
                        return record_bytes[:-2], ()
                    if case == "no-hint":
                        return native_abort_ips_bytes(abort, body={"termination": {}, "threads": []}), ()
                    return record_bytes, ()

                def sleep(seconds):
                    self.assertTrue(0 < seconds <= 1.0)
                    events.append(("sleep", seconds))
                    self.assertEqual(sum(event[0] == "sleep" for event in events), 1)
                    clock.now = abort["deadline"] if case == "sleep-expired" else clock.now + seconds
                    session.cancelled = case == "sleep-cancelled"

                constants = {name: getattr(os, name) for name in ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                fake_reader = Mock(side_effect=read_report)
                with ExitStack() as stack:
                    stack.enter_context(patch.multiple(self.module,
                        os=SimpleNamespace(**constants, stat=named, open=opened, fstat=descriptor, close=close, scandir=scandir,
                            read=lambda fd, count: file_data.read(count) if fd == 502 else self.fail("unexpected original read descriptor"),
                            get_inheritable=lambda _fd: case == "inherited-directory"),
                        time=SimpleNamespace(monotonic=lambda: clock.now, time_ns=lambda: wall + 3_000_000_000, sleep=sleep),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace()))
                    stack.enter_context(patch.object(Path, "resolve", side_effect=AssertionError("diagnostic scan cannot resolve host paths")))
                    stack.enter_context(patch.object(Path, "open", side_effect=AssertionError("diagnostic scan may use only original fake descriptors")))
                    if case != "file-iterator-directory-close-errors":
                        stack.enter_context(patch.object(session, "_native_abort_read", fake_reader))
                    expected = {"valid": "matched", "admin-group-write": "matched", "directory-time-only": "matched",
                        "no-hint": "matched-no-hint", "arrived": "matched", "incomplete-arrived": "matched",
                        "absent": "absent", "unrelated-name": "absent", "directory-absent": "absent",
                        "incomplete-twice": "malformed", "contradicted": "unavailable", "malformed": "malformed",
                        "multiple": "ambiguous", "matched-and-malformed": "ambiguous"}
                    if case in expected:
                        status, record = session._native_abort_ips(abort)
                        self.assertEqual(status, expected[case])
                        self.assertEqual(record is not None, status in {"matched", "matched-no-hint"})
                    else:
                        with self.assertRaises(self.module._NativeAbortIssue) as caught:
                            session._native_abort_ips(abort)
                        self.assertEqual(caught.exception.status, "limit" if case in {"entries-limit", "candidates-limit", "byte-limit"}
                            else "deadline" if case == "sleep-expired" else "cancelled" if case == "sleep-cancelled" else "unavailable")
                retry_cases = {"absent", "unrelated-name", "arrived", "incomplete-arrived", "incomplete-twice", "directory-absent",
                               "sleep-expired", "sleep-cancelled"}
                self.assertEqual(sum(event[0] == "sleep" for event in events), int(case in retry_cases))
                expected_passes = 0 if case in {"directory-absent", "directory-stat-error"} else 2 if case in retry_cases - {
                    "sleep-expired", "sleep-cancelled"} else 1
                self.assertEqual(len(passes), expected_passes)
                self.assertEqual(sum(event[0] == "descriptor-close" and event[2] == 501 for event in events), expected_passes)
                for iterator in original_iterators:
                    self.assertTrue(iterator.closed)
                    self.assertLess(events.index(("iterator-close", iterator.number)),
                                    events.index(("descriptor-close", iterator.number, 501)))
                if case == "entries-limit":
                    self.assertEqual(original_iterators[0].next_calls, 256)
                    fake_reader.assert_not_called()
                if case == "candidates-limit":
                    self.assertEqual((abort["candidates"], fake_reader.call_count), (8, 8))
                close_count = 3 if case == "file-iterator-directory-close-errors" else int(case in {"iterator-close-error", "directory-close-error"})
                self.assertEqual((abort["close_failed"], len(session.cleanup_errors)), (bool(close_count), close_count))
                if close_count:
                    self.assertNotIn("sleep", [event[0] for event in events])
                    self.assertEqual(abort["diagnostic_error"]["code"], "IPS_CLOSE")
                self.assertTrue(session.domain_finality)
                self.assertFalse(session._direct_producer_pending)
                self.assertEqual(session.failure, "command exited -6")
                self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", repr(session.cleanup_errors) + repr(abort.get("diagnostic_error")))

    def test_native_abort_binding_and_fixed_log_collector_never_renew_clocks_or_release_ambiguous_producers(self):
        framework = Path("/fixture-tools/python/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/Contents/MacOS/Python")
        image = b"synthetic admitted parent image, not an executable fixture\n"
        for case in ("framework", "canonical-framework", "selected", "relative", "absent", "foreign-provider", "ambiguous-provider",
                     "missing", "read-error", "read-limit", "readonly-close-error", "binding-expired", "gate-shorter", "session-shorter"):
            with self.subTest(native_abort_private_binding=case):
                session = session_double(self.module, "darwin")
                session.domain_finality = True
                session.deadline = 26.0 if case == "session-shorter" else 100.0
                state = native_state_double(session, deadline=25.0 if case == "gate-shorter" else 50.0)
                state["files"] = {Path("/fixed/immutable-input"): {"sha256": "0" * 64}}
                state["tools"] = {"synthetic-fixed-role": {"sha256": "1" * 64}}
                original_files, original_tools = repr(state["files"]), repr(state["tools"])
                original_policy = state["policy"]
                if case == "ambiguous-provider":
                    session.tool_prefixes = (*session.tool_prefixes, Path("/fixture-tools"))
                origin = [] if case == "absent" else ["relative-python"] if case == "relative" else [
                    str(session.python) if case == "selected" else "/fixture-launch/Python" if case == "canonical-framework" else
                    "/fixture-tools/ruby/Python" if case == "foreign-provider" else str(framework)]
                canonical = session.python if case == "selected" else Path(origin[0]) if case == "foreign-provider" else framework
                clock = SimpleNamespace(now=20.0)

                def read(abort, path, *, maximum):
                    self.assertEqual((path, maximum), (framework, 16 * self.module.MiB))
                    self.assertEqual(abort["deadline"], min(state["deadline"], session.deadline, 30.0))
                    self.assertEqual((state["files"], state["tools"]),
                        ({Path("/fixed/immutable-input"): {"sha256": "0" * 64}}, {"synthetic-fixed-role": {"sha256": "1" * 64}}))
                    if case == "binding-expired":
                        clock.now = abort["deadline"]
                        session._native_abort_guard(abort)
                    if case == "read-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    if case == "read-limit":
                        raise self.module._NativeAbortIssue("limit", "LIMIT")
                    if case == "readonly-close-error":
                        abort["close_failed"] = True
                        raise self.module._NativeAbortIssue("unavailable", "IPS_CLOSE", close_failed=True)
                    return image, ("private-original-image-identity",)

                resolver = Mock(return_value=canonical,
                    side_effect=FileNotFoundError(errno.ENOENT, "PRIVATE-DIAGNOSTIC-CANARY") if case == "missing" else None)
                reader = Mock(side_effect=read)
                with patch.multiple(self.module, sys=SimpleNamespace(orig_argv=origin), os=SimpleNamespace(),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace(),
                        time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", resolver), \
                     patch.object(Path, "open", side_effect=AssertionError("private image fixture may not open host files")), \
                     patch.object(session, "_native_abort_read", reader):
                    abort = session._native_abort_prepare(state)
                self.assertEqual(abort["deadline"], min(state["deadline"], session.deadline, 30.0))
                self.assertEqual((state["deadline"], session.deadline),
                    (25.0 if case == "gate-shorter" else 50.0, 26.0 if case == "session-shorter" else 100.0))
                accepted = case in {"framework", "canonical-framework", "gate-shorter", "session-shorter"}
                self.assertEqual(abort["images"], {str(session.python): "python-selected", "/usr/bin/sandbox-exec": "sandbox-exec"}
                    | ({str(framework): "python-framework"} if accepted else {}))
                self.assertEqual(abort["bindings"], {str(framework): {"identity": ("private-original-image-identity",),
                    "sha256": hashlib.sha256(image).hexdigest()}} if accepted else {})
                self.assertEqual((repr(state["files"]), repr(state["tools"]), state["policy"]),
                                 (original_files, original_tools, original_policy))
                if case in {"absent", "relative", "ambiguous-provider"}:
                    resolver.assert_not_called()
                else:
                    resolver.assert_called_once_with(strict=True)
                self.assertEqual(reader.call_count, int(case not in {"selected", "relative", "absent", "foreign-provider", "ambiguous-provider", "missing"}))
                self.assertEqual((abort.get("disabled"), session._direct_producer_pending, session.domain_finality),
                    ("deadline" if case == "binding-expired" else "unavailable" if case == "readonly-close-error" else None, False, True))
                self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", repr(abort.get("diagnostic_error")))

        for case in ("valid", "five-second-cap", "no-record", "malformed", "record-limit", "reader-error", "readonly-close-error", "stat-error",
                     "identity-drift", "expired-before", "expired-binding", "expired-return", "cancelled-before", "cancelled-return",
                     "collector-error", "successful-observation-but-raised", "collector-interrupt"):
            with self.subTest(native_abort_root_collector=case):
                session = session_double(self.module, "darwin")
                session.domain_finality = True
                session.fail("command exited -6")
                abort = native_abort_double(session, deadline=10.0 if case == "five-second-cap" else 4.0)
                session.cancelled = case == "cancelled-before"
                clock = SimpleNamespace(now=4.0 if case == "expired-before" else 0.0)
                tool = Path("/usr/bin/log")
                node = SimpleNamespace(st_dev=7, st_ino=91, st_mode=stat.S_IFREG | 0o555, st_uid=0, st_gid=0, st_nlink=1,
                    st_size=len(image), st_mtime_ns=1, st_ctime_ns=2)
                identity = self.module._native_file_key(node)
                record = {"process": "sandboxd", "processImagePath": "/usr/libexec/sandboxd", "processID": 27, "uid": 0,
                    "timestamp": "2026-09-10 08:40:01.250000+0000",
                    "eventMessage": "Sandbox: python(4242) deny(1) file-read-data /dev/null",
                    "environment": "PRIVATE-DIAGNOSTIC-CANARY"}
                raw = b"[]" if case == "no-record" else b"not JSON" if case == "malformed" else json.dumps(
                    [record] * (65 if case == "record-limit" else 1)).encode()
                original = KeyboardInterrupt("PRIVATE-DIAGNOSTIC-CANARY") if case == "collector-interrupt" else ExceptionGroup(
                    "PRIVATE-DIAGNOSTIC-CANARY", [OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")])
                if case == "successful-observation-but-raised":
                    original._ci_observation = {"returncode": 0, "waited": True, "stdout_eof": True, "stderr_eof": True,
                                               "stdout_bytes": len(raw), "stderr_bytes": 0, "error_count": 1}

                def read(actual, path, *, maximum):
                    self.assertIs(actual, abort)
                    self.assertEqual((path, maximum), (tool, 16 * self.module.MiB))
                    self.assertFalse(session._direct_producer_pending)
                    if case == "reader-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    if case == "readonly-close-error":
                        abort["close_failed"] = True
                        raise self.module._NativeAbortIssue("unavailable", "IPS_CLOSE", close_failed=True)
                    if case == "expired-binding":
                        clock.now = abort["deadline"]
                    return image, identity

                def named(path, *, follow_symlinks):
                    self.assertEqual((path, follow_symlinks), (tool, False))
                    if case == "stat-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    return SimpleNamespace(**(vars(node) | ({"st_ino": 92} if case == "identity-drift" else {})))

                def collect(argv, *, seconds, deadline):
                    self.assertEqual(argv, ["/usr/bin/log", "show", "--style", "json", "--start", "2026-09-10 08:40:00+0000",
                        "--end", "2026-09-10 08:40:03+0000", "--timezone", "UTC", "--no-pager", "--predicate",
                        '(process == "kernel" OR process == "sandboxd") AND eventMessage CONTAINS "(4242)"'])
                    self.assertEqual((seconds, deadline), (min(5.0, abort["deadline"]), abort["deadline"]))
                    self.assertTrue(session._direct_producer_pending)  # Custody is published BEFORE entering root collector.
                    self.assertFalse(session.domain_finality)
                    self.assertEqual(session.failure, "command exited -6")
                    if case in {"collector-error", "successful-observation-but-raised", "collector-interrupt"}:
                        raise original
                    if case == "expired-return":
                        clock.now = abort["deadline"]
                    if case == "cancelled-return":
                        session.cancelled = True
                    return raw

                collector, reader, domain = Mock(side_effect=collect), Mock(side_effect=read), Mock(return_value={})
                with patch.multiple(self.module, os=SimpleNamespace(stat=named), subprocess=SimpleNamespace(),
                        socket=SimpleNamespace(), signal=SimpleNamespace(), resource=SimpleNamespace(), _small_command=collector,
                        _domain=domain, time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(session, "_native_abort_read", reader), \
                     patch.object(Path, "open", side_effect=AssertionError("collector fixture cannot open host files")), \
                     patch.object(Path, "resolve", side_effect=AssertionError("bound collector fixture cannot resolve host paths")):
                    result = session._native_abort_log(abort)
                    pending = case in {"collector-error", "successful-observation-but-raised", "collector-interrupt"}
                    invoked = case in {"valid", "five-second-cap", "no-record", "malformed", "record-limit", "expired-return", "cancelled-return"} or pending
                    expected_status = "collector-error" if pending else {
                        "valid": "matched-denial", "five-second-cap": "matched-denial", "no-record": "no-record", "malformed": "malformed", "record-limit": "limit",
                        "expired-before": "deadline", "expired-binding": "deadline", "expired-return": "deadline",
                        "cancelled-before": "cancelled", "cancelled-return": "cancelled"}.get(case, "unavailable")
                    self.assertEqual(result["log_status"], expected_status)
                    self.assertEqual(collector.call_count, int(invoked))
                    self.assertEqual((session._direct_producer_pending, session.domain_finality), (pending, not invoked))
                    self.assertEqual(result.get("log_sha256"), hashlib.sha256(raw).hexdigest() if invoked and not pending else None)
                    if case in {"valid", "five-second-cap"}:
                        self.assertEqual(result["denials"], [{"operation": "file-read-data", "resource_role": "stdio-device", "public_path": "/dev/null"}])
                    reads_before, calls_before = reader.call_count, collector.call_count
                    self.assertEqual(session._native_abort_log(abort), {"log_status": "unavailable"})
                    self.assertEqual((reader.call_count, collector.call_count), (reads_before, calls_before))
                    if pending:
                        self.assertEqual(abort["diagnostic_error"], {"code": "LOG_COLLECTOR", "producer_pending": True})
                        self.assertIn("native abort diagnostic metadata collector did not release custody", session.cleanup_errors)
                        with self.assertRaises(self.module.SessionError):
                            session.ensure_idle()
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                        self.assertTrue(session.closed)
                        self.assertTrue(session._direct_producer_pending)
                        self.assertFalse(session.domain_finality)
                        self.assertIn("close did not establish reserved-identity finality", session.cleanup_errors)
                    domain.assert_not_called()  # Neither a receipt nor an empty census can retire an uncertain root producer.
                self.assertEqual((session.failure, session.deadline, abort["deadline"]),
                                 ("command exited -6", 100.0, 10.0 if case == "five-second-cap" else 4.0))
                self.assertNotIn("PRIVATE-DIAGNOSTIC-CANARY", json.dumps(result) + repr(session.cleanup_errors) + repr(abort.get("diagnostic_error")))
                if case == "successful-observation-but-raised":
                    self.assertEqual(original._ci_observation["returncode"], 0)
                    self.assertTrue(original._ci_observation["waited"] and original._ci_observation["stdout_eof"] and original._ci_observation["stderr_eof"])

    def test_native_abort_attachment_and_original_capture_keep_failure_custody_and_each_original_deadline(self):
        session = session_double(self.module, "darwin")
        template_abort = native_abort_double(session)
        template = self.module.CapturedRun(b"", self.module._NATIVE_WRITE_OUTER, -6, True, True, True, True,
            False, False, 0.15, "command exited -6", (), (0, len(self.module._NATIVE_WRITE_OUTER)))
        ips_record = self.module._native_abort_ips_record(native_abort_ips_bytes(template_abort), template_abort)
        for field, changed in (("platform", "linux"), ("phase", "wheel"), ("case", "outside-read-positive"), ("attempted", True),
                ("returncode", -9), ("returncode", 0), ("waited", False), ("stdout_eof", False), ("stderr_eof", False),
                ("domain_finality", False), ("timed_out", True), ("cancelled", True),
                ("stderr", self.module._NATIVE_WRITE_STDERR), ("stderr", b"")):
            with self.subTest(native_abort_ineligible=(field, changed)):
                session = session_double(self.module, "darwin")
                session.platform = changed if field == "platform" else "darwin"
                session.fail("command exited -6")
                abort = native_abort_double(session)
                if field in {"phase", "case", "attempted"}:
                    abort[field] = changed
                result = dataclasses.replace(template, **{field: changed}) if field not in {"platform", "phase", "case", "attempted"} else template
                ips, log = Mock(side_effect=AssertionError("ineligible capture must not scan")), Mock(side_effect=AssertionError("ineligible capture must not collect"))
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(SIGABRT=6), resource=SimpleNamespace(),
                        time=SimpleNamespace(monotonic=Mock(side_effect=AssertionError("ineligible capture has no new cutoff")))), \
                     patch.object(session, "_native_abort_ips", ips), patch.object(session, "_native_abort_log", log):
                    self.assertIsNone(session._native_abort_attach(abort, result))
                self.assertEqual(abort["attempted"], field == "attempted")
                ips.assert_not_called()
                log.assert_not_called()

        for case in ("matched", "matched-no-hint", "absent", "malformed", "io-error", "readonly-close-error", "expired-before",
                     "expired-after-scan", "cancelled-before", "cancelled-after-scan", "bad-clock", "attachment-limit"):
            with self.subTest(native_abort_failure_attachment=case):
                session = session_double(self.module, "darwin")
                session.fail("command exited -6")
                session.domain_finality = True
                session.persisted_bytes = sum(template.persisted)
                abort = native_abort_double(session)
                if case == "bad-clock":
                    abort["wall_after"] = abort["wall_before"] - 1
                session.cancelled = case == "cancelled-before"
                clock = SimpleNamespace(now=1.0 if case == "expired-before" else 0.0)

                def scan(actual):
                    self.assertIs(actual, abort)
                    if case == "io-error":
                        raise OSError(errno.EIO, "PRIVATE-DIAGNOSTIC-CANARY")
                    if case == "readonly-close-error":
                        abort["close_failed"] = True
                        raise self.module._NativeAbortIssue("unavailable", "IPS_CLOSE", close_failed=True, number=errno.EIO)
                    if case == "expired-after-scan":
                        clock.now = abort["deadline"]
                    if case == "cancelled-after-scan":
                        session.cancelled = True
                    if case in {"matched", "expired-after-scan", "cancelled-after-scan", "attachment-limit"}:
                        return "matched", ips_record | ({"frame_roles": ["abort"] * 1024} if case == "attachment-limit" else {})
                    return case, ips_record if case == "matched-no-hint" else None

                log_result = {"log_status": "matched-denial", "log_sha256": "a" * 64,
                    "denials": [{"operation": "file-read-data", "resource_role": "stdio-device", "public_path": "/dev/null"}]}
                ips, log = Mock(side_effect=scan), Mock(return_value=log_result)
                with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(SIGABRT=6), resource=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(session, "_native_abort_ips", ips), patch.object(session, "_native_abort_log", log):
                    attached = session._native_abort_attach(abort, template)
                    self.assertIsNone(session._native_abort_attach(abort, template))
                self.assertTrue(abort["attempted"])
                self.assertEqual(ips.call_count, int(case not in {"expired-before", "cancelled-before", "bad-clock"}))
                self.assertEqual(log.call_count, int(case in {"matched-no-hint", "absent", "malformed", "io-error", "bad-clock"}))
                expected_status = "limit" if case == "attachment-limit" else "deadline" if case.startswith("expired-") else (
                    "cancelled" if case.startswith("cancelled-") else "unavailable" if case in {"io-error", "readonly-close-error", "bad-clock"} else case)
                self.assertEqual(attached["ips_status"], expected_status)
                if case == "matched":
                    self.assertEqual(attached["log_status"], "not-needed")
                    self.assertEqual(attached["ips"], ips_record)
                if case == "attachment-limit":
                    self.assertEqual(attached, {"schema": 1, "subject": "source-outside-write-positive", "ips_status": "limit",
                        "log_status": "limit", "diagnostic_error": {"code": "LIMIT", "producer_pending": False}})
                self.assertLessEqual(set(attached), {"schema", "subject", "ips_status", "ips", "log_status", "log_sha256", "denials", "diagnostic_error"})
                self.assertEqual((attached["schema"], attached["subject"]), (1, "source-outside-write-positive"))
                serialized = json.dumps(attached, separators=(",", ":"), allow_nan=False)
                self.assertLessEqual(len(serialized.encode()), 4096)
                for private in ("PRIVATE-DIAGNOSTIC-CANARY", "/Users/", "PRIVATE_TOKEN", str(session.root), str(session.python)):
                    self.assertNotIn(private, serialized)
                self.assertEqual((session.failure, session.persisted_bytes, session.domain_finality, session._direct_producer_pending),
                    ("command exited -6", sum(template.persisted), True, False))
                self.assertEqual((template.returncode, template.waited, template.stdout_eof, template.stderr_eof,
                    template.domain_finality, template.timed_out, template.cancelled, template.duration, template.primary_error,
                    template.stdout, template.stderr, template.persisted),
                    (-6, True, True, True, True, False, False, 0.15, "command exited -6", b"", self.module._NATIVE_WRITE_OUTER,
                     (0, len(self.module._NATIVE_WRITE_OUTER))))

        # Real original control/capture/note/attachment integration. Only effect
        # providers are doubled; no replay, probe or native process is invoked.
        for case in ("attached", "diagnostic-expired-before-capture", "diagnostic-expired-during-capture", "held-eof", "original-timeout"):
            with self.subTest(native_abort_original_lifecycle=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session, deadline=50.0)
                state["prepared"], session._native_preparing = False, "source"
                rig = _Collection(self.module, session, stdout=(), stderr=(self.module._NATIVE_WRITE_OUTER,))
                rig.exitcode, rig.snapshot_rows = -6, {}
                if case == "held-eof":
                    rig.hold = {1}
                original_prepare, original_stamp = session._native_abort_prepare, session._native_abort_stamp
                originals, stamps, observed_cutoffs = [], [], []

                def prepare(actual):
                    self.assertIs(actual, state)
                    abort = original_prepare(actual)
                    originals.append(abort)
                    if case in {"diagnostic-expired-before-capture", "held-eof", "original-timeout"}:
                        rig.now = abort["deadline"] + 0.1
                    elif case == "diagnostic-expired-during-capture":
                        rig.now = abort["deadline"] - 0.05
                    rig.exit_at = rig.now + (50.0 if case == "original-timeout" else 0.08)
                    return abort

                def stamp(actual, key):
                    self.assertIs(actual, originals[0])
                    stamps.append((key, rig.now, session._active, session.failure))
                    rig.events.append(("abort-stamp", key))
                    if key == "wall_after":
                        self.assertIs(session._active, rig.child)  # Original custody precedes optional wall metadata.
                    if key == "wall_wait":
                        self.assertEqual(session.failure, "command/original aggregate deadline expired" if case == "original-timeout" else "command exited -6")
                    return original_stamp(actual, key)

                def credentials(pid, uid, gid, *, deadline):
                    self.assertEqual((pid, uid, gid), (rig.child.pid, session.uid, session.gid))
                    self.assertIs(session._active, rig.child)
                    observed_cutoffs.append(deadline)

                ips = Mock(return_value=("matched", ips_record))
                log = Mock(side_effect=AssertionError("expired or sufficient attachment must not invoke any collector"))
                command = [str(session.python), "-I", "-S", "-B", str(session.entry), "--native-write-control", str(state["outside_write"])]
                with rig.scope(), \
                     patch.multiple(self.module, signal=SimpleNamespace(SIGABRT=6), sys=SimpleNamespace(orig_argv=[]),
                                    _observe_original_credentials=credentials, socket=SimpleNamespace(), resource=SimpleNamespace()), \
                     patch.object(Path, "resolve", side_effect=AssertionError("fake native control cannot resolve host paths")), \
                     patch.object(session, "_native_check_inputs", Mock()), \
                     patch.object(session, "_native_abort_prepare", side_effect=prepare), \
                     patch.object(session, "_native_abort_stamp", side_effect=stamp), \
                     patch.object(session, "_native_abort_ips", ips), patch.object(session, "_native_abort_log", log):
                    result = session._native_control_capture(state, "outside-write-positive", command,
                        policy=session.bootstrap / "native-write-positive-source.sb", cwd=state["cwd"], seconds=10)
                self.assertEqual(len(originals), 1)
                abort = originals[0]
                self.assertEqual([row[0] for row in stamps], ["wall_before", "wall_after", "wall_wait"])
                self.assertEqual(abort["pid"], rig.child.pid)
                self.assertTrue(all(type(abort[key]) is int for key in ("wall_before", "wall_after", "wall_wait")))
                self.assertLessEqual(abort["wall_before"], abort["wall_after"])
                self.assertLessEqual(abort["wall_after"], abort["wall_wait"])
                self.assertEqual(sum(event[0] == "popen" for event in rig.events), 1)
                self.assertEqual(sum(event[0] == "wait-original" for event in rig.events), 1)
                before_index = rig.events.index(("abort-stamp", "wall_before"))
                after_index = rig.events.index(("abort-stamp", "wall_after"))
                spawn_index = next(i for i, event in enumerate(rig.events) if event[0] == "popen")
                self.assertLess(before_index, spawn_index)
                self.assertLess(spawn_index, after_index)
                self.assertEqual(len(observed_cutoffs), 1)
                original_cutoff = observed_cutoffs[0]
                self.assertGreater(original_cutoff, abort["deadline"])
                if case != "attached":
                    self.assertGreater(original_cutoff, abort["deadline"] + 9)
                self.assertAlmostEqual(original_cutoff - stamps[0][1], 10.0, delta=0.005)
                cleanup_cutoffs = [event[1] for event in rig.events if event[0] == "cleanup-deadline"]
                self.assertEqual(len(cleanup_cutoffs), 1)
                self.assertAlmostEqual(cleanup_cutoffs[0] - stamps[-1][1], 8.0, delta=0.1)
                self.assertLessEqual(cleanup_cutoffs[0], state["deadline"])
                self.assertEqual((state["deadline"], session.deadline), (50.0, 100.0))
                self.assertTrue(result.waited and result.stdout_eof)
                self.assertEqual(result.domain_finality, case != "held-eof")
                self.assertEqual(result.stderr_eof, case != "held-eof")
                self.assertEqual((result.timed_out, result.cancelled), (case == "original-timeout", False))
                self.assertEqual((result.returncode, result.primary_error), (-15, "command/original aggregate deadline expired")
                    if case == "original-timeout" else (-6, "command exited -6"))
                self.assertEqual((result.stdout, result.stderr, result.persisted, session.persisted_bytes),
                    (b"", self.module._NATIVE_WRITE_OUTER, (0, len(self.module._NATIVE_WRITE_OUTER)), len(self.module._NATIVE_WRITE_OUTER)))
                self.assertEqual((bytes(rig.captures[100]), bytes(rig.captures[101])), (b"", self.module._NATIVE_WRITE_OUTER))
                self.assertFalse(result.ok)
                self.assertEqual(session.failure, result.primary_error)
                self.assertIsNone(session._native_control)
                self.assertIsNone(session._active)
                self.assertFalse(session._busy or session._direct_producer_pending)
                row = state["control_notes"]["outside-write-positive"]
                self.assertFalse(row["ok"] or row["subject_ok"])
                self.assertEqual(row["native_write_startup"], "outer")
                self.assertEqual(row["persisted"], list(result.persisted))
                attachment = row.get("native_abort_diagnostic")
                if case in {"held-eof", "original-timeout"}:
                    self.assertIsNone(attachment)
                    self.assertFalse(abort["attempted"])
                else:
                    self.assertEqual(attachment["ips_status"], "matched" if case == "attached" else "deadline")
                    self.assertEqual(attachment["log_status"], "not-needed" if case == "attached" else "deadline")
                    self.assertTrue(abort["attempted"])
                self.assertEqual(ips.call_count, int(case == "attached"))
                log.assert_not_called()

        # The newly added optional wall snapshot is a fallible pre-spawn seam.
        # Only the ORIGINAL command cutoff/cancellation/failure may veto the
        # subject here; diagnostic-only expiry is separately covered above.
        for case in ("wall-interrupt", "wall-cancellation", "wall-first-failure", "original-cutoff", "wall-interrupt-close-error"):
            with self.subTest(native_abort_pre_spawn=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session, deadline=50.0)
                state["prepared"], session._native_preparing = False, "source"
                rig = _Collection(self.module, session, stdout=(), stderr=())
                if case == "wall-interrupt-close-error":
                    rig.fd_close_errors = {0}
                original_prepare = session._native_abort_prepare
                originals = []

                def prepare(actual):
                    self.assertIs(actual, state)
                    abort = original_prepare(actual)
                    originals.append(abort)
                    return abort

                def wall_snapshot():
                    self.assertEqual(len(rig.opened), 2)  # Original capture files are already owned.
                    self.assertIsNone(session._active)
                    self.assertFalse(any(event[0] == "popen" for event in rig.events))
                    if case in {"wall-interrupt", "wall-interrupt-close-error"}:
                        raise KeyboardInterrupt("synthetic optional wall snapshot interrupted")
                    if case == "wall-cancellation":
                        session.cancelled = True
                    elif case == "wall-first-failure":
                        session.fail("synthetic first failure during optional wall snapshot")
                    elif case == "original-cutoff":
                        rig.now += 11.0  # Past original start+10, still inside unchanged gate50/Session100.
                    return 1_789_029_600_000_000_000 + int(rig.now * 1_000_000_000)

                snapshot = Mock(side_effect=wall_snapshot)
                credentials, ips, log = Mock(), Mock(), Mock()
                command = [str(session.python), "-I", "-S", "-B", str(session.entry), "--native-write-control", str(state["outside_write"])]
                with rig.scope(), \
                     patch.multiple(self.module, signal=SimpleNamespace(SIGABRT=6), sys=SimpleNamespace(orig_argv=[]),
                                    _observe_original_credentials=credentials, socket=SimpleNamespace(), resource=SimpleNamespace()), \
                     patch.object(self.module.time, "time_ns", snapshot), \
                     patch.object(Path, "resolve", side_effect=AssertionError("fake pre-spawn control cannot resolve host paths")), \
                     patch.object(session, "_native_check_inputs", Mock()), \
                     patch.object(session, "_native_abort_prepare", side_effect=prepare), \
                     patch.object(session, "_native_abort_ips", ips), patch.object(session, "_native_abort_log", log):
                    result = session._native_control_capture(state, "outside-write-positive", command,
                        policy=session.bootstrap / "native-write-positive-source.sb", cwd=state["cwd"], seconds=10)
                snapshot.assert_called_once_with()
                credentials.assert_not_called()
                ips.assert_not_called()
                log.assert_not_called()
                self.assertEqual(len(originals), 1)
                abort = originals[0]
                self.assertIsNone(abort["pid"])
                self.assertIsNone(abort["wall_after"])
                self.assertIsNone(abort["wall_wait"])
                self.assertFalse(abort["attempted"])
                if case in {"wall-interrupt", "wall-interrupt-close-error"}:
                    self.assertIsNone(abort["wall_before"])
                    self.assertEqual(abort["diagnostic_error"], {"code": "CANCELLED", "producer_pending": False})
                for event in ("popen", "poll", "wait-original", "terminate-original", "kill-original", "stream-close", "cleanup"):
                    self.assertNotIn(event, [row[0] for row in rig.events])
                self.assertEqual([row for row in rig.events if row[0] == "capture-close"],
                                 [("capture-close", 100), ("capture-close", 101)])
                self.assertEqual(sum(row[0] == "selector-close" for row in rig.events), 1)
                self.assertEqual((result.stdout, result.stderr, result.persisted, session.persisted_bytes), (b"", b"", (0, 0), 0))
                self.assertEqual((result.returncode, result.waited, result.stdout_eof, result.stderr_eof, result.domain_finality),
                                 (None, False, False, False, False))
                self.assertEqual(result.timed_out, case == "original-cutoff")
                self.assertEqual(result.cancelled, case in {"wall-interrupt", "wall-cancellation", "wall-interrupt-close-error"})
                self.assertFalse(result.ok)
                self.assertIsNotNone(result.primary_error)
                self.assertIsNotNone(session.failure)
                if case == "wall-first-failure":
                    self.assertEqual(session.failure, "synthetic first failure during optional wall snapshot")
                if case == "wall-interrupt-close-error":
                    self.assertIn("capture close OSError", result.cleanup_errors)
                    self.assertIn("capture close OSError", session.cleanup_errors)
                self.assertIn("original wait or complete stream EOF missing", result.cleanup_errors)
                self.assertEqual((state["deadline"], session.deadline), (50.0, 100.0))
                self.assertIsNone(session._active)
                self.assertIsNone(session._native_control)
                self.assertFalse(session._busy or session._direct_producer_pending or session.domain_finality)
                row = state["control_notes"]["outside-write-positive"]
                self.assertFalse(row["ok"] or row["subject_ok"])
                self.assertNotIn("native_abort_diagnostic", row)
                self.assertEqual(row["persisted"], [0, 0])

    def test_native_input_reads_and_rechecks_keep_original_custody_bytes_and_close_errors(self):
        path, raw = Path("/synthetic/native/input.py"), b"immutable native input\n"
        for case in ("valid", "alias", "subject-owner", "world-write", "multiple-links", "inherited", "renamed", "grew",
                     "read-and-close-errors", "close-expired", "initial-expiry"):
            with self.subTest(native_input_read=case):
                before = SimpleNamespace(st_dev=7, st_ino=81, st_mode=stat.S_IFREG | (0o446 if case == "world-write" else 0o444),
                    st_uid=60001 if case == "subject-owner" else 0, st_gid=0, st_nlink=2 if case == "multiple-links" else 1, st_size=len(raw),
                    st_mtime_ns=11, st_ctime_ns=12)
                named = SimpleNamespace(**(vars(before) | ({"st_ino": 82} if case == "renamed" else {})))
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                data = io.BytesIO(raw + (b"x" if case == "grew" else b""))
                primary, secondary = OSError("synthetic input read error"), OSError("synthetic input close error")

                def read(fd, count):
                    self.assertEqual(fd, 701)
                    self.assertTrue(0 < count <= 65536)
                    if case == "read-and-close-errors":
                        raise primary
                    return data.read(count)

                def close(fd):
                    self.assertEqual(fd, 701)
                    if case == "read-and-close-errors":
                        raise secondary
                    if case == "close-expired":
                        clock.now = 1.0

                opened, closed = Mock(return_value=701), Mock(side_effect=close)
                constants = {name: getattr(os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, open=opened, read=read, close=closed,
                    fstat=Mock(return_value=before), get_inheritable=Mock(return_value=case == "inherited"))
                with patch.multiple(self.module, os=fake_os, subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                        socket=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now),
                        _canonical=Mock(return_value=path.with_name("alias.py") if case == "alias" else path)), \
                     patch.object(Path, "lstat", return_value=named), \
                     patch.object(Path, "open", side_effect=AssertionError("input custody may use only its fake original descriptor")):
                    if case == "valid":
                        result, identity = self.module._native_file(path, deadline=1.0, uid=60001, gid=60001, maximum=len(raw))
                        self.assertEqual(result, raw)
                        self.assertEqual(identity, (7, 81, stat.S_IFREG | 0o444, 0, 0, 1, len(raw), 11, 12))
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._native_file(path, deadline=1.0, uid=60001, gid=60001, maximum=len(raw))
                        if case == "read-and-close-errors":
                            self.assertEqual(caught.exception.exceptions, (primary, secondary))
                        if case in {"close-expired", "initial-expiry"}:
                            self.assertTrue(all(isinstance(error, self.module.DeadlineExpired) for error in caught.exception.exceptions))
                if case in {"alias", "initial-expiry"}:
                    opened.assert_not_called()
                    closed.assert_not_called()
                else:
                    opened.assert_called_once_with(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    closed.assert_called_once_with(701)

        for case in ("valid", "first-stat-error", "name-drift"):
            with self.subTest(native_original_pin=case):
                session = session_double(self.module, "darwin")
                state = {"deadline": 1.0, "pins": []}
                node = SimpleNamespace(st_dev=7, st_ino=91, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o555)
                named = SimpleNamespace(**(vars(node) | ({"st_ino": 92} if case == "name-drift" else {})))
                original = OSError("synthetic first descriptor observation failed")
                opened, closed = Mock(return_value=705), Mock()
                constants = {name: getattr(os, name) for name in ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, open=opened, close=closed,
                        fstat=Mock(return_value=node, side_effect=original if case == "first-stat-error" else None),
                        get_inheritable=lambda _fd: False), _canonical=Path,
                        time=SimpleNamespace(monotonic=lambda: 0.0), subprocess=SimpleNamespace(), signal=SimpleNamespace()), \
                     patch.object(Path, "lstat", return_value=named):
                    if case == "valid":
                        session._native_pin(state, path.parent, modes=(0o555,))
                    else:
                        with self.assertRaises(OSError if case == "first-stat-error" else self.module.SessionError) as caught:
                            session._native_pin(state, path.parent, modes=(0o555,))
                        if case == "first-stat-error":
                            self.assertIs(caught.exception, original)
                    self.assertEqual(len(state["pins"]), 1)
                    self.assertEqual(state["pins"][0]["fd"], 705)  # Owned before even the first fstat can fail.
                    self.assertEqual(state["pins"][0]["node"] is None, case != "valid")
                    self.assertEqual(session._native_close_pins(state), [])
                opened.assert_called_once_with(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                closed.assert_called_once_with(705)

        for case in ("valid", "closed-pin", "inherited-pin", "named-parent-replaced", "tree-extra", "file-bytes", "root-extra"):
            with self.subTest(native_input_recheck=case):
                session = session_double(self.module, "darwin")
                cwd = session.work / "native-authority-source"
                node = SimpleNamespace(st_dev=7, st_ino=91, st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0)
                named = SimpleNamespace(**(vars(node) | ({"st_ino": 92} if case == "named-parent-replaced" else {})))
                state = dict(deadline=1.0, cwd=cwd, pins=[{"path": path.parent, "fd": None if case == "closed-pin" else 702,
                    "node": (*self.module._home_node(node), 0o555)}], trees={path.parent: ("input.py",)},
                    files={path: {"identity": ("synthetic-bound-identity",), "sha256": hashlib.sha256(raw).hexdigest(),
                                  "root_owned": True, "maximum": len(raw)}})
                contents = raw + b"changed" if case == "file-bytes" else raw
                reader = Mock(return_value=(contents, ("synthetic-bound-identity",)))
                names = ["home", "tmp", "config", "cache", "probes"] + (["old-site-hook.py"] if case == "root-extra" else [])

                def pinned_node(fd):
                    self.assertEqual(fd, 702)
                    return node

                def named_node(queried):
                    self.assertEqual(queried, path.parent)
                    return named

                def leaves(queried):
                    self.assertEqual(queried, cwd)
                    return [cwd / name for name in names]

                with patch.multiple(self.module, os=SimpleNamespace(fstat=pinned_node,
                        get_inheritable=Mock(return_value=case == "inherited-pin")), subprocess=SimpleNamespace(),
                        socket=SimpleNamespace(), signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: 0.0),
                        _native_file=reader), \
                     patch.object(session, "_native_tree", return_value=("extra.py", "input.py") if case == "tree-extra" else ("input.py",)) as tree, \
                     patch.object(Path, "lstat", named_node), patch.object(Path, "iterdir", leaves), \
                     patch.object(Path, "open", side_effect=AssertionError("recheck must retain the fixed input reader")):
                    if case == "valid":
                        session._native_check_inputs(state)
                        reader.assert_called_once_with(path, deadline=1.0, uid=session.uid, gid=session.gid,
                                                       root_owned=True, maximum=len(raw))
                        tree.assert_called_once_with(state, path.parent, binding=False)
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session._native_check_inputs(state)
                if case in {"closed-pin", "inherited-pin", "named-parent-replaced"}:
                    tree.assert_not_called()
                    reader.assert_not_called()

        # A close failure retires only the original descriptor; it is not a
        # retry authority, and cannot suppress an independent later close.
        session = session_double(self.module, "darwin")
        state = {"pins": [{"fd": 703}, {"fd": 704}], "closed": False}
        closed = Mock(side_effect=OSError("synthetic independently reported close error"))
        with patch.object(self.module, "os", SimpleNamespace(close=closed)):
            errors = session._native_close_pins(state)
            self.assertEqual(len(errors), 2)
            self.assertEqual(session._native_close_pins(state), [])
        self.assertEqual([call.args for call in closed.call_args_list], [(704,), (703,)])
        self.assertTrue(state["closed"])
        self.assertEqual([pin["fd"] for pin in state["pins"]], [None, None])

        # The new read positive must really consume both exact finite inputs;
        # it cannot print success for absence, wrong identity or late reads.
        for case in ("source", "wheel", "linux", "wrong-phase", "root-identity", "group-mismatch", "wrong-canary", "empty-sibling", "read-error", "late-read"):
            with self.subTest(native_read_positive=case):
                phase = "wheel" if case == "wheel" else "other" if case == "wrong-phase" else "source"
                root = Path("/synthetic/native-read")
                paths = (root / "work/home" / f"native-authority-{phase}-read",
                         root / "work" / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py")
                clock, seen, output = SimpleNamespace(now=0.0), [], io.StringIO()
                uid, gid = (0 if case == "root-identity" else 60001), (60002 if case == "group-mismatch" else 60001)
                original = OSError("synthetic bounded read unavailable")

                def read(path, *, deadline, uid: int, gid: int, maximum=16 * self.module.MiB):
                    self.assertEqual((deadline, uid, gid), (1.0, 60001, 60001))
                    self.assertEqual(path, paths[len(seen)])
                    self.assertEqual(maximum, 64 if not seen else 16 * self.module.MiB)
                    seen.append(path)
                    if case == "read-error":
                        raise original
                    if len(seen) == 1:
                        return (b"wrong" if case == "wrong-canary" else b"MRK_NATIVE_PREVIOUS_SCRATCH\n"), ()
                    if case == "late-read":
                        clock.now = 1.0
                    return (b"" if case == "empty-sibling" else b"actual immutable sibling bytes"), ()

                with patch.multiple(self.module, os=SimpleNamespace(getuid=lambda: uid, geteuid=lambda: uid,
                        getgid=lambda: gid, getegid=lambda: gid), sys=SimpleNamespace(platform="linux" if case == "linux" else "darwin"),
                        time=SimpleNamespace(monotonic=lambda: clock.now), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                        signal=SimpleNamespace(), _native_file=read), \
                     patch.object(Path, "resolve", return_value=root / "bootstrap/ci_sandbox.py"), redirect_stdout(output):
                    if case in {"source", "wheel"}:
                        self.module._native_read_control(phase, 1.0)
                    else:
                        with self.assertRaises(OSError if case == "read-error" else self.module.SessionError) as caught:
                            self.module._native_read_control(phase, 1.0)
                        if case == "read-error":
                            self.assertIs(caught.exception, original)
                self.assertEqual(output.getvalue(), "MRK_NATIVE_OUTSIDE_READ_OK\n" if case in {"source", "wheel"} else "")
                self.assertEqual(len(seen), 0 if case in {"linux", "wrong-phase", "root-identity", "group-mismatch"} else
                                 1 if case == "read-error" else 2)

    def test_native_authority_admission_rejects_unknown_phase_and_producer_before_acquisition(self):
        cases = ("phase-none", "phase-list", "phase-unknown", "linux", "not-admitted", "admitting", "closed",
                 "prior-failure", "busy", "original-owned", "direct-pending", "domain-present", "domain-unknown",
                 "expired", "duplicate-attempt", "wheel-before-source")
        for case in cases:
            with self.subTest(native_role_preacquisition=case):
                session = session_double(self.module, "linux" if case == "linux" else "darwin")
                rig = _Collection(self.module, session)
                phase = {"phase-none": None, "phase-list": ["source"], "phase-unknown": "arbitrary-service-role",
                         "wheel-before-source": "wheel"}.get(case, "source")
                session.admitted = case != "not-admitted"
                session._admitting, session.closed, session._busy = case == "admitting", case == "closed", case == "busy"
                session._active = object() if case == "original-owned" else None
                session._direct_producer_pending = case == "direct-pending"
                if case == "prior-failure":
                    session.fail("original owner failure")
                elif case == "duplicate-attempt":
                    session._native_authority["source"] = {"prepared": False, "started": False, "completed": False}
                elif case == "expired":
                    rig.now = 0.5
                domain = Mock(return_value={4242} if case == "domain-present" else set(),
                              side_effect=OSError("synthetic unknown original identity domain") if case == "domain-unknown" else None)
                with rig.scope(), patch.object(self.module, "_domain", domain), ExitStack() as stack:
                    filesystem = [stack.enter_context(patch.object(Path, method,
                        side_effect=AssertionError("refused role may not acquire or inspect paths")))
                        for method in ("resolve", "stat", "lstat", "open", "mkdir", "chmod", "unlink", "rmdir",
                                       "read_bytes", "read_text", "write_bytes", "iterdir")]
                    private_file = stack.enter_context(patch.object(self.module, "_private_file",
                        side_effect=AssertionError("refused role may not create a policy or receipt")))
                    expected = (self.module.SessionError, OSError) if case == "domain-unknown" else self.module.SessionError
                    with self.assertRaises(expected):
                        session.prepare_native_authority(phase, deadline=0.5)
                    for operation in filesystem:
                        operation.assert_not_called()
                    private_file.assert_not_called()
                    session._argv.assert_not_called()
                self.assertEqual(rig.opened, [])
                self.assertFalse(any(e[0] == "popen" for e in rig.events))
                self.assertFalse(any(row.get("prepared", False) for row in session._native_authority.values()))
                self.assertEqual(session.deadline, 100.0)
                if case in {"prior-failure", "busy", "original-owned", "direct-pending", "domain-present", "domain-unknown", "expired"}:
                    self.assertIsNotNone(session.failure)
                if case == "prior-failure":
                    self.assertEqual(session.failure, "original owner failure")

    def test_native_authority_preparation_is_exclusive_once_only_and_keeps_six_fixed_control_routes(self):
        for case in ("source", "wheel", "input-failure", "cwd-collision", "mkdir-after-effect", "leaf-owner-after-effect",
                     "boundary-failure", "cleanup-errors", "late-preparation", "cancelled-preparation"):
            with self.subTest(native_preparation=case):
                session = session_double(self.module, "darwin")
                phase = "wheel" if case == "wheel" else "source"
                cwd = session.work / f"native-authority-{phase}"
                helper, helper_source = session.bootstrap / "ci_native_authority.py", session.source / ".github/scripts/ci_native_authority.py"
                payload = b"inert fixed helper bytes, never imported\n"
                controls = {"synthetic-inert-fixture": True}
                if phase == "wheel":
                    session._native_authority["source"] = dict(completed=True, closed=True, native_controls=controls)
                clock, nodes, files, fds, acquired, events = SimpleNamespace(now=0.0), {}, {}, {}, [], []
                original = OSError("synthetic native preparation fault")

                def node(path, *, directory=False, mode=0o444, owner=(0, 0), raw=b""):
                    nodes[path] = dict(st_dev=7, st_ino=100 + len(nodes), st_uid=owner[0], st_gid=owner[1],
                        st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode, st_nlink=1,
                        st_size=len(raw), st_mtime_ns=11, st_ctime_ns=12)
                    if not directory:
                        files[path] = raw

                for path in (session.root, session.work, session.bootstrap, session.fixture_controls):
                    node(path, directory=True, mode=0o755)
                node(helper_source, raw=payload)
                sibling = session.work / f"{phase}-venv/lib/python3.11/site-packages/pip/__init__.py"
                node(sibling, raw=b"frozen unrelated sibling; not an import\n")
                if phase == "wheel":
                    node(helper, raw=payload)
                if case == "cwd-collision":
                    node(cwd, directory=True, mode=0o700, owner=(1001, 20))

                def acquire(path):
                    self.assertIn(path, nodes)
                    fd = 800 + len(acquired)
                    acquired.append(fd)
                    fds[fd] = path
                    return fd

                def pin(state, path, *, owner=(0, 0), modes=(0o555, 0o755)):
                    self.assertIs(state, session._native_authority[phase])
                    observed = SimpleNamespace(**nodes[path])
                    self.assertEqual((observed.st_uid, observed.st_gid), owner)
                    self.assertIn(stat.S_IMODE(observed.st_mode), modes)
                    state["pins"].append({"path": path, "fd": acquire(path),
                                          "node": (*self.module._home_node(observed), stat.S_IMODE(observed.st_mode))})
                    events.append(("pin", path))

                def bind(state):
                    self.assertTrue(session.domain_finality)
                    self.assertEqual(session._native_preparing, phase)
                    self.assertFalse(state["prepared"])
                    events.append(("bind-inputs",))
                    if case == "input-failure":
                        raise original
                    state["package"] = (session.work / "source-build/src/mobile_release" if phase == "source" else
                                        session.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
                    state["tools"] = {"signature-tool": {"synthetic-bound-input": True}}
                    for path in (session.root, session.work, session.bootstrap):
                        pin(state, path, modes=(0o755,))

                def add_file(state, path, **_options):
                    self.assertIn(path, files)
                    raw = files[path]
                    state["files"][path] = dict(identity=(7, nodes[path]["st_ino"], nodes[path]["st_mode"], 0, 0, 1, len(raw), 11, 12),
                        sha256=hashlib.sha256(raw).hexdigest(), root_owned=True, maximum=16 * self.module.MiB)
                    return raw

                def private_file(path, raw, mode=0o600):
                    self.assertNotIn(path, nodes)  # Create-only; the existing helper is reused only for wheel.
                    events.append(("private-file", path, mode))
                    node(path, mode=mode, raw=raw)

                def mkdir(path, mode=0o777, parents=False, exist_ok=False):
                    self.assertFalse(parents or exist_ok)
                    self.assertEqual(session._native_preparing, phase)
                    self.assertIs(session._native_authority[phase]["prepared"], False)
                    events.append(("mkdir", path, mode))
                    if path in nodes:
                        raise FileExistsError("synthetic foreign scratch name")
                    node(path, directory=True, mode=mode)
                    if case == "mkdir-after-effect" and path == cwd:
                        raise original  # Effect happened but no returned/pinned identity.

                def chmod(path, mode, *, follow_symlinks=True):
                    self.assertIn(path, nodes)
                    self.assertIn((path, mode), {(cwd, 0o755), *((cwd / name, 0o700) for name in self.module._NATIVE_LEAVES)})
                    nodes[path]["st_mode"] = stat.S_IFMT(nodes[path]["st_mode"]) | mode

                def chown(path, uid, gid):
                    self.assertIn(path, [cwd / name for name in self.module._NATIVE_LEAVES])
                    self.assertEqual((uid, gid), (session.uid, session.gid))
                    nodes[path]["st_uid"], nodes[path]["st_gid"] = uid, gid
                    if case == "leaf-owner-after-effect" and path == cwd / "home":
                        raise original

                def opened(path, flags):
                    self.assertEqual((path, flags), (session._native_authority[phase]["outside_write"], os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC))
                    return acquire(path)

                def fstat(fd):
                    self.assertIn(fd, fds)
                    return SimpleNamespace(**nodes[fds[fd]])

                def fchown(fd, uid, gid):
                    self.assertEqual(fds[fd], session._native_authority[phase]["outside_write"])
                    self.assertEqual((uid, gid), (session.uid, session.gid))
                    nodes[fds[fd]]["st_uid"], nodes[fds[fd]]["st_gid"] = uid, gid

                def close(fd):
                    self.assertIn(fd, fds)
                    del fds[fd]
                    events.append(("close", fd))
                    if case == "cleanup-errors":
                        raise OSError("synthetic independently reported owned-close failure")

                def boundary(state):
                    self.assertIs(state, session._native_authority[phase])
                    self.assertFalse(state["prepared"] or state["started"])
                    self.assertIsNotNone(state["outside_fd"])
                    self.assertEqual(state["startup_seen"], [])
                    self.assertIn(state["write_policy"], state["files"])
                    self.assertEqual(state["files"][state["write_policy"]]["sha256"],
                                     hashlib.sha256(files[state["write_policy"]]).hexdigest())
                    events.append(("direct-boundaries", phase))
                    if case in {"boundary-failure", "cleanup-errors"}:
                        raise original

                fixed_cases = ("mach-baseline", "mach-ordinary", "mach-authority", "mach-nonexpand", "aia-prepare", "aia-evaluate")

                def capture(state, selected, command, *, policy, cwd: Path, seconds):
                    self.assertEqual(phase, "source")
                    self.assertEqual(session._native_preparing, phase)
                    self.assertEqual(state["control_seen"], list(fixed_cases[:fixed_cases.index(selected) + 1]))
                    base = [str(session.python), "-I", "-S", "-B", str(helper)]
                    if selected == "mach-nonexpand":
                        expected = [*base, "--mach-nonexpand", str(session.bootstrap / "native-authority-source.sb"), "1.0"]
                    elif selected.startswith("mach-"):
                        expected = [*base, "--mach", "1.0"]
                    else:
                        expected = [*base, "--" + selected, "12345", "1.0"]
                    self.assertEqual(command, expected)
                    policies = {"mach-baseline": state["mach_policy"], "mach-ordinary": session.policy,
                        "mach-authority": state["policy"], "mach-nonexpand": session.policy,
                        "aia-prepare": state["policy"], "aia-evaluate": session.bootstrap / "native-aia-source.sb"}
                    self.assertEqual(policy, policies[selected])
                    self.assertEqual(cwd, state["cwd"] / "probes")
                    self.assertEqual(seconds, 300 if selected == "aia-prepare" else 120 if selected == "aia-evaluate" else 30)
                    events.append(("control", selected))
                    state["control_notes"][selected] = {"ok": False}
                    return self.module.CapturedRun(b"", b"", 0, True, True, True, True, False, False, 0.01, None, (), (0, 0))

                def admit_controls(capture_callback, idle_callback, root, *, deadline):
                    self.assertEqual((root, deadline), (cwd / "probes", 1.0))
                    for selected in fixed_cases:
                        result = capture_callback(selected, **({"port": 12345} if selected.startswith("aia-") else {}))
                        self.assertTrue(result.ok)
                        self.assertTrue(all(not row["ok"] for row in session._native_authority[phase]["control_notes"].values()))
                        idle_callback()
                    return controls

                backend = SimpleNamespace(admit_controls=admit_controls)
                loader = SimpleNamespace(exec_module=Mock())  # Never import/evaluate the actual native helper.
                spec = SimpleNamespace(loader=loader)
                fake_imports = SimpleNamespace(util=SimpleNamespace(spec_from_file_location=Mock(return_value=spec),
                                                                  module_from_spec=Mock(return_value=backend)))

                def checked(state):
                    self.assertFalse(state["prepared"])
                    self.assertTrue(session.domain_finality)
                    events.append(("inputs-rechecked",))
                    if case == "late-preparation":
                        clock.now = 1.0
                    elif case == "cancelled-preparation":
                        session.cancelled = True
                        session.fail("synthetic preparation cancellation before publication")

                constants = {name: getattr(os, name) for name in ("O_RDWR", "O_NOFOLLOW", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, open=opened, fstat=fstat, fchown=fchown, close=close, chown=chown,
                                         get_inheritable=lambda _fd: False, path=SimpleNamespace(basename=os.path.basename))
                with patch.multiple(self.module, os=fake_os, time=SimpleNamespace(monotonic=lambda: clock.now),
                        subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(), selectors=SimpleNamespace(),
                        resource=SimpleNamespace(), importlib=fake_imports, _domain=Mock(return_value=set()), _canonical=Path,
                        _private_file=private_file), \
                     patch.object(session, "_headroom", Mock()), patch.object(session, "_native_bind_inputs", side_effect=bind), \
                     patch.object(session, "_native_add_file", side_effect=add_file), patch.object(session, "_native_pin", side_effect=pin), \
                     patch.object(session, "_native_boundary_controls", side_effect=boundary), \
                     patch.object(session, "_native_control_capture", side_effect=capture), \
                     patch.object(session, "_native_check_inputs", side_effect=checked), \
                     patch.object(Path, "mkdir", mkdir), patch.object(Path, "chmod", chmod), \
                     patch.object(Path, "lstat", lambda path: SimpleNamespace(**nodes[path])), ExitStack() as stack:
                    removal = [stack.enter_context(patch.object(Path, name, side_effect=AssertionError("native preparation cannot delete or adopt paths")))
                               for name in ("unlink", "rmdir", "open", "read_bytes", "iterdir", "resolve", "stat")]
                    if case in {"source", "wheel"}:
                        report = session.prepare_native_authority(phase, deadline=1.0)
                        state = session._native_authority[phase]
                        self.assertEqual((report["schema"], report["phase"], report["prepared"]), (1, phase, True))
                        self.assertTrue(state["prepared"])
                        self.assertFalse(state["started"] or state["closed"])
                        self.assertEqual(state["native_controls"], controls)
                        self.assertEqual(state["control_notes"], {selected: {"ok": True} for selected in fixed_cases} if phase == "source" else {})
                        self.assertEqual([event for event in events if event[0] == "direct-boundaries"], [("direct-boundaries", phase)])
                        self.assertEqual([event[1] for event in events if event[0] == "control"], list(fixed_cases) if phase == "source" else [])
                        count = len(events)
                        with self.assertRaises(self.module.SessionError):
                            session.prepare_native_authority(phase, deadline=1.0)
                        self.assertEqual(len(events), count)
                        self.assertEqual(session._native_close_pins(state), [])
                    else:
                        expected = BaseExceptionGroup if case == "cleanup-errors" else FileExistsError if case == "cwd-collision" else \
                                   self.module.DeadlineExpired if case == "late-preparation" else \
                                   self.module.SessionError if case == "cancelled-preparation" else OSError
                        with self.assertRaises(expected) as caught:
                            session.prepare_native_authority(phase, deadline=1.0)
                        state = session._native_authority[phase]
                        self.assertFalse(state["prepared"])
                        self.assertTrue(state["closed"])
                        self.assertIsNotNone(session.failure)
                        if case == "cleanup-errors":
                            self.assertIs(caught.exception.exceptions[0], original)
                            self.assertEqual(len(session.cleanup_errors), len(acquired))
                        count = len(events)
                        with self.assertRaises(self.module.SessionError):
                            session.prepare_native_authority(phase, deadline=1.0)
                        self.assertEqual(len(events), count)
                    self.assertEqual(session._native_close_pins(state), [])
                    for operation in removal:
                        operation.assert_not_called()
                self.assertIsNone(session._native_preparing)
                self.assertIsNone(session._native_control)
                self.assertEqual(fds, {})
                self.assertCountEqual([event[1] for event in events if event[0] == "close"], acquired)
                self.assertEqual(session.deadline, 100.0)
                if case == "cwd-collision":
                    self.assertEqual((nodes[cwd]["st_uid"], nodes[cwd]["st_gid"], stat.S_IMODE(nodes[cwd]["st_mode"])), (1001, 20, 0o700))
                if case == "mkdir-after-effect":
                    self.assertIn(cwd, nodes)
                    self.assertNotIn(("pin", cwd), events)
                if case in {"source", "late-preparation", "cancelled-preparation"}:
                    fake_imports.util.spec_from_file_location.assert_called_once_with("_mrk_native_authority_controls", helper)
                    loader.exec_module.assert_called_once_with(backend)
                else:
                    loader.exec_module.assert_not_called()

    def test_native_authority_run_admits_only_exact_prepared_profiles_and_keeps_original_capture(self):
        cases = ("source", "wheel", "unknown-profile", "public-control", "linux", "not-admitted", "admitting", "env", "cwd",
                 "state-root", "state-policy", "state-phase", "argv", "python-flags", "cpu", "seconds", "limit",
                 "no-cutoff", "changed-cutoff", "unlatched", "cancel-control", "unprepared", "started", "completed",
                 "closed", "busy", "original-owned", "direct-pending", "unknown-domain", "ordinary-overlap")
        for case in cases:
            with self.subTest(native_profile_invocation=case):
                session = session_double(self.module, "linux" if case == "linux" else "darwin")
                phase = "wheel" if case == "wheel" else "source"
                state = native_state_double(session, phase)
                rig = _Collection(self.module, session)
                rig.snapshot_rows = {(rig.child.pid, rig.child.pid): ((session.uid,) * 3, (session.gid,) * 3, 65536)}
                session.admitted, session._admitting = case != "not-admitted", case == "admitting"
                session._busy, session._direct_producer_pending = case == "busy", case == "direct-pending"
                session._active = object() if case == "original-owned" else None
                if case in {"started", "completed", "closed"}:
                    state[case] = True
                if case == "unprepared":
                    state["prepared"] = False
                if case == "state-root":
                    state["cwd"] = session.work / "unbound-native-root"
                elif case == "state-policy":
                    state["policy"] = session.bootstrap / "unbound-native-policy.sb"
                elif case == "state-phase":
                    state["phase"] = "wheel"
                command = list(state["argv"])
                if case == "argv":
                    command.append("--caller-selected-test")
                elif case == "python-flags":
                    command[2] = "-s"  # Not -S: site/.pth must not be initialized.
                kwargs = dict(cwd=state["cwd"], env={}, seconds=900, output_limit=8 * self.module.MiB,
                    cpu_seconds=180, profile="native-authority-" + phase, absolute_deadline=1.0)
                changes = {"unknown-profile": {"profile": "native-authority-arbitrary"}, "public-control": {"profile": "native-control"},
                    "ordinary-overlap": {"profile": "ordinary"}, "env": {"env": {"PYTHONSAFEPATH": "1"}},
                    "cwd": {"cwd": session.work}, "cpu": {"cpu_seconds": 179}, "seconds": {"seconds": 899},
                    "limit": {"output_limit": self.module.MiB}, "no-cutoff": {"absolute_deadline": None},
                    "changed-cutoff": {"absolute_deadline": 0.9}}
                kwargs.update(changes.get(case, {}))
                input_states = []

                def inputs(observed):
                    self.assertIs(observed, state)
                    self.assertFalse(session._busy)
                    self.assertIsNone(session._active)
                    self.assertTrue(session.domain_finality)
                    input_states.append(state["started"])

                actual_argv = type(session)._argv.__get__(session)
                with rig.scope(), patch.object(session, "_argv", wraps=actual_argv) as argv_builder, \
                     patch.object(session, "_native_check_inputs", side_effect=inputs) as check, \
                     patch.object(session, "_native_scratch_inventory", return_value={"entries": 0, "bytes": 0, "private_retained": True}) as inventory, \
                     patch.object(Path, "open", side_effect=AssertionError("profile test must use only closed fake capture/input seams")), \
                     patch.object(Path, "stat", side_effect=AssertionError("profile test must use only closed fake metadata seams")), ExitStack() as stack:
                    if case == "unknown-domain":
                        stack.enter_context(patch.object(self.module, "_domain", side_effect=OSError("synthetic unknown native finality")))
                    if case in {"source", "wheel"}:
                        result = session.run(command, **kwargs)
                        self.assertTrue(result.ok, result)
                        self.assertTrue(result.waited and result.stdout_eof and result.stderr_eof and result.finality)
                        self.assertEqual((result.stdout, result.stderr, result.persisted), (b"PASS\n", b"", (5, 0)))
                        self.assertEqual(session.persisted_bytes, 5)
                        self.assertEqual(input_states, [False, True])
                        self.assertTrue(state["started"] and state["completed"] and state["closed"])
                        self.assertEqual(rig.domain_calls, 3)
                        argv_builder.assert_called_once_with(command, 180, profile="native-authority-" + phase)
                        inventory.assert_called_once_with(state)
                        call = next(event for event in rig.events if event[0] == "popen")
                        self.assertEqual(call[1], tuple([str(session.python), "-I", "-S", "-B", str(session.entry), "--enter", "darwin",
                            str(session.uid), str(session.gid), "180", str(state["policy"]), *command]))
                        self.assertEqual(call[2]["env"], session._native_environment(state))
                        self.assertEqual((call[2]["user"], call[2]["group"], call[2]["extra_groups"]), (session.uid, session.gid, []))
                        with self.assertRaises(self.module.SessionError):
                            session.run(command, **kwargs)
                        self.assertEqual(len(rig.opened), 2)
                    else:
                        expected = OSError if case == "unknown-domain" else self.module.SessionError
                        with self.assertRaises(expected):
                            if case in {"unlatched", "cancel-control"}:
                                session._run(command, **kwargs, latch=case != "unlatched",
                                             cancel_after=0.01 if case == "cancel-control" else None)
                            else:
                                session.run(command, **kwargs)
                        check.assert_not_called()
                        inventory.assert_not_called()
                        self.assertEqual(rig.opened, [])
                        self.assertFalse(any(event[0] == "popen" for event in rig.events))
                self.assertEqual(session.deadline, 100.0)

    def test_native_postconditions_preserve_failure_accounting_and_close_only_original_resources(self):
        for case in ("input-refusal", "original-and-close-errors", "unknown-finality", "unsafe-output", "close-expired", "close-cancelled"):
            with self.subTest(native_capture_finalization=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session)
                state["pins"], state["outside_fd"] = [{"fd": 703}], 704
                rig = _Collection(self.module, session)
                rig.snapshot_rows = {(rig.child.pid, rig.child.pid): ((session.uid,) * 3, (session.gid,) * 3, 65536)}
                if case == "original-and-close-errors":
                    rig.exit_at, rig.exitcode = 0.0, 7
                elif case == "unknown-finality":
                    rig.final_domain = OSError("synthetic unknown native domain")
                original, owned_closes = OSError("synthetic immutable input changed"), []

                def close(fd):
                    if fd not in (703, 704):
                        return rig.close(fd)
                    self.assertNotIn(fd, owned_closes)
                    owned_closes.append(fd)
                    if case in {"input-refusal", "original-and-close-errors"}:
                        raise OSError("synthetic independently reported native close")
                    if case == "close-expired" and fd == 703:
                        rig.now = 1.0
                    elif case == "close-cancelled" and fd == 703:
                        session.cancelled = True
                        session.fail("synthetic late owner cancellation")

                with rig.scope(), patch.object(self.module.os, "close", side_effect=close), \
                     patch.object(session, "_native_check_inputs", side_effect=original if case == "input-refusal" else None) as inputs, \
                     patch.object(session, "_native_scratch_inventory", return_value={"entries": 0, "bytes": 0, "private_retained": True},
                                  side_effect=self.module.SessionError("synthetic unsafe native output") if case == "unsafe-output" else None) as inventory, \
                     patch.object(Path, "unlink", side_effect=AssertionError("uncertain native state may not authorize path removal")) as remove:
                    kwargs = dict(cwd=state["cwd"], env={}, seconds=900, profile="native-authority-source", absolute_deadline=1.0)
                    if case == "input-refusal":
                        with self.assertRaises(OSError) as caught:
                            session.run(state["argv"], **kwargs)
                        self.assertIs(caught.exception, original)
                        self.assertEqual(rig.opened, [])
                        self.assertFalse(state["prepared"] or state["started"])
                        self.assertEqual(len(session.cleanup_errors), 2)
                    else:
                        result = session.run(state["argv"], **kwargs)
                        self.assertFalse(result.ok)
                        self.assertTrue(result.waited and result.stdout_eof and result.stderr_eof)
                        self.assertEqual((result.stdout, result.stderr, result.persisted), (b"PASS\n", b"", (5, 0)))
                        self.assertEqual(session.persisted_bytes, 5)
                        self.assertEqual(result.timed_out, case == "close-expired")
                        self.assertEqual(result.cancelled, case == "close-cancelled")
                        if case == "original-and-close-errors":
                            self.assertEqual((result.returncode, result.primary_error, session.failure), (7, "command exited 7", "command exited 7"))
                            self.assertIn("native authority outside fixture close OSError", result.cleanup_errors)
                            self.assertIn("native authority owned directory close OSError", result.cleanup_errors)
                        elif case == "unknown-finality":
                            self.assertFalse(result.finality or session.domain_finality)
                        elif case == "close-cancelled":
                            self.assertEqual(session.failure, "synthetic late owner cancellation")
                        else:
                            self.assertIn("native authority postconditions", result.primary_error)
                    self.assertEqual(inputs.call_count, 1 if case in {"input-refusal", "original-and-close-errors", "unknown-finality"} else 2)
                    if case in {"input-refusal", "original-and-close-errors", "unknown-finality"}:
                        inventory.assert_not_called()
                    remove.assert_not_called()
                    self.assertEqual(owned_closes, [704, 703])
                    self.assertTrue(state["closed"])
                    self.assertFalse(state["completed"])
                    self.assertIsNone(state["outside_fd"])
                    self.assertEqual(state["pins"], [{"fd": None}])
                    self.assertIsNotNone(session.failure)
                    with self.assertRaises(self.module.SessionError):
                        session.run(state["argv"], **kwargs)
                    self.assertEqual(owned_closes, [704, 703])

        for case in ("valid", "link", "foreign-owner", "world-write", "set-id", "hard-link", "too-large", "expired"):
            with self.subTest(native_safe_output_inventory=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session)
                leaves = [state["cwd"] / name for name in self.module._NATIVE_LEAVES]
                path = state["cwd"] / "tmp/output"
                info = SimpleNamespace(st_uid=1001 if case == "foreign-owner" else session.uid, st_gid=session.gid,
                    st_mode=(stat.S_IFLNK if case == "link" else stat.S_IFREG) |
                            (0o602 if case == "world-write" else 0o4600 if case == "set-id" else 0o600),
                    st_nlink=2 if case == "hard-link" else 1, st_size=128 * self.module.MiB + 1 if case == "too-large" else 4)

                def walk(root, *, followlinks, onerror):
                    self.assertIn(root, leaves)
                    self.assertFalse(followlinks)
                    self.assertTrue(callable(onerror))
                    return [(str(root), [], ["output"] if root == path.parent else [])]

                def metadata(queried):
                    self.assertEqual(queried, path)
                    return info

                with patch.multiple(self.module, os=SimpleNamespace(walk=walk), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    socket=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: 1.0 if case == "expired" else 0.0)), \
                     patch.object(Path, "lstat", metadata), \
                     patch.object(Path, "unlink", side_effect=AssertionError("inventory is not a deletion capability")):
                    if case == "valid":
                        self.assertEqual(session._native_scratch_inventory(state), {"entries": 1, "bytes": 4, "private_retained": True})
                    else:
                        with self.assertRaises(self.module.SessionError):
                            session._native_scratch_inventory(state)

        for case in ("prepared-only", "prior-failure", "direct-pending"):
            with self.subTest(native_terminal_close=case):
                session = session_double(self.module, "darwin")
                state = native_state_double(session)
                state["pins"], state["outside_fd"] = [{"fd": 703}], 704
                session._direct_producer_pending = case == "direct-pending"
                if case == "prior-failure":
                    session.fail("earlier original owner failure")
                closes = Mock(side_effect=OSError("synthetic independently reported terminal close"))
                with patch.multiple(self.module, os=SimpleNamespace(close=closes), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                        socket=SimpleNamespace(), _domain=Mock(return_value=set()), time=SimpleNamespace(monotonic=lambda: 0.0)), \
                     patch.object(Path, "unlink", side_effect=AssertionError("terminal close may not remove unknown native outputs")):
                    for _ in range(2):
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                    self.assertTrue(session.closed and state["closed"])
                    self.assertFalse(state["completed"])
                    self.assertFalse(session._timer_finished)
                    if case == "prior-failure":
                        self.assertEqual(session.failure, "earlier original owner failure")
                    if case == "direct-pending":
                        self.assertFalse(session.domain_finality)
                    self.assertIn("native authority outside fixture close OSError", session.cleanup_errors)
                    self.assertIn("native authority owned directory close OSError", session.cleanup_errors)
                self.assertEqual([call.args for call in closes.call_args_list], [(704,), (703,)])

    def test_finality_access_guard_and_close_fail_without_adopting_or_resetting(self):
        for case in ("busy", "owned", "pending-direct", "remaining", "unknown"):
            session = session_double(self.module)
            session._busy = case == "busy"
            session._active = object() if case == "owned" else None
            session._direct_producer_pending = case == "pending-direct"
            session.domain_finality = case == "pending-direct"  # A stale census is not current producer finality.
            domain = Mock(side_effect=OSError("unknown census")) if case == "unknown" else Mock(
                return_value={"synthetic": 1} if case == "remaining" else {},
            )
            with self.subTest(case=case), patch.object(self.module, "_domain", domain), \
                 patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 0.0)), \
                 patch.object(session, "_headroom") as headroom:
                with self.assertRaises((self.module.SessionError, OSError)):
                    session.ensure_idle()
                self.assertIsNotNone(session.failure)
                self.assertFalse(session.domain_finality)
                headroom.assert_not_called()
                if case in {"busy", "owned", "pending-direct"}:
                    domain.assert_not_called()
        session = session_double(self.module)
        previous = object()
        session._handlers = {14: previous}
        session.fail("earlier real failure")
        fake_signal = SimpleNamespace(ITIMER_REAL=0, setitimer=Mock(), signal=Mock())
        with patch.object(self.module, "_domain", return_value={}), \
             patch.object(self.module, "signal", fake_signal), \
             patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: 0.0)), \
             patch.object(Path, "unlink", side_effect=AssertionError("no disposal evidence from deletion")) as unlink:
            with self.assertRaisesRegex(self.module.SessionError, "earlier real failure"):
                session.close()
        self.assertTrue(session.closed)
        self.assertTrue(session.domain_finality)
        self.assertEqual(session.failure, "earlier real failure")
        fake_signal.setitimer.assert_called_once_with(0, 0)
        fake_signal.signal.assert_called_once_with(14, previous)
        unlink.assert_not_called()

    def test_terminal_timer_covers_publication_and_releases_all_owned_handlers_once(self):
        session = session_double(self.module)
        fake_signal = SimpleNamespace(ITIMER_REAL=0, setitimer=Mock(), signal=Mock())
        with patch.object(self.module, "signal", fake_signal):
            with self.assertRaisesRegex(self.module.SessionError, "terminal close is required"):
                session.finish()
        fake_signal.setitimer.assert_not_called()
        fake_signal.signal.assert_not_called()
        self.assertFalse(session._timer_finished)

        for case in ("success", "prior-failure", "unknown-domain", "release-errors",
                     "prior-and-release-errors", "late-deadline"):
            with self.subTest(case=case):
                session = session_double(self.module)
                session._handlers = {14: object(), 2: object(), 15: object()}
                clock = SimpleNamespace(now=0.0)
                release_errors = "release-errors" in case

                def restore(number, _previous):
                    if release_errors and number == 2:
                        raise OSError("synthetic one-handler restoration error")

                fake_signal = SimpleNamespace(
                    ITIMER_REAL=0, signal=Mock(side_effect=restore),
                    setitimer=Mock(side_effect=OSError("synthetic disarm error") if release_errors else None),
                )
                domain = Mock(side_effect=OSError("synthetic unknown finality")) if case == "unknown-domain" else Mock(return_value={})
                if case.startswith("prior"):
                    session.fail("first real failure")
                with patch.multiple(self.module, signal=fake_signal, _domain=domain,
                                    os=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)):
                    if case.startswith("prior") or case == "unknown-domain":
                        with self.assertRaises(self.module.SessionError):
                            session.close(keep_timer=True)
                    else:
                        session.close(keep_timer=True)
                    self.assertTrue(session.closed)
                    self.assertFalse(session._timer_finished)
                    fake_signal.setitimer.assert_not_called()
                    fake_signal.signal.assert_not_called()
                    with self.assertRaises(self.module.SessionError):
                        session._guard()  # Publication cannot admit another product command.
                    if case == "late-deadline":
                        clock.now = session.deadline
                    expected = ("first real failure" if case.startswith("prior") else
                                "close reserved-identity census is unknown" if case == "unknown-domain" else
                                "original timer/handler cleanup failed" if release_errors else
                                "original aggregate deadline expired" if case == "late-deadline" else None)
                    for _ in range(2):
                        if expected is None:
                            session.finish()
                        else:
                            with self.assertRaisesRegex(self.module.SessionError, expected):
                                session.finish()
                    self.assertEqual(session.failure, expected)
                    self.assertTrue(session._timer_finished)
                    self.assertEqual(session.deadline, 100.0)
                    fake_signal.setitimer.assert_called_once_with(0, 0)
                    self.assertEqual([c.args for c in fake_signal.signal.call_args_list],
                                     list(session._handlers.items()))
                    if release_errors:
                        self.assertIn("aggregate timer release OSError", session.cleanup_errors)
                        self.assertIn("owned signal handler restore 2 OSError", session.cleanup_errors)

    def test_selector_acquisition_failures_keep_custody_and_public_diagnostics_bounded(self):
        primary = OSError("synthetic-private-diagnostic-must-not-be-published")
        rig = _Collection(self.module)
        rig.session._admitting = True
        rig.selector_error = primary
        result = rig.collect()
        self.assertFalse(result.ok)
        self.assertEqual(result.primary_error, "collection OSError")
        self.assertEqual(rig.session.failure, result.primary_error)
        self.assertFalse(rig.session._busy)
        self.assertIsNone(rig.session._active)
        self.assertEqual(rig.opened, [])
        self.assertFalse(any(e[0] in {"popen", "selector-close"} for e in rig.events))
        self.assertFalse(result.waited or result.stdout_eof or result.stderr_eof or result.finality)
        note = rig.session.admission_results[0]
        self.assertEqual((note["name"], note["ok"]), ("collector-exception", False))
        self.assertEqual(note["exceptions"][0]["exception"], "OSError")
        self.assertNotIn(str(primary), json.dumps(note))

        # This retained function is the real metadata collector body. Its
        # complete OS/Popen/selector dependencies still come from rig.scope().
        small_command = self.module._small_command
        rig = _Collection(self.module)
        rig.exit_at = float("inf")
        rig.selector_error = primary
        rig.stream_close_errors = {0}
        with rig.scope():
            with self.assertRaises(BaseExceptionGroup) as caught:
                small_command(["/synthetic/metadata"], seconds=10, deadline=0.25)
        group = caught.exception
        self.assertIs(group.exceptions[0], primary)
        self.assertEqual(len(group.exceptions), 2)
        self.assertIsInstance(group.exceptions[1], OSError)
        self.assertIn(("kill-original",), rig.events)
        budget = next(e for e in rig.events if e[0] == "wait-budget")
        self.assertGreater(budget[1], 0)
        self.assertLessEqual(budget[1], 0.25 - budget[2] + 0.001001)
        self.assertIn(("stream-close", 0), rig.events)
        self.assertIn(("stream-close", 1), rig.events)
        self.assertNotIn(("selector-close",), rig.events)
        self.assertEqual(group._ci_observation,
                         {"returncode": -9, "waited": True, "stdout_eof": False,
                          "stderr_eof": False, "stdout_bytes": 0, "stderr_bytes": 0,
                          "error_count": 2, "exceptions": []})
        self.assertEqual(rig.domain_calls, 0)

        rig = _Collection(self.module)
        rig.now = 0.25
        with rig.scope(), self.assertRaises(self.module.DeadlineExpired):
            small_command(["/synthetic/metadata"], deadline=0.25)
        self.assertFalse(any(e[0] == "popen" for e in rig.events))

        for case in ("success", "timeout", "launch-consumed-cutoff", "poll-error", "kill-error", "late-wait-error"):
            with self.subTest(metadata=case):
                rig = _Collection(self.module)
                late_error = OSError(errno.EACCES, "synthetic permission error after launch")
                with rig.scope(), ExitStack() as changes:
                    if case == "timeout":
                        rig.hold = {0}
                        rig.exit_at = float("inf")
                    elif case == "launch-consumed-cutoff":
                        original_launch = rig.popen

                        def delayed_launch(*args, **kwargs):
                            child = original_launch(*args, **kwargs)
                            rig.now = 0.25
                            return child

                        changes.enter_context(patch.object(self.module.subprocess, "Popen", delayed_launch))
                    elif case in {"poll-error", "kill-error"}:
                        rig.selector_error = primary
                        rig.exit_at = float("inf")
                        changes.enter_context(patch.object(rig.child, "poll" if case == "poll-error" else "kill",
                                                           side_effect=late_error))
                        # An independently completed original can still be
                        # waited even if the stop attempt itself reported error.
                        owned_wait = changes.enter_context(patch.object(rig.child, "wait", return_value=-9))
                    elif case == "late-wait-error":
                        owned_wait = changes.enter_context(patch.object(rig.child, "wait", side_effect=[late_error, 0]))
                    if case == "success":
                        self.assertEqual(small_command(["/synthetic/metadata"], deadline=0.25, return_pid=True),
                                         (b"PASS\n", rig.child.pid))
                        self.assertIn(("unregister-eof", 0), rig.events)
                        self.assertIn(("unregister-eof", 1), rig.events)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as failed:
                            small_command(["/synthetic/metadata"], deadline=0.25)
                        observation = failed.exception._ci_observation
                        self.assertTrue(observation["waited"])
                        if case in {"poll-error", "kill-error"}:
                            self.assertEqual(failed.exception.exceptions, (primary, late_error))
                            owned_wait.assert_called_once()
                        elif case == "late-wait-error":
                            self.assertEqual(failed.exception.exceptions, (late_error,))
                            self.assertEqual(owned_wait.call_count, 2)
                        else:
                            self.assertTrue(any(isinstance(e, self.module.DeadlineExpired)
                                                for e in failed.exception.exceptions))
                        if case == "launch-consumed-cutoff":
                            self.assertNotIn(("selector-acquire",), rig.events)
                    if case in {"poll-error", "kill-error", "late-wait-error"}:
                        self.assertTrue(all(0 <= call.kwargs["timeout"] <= 0.25
                                            for call in owned_wait.call_args_list))
                for event in (("stream-close", 0), ("stream-close", 1)):
                    self.assertIn(event, rig.events)
                if case not in {"poll-error", "kill-error", "launch-consumed-cutoff"}:
                    self.assertIn(("selector-close",), rig.events)
                for _, allowance, recorded_now in (e for e in rig.events if e[0] == "wait-budget"):
                    # The fake clock advances one bookkeeping tick on read.
                    self.assertLessEqual(allowance, max(0.0, 0.25 - recorded_now + 0.001001))
                self.assertLess(rig.now, 0.3)  # No fresh ten-second metadata budget.

        tagged = {"code": "GROUP_COUNT", "errno": 1, "library_close_failed": True}
        raw_tag = b"MRK_PROCESS_V1 error GROUP_COUNT_1_AND_CLOSE\n"
        self.assertEqual(self.module._observer_error_note(raw_tag), tagged)
        self.assertEqual(self.module._observer_error_note(b"MRK_PROCESS_V1 error SELF_QUERY\n"),
                         {"code": "SELF_QUERY", "errno": None, "library_close_failed": False})
        for invalid in (b"prefix " + raw_tag, raw_tag + b"extra\n", raw_tag[:-1],
                        b"MRK_PROCESS_V1 error UNKNOWN_PRIVATE_VALUE\n",
                        b"MRK_PROCESS_V1 error GROUP_COUNT_4096\n", b"MRK_PROCESS_V1 error GROUP_SYMBOL_1\n"):
            self.assertIsNone(self.module._observer_error_note(invalid))
        for value in (tagged | {"errno": True}, tagged | {"private": "must-not-propagate"},
                      tagged | {"library_close_failed": 1}, tagged | {"code": "unknown"}):
            self.assertIsNone(self.module._observer_error_fields(value))
        rig = _Collection(self.module, stdout=(raw_tag,))
        rig.exit_at, rig.exitcode = 0.0, 3
        with rig.scope(), self.assertRaises(BaseExceptionGroup) as caught:
            small_command(["/synthetic/metadata"], deadline=0.25)
        self.assertEqual(caught.exception._ci_observation["returncode"], 3)
        self.assertTrue(caught.exception._ci_observation["waited"])
        self.assertEqual(caught.exception._ci_observation["observer_error"], tagged)
        record = {"exception": "ExceptionGroup", "lines": [7], "observation": {
            "observer_error": tagged, "raw_output": "synthetic-private-canary"}, "message": "synthetic-private-canary"}
        payload = b"MRK_SANDBOX_ERROR=" + json.dumps([record]).encode()
        self.assertEqual(self.module._child_exception_notes(payload), [{"exception": "ExceptionGroup", "lines": [7],
                         "observation": {"observer_error": tagged}}])
        record["observation"]["observer_error"] = tagged | {"errno": True}
        self.assertEqual(self.module._child_exception_notes(b"MRK_SANDBOX_ERROR=" + json.dumps([record]).encode()),
                         [{"exception": "ExceptionGroup", "lines": [7]}])

        many = ExceptionGroup("synthetic-private-group-message", [ValueError(str(primary)) for _ in range(80)])
        with patch.object(self.module, "os", SimpleNamespace(path=SimpleNamespace(basename=os.path.basename))):
            notes = self.module._exception_notes(many)
        self.assertEqual(len(notes), 32)
        self.assertTrue(all(set(n) == {"exception", "lines"} and len(n["lines"]) <= 16 for n in notes))
        self.assertNotIn(str(primary), json.dumps(notes))
        annotated = OSError(22, str(primary), "/synthetic/private")
        annotated._ci_operation = "kernel-groups-fill"
        self.assertEqual(self.module._exception_notes(annotated),
                         [{"exception": "OSError", "lines": [], "errno": 22, "operation": "kernel-groups-fill"}])
        for invalid_errno in (True, 0, -1, 4096, "22"):
            annotated.errno = invalid_errno
            annotated._ci_operation = str(primary)
            self.assertEqual(self.module._exception_notes(annotated), [{"exception": "OSError", "lines": []}])
        rows = [{"exception": "OSError", "lines": [7, 9], "message": str(primary), "path": "/synthetic/private"},
                {"exception": "Invalid Name", "lines": [7]}, {"exception": "OSError", "lines": [True]},
                {"exception": "OSError", "lines": [0]}, {"exception": "OSError", "lines": list(range(1, 18))}]
        prefix = b"MRK_SANDBOX_ERROR="
        payload = b"untrusted raw diagnostic\n" + prefix + b"not-json\n" + prefix + json.dumps(rows).encode() + b"\n"
        self.assertEqual(self.module._child_exception_notes(payload), [{"exception": "OSError", "lines": [7, 9]}])
        safe_fields = {"exception": "OSError", "lines": [7], "errno": 22, "operation": "kernel-groups-count"}
        record = safe_fields | {"message": str(primary), "path": "/synthetic/private"}
        self.assertEqual(self.module._child_exception_notes(prefix + json.dumps([record]).encode()), [safe_fields])
        for invalid_errno in (True, 0, -1, 4096, "22"):
            invalid = record | {"errno": invalid_errno, "operation": str(primary)}
            self.assertEqual(self.module._child_exception_notes(prefix + json.dumps([invalid]).encode()),
                             [{"exception": "OSError", "lines": [7]}])
        repeated = prefix + json.dumps([{"exception": "OSError", "lines": []}] * 80).encode() + b"\n"
        self.assertEqual(len(self.module._child_exception_notes(repeated)), 32)
        self.assertEqual(self.module._child_exception_notes(payload + b"x" * 16384), [])
        session = session_double(self.module)
        for number, text in ((2, "No such file or directory"), (13, "Permission denied")):
            data = f"{session.python}: can't open file '{session.entry}': [Errno {number}] {text}\n".encode()
            self.assertEqual(self.module._launcher_error(data, session.python, session.entry),
                             {"code": "python-script-open", "errno": number})
            for changed in (b"prefix " + data, data + b"extra diagnostics\n",
                            data.replace(str(session.python).encode(), b"/other/python"),
                            data.replace(str(session.entry).encode(), b"/other/script"),
                            data.replace(text.encode(), b"localized-or-unknown-message")):
                self.assertIsNone(self.module._launcher_error(changed, session.python, session.entry))

        # Explain only a completely collected failure from the actual fixed
        # Darwin Ruby admission role. A known launcher line cannot grant success
        # or replace the original failure, including its output accounting.
        literal_errors = ((errno.EPERM, "Operation not permitted"), (errno.EACCES, "Permission denied"),
                          (errno.ENOENT, "No such file or directory"), (errno.ENOEXEC, "Exec format error"),
                          (errno.ENOMEM, "Cannot allocate memory"), (errno.E2BIG, "Argument list too long"),
                          (errno.ETXTBSY, "Text file busy"))
        session = session_double(self.module, "darwin")
        session.ruby = Path("/synthetic/private-launch-canary/bin/ruby")
        session.failure = "earlier immutable failure"

        def failed_capture(stderr):
            return self.module.CapturedRun(b"", stderr, 71, True, True, True, True, False, False,
                                           0.01, "command exited 71", (), (0, len(stderr)))

        def noted(result, *, platform="darwin", name="ruby-numerical-identity"):
            session.platform = platform
            before = len(session.admission_results)
            with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                signal=SimpleNamespace(), socket=SimpleNamespace()), \
                 patch.object(Path, "stat", side_effect=AssertionError("capture diagnostics may not restat tools")), \
                 patch.object(Path, "resolve", side_effect=AssertionError("capture diagnostics may not resolve tools")):
                row = session._note_capture(name, result)
            self.assertIs(row, session.admission_results[-1])
            self.assertEqual(len(session.admission_results), before + 1)
            self.assertFalse(row["ok"])
            self.assertFalse(row["subject_ok"])
            self.assertFalse(result.ok)
            self.assertEqual(session.failure, "earlier immutable failure")
            public = json.dumps(row)
            self.assertNotIn("private-launch-canary", public)
            self.assertNotIn("sandbox-exec: execvp()", public)
            self.assertNotIn("unpublished-extra-diagnostic", public)
            return row

        for number, message in literal_errors:
            data = f"sandbox-exec: execvp() of '{session.ruby}' failed: {message}\n".encode()
            with self.subTest(ruby_launcher_errno=number):
                result = failed_capture(data)
                row = noted(result)
                self.assertEqual(row["launcher_error"], {"operation": "sandbox-execvp", "role": "ruby", "errno": number})
                self.assertEqual(row["error_count"], 1)
                self.assertEqual(row["persisted"], [0, len(data)])
                self.assertEqual(result.primary_error, "command exited 71")
        data = f"sandbox-exec: execvp() of '{session.ruby}' failed: Operation not permitted\n".encode()
        malformed = (b"", data[:-1], data + b"unpublished-extra-diagnostic\n", b"prefix " + data,
                     data + data, data.replace(str(session.ruby).encode(), b"/synthetic/other/bin/ruby"),
                     data.replace(b"Operation not permitted", b"localized-or-unknown-message"),
                     data.replace(b"\n", b"\r\n"), data + b"\0", b"\xff" + data,
                     b"sandbox-exec: sandbox_apply: Operation not permitted\n")
        for index, raw in enumerate(malformed):
            with self.subTest(ruby_launcher_text=index):
                self.assertNotIn("launcher_error", noted(failed_capture(raw)))
        for changed in ({"returncode": 72}, {"returncode": None}, {"stdout": b"unexpected stdout"},
                        {"waited": False}, {"stdout_eof": False}, {"stderr_eof": False}, {"domain_finality": False},
                        {"timed_out": True}, {"cancelled": True}, {"cleanup_errors": ("synthetic close ambiguity",)},
                        {"primary_error": "per-stream or whole-attempt persisted-output limit"}, {"primary_error": None},
                        {"persisted": (0, len(data) - 1)}, {"persisted": (0, len(data) + 1)},
                        {"persisted": (0, None)}, {"persisted": (1, len(data))}):
            with self.subTest(ruby_launcher_receipt=changed):
                self.assertNotIn("launcher_error", noted(dataclasses.replace(failed_capture(data), **changed)))
        for platform, name in (("linux", "ruby-numerical-identity"), ("darwin", "native-isolation"),
                               ("darwin", "ruby-numerical-identity-extra")):
            with self.subTest(ruby_launcher_role=(platform, name)):
                self.assertNotIn("launcher_error", noted(failed_capture(data), platform=platform, name=name))

    def test_admission_listener_teardown_attempts_every_owned_close_and_retains_primary(self):
        session = session_double(self.module)
        primary = self.module.SessionError("synthetic admission failure")
        cleanup = {0: OSError("synthetic listener zero close"), 2: OSError("synthetic listener two close")}
        created, closed, events = [], [], []
        outside_error = None

        class Endpoint:
            def __init__(self, role, index, family, kind):
                self.role, self.index = role, index
                self.family, self.type = family, kind
                self.address = None
                self.nonblocking = False

            def settimeout(self, _seconds):
                pass

            def bind(self, address):
                self.address = (address[0], 42000 + self.index)

            def getsockname(self):
                return self.address

            def listen(self, _backlog):
                pass

            def connect(self, _address):
                pass

            def accept(self):
                if self.nonblocking:
                    raise BlockingIOError(errno.EAGAIN, "synthetic empty listener")
                events.append(("positive-consumed", self.index))
                return Endpoint("accepted", self.index, self.family, self.type), ("synthetic-peer", 1)

            def sendto(self, _data, _address):
                return len(_data)

            def recv(self, _size):
                if self.nonblocking:
                    raise BlockingIOError(errno.EWOULDBLOCK, "synthetic empty listener")
                events.append(("positive-consumed", self.index))
                return b"owned-control"

            def setblocking(self, blocking):
                self.nonblocking = not blocking
                events.append(("outside-observation", self.index))
                if outside_error is not None and self.index == 0:
                    raise outside_error

            def close(self):
                closed.append((self.role, self.index))
                if self.role == "listener" and self.index in cleanup:
                    raise cleanup[self.index]

            def __enter__(self):
                return self

            def __exit__(self, *_exception):
                self.close()

        def socket_factory(family, kind):
            if len(created) >= 8:
                raise AssertionError("only four synthetic listener/positive pairs are admitted")
            endpoint = Endpoint("listener" if len(created) % 2 == 0 else "positive", len(created) // 2, family, kind)
            created.append(endpoint)
            return endpoint

        fake_socket = SimpleNamespace(AF_INET=2, AF_INET6=10, AF_UNIX=1, SOCK_STREAM=1, SOCK_DGRAM=2, socket=socket_factory)
        fake_os = SimpleNamespace(chown=Mock(), readlink=lambda _: "synthetic-namespace")

        def read_positive(path):
            if path != session.outside_write:
                raise AssertionError("no actual file reads are permitted")
            return b"MRK_POSITIVE_WRITE\n"

        with patch.multiple(self.module, os=fake_os, socket=fake_socket,
                            subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                            time=SimpleNamespace(monotonic=lambda: 0.0),
                            _domain=Mock(side_effect=AssertionError("no census is permitted")),
                            _small_command=Mock(return_value=b"MRK_OUTSIDE_WRITE_POSITIVE\n")), \
             patch.object(session, "ensure_idle", return_value=None), \
             patch.object(session, "_assert_userns_boundary", Mock()) as userns, \
             patch.object(session, "_run", side_effect=primary) as run, \
             patch.object(Path, "read_bytes", read_positive), \
             patch.object(Path, "stat", side_effect=AssertionError("failed native prefix cannot inspect Ruby metadata")), \
             patch.object(Path, "chmod", side_effect=AssertionError("failed admission cannot adopt output")) as chmod:
            with self.assertRaises(BaseExceptionGroup) as caught:
                session._preflight()
        self.assertEqual(caught.exception.exceptions, (primary, cleanup[0], cleanup[2]))
        run.assert_called_once()
        userns.assert_called_once_with()
        self.assertIn("--probe", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs["latch"])
        self.assertEqual([entry for entry in closed if entry[0] == "listener"],
                         [("listener", index) for index in range(4)])
        self.assertEqual(len([entry for entry in closed if entry[0] == "positive"]), 4)
        self.assertEqual(len([entry for entry in closed if entry[0] == "accepted"]), 2)
        fake_os.chown.assert_called_once_with(session.outside_write, session.uid, session.gid)
        chmod.assert_not_called()

        # Invoke the actual original-handle collector under its complete fake
        # dependencies, then the actual outside-receiver check.  A private stop
        # at the next Ruby probe keeps this a caller-order test, not admission.
        class AfterNative(RuntimeError):
            pass

        cases = ("ordered", "waited", "stdout_eof", "stderr_eof", "domain_finality", "outside-error", "ruby-metadata-error",
                 "home-positive-error", "home-non-delivery-error")
        actual_home_empty = self.module._home_socket_empty
        for platform, case in ((p, c) for p in ("linux", "darwin") for c in cases
                               if p == "darwin" or c not in {"home-positive-error", "home-non-delivery-error"}):
            with self.subTest(native_boundary=(platform, case)):
                session = session_double(self.module, platform)
                if platform == "darwin":
                    session.runner_home = Path("/Users/runner")
                    session.ruby = session.runner_home / "tools/ruby/bin/ruby"
                    session.ruby_prefix = session.ruby.parent.parent
                    session.ruby_ancestors = (session.runner_home, session.ruby_prefix.parent)
                    session.tool_prefixes = (session.python.parent.parent, session.ruby_prefix)
                rig = _Collection(self.module, session, stdout=(b"MRK_NATIVE_ISOLATION_OK\n",))
                rig.snapshot_rows = {(rig.child.pid, rig.child.pid): ((session.uid,) * 3, (session.gid,) * 3, 65536)}
                created, closed, events, cleanup = [], [], rig.events, {}
                outside_error = OSError(errno.EIO, "synthetic unknown receiver") if case == "outside-error" else None
                native_run = session._run
                stop = AfterNative("end of the explicitly inert native-prefix test")
                metadata_error = OSError(errno.EACCES, "synthetic Ruby metadata observation failure")
                ruby_paths = [session.ruby, *session.ruby.parents]
                metadata_seen = []
                home_error = OSError(errno.EIO, "synthetic owned HOME admission control")
                admission_idle = [("domain", 1), ("domain-deadline", 1, session.deadline)]

                def home_positive():
                    self.assertEqual(platform, "darwin")
                    self.assertEqual(events, admission_idle)
                    events.append(("home-positive",))
                    if case == "home-positive-error":
                        raise home_error

                def write_positive(*_argv, **_options):
                    self.assertEqual(events, admission_idle + ([("home-positive",)] if platform == "darwin" else []))
                    self.assertEqual(session._assert_userns_boundary.call_count, int(platform == "linux"))
                    events.append(("write-positive",))
                    return b"MRK_OUTSIDE_WRITE_POSITIVE\n"

                def home_accept():
                    if case == "home-non-delivery-error":
                        raise home_error
                    raise BlockingIOError(errno.EAGAIN, "synthetic empty original HOME listener")

                home_listener = SimpleNamespace(family=1, type=1, setblocking=Mock(), accept=Mock(side_effect=home_accept), close=Mock())
                session._home_state = {"listener": home_listener} if platform == "darwin" else None

                def home_empty(listener, *, deadline):
                    self.assertIs(listener, home_listener)
                    self.assertEqual(deadline, session.deadline)
                    self.assertEqual(len([e for e in events if e[0] == "outside-observation"]), 4)
                    self.assertIsNone(session._active)
                    self.assertTrue(session.domain_finality)
                    self.assertFalse(next(n for n in session.admission_results if n["name"] == "native-isolation")["ok"])
                    self.assertLess(max(i for i, e in enumerate(events) if e[0] == "wait-original"),
                                    max(i for i, e in enumerate(events) if e[0] == "domain"))
                    self.assertEqual({e[1] for e in events if e[0] == "unregister-eof"}, {0, 1})
                    events.append(("home-non-delivery",))
                    return actual_home_empty(listener, deadline=deadline)

                def ruby_metadata(path):
                    self.assertEqual(path, ruby_paths[len(metadata_seen)])
                    metadata_seen.append(path)
                    self.assertEqual(len([e for e in events if e[0] == "outside-observation"]), 4)
                    if platform == "darwin":
                        self.assertIn(("home-non-delivery",), events)
                    events.append(("ruby-metadata", len(metadata_seen) - 1))
                    if case == "ruby-metadata-error":
                        raise metadata_error
                    # Deliberately nonexecutable, subject-owned and writable:
                    # observing these bits must not introduce a new Ruby gate.
                    return SimpleNamespace(st_uid=session.uid, st_gid=session.gid, st_mode=stat.S_IFREG | 0o6666)

                def collect_prefix(argv, **kwargs):
                    if "--probe" not in argv:
                        self.assertEqual(argv, [str(session.ruby), "-e",
                            f"abort unless Process.uid == {session.uid} && Process.gid == {session.gid}; puts 'MRK_RUBY_NUMERIC_OK'"])
                        self.assertEqual(kwargs, {"cwd": session.work, "env": {}, "seconds": 10, "latch": False})
                        self.assertEqual(metadata_seen, ruby_paths)
                        self.assertTrue(next(n for n in session.admission_results if n["name"] == "ruby-path-metadata")["ok"])
                        events.append(("ruby-probe",))
                        raise stop
                    self.assertEqual([e[1] for e in events if e[0] == "positive-consumed"], list(range(4)))
                    self.assertEqual(argv[:6], [str(session.python), "-I", "-S", "-B", str(session.entry), "--probe"])
                    data = json.loads(argv[6])
                    self.assertEqual((data["uid"], data["gid"], data["platform"]), (session.uid, session.gid, platform))
                    if platform == "darwin":
                        self.assertEqual((data["home_canary"], data["home_socket"]),
                            (str(session.runner_home / f".{session.root.name}-home-read"), str(session.runner_home / f".{session.root.name}-home-socket")))
                        self.assertEqual((data["ruby_prefix"], data["ruby_executable"], data["home_sibling"]),
                            (str(session.ruby_prefix), str(session.ruby), str(session.ruby_prefix.parent / f".{session.root.name}-ancestor-read")))
                        self.assertNotIn("ruby_ancestors", data)  # Child derives finite literals, never accepts a reader list.
                        self.assertNotIn("runtime_executables", data)
                        self.assertLess(events.index(("home-positive",)), events.index(("write-positive",)))
                    else:
                        self.assertEqual(data["runtime_executables"], [str(session.python), str(session.ruby)])
                        self.assertNotIn("home_canary", data)
                        self.assertNotIn("home_socket", data)
                    result = native_run(argv, **kwargs)
                    self.assertTrue(result.ok, result)
                    return dataclasses.replace(result, **{case: False}) if case in {
                        "waited", "stdout_eof", "stderr_eof", "domain_finality",
                    } else result

                with rig.scope(), patch.object(self.module, "socket", fake_socket), \
                     patch.object(self.module.os, "chown", create=True) as chown, \
                     patch.object(self.module.os, "readlink", return_value="synthetic-namespace", create=True), \
                     patch.object(self.module.os, "fsencode", os.fsencode, create=True), \
                     patch.object(self.module, "_small_command", side_effect=write_positive), \
                     patch.object(self.module, "_home_socket_empty", side_effect=home_empty) as home_negative, \
                     patch.object(self.module, "_admit_executable", side_effect=AssertionError("Ruby metadata grants no new admission role")), \
                     patch.object(session, "_home_positive_control", side_effect=home_positive) as home_control, \
                     patch.object(session, "_run", side_effect=collect_prefix), \
                     patch.object(Path, "read_bytes", read_positive), \
                     patch.object(Path, "stat", ruby_metadata), \
                     patch.object(Path, "resolve", side_effect=AssertionError("no provider path resolution is permitted")), \
                     patch.object(Path, "chmod") as chmod:
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        session._preflight()
                self.assertEqual(home_control.call_count, int(platform == "darwin"))
                home_listener.close.assert_not_called()
                if case == "home-positive-error":
                    self.assertEqual(caught.exception.exceptions, (home_error,))
                    self.assertEqual(events, admission_idle + [("home-positive",)])
                    self.assertEqual(created, [])
                    self.assertFalse(session.admission_results)
                    chown.assert_not_called()
                    chmod.assert_not_called()
                    home_negative.assert_not_called()
                    continue
                seen = [i for i, event in enumerate(events) if event[0] == "outside-observation"]
                note = next(n for n in session.admission_results if n["name"] == "native-isolation")
                self.assertEqual([entry for entry in closed if entry[0] == "listener"],
                                 [("listener", index) for index in range(4)])
                if case in {"ordered", "outside-error", "ruby-metadata-error", "home-non-delivery-error"}:
                    self.assertEqual(len(seen), 4)
                    for event_name in ("wait-original", "unregister-eof", "domain"):
                        self.assertLess(max(i for i, event in enumerate(events) if event[0] == event_name), seen[0])
                    self.assertIsNone(session._active)
                else:
                    self.assertEqual(seen, [])
                self.assertEqual(home_negative.call_count, int(platform == "darwin" and case in
                    {"ordered", "ruby-metadata-error", "home-non-delivery-error"}))
                if case in {"ordered", "ruby-metadata-error"}:
                    self.assertEqual(caught.exception.exceptions, (stop if case == "ordered" else metadata_error,))
                    self.assertTrue(note["ok"])
                    self.assertEqual([c.args for c in chown.call_args_list],
                                     [(session.outside_write, session.uid, session.gid), (session.outside_write, 0, 0)])
                    chmod.assert_called_once_with(0o400)
                    metadata_note = next(n for n in session.admission_results if n["name"] == "ruby-path-metadata")
                    self.assertEqual(metadata_note["ok"], case == "ordered")
                    if case == "ordered":
                        self.assertEqual(metadata_seen, ruby_paths)
                        self.assertLess(max(i for i, e in enumerate(events) if e[0] == "ruby-metadata"), events.index(("ruby-probe",)))
                    else:
                        self.assertEqual(metadata_seen, [session.ruby])
                        self.assertEqual(metadata_note["entries"], [])
                        self.assertEqual(metadata_note["unobserved_index"], 0)
                        self.assertNotIn(("ruby-probe",), events)
                else:
                    self.assertFalse(note["ok"])
                    chown.assert_called_once_with(session.outside_write, session.uid, session.gid)
                    chmod.assert_not_called()
                    self.assertEqual(metadata_seen, [])
                    self.assertFalse(any(n["name"] == "ruby-path-metadata" for n in session.admission_results))

    def test_collection_keeps_streams_separate_waits_and_persists_short_writes(self):
        rig = _Collection(self.module, stdout=(b"out-1", b"out-2"), stderr=(b"err-1",))
        rig.write_step = 2
        result = rig.collect()
        self.assertTrue(result.ok, result)
        self.assertEqual((result.stdout, result.stderr), (b"out-1out-2", b"err-1"))
        self.assertEqual(result.persisted, (10, 5))
        self.assertEqual(rig.session.persisted_bytes, 15)
        self.assertEqual((bytes(rig.captures[100]), bytes(rig.captures[101])), (result.stdout, result.stderr))
        self.assertEqual(rig.domain_calls, 2)
        self.assertIn(("unregister-eof", 0), rig.events)
        self.assertIn(("unregister-eof", 1), rig.events)
        wait = next(i for i, e in enumerate(rig.events) if e[0] == "wait-original")
        final = rig.events.index(("domain", 2))
        self.assertLess(wait, final)
        self.assertIsNone(rig.session._active)
        self.assertFalse(rig.session._busy)
        self.assertIsNone(rig.session.failure)
        call = next(e for e in rig.events if e[0] == "popen")
        self.assertTrue(call[2]["close_fds"])
        self.assertTrue(call[2]["start_new_session"])
        self.assertEqual(call[2]["stdin"], -3)

    def test_nonzero_is_latched_before_first_read_and_pass_text_cannot_recover(self):
        rig = _Collection(self.module)
        rig.exit_at, rig.exitcode = 0.0, 7
        result = rig.collect()
        self.assertEqual(result.stdout, b"PASS\n")
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.ok)
        self.assertEqual(result.primary_error, "command exited 7")
        self.assertEqual(rig.session.failure, result.primary_error)
        first_read = next(e for e in rig.events if e[0] == "read")
        self.assertEqual(first_read[3], "command exited 7")
        self.assertTrue(result.stdout_eof and result.stderr_eof and result.waited and result.finality)
        opened = len(rig.opened)
        with self.assertRaises(self.module.SessionError):
            rig.collect()
        self.assertEqual(len(rig.opened), opened)

    def test_cap_plus_one_drains_to_real_eof_and_aggregate_cap_is_not_renewed(self):
        for total_cap in (False, True):
            with self.subTest(total_cap=total_cap):
                rig = _Collection(self.module, stdout=(b"abcdefghi", b"more"), stderr=())
                initial = self.module.CAPTURE_TOTAL - 4 if total_cap else 0
                rig.session.persisted_bytes = initial
                result = rig.collect(output_limit=64 if total_cap else 4)
                self.assertFalse(result.ok)
                self.assertIn("persisted-output limit", result.primary_error)
                self.assertEqual(result.stdout, b"abcd")
                self.assertEqual(result.persisted, (4, 0))
                self.assertEqual(rig.session.persisted_bytes, initial + 4)
                self.assertEqual(bytes(rig.captures[100]), b"abcd")
                self.assertEqual(rig.chunks, [[], []])
                self.assertTrue(result.stdout_eof and result.stderr_eof and result.finality)
                self.assertEqual(result.cleanup_errors, ())
                self.assertTrue(all(e[2] > 0 for e in rig.events if e[0] == "read"))

    def test_persisted_after_effects_and_independent_late_cleanup_errors_fail(self):
        rig = _Collection(self.module, stdout=(b"abcdef",))
        rig.write_step, rig.after_write_error = 2, 0
        result = rig.collect()
        self.assertFalse(result.ok)
        self.assertEqual(result.primary_error, "collection OSError")
        self.assertEqual(result.persisted, (2, 0))
        self.assertEqual(rig.session.persisted_bytes, 2)
        self.assertIn("capture persisted length differs from returned bytes", result.cleanup_errors)
        for initial_failure in (False, True):
            with self.subTest(initial_failure=initial_failure):
                rig = _Collection(self.module)
                rig.exit_at, rig.exitcode = 0.0, 7 if initial_failure else 0
                rig.stream_close_errors = {0}
                rig.selector_close_error = True
                rig.fsync_errors, rig.fstat_errors, rig.fd_close_errors = {0, 1}, {1}, {0}
                if initial_failure:
                    rig.cleanup_diagnostics = ["synthetic numerical cleanup error"]
                result = rig.collect()
                wanted = "command exited 7" if initial_failure else "late capture/cleanup/finality error"
                self.assertEqual(result.primary_error, wanted)
                self.assertEqual(rig.session.failure, wanted)
                self.assertFalse(result.ok)
                self.assertEqual(result.persisted, (5, None))
                for text in ("stream close OSError", "selector close OSError", "capture fsync OSError",
                             "capture persist OSError", "capture close OSError"):
                    self.assertIn(text, result.cleanup_errors)
                self.assertEqual(rig.session.cleanup_errors, list(result.cleanup_errors))
                for event in (("stream-close", 1), ("capture-fsync", 101), ("capture-close", 101)):
                    self.assertIn(event, rig.events)

    def test_original_wait_eof_and_domain_unknowns_each_prevent_success(self):
        for case in ("held-stdout", "unreapable", "wait-error", "remaining-domain", "unknown-domain"):
            with self.subTest(case=case):
                rig = _Collection(self.module)
                if case == "held-stdout":
                    rig.hold = {0}
                elif case == "unreapable":
                    rig.unreapable = True
                elif case == "wait-error":
                    rig.wait_error = True
                elif case == "remaining-domain":
                    rig.final_domain = {"synthetic-owned-process": 1}
                else:
                    rig.final_domain = OSError("synthetic census failure")
                result = rig.collect(seconds=0.2)
                self.assertFalse(result.ok)
                self.assertIsNotNone(rig.session.failure)
                if case == "held-stdout":
                    self.assertFalse(result.stdout_eof)
                    self.assertTrue(result.waited)
                elif case == "unreapable":
                    self.assertFalse(result.waited)
                    self.assertFalse(result.finality)
                    self.assertIs(rig.session._active, rig.child)
                    self.assertIn("original child wait TimeoutError", result.cleanup_errors)
                elif case == "wait-error":
                    self.assertIn("original child wait OSError", result.cleanup_errors)
                else:
                    self.assertFalse(result.finality)
                self.assertLessEqual(rig.select_calls, 512)

    def test_original_timeout_cancellation_and_late_events_latch_failure(self):
        for case in ("aggregate", "relative-timeout", "cancel", "late-timeout", "late-cancel"):
            with self.subTest(case=case):
                rig = _Collection(self.module)
                seconds = 1.0
                if case == "aggregate":
                    rig.session.deadline = 0.2
                    rig.exit_at, rig.terminate_exits = float("inf"), False
                    seconds = 10.0
                elif case == "relative-timeout":
                    rig.exit_at, rig.terminate_exits = float("inf"), False
                    seconds = 0.2
                elif case == "cancel":
                    rig.exit_at, rig.cancel_at = float("inf"), 0.08
                elif case == "late-timeout":
                    rig.final_time = 2.0
                else:
                    rig.cancel_on_finality = True
                result = rig.collect(seconds=seconds)
                self.assertFalse(result.ok)
                self.assertIsNotNone(rig.session.failure)
                self.assertEqual(result.timed_out, case in {"aggregate", "relative-timeout", "late-timeout"})
                self.assertEqual(result.cancelled, case in {"cancel", "late-cancel"})
                if case == "aggregate":
                    self.assertEqual(rig.session.deadline, 0.2)
                    # An exhausted aggregate endpoint cannot acquire another
                    # second of TERM grace. Finalization still owns the exact
                    # original handle and attempts kill/wait0 and all closes.
                    self.assertNotIn(("terminate-original",), rig.events)
                    self.assertEqual(rig.events.count(("kill-original",)), 1)
                    self.assertEqual(len([e for e in rig.events if e[0] == "wait-budget"]), 1)
                    self.assertTrue(all(e[1] == 0.0 for e in rig.events if e[0] == "wait-budget"))
                    self.assertIn(("selector-close",), rig.events)
                    self.assertEqual([e for e in rig.events if e[0] == "capture-close"],
                                     [("capture-close", 100), ("capture-close", 101)])
                    self.assertFalse(result.finality or rig.session.domain_finality)
                    self.assertLess(result.duration, 1.0)
                elif case == "relative-timeout":
                    # The original staged cleanup remains available while the
                    # original aggregate deadline still has real headroom.
                    self.assertEqual(rig.session.deadline, 100.0)
                    term = rig.events.index(("terminate-original",))
                    kill = rig.events.index(("kill-original",))
                    self.assertLess(term, kill)
                    self.assertGreaterEqual(result.duration, 1.0)
                with self.assertRaises(self.module.SessionError):
                    rig.collect()

    def test_absolute_deadline_validation_and_preparation_expiry_precede_any_capture(self):
        for endpoint in (True, False, 0, -1.0, float("nan"), float("inf"), -float("inf"),
                         "0.5", 100.001):
            with self.subTest(invalid_absolute_endpoint=repr(endpoint)):
                rig = _Collection(self.module)
                with rig.scope(), patch.object(Path, "stat", side_effect=AssertionError("invalid endpoint may not observe files")), \
                     patch.object(Path, "open", side_effect=AssertionError("invalid endpoint may not open files")), \
                     patch.object(self.module, "_canonical", side_effect=AssertionError("invalid endpoint may not resolve paths")) as canonical:
                    with self.assertRaises(self.module.SessionError):
                        rig.session.run([str(rig.session.python), "--synthetic"], cwd=rig.session.work,
                            env={}, seconds=1.0, absolute_deadline=endpoint)
                    rig.session._argv.assert_not_called()
                    canonical.assert_not_called()
                self.assertEqual(rig.opened, [])
                self.assertFalse(any(e[0] == "popen" for e in rig.events))
                self.assertIsNone(rig.session._active)
                self.assertFalse(rig.session._busy)
                self.assertEqual(rig.session.deadline, 100.0)

        for case in ("expired-entry", "preparation-consumed-budget"):
            with self.subTest(absolute_preacquisition=case):
                rig = _Collection(self.module)
                if case == "expired-entry":
                    rig.now = 0.5

                def prepare(*_args, **_kwargs):
                    rig.events.append(("preparation-consumed",))
                    rig.now = 0.5  # Exactly the gate's old endpoint, not a new allowance.
                    return ["/synthetic/entry"], {}

                with rig.scope():
                    rig.session._argv.side_effect = prepare
                    with self.assertRaises(self.module.DeadlineExpired):
                        rig.session.run([str(rig.session.python), "--synthetic"], cwd=rig.session.work,
                            env={}, seconds=900, absolute_deadline=0.5)
                    self.assertEqual(rig.session._argv.call_count, int(case == "preparation-consumed-budget"))
                self.assertEqual(rig.opened, [])
                self.assertFalse(any(e[0] == "popen" for e in rig.events))
                self.assertIsNotNone(rig.session.failure)
                self.assertIsNone(rig.session._active)
                self.assertFalse(rig.session._busy)
                self.assertEqual(rig.session.deadline, 100.0)

    def test_absolute_deadline_bounds_collection_finality_and_second_phase_without_renewal(self):
        for case in ("absolute-tighter", "relative-tighter", "integer-endpoint", "late-finality", "expired-before-spawn"):
            with self.subTest(absolute_collection=case):
                session = session_double(self.module, "darwin")
                rig = _Collection(self.module, session)
                rig.snapshot_rows = {(rig.child.pid, rig.child.pid): ((session.uid,) * 3, (session.gid,) * 3, 65536)}
                endpoint = 1 if case == "integer-endpoint" else 0.5
                seconds = 0.2 if case == "relative-tighter" else 900
                if case == "late-finality":
                    rig.final_time = endpoint
                elif case == "expired-before-spawn":
                    rig.fsync_errors, rig.fd_close_errors = {0}, {1}
                original_open = rig.open

                def opened(*args):
                    fd = original_open(*args)
                    if case == "expired-before-spawn" and len(rig.opened) == 2:
                        rig.now = endpoint
                    return fd

                with rig.scope(), patch.object(self.module.os, "open", side_effect=opened):
                    result = session.run([str(session.python), "--synthetic"], cwd=session.work, env={},
                                         seconds=seconds, output_limit=64, absolute_deadline=endpoint)
                self.assertEqual(result.ok, case not in {"late-finality", "expired-before-spawn"}, result)
                self.assertEqual(session.deadline, 100.0)
                self.assertIsNone(session._active)
                self.assertFalse(session._busy)
                self.assertIn(("domain-deadline", 1, endpoint), rig.events)
                if case == "expired-before-spawn":
                    self.assertFalse(any(e[0] in {"popen", "root-snapshot", "wait-original"} for e in rig.events))
                    self.assertFalse(result.waited)
                    self.assertFalse(result.stdout_eof or result.stderr_eof or result.finality)
                    self.assertEqual(result.persisted, (0, 0))
                    self.assertEqual(session.persisted_bytes, 0)
                    self.assertEqual([e for e in rig.events if e[0] == "capture-close"],
                                     [("capture-close", 100), ("capture-close", 101)])
                    self.assertIn("capture fsync OSError", result.cleanup_errors)
                    self.assertIn("capture close OSError", result.cleanup_errors)
                    self.assertEqual(session.failure, result.primary_error)
                    self.assertEqual(session.cleanup_errors, list(result.cleanup_errors))
                else:
                    observations = [e[1] for e in rig.events if e[0] == "root-snapshot"]
                    self.assertEqual(len(observations), 1)
                    cutoff = observations[0]
                    if case == "relative-tighter":
                        self.assertLess(cutoff, endpoint)
                        self.assertGreaterEqual(cutoff, seconds)
                    else:
                        self.assertEqual(cutoff, endpoint)
                    self.assertTrue(all(e[2] <= cutoff for e in rig.events
                                        if e[0] == "domain-deadline" and e[1] > 1))
                    self.assertTrue(result.waited and result.stdout_eof and result.stderr_eof)
                    self.assertEqual(result.persisted, (5, 0))
                if case in {"late-finality", "expired-before-spawn"}:
                    self.assertTrue(result.timed_out)
                    self.assertIsNotNone(session.failure)

        # Two genuine in-memory captures share ONE old endpoint. The second
        # enters after most preparation time has elapsed; it cannot renew900s.
        session = session_double(self.module)
        session.deadline = 1500.0
        first = _Collection(self.module, session, stdout=(b"first phase\n",))
        first.now, first.exit_at = 100.0, 100.08
        first_result = first.collect(seconds=900, absolute_deadline=900.0)
        self.assertTrue(first_result.ok, first_result)
        first_persisted = session.persisted_bytes
        second = _Collection(self.module, session, stdout=(b"second phase\n",))
        second.now, second.exit_at = 899.8, 900.5
        second_result = second.collect(seconds=900, absolute_deadline=900.0)
        self.assertIsNot(first_result, second_result)
        self.assertFalse(second_result.ok)
        self.assertTrue(second_result.timed_out)
        self.assertLess(second_result.duration, 2.0)
        self.assertEqual(session.deadline, 1500.0)
        self.assertEqual(session._run_number, 2)
        self.assertEqual(session.persisted_bytes, first_persisted + len(b"second phase\n"))
        self.assertTrue(all(e[1] <= 900.0 for e in second.events if e[0] == "cleanup-deadline"))
        self.assertTrue(all(e[2] <= 900.0 for e in second.events if e[0] == "domain-deadline" and e[1] > 1))
        self.assertIsNotNone(session.failure)
        with self.assertRaises(self.module.SessionError):
            _Collection(self.module, session).collect(seconds=900, absolute_deadline=900.0)

    def test_expected_negative_subject_isolated_but_cannot_rehabilitate_real_failure(self):
        session = session_double(self.module)
        negative = _Collection(self.module, session)
        negative.exit_at, negative.exitcode = 0.0, 7
        result = negative.collect(latch=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.primary_error, "command exited 7")
        self.assertEqual(result.cleanup_errors, ())
        self.assertIsNone(session.failure)
        self.assertTrue(_Collection(self.module, session).collect().ok)
        real = _Collection(self.module, session)
        real.exit_at, real.exitcode = 0.0, 9
        self.assertFalse(real.collect().ok)
        self.assertEqual(session.failure, "command exited 9")
        with self.assertRaises(self.module.SessionError):
            _Collection(self.module, session).collect(latch=False)
        self.assertEqual(session.failure, "command exited 9")

    def test_mac_original_credentials_precede_any_reap_and_all_censuses_keep_the_cutoff(self):
        for case in ("live", "zombie", "missing", "saved-uid", "saved-gid", "census-error", "census-expired"):
            with self.subTest(original_observation=case):
                session = session_double(self.module, "darwin")
                session.deadline = 0.5
                session._admitting = True
                rig = _Collection(self.module, session)
                uids, gids = (session.uid,) * 3, (session.gid,) * 3
                if case == "saved-uid":
                    uids = (session.uid, session.uid, 0)
                if case == "saved-gid":
                    gids = (session.gid, session.gid, 0)
                rig.snapshot_rows = {(rig.child.pid, rig.child.pid): (uids, gids, 65536)}
                if case == "zombie":
                    rig.exit_at = 0.0  # Original has exited, but no owner poll/wait has occurred.
                elif case == "missing":
                    rig.snapshot_rows = {}
                elif case == "census-error":
                    rig.snapshot_error = OSError(errno.EIO, "synthetic root census failure")
                elif case == "census-expired":
                    rig.snapshot_advance = 0.6
                result = rig.collect()
                observed = [(i, event) for i, event in enumerate(rig.events) if event[0] == "root-snapshot"]
                self.assertEqual(len(observed), 1)
                index, event = observed[0]
                self.assertEqual(event[1], 0.5)
                self.assertIs(event[2], rig.child)  # Strong original-handle custody, not just a PID match.
                self.assertTrue(any(e[0] == "popen" for e in rig.events[:index]))
                self.assertTrue(all(index < i for i, e in enumerate(rig.events) if e[0] in {"poll", "wait-original"}))
                self.assertEqual(result.ok, case in {"live", "zombie"}, result)
                self.assertTrue(all(e[2] == 0.5 for e in rig.events if e[0] == "domain-deadline"))
                for _, allowance, recorded_now in (e for e in rig.events if e[0] == "wait-budget"):
                    self.assertLessEqual(allowance, max(0.0, 0.5 - recorded_now + 0.001001))
                if case not in {"live", "zombie"}:
                    self.assertEqual(session.failure, result.primary_error)
                    self.assertTrue(any(e[0] == "cleanup" for e in rig.events))
                    self.assertTrue(all(e[1] == 0.5 for e in rig.events if e[0] == "cleanup-deadline"))
                    self.assertEqual(result.timed_out, case == "census-expired")
                    notes = next(n["exceptions"] for n in session.admission_results
                                 if n["name"] == "collector-exception")
                    self.assertEqual(notes[0]["operation"], "mac-original-credentials")
                    if case != "census-expired":
                        self.assertTrue(result.waited and result.finality)
                        self.assertFalse(result.ok)  # A later empty cleanup census cannot repair observation.
                    with self.assertRaises(self.module.SessionError):
                        rig.collect()

        # Literal process rows are parser inputs only. No /bin/ps or real
        # process-table read is reachable; the observer's own PID is synthetic.
        raw = (b"1 0 0 0 0 0 0 64 S\n"
               b"4242 60001 60001 60001 60001 60001 60001 0 Z\n"
               b"9999 0 0 0 0 0 0 4 R\n")
        clock = SimpleNamespace(now=0.0)
        metadata = Mock(return_value=(raw, 9999))
        with patch.multiple(self.module, _small_command=metadata,
                            os=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                            time=SimpleNamespace(monotonic=lambda: clock.now)):
            rows = self.module._mac_snapshot(deadline=0.5)
            self.assertEqual(rows[(4242, 4242)], ((60001,) * 3, (60001,) * 3, 0))
            self.assertEqual(rows[(1, 1)][2], 64 * 1024)
            self.assertNotIn((9999, 9999), rows)
            metadata.assert_called_once_with(
                ["/bin/ps", "-axo", "pid=,ruid=,uid=,svuid=,rgid=,gid=,svgid=,rss=,stat="],
                return_pid=True, deadline=0.5,
            )
            for malformed in (raw + raw.splitlines(keepends=True)[1], b"4242 60001 incomplete\n",
                              raw.replace(b"60001", b"unknown", 1)):
                metadata.return_value = (malformed, 9999)
                with self.assertRaises(self.module.SessionError):
                    self.module._mac_snapshot(deadline=0.5)

            def consumed_census(*_args, **_kwargs):
                clock.now = 0.5
                return raw, 9999

            metadata.side_effect = consumed_census
            with self.assertRaises(self.module.DeadlineExpired):
                self.module._mac_snapshot(deadline=0.5)

        # Exercise the actual routing/two-pass census wrapper, not the
        # collector rig's domain double, with the same absolute endpoint.
        for platform in ("linux", "darwin"):
            linux, mac = Mock(return_value=rows), Mock(return_value=rows)
            with patch.multiple(self.module, _linux_snapshot=linux, _mac_snapshot=mac,
                                time=SimpleNamespace(monotonic=lambda: 0.0)):
                self.assertEqual(self.module._domain(platform, 60001, deadline=0.5), {4242})
            selected, other = (linux, mac) if platform == "linux" else (mac, linux)
            self.assertEqual([c.kwargs for c in selected.call_args_list], [{"deadline": 0.5}] * 2)
            other.assert_not_called()

        # Linux's source-only /proc substitute also must check the deadline
        # after its last metadata read. Unknown paths never reach the host FS.
        base = Path("/proc/4242/task/4242")
        status = b"Uid:\t60001 60001 60001 60001\nGid:\t60001 60001 60001 60001\n"
        birth = b"4242 (synthetic task) S " + b"0 " * 18 + b"99 0\n"
        for expired in (False, True):
            clock = SimpleNamespace(now=0.0)

            def children(path):
                if path == Path("/proc"):
                    return [Path("/proc/4242")]
                if path == base.parent:
                    return [base]
                raise AssertionError("unexpected synthetic census directory")

            def read_row(path):
                if path == base / "stat":
                    return birth
                if path == base / "status":
                    if expired:
                        clock.now = 0.5
                    return status
                raise AssertionError("unexpected synthetic census file")

            with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)), \
                 patch.object(Path, "iterdir", children), patch.object(Path, "read_bytes", read_row):
                if expired:
                    with self.assertRaises(self.module.DeadlineExpired):
                        self.module._linux_snapshot(deadline=0.5)
                else:
                    self.assertEqual(self.module._linux_snapshot(deadline=0.5),
                                     {(4242, 4242): ((60001,) * 4, (60001,) * 4, 99)})

    def test_network_local_enqueue_never_substitutes_for_outside_non_delivery(self):
        endpoints = [(2, 1, "127.0.0.1", 42001), (2, 2, "127.0.0.1", 42002),
                     (10, 1, "::1", 42003), (10, 2, "::1", 42004)]
        for platform, case, allowed in (
            ("linux", "valid", True), ("linux", "udp-denied", True),
            ("linux", "partial-udp", False), ("linux", "tcp-connect", False),
            ("linux", "unknown-errno", False), ("linux", "close-error", False),
            ("linux", "no-loopback", False), ("linux", "extra-interface", False),
            ("linux", "invalid-index", False), ("linux", "wrong-interface", False),
            ("darwin", "valid", True), ("darwin", "udp-enqueued", False),
            ("darwin", "connection-refused", False),
        ):
            with self.subTest(subject_network=(platform, case)):
                streams = []
                interfaces = {"no-loopback": [], "extra-interface": [(1, "lo"), (2, "eth0")],
                              "invalid-index": [(0, "lo")], "wrong-interface": [(1, "eth0")]}.get(case, [(1, "lo")])

                def make_socket(family, kind):
                    self.assertIn((family, kind), {(2, 1), (2, 2), (10, 1), (10, 2)})
                    connect_error = None if case == "tcp-connect" else OSError(
                        errno.ECONNREFUSED if platform == "linux" or case == "connection-refused" else errno.EPERM,
                        "synthetic connect outcome",
                    )
                    send_error = (OSError(errno.EIO, "synthetic unknown send") if case == "unknown-errno" else
                                  OSError(errno.EACCES, "synthetic send denial")
                                  if case == "udp-denied" or platform == "darwin" and case != "udp-enqueued" else None)
                    stream = SimpleNamespace(
                        settimeout=Mock(), connect=Mock(side_effect=connect_error),
                        sendto=Mock(return_value=1 if case == "partial-udp" else len(b"must-not-escape"),
                                    side_effect=send_error),
                        close=Mock(side_effect=OSError(errno.EIO, "synthetic close") if case == "close-error" else None),
                    )
                    streams.append(stream)
                    return stream

                sockets = SimpleNamespace(AF_INET=2, AF_INET6=10, SOCK_STREAM=1, SOCK_DGRAM=2,
                                          socket=Mock(side_effect=make_socket), if_nameindex=Mock(return_value=interfaces))
                with patch.multiple(self.module, socket=sockets, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                    signal=SimpleNamespace()):
                    if allowed:
                        self.module._probe_network(platform, endpoints)
                        self.assertEqual(len(streams), 4)
                    else:
                        with self.assertRaises((self.module.SessionError, BaseExceptionGroup)):
                            self.module._probe_network(platform, endpoints)
                for stream in streams:
                    stream.settimeout.assert_called_once_with(0.5)
                    stream.close.assert_called_once_with()
                if platform == "darwin":
                    sockets.if_nameindex.assert_not_called()
                elif case in {"no-loopback", "extra-interface", "invalid-index", "wrong-interface"}:
                    sockets.socket.assert_not_called()
                if allowed:
                    for stream, (_, kind, host, port) in zip(streams, endpoints):
                        if kind == 1:
                            stream.connect.assert_called_once_with((host, port))
                            stream.sendto.assert_not_called()
                        else:
                            stream.sendto.assert_called_once_with(b"must-not-escape", (host, port))
                            stream.connect.assert_not_called()

        # The positive's connect/send may consume its original absolute budget.
        # No second blocking receive is then permitted, and only actually
        # acquired local handles are closed; the listener is still caller-owned.
        for family, kind, host, port in endpoints:
            for case in ("valid", "operation-expired", "close-expired", "independent-close-errors"):
                with self.subTest(outside_network_positive=(family, kind, case)):
                    clock = SimpleNamespace(now=0.0)
                    positive_error = OSError("synthetic original positive close error")
                    accepted_error = OSError("synthetic original accepted close error")

                    def operation(*args):
                        self.assertEqual(args, ((host, port),) if kind == 1 else (b"owned-control", (host, port)))
                        if case == "operation-expired":
                            clock.now = 1.0
                        return None if kind == 1 else len(b"owned-control")

                    def positive_close():
                        if case == "close-expired":
                            clock.now = 1.0
                        if case == "independent-close-errors":
                            raise positive_error

                    accepted = SimpleNamespace(close=Mock(side_effect=accepted_error if case == "independent-close-errors" else None))
                    positive = SimpleNamespace(settimeout=Mock(), connect=Mock(side_effect=operation),
                        sendto=Mock(side_effect=operation), close=Mock(side_effect=positive_close))
                    listener = SimpleNamespace(family=family, type=kind, getsockname=Mock(return_value=(host, port)),
                        settimeout=Mock(), accept=Mock(return_value=(accepted, ("synthetic-peer", 1))),
                        recv=Mock(return_value=b"owned-control"), close=Mock())
                    sockets = SimpleNamespace(AF_INET=2, AF_INET6=10, SOCK_STREAM=1, SOCK_DGRAM=2,
                                              socket=Mock(return_value=positive))
                    with patch.multiple(self.module, socket=sockets, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                        signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)):
                        if case == "valid":
                            self.module._outside_network_control(listener, deadline=1.0)
                        else:
                            with self.assertRaises(BaseExceptionGroup) as caught:
                                self.module._outside_network_control(listener, deadline=1.0)
                            if "expired" in case:
                                self.assertTrue(all(isinstance(error, self.module.DeadlineExpired) for error in caught.exception.exceptions))
                            else:
                                self.assertEqual(caught.exception.exceptions, (accepted_error, positive_error) if kind == 1 else (positive_error,))
                    sockets.socket.assert_called_once_with(family, kind)
                    positive.settimeout.assert_called_once_with(1.0)
                    positive.close.assert_called_once_with()
                    listener.close.assert_not_called()
                    self.assertEqual([call.args for call in listener.settimeout.call_args_list],
                                     [(1.0,)] if case == "operation-expired" else [(1.0,), (1.0,)])
                    if kind == 1:
                        positive.connect.assert_called_once_with((host, port))
                        positive.sendto.assert_not_called()
                    else:
                        positive.sendto.assert_called_once_with(b"owned-control", (host, port))
                        positive.connect.assert_not_called()
                    self.assertEqual(listener.accept.call_count, int(kind == 1 and case != "operation-expired"))
                    self.assertEqual(accepted.close.call_count, listener.accept.call_count)
                    self.assertEqual(listener.recv.call_count, int(kind == 2 and case != "operation-expired"))

        sockets = SimpleNamespace(AF_INET=2, AF_INET6=10, SOCK_STREAM=1, SOCK_DGRAM=2,
                                  socket=Mock(side_effect=AssertionError("no real receiver creation")))
        for case in ("empty", "zero-datagram", "data-datagram", "accepted-tcp", "accepted-close", "receiver-error",
                     "receiver-unknown-blocking", "setblocking-eagain", "expired", "last-receive-expired", "inventory"):
            with self.subTest(outside_network=case):
                clock = SimpleNamespace(now=1.0 if case == "expired" else 0.0)
                accepted = SimpleNamespace(close=Mock(side_effect=OSError(errno.EIO, "synthetic accepted close")
                                                      if case == "accepted-close" else None))
                listeners = []
                for family, kind, _host, _port in endpoints:
                    listeners.append(SimpleNamespace(
                        family=family, type=kind, setblocking=Mock(), close=Mock(),
                        accept=Mock(side_effect=BlockingIOError(errno.EAGAIN, "synthetic empty TCP")),
                        recv=Mock(side_effect=BlockingIOError(errno.EWOULDBLOCK, "synthetic empty UDP")),
                    ))
                if case in {"zero-datagram", "data-datagram"}:
                    listeners[1].recv.side_effect = None
                    listeners[1].recv.return_value = b"" if case == "zero-datagram" else b"x"
                elif case in {"accepted-tcp", "accepted-close"}:
                    listeners[0].accept.side_effect = None
                    listeners[0].accept.return_value = (accepted, ("synthetic-peer", 1))
                elif case == "receiver-error":
                    listeners[1].recv.side_effect = OSError(errno.EIO, "synthetic unknown receiver")
                elif case == "receiver-unknown-blocking":
                    listeners[1].recv.side_effect = BlockingIOError(errno.EIO, "synthetic unknown blocking state")
                elif case == "setblocking-eagain":
                    listeners[0].setblocking.side_effect = BlockingIOError(errno.EAGAIN, "synthetic setup failure")
                elif case == "last-receive-expired":

                    def last_receive(_size):
                        clock.now = 1.0
                        raise BlockingIOError(errno.EAGAIN, "synthetic empty but late")

                    listeners[-1].recv.side_effect = last_receive
                elif case == "inventory":
                    listeners.pop()
                with patch.multiple(self.module, socket=sockets, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                    signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)):
                    if case == "empty":
                        self.module._outside_network_empty(listeners, deadline=1.0)
                    elif case == "inventory":
                        with self.assertRaises(self.module.SessionError):
                            self.module._outside_network_empty(listeners, deadline=1.0)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._outside_network_empty(listeners, deadline=1.0)
                        if case == "accepted-close":
                            self.assertEqual(len(caught.exception.exceptions), 2)
                            self.assertIsInstance(caught.exception.exceptions[0], self.module.SessionError)
                            self.assertIsInstance(caught.exception.exceptions[1], OSError)
                        if "expired" in case:
                            self.assertTrue(all(isinstance(e, self.module.DeadlineExpired) for e in caught.exception.exceptions))
                for listener in listeners:
                    listener.close.assert_not_called()  # Original listeners remain in _preflight's custody.
                    if case not in {"expired", "inventory"}:
                        listener.setblocking.assert_called_once_with(False)
                if case in {"accepted-tcp", "accepted-close"}:
                    accepted.close.assert_called_once_with()
                else:
                    accepted.close.assert_not_called()
        sockets.socket.assert_not_called()

    def test_cleanup_routes_only_fixed_unprivileged_batches_and_requires_fresh_finality(self):
        for case, aggregate, enclosing in (
            ("sequence", 100.0, None), ("sequence", 12.0, None), ("sequence", 100.0, 11.5),
            ("empty", 100.0, None), ("bad-ack", 100.0, None), ("ack-at-cutoff", 100.0, None),
            ("unknown-census", 100.0, None), ("oversized", 100.0, None),
            ("helper-wait-error", 100.0, None), ("enclosing-expired", 100.0, 10.0),
        ):
            with self.subTest(root_cleanup=(case, aggregate, enclosing)):
                session = session_double(self.module, "darwin")
                session.deadline = aggregate
                clock = SimpleNamespace(now=10.0)
                cutoff = min(aggregate, 14.0, enclosing if enclosing is not None else aggregate)
                censuses, batches, sleeps = [], [], []
                root_kill = Mock(side_effect=AssertionError("root has no discovered-process signal role"))

                def census(platform, uid, *, deadline):
                    self.assertEqual((platform, uid, deadline), ("darwin", session.uid, cutoff))
                    self.module._remaining(deadline)
                    index = len(censuses)
                    if index > 2:
                        raise AssertionError("finite synthetic census inventory exhausted")
                    if case == "unknown-census" and index == 1:
                        raise OSError(errno.EIO, "synthetic final census unknown")
                    rows = (set() if case == "empty" else set(range(10000, 14097)) if case == "oversized" else
                            ({4242, 4343}, {4343}, set())[index])
                    censuses.append(set(rows))
                    return rows

                def batch(argv, seconds, **kwargs):
                    batches.append((argv, seconds, kwargs))
                    self.assertEqual(seconds, 4)
                    self.assertEqual(kwargs, {"user": session.uid, "group": session.gid, "deadline": cutoff})
                    self.module._remaining(kwargs["deadline"])
                    if case == "helper-wait-error":
                        raise ExceptionGroup("synthetic original metadata wait failure", [TimeoutError("not waited")])
                    if case == "ack-at-cutoff":
                        clock.now = cutoff
                    return b"not-the-batch-ack\n" if case == "bad-ack" else b"MRK_CLEANUP_BATCH_ATTEMPTED\n"

                def sleep(seconds):
                    sleeps.append(seconds)
                    clock.now += seconds

                with patch.multiple(self.module, _domain=census, _small_command=batch,
                                    os=SimpleNamespace(kill=root_kill), subprocess=SimpleNamespace(),
                                    signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep)):
                    errors = session._cleanup(deadline=enclosing)
                root_kill.assert_not_called()
                self.assertEqual(errors == [], case in {"sequence", "empty"}, errors)
                if case == "sequence":
                    self.assertEqual(censuses, [{4242, 4343}, {4343}, set()])
                    self.assertEqual(len(batches), 2)
                    self.assertEqual(sleeps, [0.1, 0.1])
                    for (argv, _seconds, _kwargs), kind, targets in zip(batches, ("TERM", "KILL"), ([4242, 4343], [4343])):
                        self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry),
                                               "--enter", "darwin", str(session.uid), str(session.gid), "10",
                                               str(session.cleanup_policy), str(session.python), "-I", "-S", "-B",
                                               str(session.entry), "--cleanup-batch", str(session.uid), str(session.gid),
                                               kind, json.dumps(targets), repr(cutoff)])
                elif case in {"empty", "oversized", "enclosing-expired"}:
                    self.assertEqual(batches, [])
                elif case == "ack-at-cutoff":
                    self.assertEqual(censuses, [{4242, 4343}])
                    self.assertEqual(errors, ["numerical cleanup DeadlineExpired"])
                    self.assertEqual(sleeps, [])  # Receipt alone never proves an empty domain.
                elif case == "helper-wait-error":
                    self.assertEqual(errors, ["numerical cleanup ExceptionGroup"])

        cases = ("TERM", "KILL", "esrch", "eperm", "unknown-errno", "initial-expiry", "between-targets-expiry",
                 "after-last-expiry", "wrong-platform", "uid-range", "bool-uid", "gid-mismatch", "root-euid",
                 "missing-primary-group", "extra-group", "empty-targets", "tuple-targets", "duplicate-targets",
                 "bool-target", "zero-target", "negative-target", "one-target", "large-target", "self-target",
                 "oversized-targets", "wrong-signal", "numeric-signal")
        for case in cases:
            with self.subTest(numeric_cleanup=case):
                uid = gid = 60001
                actual = (uid, uid, gid, gid)
                groups, targets, kind = [gid], [4242, 4343], "KILL" if case == "KILL" else "TERM"
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                if case == "uid-range":
                    uid = gid = 59999
                elif case == "bool-uid":
                    uid = True
                elif case == "gid-mismatch":
                    gid += 1
                elif case == "root-euid":
                    actual = (uid, 0, gid, gid)
                elif case == "missing-primary-group":
                    groups = []
                elif case == "extra-group":
                    groups = [gid, 0]
                target_cases = {"empty-targets": [], "tuple-targets": (4242,), "duplicate-targets": [4242, 4242],
                                "bool-target": [True], "zero-target": [0], "negative-target": [-1], "one-target": [1],
                                "large-target": [2**31], "self-target": [9999],
                                "oversized-targets": list(range(10000, 14097))}
                targets = target_cases.get(case, targets)
                if case == "wrong-signal":
                    kind = "HUP"
                elif case == "numeric-signal":
                    kind = 15

                def kernel_signal(pid, signum):
                    self.assertIn((pid, signum), {(4242, 15), (4343, 15), (4242, 9), (4343, 9)})
                    if case in {"esrch", "eperm", "unknown-errno"}:
                        raise OSError({"esrch": errno.ESRCH, "eperm": errno.EPERM, "unknown-errno": errno.EIO}[case],
                                      "synthetic kernel signal result")
                    if case == "between-targets-expiry" or case == "after-last-expiry" and pid == 4343:
                        clock.now = 1.0

                kill = Mock(side_effect=kernel_signal)
                no_census = Mock(side_effect=AssertionError("the numerical helper has no census role"))
                no_metadata = Mock(side_effect=AssertionError("the numerical helper cannot invoke metadata tools"))
                fake_os = SimpleNamespace(getuid=lambda: actual[0], geteuid=lambda: actual[1],
                                          getgid=lambda: actual[2], getegid=lambda: actual[3], getpid=lambda: 9999, kill=kill)
                output = io.StringIO()
                with patch.multiple(self.module, os=fake_os, sys=SimpleNamespace(platform="linux" if case == "wrong-platform" else "darwin"),
                                    signal=SimpleNamespace(SIGTERM=15, SIGKILL=9), subprocess=SimpleNamespace(),
                                    _process_groups=Mock(return_value=groups), _domain=no_census, _small_command=no_metadata,
                                    time=SimpleNamespace(monotonic=lambda: clock.now)), redirect_stdout(output):
                    if case in {"TERM", "KILL", "esrch"}:
                        self.module._cleanup_numeric(uid, gid, kind, targets, 1.0)
                    else:
                        with self.assertRaises((self.module.SessionError, OSError)) as caught:
                            self.module._cleanup_numeric(uid, gid, kind, targets, 1.0)
                        self.assertEqual(caught.exception._ci_operation, "cleanup-batch")
                        if case in {"eperm", "unknown-errno"}:
                            self.assertEqual(caught.exception.errno, errno.EPERM if case == "eperm" else errno.EIO)
                no_census.assert_not_called()
                no_metadata.assert_not_called()
                if case in {"TERM", "KILL", "esrch"}:
                    self.assertEqual(output.getvalue(), "MRK_CLEANUP_BATCH_ATTEMPTED\n")
                    self.assertEqual([c.args for c in kill.call_args_list], [(4242, 9 if kind == "KILL" else 15),
                                                                          (4343, 9 if kind == "KILL" else 15)])
                else:
                    self.assertEqual(output.getvalue(), "")
                    count = 2 if case == "after-last-expiry" else 1 if case in {"eperm", "unknown-errno", "between-targets-expiry"} else 0
                    self.assertEqual(kill.call_count, count)

    def test_sudo_denial_requires_launch_denial_or_nonzero_wait_and_independent_cleanup(self):
        fixed = ["/usr/bin/sudo", "-n", "-u", "root", "/usr/bin/true"]
        for number in (errno.EPERM, errno.EACCES, errno.ENOENT, errno.EIO):
            with self.subTest(sudo_launch_errno=number):
                original = OSError(number, "synthetic fixed-tool launch error")
                launch = Mock(side_effect=original)
                with patch.multiple(self.module, subprocess=SimpleNamespace(Popen=launch, DEVNULL=-3),
                                    os=SimpleNamespace(), signal=SimpleNamespace()):
                    if number in {errno.EPERM, errno.EACCES}:
                        self.module._sudo_denial()
                    else:
                        with self.assertRaises(OSError) as caught:
                            self.module._sudo_denial()
                        self.assertIs(caught.exception, original)
                launch.assert_called_once_with(fixed, stdin=-3, stdout=-3, stderr=-3, close_fds=True)

        for case in ("nonzero", "negative", "zero", "missing-wait", "bool-wait", "first-wait-eperm", "first-wait-timeout",
                     "poll-eacces", "kill-eperm", "cleanup-wait-eacces", "cleanup-wait-missing", "two-cleanup-errors"):
            with self.subTest(sudo_original=case):
                first_error = OSError(errno.EPERM, "synthetic first wait denied after launch")
                stop_error = OSError(errno.EACCES, "synthetic original stop error after launch")
                final_error = OSError(errno.EACCES, "synthetic original final wait error after launch")
                first = {"negative": -9, "zero": 0, "missing-wait": None, "bool-wait": True,
                         "first-wait-eperm": first_error, "first-wait-timeout": TimeoutError("synthetic unknown wait")}.get(case, 1)
                last = final_error if case in {"cleanup-wait-eacces", "two-cleanup-errors"} else None if case == "cleanup-wait-missing" else 1
                child = SimpleNamespace(wait=Mock(side_effect=[first, last]),
                                        poll=Mock(return_value=None if case == "kill-eperm" else 1,
                                                  side_effect=stop_error if case in {"poll-eacces", "two-cleanup-errors"} else None),
                                        kill=Mock(side_effect=first_error if case == "kill-eperm" else None))
                launch = Mock(return_value=child)
                with patch.multiple(self.module, subprocess=SimpleNamespace(Popen=launch, DEVNULL=-3),
                                    os=SimpleNamespace(), signal=SimpleNamespace()):
                    if case in {"nonzero", "negative"}:
                        self.module._sudo_denial()
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._sudo_denial()
                        if case == "first-wait-eperm":
                            self.assertEqual(caught.exception.exceptions, (first_error,))
                        elif case == "two-cleanup-errors":
                            self.assertEqual(caught.exception.exceptions, (stop_error, final_error))
                launch.assert_called_once_with(fixed, stdin=-3, stdout=-3, stderr=-3, close_fds=True)
                self.assertEqual([c.kwargs for c in child.wait.call_args_list], [{"timeout": 3}, {"timeout": 2}])
                child.poll.assert_called_once_with()
                if case == "kill-eperm":
                    child.kill.assert_called_once_with()
                else:
                    child.kill.assert_not_called()

    def test_observer_artifact_and_exclusive_copy_keep_identity_deadlines_and_all_close_errors(self):
        path = Path("/synthetic/private/observer-artifact")
        payload = b"inert observer image, never executed"
        read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        for case in ("source", "frozen", "open-link", "nonregular", "multiple-links", "wrong-owner", "wrong-group",
                     "setuid", "setgid", "group-write", "world-write", "nonexecutable", "empty", "oversized",
                     "changed-inode", "changed-name", "changed-time", "truncated", "grew", "read-error", "close-error",
                     "read-and-close-error", "read-expiry", "close-expiry", "initial-expiry"):
            with self.subTest(observer_artifact=case):
                uid = gid = 0 if case == "frozen" else 60001
                mode = 0o555 if case == "frozen" else 0o755
                state = dict(st_dev=7, st_ino=11, st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid,
                             st_nlink=1, st_size=len(payload), st_mtime_ns=101, st_ctime_ns=102)
                changes = {"nonregular": {"st_mode": stat.S_IFIFO | 0o755}, "multiple-links": {"st_nlink": 2},
                           "wrong-owner": {"st_uid": uid + 1}, "wrong-group": {"st_gid": gid + 1},
                           "setuid": {"st_mode": stat.S_IFREG | 0o4755}, "setgid": {"st_mode": stat.S_IFREG | 0o2755},
                           "group-write": {"st_mode": stat.S_IFREG | 0o775}, "world-write": {"st_mode": stat.S_IFREG | 0o757},
                           "nonexecutable": {"st_mode": stat.S_IFREG | 0o644}, "empty": {"st_size": 0},
                           "oversized": {"st_size": 16 * self.module.MiB + 1}}
                before = SimpleNamespace(**(state | changes.get(case, {})))
                after = SimpleNamespace(**(vars(before) | ({"st_ino": 12} if case == "changed-inode" else
                                                           {"st_mtime_ns": 103} if case == "changed-time" else {})))
                named = SimpleNamespace(**(vars(before) | ({"st_ino": 13} if case == "changed-name" else {})))
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                data = payload[:-1] if case == "truncated" else payload + b"x" if case == "grew" else payload
                chunks = [data[:7], data[7:], b""]
                read_error = OSError(errno.EIO, "synthetic artifact read")
                close_error = OSError(errno.EIO, "synthetic artifact close")

                def read(fd, size):
                    self.assertEqual(fd, 101)
                    self.assertTrue(0 < size <= 65536)
                    if case in {"read-error", "read-and-close-error"}:
                        raise read_error
                    if case == "read-expiry":
                        clock.now = 1.0
                    return chunks.pop(0)

                def close(fd):
                    self.assertEqual(fd, 101)
                    if case in {"close-error", "read-and-close-error"}:
                        raise close_error
                    if case == "close-expiry":
                        clock.now = 1.0

                opened = Mock(return_value=101, side_effect=OSError(errno.ELOOP, "synthetic no-follow link")
                              if case == "open-link" else None)
                closed, reads = Mock(side_effect=close), Mock(side_effect=read)
                metadata = Mock(side_effect=[before, after])
                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, open=opened, read=reads,
                                                                   fstat=metadata, close=closed),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "lstat", return_value=named), \
                     patch.object(Path, "stat", side_effect=AssertionError("unexpected artifact filesystem query")):
                    if case in {"source", "frozen"}:
                        self.assertEqual(self.module._observer_artifact(path, uid, gid, deadline=1.0), (payload, mode))
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._observer_artifact(path, uid, gid, deadline=1.0)
                        if case == "read-and-close-error":
                            self.assertEqual(caught.exception.exceptions, (read_error, close_error))
                        if "expiry" in case:
                            self.assertTrue(all(isinstance(e, self.module.DeadlineExpired) for e in caught.exception.exceptions))
                if case == "initial-expiry":
                    opened.assert_not_called()
                else:
                    opened.assert_called_once_with(path, read_flags)
                if case in {"initial-expiry", "open-link"}:
                    closed.assert_not_called()
                    metadata.assert_not_called()
                else:
                    closed.assert_called_once_with(101)
                    self.assertTrue(all(c.args == (101,) for c in metadata.call_args_list))
                if case in changes or case in {"initial-expiry", "open-link"}:
                    reads.assert_not_called()

        # Root's existing copy primitive must really use exclusive no-follow
        # creation and independently close after partial writes/permission errors.
        # Every descriptor here is synthetic; no filesystem path is opened.
        for case in ("success", "collision", "partial-write-error", "write-and-close-error", "mode-error"):
            with self.subTest(observer_copy=case):
                persisted = bytearray()
                write_error = OSError(errno.EIO, "synthetic interrupted copy write")
                close_error = OSError(errno.EIO, "synthetic copy close")

                def write(fd, data):
                    self.assertEqual(fd, 202)
                    count = min(2, len(data))
                    persisted.extend(data[:count])
                    if case in {"partial-write-error", "write-and-close-error"}:
                        raise write_error
                    return count

                opened = Mock(return_value=202, side_effect=FileExistsError(errno.EEXIST, "synthetic bootstrap collision")
                              if case == "collision" else None)
                writes = Mock(side_effect=write)
                closed = Mock(side_effect=close_error if case == "write-and-close-error" else None)
                chmod = Mock(side_effect=OSError(errno.EIO, "synthetic immutable-mode failure") if case == "mode-error" else None)
                fsync = Mock()
                constants = {k: getattr(os, k) for k in ("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, open=opened, write=writes, fsync=fsync, fchmod=chmod, close=closed)
                with patch.object(self.module, "os", fake_os):
                    if case == "success":
                        self.module._private_file(path, payload, 0o555)
                    elif case == "collision":
                        with self.assertRaises(FileExistsError):
                            self.module._private_file(path, payload, 0o555)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._private_file(path, payload, 0o555)
                        if case == "write-and-close-error":
                            self.assertEqual(caught.exception.exceptions, (write_error, close_error))
                opened.assert_called_once_with(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o555)
                if case == "collision":
                    writes.assert_not_called()
                    closed.assert_not_called()
                    chmod.assert_not_called()
                    self.assertEqual(persisted, b"")
                else:
                    closed.assert_called_once_with(202)
                    if case in {"success", "mode-error"}:
                        self.assertEqual(persisted, payload)
                        fsync.assert_called_once_with(202)
                        chmod.assert_called_once_with(202, 0o555)
                    else:
                        self.assertEqual(persisted, payload[:2])
                        fsync.assert_not_called()
                        chmod.assert_not_called()

    def test_observer_signature_metadata_requires_complete_unprivileged_singletons(self):
        path = Path("/synthetic/private/process-observer-build")
        for arch in ("arm64", "x86_64"):
            for flags, label in ((2, "adhoc"), (0x20002, "adhoc,linker-signed")):
                lines = [f"Executable={path}", f"Identifier={path.name}", f"Format=Mach-O thin ({arch})",
                         f"CodeDirectory v=20400 size=200 flags=0x{flags:x}({label}) hashes=2+0 location=embedded",
                         "Signature=adhoc", "TeamIdentifier=not set", "Page size=4096", "Hash type=sha256 size=32",
                         "Hash choices=sha256", "CDHash=" + "a" * 40, "CMSDigest=" + "b" * 64,
                         "CMSDigestType=2", "Info.plist=not bound", "Sealed Resources=none", "Internal requirements=none"]
                raw = ("\n".join(lines) + "\n").encode()
                # These are admitted grammar fixtures, not claims about a real
                # codesign invocation. Original wait/EOF and entitlement probes
                # are independently required by the preparation caller.
                self.assertEqual(self.module._observer_signature_metadata(b"", raw, path, arch),
                                 {"signature": "adhoc", "flags": flags, "architecture": arch})
                for omitted in range(6):
                    incomplete = ("\n".join(line for i, line in enumerate(lines) if i != omitted) + "\n").encode()
                    with self.subTest(architecture=arch, omitted=omitted), self.assertRaises(self.module.SessionError):
                        self.module._observer_signature_metadata(b"", incomplete, path, arch)
        cases = (
            (b"unexpected stdout", raw), (b"", b""), (b"", raw[:-1]), (b"", raw + b"x" * 16384 + b"\n"),
            (b"", raw + b"\xff\n"), (b"", raw.replace(b"\n", b"\r\n", 1)), (b"", raw + b"\0\n"),
            (b"", raw.replace(b"Signature=adhoc", b"Signature=Developer ID")),
            (b"", raw.replace(b"TeamIdentifier=not set", b"TeamIdentifier=synthetic-team")),
            (b"", raw + b"Authority=synthetic-authority\n"), (b"", raw + b"PlatformIdentifier=1\n"),
            (b"", raw + b"Entitlements=unknown\n"), (b"", raw + b"Page size=16384\n"),
            (b"", raw + ("CDHash=" + "c" * 40 + "\n").encode()),
            (b"", raw + ("CMSDigest=" + "d" * 64 + "\n").encode()),
            (b"", raw + b"Internal requirements count=0 size=12\n"),
            (b"", raw + b"Signature=adhoc\n"),
            (b"", raw.replace(b"flags=0x20002(adhoc,linker-signed)", b"flags=0x0(adhoc)")),
            (b"", raw.replace(b"flags=0x20002(adhoc,linker-signed)", b"flags=0x20002(adhoc)")),
            (b"", raw.replace(b"size=200 flags=", b"size=0 flags=")),
            (b"", raw.replace(b"hashes=2+0", b"hashes=0+0")),
            (b"", raw.replace(b"hashes=2+0", b"hashes=2+33")),
            (b"", raw.replace(b"v=20400", b"v=1")), (b"", raw.replace(b"location=embedded", b"location=detached")),
        )
        for index, (stdout, stderr) in enumerate(cases):
            with self.subTest(signature_case=index), self.assertRaises((self.module.SessionError, UnicodeDecodeError)):
                self.module._observer_signature_metadata(stdout, stderr, path, "x86_64")
        for candidate, arch in ((path.parent / "other", "x86_64"), (path, "arm64"), (path, "unknown")):
            with self.subTest(path=candidate, arch=arch), self.assertRaises(self.module.SessionError):
                self.module._observer_signature_metadata(b"", raw, candidate, arch)

        source = Path("/synthetic/private/source/.github/scripts/ci_process_observer.c")
        canary = "synthetic-private-compiler-message-not-for-publication"
        own = f"{source}:7:9: error: {canary}\n".encode()
        foreign = f"/synthetic/private/SDK/header.h:1:2: warning: {canary}\n".encode()
        expected = {"file": ".github/scripts/ci_process_observer.c", "line": 7, "column": 9, "severity": "error"}
        self.assertEqual(self.module._observer_build_notes(own + foreign, source), [expected])
        self.assertEqual(self.module._observer_build_notes(foreign, source), [{"category": "unclassified-compiler-diagnostics"}])
        self.assertEqual(self.module._observer_build_notes(b"clang: error: " + canary.encode(), source), [{"category": "clang-driver"}])
        self.assertEqual(self.module._observer_build_notes(b"", source), [])
        self.assertEqual(self.module._observer_build_notes(own * 20, source), [expected] * 16)
        self.assertNotIn(canary, json.dumps(self.module._observer_build_notes(own + foreign, source)))
        with self.assertRaises(self.module.SessionError) as caught:
            self.module._observer_signature_metadata(b"", raw + f"{canary}=private\n".encode(), path, "x86_64")
        self.assertEqual(caught.exception._ci_observation, {"signature_field": "unclassified"})

    def test_observer_toolchain_binds_readonly_provider_inventory_and_complete_hashes(self):
        xcode = Path("/Applications/Xcode_26.3.app/Contents/Developer")
        toolchain = xcode / "Toolchains/XcodeDefault.xctoolchain"
        sdk_alias = xcode / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
        default_sdk = sdk_alias.parent / "MacOSX26.4.sdk"
        clang, linker = (toolchain / "usr/bin" / name for name in ("clang", "ld"))
        positive_cases = {"valid", "ancestor-owner", "provider-owned-group-write", "sdk-alias-other-branch", "internal-link-target-valid"}
        for case in ("valid", "sdk-escape", "link-escape", "link-owner", "ancestor-owner", "world-write", "subject-group-write",
                     "setid-compiler", "nonexec-linker", "codesign-write", "settings-version", "settings-changed",
                     "compiler-changed", "oversized-compiler", "read-expiry", "initial-expiry", "provider-owned-group-write",
                     "ancestor-subject-owner", "intermediate-owner", "intermediate-group-write", "intermediate-file",
                     "intermediate-stat-error", "codesign-owner", "sdk-link-owner", "sdk-link-drift", "entry-drift",
                     "settings-open-error", "settings-read-error", "settings-read-expiry", "settings-oversized", "settings-json", "settings-not-object",
                     "sdk-alias-other-branch", "sdk-alias-parent-owner", "sdk-alias-parent-group-write",
                     "internal-link-target-valid", "internal-link-parent-owner", "internal-link-parent-group-write",
                     "internal-link-parent-alias", "internal-link-parent-too-deep"):
            with self.subTest(observer_toolchain=case):
                sdk = xcode / "AlternateSDKs/MacOSX26.4.sdk" if case.startswith("sdk-alias-") else default_sdk
                settings = sdk / "SDKSettings.json"
                link_item = clang.parent / "provider-link"
                internal_target = (xcode.joinpath(*(f"branch{n}" for n in range(65)), "header.h") if case == "internal-link-parent-too-deep"
                                   else xcode / "ExternalProviders/includes/header.h")
                intermediates = {toolchain.parent}
                for parent in (sdk_alias.parent, sdk.parent, *([internal_target.parent] if case.startswith("internal-link-") else [])):
                    intermediates.update(p for p in (parent, *parent.parents) if p != xcode and p.is_relative_to(xcode))
                settings_data = {"Version": "26.4", "CanonicalName": "not-macos" if case == "settings-version" else "macosx26.4"}
                files = {clang: b"inert compiler image", linker: b"inert linker image",
                         settings: json.dumps(settings_data).encode(), Path("/usr/bin/codesign"): b"inert signature-tool image"}
                if case in {"settings-json", "settings-not-object"}:
                    files[settings] = b"not-json" if case == "settings-json" else b"[]"
                directories = {toolchain: [toolchain / "usr"], toolchain / "usr": [clang.parent],
                               clang.parent: [clang, linker], sdk: [settings]}
                if case.startswith("internal-link-"):
                    directories[clang.parent].append(link_item)
                    files[internal_target] = b"inert internally linked provider file"
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                opened, streams, observations, link_reads, reads = [], [], [], {}, []
                original_error = OSError(errno.EACCES, "synthetic-private-provider-message", "/synthetic/private-provider-path")

                def resolve(path, *, strict=False):
                    self.assertTrue(strict)
                    if path == sdk_alias:
                        return Path("/outside/sdk") if case == "sdk-escape" else sdk
                    if path == clang and case == "link-escape":
                        return Path("/outside/clang")
                    if path == link_item and case.startswith("internal-link-"):
                        return internal_target
                    if path == internal_target.parent and case == "internal-link-parent-alias":
                        return xcode / "DifferentProviderParent"
                    if path not in files and path not in directories and path not in intermediates:
                        raise AssertionError("unknown synthetic provider link")
                    return path

                def state(path):
                    if path not in files and path not in directories and path not in intermediates and path not in (xcode, *xcode.parents):
                        raise AssertionError("unknown synthetic provider stat")
                    mode = (stat.S_IFREG if path in files else stat.S_IFDIR) | 0o755
                    owner, group, inode, size = 0, 0, 17, len(files.get(path, b""))
                    if case == "ancestor-owner" and path == Path("/Applications"):
                        owner = 1001
                    if case == "provider-owned-group-write" and path != Path("/usr/bin/codesign"):
                        owner, group, mode = 1001, 20, mode | 0o020
                    if case == "ancestor-subject-owner" and path == Path("/Applications"):
                        owner = 60001
                    if case == "intermediate-owner" and path == toolchain.parent:
                        owner = 60001
                    if case == "intermediate-group-write" and path == sdk.parent:
                        group, mode = 60001, mode | 0o020
                    if case == "intermediate-file" and path == xcode / "Platforms":
                        mode = stat.S_IFREG | 0o755
                    if case == "intermediate-stat-error" and path == sdk.parent:
                        observations.append((path, None))
                        raise original_error
                    if case == "sdk-alias-parent-owner" and path == sdk_alias.parent:
                        owner = 60001
                    if case == "sdk-alias-parent-group-write" and path == sdk_alias.parent:
                        group, mode = 60001, mode | 0o020
                    if case == "internal-link-parent-owner" and path == internal_target.parent:
                        owner = 60001
                    if case == "internal-link-parent-group-write" and path == internal_target.parent:
                        group, mode = 60001, mode | 0o020
                    if case == "world-write" and path == sdk:
                        mode |= 0o002
                    if case == "subject-group-write" and path == clang:
                        mode |= 0o020
                        group = 60001
                    if case == "setid-compiler" and path == clang:
                        mode |= stat.S_ISUID
                    if case == "nonexec-linker" and path == linker:
                        mode = stat.S_IFREG | 0o644
                    if case == "codesign-write" and path == Path("/usr/bin/codesign"):
                        mode |= 0o002
                    if case == "codesign-owner" and path == Path("/usr/bin/codesign"):
                        owner = 1001
                    if case == "compiler-changed" and path == clang and path in opened:
                        inode += 1
                    if case == "oversized-compiler" and path == clang:
                        size = 512 * self.module.MiB + 1
                    info = SimpleNamespace(st_uid=owner, st_gid=group, st_mode=mode, st_dev=3, st_ino=inode,
                                           st_size=size, st_mtime_ns=101, st_ctime_ns=102)
                    observations.append((path, info))
                    return info

                def link_state(path):
                    link_reads[path] = link_reads.get(path, 0) + 1
                    if path == sdk_alias:
                        result = SimpleNamespace(st_uid=60001 if case == "sdk-link-owner" else
                                                 1001 if case == "provider-owned-group-write" else 0,
                            st_gid=20, st_mode=stat.S_IFLNK | 0o777, st_dev=3, st_ino=18,
                            st_size=20, st_mtime_ns=101, st_ctime_ns=102)
                        if case == "sdk-link-drift" and link_reads[path] == 2:
                            result.st_ino += 1
                        observations.append((path, result))
                        return result
                    if path == link_item and case.startswith("internal-link-"):
                        result = SimpleNamespace(st_uid=0, st_gid=20, st_mode=stat.S_IFLNK | 0o777, st_dev=3, st_ino=19,
                                                 st_size=30, st_mtime_ns=101, st_ctime_ns=102)
                        observations.append((path, result))
                        return result
                    result = state(path)
                    if case == "link-owner" and path == clang:
                        result.st_uid = 60001
                    if case == "entry-drift" and path == clang and link_reads[path] == 2:
                        result.st_ino += 1
                    return result

                def children(path):
                    if path not in directories:
                        raise AssertionError("unknown synthetic provider directory")
                    return directories[path]

                class Input(io.BytesIO):
                    def read(stream, count=-1):
                        self.assertEqual(count, self.module.MiB + 1 if stream.settings_read else 65536)
                        reads.append((stream.path, stream.settings_read, count))
                        if case == "read-expiry" and stream.path == clang:
                            clock.now = 1.0
                        if stream.settings_read and case == "settings-read-error":
                            raise original_error
                        if stream.settings_read and case == "settings-read-expiry":
                            clock.now = 1.0
                        return super().read(count)

                def open_input(path, mode):
                    self.assertEqual(mode, "rb")
                    if path not in files:
                        raise AssertionError("unknown synthetic provider read")
                    opened.append(path)
                    settings_read = path == settings and opened.count(settings) == 2
                    if settings_read and case == "settings-open-error":
                        raise original_error
                    payload = (files[path] + b" " if settings_read and case == "settings-changed" else
                               b"x" * (self.module.MiB + 1) if settings_read and case == "settings-oversized" else files[path])
                    stream = Input(payload)
                    stream.path = path
                    stream.settings_read = settings_read
                    streams.append(stream)
                    return stream

                executable = self.module._admit_executable
                with patch.multiple(self.module, _canonical=Path, os=SimpleNamespace(path=SimpleNamespace(basename=os.path.basename)),
                                    subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", resolve), patch.object(Path, "stat", state), \
                     patch.object(Path, "lstat", link_state), patch.object(Path, "iterdir", children), \
                     patch.object(Path, "open", open_input), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("provider settings require the fixed bounded read")), \
                     patch.object(self.module, "_admit_executable", wraps=executable) as role:
                    if case in positive_cases:
                        result = self.module._observer_toolchain(60001, 60001, deadline=1.0)
                        self.assertEqual({key: result[key] for key in ("clang", "linker", "sdk", "toolchain")},
                                         {"clang": clang, "linker": linker, "sdk": sdk, "toolchain": toolchain})
                        self.assertEqual(result["evidence"], {"xcode": "26.3", "sdk": "macosx26.4",
                                         "provider_entries": 6 if case == "internal-link-target-valid" else 5,
                                         "clang_sha256": hashlib.sha256(files[clang]).hexdigest(),
                                         "linker_sha256": hashlib.sha256(files[linker]).hexdigest(),
                                         "sdk_settings_sha256": hashlib.sha256(files[settings]).hexdigest()})
                        self.assertEqual([c.args for c in role.call_args_list],
                                         [(clang, 60001, 60001), (linker, 60001, 60001), (Path("/usr/bin/codesign"), 60001, 60001)])
                        self.assertEqual([(c.kwargs["role"], c.kwargs.get("root_owned", False),
                                           c.kwargs.get("non_set_id", True)) for c in role.call_args_list],
                                         [("compiler", False, True), ("linker", False, True), ("signature-tool", True, True)])
                        for parent in intermediates:
                            self.assertEqual(sum(p == parent for p, _ in observations), 1)
                        self.assertEqual(link_reads[sdk_alias], 2)  # Real-provider 0777 links are not ordinary writable files.
                        self.assertEqual([item for item in reads if item[1]], [(settings, True, self.module.MiB + 1)])
                    else:
                        error_type = OSError if case in {"intermediate-stat-error", "settings-open-error", "settings-read-error"} else (
                                     ValueError if case == "settings-json" else self.module.SessionError)
                        with self.assertRaises(error_type) as caught:
                            self.module._observer_toolchain(60001, 60001, deadline=1.0)
                        if case == "intermediate-stat-error":
                            self.assertIs(caught.exception, original_error)
                            self.assertEqual(original_error._ci_observation["provider"],
                                {"phase": "intermediate", "role": "sdk", "index": original_error._ci_observation["provider"]["index"], "observed": False})
                            self.assertEqual(sum(p == sdk.parent for p, _ in observations), 1)
                        if case.startswith("settings-"):
                            self.assertEqual(caught.exception._ci_observation["provider"],
                                             {"phase": "settings", "role": "sdk", "index": 0, "observed": False})
                            self.assertEqual(opened.count(settings), 2)
                            self.assertNotIn(clang, opened)
                            if case in {"settings-open-error", "settings-read-error"}:
                                self.assertIs(caught.exception, original_error)
                        predicate_cases = {"ancestor-subject-owner", "world-write", "subject-group-write", "link-owner",
                                           "intermediate-owner", "intermediate-group-write", "intermediate-file",
                                           "setid-compiler", "nonexec-linker", "codesign-write", "codesign-owner",
                                           "sdk-link-owner", "sdk-link-drift", "entry-drift", "sdk-alias-parent-owner", "sdk-alias-parent-group-write",
                                           "internal-link-parent-owner", "internal-link-parent-group-write"}
                        if case in predicate_cases:
                            note = caught.exception._ci_observation["provider"]
                            observed = observations[-1][1]
                            self.assertEqual(set(note), {"phase", "role", "index", "observed", "kind", "mode",
                                             "root_owned", "subject_owned", "subject_group", "failed_predicates"})
                            self.assertIs(note["observed"], True)
                            self.assertEqual(note["mode"], format(stat.S_IMODE(observed.st_mode), "04o"))
                            self.assertEqual((note["root_owned"], note["subject_owned"], note["subject_group"]),
                                             (observed.st_uid == 0, observed.st_uid == 60001, observed.st_gid == 60001))
                            expected = {
                                "ancestor-subject-owner": ("ancestor", "xcode", ["subject-owned"]),
                                "world-write": ("intermediate", "sdk", ["world-writable"]),
                                "subject-group-write": ("entry", "toolchain", ["subject-group-writable"]),
                                "link-owner": ("entry", "toolchain", ["subject-owned"]),
                                "intermediate-owner": ("intermediate", "toolchain", ["subject-owned"]),
                                "intermediate-group-write": ("intermediate", "sdk", ["subject-group-writable"]),
                                "intermediate-file": ("intermediate", "sdk", ["not-directory"]),
                                "setid-compiler": ("executable", "compiler", ["set-id-forbidden"]),
                                "nonexec-linker": ("executable", "linker", ["no-execute-bit"]),
                                "codesign-write": ("executable", "signature-tool", ["world-writable", "root-role-group-or-world-writable"]),
                                "codesign-owner": ("executable", "signature-tool", ["root-role-not-root-owned"]),
                                "sdk-link-owner": ("entry", "sdk", ["subject-owned"]),
                                "sdk-link-drift": ("entry", "sdk", ["identity-changed"]),
                                "entry-drift": ("entry", "toolchain", ["identity-changed"]),
                                "sdk-alias-parent-owner": ("intermediate", "sdk", ["subject-owned"]),
                                "sdk-alias-parent-group-write": ("intermediate", "sdk", ["subject-group-writable"]),
                                "internal-link-parent-owner": ("intermediate", "toolchain", ["subject-owned"]),
                                "internal-link-parent-group-write": ("intermediate", "toolchain", ["subject-group-writable"]),
                            }
                            self.assertEqual((note["phase"], note["role"], note["failed_predicates"]), expected[case])
                            self.assertIs(type(note["index"]), int)
                            self.assertTrue(0 <= note["index"] <= 300000)
                        if case in {"internal-link-parent-alias", "internal-link-parent-too-deep"}:
                            note = caught.exception._ci_observation["provider"]
                            self.assertEqual(set(note), {"phase", "role", "index", "observed"})
                            self.assertEqual((note["phase"], note["role"], note["observed"]), ("intermediate", "toolchain", False))
                            if case == "internal-link-parent-too-deep":
                                self.assertEqual(note["index"], 64)
                            self.assertNotIn(internal_target, [path for path, _ in observations])
                        count = len(observations)
                        notes = self.module._exception_notes(caught.exception)
                        self.assertEqual(len(observations), count)  # Diagnostics never replace the decision's stat.
                        self.assertNotIn(str(xcode), json.dumps(notes))
                        self.assertNotIn("synthetic-private", json.dumps(notes))
                self.assertTrue(all(stream.closed for stream in streams))
                if case in {"sdk-escape", "initial-expiry", "ancestor-subject-owner", "world-write", "link-escape", "link-owner",
                            "intermediate-owner", "intermediate-group-write", "intermediate-file", "intermediate-stat-error",
                            "sdk-link-owner", "sdk-link-drift", "entry-drift", "sdk-alias-parent-owner", "sdk-alias-parent-group-write",
                            "internal-link-parent-owner", "internal-link-parent-group-write", "internal-link-parent-alias", "internal-link-parent-too-deep"}:
                    self.assertEqual(opened, [])
                if case == "oversized-compiler":
                    self.assertNotIn(clang, opened)

    def test_observer_preparation_requires_each_real_result_and_revokes_publication_on_late_failure(self):
        cases = ("valid", "toolchain-error", "toolchain-stat-error", "unsupported-arch", "source-too-large", "output-collision", "frozen-collision",
                 "version-invalid", "compile-nonzero", "compile-unwaited", "compile-no-stdout-eof", "compile-no-stderr-eof",
                 "compile-no-finality", "compile-timeout", "compile-cancel", "compile-cleanup-error", "compile-diagnostics",
                 "compile-idle-error", "compile-late-deadline", "verify-unwaited", "verify-diagnostics", "display-empty",
                 "display-unwaited", "entitlements-unwaited", "entitlements-present", "entitlements-diagnostics",
                 "post-signature-bytes", "post-signature-mode", "freeze-copy-error", "frozen-bytes", "frozen-mode",
                 "native-error", "native-finality", "outer-finality")
        for case in cases:
            with self.subTest(observer_preparation=case):
                session = session_double(self.module, "darwin")
                session.admitted = False
                session.process_observer = None
                source = session.source / ".github/scripts/ci_process_observer.c"
                output, frozen = session.work / "process-observer", session.bootstrap / "process-observer"
                c_bytes, binary = b"int main(void) { return 0; }\n", b"inert compiled image, never executed"
                xcode = Path("/Applications/Xcode_26.3.app/Contents/Developer")
                toolchain = xcode / "Toolchains/XcodeDefault.xctoolchain"
                tools = {"clang": toolchain / "usr/bin/clang", "linker": toolchain / "usr/bin/ld",
                         "sdk": xcode / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.4.sdk",
                         "toolchain": toolchain, "evidence": {"xcode": "26.3", "sdk": "macosx26.4"}}
                display = (f"Executable={output}\nIdentifier={output.name}\nFormat=Mach-O thin (arm64)\n"
                           "CodeDirectory v=20400 size=200 flags=0x20002(adhoc,linker-signed) hashes=2+0 location=embedded\n"
                           "Signature=adhoc\nTeamIdentifier=not set\n").encode()
                events, artifacts = [], []
                progress = SimpleNamespace(stage="base", now=0.0)
                observer_key = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"

                def preflight():
                    self.assertIsNone(session.process_observer)
                    self.assertFalse(session.admitted)
                    events.append(("base-preflight",))

                def idle():
                    self.module._remaining(session.deadline)
                    events.append(("idle", progress.stage, session.process_observer is not None))
                    if (case == "compile-idle-error" and progress.stage == "build"
                            or case == "native-finality" and progress.stage == "native"
                            or case == "outer-finality" and session.process_observer is not None):
                        raise OSError(errno.EIO, "synthetic finality unknown")
                    session.domain_finality = True

                def run(argv, **kwargs):
                    self.assertIsNone(session.process_observer)
                    self.assertFalse(session.admitted)
                    self.assertNotIn(observer_key, session._environment(kwargs["env"]))
                    self.assertEqual(kwargs, {"cwd": session.work, "env": {"DEVELOPER_DIR": str(xcode)},
                                             "seconds": 120 if "-o" in argv else 15,
                                             "cpu_seconds": 60, "output_limit": 65536, "latch": False})
                    if "--version" in argv:
                        stage = "version"
                        self.assertEqual(argv, [str(tools["clang"]), "--no-default-config", "--version"])
                        out = b"unknown compiler\n" if case == "version-invalid" else b"Apple clang version 17.0.0\n"
                        err = b""
                    elif "-o" in argv:
                        stage, out, err = "build", b"", b""
                        self.assertEqual(argv, [str(tools["clang"]), "--no-default-config", "-fno-modules", "-std=c11",
                            "-D_DARWIN_C_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror", "-arch", "arm64",
                            "-isysroot", str(tools["sdk"]), "-B", str(toolchain / "usr/bin"), "-Wl,-adhoc_codesign",
                            str(source), "-lproc", "-o", str(output)])
                        if case == "compile-diagnostics":
                            err = f"{source}:7:9: error: synthetic-private-compiler-canary\n".encode()
                    elif "--verify" in argv:
                        stage, out = "verify", b""
                        err = b"unknown verification diagnostic\n" if case == "verify-diagnostics" else b""
                        self.assertEqual(argv, ["/usr/bin/codesign", "--verify", "--strict", str(output)])
                    elif "--verbose=2" in argv:
                        stage, out = "display", b""
                        err = b"" if case == "display-empty" else display
                        self.assertEqual(argv, ["/usr/bin/codesign", "--display", "--verbose=2", str(output)])
                    else:
                        stage = "entitlements"
                        self.assertEqual(argv, ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(output)])
                        out = b"<plist><dict/></plist>\n" if case == "entitlements-present" else b""
                        err = b"unknown extraction state\n" if case == "entitlements-diagnostics" else f"Executable={output}\n".encode()
                    progress.stage = stage
                    events.append(("run", stage))
                    result = self.module.CapturedRun(out, err, 0, True, True, True, True, False, False,
                                                    0.01, None, (), (len(out), len(err)))
                    failures = {"compile-nonzero": {"returncode": 7}, "compile-unwaited": {"waited": False},
                                "compile-no-stdout-eof": {"stdout_eof": False}, "compile-no-stderr-eof": {"stderr_eof": False},
                                "compile-no-finality": {"domain_finality": False}, "compile-timeout": {"timed_out": True},
                                "compile-cancel": {"cancelled": True}, "compile-cleanup-error": {"cleanup_errors": ("synthetic close",)}}
                    if stage == "build" and case in failures:
                        result = dataclasses.replace(result, **failures[case])
                    if case == stage + "-unwaited":
                        result = dataclasses.replace(result, waited=False)
                    if case == "compile-late-deadline" and stage == "build":
                        progress.now = session.deadline
                    return result

                def artifact(path, uid, gid, *, deadline):
                    self.assertEqual(deadline, session.deadline)
                    self.assertIsNone(session.process_observer)
                    self.assertTrue(any(event[:2] == ("idle", "build") for event in events))
                    artifacts.append(path)
                    events.append(("artifact", path))
                    if path == output:
                        self.assertEqual((uid, gid), (session.uid, session.gid))
                        if len(artifacts) == 2:
                            if case == "post-signature-bytes":
                                return binary + b"changed", 0o755
                            if case == "post-signature-mode":
                                return binary, 0o555
                        return binary, 0o755
                    self.assertEqual((path, uid, gid), (frozen, 0, 0))
                    return (binary + b"changed" if case == "frozen-bytes" else binary,
                            0o755 if case == "frozen-mode" else 0o555)

                def freeze(path, data, mode):
                    self.assertEqual((path, data, mode), (frozen, binary, 0o555))
                    self.assertEqual(artifacts, [output, output])
                    events.append(("freeze",))
                    if case == "freeze-copy-error":
                        raise ExceptionGroup("synthetic copy failure", [OSError(errno.EEXIST, "synthetic no-clobber collision")])

                def native(candidate):
                    self.assertEqual(candidate, frozen)
                    self.assertEqual(artifacts, [output, output, frozen])
                    self.assertIsNone(session.process_observer)
                    self.assertFalse(session.admitted)
                    self.assertNotIn(observer_key, session._environment({}))
                    events.append(("native",))
                    progress.stage = "native"
                    if case == "native-error":
                        raise ExceptionGroup("synthetic native failure", [OSError(errno.EIO, "not proven")])

                def source_bytes(path):
                    self.assertEqual(path, source)
                    return b"x" * 65537 if case == "source-too-large" else c_bytes

                def absent(path):
                    self.assertIn(path, (output, frozen))
                    if case == "output-collision" and path == output or case == "frozen-collision" and path == frozen:
                        return SimpleNamespace()
                    raise FileNotFoundError(errno.ENOENT, "synthetic absent task-owned name")

                def mkdir(path, *, mode):
                    self.assertEqual(mode, 0o700)
                    self.assertIn(path, [session.work / name for name in ("home", "tmp", "config", "cache")])

                actual_toolchain, provider_failures = self.module._observer_toolchain, []
                provider_snapshot = SimpleNamespace(st_uid=session.uid, st_gid=20, st_mode=stat.S_IFDIR | 0o755)
                provider_error = OSError(errno.EACCES, "synthetic-private-provider-message", "/synthetic/private-provider-path")

                def provider_state(path):
                    self.assertEqual(path, xcode)
                    if case == "toolchain-stat-error":
                        raise provider_error
                    return provider_snapshot

                provider_stat = Mock(side_effect=provider_state)

                def failing_toolchain(uid, gid, *, deadline):
                    self.assertEqual((uid, gid, deadline), (session.uid, session.gid, session.deadline))
                    # Reach the actual first provider decision in the actual
                    # admit -> observer-preparation -> toolchain call chain.
                    # Its canonical paths and sole metadata result are inert;
                    # inventory reads/builds cannot be reached on this failure.
                    with patch.object(self.module, "_canonical", Path), \
                         patch.object(Path, "resolve", lambda path, *, strict: path), \
                         patch.object(Path, "stat", lambda path: provider_stat(path)), \
                         patch.object(Path, "iterdir", side_effect=AssertionError("rejected provider may not enumerate")), \
                         patch.object(Path, "open", side_effect=AssertionError("rejected provider may not read")):
                        try:
                            return actual_toolchain(uid, gid, deadline=deadline)
                        except BaseException as exc:
                            provider_failures.append(exc)
                            raise

                prepared_tools = Mock(return_value=tools, side_effect=failing_toolchain
                                      if case in {"toolchain-error", "toolchain-stat-error"} else None)
                fake_os = SimpleNamespace(chown=Mock(), uname=lambda: SimpleNamespace(machine="unsupported" if case == "unsupported-arch" else "arm64"),
                                          path=SimpleNamespace(basename=os.path.basename))
                with patch.multiple(self.module, os=fake_os, subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    _readonly_tree=Mock(), _domain=Mock(return_value=set()),
                                    _small_command=Mock(return_value=b"MRK_NSS_ABSENT\n"),
                                    _admit_executable=Mock(return_value={"root_owned": True, "setuid": False, "setgid": False}),
                                    _observer_toolchain=prepared_tools, _observer_artifact=artifact,
                                    time=SimpleNamespace(monotonic=lambda: progress.now)), \
                     patch.object(session, "_headroom", Mock()), patch.object(session, "_preflight", side_effect=preflight), \
                     patch.object(session, "_prepare_home_boundary", Mock()), \
                     patch.object(session, "ensure_idle", side_effect=idle), patch.object(session, "_run", side_effect=run) as commands, \
                     patch.object(session, "_observer_native_controls", side_effect=native) as controls, \
                     patch.object(self.module, "_private_file", side_effect=freeze) as copy, \
                     patch.object(Path, "read_bytes", source_bytes), patch.object(Path, "lstat", absent), patch.object(Path, "mkdir", mkdir):
                    if case == "valid":
                        session.admit()
                        self.assertTrue(session.admitted)
                        self.assertEqual(session.process_observer, frozen)
                        self.assertEqual(session._environment({})[observer_key], str(frozen))
                        self.assertIsNone(session.failure)
                        self.assertEqual(commands.call_count, 5)
                        copy.assert_called_once_with(frozen, binary, 0o555)
                        controls.assert_called_once_with(frozen)
                        self.assertLess(events.index(("base-preflight",)), events.index(("run", "version")))
                        self.assertLess(events.index(("run", "build")), events.index(("artifact", output)))
                        self.assertLess(events.index(("freeze",)), events.index(("native",)))
                        self.assertEqual(events[-1], ("idle", "native", True))
                        note = next(n for n in session.admission_results if n["name"] == "process-observer")
                        self.assertTrue(note["ok"])
                        self.assertEqual(note["source_sha256"], hashlib.sha256(c_bytes).hexdigest())
                        self.assertEqual(note["binary_sha256"], hashlib.sha256(binary).hexdigest())
                        self.assertEqual((note["mode"], note["producer_mode"], note["entitlements"]), ("0555", "0755", "none"))
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)) as caught:
                            session.admit()
                        self.assertFalse(session.admitted)
                        self.assertIsNone(session.process_observer)
                        self.assertNotIn(observer_key, session._environment({}))
                        self.assertEqual(session.failure, "native isolation admission failed; no product command permitted")
                        self.assertFalse(any(n["ok"] for n in session.admission_results if n["name"] == "process-observer"))
                        if case in {"toolchain-error", "toolchain-stat-error"}:
                            self.assertEqual(provider_failures, [caught.exception])
                            provider_stat.assert_called_once_with(xcode)
                            rejection = next(n for n in session.admission_results if n["name"] == "native-admission-failure")
                            observation = caught.exception._ci_observation["provider"]
                            self.assertEqual(rejection["exceptions"][0]["observation"], {"provider": observation})
                            self.assertEqual((observation["phase"], observation["role"], observation["index"]),
                                             ("ancestor", "xcode", 0))
                            if case == "toolchain-stat-error":
                                self.assertIs(caught.exception, provider_error)
                                self.assertEqual(observation, {"phase": "ancestor", "role": "xcode", "index": 0, "observed": False})
                                self.assertEqual(rejection["exceptions"][0]["errno"], errno.EACCES)
                            else:
                                self.assertIs(observation["subject_owned"], True)
                                self.assertEqual(observation["failed_predicates"], ["subject-owned"])
                            self.assertNotIn("synthetic-private", json.dumps(session.admission_results))
                            self.assertNotIn(str(xcode), json.dumps(rejection))
                        before = commands.call_count
                        progress.now = 0.0
                        with self.assertRaises(self.module.SessionError):
                            session.run([str(session.python)], cwd=session.work, env={}, seconds=1)
                        self.assertEqual(commands.call_count, before)
                    self.assertFalse(session._admitting)
                prepared_tools.assert_called_once_with(session.uid, session.gid, deadline=session.deadline)
                early = case.startswith("compile-") or case in {"toolchain-error", "toolchain-stat-error", "unsupported-arch", "source-too-large",
                                                               "output-collision", "frozen-collision", "version-invalid"}
                if early:
                    self.assertEqual(artifacts, [])
                    copy.assert_not_called()
                    controls.assert_not_called()
                if case == "compile-diagnostics":
                    note = next(n for n in session.admission_results if n["name"] == "process-observer-build")
                    self.assertFalse(note["ok"])
                    self.assertEqual(note["compiler_diagnostics"], [{"file": ".github/scripts/ci_process_observer.c",
                                     "line": 7, "column": 9, "severity": "error"}])
                    self.assertNotIn("synthetic-private-compiler-canary", json.dumps(session.admission_results))

    def test_observer_root_control_keeps_foreign_original_custody_and_collects_late_failures(self):
        for case in ("valid", "bad-ready", "bad-root-observation", "probe-unwaited", "probe-footer", "probe-stderr",
                     "communicate-error", "wrong-close-footer", "poll-error", "wait-error", "missing-wait",
                     "primary-and-close-errors", "unknown-domain", "late-close"):
            with self.subTest(observer_root_control=case):
                session = session_double(self.module, "darwin")
                session.admitted = False
                session.process_observer = None
                session.deadline = 25.0
                candidate = session.bootstrap / "process-observer"
                clock, events = SimpleNamespace(now=0.0), []
                original_error = OSError(errno.EIO, "synthetic original control error")
                close_errors = [OSError(errno.EIO, "synthetic stdin close"), OSError(errno.EIO, "synthetic stderr close")]
                child = SimpleNamespace(pid=5252, returncode=None)

                def close(index):
                    events.append(("close", index))
                    if case == "primary-and-close-errors" and index in {0, 2}:
                        raise close_errors[index // 2]
                    if case == "late-close" and index == 2:
                        clock.now = 25.0

                child.stdin, child.stdout, child.stderr = [SimpleNamespace(close=Mock(side_effect=lambda i=i: close(i))) for i in range(3)]

                def communicate(data, *, timeout):
                    self.assertEqual((data, timeout), (b"q", 2))
                    events.append(("communicate",))
                    if case == "communicate-error":
                        raise original_error
                    child.returncode = 0
                    return (b"wrong\n" if case == "wrong-close-footer" else b"MRK_SENTINEL_CLOSED\n"), b""

                def poll():
                    events.append(("poll",))
                    if case == "poll-error":
                        raise original_error
                    return child.returncode

                def kill():
                    events.append(("kill-original",))
                    child.returncode = -9

                def wait(*, timeout):
                    events.append(("wait", timeout))
                    if case == "wait-error":
                        raise original_error
                    return None if case == "missing-wait" else child.returncode

                child.communicate, child.poll, child.kill, child.wait = (Mock(side_effect=communicate), Mock(side_effect=poll),
                                                                       Mock(side_effect=kill), Mock(side_effect=wait))

                def ready(stream, timeout):
                    self.assertIs(stream, child.stdout)
                    self.assertEqual(timeout, 5)
                    events.append(("ready",))
                    return b"wrong\n" if case == "bad-ready" else b"MRK_SENTINEL_READY\n"

                def snapshot(*, deadline):
                    self.assertEqual(deadline, 25.0)
                    child.poll.assert_not_called()
                    child.wait.assert_not_called()
                    events.append(("root-observation",))
                    return {} if case == "bad-root-observation" else {(child.pid, child.pid): ((0, 0, 0), (0, 0, 0), 65536)}

                def run(argv, **kwargs):
                    self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry),
                                           "--observer-probe", str(candidate), str(child.pid), "20.0"])
                    self.assertEqual(kwargs, {"cwd": session.work, "env": {}, "seconds": 20.0, "latch": False})
                    self.assertIn(("root-observation",), events)
                    child.poll.assert_not_called()
                    child.wait.assert_not_called()
                    events.append(("subject-control",))
                    out = b"wrong\n" if case in {"probe-footer", "primary-and-close-errors"} else b"MRK_PROCESS_OBSERVER_OK\n"
                    err = b"unexpected\n" if case == "probe-stderr" else b""
                    return self.module.CapturedRun(out, err, 0, case != "probe-unwaited", True, True, True,
                                                   False, False, 0.01, None, (), (len(out), len(err)))

                domain = Mock(return_value=set(), side_effect=OSError(errno.EIO, "synthetic domain unknown")
                              if case == "unknown-domain" else None)
                launch = Mock(return_value=child)
                with patch.multiple(self.module, os=SimpleNamespace(geteuid=lambda: 0, getgid=lambda: 0),
                                    subprocess=SimpleNamespace(Popen=launch, PIPE=-1), selectors=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now), _ready_line=ready,
                                    _mac_snapshot=snapshot, _domain=domain,
                                    _small_command=Mock(side_effect=AssertionError("no real metadata/native tool"))), \
                     patch.object(session, "_headroom", Mock()), patch.object(session, "_run", side_effect=run):
                    if case == "valid":
                        session._observer_native_controls(candidate)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            session._observer_native_controls(candidate)
                        if case == "primary-and-close-errors":
                            self.assertIsInstance(caught.exception.exceptions[0], self.module.SessionError)
                            self.assertEqual(caught.exception.exceptions[1:], tuple(close_errors))
                launch.assert_called_once_with([str(session.python), "-I", "-S", "-B", str(session.entry), "--sentinel"],
                    cwd=session.work, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, stdin=-1, stdout=-1, stderr=-1,
                    close_fds=True, start_new_session=True, bufsize=0)
                self.assertNotIn(str(candidate), launch.call_args.args[0])  # The compiled reader is NEVER a root command.
                child.wait.assert_called_once()
                self.assertTrue(0 <= child.wait.call_args.kwargs["timeout"] <= 2)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close.assert_called_once_with()
                notes = [n for n in session.admission_results if n["name"] == "process-observer-native"]
                if notes:
                    self.assertEqual(notes[0]["ok"], case == "valid")
                if case == "valid":
                    self.assertEqual(len(notes), 1)
                    self.assertLess(events.index(("subject-control",)), events.index(("communicate",)))
                    self.assertLess(events.index(("communicate",)), events.index(("poll",)))
                    child.kill.assert_not_called()
                    self.assertEqual(domain.call_count, 2)
                self.assertIsNone(session.process_observer)

    def test_observer_eof_never_reaps_and_foreign_denial_is_an_exact_waited_kernel_result(self):
        footer = b"MRK_OBSERVER_FAMILY_RELEASED\n"
        for case in ("valid", "missing-footer", "stderr", "over-limit", "held-pipe", "selector-acquire", "selector-close", "close-expiry"):
            with self.subTest(observer_eof=case):
                rig = _Collection(self.module, stdout=(footer,), stderr=())
                primary = OSError(errno.EIO, "synthetic observer selector acquisition")
                if case == "missing-footer":
                    rig.chunks[0] = []
                elif case == "stderr":
                    rig.chunks[1] = [b"unexpected diagnostics\n"]
                elif case == "over-limit":
                    rig.chunks[0] = [b"x" * 513]
                elif case == "held-pipe":
                    rig.hold = {0}
                elif case == "selector-acquire":
                    rig.selector_error = primary
                elif case == "selector-close":
                    rig.selector_close_error = True
                original_close = rig.selector.close

                def close_selector():
                    original_close()
                    if case == "close-expiry":
                        rig.now = 1.0

                with rig.scope(), patch.object(rig.selector, "close", close_selector):
                    if case == "valid":
                        self.module._observer_control_eof(rig.child, deadline=1.0)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._observer_control_eof(rig.child, deadline=1.0)
                        if case == "selector-acquire":
                            self.assertEqual(caught.exception.exceptions, (primary,))
                        elif case in {"held-pipe", "close-expiry"}:
                            self.assertTrue(any(isinstance(e, self.module.DeadlineExpired) for e in caught.exception.exceptions))
                self.assertFalse(any(event[0] in {"poll", "wait-original", "kill-original", "terminate-original", "stream-close", "popen"}
                                     for event in rig.events))
                self.assertEqual(sum(event[0] == "selector-close" for event in rig.events), int(case != "selector-acquire"))
                if case == "valid":
                    self.assertIn(("unregister-eof", 0), rig.events)
                    self.assertIn(("unregister-eof", 1), rig.events)

        observer, foreign = Path("/synthetic/bootstrap/process-observer"), 7000
        for case in ("eperm", "eacces", "identity-denied", "generic-error", "absent", "metadata-unwaited", "late", "root", "linux"):
            with self.subTest(observer_foreign_query=case):
                clock = SimpleNamespace(now=0.0)
                records = {"identity-denied": f"MRK_PROCESS_V1 denied {foreign} identity 0\n",
                           "generic-error": "MRK_PROCESS_V1 error target-query\n", "absent": f"MRK_PROCESS_V1 absent {foreign}\n"}
                raw = records.get(case, f"MRK_PROCESS_V1 denied {foreign} kernel {errno.EACCES if case == 'eacces' else errno.EPERM}\n").encode()

                def metadata(argv, seconds, **kwargs):
                    self.assertEqual(argv, [str(observer), str(foreign)])
                    self.assertEqual(seconds, 3)
                    self.assertEqual(kwargs, {"expected_code": 2, "deadline": 1.0})
                    if case == "metadata-unwaited":
                        raise ExceptionGroup("synthetic original metadata wait failure", [TimeoutError("no actual wait")])
                    if case == "late":
                        clock.now = 1.0
                    return raw

                command = Mock(side_effect=metadata)
                with patch.multiple(self.module, sys=SimpleNamespace(platform="linux" if case == "linux" else "darwin"),
                                    os=SimpleNamespace(getuid=lambda: 0 if case == "root" else 60001, getgid=lambda: 60001),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(), _small_command=command,
                                    time=SimpleNamespace(monotonic=lambda: clock.now)):
                    if case in {"eperm", "eacces"}:
                        self.assertEqual(self.module._observer_query(observer, foreign, None, deadline=1.0, kernel_denied=True), "denied")
                    else:
                        with self.assertRaises((self.module.SessionError, BaseExceptionGroup)):
                            self.module._observer_query(observer, foreign, None, deadline=1.0, kernel_denied=True)
                if case in {"root", "linux"}:
                    command.assert_not_called()
                else:
                    command.assert_called_once()

    def test_observer_probe_keeps_real_zombie_window_and_family_waits_its_own_descendant(self):
        entry = Path("/synthetic/bootstrap/ci_sandbox.py")
        candidate, foreign = entry.parent / "process-observer", 7000

        def own_entry(path):
            self.assertEqual(path, Path(self.module.__file__))
            return entry

        for case in ("valid", "vanished-before-reap", "present-after-reap", "foreign-error", "eof-error", "deadline"):
            with self.subTest(observer_probe=case):
                clock = SimpleNamespace(now=0.0, released=False, reaped=False)
                events = []
                child = SimpleNamespace(pid=4242, returncode=None)
                for name, fd in (("stdin", 12), ("stdout", 10), ("stderr", 11)):
                    setattr(child, name, SimpleNamespace(fileno=lambda fd=fd: fd, close=Mock()))

                def poll():
                    events.append(("poll",))
                    return child.returncode

                def kill():
                    events.append(("kill-original",))
                    child.returncode = -9

                def wait(*, timeout):
                    events.append(("wait", timeout))
                    clock.reaped = True
                    child.returncode = 0 if child.returncode is None else child.returncode
                    return child.returncode

                child.poll, child.kill, child.wait = Mock(side_effect=poll), Mock(side_effect=kill), Mock(side_effect=wait)

                def query(observer, pid, group, *, deadline, kernel_denied=False):
                    self.assertEqual((observer, deadline), (candidate, 1.0))
                    if pid == foreign:
                        self.assertEqual((group, kernel_denied), (None, True))
                        if case == "foreign-error":
                            raise self.module.SessionError("synthetic foreign observation not kernel-denied")
                        state = "denied"
                    else:
                        self.assertIn(pid, (child.pid, 5277))
                        self.assertEqual((group, kernel_denied), (child.pid, False))
                        state = ("indeterminate" if case == "deadline" else "live") if not clock.released else (
                            ("absent" if case == "vanished-before-reap" else "zombie") if not clock.reaped else
                            ("live" if case == "present-after-reap" else "absent"))
                    events.append(("query", pid, state))
                    if len(events) > 128:
                        raise AssertionError("finite synthetic observation budget exhausted")
                    return state

                def release(fd, data):
                    self.assertEqual((fd, data), (12, b"q"))
                    child.poll.assert_not_called()
                    child.wait.assert_not_called()
                    clock.released = True
                    events.append(("release",))
                    return 1

                def eof(original, *, deadline):
                    self.assertIs(original, child)
                    self.assertEqual(deadline, 1.0)
                    self.assertTrue(clock.released)
                    child.poll.assert_not_called()
                    child.wait.assert_not_called()
                    events.append(("eof",))
                    if case == "eof-error":
                        raise self.module.SessionError("synthetic incomplete owned EOF")

                def sleep(seconds):
                    self.assertTrue(0 < seconds <= 0.01)
                    clock.now += seconds

                launch = Mock(return_value=child)
                output = io.StringIO()
                with patch.multiple(self.module, sys=SimpleNamespace(platform="darwin", executable="/synthetic/python"),
                                    os=SimpleNamespace(getuid=lambda: 60001, geteuid=lambda: 60001, getgid=lambda: 60001,
                                                       getegid=lambda: 60001, getpid=lambda: 6161, write=release),
                                    subprocess=SimpleNamespace(Popen=launch, PIPE=-1), signal=SimpleNamespace(), selectors=SimpleNamespace(),
                                    _ready_line=Mock(return_value=b"MRK_OBSERVER_FAMILY 5277\n"),
                                    _observer_query=query, _observer_control_eof=eof,
                                    _small_command=Mock(side_effect=AssertionError("no real observer invocation")),
                                    time=SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep)), \
                     patch.object(Path, "resolve", own_entry), redirect_stdout(output):
                    if case == "valid":
                        self.module._observer_probe(candidate, foreign, 1.0)
                    else:
                        with self.assertRaises(BaseExceptionGroup):
                            self.module._observer_probe(candidate, foreign, 1.0)
                launch.assert_called_once_with(["/synthetic/python", "-I", "-S", "-B", str(entry), "--observer-family", "1.0"],
                    stdin=-1, stdout=-1, stderr=-1, close_fds=True, start_new_session=True, bufsize=0)
                self.assertLessEqual(clock.now, 1.001)
                self.assertTrue(child.wait.called)
                for stream in (child.stdout, child.stderr):
                    stream.close.assert_called_once_with()
                self.assertTrue(child.stdin.close.called)
                if case == "valid":
                    self.assertEqual(output.getvalue(), "MRK_PROCESS_OBSERVER_OK\n")
                    zombie = events.index(("query", child.pid, "zombie"))
                    original_wait = next(i for i, event in enumerate(events) if event[0] == "wait")
                    self.assertLess(events.index(("query", 5277, "live")), events.index(("release",)))
                    self.assertLess(events.index(("eof",)), zombie)
                    self.assertLess(zombie, original_wait)
                    self.assertLess(original_wait, events.index(("query", child.pid, "absent")))
                    self.assertTrue(all(i > zombie for i, event in enumerate(events) if event[0] in {"poll", "wait"}))
                    self.assertEqual(child.wait.call_count, 2)
                    child.kill.assert_not_called()
                else:
                    self.assertEqual(output.getvalue(), "")
                    if case == "vanished-before-reap":
                        self.assertLess(events.index(("query", child.pid, "absent")),
                                        next(i for i, event in enumerate(events) if event[0] == "wait"))

        for case in ("valid", "wrong-descendant-footer", "selector-and-stream-close-errors", "late-final-close"):
            with self.subTest(observer_family=case):
                clock = SimpleNamespace(now=0.0)
                events = []
                child = SimpleNamespace(pid=5277, returncode=None)
                selector_error = OSError(errno.EIO, "synthetic release selector close")
                stream_error = OSError(errno.EIO, "synthetic descendant stdout close")

                def close(index):
                    events.append(("stream-close", index))
                    if case == "selector-and-stream-close-errors" and index == 1:
                        raise stream_error
                    if case == "late-final-close" and index == 2:
                        clock.now = 1.0

                child.stdin, child.stdout, child.stderr = [SimpleNamespace(close=Mock(side_effect=lambda i=i: close(i))) for i in range(3)]

                def communicate(data, *, timeout):
                    self.assertEqual((data, timeout), (b"q", 1.0))
                    events.append(("communicate",))
                    child.returncode = 0
                    return (b"wrong\n" if case == "wrong-descendant-footer" else b"MRK_SENTINEL_CLOSED\n"), b""

                def wait(*, timeout):
                    events.append(("wait", timeout))
                    return child.returncode

                def kill():
                    child.returncode = -9

                child.communicate, child.poll, child.kill, child.wait = (Mock(side_effect=communicate), Mock(side_effect=lambda: child.returncode),
                                                                       Mock(side_effect=kill), Mock(side_effect=wait))

                class ReleaseSelector:
                    def __enter__(selector):
                        return selector

                    def register(selector, fd, event):
                        self.assertEqual((fd, event), (0, 1))

                    def select(selector, timeout):
                        self.assertEqual(timeout, 1.0)
                        return [("synthetic-ready", 1)]

                    def __exit__(selector, *_error):
                        events.append(("selector-close",))
                        if case == "selector-and-stream-close-errors":
                            raise selector_error

                launch, output = Mock(return_value=child), io.StringIO()
                with patch.multiple(self.module, sys=SimpleNamespace(platform="darwin", executable="/synthetic/python"),
                                    os=SimpleNamespace(getuid=lambda: 60001, geteuid=lambda: 60001, read=Mock(return_value=b"q")),
                                    subprocess=SimpleNamespace(Popen=launch, PIPE=-1), signal=SimpleNamespace(),
                                    selectors=SimpleNamespace(DefaultSelector=ReleaseSelector, EVENT_READ=1),
                                    _ready_line=Mock(return_value=b"MRK_SENTINEL_READY\n"),
                                    time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", own_entry), redirect_stdout(output):
                    if case == "valid":
                        self.module._observer_family(1.0)
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            self.module._observer_family(1.0)
                        if case == "selector-and-stream-close-errors":
                            self.assertEqual(caught.exception.exceptions, (selector_error, stream_error))
                launch.assert_called_once_with(["/synthetic/python", "-I", "-S", "-B", str(entry), "--sentinel"],
                                               stdin=-1, stdout=-1, stderr=-1, close_fds=True, bufsize=0)
                child.wait.assert_called_once()
                self.assertEqual([event for event in events if event[0] == "stream-close"], [("stream-close", 0), ("stream-close", 1), ("stream-close", 2)])
                self.assertEqual("MRK_OBSERVER_FAMILY_RELEASED\n" in output.getvalue(), case == "valid")
                if case == "valid":
                    child.kill.assert_not_called()
                    self.assertLess(events.index(("communicate",)), next(i for i, event in enumerate(events) if event[0] == "wait"))

    def test_provider_boundary_probe_runs_after_inherited_fd_guard_and_keeps_every_fixed_child_route(self):
        class BoundaryReached(RuntimeError):
            pass

        uid = gid = 60001
        for platform in ("linux", "darwin"):
            data = {"platform": platform, "uid": uid, "gid": gid,
                    "runtime_executables": ["/synthetic/python/bin/python", "/synthetic/ruby/bin/ruby"],
                    "runner_home": "/Users/runner", "ruby_prefix": "/Users/runner/tools/ruby",
                    "ruby_executable": "/Users/runner/tools/ruby/bin/ruby",
                    "home_canary": "/Users/runner/.mrk-pure-fixture-home-read", "home_socket": "/Users/runner/.mrk-pure-fixture-home-socket",
                    "home_sibling": "/Users/runner/tools/.mrk-pure-fixture-ancestor-read",
                    "work": "/tmp/mrk-pure-fixture/work", "host_net": "host-net", "host_pid": "host-pid"}
            seen = []

            def inherited(fd):
                self.assertIn(fd, range(1024))
                seen.append(fd)
                if fd > 2:
                    raise OSError(errno.EBADF, "synthetic absent inherited descriptor")
                return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)

            def boundary(actual):
                self.assertIs(actual, data)
                self.assertEqual(seen, list(range(1024)))
                raise BoundaryReached

            def root_stat(path):
                self.assertEqual(path, Path(data["work"]).parent)
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)

            def status(path):
                self.assertEqual(path, Path("/proc/self/status"))
                return "CapInh:0\nCapPrm:0\nCapEff:0\nCapBnd:0\nCapAmb:0\nNoNewPrivs:1\n"

            def namespace(path):
                self.assertIn(path, ("/proc/self/ns/net", "/proc/self/ns/pid"))
                return "subject-" + path.rsplit("/", 1)[1]

            def root_entries(path):
                self.assertEqual(path, Path(data["work"]).parent)
                return ["source", "inputs", "bootstrap", "work"]

            regain = Mock(side_effect=PermissionError(errno.EPERM, "synthetic regain-root denial"))

            with self.subTest(provider_leaf_order=platform), \
                 patch.multiple(self.module, os=SimpleNamespace(getuid=lambda: uid, geteuid=lambda: uid,
                                    getgid=lambda: gid, getegid=lambda: gid, fstat=inherited,
                                    getresuid=lambda: (uid, uid, uid), getresgid=lambda: (gid, gid, gid),
                                    readlink=namespace, listdir=root_entries, setuid=regain),
                                socket=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                _process_groups=Mock(return_value=[] if platform == "linux" else [gid]),
                                _probe_provider_boundaries=Mock(side_effect=boundary)), \
                 patch.object(Path, "stat", root_stat), patch.object(Path, "read_text", status), \
                 patch.object(Path, "read_bytes", side_effect=AssertionError("no actual file may be read")):
                with self.assertRaises(BoundaryReached):
                    self.module._probe_leaf(data)
            regain.assert_called_once_with(0)

        entry = Path("/synthetic/bootstrap/ci_sandbox.py")
        for case in ("parent", "grandchild", "child-footer", "child-unwaited"):
            with self.subTest(provider_inheritance=case):
                routes, output = [], io.StringIO()
                original = TimeoutError("synthetic incomplete original child collection")

                def own_entry(path):
                    self.assertEqual(path, Path(self.module.__file__))
                    return entry

                def collected(argv, seconds, *, detached):
                    self.assertEqual(argv[:5], ["/synthetic/python", "-I", "-S", "-B", str(entry)])
                    self.assertEqual(len(argv), 7)
                    self.assertEqual(json.loads(argv[6]), data)
                    self.assertEqual(seconds, 10)
                    self.assertIn(argv[5], ("--leaf", "--grandchild"))
                    self.assertEqual(detached, argv[5] == "--grandchild")
                    routes.append(argv[5])
                    if case == "child-unwaited":
                        raise original
                    return b"wrong\n" if case == "child-footer" else b"MRK_LEAF_OK\n"

                leaf, sudo = Mock(), Mock()
                with patch.multiple(self.module, sys=SimpleNamespace(executable="/synthetic/python"),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    _probe_leaf=leaf, _small_command=collected, _sudo_denial=sudo), \
                     patch.object(Path, "resolve", own_entry), redirect_stdout(output):
                    if case in {"parent", "grandchild"}:
                        self.module._probe(data, grandchild=case == "grandchild")
                    else:
                        with self.assertRaises(TimeoutError if case == "child-unwaited" else self.module.SessionError) as caught:
                            self.module._probe(data)
                        if case == "child-unwaited":
                            self.assertIs(caught.exception, original)
                leaf.assert_called_once_with(data)
                self.assertEqual(routes, ["--leaf", "--grandchild"] if case == "parent" else ["--leaf"])
                if case == "parent":
                    sudo.assert_called_once_with()
                else:
                    sudo.assert_not_called()
                self.assertEqual(output.getvalue(), "MRK_NATIVE_ISOLATION_OK\n" if case == "parent" else
                                 "MRK_LEAF_OK\n" if case == "grandchild" else "")

    def test_home_owned_handles_close_once_without_restoring_unknown_finality_or_expired_state(self):
        for case in ("busy", "active", "pending-direct", "pending-direct-close", "remaining", "unknown", "expired", "independent-close-errors"):
            with self.subTest(home_unknown_finality=case):
                session = session_double(self.module, "darwin")
                session.runner_home = Path("/Users/runner")
                session.ruby_prefix = session.runner_home / "tools/ruby"
                session.ruby_ancestors = (session.runner_home, session.ruby_prefix.parent)
                session.deadline = 1.0
                session.failure = "earlier immutable failure"
                session.domain_finality = True
                session._busy = case == "busy"
                session._active = object() if case == "active" else None
                session._direct_producer_pending = case in {"pending-direct", "pending-direct-close"}
                original = SimpleNamespace(st_dev=7, st_ino=101, st_mode=stat.S_IFDIR | 0o750, st_uid=1001, st_gid=20, st_nlink=2)
                canary = SimpleNamespace(st_dev=7, st_ino=102, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1)
                endpoint = SimpleNamespace(st_dev=7, st_ino=103, st_mode=stat.S_IFSOCK | 0o666, st_uid=0, st_gid=0, st_nlink=1)
                primary = OSError(errno.EIO, "synthetic unknown reserved-identity domain")
                listener_error = OSError(errno.EIO, "synthetic original HOME listener close")
                canary_error = OSError(errno.EIO, "synthetic original HOME canary close")
                pin_error = OSError(errno.EIO, "synthetic original HOME pin close")
                sibling_error = OSError(errno.EIO, "synthetic original sibling close")
                sibling_pin_error = OSError(errno.EIO, "synthetic original sibling parent close")
                listener = SimpleNamespace(close=Mock(side_effect=listener_error if case == "independent-close-errors" else None))
                session._home_state = {"pin": 101, "original": original, "change_attempted": True, "prepared": True,
                    "expected_mode": 0o751, "canary_fd": 102, "canary_name": f".{session.root.name}-home-read",
                    "canary_identity": canary, "canary_mode": 0o444, "canary_create_attempted": True, "listener": listener,
                    "socket_name": f".{session.root.name}-home-socket", "socket_identity": endpoint, "socket_mode": 0o666,
                    "socket_bind_attempted": True, "sibling_pin": 103, "sibling_parent_original": original,
                    "sibling_parent_mode": 0o755, "sibling_fd": 104, "sibling_name": f".{session.root.name}-ancestor-read",
                    "sibling_create_attempted": True, "sibling_identity": canary, "sibling_mode": 0o444, "closed": False}

                def close(fd):
                    self.assertIn(fd, (101, 102, 103, 104))
                    if case == "independent-close-errors":
                        raise {101: pin_error, 102: canary_error, 103: sibling_pin_error, 104: sibling_error}[fd]

                closed = Mock(side_effect=close)
                denied = Mock(side_effect=AssertionError("unknown ownership/finality cannot change HOME state"))
                domain = Mock(side_effect=primary) if case in {"unknown", "independent-close-errors"} else Mock(
                    return_value={} if case in {"pending-direct", "pending-direct-close"} else {4242})
                with patch.multiple(self.module, os=SimpleNamespace(close=closed, fchmod=denied, unlink=denied, geteuid=lambda: 0,
                                        path=SimpleNamespace(basename=os.path.basename)),
                                    subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(),
                                    _domain=domain, time=SimpleNamespace(monotonic=lambda: 1.0 if case == "expired" else 0.0)), \
                     patch.object(Path, "stat", side_effect=AssertionError("no real HOME stat is permitted")), \
                     patch.object(Path, "lstat", side_effect=AssertionError("no real HOME lstat is permitted")), \
                     patch.object(Path, "chmod", denied), patch.object(Path, "unlink", denied):
                    if case == "pending-direct-close":
                        finalizer, failures = session._close_home_boundary, []

                        def finalize():
                            errors = finalizer()
                            failures.extend(errors)
                            return errors

                        with patch.object(session, "_close_home_boundary", side_effect=finalize):
                            with self.assertRaisesRegex(self.module.SessionError, "earlier immutable failure"):
                                session.close(keep_timer=True)
                        self.assertTrue(session.closed)
                        self.assertFalse(session.domain_finality)
                    else:
                        failures = session._close_home_boundary()
                    self.assertTrue(failures)
                    self.assertTrue(session._home_state["closed"])
                    self.assertEqual(session._close_home_boundary(), [])
                denied.assert_not_called()
                self.assertEqual(sorted(c.args[0] for c in closed.call_args_list), [101, 102, 103, 104])
                listener.close.assert_called_once_with()
                self.assertEqual(session.failure, "earlier immutable failure")
                self.assertEqual(session.deadline, 1.0)
                if case in {"pending-direct", "pending-direct-close"}:
                    domain.assert_not_called()  # Empty U census cannot resolve another original root producer.
                    self.assertTrue(session._direct_producer_pending)
                if case in {"unknown", "independent-close-errors"}:
                    self.assertIn(primary, failures)
                if case == "independent-close-errors":
                    self.assertTrue(all(error in failures for error in (listener_error, canary_error, pin_error, sibling_error, sibling_pin_error)))

    def test_provider_fixed_write_and_home_read_stat_socket_controls_require_real_specific_denials(self):
        executables = ["/synthetic/python/bin/python", "/synthetic/ruby/bin/ruby"]
        for case in ("eacces", "eperm", "erofs", "missing", "running-text", "unknown", "write-permitted", "write-close-error"):
            with self.subTest(runtime_write_control=case):
                calls = []
                close_error = OSError(errno.EIO, "synthetic admitted-write descriptor close")

                def opened(path, flags):
                    self.assertEqual(str(path), executables[len(calls)])
                    self.assertEqual(flags & os.O_ACCMODE, os.O_WRONLY)
                    self.assertFalse(flags & (os.O_TRUNC | os.O_CREAT | os.O_APPEND))
                    calls.append(str(path))
                    if len(calls) == 2 and case in {"write-permitted", "write-close-error"}:
                        return 301
                    number = {"eacces": errno.EACCES, "eperm": errno.EPERM, "erofs": errno.EROFS,
                              "missing": errno.ENOENT, "running-text": errno.ETXTBSY, "unknown": errno.EIO}.get(case, errno.EACCES)
                    raise OSError(number if len(calls) == 2 else errno.EACCES, "synthetic fixed executable write result")

                closed = Mock(side_effect=close_error if case == "write-close-error" else None)
                constants = {k: getattr(os, k) for k in ("O_WRONLY", "O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, open=opened, close=closed),
                                    sys=SimpleNamespace(platform="linux"), socket=SimpleNamespace(),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace()), \
                     patch.object(Path, "stat", side_effect=AssertionError("runtime-write denial is not inferred from stat")), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("runtime-write probe must not read other files")):
                    if case in {"eacces", "eperm", "erofs"}:
                        self.module._probe_provider_boundaries({"platform": "linux", "runtime_executables": executables})
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)):
                            self.module._probe_provider_boundaries({"platform": "linux", "runtime_executables": executables})
                self.assertEqual(calls, executables)
                if case in {"write-permitted", "write-close-error"}:
                    closed.assert_called_once_with(301)
                else:
                    closed.assert_not_called()

        home = Path("/Users/runner")
        canary, address = home / ".mrk-pure-fixture-home-read", home / ".mrk-pure-fixture-home-socket"
        ruby_prefix = home / "tools/ruby"
        ruby = ruby_prefix / "bin/ruby"
        ancestors = (home, ruby_prefix.parent)
        sibling = ruby_prefix.parent / ".mrk-pure-fixture-ancestor-read"
        cases = ("eacces", "eperm", "read-missing", "read-permitted", "stat-missing", "stat-readonly", "stat-permitted",
                 "socket-missing", "socket-unknown", "socket-permitted", "socket-close-error", "ancestor-missing",
                 "ancestor-file", "ancestor-writable", "ancestor-subject-group", "resolve-missing", "resolve-alias",
                 "sibling-binding", "ruby-binding", "sibling-read-missing", "sibling-read-permitted", "sibling-read-close-error",
                 "sibling-stat-missing", "sibling-stat-permitted")
        for case in cases:
            with self.subTest(home_mandatory_control=case):
                events = []
                read_close_error = OSError(errno.EIO, "synthetic sibling denial descriptor close")

                def denied(path, operation):
                    self.assertIn(path, (canary, sibling))
                    operation = operation if path == canary else "sibling-" + operation
                    events.append((operation,))
                    if case == operation + "-permitted" or case == "sibling-read-close-error" and operation == "sibling-read":
                        return b"synthetic literal is readable" if operation in {"read", "sibling-read"} else SimpleNamespace(st_mode=stat.S_IFREG | 0o444)
                    number = errno.EPERM if case == "eperm" else errno.ENOENT if case == operation + "-missing" else errno.EROFS if case == "stat-readonly" and operation == "stat" else errno.EACCES
                    raise OSError(number, "synthetic HOME canary permission result")

                def connect(target):
                    self.assertEqual(str(target), str(address))
                    events.append(("connect",))
                    if case == "socket-permitted":
                        return
                    number = errno.EPERM if case == "eperm" else errno.ENOENT if case == "socket-missing" else errno.EIO if case == "socket-unknown" else errno.EACCES
                    raise OSError(number, "synthetic HOME endpoint connection result")

                endpoint = SimpleNamespace(settimeout=Mock(), connect=Mock(side_effect=connect),
                    close=Mock(side_effect=OSError(errno.EIO, "synthetic HOME endpoint close") if case == "socket-close-error" else None))
                factory = Mock(return_value=endpoint)
                data = {"platform": "darwin", "home_canary": str(canary), "home_socket": str(address),
                        "runner_home": str(home), "work": "/private/tmp/mrk-pure-fixture/work", "uid": 60001, "gid": 60001,
                        "ruby_prefix": str(ruby_prefix), "ruby_executable": str(ruby), "home_sibling": str(sibling)}
                if case == "sibling-binding":
                    data["home_sibling"] = "/unrelated/private-fixture"
                if case == "ruby-binding":
                    data["ruby_executable"] = "/other/provider/bin/ruby"

                def opened(path, flags):
                    self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    result = denied(path, "read")
                    self.assertIsInstance(result, bytes)
                    return 302 if path == canary else 303

                def metadata(path, *, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    if path in ancestors:
                        events.append(("ancestor", path))
                        if path == ancestors[-1] and case == "ancestor-missing":
                            raise FileNotFoundError(errno.ENOENT, "synthetic required ancestor metadata unavailable")
                        mode = stat.S_IFREG | 0o755 if case == "ancestor-file" and path == ancestors[-1] else stat.S_IFDIR | (
                            0o777 if case == "ancestor-writable" and path == ancestors[-1] else 0o751 if path == home else 0o755)
                        return SimpleNamespace(st_mode=mode, st_uid=1001,
                            st_gid=60001 if case == "ancestor-subject-group" and path == ancestors[-1] else 20)
                    return denied(path, "stat")

                def resolved(path, *, strict):
                    self.assertEqual((path, strict), (ruby, True))
                    self.assertEqual(events, [("ancestor", p) for p in ancestors])
                    events.append(("resolve",))
                    if case == "resolve-missing":
                        raise FileNotFoundError(errno.ENOENT, "synthetic selected Ruby resolution failure")
                    return ruby.with_name("other-ruby") if case == "resolve-alias" else ruby

                def read(fd, count):
                    self.assertIn(fd, (302, 303))
                    self.assertEqual(count, len(self.module._HOME_READ_BYTES if fd == 302 else self.module._ANCESTOR_READ_BYTES) + 1)
                    return b"synthetic readable bytes"

                closed = Mock(side_effect=read_close_error if case == "sibling-read-close-error" else None)
                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, fsencode=os.fsencode,
                                        open=opened, stat=metadata, read=read, close=closed), sys=SimpleNamespace(platform="darwin"),
                                    socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=factory),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace()), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("the known-path probe uses only its bounded descriptor")), \
                     patch.object(Path, "resolve", resolved), \
                     patch.object(Path, "stat", side_effect=AssertionError("the known-path probe must not follow links")):
                    if case in {"eacces", "eperm"}:
                        self.module._probe_provider_boundaries(data)
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)) as caught:
                            self.module._probe_provider_boundaries(data)
                        if case == "sibling-read-close-error":
                            self.assertIn(read_close_error, caught.exception.exceptions)
                if factory.called:
                    factory.assert_called_once_with(1, 1)
                    endpoint.close.assert_called_once_with()
                    endpoint.settimeout.assert_called_once()
                    self.assertTrue(0 < endpoint.settimeout.call_args.args[0] <= 3)
                else:
                    endpoint.close.assert_not_called()
                if case == "read-permitted":
                    closed.assert_called_once_with(302)
                elif case in {"sibling-read-permitted", "sibling-read-close-error"}:
                    closed.assert_called_once_with(303)
                else:
                    closed.assert_not_called()
                if case in {"eacces", "eperm"}:
                    self.assertEqual(events, [("ancestor", p) for p in ancestors] +
                                     [("resolve",), ("read",), ("stat",), ("sibling-read",), ("sibling-stat",), ("connect",)])
                elif case in {"sibling-binding", "ruby-binding"}:
                    self.assertEqual(events, [])
                elif case.startswith("ancestor-"):
                    self.assertEqual(events, [("ancestor", p) for p in ancestors])
                elif case.startswith("resolve-"):
                    self.assertEqual(events, [("ancestor", p) for p in ancestors] + [("resolve",)])
                elif case.startswith("socket-"):
                    factory.assert_called_once_with(1, 1)
                    self.assertEqual(events[-1], ("connect",))
                else:
                    operation = "sibling-read" if case.startswith("sibling-read-") else "sibling-stat" if case.startswith("sibling-stat-") else case.split("-", 1)[0]
                    self.assertIn((operation,), events)

    def test_home_search_preparation_and_terminal_restore_keep_original_handles_and_uncertain_effects(self):
        cases = ("750", "751", "755", "deepest-home", "home-mode", "home-owner", "home-group", "home-name", "open-home",
                 "change-before-effect", "change-after-effect", "canary-collision", "canary-stat-error", "canary-links", "canary-subject-group",
                 "canary-short-write", "canary-mode-after-effect", "socket-collision", "socket-subject-group", "socket-mode-after-effect",
                 "manifest-error", "late-preparation", "close-name-drift", "close-mode-drift", "canary-replaced", "canary-group-drift", "socket-group-drift",
                 "restore-after-effect", "all-close-errors", "sibling-parent-open", "sibling-parent-drift", "sibling-replaced",
                 "sibling-collision", "sibling-create-after-effect", "sibling-stat-error", "sibling-subject-group",
                 "sibling-short-write", "sibling-mode-after-effect")
        for case in cases:
            with self.subTest(home_pin_lifecycle=case):
                session = session_double(self.module, "darwin")
                session.admitted = False
                session.process_observer = None
                session.runner_home = Path("/Users/runner")
                session.ruby = session.runner_home / ("ruby/bin/ruby" if case == "deepest-home" else "tools/ruby/bin/ruby")
                session.ruby_prefix = session.ruby.parent.parent
                sibling_parent = session.ruby_prefix.parent
                session.ruby_ancestors = (session.runner_home,) if case == "deepest-home" else (session.runner_home, sibling_parent)
                session.tool_prefixes = (session.python.parent.parent, session.ruby.parent.parent)
                session.deadline = 1.0
                canary_name, socket_name = f".{session.root.name}-home-read", f".{session.root.name}-home-socket"
                canary_path, socket_path = session.runner_home / canary_name, session.runner_home / socket_name
                sibling_name = f".{session.root.name}-ancestor-read"
                sibling_path = sibling_parent / sibling_name
                original_mode = int(case, 8) if case in {"750", "751", "755"} else 0o777 if case == "home-mode" else 0o750
                clock = SimpleNamespace(now=0.0, closing=False)
                events, nodes, captured_cleanup = [], {}, []
                live_fds = {}
                acquired = []
                original_error = OSError(errno.EIO, "synthetic private HOME operation")
                close_errors = {101: OSError(errno.EIO, "synthetic pin close"), 102: OSError(errno.EIO, "synthetic canary close"),
                                103: OSError(errno.EIO, "synthetic sibling parent close"), 104: OSError(errno.EIO, "synthetic sibling close"),
                                "listener": OSError(errno.EIO, "synthetic listener close")}

                def node(inode, kind, mode, *, uid=0, gid=0, links=1, size=0):
                    return dict(st_dev=7, st_ino=inode, st_mode=kind | mode, st_uid=uid, st_gid=gid,
                                st_nlink=links, st_size=size)

                home_node = node(11, stat.S_IFDIR, original_mode,
                                 uid=session.uid if case == "home-owner" else 1001,
                                 gid=session.gid if case == "home-group" else 20, links=2)
                parent_node = home_node if case == "deepest-home" else node(14, stat.S_IFDIR, 0o755, uid=1001, gid=20, links=2)
                session._ruby_ancestor_states = tuple(SimpleNamespace(**(home_node if p == session.runner_home else parent_node))
                                                       for p in session.ruby_ancestors)

                def named_home(path):
                    self.assertIn(path, (session.runner_home, sibling_parent))
                    result = dict(home_node if path == session.runner_home else parent_node)
                    if path == session.runner_home and (case == "home-name" or clock.closing and case == "close-name-drift"):
                        result["st_ino"] += 1
                    if path == sibling_parent and clock.closing and case == "sibling-parent-drift":
                        result["st_ino"] += 1
                    return SimpleNamespace(**result)

                def opened(path, flags, mode=None, *, dir_fd=None):
                    events.append(("open", str(path), flags, mode, dir_fd))
                    if path == session.runner_home and 101 not in acquired:
                        self.assertEqual((flags, mode, dir_fd), (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, None, None))
                        if case == "open-home":
                            raise original_error
                        live_fds[101] = home_node
                        acquired.append(101)
                        return 101
                    if path == sibling_parent:
                        self.assertEqual((flags, mode, dir_fd), (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, None, None))
                        self.assertTrue(session._home_state["prepared"])
                        self.assertIn(("ancestors", session._home_state["expected_mode"]), events)
                        if case == "sibling-parent-open":
                            raise original_error
                        self.assertNotIn(103, acquired)
                        live_fds[103] = parent_node
                        acquired.append(103)
                        return 103
                    self.assertIn(path, (canary_name, sibling_name))
                    is_sibling = path == sibling_name
                    fd = 104 if is_sibling else 102
                    self.assertEqual((flags, mode, dir_fd),
                        (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, 103 if is_sibling else 101))
                    self.assertTrue(session._home_state["prepared"])
                    self.assertTrue(session._home_state["sibling_create_attempted" if is_sibling else "canary_create_attempted"])
                    if case == ("sibling-collision" if is_sibling else "canary-collision"):
                        nodes[path] = node(91, stat.S_IFREG, 0o444, uid=1001)
                        raise FileExistsError(errno.EEXIST, "synthetic foreign existing file name")
                    self.assertNotIn(path, nodes)
                    nodes[path] = node(15 if is_sibling else 12, stat.S_IFREG, 0o600,
                        gid=session.gid if case == ("sibling-subject-group" if is_sibling else "canary-subject-group") else 20,
                        links=2 if not is_sibling and case == "canary-links" else 1)
                    if is_sibling and case == "sibling-create-after-effect":
                        raise original_error  # Created name, but no returned FD/verified identity.
                    live_fds[fd] = nodes[path]
                    acquired.append(fd)
                    return fd

                def fstat(fd):
                    self.assertIn(fd, live_fds)
                    if fd == 102 and case == "canary-stat-error" and not clock.closing:
                        raise original_error
                    if fd == 104 and case == "sibling-stat-error" and not clock.closing:
                        raise original_error
                    return SimpleNamespace(**live_fds[fd])

                def metadata(name, *, dir_fd, follow_symlinks):
                    self.assertEqual((dir_fd, follow_symlinks), (103 if name == sibling_name else 101, False))
                    self.assertIn(name, (canary_name, socket_name, sibling_name))
                    result = dict(nodes[name])
                    if clock.closing and case == "canary-replaced" and name == canary_name:
                        result["st_ino"] += 1
                    if clock.closing and case == "sibling-replaced" and name == sibling_name:
                        result["st_ino"] += 1
                    if clock.closing and (case == "canary-group-drift" and name == canary_name
                                          or case == "socket-group-drift" and name == socket_name):
                        result["st_gid"] = 0  # Even another non-U group is not the original owned node.
                    return SimpleNamespace(**result)

                def fchmod(fd, mode):
                    self.assertIn(fd, live_fds)
                    self.assertIn((fd, mode), {(101, 0o751), (101, original_mode), (102, 0o444), (104, 0o444)})
                    if fd == 101 and not clock.closing:
                        self.assertTrue(session._home_state["change_attempted"])
                    if fd == 102:
                        self.assertIsNone(session._home_state["canary_mode"])
                    if fd == 104:
                        self.assertIsNone(session._home_state["sibling_mode"])
                    events.append(("fchmod", fd, mode, clock.closing))
                    if case == "change-before-effect" and fd == 101 and not clock.closing:
                        raise original_error
                    live_fds[fd]["st_mode"] = stat.S_IFMT(live_fds[fd]["st_mode"]) | mode
                    if (case == "change-after-effect" and fd == 101 and not clock.closing
                            or case == "canary-mode-after-effect" and fd == 102
                            or case == "sibling-mode-after-effect" and fd == 104
                            or case == "restore-after-effect" and fd == 101 and clock.closing):
                        raise original_error

                def write(fd, data):
                    self.assertIn(fd, (102, 104))
                    self.assertEqual(data, self.module._HOME_READ_BYTES if fd == 102 else self.module._ANCESTOR_READ_BYTES)
                    self.assertIsNotNone(session._home_state["canary_identity" if fd == 102 else "sibling_identity"])
                    count = len(data) - 1 if case == ("canary-short-write" if fd == 102 else "sibling-short-write") else len(data)
                    nodes[canary_name if fd == 102 else sibling_name]["st_size"] = count
                    return count

                def socket_chmod(path, mode, *, follow_symlinks):
                    self.assertEqual((path, mode, follow_symlinks), (socket_path, 0o666, False))
                    self.assertIsNotNone(session._home_state["socket_identity"])
                    self.assertIsNone(session._home_state["socket_mode"])
                    events.append(("socket-chmod",))
                    nodes[socket_name]["st_mode"] = stat.S_IFSOCK | mode
                    if case == "socket-mode-after-effect":
                        raise original_error

                def unlink(name, *, dir_fd):
                    self.assertTrue(clock.closing)
                    self.assertEqual(dir_fd, 103 if name == sibling_name else 101)
                    self.assertIn(name, (canary_name, socket_name, sibling_name))
                    self.assertIn(name, nodes)
                    self.assertEqual(nodes[name]["st_uid"], 0)  # Never the collision's pre-existing file.
                    events.append(("unlink", name))
                    del nodes[name]

                def close(fd):
                    self.assertIn(fd, live_fds)
                    events.append(("close", fd))
                    del live_fds[fd]
                    if case == "all-close-errors":
                        raise close_errors[fd]

                def bind(address):
                    self.assertEqual(address, str(socket_path))
                    self.assertIsNotNone(session._home_state["listener"])
                    self.assertTrue(session._home_state["socket_bind_attempted"])
                    events.append(("bind",))
                    if case == "socket-collision":
                        nodes[socket_name] = node(92, stat.S_IFSOCK, 0o700, uid=1001)
                        raise OSError(errno.EADDRINUSE, "synthetic foreign existing socket name")
                    nodes[socket_name] = node(13, stat.S_IFSOCK, 0o700, gid=session.gid if case == "socket-subject-group" else 20)

                def listener_close():
                    events.append(("listener-close",))
                    if case == "all-close-errors":
                        raise close_errors["listener"]

                listener = SimpleNamespace(settimeout=Mock(), bind=Mock(side_effect=bind), listen=Mock(),
                                           close=Mock(side_effect=listener_close))
                factory = Mock(return_value=listener)

                def manifest(path, data, mode):
                    self.assertEqual((path, mode), (session.bootstrap / "home-control.json", 0o444))
                    self.assertEqual(json.loads(data), {"home": str(session.runner_home), "uid": session.uid,
                                                       "gid": session.gid, "deadline": session.deadline, "ruby_prefix": str(session.ruby_prefix)})
                    events.append(("manifest",))
                    if case == "manifest-error":
                        raise original_error
                    if case == "late-preparation":
                        clock.now = 1.0

                def domain(platform, uid, *, deadline):
                    self.assertEqual((platform, uid, deadline), ("darwin", session.uid, 1.0))
                    self.module._remaining(deadline)
                    events.append(("domain", clock.closing))
                    return set()

                def canonical(value):
                    self.assertIn(Path(value), (*session.ruby_ancestors, session.ruby_prefix, session.ruby))
                    return Path(value)

                def checked_ancestors(*, home_mode=None):
                    # The actual binding/recheck body is tested independently;
                    # this lifetime fixture pins its exact two caller boundaries.
                    self.module._remaining(session.deadline)
                    if home_mode is None:
                        self.assertIsNone(session._home_state)
                        self.assertFalse(acquired)
                    else:
                        self.assertTrue(session._home_state["prepared"])
                        self.assertEqual(home_mode, stat.S_IMODE(home_node["st_mode"]))
                        self.assertNotIn(103, acquired)
                    events.append(("ancestors", home_mode))

                finalize = session._close_home_boundary

                def finalization():
                    errors = finalize()
                    captured_cleanup.extend(errors)
                    return errors

                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_RDWR", "O_DIRECTORY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, geteuid=lambda: 0, fsencode=os.fsencode,
                    open=opened, fstat=fstat, stat=metadata, fchmod=fchmod, write=write, fsync=Mock(),
                    chmod=socket_chmod, unlink=unlink, close=close, path=SimpleNamespace(basename=os.path.basename))
                prepared = case in {"750", "751", "755", "deepest-home", "close-name-drift", "close-mode-drift", "canary-replaced", "canary-group-drift", "socket-group-drift",
                                    "restore-after-effect", "all-close-errors", "sibling-parent-drift", "sibling-replaced"}
                with patch.multiple(self.module, os=fake_os, sys=SimpleNamespace(platform="darwin"),
                                    socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=factory),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(), _domain=domain,
                                    _private_file=Mock(side_effect=manifest), _canonical=canonical,
                                    time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "lstat", named_home), \
                     patch.object(Path, "stat", side_effect=AssertionError("HOME pin must not follow paths")), \
                     patch.object(Path, "chmod", side_effect=AssertionError("HOME permission changes require the original pin")), \
                     patch.object(session, "_check_ruby_ancestors", side_effect=checked_ancestors), \
                     patch.object(session, "_headroom", Mock()), \
                     patch.object(session, "_close_home_boundary", side_effect=finalization) as final:
                    if prepared:
                        session._prepare_home_boundary()
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)):
                            session._prepare_home_boundary()
                    self.assertFalse(any(e[0] in {"close", "listener-close"} for e in events))
                    self.assertFalse(session.admitted)
                    preparation_note = next(n for n in session.admission_results if n["name"] == "home-search-preparation")
                    self.assertEqual(preparation_note["ok"], prepared)
                    if prepared:
                        self.assertTrue(session._home_state["prepared"])
                        self.assertEqual(session._home_state["pin"], 101)
                        self.assertEqual(session._home_state["canary_fd"], 102)
                        self.assertEqual(session._home_state["sibling_pin"], 103)
                        self.assertEqual(session._home_state["sibling_fd"], 104)
                        self.assertIs(session._home_state["listener"], listener)
                        self.assertEqual(session._home_state["canary_identity"].st_gid, 20)
                        self.assertEqual(session._home_state["socket_identity"].st_gid, 20)
                        self.assertEqual(session._home_state["sibling_identity"].st_gid, 20)
                        self.assertEqual(stat.S_IMODE(home_node["st_mode"]), 0o751 if original_mode == 0o750 else original_mode)
                    clock.closing = True
                    if case == "close-mode-drift":
                        home_node["st_mode"] = stat.S_IFDIR | 0o775
                    # Model the outer admission/product failure; restoration
                    # must never rehabilitate this existing first failure.
                    session.fail("earlier immutable failure")
                    for _ in range(2):
                        with self.assertRaisesRegex(self.module.SessionError, "earlier immutable failure"):
                            session.close(keep_timer=True)
                    final.assert_called_once_with()
                self.assertTrue(session.closed)
                self.assertFalse(session._timer_finished)
                self.assertEqual(session.failure, "earlier immutable failure")
                self.assertEqual(session.deadline, 1.0)
                self.assertEqual(live_fds, {})
                self.assertEqual(sorted(e[1] for e in events if e[0] == "close"), sorted(acquired))
                self.assertEqual(len(acquired), len(set(acquired)))
                self.assertEqual(listener.close.call_count, factory.call_count)
                note = next(n for n in session.admission_results if n["name"] == "home-boundary-finalization")
                if case in {"750", "751", "755", "deepest-home"}:
                    self.assertEqual(captured_cleanup, [])
                    self.assertTrue(note["ok"])
                    self.assertEqual(note["restored"], case in {"750", "deepest-home"})
                    self.assertTrue(note["canary_removed"] and note["socket_removed"])
                    self.assertTrue(note["sibling_removed"])
                    self.assertEqual(nodes, {})
                    self.assertEqual(stat.S_IMODE(home_node["st_mode"]), original_mode)
                    home_changes = [e for e in events if e[0] == "fchmod" and e[1] == 101]
                    self.assertEqual(home_changes, [("fchmod", 101, 0o751, False), ("fchmod", 101, 0o750, True)] if case in {"750", "deepest-home"} else [])
                if case in {"change-after-effect", "late-preparation", "close-name-drift", "close-mode-drift"}:
                    self.assertTrue(captured_cleanup)
                    self.assertFalse(note["ok"] or note["restored"])
                    self.assertFalse(any(e[0] == "unlink" or e[:2] == ("fchmod", 101) and e[3] for e in events))
                if case in {"canary-collision", "canary-stat-error", "canary-links", "canary-subject-group", "canary-mode-after-effect", "canary-replaced", "canary-group-drift"}:
                    self.assertNotIn(("unlink", canary_name), events)
                    self.assertIn(canary_name, nodes)
                    self.assertTrue(captured_cleanup)
                if case in {"socket-collision", "socket-subject-group", "socket-mode-after-effect", "socket-group-drift"}:
                    self.assertNotIn(("unlink", socket_name), events)
                    self.assertIn(socket_name, nodes)
                    self.assertTrue(captured_cleanup)
                if case == "restore-after-effect":
                    self.assertIn(original_error, captured_cleanup)
                    self.assertFalse(note["restored"])
                    self.assertFalse(any(e[0] == "unlink" for e in events))
                if case in {"sibling-parent-drift", "sibling-replaced", "sibling-collision", "sibling-create-after-effect",
                            "sibling-stat-error", "sibling-subject-group", "sibling-mode-after-effect"}:
                    self.assertNotIn(("unlink", sibling_name), events)
                    self.assertIn(sibling_name, nodes)
                    self.assertTrue(captured_cleanup)
                if case in {"sibling-parent-drift", "sibling-replaced"}:
                    self.assertTrue(note["restored"] and note["canary_removed"] and note["socket_removed"])
                    self.assertFalse(note["sibling_removed"])  # One drift does not suppress other eligible owned cleanup.
                if case in {"sibling-collision", "sibling-create-after-effect", "sibling-stat-error", "sibling-subject-group"}:
                    self.assertIn("sibling", note["unverified_creation"])
                if case == "all-close-errors":
                    self.assertTrue(all(error in captured_cleanup for error in close_errors.values()))

    def test_linux_provider_wrapper_keeps_collision_writer_import_and_partial_preparation_gates(self):
        cases = ("valid", "nss-bad", "collision", "userns-preparation-error", "busy", "active", "prior-failure", "wrong-platform", "not-root",
                 "missing-prefix", "existing-module", "spec-missing", "loader-failure", "partial-preparation",
                 "incomplete-report", "late-preparation")
        for case in cases:
            with self.subTest(provider_owner_integration=case):
                session = session_double(self.module)
                session.admitted = False
                python_prefix, ruby_prefix, jdk_prefix = session.python.parent.parent, session.ruby.parent.parent, Path("/synthetic/jdk")
                session.tool_prefixes = (python_prefix, ruby_prefix, jdk_prefix)
                if case == "missing-prefix":
                    session.tool_prefixes = (python_prefix, ruby_prefix)
                if case == "wrong-platform":
                    session.platform = "darwin"
                session._busy = case == "busy"
                session._active = object() if case == "active" else None
                if case == "prior-failure":
                    session.fail("earlier immutable failure")
                clock, events = SimpleNamespace(now=0.0), []
                module_name = "_mrk_ci_provider_runtime"
                real_module_before = sys.modules.get(module_name)
                foreign = object()
                modules = {module_name: foreign} if case == "existing-module" else {}
                original = OSError(errno.EIO, "synthetic immutable module/preparation failure")

                def protect(prefixes, **kwargs):
                    self.assertEqual(prefixes, (("python", python_prefix), ("ruby", ruby_prefix), ("jdk", jdk_prefix)))
                    self.assertEqual({k: v for k, v in kwargs.items() if k != "report"},
                                     {"uid": session.uid, "gid": session.gid, "deadline": session.deadline})
                    report = kwargs["report"]
                    self.assertIs(report, session.admission_results[-1])
                    self.assertEqual(report, {"name": "provider-runtime-permissions", "ok": False})
                    events.append(("protect",))
                    report.update(attempted=2, confirmed=1 if case == "partial-preparation" else 2)
                    if case == "partial-preparation":
                        raise original
                    report["ok"] = case != "incomplete-report"
                    if case == "late-preparation":
                        clock.now = session.deadline
                    return {"ok": True}  # Only the original shared report is authority.

                prepared_module = SimpleNamespace(protect_selected_runtimes=Mock(side_effect=protect))

                def load(actual):
                    self.assertIs(actual, prepared_module)
                    self.assertIs(modules[module_name], prepared_module)
                    events.append(("load",))
                    if case == "loader-failure":
                        raise original

                spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock(side_effect=load)))

                def specification(name, path):
                    self.assertEqual((name, path), (module_name, session.source / ".github/scripts/ci_provider_runtime.py"))
                    events.append(("spec",))
                    return None if case == "spec-missing" else spec

                def nss(argv, *, deadline):
                    self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry), "--nss", str(session.uid)])
                    self.assertEqual(deadline, session.deadline)
                    events.append(("nss",))
                    return b"unobserved\n" if case == "nss-bad" else b"MRK_NSS_ABSENT\n"

                def domain(platform, uid, *, collision=False, deadline):
                    self.assertEqual((platform, uid, deadline), ("linux", session.uid, session.deadline))
                    self.module._remaining(deadline)
                    events.append(("domain", collision))
                    return {4242} if case == "collision" and collision else set()

                def tool(path, uid, gid, **options):
                    self.assertEqual((uid, gid), (session.uid, session.gid))
                    self.assertIn(path, (session.python, Path("/usr/bin/sudo"), Path("/usr/bin/true")))
                    self.assertIn(("protect",), events)
                    self.assertTrue(next(n for n in session.admission_results if n["name"] == "provider-runtime-permissions")["ok"])
                    events.append(("tool", options["role"]))
                    return {"role": options["role"], "failed_predicates": []}

                def mkdir(path, *, mode):
                    self.assertEqual(mode, 0o700)
                    self.assertIn(path, [session.work / name for name in ("home", "tmp", "config", "cache")])

                def preflight():
                    self.assertIn(("tool", "python"), events)
                    self.assertTrue(next(n for n in session.admission_results if n["name"] == "provider-runtime-permissions")["ok"])
                    events.append(("preflight",))

                def userns_preparation():
                    self.assertEqual(events, [("nss",), ("domain", True)])
                    events.append(("userns-preparation",))
                    if case == "userns-preparation-error":
                        raise original

                direct = case in {"busy", "active", "prior-failure", "wrong-platform", "not-root", "missing-prefix",
                                  "existing-module", "spec-missing", "loader-failure"}
                chown = Mock()
                with patch.multiple(self.module, os=SimpleNamespace(geteuid=lambda: 1001 if case == "not-root" else 0,
                                        chown=chown, path=SimpleNamespace(basename=os.path.basename)),
                                    sys=SimpleNamespace(platform="linux", base_prefix=str(python_prefix), modules=modules),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(), _canonical=Path,
                                    _readonly_tree=Mock(), _small_command=nss, _domain=domain,
                                    _admit_executable=tool, time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(importlib.util, "spec_from_file_location", side_effect=specification) as make_spec, \
                     patch.object(importlib.util, "module_from_spec", return_value=prepared_module) as make_module, \
                     patch.object(session, "_prepare_userns_boundary", side_effect=userns_preparation) as userns, \
                     patch.object(session, "_headroom", Mock()), patch.object(session, "_preflight", side_effect=preflight), \
                     patch.object(session, "_run", side_effect=AssertionError("this test may not launch any subject")), \
                     patch.object(Path, "mkdir", mkdir), \
                     patch.object(Path, "stat", side_effect=AssertionError("provider metadata belongs to the substituted module")), \
                     patch.object(Path, "resolve", side_effect=AssertionError("no provider path resolution is permitted")):
                    if case == "valid":
                        session.admit()
                    else:
                        with self.assertRaises((self.module.SessionError, OSError)) as caught:
                            session._prepare_provider_runtime() if direct else session.admit()
                        if case in {"loader-failure", "partial-preparation", "userns-preparation-error"}:
                            self.assertIs(caught.exception, original)
                self.assertIs(sys.modules.get(module_name), real_module_before)  # No real lazy import or ownership mutation.
                self.assertEqual(session.admitted, case == "valid")
                if case == "valid":
                    self.assertLess(events.index(("nss",)), events.index(("domain", True)))
                    self.assertLess(events.index(("domain", True)), events.index(("load",)))
                    self.assertLess(events.index(("domain", True)), events.index(("userns-preparation",)))
                    self.assertLess(events.index(("userns-preparation",)), events.index(("load",)))
                    self.assertLess(events.index(("protect",)), events.index(("tool", "python")))
                    self.assertLess(events.index(("tool", "true")), events.index(("preflight",)))
                    self.assertEqual(chown.call_count, 5)
                else:
                    self.assertFalse(any(e[0] in {"tool", "preflight"} for e in events))
                    chown.assert_not_called()
                    if not direct:
                        self.assertEqual(session.failure, "native isolation admission failed; no product command permitted")
                self.assertEqual(userns.call_count, int(not direct and case not in {"nss-bad", "collision"}))
                early = case in {"nss-bad", "collision", "userns-preparation-error", "busy", "active", "prior-failure", "wrong-platform", "not-root", "missing-prefix", "existing-module"}
                if early:
                    make_spec.assert_not_called()
                    make_module.assert_not_called()
                    prepared_module.protect_selected_runtimes.assert_not_called()
                if case == "existing-module":
                    self.assertIs(modules[module_name], foreign)
                reports = [n for n in session.admission_results if n["name"] == "provider-runtime-permissions"]
                if reports:
                    self.assertEqual(reports[0]["ok"], case == "valid")
                if case in {"partial-preparation", "incomplete-report", "late-preparation"}:
                    self.assertEqual((reports[0]["attempted"], reports[0]["confirmed"]), (2, 1 if case == "partial-preparation" else 2))

    def test_fixed_home_positive_requires_immutable_bounded_manifest_actual_literal_read_and_delivery(self):
        metadata_cases = {
            "manifest-owner": (201, "st_uid", 1001), "manifest-group": (201, "st_gid", 20),
            "manifest-mode": (201, "st_mode", stat.S_IFREG | 0o644), "manifest-links": (201, "st_nlink", 2),
            "manifest-type": (201, "st_mode", stat.S_IFLNK | 0o444), "manifest-empty": (201, "st_size", 0),
            "manifest-large": (201, "st_size", 16385), "canary-owner": (202, "st_uid", 1001),
            "canary-subject-group": (202, "st_gid", 60001), "canary-mode": (202, "st_mode", stat.S_IFREG | 0o644),
            "canary-links": (202, "st_nlink", 2), "canary-type": (202, "st_mode", stat.S_IFSOCK | 0o444),
            "canary-size": (202, "st_size", 1),
            "sibling-owner": (203, "st_uid", 1001), "sibling-subject-group": (203, "st_gid", 60001),
            "sibling-links": (203, "st_nlink", 2), "sibling-mode": (203, "st_mode", stat.S_IFREG | 0o644),
        }
        cases = ("valid", "wrong-platform", "wrong-uid", "effective-uid", "effective-gid", "manifest-open", "canary-open",
                 "manifest-short", "manifest-tail", "manifest-key", "manifest-bool-uid", "manifest-wrong-gid", "extra-groups",
                 "invalid-deadline", "expired-deadline", "canary-bytes", "canary-tail", "connect-error", "send-error",
                 "send-late", "close-late", "all-close-errors", "sibling-open", "sibling-bytes", "sibling-tail",
                 "sibling-stat-error", "sibling-name-drift", "prefix-binding", *metadata_cases)
        for case in cases:
            with self.subTest(fixed_home_control=case):
                home, bootstrap = Path("/Users/runner"), Path("/private/tmp/mrk-pure-fixture/bootstrap")
                entry, manifest = bootstrap / "ci_sandbox.py", bootstrap / "home-control.json"
                canary, address = home / ".mrk-pure-fixture-home-read", home / ".mrk-pure-fixture-home-socket"
                ruby_prefix = home / "tools/ruby"
                sibling = ruby_prefix.parent / ".mrk-pure-fixture-ancestor-read"
                clock, events, live, acquired, reads = SimpleNamespace(now=0.0), [], set(), [], {}
                body_error = OSError(errno.EIO, "synthetic fixed HOME control operation")
                close_errors = {201: OSError(errno.EIO, "synthetic manifest close"), 202: OSError(errno.EIO, "synthetic canary close"),
                                203: OSError(errno.EIO, "synthetic sibling close"),
                                "peer": OSError(errno.EIO, "synthetic HOME positive peer close")}
                data = {"home": str(home), "ruby_prefix": str(ruby_prefix), "uid": 60001, "gid": 60001, "deadline": 100.0}
                if case == "prefix-binding":
                    data["ruby_prefix"] = "/outside-home/ruby"
                if case == "manifest-key":
                    data["path"] = "/not-an-accepted-reader-interface"
                if case == "manifest-bool-uid":
                    data["uid"] = True
                if case == "manifest-wrong-gid":
                    data["gid"] += 1
                if case in {"invalid-deadline", "expired-deadline"}:
                    data["deadline"] = True if case == "invalid-deadline" else 0.0
                raw = json.dumps(data).encode()
                nodes = {201: dict(st_dev=7, st_ino=201, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1, st_size=len(raw)),
                         202: dict(st_dev=7, st_ino=202, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=20, st_nlink=1, st_size=len(self.module._HOME_READ_BYTES)),
                         203: dict(st_dev=7, st_ino=203, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=20, st_nlink=1, st_size=len(self.module._ANCESTOR_READ_BYTES))}
                if case in metadata_cases:
                    fd, key, value = metadata_cases[case]
                    nodes[fd][key] = value

                def opened(path, flags):
                    self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    self.assertLess(len(acquired), 3)
                    expected = (manifest, canary, sibling)[len(acquired)]
                    self.assertEqual(path, expected)
                    fd = 201 + len(acquired)
                    if fd != 201:
                        self.assertIn(("named-stat", fd), events)
                    events.append(("open", fd))
                    if case == {201: "manifest-open", 202: "canary-open", 203: "sibling-open"}[fd]:
                        raise body_error
                    acquired.append(fd)
                    live.add(fd)
                    return fd

                def metadata(fd):
                    self.assertIn(fd, live)
                    events.append(("fstat", fd))
                    return SimpleNamespace(**nodes[fd])

                def named_metadata(path, *, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    self.assertIn(path, (canary, sibling))
                    fd = 202 if path == canary else 203
                    events.append(("named-stat", fd))
                    if path == sibling and case == "sibling-stat-error":
                        raise body_error
                    value = dict(nodes[fd])
                    if path == sibling and case == "sibling-name-drift":
                        value["st_ino"] += 1
                    return SimpleNamespace(**value)

                def read(fd, size):
                    self.assertIn(fd, live)
                    count = reads.get(fd, 0)
                    self.assertLess(count, 2)
                    reads[fd] = count + 1
                    literal = self.module._HOME_READ_BYTES if fd == 202 else self.module._ANCESTOR_READ_BYTES
                    self.assertEqual(size, (16385 if fd == 201 else len(literal) + 1) if count == 0 else 1)
                    events.append(("read", fd, size))
                    if count:
                        return b"x" if case == {201: "manifest-tail", 202: "canary-tail", 203: "sibling-tail"}[fd] else b""
                    if fd == 201:
                        return raw[:-1] if case == "manifest-short" else raw
                    return b"wrong\n" if case == ("canary-bytes" if fd == 202 else "sibling-bytes") else literal

                def close(fd):
                    self.assertIn(fd, live)
                    live.remove(fd)
                    events.append(("close", fd))
                    if case == "close-late" and fd == 201:
                        clock.now = 100.0
                    if case == "all-close-errors":
                        raise close_errors[fd]

                def canonical(value):
                    self.assertIn(value, (str(home), data["ruby_prefix"]))
                    return Path(value)

                def own_entry(path):
                    self.assertEqual(path, entry)
                    return path

                def connect(value):
                    self.assertEqual(value, str(address))
                    self.assertEqual(reads, {201: 2, 202: 2, 203: 2})
                    self.assertIn(("named-stat", 203), events)
                    events.append(("connect",))
                    if case == "connect-error":
                        raise body_error

                def send(value):
                    self.assertEqual(value, self.module._HOME_SOCKET_BYTES)
                    events.append(("send",))
                    if case == "send-error":
                        raise body_error
                    if case == "send-late":
                        clock.now = 100.0

                def peer_close():
                    events.append(("peer-close",))
                    if case == "all-close-errors":
                        raise close_errors["peer"]

                peer = SimpleNamespace(settimeout=Mock(), connect=Mock(side_effect=connect), sendall=Mock(side_effect=send),
                                       close=Mock(side_effect=peer_close))
                factory, limits = Mock(return_value=peer), Mock()
                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, open=opened, fstat=metadata, stat=named_metadata, read=read, close=close, fsencode=os.fsencode,
                    getuid=lambda: 0 if case == "wrong-uid" else 60001, geteuid=lambda: 0 if case == "effective-uid" else 60001,
                    getgid=lambda: 60001, getegid=lambda: 0 if case == "effective-gid" else 60001)
                output = io.StringIO()
                with patch.multiple(self.module, __file__=str(entry), os=fake_os,
                                    sys=SimpleNamespace(platform="linux" if case == "wrong-platform" else "darwin"),
                                    socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=factory),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(), _limits=limits,
                                    _process_groups=Mock(return_value=[60001, 20] if case == "extra-groups" else [60001]),
                                    _canonical=canonical, time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", own_entry), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("fixed control reads only bounded original descriptors")), \
                     patch.object(Path, "stat", side_effect=AssertionError("fixed control metadata requires the opened descriptor")), \
                     redirect_stdout(output):
                    if case == "valid":
                        self.module._home_positive()
                    else:
                        with self.assertRaises((self.module.SessionError, BaseExceptionGroup)) as caught:
                            self.module._home_positive()
                        if case == "all-close-errors":
                            self.assertEqual(caught.exception.exceptions, (close_errors["peer"], close_errors[203], close_errors[202], close_errors[201]))
                        if case in {"manifest-open", "canary-open", "sibling-open", "sibling-stat-error", "connect-error", "send-error"}:
                            self.assertIs(caught.exception.exceptions[0], body_error)
                self.assertEqual(live, set())
                self.assertEqual([e[1] for e in events if e[0] == "close"], list(reversed(acquired)))
                self.assertEqual(peer.close.call_count, factory.call_count)
                self.assertEqual(output.getvalue(), "MRK_HOME_POSITIVE_OK\n" if case == "valid" else "")
                if case in {"wrong-platform", "wrong-uid", "effective-uid", "effective-gid"}:
                    limits.assert_not_called()
                    self.assertEqual(events, [])
                else:
                    limits.assert_called_once_with("darwin", 10)
                if factory.called:
                    factory.assert_called_once_with(1, 1)
                    self.assertTrue(all(0 < c.args[0] <= 2 for c in peer.settimeout.call_args_list))
                    self.assertLess(events.index(("peer-close",)), events.index(("close", 202)))
                if case == "valid":
                    self.assertEqual(reads, {201: 2, 202: 2, 203: 2})
                    peer.connect.assert_called_once_with(str(address))
                    peer.sendall.assert_called_once_with(self.module._HOME_SOCKET_BYTES)

        # Dispatch has exactly one fixed role and cannot accept a caller path,
        # socket name or arbitrary command in place of its immutable manifest.
        control = Mock()
        with patch.multiple(self.module, _home_positive=control, os=SimpleNamespace(),
                            subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace()):
            self.assertEqual(self.module._main(["--home-positive"]), 0)
            control.assert_called_once_with()
            for tail in (["/other/path"], ["--", "/other/command"]):
                with self.assertRaises(self.module.SessionError):
                    self.module._main(["--home-positive", *tail])
            control.assert_called_once_with()

    def test_root_home_positive_uses_genuine_fixed_child_collection_finality_and_exact_delivery_eof(self):
        genuine_collection = self.module._small_command
        cases = ("valid", "fragmented", "missing-state", "unprepared", "missing-listener", "sibling-unowned", "sibling-mode",
                 "busy", "pending-direct", "pin-drift", "ancestor-drift", "sibling-pin-drift",
                 "pre-domain", "post-domain", "nonzero", "stderr", "wait-error", "stdout-held", "stderr-held",
                 "collection-close-error", "wrong-footer", "accept-error", "wrong-token", "excess-token", "held-delivery",
                 "accepted-close-error", "body-and-close-errors", "late-close")
        for case in cases:
            with self.subTest(root_home_positive=case):
                session = session_double(self.module, "darwin")
                rig = _Collection(self.module, session, stdout=(b"wrong\n" if case == "wrong-footer" else b"MRK_HOME_POSITIVE_OK\n",),
                                  stderr=(b"synthetic diagnostic\n",) if case == "stderr" else ())
                rig.exitcode = 7 if case == "nonzero" else 0
                rig.wait_error = case == "wait-error"
                if case in {"stdout-held", "stderr-held"}:
                    rig.hold.add(0 if case == "stdout-held" else 1)
                if case == "collection-close-error":
                    rig.stream_close_errors = {0}
                session._busy = case == "busy"
                session._direct_producer_pending = case == "pending-direct"
                body_error = TimeoutError("synthetic HOME receiver incomplete delivery")
                close_error = OSError(errno.EIO, "synthetic accepted HOME connection close")
                pin_error = self.module.SessionError("synthetic HOME pin identity drift")
                token, received = self.module._HOME_SOCKET_BYTES, 0
                chunks = ([token[:5], token[5:], b""] if case == "fragmented" else
                          [b"x" * len(token), b""] if case == "wrong-token" else
                          [token + b"x"] if case == "excess-token" else
                          [token, body_error] if case in {"held-delivery", "body-and-close-errors"} else [token, b""])

                def recv(size):
                    nonlocal received
                    self.assertEqual(size, len(token) + 1 - received)
                    self.assertTrue(chunks)
                    chunk = chunks.pop(0)
                    rig.events.append(("home-recv", size))
                    if isinstance(chunk, BaseException):
                        raise chunk
                    received += len(chunk)
                    return chunk

                def accepted_close():
                    rig.events.append(("home-accepted-close",))
                    if case == "late-close":
                        rig.now = session.deadline
                    if case in {"accepted-close-error", "body-and-close-errors"}:
                        raise close_error

                accepted = SimpleNamespace(settimeout=Mock(), recv=Mock(side_effect=recv), close=Mock(side_effect=accepted_close))

                def accept():
                    rig.events.append(("home-accept",))
                    self.assertEqual(rig.domain_calls, 2)
                    self.assertTrue(session.domain_finality)
                    self.assertIsNone(session._active)
                    self.assertLess(max(i for i, e in enumerate(rig.events) if e[0] == "wait-original"),
                                    max(i for i, e in enumerate(rig.events) if e[0] == "domain"))
                    self.assertEqual({e[1] for e in rig.events if e[0] == "unregister-eof"}, {0, 1})
                    if case == "accept-error":
                        raise body_error
                    return accepted, "synthetic-peer"

                listener = SimpleNamespace(settimeout=Mock(), accept=Mock(side_effect=accept), close=Mock())
                session._home_state = None if case == "missing-state" else {
                    "prepared": case != "unprepared", "listener": None if case == "missing-listener" else listener,
                    "expected_mode": 0o751,
                    "sibling_identity": None if case == "sibling-unowned" else object(),
                    "sibling_mode": 0o600 if case == "sibling-mode" else 0o444,
                }

                def domain(platform, uid, *, deadline):
                    result = rig.domain(platform, uid, deadline=deadline)
                    self.assertEqual(deadline, session.deadline)
                    return {4242} if (case == "pre-domain" and rig.domain_calls == 1
                                      or case == "post-domain" and rig.domain_calls == 2) else result

                def pin(mode):
                    self.assertEqual(mode, 0o751)
                    self.assertEqual(rig.domain_calls, 1)
                    self.assertTrue(session.domain_finality)
                    rig.events.append(("pin-check",))
                    if case == "pin-drift":
                        raise pin_error

                def ancestors(*, home_mode):
                    self.assertEqual(home_mode, 0o751)
                    self.assertEqual(rig.domain_calls, 1)
                    self.assertTrue(session.domain_finality)
                    rig.events.append(("ancestor-check",))
                    if case == "ancestor-drift":
                        raise pin_error

                def sibling_pin(mode):
                    self.assertEqual(mode, 0o751)
                    self.assertEqual(rig.domain_calls, 1)
                    rig.events.append(("sibling-pin-check",))
                    if case == "sibling-pin-drift":
                        raise pin_error

                def collect(argv, seconds, **kwargs):
                    self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry), "--home-positive"])
                    self.assertEqual((seconds, kwargs), (10, {"user": session.uid, "group": session.gid, "deadline": session.deadline}))
                    self.assertIn(("pin-check",), rig.events)
                    self.assertIn(("ancestor-check",), rig.events)
                    self.assertIn(("sibling-pin-check",), rig.events)
                    self.assertTrue(session._direct_producer_pending)
                    self.assertFalse(session.domain_finality)
                    return genuine_collection(argv, seconds, **kwargs)

                metadata = Mock(side_effect=collect)
                with rig.scope(), patch.object(self.module, "_small_command", metadata), \
                     patch.object(self.module, "_domain", side_effect=domain), \
                     patch.object(self.module, "socket", SimpleNamespace()), \
                     patch.object(session, "_check_home_pin", side_effect=pin), \
                     patch.object(session, "_check_ruby_ancestors", side_effect=ancestors), \
                     patch.object(session, "_check_ruby_sibling_pin", side_effect=sibling_pin), \
                     patch.object(Path, "stat", side_effect=AssertionError("all HOME metadata is owned by the substituted pin check")), \
                     patch.object(Path, "lstat", side_effect=AssertionError("no actual HOME path observation is permitted")), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("the root HOME control may not read paths")):
                    if case in {"valid", "fragmented"}:
                        session._home_positive_control()
                    else:
                        with self.assertRaises((self.module.SessionError, BaseExceptionGroup)) as caught:
                            session._home_positive_control()
                        if case == "body-and-close-errors":
                            self.assertEqual(caught.exception.exceptions, (body_error, close_error))
                        if case in {"pin-drift", "ancestor-drift", "sibling-pin-drift"}:
                            self.assertIs(caught.exception, pin_error)
                notes = [n for n in session.admission_results if n["name"] == "home-DAC-and-delivery-positive"]
                self.assertEqual(notes, [{"name": "home-DAC-and-delivery-positive", "ok": True}] if case in {"valid", "fragmented"} else [])
                listener.close.assert_not_called()  # Root listener stays in Session's custody until owned finalization.
                if case not in {"missing-state", "missing-listener"}:
                    self.assertIs(session._home_state["listener"], listener)
                preaccept = {"missing-state", "unprepared", "missing-listener", "sibling-unowned", "sibling-mode", "busy", "pending-direct",
                             "pin-drift", "ancestor-drift", "sibling-pin-drift", "pre-domain", "post-domain",
                             "nonzero", "stderr", "wait-error", "stdout-held", "stderr-held", "collection-close-error", "wrong-footer"}
                if case in preaccept:
                    listener.accept.assert_not_called()
                    accepted.close.assert_not_called()
                else:
                    listener.accept.assert_called_once_with()
                    self.assertEqual(accepted.close.call_count, int(case != "accept-error"))
                for _, command, kwargs in (e for e in rig.events if e[0] == "popen"):
                    self.assertEqual(command[-1], "--home-positive")
                    self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (session.uid, session.gid, []))
                    self.assertTrue(kwargs["close_fds"])
                    self.assertNotIn("pass_fds", kwargs)
                    self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
                self.assertEqual(session.deadline, 100.0)
                self.assertEqual(session._direct_producer_pending, case in {
                    "pending-direct", "nonzero", "stderr", "wait-error", "stdout-held", "stderr-held", "collection-close-error"})

    def test_root_home_non_delivery_requires_real_would_block_and_retains_listener_on_every_failure(self):
        for case in ("eagain", "ewouldblock", "wrong-family", "wrong-kind", "unknown-blocking", "unknown-error", "delivery",
                     "delivery-close-error", "setblocking-error", "expired", "late-empty", "late-close"):
            with self.subTest(home_non_delivery=case):
                clock, events = SimpleNamespace(now=0.0), []
                original = OSError(errno.EIO, "synthetic original HOME non-delivery observation")
                close_error = OSError(errno.EIO, "synthetic prohibited HOME delivery close")

                def close():
                    events.append(("accepted-close",))
                    if case == "late-close":
                        clock.now = 1.0
                    if case == "delivery-close-error":
                        raise close_error

                accepted = SimpleNamespace(close=Mock(side_effect=close))

                def setblocking(value):
                    self.assertFalse(value)
                    events.append(("nonblocking",))
                    if case == "setblocking-error":
                        raise original

                def accept():
                    events.append(("accept",))
                    if case in {"delivery", "delivery-close-error", "late-close"}:
                        return accepted, "synthetic-peer"
                    if case == "unknown-error":
                        raise original
                    if case == "late-empty":
                        clock.now = 1.0
                    raise BlockingIOError(errno.EIO if case == "unknown-blocking" else
                                          errno.EWOULDBLOCK if case == "ewouldblock" else errno.EAGAIN, "synthetic original accept result")

                listener = SimpleNamespace(family=2 if case == "wrong-family" else 1,
                    type=2 if case == "wrong-kind" else 1, setblocking=Mock(side_effect=setblocking),
                    accept=Mock(side_effect=accept), close=Mock())
                clock.now = 1.0 if case == "expired" else 0.0
                with patch.multiple(self.module, socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), signal=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: clock.now)):
                    if case in {"eagain", "ewouldblock"}:
                        self.module._home_socket_empty(listener, deadline=1.0)
                    else:
                        with self.assertRaises((self.module.SessionError, BaseExceptionGroup)) as caught:
                            self.module._home_socket_empty(listener, deadline=1.0)
                        if case == "delivery-close-error":
                            self.assertEqual(len(caught.exception.exceptions), 2)
                            self.assertIsInstance(caught.exception.exceptions[0], self.module.SessionError)
                            self.assertIs(caught.exception.exceptions[1], close_error)
                        if case in {"unknown-error", "setblocking-error"}:
                            self.assertIs(caught.exception.exceptions[0], original)
                listener.close.assert_not_called()
                self.assertEqual(accepted.close.call_count, int(case in {"delivery", "delivery-close-error", "late-close"}))
                if case in {"wrong-family", "wrong-kind", "expired"}:
                    self.assertEqual(events, [])
                else:
                    self.assertEqual(events[:2], [("nonblocking",)] if case == "setblocking-error" else [("nonblocking",), ("accept",)])

    def test_ruby_startup_diagnostic_requires_the_exact_failed_capture_without_changing_admission(self):
        session = session_double(self.module, "darwin")
        session.ruby = Path("/synthetic/private-ruby-diagnostic/bin/ruby")
        session.failure = "earlier immutable failure"
        session.admitted = False
        raw = b"synthetic unpublished unknown startup text\n"
        result = self.module.CapturedRun(b"", raw, 1, True, True, True, True, False, False,
                                         0.01, "command exited 1", (), (0, len(raw)))
        original = dataclasses.asdict(result)
        unclassified = {"semantics": "stderr-tokens-only", "classification": "unclassified"}

        def noted(capture, *, platform="darwin", name="ruby-numerical-identity"):
            session.platform = platform
            before = len(session.admission_results)
            record = session._note_capture(name, capture)
            self.assertIs(record, session.admission_results[-1])
            self.assertEqual(len(session.admission_results), before + 1)
            self.assertFalse(record["ok"])
            self.assertEqual(record["subject_ok"], capture.ok)
            self.assertFalse(session.admitted)
            self.assertEqual(session.failure, "earlier immutable failure")
            public = json.dumps(record)
            self.assertNotIn("private-ruby-diagnostic", public)
            self.assertNotIn("synthetic unpublished", public)
            return record

        with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace()), \
             patch.object(session, "_run", side_effect=AssertionError("a capture observation cannot start another command")), \
             patch.object(Path, "stat", side_effect=AssertionError("a capture observation cannot inspect provider files")), \
             patch.object(Path, "resolve", side_effect=AssertionError("a capture observation cannot resolve provider paths")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("only the already captured bytes are authority")), \
             patch.object(Path, "read_text", side_effect=AssertionError("only the already captured bytes are authority")):
            self.assertEqual(self.module._ruby_startup_error(result, session.ruby), unclassified)
            row = noted(result)
            self.assertEqual(row["ruby_startup_error"], unclassified)
            self.assertEqual(row["persisted"], [0, len(raw)])
            self.assertEqual(row["error_count"], 1)
            self.assertFalse(result.ok)
            for changed in ({"returncode": 0}, {"returncode": 71}, {"returncode": None}, {"returncode": True},
                            {"returncode": 1.0}, {"stdout": b"unexpected stdout"}, {"waited": False},
                            {"stdout_eof": False}, {"stderr_eof": False}, {"domain_finality": False},
                            {"timed_out": True}, {"cancelled": True}, {"cleanup_errors": ("synthetic close ambiguity",)},
                            {"primary_error": None}, {"primary_error": "command exited 71"},
                            {"primary_error": "per-stream or whole-attempt persisted-output limit"},
                            {"persisted": (0, len(raw) - 1)}, {"persisted": (0, len(raw) + 1)},
                            {"persisted": (0, None)}, {"persisted": (1, len(raw))}):
                with self.subTest(startup_receipt=changed):
                    capture = dataclasses.replace(result, **changed)
                    self.assertIsNone(self.module._ruby_startup_error(capture, session.ruby))
                    self.assertNotIn("ruby_startup_error", noted(capture))
            # These values cannot arise from a genuine CapturedRun producer;
            # an equal-looking value is nevertheless not the required fact.
            for changed in ({"stdout": ""}, {"stdout": bytearray()}, {"stderr": bytearray(raw)}, {"stderr": raw.decode()},
                            {"waited": 1}, {"stdout_eof": 1}, {"stderr_eof": 1}, {"domain_finality": 1},
                            {"timed_out": 0}, {"cancelled": 0}, {"cleanup_errors": []}, {"persisted": [0, len(raw)]},
                            {"persisted": (False, len(raw))}, {"persisted": (0.0, len(raw))},
                            {"persisted": (0, float(len(raw)))}, {"persisted": None}):
                with self.subTest(startup_typed_receipt=changed):
                    self.assertIsNone(self.module._ruby_startup_error(dataclasses.replace(result, **changed), session.ruby))
            for platform, name in (("linux", "ruby-numerical-identity"), ("darwin", "native-isolation"),
                                   ("darwin", "ruby-numerical-identity-extra")):
                with self.subTest(startup_capture_role=(platform, name)):
                    self.assertNotIn("ruby_startup_error", noted(result, platform=platform, name=name))
            success = dataclasses.replace(result, returncode=0, primary_error=None)
            self.assertTrue(success.ok)
            self.assertNotIn("ruby_startup_error", noted(success))
            # Exit71 remains the separate exact launcher observation. Neither
            # classifier can silently redefine it as an exit1 startup failure.
            launcher = f"sandbox-exec: execvp() of '{session.ruby}' failed: Permission denied\n".encode()
            old_capture = dataclasses.replace(result, stderr=launcher, returncode=71, primary_error="command exited 71",
                                              persisted=(0, len(launcher)))
            old = {"operation": "sandbox-execvp", "role": "ruby", "errno": errno.EACCES}
            self.assertEqual(self.module._ruby_launch_error(old_capture, session.ruby), old)
            self.assertIsNone(self.module._ruby_startup_error(old_capture, session.ruby))
            row = noted(old_capture)
            self.assertEqual(row["launcher_error"], old)
            self.assertNotIn("ruby_startup_error", row)
        self.assertEqual(dataclasses.asdict(result), original)

    def test_ruby_startup_tokens_and_frames_are_finite_bound_to_the_selected_provider_and_never_raw(self):
        session = session_double(self.module, "darwin")
        session.ruby = Path("/synthetic/private-ruby-diagnostic/bin/ruby")
        library = session.ruby.parent.parent / "lib/ruby/3.3.0"
        session.failure = "earlier immutable failure"
        session.admitted = False

        def diagnose(raw):
            capture = self.module.CapturedRun(b"", raw, 1, True, True, True, True, False, False,
                                              0.01, "command exited 1", (), (0, len(raw)))
            before = dataclasses.asdict(capture)
            note = self.module._ruby_startup_error(capture, session.ruby)
            row = session._note_capture("ruby-numerical-identity", capture)
            self.assertEqual(row["ruby_startup_error"], note)
            self.assertFalse(capture.ok or row["ok"] or row["subject_ok"] or session.admitted)
            self.assertEqual(capture.primary_error, "command exited 1")
            self.assertEqual(dataclasses.asdict(capture), before)
            self.assertEqual(session.failure, "earlier immutable failure")
            self.assertEqual(note["semantics"], "stderr-tokens-only")
            self.assertLessEqual(set(note), {"semantics", "classification", "exception", "errno", "operation", "frames"})
            for frame in note.get("frames", []):
                self.assertEqual(set(frame), {"role", "line"})
                self.assertIs(type(frame["line"]), int)
                self.assertTrue(0 < frame["line"] < 1_000_000)
            public = json.dumps(row)
            for private in ("private-ruby-diagnostic", "private-message-canary", "private-function-canary",
                            "private-path-canary", "private-frame-canary", "private-operation-canary", "0xDEADBEEF"):
                self.assertNotIn(private, public)
            return note

        common = {"semantics": "stderr-tokens-only", "classification": "recognized"}
        errnos = (("Errno::EPERM", 1, "Operation not permitted"), ("Errno::ENOENT", 2, "No such file or directory"),
                  ("Errno::ENOEXEC", 8, "Exec format error"), ("Errno::ENOMEM", 12, "Cannot allocate memory"),
                  ("Errno::EACCES", 13, "Permission denied"), ("Errno::ENOTDIR", 20, "Not a directory"))
        plain = ("LoadError", "ArgumentError", "RuntimeError", "ThreadError", "SecurityError", "SyntaxError",
                 "NameError", "TypeError", "NoMemoryError")
        frames = ((str(library / "rubygems.rb"), "rubygems", 12),
                  (str(library / "rubygems/defaults.rb"), "rubygems-defaults", 13),
                  (str(library / "rubygems/path_support.rb"), "rubygems-path-support", 14),
                  (str(library / "rubygems/core_ext/kernel_require.rb"), "rubygems-kernel-require", 15),
                  (str(library / "bundled_gems.rb"), "bundled-gems", 16),
                  (f"<internal:{library / 'rubygems/core_ext/kernel_require.rb'}>", "rubygems-kernel-require", 17),
                  ("<internal:gem_prelude>", "gem-prelude", 18), ("<internal:prelude>", "ruby-prelude", 19),
                  ("-e", "numerical-probe", 1))
        with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace()), \
             patch.object(session, "_run", side_effect=AssertionError("no diagnostic command may run")), \
             patch.object(Path, "stat", side_effect=AssertionError("no diagnostic metadata query may run")), \
             patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic provider resolution may run")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("no diagnostic file read may run")), \
             patch.object(Path, "read_text", side_effect=AssertionError("no diagnostic file read may run")):
            for exception, number, message in errnos:
                with self.subTest(startup_errno_token=exception):
                    # The number follows only this exact finite symbolic class,
                    # not the message's number or an arbitrary native address.
                    raw = f"{session.ruby}: private-message-canary 999 0xDEADBEEF ({exception})\n".encode()
                    self.assertEqual(diagnose(raw), common | {"exception": exception, "errno": number, "frames": []})
                    bare = f"{message} @ rb_check_realpath_internal - /private-path-canary ({exception})\n".encode()
                    self.assertEqual(diagnose(bare), common | {"exception": exception, "errno": number,
                                                            "operation": "rb_check_realpath_internal", "frames": []})
            for exception in plain:
                with self.subTest(startup_non_errno_token=exception):
                    raw = f"{session.ruby.name}: Permission denied private-message-canary ({exception})\n".encode()
                    self.assertEqual(diagnose(raw), common | {"exception": exception, "frames": []})
            raw = f"{session.ruby}: private-message-canary @ rb_check_realpath_internal - /private-path-canary (RuntimeError)\n".encode()
            self.assertEqual(diagnose(raw), common | {"exception": "RuntimeError", "operation": "rb_check_realpath_internal", "frames": []})
            for operation in ("private-operation-canary", "rb_check_realpath_internal_extra", "realpath"):
                raw = f"{session.ruby}: private-message-canary @ {operation} - /private-path-canary (RuntimeError)\n".encode()
                self.assertEqual(diagnose(raw), common | {"exception": "RuntimeError", "frames": []})
            for source, role, line in frames:
                with self.subTest(startup_fixed_frame=role):
                    raw = f"{source}:{line}:in `private-function-canary': private-message-canary (LoadError)\n".encode()
                    self.assertEqual(diagnose(raw), common | {"exception": "LoadError", "frames": [{"role": role, "line": line}]})
            source = str(library / "rubygems.rb")
            header = f"{source}:1: private-message-canary (RuntimeError)\n"
            tails = [f"\tfrom {source}:{line}:in 'private-function-canary'\n" for line in range(1, 13)]
            limited = diagnose((header + "".join(tails)).encode())
            self.assertEqual(limited, common | {"exception": "RuntimeError",
                             "frames": [{"role": "rubygems", "line": line} for line in range(1, 9)]})
            # A recognized fixed header does not claim that every tail is known.
            # A familiar basename at another prefix never becomes a frame role.
            foreign = f"/private-frame-canary/lib/ruby/3.3.0/rubygems.rb:27:in `private-function-canary'"
            tail = (f"\tfrom {foreign}\n\tfrom {source}:1\n\tfrom {source}:999999\n"
                    "\tfrom <internal:private-frame-canary>:22\n\tfrom -e:2\n"
                    "private-message-canary unknown surrounding text\n")
            self.assertEqual(diagnose((header + tail).encode()), common | {"exception": "RuntimeError", "frames": [
                {"role": "rubygems", "line": 1}, {"role": "rubygems", "line": 999999}]})

    def test_ruby_startup_parser_rejects_foreign_tokens_framing_controls_and_complete_input_overflow(self):
        ruby = Path("/synthetic/private-ruby-diagnostic/bin/ruby")
        source = ruby.parent.parent / "lib/ruby/3.3.0/rubygems.rb"
        common = {"semantics": "stderr-tokens-only", "classification": "recognized", "exception": "RuntimeError", "frames": []}
        unclassified = {"semantics": "stderr-tokens-only", "classification": "unclassified"}

        def diagnose(raw):
            capture = self.module.CapturedRun(b"", raw, 1, True, True, True, True, False, False,
                                              0.01, "command exited 1", (), (0, len(raw)))
            note = self.module._ruby_startup_error(capture, ruby)
            self.assertFalse(capture.ok)
            public = json.dumps(note)
            for private in ("private-ruby-diagnostic", "private-message-canary", "private-frame-canary", "ForeignPrivateError"):
                self.assertNotIn(private, public)
            return note

        valid = f"{ruby}: private-message-canary (RuntimeError)\n".encode()
        malformed = [b"", valid[:-1], b"prefix " + valid, b"\n" + valid, valid.replace(b"\n", b"\r\n"),
                     valid.replace(b"private-message-canary", b"\xff"), valid + b"\x80\n", valid + "\u00e9\n".encode(),
                     valid.replace(b"RuntimeError)", b"RuntimeError) suffix"), valid.replace(b"(RuntimeError)", b"RuntimeError"),
                     valid.replace(b"(RuntimeError)", b"((RuntimeError))"), valid.replace(b"(RuntimeError)", b"()"),
                     valid.replace(b"private-message-canary", b""), b"arbitrary message (RuntimeError)\n",
                     f"/private-frame-canary/bin/ruby: private-message-canary (RuntimeError)\n".encode(),
                     f"/private-frame-canary/lib/ruby/3.3.0/rubygems.rb:1: private-message-canary (RuntimeError)\n".encode(),
                     f"<internal:/private-frame-canary/kernel_require.rb>:1: private-message-canary (RuntimeError)\n".encode(),
                     b"<internal:private-frame-canary>:1: private-message-canary (RuntimeError)\n",
                     b"-e:2: private-message-canary (RuntimeError)\n"]
        for exception in ("ForeignPrivateError", "Errno::EIO", "Errno::EACCES_PRIVATE", "Errno::13", "IOError", "runtimeerror"):
            malformed.append(valid.replace(b"RuntimeError", exception.encode()))
        for line in ("0", "01", "-1", "+1", "1000000", "1.0", " 1"):
            malformed.append(f"{source}:{line}: private-message-canary (RuntimeError)\n".encode())
        for name in ("", "f" * 129, "embedded`quote", "embedded'quote"):
            malformed.append(f"{source}:1:in `{name}': private-message-canary (RuntimeError)\n".encode())
        for control in (*range(0, 9), *range(11, 32), 127):
            malformed.append(valid.replace(b"private-message-canary", b"private-message-canary" + bytes([control])))
        malformed += [valid.replace(b"private-message-canary", b"private\tmessage-canary"),
                      valid + f"\tfrom {source}:2\t\n".encode(), valid + b"\tunknown-private-tail\n",
                      b"Permission denied @ rb_check_realpath_internal - /private-message-canary (Errno::EPERM)\n",
                      b"Permission denied @ rb_check_realpath_internal -  (Errno::EACCES)\n",
                      b"Permission denied @ private-operation-canary - /private-message-canary (Errno::EACCES)\n"]
        with patch.multiple(self.module, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace()), \
             patch.object(Path, "stat", side_effect=AssertionError("no diagnostic metadata query may run")), \
             patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic provider resolution may run")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("no diagnostic file read may run")), \
             patch.object(Path, "read_text", side_effect=AssertionError("no diagnostic file read may run")):
            self.assertEqual(diagnose(valid), common)
            for index, raw in enumerate(malformed):
                with self.subTest(startup_malformed=index):
                    self.assertEqual(diagnose(raw), unclassified)
            prefix, suffix = f"{ruby}: ".encode(), b" (RuntimeError)\n"
            exact = prefix + b"x" * (16384 - len(prefix) - len(suffix)) + suffix
            self.assertEqual(len(exact), 16384)
            self.assertEqual(diagnose(exact), common)
            over = prefix + b"x" * (16385 - len(prefix) - len(suffix)) + suffix
            self.assertEqual(len(over), 16385)
            self.assertEqual(diagnose(over), unclassified)
            bounded_frame = f"{source}:999999:in `{'f' * 128}': private-message-canary (RuntimeError)\n".encode()
            self.assertEqual(diagnose(bounded_frame), common | {"frames": [{"role": "rubygems", "line": 999999}]})
            sixty_four = valid + b"private-message-canary unknown tail\n" * 63
            self.assertEqual(diagnose(sixty_four), common)
            self.assertEqual(diagnose(sixty_four + b"private-message-canary extra tail\n"), unclassified)
            # Validation covers the whole captured envelope, even after the
            # eighth recognized frame. A truncated-prefix success is forbidden.
            tail = b"".join(f"\tfrom {source}:{line}\n".encode() for line in range(1, 12))
            self.assertEqual(len(diagnose(valid + tail)["frames"]), 8)
            self.assertEqual(diagnose(valid + tail + b"private-message-canary\x1b\n"), unclassified)

    def test_ruby_runtime_metadata_ancestors_are_finite_exact_and_bound_before_policy_publication(self):
        home, prefix, root = Path("/Users/runner"), Path("/Users/runner/tools/rubies/3.3.12"), Path("/private/tmp/mrk-pure-fixture")
        expected = (home, home / "tools", home / "tools/rubies")
        with patch.multiple(self.module, os=SimpleNamespace(fsencode=os.fsencode), subprocess=SimpleNamespace(),
                            socket=SimpleNamespace(), signal=SimpleNamespace(),
                            _canonical=Mock(side_effect=AssertionError("lexical derivation may not resolve paths"))), \
             patch.object(Path, "resolve", side_effect=AssertionError("lexical derivation may not resolve paths")), \
             patch.object(Path, "stat", side_effect=AssertionError("lexical derivation may not inspect the host")), \
             patch.object(Path, "lstat", side_effect=AssertionError("lexical derivation may not inspect the host")):
            self.assertEqual(self.module._ruby_ancestor_paths(home, prefix), expected)
            self.assertIs(type(self.module._ruby_ancestor_paths(home, prefix)), tuple)
            self.assertEqual(self.module._ruby_sibling_path(home, prefix, root), expected[-1] / ".mrk-pure-fixture-ancestor-read")
            self.assertEqual(self.module._ruby_ancestor_paths(home, home / "ruby"), (home,))
            self.assertEqual(self.module._ruby_sibling_path(home, home / "ruby", root), home / ".mrk-pure-fixture-ancestor-read")
            components = [f"part{i}" for i in range(15)]
            deep = home.joinpath(*components, "ruby")
            self.assertEqual(self.module._ruby_ancestor_paths(home, deep),
                             tuple(home.joinpath(*components[:i]) for i in range(16)))
            for bad_home, bad_prefix in ((Path("Users/runner"), prefix), (home, Path("tools/ruby")), (home, home),
                                         (home, Path("/other/provider/ruby")), (home, home / "../ruby"),
                                         (home / "../runner", prefix), (Path("/Users/runnér"), Path("/Users/runnér/ruby")),
                                         (home, home / ("x" * 4097)), (home, deep.parent / "extra/ruby")):
                with self.subTest(ancestor_derivation=(bad_home, bad_prefix)), self.assertRaises(self.module.SessionError):
                    self.module._ruby_ancestor_paths(bad_home, bad_prefix)
            for bad_root in (Path("relative-root"), Path("/private/tmp/mrk.dot"), Path("/private/tmp") / ("x" * 81)):
                with self.subTest(sibling_name_binding=bad_root), self.assertRaises(self.module.SessionError):
                    self.module._ruby_sibling_path(home, prefix, bad_root)

        # Exercise the real binder, its canonical resolver and later recheck
        # against complete in-memory metadata. No constructor allocation,
        # descriptor operation, host metadata query or timer can be performed.
        python, ruby = Path("/fixture-tools/python/bin/python"), prefix / "bin/ruby"
        original = {path: SimpleNamespace(st_dev=1, st_ino=800 + i, st_uid=1001, st_gid=20,
                    st_mode=stat.S_IFDIR | (0o750 if path == home else 0o755)) for i, path in enumerate(expected)}
        state = {"nodes": dict(original), "case": "valid", "calls": {}, "clock_calls": 0}
        events, bound, allocations = [], [], []

        def reset(case="valid"):
            state.update(nodes=dict(original), case=case, calls={}, clock_calls=0)

        def observed(path):
            self.assertIn(path, expected)
            count = state["calls"].get(path, 0) + 1
            state["calls"][path] = count
            info = state["nodes"][path]
            if path == expected[-1]:
                fields = {"ancestor-file": {"st_mode": stat.S_IFREG | 0o755},
                          "subject-owner": {"st_uid": 60001}, "subject-group": {"st_gid": 60001},
                          "world-write": {"st_mode": stat.S_IFDIR | 0o757},
                          "unsearchable": {"st_mode": stat.S_IFDIR | 0o750}}
                if state["case"] == "identity-drift" and count == 2:
                    return SimpleNamespace(**(vars(info) | {"st_ino": info.st_ino + 1}))
                if state["case"] == "mode-drift" and count == 2:
                    return SimpleNamespace(**(vars(info) | {"st_mode": stat.S_IFDIR | 0o751}))
                if state["case"] == "metadata-error":
                    raise FileNotFoundError(errno.ENOENT, "synthetic required ancestor disappeared")
                info = SimpleNamespace(**(vars(info) | fields.get(state["case"], {})))
            return info

        known = {*expected, prefix, ruby, python, python.parent.parent, root, root.parent, home / "work/_temp"}

        def resolved(path, *, strict):
            self.assertTrue(strict)
            self.assertIn(path, known)
            events.append(("resolve", path))
            return path / "alias" if state["case"] == "canonical-alias" and path == expected[-1] else path

        def clock():
            state["clock_calls"] += 1
            return 100.0 if state["case"] == "deadline" and state["clock_calls"] >= 4 else 1.0

        def root_metadata(path):
            self.assertIn(path, (root, root.parent))
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | (0o1777 if path == root.parent else 0o755))

        class BeforeAllocation(Exception):
            pass

        def allocation_boundary(path, *, mode):
            self.assertEqual(len(bound), 1, "binding must complete before the first attempted allocation")
            self.assertEqual((path, mode), (root.parent / "mrk-ci-identity-reservation", 0o700))
            self.assertEqual(bound[0].ruby_ancestors, expected)
            self.assertEqual(bound[0].ruby_prefix, prefix)
            self.assertFalse(hasattr(bound[0], "policy"), "no policy may have been published")
            allocations.append(path)
            raise BeforeAllocation("inert stop before reservation creation")

        forbidden = Mock(side_effect=AssertionError("ancestor binding must have no resource effects"))
        fake_signal = SimpleNamespace(ITIMER_REAL=0, SIGCHLD=17, SIG_DFL=0,
            getitimer=Mock(return_value=(0.0, 0.0)), getsignal=Mock(return_value=0), signal=forbidden, setitimer=forbidden)
        with patch.multiple(self.module, os=SimpleNamespace(geteuid=lambda: 0), sys=SimpleNamespace(platform="darwin"),
                            subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=fake_signal,
                            time=SimpleNamespace(monotonic=clock), secrets=SimpleNamespace(randbelow=lambda n: 1),
                            _private_file=forbidden, _readonly_tree=forbidden), \
             patch.object(Path, "resolve", resolved), patch.object(Path, "lstat", observed), \
             patch.object(Path, "stat", root_metadata), patch.object(Path, "mkdir", allocation_boundary), \
             patch.object(Path, "chmod", forbidden), patch.object(Path, "read_bytes", forbidden), \
             patch.object(Path, "read_text", forbidden), patch.object(Path, "open", forbidden):
            for case in ("valid", "prefix-missing", "prefix-ambiguous", "ancestor-file", "subject-owner", "subject-group",
                         "world-write", "unsearchable", "canonical-alias", "identity-drift", "mode-drift", "metadata-error", "deadline"):
                with self.subTest(actual_ancestor_binding=case):
                    reset(case)
                    session = session_double(self.module, "darwin")
                    session.runner_home, session.ruby = home, ruby
                    session.tool_prefixes = (python.parent.parent, prefix)
                    if case == "prefix-missing":
                        session.tool_prefixes = (python.parent.parent,)
                    elif case == "prefix-ambiguous":
                        session.tool_prefixes += (prefix.parent,)
                    for name in ("ruby_prefix", "ruby_ancestors", "_ruby_ancestor_states"):
                        delattr(session, name)
                    if case != "valid":
                        failure_type = FileNotFoundError if case == "metadata-error" else self.module.SessionError
                        with self.assertRaises(failure_type):
                            session._bind_ruby_ancestors()
                        for name in ("ruby_prefix", "ruby_ancestors", "_ruby_ancestor_states"):
                            self.assertFalse(hasattr(session, name), "failed partial inventory must never be published")
                    else:
                        session._bind_ruby_ancestors()
                        self.assertEqual((session.ruby_prefix, session.ruby_ancestors), (prefix, expected))
                        self.assertIs(type(session.ruby_ancestors), tuple)
                        self.assertIs(type(session._ruby_ancestor_states), tuple)
                        self.assertEqual(state["calls"], {path: 2 for path in expected})
                        baseline = session._ruby_ancestor_states
                        self.assertEqual(tuple(self.module._home_node(s) for s in baseline),
                                         tuple(self.module._home_node(original[p]) for p in expected))
                        session._check_ruby_ancestors()
                        state["nodes"][home] = SimpleNamespace(**(vars(original[home]) | {"st_mode": stat.S_IFDIR | 0o751}))
                        session._check_ruby_ancestors(home_mode=0o751)
                        with self.assertRaises(self.module.SessionError):
                            session._check_ruby_ancestors()  # An implicit mode exception is forbidden.
                        state["nodes"][home] = original[home]
                        session._check_ruby_ancestors(home_mode=0o750)
                        self.assertIs(session._ruby_ancestor_states, baseline)
                        self.assertEqual(stat.S_IMODE(baseline[0].st_mode), 0o750)
                        for drift in ("tuple", "state-count", "identity", "mode", "canonical-alias", "deadline"):
                            with self.subTest(actual_ancestor_recheck=drift):
                                reset(drift)
                                session.ruby_ancestors, session._ruby_ancestor_states = expected, baseline
                                if drift == "tuple":
                                    session.ruby_ancestors = expected[:-1]
                                elif drift == "state-count":
                                    session._ruby_ancestor_states = baseline[:-1]
                                elif drift in {"identity", "mode"}:
                                    key, value = ("st_ino", 999) if drift == "identity" else ("st_mode", stat.S_IFDIR | 0o751)
                                    state["nodes"][expected[-1]] = SimpleNamespace(**(vars(original[expected[-1]]) | {key: value}))
                                with self.assertRaises(self.module.SessionError):
                                    session._check_ruby_ancestors()
                        reset()
                        session.ruby_ancestors, session._ruby_ancestor_states = expected, baseline
                        session._check_ruby_ancestors()
                    self.assertEqual(session.deadline, 100.0)

            # Call the actual constructor only through its pre-allocation phase.
            # A real binder failure must reach no allocation; successful binding
            # must precede the first intercepted create, not just policy writing.
            original_bind = self.module.Session._bind_ruby_ancestors

            def bind_then_record(instance):
                original_bind(instance)
                bound.append(instance)

            with patch.object(self.module.Session, "_bind_ruby_ancestors", bind_then_record):
                for case in ("subject-group", "valid"):
                    reset(case)
                    with self.subTest(constructor_before_allocation=case), self.assertRaises(
                            self.module.SessionError if case == "subject-group" else BeforeAllocation):
                        self.module.Session("darwin", root, python=python, ruby=ruby, runner_home=home,
                            runner_temp=home / "work/_temp", tool_prefixes=(python.parent.parent, prefix), deadline=100.0)
                    self.assertEqual(len(allocations), 0 if case == "subject-group" else 1)
            self.assertEqual(len(bound), 1)
            self.assertEqual(bound[0].deadline, 100.0)
            forbidden.assert_not_called()
