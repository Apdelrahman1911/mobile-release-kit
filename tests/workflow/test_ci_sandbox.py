"""Pure hosted-owner regressions, not native isolation or process evidence.

Only inert definitions are loaded. Collection uses synthetic paths, in-memory
files, original-child doubles, a bounded fake clock and a fake selector. Neither
Session construction's resource path nor any native entry point is executed.
The helper's OS/process/signal namespaces are replaced, not shared stdlib APIs.
"""
from __future__ import annotations

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
    session.process_observer = session.bootstrap / "process-observer" if platform == "darwin" else None
    return session


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
                time=SimpleNamespace(monotonic=self.monotonic), signal=SimpleNamespace(),
                _domain=self.domain, _canonical=Path,
                _small_command=Mock(side_effect=AssertionError("native metadata is forbidden")),
                _mac_snapshot=self.mac_snapshot,
            ))
            stack.enter_context(patch.object(self.session, "_headroom", Mock()))
            stack.enter_context(patch.object(self.session, "_cleanup", self.cleanup))
            stack.enter_context(patch.object(self.session, "_argv", return_value=(["/synthetic/entry"], {})))
            yield

    def collect(self, *, seconds=1.0, output_limit=64, latch=True):
        with self.scope():
            kwargs = dict(cwd=self.session.work, env={}, seconds=seconds, output_limit=output_limit)
            if latch:
                return self.session.run([str(self.session.python), "--synthetic"], **kwargs)
            return self.session._run([str(self.session.python), "--synthetic"], latch=False, **kwargs)


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
        drop = argv.index("/usr/bin/setpriv")
        for flag in ("--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
                     "--new-session", "--die-with-parent", "--proc", "--dev", "--tmpfs"):
            self.assertLess(argv.index(flag), drop)
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
        session.runner_home = Path("/opt/runner-private")
        with patch.object(Path, "exists", return_value=True), self.assertRaisesRegex(
            self.module.SessionError, "broad OS bind",
        ):
            session._argv([str(session.python)], 180)

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

    def test_finality_access_guard_and_close_fail_without_adopting_or_resetting(self):
        for case in ("busy", "owned", "remaining", "unknown"):
            session = session_double(self.module)
            session._busy = case == "busy"
            session._active = object() if case == "owned" else None
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
                if case in {"busy", "owned"}:
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
             patch.object(session, "_run", side_effect=primary) as run, \
             patch.object(Path, "read_bytes", read_positive), \
             patch.object(Path, "stat", side_effect=AssertionError("failed native prefix cannot inspect Ruby metadata")), \
             patch.object(Path, "chmod", side_effect=AssertionError("failed admission cannot adopt output")) as chmod:
            with self.assertRaises(BaseExceptionGroup) as caught:
                session._preflight()
        self.assertEqual(caught.exception.exceptions, (primary, cleanup[0], cleanup[2]))
        run.assert_called_once()
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

                def home_positive():
                    self.assertEqual(platform, "darwin")
                    self.assertEqual(events, [])
                    events.append(("home-positive",))
                    if case == "home-positive-error":
                        raise home_error

                def write_positive(*_argv, **_options):
                    self.assertEqual(events, [("home-positive",)] if platform == "darwin" else [])
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
                    self.assertEqual(events, [("home-positive",)])
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
        for case in ("aggregate", "cancel", "late-timeout", "late-cancel"):
            with self.subTest(case=case):
                rig = _Collection(self.module)
                seconds = 1.0
                if case == "aggregate":
                    rig.session.deadline = 0.2
                    rig.exit_at, rig.terminate_exits = float("inf"), False
                    seconds = 10.0
                elif case == "cancel":
                    rig.exit_at, rig.cancel_at = float("inf"), 0.08
                elif case == "late-timeout":
                    rig.final_time = 2.0
                else:
                    rig.cancel_on_finality = True
                result = rig.collect(seconds=seconds)
                self.assertFalse(result.ok)
                self.assertIsNotNone(rig.session.failure)
                self.assertEqual(result.timed_out, case in {"aggregate", "late-timeout"})
                self.assertEqual(result.cancelled, case in {"cancel", "late-cancel"})
                if case == "aggregate":
                    self.assertEqual(rig.session.deadline, 0.2)
                    term = rig.events.index(("terminate-original",))
                    kill = rig.events.index(("kill-original",))
                    self.assertLess(term, kill)
                with self.assertRaises(self.module.SessionError):
                    rig.collect()

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
        sdk = sdk_alias.parent / "MacOSX26.4.sdk"
        clang, linker = (toolchain / "usr/bin" / name for name in ("clang", "ld"))
        settings = sdk / "SDKSettings.json"
        for case in ("valid", "sdk-escape", "link-escape", "link-owner", "ancestor-owner", "world-write", "subject-group-write",
                     "setid-compiler", "nonexec-linker", "codesign-write", "settings-version", "settings-changed",
                     "compiler-changed", "oversized-compiler", "read-expiry", "initial-expiry"):
            with self.subTest(observer_toolchain=case):
                settings_data = {"Version": "26.4", "CanonicalName": "not-macos" if case == "settings-version" else "macosx26.4"}
                files = {clang: b"inert compiler image", linker: b"inert linker image",
                         settings: json.dumps(settings_data).encode(), Path("/usr/bin/codesign"): b"inert signature-tool image"}
                directories = {toolchain: [toolchain / "usr"], toolchain / "usr": [clang.parent],
                               clang.parent: [clang, linker], sdk: [settings]}
                clock = SimpleNamespace(now=1.0 if case == "initial-expiry" else 0.0)
                opened, streams = [], []

                def resolve(path, *, strict=False):
                    self.assertTrue(strict)
                    if path == sdk_alias:
                        return Path("/outside/sdk") if case == "sdk-escape" else sdk
                    if path == clang and case == "link-escape":
                        return Path("/outside/clang")
                    if path not in files and path not in directories:
                        raise AssertionError("unknown synthetic provider link")
                    return path

                def state(path):
                    if path not in files and path not in directories and path not in (xcode, *xcode.parents):
                        raise AssertionError("unknown synthetic provider stat")
                    mode = (stat.S_IFREG if path in files else stat.S_IFDIR) | 0o755
                    owner, group, inode, size = 0, 0, 17, len(files.get(path, b""))
                    if case == "ancestor-owner" and path == Path("/Applications"):
                        owner = 1001
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
                    if case == "compiler-changed" and path == clang and path in opened:
                        inode += 1
                    if case == "oversized-compiler" and path == clang:
                        size = 512 * self.module.MiB + 1
                    return SimpleNamespace(st_uid=owner, st_gid=group, st_mode=mode, st_dev=3, st_ino=inode,
                                           st_size=size, st_mtime_ns=101, st_ctime_ns=102)

                def link_state(path):
                    result = state(path)
                    if case == "link-owner" and path == clang:
                        result.st_uid = 60001
                    return result

                def children(path):
                    if path not in directories:
                        raise AssertionError("unknown synthetic provider directory")
                    return directories[path]

                class Input(io.BytesIO):
                    def read(stream, count=-1):
                        self.assertEqual(count, 65536)
                        if case == "read-expiry" and stream.path == clang:
                            clock.now = 1.0
                        return super().read(count)

                def open_input(path, mode):
                    self.assertEqual(mode, "rb")
                    if path not in files:
                        raise AssertionError("unknown synthetic provider read")
                    opened.append(path)
                    stream = Input(files[path])
                    stream.path = path
                    streams.append(stream)
                    return stream

                def read_settings(path):
                    self.assertEqual(path, settings)
                    return files[path] + b" " if case == "settings-changed" else files[path]

                executable = self.module._admit_executable
                with patch.multiple(self.module, _canonical=Path, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                    signal=SimpleNamespace(), time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "resolve", resolve), patch.object(Path, "stat", state), \
                     patch.object(Path, "lstat", link_state), patch.object(Path, "iterdir", children), \
                     patch.object(Path, "open", open_input), patch.object(Path, "read_bytes", read_settings), \
                     patch.object(self.module, "_admit_executable", wraps=executable) as role:
                    if case == "valid":
                        result = self.module._observer_toolchain(60001, 60001, deadline=1.0)
                        self.assertEqual({key: result[key] for key in ("clang", "linker", "sdk", "toolchain")},
                                         {"clang": clang, "linker": linker, "sdk": sdk, "toolchain": toolchain})
                        self.assertEqual(result["evidence"], {"xcode": "26.3", "sdk": "macosx26.4", "provider_entries": 5,
                                         "clang_sha256": hashlib.sha256(files[clang]).hexdigest(),
                                         "linker_sha256": hashlib.sha256(files[linker]).hexdigest(),
                                         "sdk_settings_sha256": hashlib.sha256(files[settings]).hexdigest()})
                        self.assertEqual([c.args for c in role.call_args_list],
                                         [(clang, 60001, 60001), (linker, 60001, 60001), (Path("/usr/bin/codesign"), 60001, 60001)])
                        self.assertEqual([c.kwargs for c in role.call_args_list],
                                         [{"root_owned": True, "role": name} for name in ("compiler", "linker", "signature-tool")])
                    else:
                        with self.assertRaises(self.module.SessionError):
                            self.module._observer_toolchain(60001, 60001, deadline=1.0)
                self.assertTrue(all(stream.closed for stream in streams))
                if case in {"sdk-escape", "initial-expiry", "ancestor-owner", "world-write", "link-escape", "link-owner"}:
                    self.assertEqual(opened, [])
                if case == "oversized-compiler":
                    self.assertNotIn(clang, opened)

    def test_observer_preparation_requires_each_real_result_and_revokes_publication_on_late_failure(self):
        cases = ("valid", "toolchain-error", "unsupported-arch", "source-too-large", "output-collision", "frozen-collision",
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

                prepared_tools = Mock(return_value=tools, side_effect=self.module.SessionError("synthetic provider binding failure")
                                      if case == "toolchain-error" else None)
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
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)):
                            session.admit()
                        self.assertFalse(session.admitted)
                        self.assertIsNone(session.process_observer)
                        self.assertNotIn(observer_key, session._environment({}))
                        self.assertEqual(session.failure, "native isolation admission failed; no product command permitted")
                        self.assertFalse(any(n["ok"] for n in session.admission_results if n["name"] == "process-observer"))
                        before = commands.call_count
                        progress.now = 0.0
                        with self.assertRaises(self.module.SessionError):
                            session.run([str(session.python)], cwd=session.work, env={}, seconds=1)
                        self.assertEqual(commands.call_count, before)
                    self.assertFalse(session._admitting)
                prepared_tools.assert_called_once_with(session.uid, session.gid, deadline=session.deadline)
                early = case.startswith("compile-") or case in {"toolchain-error", "unsupported-arch", "source-too-large",
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
                    "home_canary": "/Users/runner/.synthetic-home-canary", "home_socket": "/Users/runner/.synthetic-home-socket",
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
        for case in ("busy", "active", "remaining", "unknown", "expired", "independent-close-errors"):
            with self.subTest(home_unknown_finality=case):
                session = session_double(self.module, "darwin")
                session.runner_home = Path("/Users/runner")
                session.deadline = 1.0
                session.failure = "earlier immutable failure"
                session.domain_finality = True
                session._busy = case == "busy"
                session._active = object() if case == "active" else None
                original = SimpleNamespace(st_dev=7, st_ino=101, st_mode=stat.S_IFDIR | 0o750, st_uid=1001, st_gid=20, st_nlink=2)
                canary = SimpleNamespace(st_dev=7, st_ino=102, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1)
                endpoint = SimpleNamespace(st_dev=7, st_ino=103, st_mode=stat.S_IFSOCK | 0o666, st_uid=0, st_gid=0, st_nlink=1)
                primary = OSError(errno.EIO, "synthetic unknown reserved-identity domain")
                listener_error = OSError(errno.EIO, "synthetic original HOME listener close")
                canary_error = OSError(errno.EIO, "synthetic original HOME canary close")
                pin_error = OSError(errno.EIO, "synthetic original HOME pin close")
                listener = SimpleNamespace(close=Mock(side_effect=listener_error if case == "independent-close-errors" else None))
                session._home_state = {"pin": 101, "original": original, "change_attempted": True, "prepared": True,
                    "expected_mode": 0o751, "canary_fd": 102, "canary_name": f".{session.root.name}-home-read",
                    "canary_identity": canary, "canary_mode": 0o444, "canary_create_attempted": True, "listener": listener,
                    "socket_name": f".{session.root.name}-home-socket", "socket_identity": endpoint, "socket_mode": 0o666,
                    "socket_bind_attempted": True, "closed": False}

                def close(fd):
                    self.assertIn(fd, (101, 102))
                    if case == "independent-close-errors":
                        raise canary_error if fd == 102 else pin_error

                closed = Mock(side_effect=close)
                denied = Mock(side_effect=AssertionError("unknown ownership/finality cannot change HOME state"))
                domain = Mock(side_effect=primary) if case in {"unknown", "independent-close-errors"} else Mock(return_value={4242})
                with patch.multiple(self.module, os=SimpleNamespace(close=closed, fchmod=denied, unlink=denied, geteuid=lambda: 0,
                                        path=SimpleNamespace(basename=os.path.basename)),
                                    subprocess=SimpleNamespace(), socket=SimpleNamespace(), signal=SimpleNamespace(),
                                    _domain=domain, time=SimpleNamespace(monotonic=lambda: 1.0 if case == "expired" else 0.0)), \
                     patch.object(Path, "stat", side_effect=AssertionError("no real HOME stat is permitted")), \
                     patch.object(Path, "lstat", side_effect=AssertionError("no real HOME lstat is permitted")), \
                     patch.object(Path, "chmod", denied), patch.object(Path, "unlink", denied):
                    failures = session._close_home_boundary()
                    self.assertTrue(failures)
                    self.assertTrue(session._home_state["closed"])
                    self.assertEqual(session._close_home_boundary(), [])
                denied.assert_not_called()
                self.assertEqual(sorted(c.args[0] for c in closed.call_args_list), [101, 102])
                listener.close.assert_called_once_with()
                self.assertEqual(session.failure, "earlier immutable failure")
                self.assertEqual(session.deadline, 1.0)
                if case in {"unknown", "independent-close-errors"}:
                    self.assertIn(primary, failures)
                if case == "independent-close-errors":
                    self.assertTrue(all(error in failures for error in (listener_error, canary_error, pin_error)))

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
        cases = ("eacces", "eperm", "read-missing", "read-permitted", "stat-missing", "stat-readonly", "stat-permitted",
                 "socket-missing", "socket-unknown", "socket-permitted", "socket-close-error")
        for case in cases:
            with self.subTest(home_mandatory_control=case):
                events = []

                def denied(path, operation):
                    self.assertEqual(path, canary)
                    events.append((operation,))
                    if case == operation + "-permitted":
                        return b"synthetic literal is readable" if operation == "read" else SimpleNamespace(st_mode=stat.S_IFREG | 0o444)
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
                        "runner_home": str(home), "work": "/private/tmp/mrk-pure-fixture/work"}

                def opened(path, flags):
                    self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    result = denied(path, "read")
                    self.assertIsInstance(result, bytes)
                    return 302

                def metadata(path, *, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    return denied(path, "stat")

                def read(fd, count):
                    self.assertEqual((fd, count), (302, len(self.module._HOME_READ_BYTES) + 1))
                    return b"synthetic readable bytes"

                closed = Mock()
                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                with patch.multiple(self.module, os=SimpleNamespace(**constants, fsencode=os.fsencode,
                                        open=opened, stat=metadata, read=read, close=closed), sys=SimpleNamespace(platform="darwin"),
                                    socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=factory),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace()), \
                     patch.object(Path, "read_bytes", side_effect=AssertionError("the known-path probe uses only its bounded descriptor")), \
                     patch.object(Path, "stat", side_effect=AssertionError("the known-path probe must not follow links")):
                    if case in {"eacces", "eperm"}:
                        self.module._probe_provider_boundaries(data)
                    else:
                        with self.assertRaises((self.module.SessionError, OSError, BaseExceptionGroup)):
                            self.module._probe_provider_boundaries(data)
                if factory.called:
                    factory.assert_called_once_with(1, 1)
                    endpoint.close.assert_called_once_with()
                    endpoint.settimeout.assert_called_once()
                    self.assertTrue(0 < endpoint.settimeout.call_args.args[0] <= 3)
                else:
                    endpoint.close.assert_not_called()
                if case == "read-permitted":
                    closed.assert_called_once_with(302)
                else:
                    closed.assert_not_called()
                if case in {"eacces", "eperm"}:
                    self.assertEqual(events, [("read",), ("stat",), ("connect",)])

    def test_home_search_preparation_and_terminal_restore_keep_original_handles_and_uncertain_effects(self):
        cases = ("750", "751", "755", "home-mode", "home-owner", "home-group", "home-name", "open-home",
                 "change-before-effect", "change-after-effect", "canary-collision", "canary-stat-error", "canary-links", "canary-subject-group",
                 "canary-short-write", "canary-mode-after-effect", "socket-collision", "socket-subject-group", "socket-mode-after-effect",
                 "manifest-error", "late-preparation", "close-name-drift", "close-mode-drift", "canary-replaced", "canary-group-drift", "socket-group-drift",
                 "restore-after-effect", "three-close-errors")
        for case in cases:
            with self.subTest(home_pin_lifecycle=case):
                session = session_double(self.module, "darwin")
                session.admitted = False
                session.process_observer = None
                session.runner_home = Path("/Users/runner")
                session.ruby = session.runner_home / "tools/ruby/bin/ruby"
                session.tool_prefixes = (session.python.parent.parent, session.ruby.parent.parent)
                session.deadline = 1.0
                canary_name, socket_name = f".{session.root.name}-home-read", f".{session.root.name}-home-socket"
                canary_path, socket_path = session.runner_home / canary_name, session.runner_home / socket_name
                original_mode = int(case, 8) if case in {"750", "751", "755"} else 0o777 if case == "home-mode" else 0o750
                clock = SimpleNamespace(now=0.0, closing=False)
                events, nodes, captured_cleanup = [], {}, []
                live_fds = {}
                original_error = OSError(errno.EIO, "synthetic private HOME operation")
                close_errors = {101: OSError(errno.EIO, "synthetic pin close"), 102: OSError(errno.EIO, "synthetic canary close"),
                                "listener": OSError(errno.EIO, "synthetic listener close")}

                def node(inode, kind, mode, *, uid=0, gid=0, links=1, size=0):
                    return dict(st_dev=7, st_ino=inode, st_mode=kind | mode, st_uid=uid, st_gid=gid,
                                st_nlink=links, st_size=size)

                home_node = node(11, stat.S_IFDIR, original_mode,
                                 uid=session.uid if case == "home-owner" else 1001,
                                 gid=session.gid if case == "home-group" else 20, links=2)

                def named_home(path):
                    self.assertEqual(path, session.runner_home)
                    result = dict(home_node)
                    if case == "home-name" or clock.closing and case == "close-name-drift":
                        result["st_ino"] += 1
                    return SimpleNamespace(**result)

                def opened(path, flags, mode=None, *, dir_fd=None):
                    events.append(("open", str(path), flags, mode, dir_fd))
                    if path == session.runner_home:
                        self.assertEqual((flags, mode, dir_fd), (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, None, None))
                        if case == "open-home":
                            raise original_error
                        live_fds[101] = home_node
                        return 101
                    self.assertEqual((path, flags, mode, dir_fd), (canary_name,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, 101))
                    self.assertTrue(session._home_state["prepared"])
                    self.assertTrue(session._home_state["canary_create_attempted"])
                    if case == "canary-collision":
                        nodes[canary_name] = node(91, stat.S_IFREG, 0o444, uid=1001)
                        raise FileExistsError(errno.EEXIST, "synthetic foreign existing canary name")
                    self.assertNotIn(canary_name, nodes)
                    nodes[canary_name] = node(12, stat.S_IFREG, 0o600, gid=session.gid if case == "canary-subject-group" else 20,
                                              links=2 if case == "canary-links" else 1)
                    live_fds[102] = nodes[canary_name]
                    return 102

                def fstat(fd):
                    self.assertIn(fd, live_fds)
                    if fd == 102 and case == "canary-stat-error" and not clock.closing:
                        raise original_error
                    return SimpleNamespace(**live_fds[fd])

                def metadata(name, *, dir_fd, follow_symlinks):
                    self.assertEqual((dir_fd, follow_symlinks), (101, False))
                    self.assertIn(name, (canary_name, socket_name))
                    result = dict(nodes[name])
                    if clock.closing and case == "canary-replaced" and name == canary_name:
                        result["st_ino"] += 1
                    if clock.closing and (case == "canary-group-drift" and name == canary_name
                                          or case == "socket-group-drift" and name == socket_name):
                        result["st_gid"] = 0  # Even another non-U group is not the original owned node.
                    return SimpleNamespace(**result)

                def fchmod(fd, mode):
                    self.assertIn(fd, live_fds)
                    self.assertIn((fd, mode), {(101, 0o751), (101, original_mode), (102, 0o444)})
                    if fd == 101 and not clock.closing:
                        self.assertTrue(session._home_state["change_attempted"])
                    if fd == 102:
                        self.assertIsNone(session._home_state["canary_mode"])
                    events.append(("fchmod", fd, mode, clock.closing))
                    if case == "change-before-effect" and fd == 101 and not clock.closing:
                        raise original_error
                    live_fds[fd]["st_mode"] = stat.S_IFMT(live_fds[fd]["st_mode"]) | mode
                    if (case == "change-after-effect" and fd == 101 and not clock.closing
                            or case == "canary-mode-after-effect" and fd == 102
                            or case == "restore-after-effect" and fd == 101 and clock.closing):
                        raise original_error

                def write(fd, data):
                    self.assertEqual((fd, data), (102, self.module._HOME_READ_BYTES))
                    self.assertIsNotNone(session._home_state["canary_identity"])
                    count = len(data) - 1 if case == "canary-short-write" else len(data)
                    nodes[canary_name]["st_size"] = count
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
                    self.assertEqual(dir_fd, 101)
                    self.assertIn(name, (canary_name, socket_name))
                    self.assertIn(name, nodes)
                    self.assertEqual(nodes[name]["st_uid"], 0)  # Never the collision's pre-existing file.
                    events.append(("unlink", name))
                    del nodes[name]

                def close(fd):
                    self.assertIn(fd, live_fds)
                    events.append(("close", fd))
                    del live_fds[fd]
                    if case == "three-close-errors":
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
                    if case == "three-close-errors":
                        raise close_errors["listener"]

                listener = SimpleNamespace(settimeout=Mock(), bind=Mock(side_effect=bind), listen=Mock(),
                                           close=Mock(side_effect=listener_close))
                factory = Mock(return_value=listener)

                def manifest(path, data, mode):
                    self.assertEqual((path, mode), (session.bootstrap / "home-control.json", 0o444))
                    self.assertEqual(json.loads(data), {"home": str(session.runner_home), "uid": session.uid,
                                                       "gid": session.gid, "deadline": session.deadline})
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

                finalize = session._close_home_boundary

                def finalization():
                    errors = finalize()
                    captured_cleanup.extend(errors)
                    return errors

                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_RDWR", "O_DIRECTORY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, geteuid=lambda: 0, fsencode=os.fsencode,
                    open=opened, fstat=fstat, stat=metadata, fchmod=fchmod, write=write, fsync=Mock(),
                    chmod=socket_chmod, unlink=unlink, close=close, path=SimpleNamespace(basename=os.path.basename))
                prepared = case in {"750", "751", "755", "close-name-drift", "close-mode-drift", "canary-replaced", "canary-group-drift", "socket-group-drift",
                                    "restore-after-effect", "three-close-errors"}
                with patch.multiple(self.module, os=fake_os, sys=SimpleNamespace(platform="darwin"),
                                    socket=SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=factory),
                                    subprocess=SimpleNamespace(), signal=SimpleNamespace(), _domain=domain,
                                    _private_file=Mock(side_effect=manifest), time=SimpleNamespace(monotonic=lambda: clock.now)), \
                     patch.object(Path, "lstat", named_home), \
                     patch.object(Path, "stat", side_effect=AssertionError("HOME pin must not follow paths")), \
                     patch.object(Path, "chmod", side_effect=AssertionError("HOME permission changes require the original pin")), \
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
                        self.assertIs(session._home_state["listener"], listener)
                        self.assertEqual(session._home_state["canary_identity"].st_gid, 20)
                        self.assertEqual(session._home_state["socket_identity"].st_gid, 20)
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
                self.assertEqual(sum(e == ("close", 101) for e in events), int(case != "open-home"))
                self.assertLessEqual(sum(e == ("close", 102) for e in events), 1)
                self.assertEqual(listener.close.call_count, factory.call_count)
                note = next(n for n in session.admission_results if n["name"] == "home-boundary-finalization")
                if case in {"750", "751", "755"}:
                    self.assertEqual(captured_cleanup, [])
                    self.assertTrue(note["ok"])
                    self.assertEqual(note["restored"], case == "750")
                    self.assertTrue(note["canary_removed"] and note["socket_removed"])
                    self.assertEqual(nodes, {})
                    self.assertEqual(stat.S_IMODE(home_node["st_mode"]), original_mode)
                    home_changes = [e for e in events if e[0] == "fchmod" and e[1] == 101]
                    self.assertEqual(home_changes, [("fchmod", 101, 0o751, False), ("fchmod", 101, 0o750, True)] if case == "750" else [])
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
                if case == "three-close-errors":
                    self.assertTrue(all(error in captured_cleanup for error in close_errors.values()))

    def test_linux_provider_wrapper_keeps_collision_writer_import_and_partial_preparation_gates(self):
        cases = ("valid", "nss-bad", "collision", "busy", "active", "prior-failure", "wrong-platform", "not-root",
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
                        if case in {"loader-failure", "partial-preparation"}:
                            self.assertIs(caught.exception, original)
                self.assertIs(sys.modules.get(module_name), real_module_before)  # No real lazy import or ownership mutation.
                self.assertEqual(session.admitted, case == "valid")
                if case == "valid":
                    self.assertLess(events.index(("nss",)), events.index(("domain", True)))
                    self.assertLess(events.index(("domain", True)), events.index(("load",)))
                    self.assertLess(events.index(("protect",)), events.index(("tool", "python")))
                    self.assertLess(events.index(("tool", "true")), events.index(("preflight",)))
                    self.assertEqual(chown.call_count, 5)
                else:
                    self.assertFalse(any(e[0] in {"tool", "preflight"} for e in events))
                    chown.assert_not_called()
                    if not direct:
                        self.assertEqual(session.failure, "native isolation admission failed; no product command permitted")
                early = case in {"nss-bad", "collision", "busy", "active", "prior-failure", "wrong-platform", "not-root", "missing-prefix", "existing-module"}
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
        }
        cases = ("valid", "wrong-platform", "wrong-uid", "effective-uid", "effective-gid", "manifest-open", "canary-open",
                 "manifest-short", "manifest-tail", "manifest-key", "manifest-bool-uid", "manifest-wrong-gid", "extra-groups",
                 "invalid-deadline", "expired-deadline", "canary-bytes", "canary-tail", "connect-error", "send-error",
                 "send-late", "close-late", "three-close-errors", *metadata_cases)
        for case in cases:
            with self.subTest(fixed_home_control=case):
                home, bootstrap = Path("/Users/runner"), Path("/private/tmp/mrk-pure-fixture/bootstrap")
                entry, manifest = bootstrap / "ci_sandbox.py", bootstrap / "home-control.json"
                canary, address = home / ".mrk-pure-fixture-home-read", home / ".mrk-pure-fixture-home-socket"
                clock, events, live, acquired, reads = SimpleNamespace(now=0.0), [], set(), [], {}
                body_error = OSError(errno.EIO, "synthetic fixed HOME control operation")
                close_errors = {201: OSError(errno.EIO, "synthetic manifest close"), 202: OSError(errno.EIO, "synthetic canary close"),
                                "peer": OSError(errno.EIO, "synthetic HOME positive peer close")}
                data = {"home": str(home), "uid": 60001, "gid": 60001, "deadline": 100.0}
                if case == "manifest-key":
                    data["path"] = "/not-an-accepted-reader-interface"
                if case == "manifest-bool-uid":
                    data["uid"] = True
                if case == "manifest-wrong-gid":
                    data["gid"] += 1
                if case in {"invalid-deadline", "expired-deadline"}:
                    data["deadline"] = True if case == "invalid-deadline" else 0.0
                raw = json.dumps(data).encode()
                nodes = {201: dict(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0, st_nlink=1, st_size=len(raw)),
                         202: dict(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=20, st_nlink=1, st_size=len(self.module._HOME_READ_BYTES))}
                if case in metadata_cases:
                    fd, key, value = metadata_cases[case]
                    nodes[fd][key] = value

                def opened(path, flags):
                    self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    expected = manifest if not acquired else canary
                    self.assertEqual(path, expected)
                    fd = 201 if path == manifest else 202
                    events.append(("open", fd))
                    if case == ("manifest-open" if fd == 201 else "canary-open"):
                        raise body_error
                    acquired.append(fd)
                    live.add(fd)
                    return fd

                def metadata(fd):
                    self.assertIn(fd, live)
                    events.append(("fstat", fd))
                    return SimpleNamespace(**nodes[fd])

                def read(fd, size):
                    self.assertIn(fd, live)
                    count = reads.get(fd, 0)
                    self.assertLess(count, 2)
                    reads[fd] = count + 1
                    self.assertEqual(size, (16385 if fd == 201 else len(self.module._HOME_READ_BYTES) + 1) if count == 0 else 1)
                    events.append(("read", fd, size))
                    if count:
                        return b"x" if case == ("manifest-tail" if fd == 201 else "canary-tail") else b""
                    if fd == 201:
                        return raw[:-1] if case == "manifest-short" else raw
                    return b"wrong\n" if case == "canary-bytes" else self.module._HOME_READ_BYTES

                def close(fd):
                    self.assertIn(fd, live)
                    live.remove(fd)
                    events.append(("close", fd))
                    if case == "close-late" and fd == 201:
                        clock.now = 100.0
                    if case == "three-close-errors":
                        raise close_errors[fd]

                def canonical(value):
                    self.assertEqual(value, str(home))
                    return home

                def own_entry(path):
                    self.assertEqual(path, entry)
                    return path

                def connect(value):
                    self.assertEqual(value, str(address))
                    self.assertEqual(reads, {201: 2, 202: 2})
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
                    if case == "three-close-errors":
                        raise close_errors["peer"]

                peer = SimpleNamespace(settimeout=Mock(), connect=Mock(side_effect=connect), sendall=Mock(side_effect=send),
                                       close=Mock(side_effect=peer_close))
                factory, limits = Mock(return_value=peer), Mock()
                constants = {k: getattr(os, k) for k in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")}
                fake_os = SimpleNamespace(**constants, open=opened, fstat=metadata, read=read, close=close, fsencode=os.fsencode,
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
                        if case == "three-close-errors":
                            self.assertEqual(caught.exception.exceptions, (close_errors["peer"], close_errors[202], close_errors[201]))
                        if case in {"manifest-open", "canary-open", "connect-error", "send-error"}:
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
                    self.assertEqual(reads, {201: 2, 202: 2})
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
        cases = ("valid", "fragmented", "missing-state", "unprepared", "missing-listener", "busy", "pin-drift",
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

                def collect(argv, seconds, **kwargs):
                    self.assertEqual(argv, [str(session.python), "-I", "-S", "-B", str(session.entry), "--home-positive"])
                    self.assertEqual((seconds, kwargs), (10, {"user": session.uid, "group": session.gid, "deadline": session.deadline}))
                    self.assertIn(("pin-check",), rig.events)
                    return genuine_collection(argv, seconds, **kwargs)

                metadata = Mock(side_effect=collect)
                with rig.scope(), patch.object(self.module, "_small_command", metadata), \
                     patch.object(self.module, "_domain", side_effect=domain), \
                     patch.object(self.module, "socket", SimpleNamespace()), \
                     patch.object(session, "_check_home_pin", side_effect=pin), \
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
                        if case == "pin-drift":
                            self.assertIs(caught.exception, pin_error)
                notes = [n for n in session.admission_results if n["name"] == "home-DAC-and-delivery-positive"]
                self.assertEqual(notes, [{"name": "home-DAC-and-delivery-positive", "ok": True}] if case in {"valid", "fragmented"} else [])
                listener.close.assert_not_called()  # Root listener stays in Session's custody until owned finalization.
                if case not in {"missing-state", "missing-listener"}:
                    self.assertIs(session._home_state["listener"], listener)
                preaccept = {"missing-state", "unprepared", "missing-listener", "busy", "pin-drift", "pre-domain", "post-domain",
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
