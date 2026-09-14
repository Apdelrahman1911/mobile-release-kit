"""Inert original-PTY ownership contracts; no native PTY/process is created."""
from __future__ import annotations

import ast
from contextlib import contextmanager, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from workflow.test_ci_sandbox import sandbox_module, session_double


ROOT = Path(__file__).resolve().parents[2]


class InertTTY:
    """Every process, terminal, descriptor, stream and ioctl API is a double."""
    def __init__(self, *, ready=False, fault=None):
        self.events, self.acquired, self.closed, self.output = [], [], [], []
        self.uid, self.fault, self.inside = 60001, fault, ready
        self.failure = OSError(errno.EIO, "synthetic terminal operation")
        self.close_errors, self.stream_errors = {}, {}
        self.next_fd, self.counts = 80, {}
        self.live = {41, 42} if ready else set()
        self.aliases, self.inherit = {41: 41, 42: 42}, {41: ready, 42: ready}
        self.nodes = {
            41: SimpleNamespace(st_dev=1, st_ino=41, st_mode=stat.S_IFCHR | 0o666, st_uid=0, st_gid=0, st_rdev=41),
            42: SimpleNamespace(st_dev=1, st_ino=42, st_mode=stat.S_IFCHR | (0o600 if ready else 0o620),
                                st_uid=self.uid, st_gid=4, st_rdev=42),
        }
        self.queues, self.environ = {41: [], 42: []}, {}
        constants = {name: getattr(os, name) for name in ("O_RDWR", "O_NOFOLLOW", "O_NOCTTY", "O_NONBLOCK", "O_CLOEXEC")}
        self.os = SimpleNamespace(**constants, environ=self.environ,
            getuid=lambda: self.uid, geteuid=lambda: self.uid, getgid=lambda: self.uid, getegid=lambda: self.uid,
            openpty=self.openpty, open=self.open, close=self.close, dup=self.dup, fdopen=self.fdopen,
            fstat=self.fstat, fchmod=self.fchmod, isatty=lambda fd: fd in self.live,
            ttyname=lambda fd: "/dev/ttys042", get_inheritable=lambda fd: self.inherit[fd],
            set_inheritable=self.set_inheritable, set_blocking=lambda *args: self.step("blocking", *args),
            execve=self.execve, write=self.write, read=self.read)
        self.tty = SimpleNamespace(setraw=lambda fd: self.step("setraw", fd))
        self.termios = SimpleNamespace(ICANON=2, TCSANOW=0, TCIOFLUSH=2, VEOF=0,
            tcgetattr=self.attributes, tcsetattr=lambda *args: self.step("setattrs", *args),
            tcflush=lambda *args: self.step("flush", *args))

    def step(self, name, *args):
        self.events.append((name, *args))
        self.counts[name] = self.counts.get(name, 0) + 1
        if self.fault in (name, f"{name}:{self.counts[name]}"):
            raise self.failure

    def attributes(self, fd):
        self.step("attributes", fd)
        return [0, 0, 0, 0, 0, 0, [b"\x04"]]

    def openpty(self):
        self.step("allocate")
        self.live.update((41, 42))
        self.acquired.extend((41, 42))
        return 41, 42

    def dup(self, fd):
        self.step("dup", fd)
        assert fd in self.live
        value, self.next_fd = self.next_fd, self.next_fd + 1
        self.aliases[value], self.inherit[value] = self.aliases[fd], False
        self.live.add(value)
        self.acquired.append(value)
        return value

    def open(self, name, flags):
        self.step("named-open", name, flags)
        assert name == "/dev/ttys042"
        if self.inside:
            raise PermissionError(errno.EACCES, "synthetic named denial")
        return self.dup(42)

    def fstat(self, fd):
        if fd in (0, 1, 2):
            return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        if fd not in self.live:
            raise OSError(errno.EBADF, "synthetic absent descriptor")
        return self.nodes[self.aliases[fd]]

    def fchmod(self, fd, mode):
        self.step("chmod", fd, mode)
        assert fd == 42  # No path or shared master metadata mutation.
        if self.inside:
            raise PermissionError(errno.EPERM, "synthetic metadata denial")
        self.nodes[42].st_mode = stat.S_IFCHR | mode

    def set_inheritable(self, fd, value):
        self.step("inherit", fd, value)
        assert fd in self.live
        self.inherit[fd] = value

    def close(self, fd):
        assert fd in self.live and fd not in self.closed, "double/foreign close"
        self.closed.append(fd)
        self.live.remove(fd)  # A lost close return still cannot be retried.
        self.step("close", fd)
        if fd in self.close_errors:
            raise self.close_errors[fd]

    def execve(self, executable, argv, environment):
        self.events.append(("exec", executable, argv, dict(environment)))
        assert self.live == {41, 42} and all(self.inherit[fd] for fd in self.live)
        raise self.failure  # Observed transfer seam, NOT a real/successful exec.

    def write(self, fd, payload):
        if fd == 2:
            self.output.append(payload)
            return len(payload)
        self.step("write", fd, payload)
        target = 42 if self.aliases[fd] == 41 else 41
        self.queues[target].append(b"" if payload == b"\x04" else payload)
        return len(payload)

    def read(self, fd, size):
        self.step("read", fd, size)
        queue = self.queues[self.aliases[fd]]
        if not queue:
            raise BlockingIOError(errno.EAGAIN, "synthetic drained queue")
        value = queue.pop(0)
        assert len(value) <= size
        return value

    def fdopen(self, fd, mode, *, closefd):
        assert closefd is False and fd in self.live
        self.step("fdopen-" + mode, fd)
        owner = self
        class Stream:
            def isatty(self): return fd in owner.live
            def write(self, value): return owner.write(fd, value.encode())
            def flush(self): pass
            def readline(self, bound): return owner.read(fd, bound).decode()
            def close(self):
                owner.step("stream-close", fd)
                if mode in owner.stream_errors:
                    raise owner.stream_errors[mode]
        return Stream()

    def binding(self):
        def identity(info):
            return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_rdev]
        return json.dumps({"version": 1, "uid": self.uid, "gid": self.uid,
                           "pair": [[fd, identity(self.nodes[fd])] for fd in (41, 42)]},
                          sort_keys=True, separators=(",", ":"))

    def fixture(self, platform="darwin"):
        path = ROOT / "tests/workflow/local_signing_persistent_fixture.py"
        selected = [node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name in {"_owner_tty_original", "owner_tty"}]
        assert len(selected) == 2
        state = {"active": False, "broken": False, "pair": None, "binding": None}
        namespace = {"os": self.os, "sys": SimpleNamespace(platform=platform), "stat": stat, "re": re,
            "json": json, "tty": self.tty, "termios": self.termios, "contextmanager": contextmanager,
            "_OWNER_TTY_ENV": "MRK_CI_PRIVATE_PTY", "_OWNER_TTY_STATE": state,
            "FOCUSED_OWNER_VARIANTS": (), "signing": SimpleNamespace(signing_status=lambda **_kw: {"status": "busy"})}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
        return namespace


class PrivateTTYContractTests(unittest.TestCase):
    def setUp(self):
        self.module = sandbox_module()

    def test_original_entry_failure_closes_every_owned_slot_and_preserves_first_error(self):
        for fault in (None, "allocate", "chmod", "named-open", "close:1", "inherit:2"):
            with self.subTest(fault=fault):
                tty = InertTTY(fault=fault)
                with patch.multiple(self.module, os=tty.os, sys=SimpleNamespace(platform="darwin")):
                    with self.assertRaises(OSError) as caught:
                        self.module._exec_private_pty(["/inert/python", "inert-case"], "/inert/subject.sb", tty.uid, tty.uid)
                self.assertIs(caught.exception, tty.failure)
                self.assertCountEqual(tty.closed, tty.acquired)
                self.assertFalse(tty.live)
                note = self.module._private_pty_failure_note(b"".join(tty.output))
                self.assertEqual(note["errno"], errno.EIO)
                self.assertNotIn(b"synthetic", b"".join(tty.output))
                if fault is None:
                    event = next(event for event in tty.events if event[0] == "exec")
                    self.assertEqual(event[1:3], ("/usr/bin/sandbox-exec",
                        ["/usr/bin/sandbox-exec", "-f", "/inert/subject.sb", "/inert/python", "inert-case"]))
                    self.assertEqual(json.loads(event[3][self.module._PRIVATE_PTY_ENV])["pair"][1][1][2], stat.S_IFCHR | 0o600)
        tty = InertTTY()
        errors = [OSError(errno.EIO, "synthetic slave close"), OSError(errno.EIO, "synthetic master close")]
        tty.close_errors = dict(zip((42, 41), errors))
        with patch.multiple(self.module, os=tty.os, sys=SimpleNamespace(platform="darwin")):
            with self.assertRaises(BaseExceptionGroup) as caught:
                self.module._exec_private_pty(["/inert/python"], "/inert/subject.sb", tty.uid, tty.uid)
        self.assertEqual(caught.exception.exceptions, (tty.failure, *errors))
        self.assertCountEqual(tty.closed, tty.acquired)

    def test_binding_is_closed_and_restores_cloexec_without_adopting_replacements(self):
        tty = InertTTY(ready=True)
        raw = tty.binding()
        with patch.object(self.module, "os", tty.os):
            self.assertEqual(self.module._private_pty_binding(raw), (41, 42))
            self.assertFalse(any(tty.inherit.values()))
            for replacement in (None, "{}", raw + " ", raw.replace('"uid":60001', '"uid":true'),
                                raw.replace('[42,', '[41,'), raw.replace('"version":1', '"version":2')):
                with self.subTest(binding=replacement):
                    with self.assertRaises(self.module.SessionError):
                        self.module._private_pty_binding(replacement)
            tty.nodes[42].st_mode = stat.S_IFCHR | 0o620
            with self.assertRaises(self.module.SessionError):
                self.module._private_pty_binding(raw)
        self.assertFalse(tty.closed)

    def test_probe_positive_and_real_denial_causes_share_exact_pair_not_new_authority(self):
        tty = InertTTY(ready=True)
        with patch.multiple(self.module, os=tty.os, tty=tty.tty, termios=tty.termios,
                            select=SimpleNamespace(select=lambda readers, *_args: (readers, [], [])),
                            time=SimpleNamespace(monotonic=lambda: 10.0)):
            self.assertEqual(self.module._probe_private_pty(tty.binding()), (41, 42))
        self.assertEqual(tty.live, {41, 42})
        self.assertFalse(tty.acquired or tty.closed or tty.output)
        self.assertIn(("chmod", 42, 0o400), tty.events)
        self.assertEqual(tty.nodes[42].st_mode, stat.S_IFCHR | 0o600)
        original = OSError(errno.ENOENT, "synthetic irrelevant denial")
        tty.os.open = Mock(side_effect=original)
        with patch.multiple(self.module, os=tty.os, tty=tty.tty, termios=tty.termios,
                            select=SimpleNamespace(select=lambda readers, *_args: (readers, [], [])),
                            time=SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaises(OSError) as caught:
                self.module._probe_private_pty(tty.binding())
        self.assertIs(caught.exception, original)
        self.assertEqual(self.module._private_pty_failure_note(b"".join(tty.output))["errno"], errno.ENOENT)
        # Unexpected successful named open is failure, and its exact new FD
        # still gets one close even if that close's return is lost.
        tty = InertTTY(ready=True)
        tty.inside = False
        close = OSError(errno.EIO, "synthetic unexpected-open close")
        tty.close_errors[80] = close
        with patch.multiple(self.module, os=tty.os, tty=tty.tty, termios=tty.termios,
                            select=SimpleNamespace(select=lambda readers, *_args: (readers, [], [])),
                            time=SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaises(BaseExceptionGroup) as caught:
                self.module._probe_private_pty(tty.binding())
        self.assertIsInstance(caught.exception.exceptions[0], self.module.SessionError)
        self.assertIs(caught.exception.exceptions[1], close)
        self.assertEqual(tty.closed, [80])
        self.assertEqual(tty.live, {41, 42})
        tty = InertTTY(ready=True)
        tty.os.fchmod = Mock()  # A successful no-op also cannot prove denial.
        with patch.multiple(self.module, os=tty.os, tty=tty.tty, termios=tty.termios,
                            select=SimpleNamespace(select=lambda readers, *_args: (readers, [], [])),
                            time=SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaises(self.module.SessionError):
                self.module._probe_private_pty(tty.binding())
        self.assertEqual(self.module._private_pty_failure_note(b"".join(tty.output))["stage"], "metadata-denial")

    def test_top_pair_exemption_does_not_reach_exec_descendants_or_native_roles(self):
        tty = InertTTY(ready=True)
        tty.environ[self.module._PRIVATE_PTY_ENV] = tty.binding()
        data = {"platform": "darwin", "uid": tty.uid, "gid": tty.uid, "private_pty_required": True}
        boundary = RuntimeError("inert boundary after descriptor inventory")
        tty.os.setuid = Mock(side_effect=PermissionError(errno.EPERM, "synthetic root denial"))
        with patch.multiple(self.module, os=tty.os, _process_groups=Mock(return_value=[tty.uid]),
                            _probe_provider_boundaries=Mock(side_effect=boundary)):
            with self.assertRaises(RuntimeError) as caught:
                self.module._probe_leaf(data)
            self.assertIs(caught.exception, boundary)
            for changed in ({**data, "private_pty_required": False}, {**data, "probe_scratch": "/inert"}):
                with self.assertRaises(self.module.SessionError):
                    self.module._probe_leaf(changed)
            tty.live.add(99)
            tty.aliases[99] = 41
            with self.assertRaises(self.module.SessionError):
                self.module._probe_leaf(data)
            original = OSError(errno.EBADF, "synthetic original transfer loss")
            tty.os.fstat = Mock(side_effect=original)
            with self.assertRaises(OSError) as caught:
                self.module._probe_leaf(data)
            self.assertIs(caught.exception, original)
            note = self.module._private_pty_failure_note(b"".join(tty.output))
            self.assertEqual((note["stage"], note["errno"]), ("binding", errno.EBADF))
        calls = []
        def child(argv, _seconds, *, detached):
            self.assertFalse(json.loads(argv[-1])["private_pty_required"])
            calls.append((argv[-2], detached))
            return b"MRK_LEAF_OK\n"
        with patch.multiple(self.module, _probe_leaf=Mock(), _small_command=child, _sudo_denial=Mock()), redirect_stdout(io.StringIO()):
            self.module._probe(data)
        self.assertTrue(data["private_pty_required"])
        self.assertEqual(calls, [("--leaf", False), ("--grandchild", True)])
        session = session_double(self.module, "darwin")
        self.assertEqual(session._argv([str(session.python), "inert"], 10)[0][5], "--enter")
        self.assertEqual(session._trusted_entry(session.cleanup_policy, ["--sentinel"])[5], "--enter")
        linux = session_double(self.module)
        with patch.object(Path, "exists", return_value=False):
            arguments = linux._argv(["inert"], 10)[0]
        self.assertEqual(arguments[arguments.index(str(linux.entry)) + 1], "--enter")

    def test_only_fixed_probe_and_matrix_vectors_issue_capabilities_in_both_entry_seams(self):
        session = session_double(self.module, "darwin")
        data = {"platform": "darwin", "uid": session.uid, "gid": session.uid,
                "private_pty_required": True, "work": str(session.work), "source": str(session.source)}
        probe = [str(session.python), "-I", "-S", "-B", str(session.entry), "--probe", json.dumps(data)]
        vectors = [probe]
        for flag in ("--phase", "--adapter-phase"):
            for phase in ("source", "wheel"):
                matrix = flag == "--phase"
                package = (session.work / "source-build/src/mobile_release" if phase == "source" else
                           session.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
                vectors.append([str(session.work / f"{phase}-venv/bin/python"), "-I", "-S", "-B",
                    str(session.source / "tests/workflow/run_local_signing_matrix.py"), flag, phase,
                    "--package-root", str(package), "--output",
                    str(session.work / ("signing-matrix" if matrix else "signing-adapter") / phase),
                    *(["--shard", "15"] if matrix else []), "--deadline", "50.0", "--os", "macos-26",
                    "--repository", "synthetic/project", "--commit", "a" * 40, "--run-id", "1", "--run-attempt", "1",
                    "--job", "test-signing-matrix" if matrix else "test-signing-adapter"])
        for command in vectors:
            self.assertTrue(self.module._private_pty_command(command, session.root, session.python, session.uid))
            self.assertEqual(session._argv(command, 10)[0][5], "--enter-private-pty")
        invalid = [probe[:-1] + [json.dumps({**data, "private_pty_required": False})],
                   probe[:-1] + [json.dumps({**data, "probe_scratch": "/inert"})],
                   [str(session.ruby), "--inert"], [str(session.python), "-m", "pip"],
                   [*probe[:4], str(session.source / ".github/scripts/ci_checks.py"), "--check", "native"],
                   [*vectors[1][:5], "--reduce", *vectors[1][6:]],
                   ["/foreign/python", *vectors[1][1:]], [*vectors[1], "--local"]]
        for command in invalid:
            self.assertFalse(self.module._private_pty_command(command, session.root, session.python, session.uid))
            self.assertEqual(session._argv(command, 10)[0][5], "--enter")
        framework = "/inert/python/Resources/Python.app/Contents/MacOS/Python"
        for original_tool, command in ((str(session.python), probe), (framework, probe), (framework, vectors[-1])):
            with self.subTest(original_tool_spelling="framework" if original_tool == framework else "selected",
                              command_role=command[5]):
                args = ["--enter-private-pty", "darwin", str(session.uid), str(session.gid), "10", str(session.policy), *command]
                original = [original_tool, "-I", "-S", "-B", str(session.entry), *args]
                tty = InertTTY()
                boundary = RuntimeError("inert transfer boundary")
                flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1,
                                        ignore_environment=1, no_user_site=1, safe_path=True)
                fake_sys = SimpleNamespace(platform="darwin", orig_argv=original,
                                           executable=str(session.python), flags=flags)
                transfer = Mock(side_effect=boundary)
                resolved = []
                def resolve(path, *, strict):
                    self.assertTrue(strict)
                    self.assertIn(path, (session.entry, session.python))
                    resolved.append(path)
                    return path  # No native resolution, launcher or PTY operation.
                with patch.multiple(self.module, __file__=str(session.entry), os=tty.os, sys=fake_sys,
                                    _limits=Mock(), _exec_private_pty=transfer), \
                     patch.object(Path, "resolve", resolve):
                    with self.assertRaises(RuntimeError) as caught:
                        self.module._main(args)
                self.assertIs(caught.exception, boundary)
                transfer.assert_called_once_with(command, str(session.policy), session.uid, session.gid)
                self.assertEqual(resolved, [session.entry, session.python])
                self.assertFalse(tty.acquired or tty.closed or tty.output)

        expected = {
            "platform": ["platform"], "numeric": ["numeric"],
            "entry": ["entry", "original-suffix"], "policy": ["policy"],
            "original-shape": ["original-shape"], "original-suffix": ["original-suffix"],
            "original-tool-shape": ["original-tool-shape"], "runtime": ["runtime"],
            "runtime-bin": ["runtime"], "runtime-different": ["command"], "flags": ["flags"],
            "command": ["command"], "several": ["original-suffix", "flags", "command"],
        }
        for case, groups in expected.items():
            with self.subTest(rejected_group=case):
                tty = InertTTY()
                command = list(probe)
                if case == "command":
                    command[5] = "--leaf"
                args = ["--enter-private-pty", "darwin", str(session.uid), str(session.gid), "10", str(session.policy), *command]
                if case == "numeric":
                    args[2] = "0" + args[2]  # Same dropped UID, noncanonical entry literal.
                if case == "policy":
                    args[5] = str(session.cleanup_policy)
                original = [framework, "-I", "-S", "-B", str(session.entry), *args]
                flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1,
                                        ignore_environment=1, no_user_site=1, safe_path=True)
                fake_sys = SimpleNamespace(platform="darwin", orig_argv=original,
                                           executable=str(session.python), flags=flags)
                entry = session.entry
                if case == "platform":
                    fake_sys.platform = "not-darwin"
                elif case == "entry":
                    entry = session.bootstrap / "different.py"
                elif case == "original-shape":
                    fake_sys.orig_argv = tuple(original)
                elif case == "original-tool-shape":
                    original[0] = "relative"
                elif case == "runtime":
                    fake_sys.executable = "relative"
                elif case == "runtime-bin":
                    fake_sys.executable = framework
                if case in {"original-suffix", "several"}:
                    original[1] = "-E"
                if case in {"runtime-different", "several"}:
                    fake_sys.executable = "/inert/other/bin/python"
                if case in {"flags", "several"}:
                    flags.no_site = 0
                transfer, resolved = Mock(), []
                def resolve(path, *, strict):
                    self.assertTrue(strict)
                    resolved.append(path)
                    return path
                with patch.multiple(self.module, __file__=str(entry), os=tty.os, sys=fake_sys,
                                    _limits=Mock(), _exec_private_pty=transfer), \
                     patch.object(Path, "resolve", resolve):
                    with self.assertRaises(self.module.SessionError):
                        self.module._main(args)
                transfer.assert_not_called()
                self.assertFalse(tty.acquired or tty.closed)
                note = self.module._private_pty_failure_note(b"".join(tty.output))
                self.assertEqual((note["stage"], note["failed_predicates"], note["cleanup_errors"]), ("entry", groups, 0))
                self.assertEqual(len(resolved), 1 if case == "runtime" else 2)
                self.assertNotIn(b"/inert", b"".join(tty.output))
                self.assertNotIn(b"/private", b"".join(tty.output))

        # Observation and diagnostic errors retain the first actual exception;
        # dependent suffix/command checks are not claimed when resolution failed.
        for diagnostic_error in (False, True):
            tty = InertTTY()
            original_error = OSError(errno.EIO, "synthetic first entry resolution")
            later = OSError(errno.ENOENT, "synthetic later runtime resolution")
            args = ["--enter-private-pty", "darwin", str(session.uid), str(session.gid), "10", str(session.policy), *probe]
            fake_sys = SimpleNamespace(platform="darwin", executable=str(session.python), flags=SimpleNamespace(),
                orig_argv=[framework, "-I", "-S", "-B", str(session.entry), *args])
            def resolve(path, *, strict):
                raise original_error if path == session.entry else later
            if diagnostic_error:
                tty.os.write = Mock(side_effect=OSError(errno.EPIPE, "synthetic diagnostic delivery"))
            transfer = Mock()
            with patch.multiple(self.module, __file__=str(session.entry), os=tty.os, sys=fake_sys,
                                _limits=Mock(), _exec_private_pty=transfer), \
                 patch.object(Path, "resolve", resolve):
                with self.assertRaises(OSError) as caught:
                    self.module._main(args)
            self.assertIs(caught.exception, original_error)
            transfer.assert_not_called()
            self.assertFalse(tty.acquired or tty.closed)
            note = self.module._private_pty_failure_note(b"".join(tty.output))
            if diagnostic_error:
                self.assertIsNone(note)
            else:
                self.assertEqual((note["errno"], note["failed_predicates"], note["argv0_relation"]),
                                 (errno.EIO, ["entry", "runtime", "flags"], "unavailable"))

        tty = InertTTY()
        observed = OSError(errno.EIO, "synthetic runtime observation after boolean rejection")
        args = ["--enter-private-pty", "darwin", str(session.uid), str(session.gid), "10", str(session.policy), *probe]
        flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1,
                                ignore_environment=1, no_user_site=1, safe_path=True)
        fake_sys = SimpleNamespace(platform="darwin", executable=str(session.python), flags=flags,
            orig_argv=[framework, "-E", "-S", "-B", str(session.entry), *args])
        def resolve(path, *, strict):
            if path == session.entry:
                return path
            raise observed
        transfer = Mock()
        with patch.multiple(self.module, __file__=str(session.entry), os=tty.os, sys=fake_sys,
                            _limits=Mock(), _exec_private_pty=transfer), \
             patch.object(Path, "resolve", resolve):
            with self.assertRaises(OSError) as caught:
                self.module._main(args)
        self.assertIs(caught.exception, observed)
        transfer.assert_not_called()
        self.assertFalse(tty.acquired or tty.closed)
        note = self.module._private_pty_failure_note(b"".join(tty.output))
        self.assertEqual((note["errno"], note["failed_predicates"]), (errno.EIO, ["original-suffix", "runtime"]))

    def test_fixture_setup_failure_and_cleanup_errors_do_not_leak_or_rearm(self):
        for fault in ("allocate", "setraw", "attributes", "setattrs", "flush", "blocking:2", "dup:2", "fdopen-r", "fdopen-w"):
            with self.subTest(fault=fault):
                tty = InertTTY(fault=fault)
                fixture = tty.fixture("linux")
                with self.assertRaises(OSError) as caught:
                    with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                        self.fail("failed setup reached body")
                self.assertIs(caught.exception, tty.failure)
                self.assertCountEqual(tty.closed, tty.acquired)
        for fault in ("dup:1", "dup:2", "binding"):
            with self.subTest(private_acquisition=fault):
                tty = InertTTY(ready=True, fault=fault)
                tty.environ[self.module._PRIVATE_PTY_ENV] = tty.binding()
                fixture = tty.fixture()
                fixture["_owner_tty_original"]()
                if fault == "binding":
                    tty.environ[self.module._PRIVATE_PTY_ENV] = tty.binding() + " "
                with self.assertRaises(AssertionError if fault == "binding" else OSError):
                    with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                        self.fail("failed private acquisition reached body")
                self.assertCountEqual(tty.closed, tty.acquired)
                self.assertEqual(tty.live, {41, 42})
                self.assertTrue(fixture["_OWNER_TTY_STATE"]["broken"])
        tty = InertTTY(ready=True)
        tty.environ[self.module._PRIVATE_PTY_ENV] = tty.binding()
        fixture = tty.fixture()
        body, stream, close = RuntimeError("inert body"), OSError("inert stream"), OSError("inert close")
        tty.stream_errors["r"], tty.close_errors[83] = stream, close
        with self.assertRaises(BaseExceptionGroup) as caught:
            with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                raise body
        self.assertEqual(caught.exception.exceptions, (body, stream, close))
        self.assertCountEqual(tty.closed, tty.acquired)
        self.assertEqual(tty.live, {41, 42})
        self.assertTrue(fixture["_OWNER_TTY_STATE"]["broken"])
        with self.assertRaises(AssertionError):
            with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                self.fail("uncertain pair was reused")

    def test_fixture_keeps_real_stream_contract_and_sequential_expected_refusals(self):
        tty = InertTTY(ready=True)
        tty.environ[self.module._PRIVATE_PTY_ENV] = tty.binding()
        fixture = tty.fixture()
        fixture["_owner_tty_original"]()  # Same source function as import-time admission.
        self.assertFalse(any(tty.inherit.values()))
        trace = SimpleNamespace(begin=lambda *_args: {"index": 0}, end=lambda *_args, **_kwargs: None)
        for action in ("wrong", "eof"):
            observations = []
            with fixture["owner_tty"](Path("/inert"), "token", None, trace, action,
                                      input_observations=observations) as (reader, writer):
                self.assertTrue(reader.isatty() and writer.isatty())
                self.assertEqual(writer.write("x" * 129), 129)
                self.assertEqual(reader.readline(100), "wrong\n" if action == "wrong" else "")
                with self.assertRaises(AssertionError):
                    with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                        self.fail("overlapping use was admitted")
            self.assertEqual(observations[0]["read"]["kind"], action)
        for original in (RuntimeError("expected refusal"), KeyboardInterrupt()):
            with self.assertRaises(type(original)) as caught:
                with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                    raise original
            self.assertIs(caught.exception, original)
            self.assertFalse(fixture["_OWNER_TTY_STATE"]["broken"])
        self.assertEqual(tty.live, {41, 42})
        self.assertCountEqual(tty.closed, tty.acquired)
        self.assertEqual(tty.counts["flush"], 4)
        tty.environ.clear()
        with self.assertRaises(AssertionError):
            with fixture["owner_tty"](Path("/inert"), "token", None, None, "none"):
                self.fail("missing capability used a raw PTY fallback")
        self.assertNotIn("allocate", tty.counts)

    def test_failure_note_is_bounded_data_and_cannot_turn_a_capture_into_success(self):
        prefix = self.module._PRIVATE_PTY_PREFIX
        valid = b'{"cleanup_errors":1,"errno":5,"stage":"transfer"}'
        self.assertEqual(self.module._private_pty_failure_note(prefix + valid)["stage"], "transfer")
        for raw in (prefix + valid + b"\n" + prefix + valid, prefix + b"x" * 257,
                    prefix + valid + b"\n" + b"x\n" * 513 + prefix + valid,
                    prefix + valid + b"\n" + b"x" * 65536 + b"\n" + prefix + valid,
                    prefix + valid.replace(b'"transfer"', b'"/private/path"'),
                    prefix + valid.replace(b'"errno":5', b'"errno":true'),
                    prefix + valid.replace(b'"errno":5', b'"errno":4096'),
                    prefix + valid[:-1] + b',"private":"data"}'):
            self.assertIsNone(self.module._private_pty_failure_note(raw))
        session = session_double(self.module, "darwin")
        capture = self.module.CapturedRun(stdout=b"", stderr=prefix + valid, returncode=1,
            waited=True, stdout_eof=True, stderr_eof=True, domain_finality=True, timed_out=False, cancelled=False,
            duration=0.1, primary_error="original failure", cleanup_errors=(), persisted=(0, len(prefix + valid)))
        note = session._note_capture("native-isolation", capture)
        self.assertFalse(note["ok"])
        self.assertEqual(note["private_pty_error"]["errno"], 5)
        self.assertEqual(capture.primary_error, "original failure")
        class HiddenErrno(OSError):
            @property
            def errno(self):
                raise AssertionError("diagnostics invoked an exception property")
        tty = InertTTY()
        with patch.object(self.module, "os", tty.os):
            self.module._private_pty_failure("transfer", HiddenErrno(errno.EIO, "private error"), [])
        self.assertEqual(self.module._private_pty_failure_note(b"".join(tty.output))["errno"], errno.EIO)
        entry = {"stage": "entry", "errno": None, "cleanup_errors": 0,
                 "failed_predicates": list(self.module._PRIVATE_PTY_ENTRY_GROUPS), "argv0_relation": "unavailable"}
        encoded = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.assertLessEqual(len(encoded), 256)
        self.assertEqual(self.module._private_pty_failure_note(prefix + encoded), entry)
        for change in ({"failed_predicates": []}, {"failed_predicates": ["unknown"]},
                       {"failed_predicates": ["flags", "flags"]}, {"failed_predicates": ["flags", "entry"]},
                       {"failed_predicates": "entry"}, {"argv0_relation": "/private/path"},
                       {"argv0_relation": False}, {"cleanup_errors": 1}, {"stage": "allocate"}):
            raw = json.dumps({**entry, **change}, sort_keys=True, separators=(",", ":")).encode("ascii")
            self.assertIsNone(self.module._private_pty_failure_note(prefix + raw))
        self.assertIsNone(self.module._private_pty_failure_note(prefix + valid.replace(b'"transfer"', b'"entry"')))
        self.assertIsNone(self.module._private_pty_failure_note(prefix + encoded + b"\n" + prefix + encoded))
        for relation in self.module._PRIVATE_PTY_ARGV0_RELATIONS:
            tty = InertTTY()
            with patch.object(self.module, "os", tty.os):
                self.module._private_pty_failure("entry", HiddenErrno(errno.EIO, "private error"), [],
                    failed_predicates=["runtime"], argv0_relation=relation)
            note = self.module._private_pty_failure_note(b"".join(tty.output))
            self.assertEqual((note["errno"], note["failed_predicates"], note["argv0_relation"]),
                             (errno.EIO, ["runtime"], relation))
        entry_capture = self.module.CapturedRun(stdout=b"", stderr=prefix + encoded, returncode=1,
            waited=True, stdout_eof=True, stderr_eof=True, domain_finality=True, timed_out=False, cancelled=False,
            duration=0.1, primary_error="entry failure", cleanup_errors=(), persisted=(0, len(prefix + encoded)))
        note = session._note_capture("native-isolation", entry_capture)
        self.assertFalse(note["ok"] or note["subject_ok"])
        self.assertEqual(note["private_pty_error"], entry)
        self.assertEqual(entry_capture.primary_error, "entry failure")
