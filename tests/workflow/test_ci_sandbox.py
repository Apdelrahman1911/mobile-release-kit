"""Pure hosted-owner regressions, not native isolation or process evidence.

Only inert definitions are loaded. Collection uses synthetic paths, in-memory
files, original-child doubles, a bounded fake clock and a fake selector. Neither
Session construction's resource path nor any native entry point is executed.
The helper's OS/process/signal namespaces are replaced, not shared stdlib APIs.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import dataclasses
import functools
import importlib.util
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

    def domain(self, platform, uid):
        if (platform, uid) != (self.session.platform, self.session.uid):
            raise AssertionError("wrong synthetic identity domain")
        self.domain_calls += 1
        self.events.append(("domain", self.domain_calls))
        if self.domain_calls == 1:
            return {}
        if self.cancel_on_finality:
            self.session.cancelled = True
        if self.final_time is not None:
            self.now = self.final_time
        if isinstance(self.final_domain, BaseException):
            raise self.final_domain
        return self.final_domain

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

    def cleanup(self):
        self.events.append(("cleanup",))
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
                                  path=SimpleNamespace(basename=os.path.basename))
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(
                self.module, os=fake_os,
                subprocess=SimpleNamespace(Popen=self.popen, DEVNULL=-3, PIPE=-1),
                selectors=SimpleNamespace(DefaultSelector=self.make_selector, EVENT_READ=1),
                time=SimpleNamespace(monotonic=self.monotonic), signal=SimpleNamespace(),
                _domain=self.domain, _canonical=Path,
                _small_command=Mock(side_effect=AssertionError("native metadata is forbidden")),
                _mac_snapshot=Mock(side_effect=AssertionError("native census is forbidden")),
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

    def test_constructor_rejects_early_guards_before_allocation_or_timer_ownership(self):
        kwargs = dict(platform="linux", root=Path("/tmp/mrk-pure-fixture"),
                      python="/fixture-tools/python/bin/python", ruby="/fixture-tools/ruby/bin/ruby",
                      runner_home="/home/runner", runner_temp="/home/runner/work/_temp",
                      tool_prefixes=("/fixture-tools/python", "/fixture-tools/ruby"), deadline=20.0)
        cases = (
            ({"platform": "darwin"}, 0, (0.0, 0.0)),
            ({}, 1000, (0.0, 0.0)),
            ({"deadline": 0.0}, 0, (0.0, 0.0)),
            ({"deadline": 3301.0}, 0, (0.0, 0.0)),
            ({}, 0, (1.0, 0.0)),
        )
        for changed, euid, timer in cases:
            with self.subTest(changed=changed, euid=euid, timer=timer):
                canonical = Mock(side_effect=AssertionError("resource path must not be entered"))
                fake_signal = SimpleNamespace(ITIMER_REAL=0, getitimer=Mock(return_value=timer),
                                              setitimer=Mock(), signal=Mock())
                with patch.multiple(self.module, _canonical=canonical,
                                    os=SimpleNamespace(geteuid=lambda: euid),
                                    sys=SimpleNamespace(platform="linux"), signal=fake_signal,
                                    time=SimpleNamespace(monotonic=lambda: 0.0)):
                    with self.assertRaises(self.module.SessionError):
                        self.module.Session(**(kwargs | changed))
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
                                              setitimer=Mock(), signal=Mock())
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
        with patch.object(Path, "exists", return_value=True):
            argv, kwargs = session._argv([str(session.python), "--synthetic"], 180)
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
        writable = [tuple(argv[i + 1:i + 3]) for i, a in enumerate(argv) if a == "--bind"]
        self.assertEqual(writable, [(str(session.work), str(session.work))])
        for denied in (session.control, session.runner_home, session.runner_temp):
            self.assertNotIn(str(denied), argv)
        session.runner_home = Path("/opt/runner-private")
        with patch.object(Path, "exists", return_value=True), self.assertRaisesRegex(
            self.module.SessionError, "broad OS bind",
        ):
            session._argv([str(session.python)], 180)

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
                small_command(["/synthetic/metadata"], seconds=1)
        group = caught.exception
        self.assertIs(group.exceptions[0], primary)
        self.assertEqual(len(group.exceptions), 2)
        self.assertIsInstance(group.exceptions[1], OSError)
        self.assertIn(("kill-original",), rig.events)
        self.assertIn(("wait-original", 2), rig.events)
        self.assertIn(("stream-close", 0), rig.events)
        self.assertIn(("stream-close", 1), rig.events)
        self.assertNotIn(("selector-close",), rig.events)
        self.assertEqual(group._ci_observation,
                         {"returncode": -9, "waited": True, "stdout_eof": False,
                          "stderr_eof": False, "stdout_bytes": 0, "stderr_bytes": 0,
                          "error_count": 2, "exceptions": []})
        self.assertEqual(rig.domain_calls, 0)

        many = ExceptionGroup("synthetic-private-group-message", [ValueError(str(primary)) for _ in range(80)])
        with patch.object(self.module, "os", SimpleNamespace(path=SimpleNamespace(basename=os.path.basename))):
            notes = self.module._exception_notes(many)
        self.assertEqual(len(notes), 32)
        self.assertTrue(all(set(n) == {"exception", "lines"} and len(n["lines"]) <= 16 for n in notes))
        self.assertNotIn(str(primary), json.dumps(notes))
        rows = [{"exception": "OSError", "lines": [7, 9], "message": str(primary), "path": "/synthetic/private"},
                {"exception": "Invalid Name", "lines": [7]}, {"exception": "OSError", "lines": [True]},
                {"exception": "OSError", "lines": [0]}, {"exception": "OSError", "lines": list(range(1, 18))}]
        prefix = b"MRK_SANDBOX_ERROR="
        payload = b"untrusted raw diagnostic\n" + prefix + b"not-json\n" + prefix + json.dumps(rows).encode() + b"\n"
        self.assertEqual(self.module._child_exception_notes(payload), [{"exception": "OSError", "lines": [7, 9]}])
        repeated = prefix + json.dumps([rows[0]] * 80).encode() + b"\n"
        self.assertEqual(len(self.module._child_exception_notes(repeated)), 32)
        self.assertEqual(self.module._child_exception_notes(payload + b"x" * 16384), [])

    def test_admission_listener_teardown_attempts_every_owned_close_and_retains_primary(self):
        session = session_double(self.module)
        primary = self.module.SessionError("synthetic admission failure")
        cleanup = {0: OSError("synthetic listener zero close"), 2: OSError("synthetic listener two close")}
        created, closed = [], []

        class Endpoint:
            def __init__(self, role, index):
                self.role, self.index = role, index
                self.address = None

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
                return Endpoint("accepted", self.index), ("synthetic-peer", 1)

            def sendto(self, _data, _address):
                pass

            def recv(self, _size):
                return b"owned-control"

            def close(self):
                closed.append((self.role, self.index))
                if self.role == "listener" and self.index in cleanup:
                    raise cleanup[self.index]

            def __enter__(self):
                return self

            def __exit__(self, *_exception):
                self.close()

        def socket_factory(_family, _kind):
            if len(created) >= 8:
                raise AssertionError("only four synthetic listener/positive pairs are admitted")
            endpoint = Endpoint("listener" if len(created) % 2 == 0 else "positive", len(created) // 2)
            created.append(endpoint)
            return endpoint

        fake_socket = SimpleNamespace(AF_INET=2, AF_INET6=10, SOCK_STREAM=1, SOCK_DGRAM=2, socket=socket_factory)
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
