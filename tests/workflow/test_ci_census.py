"""Pure complete-census and owner-loss regressions, not native finality proof.

The helper is loaded lazily for definitions only. Its paths, clock, metadata
command and OS/process interfaces are replaced in that private module before
any tested body runs. Every apparent /proc entry below is an in-memory lexical
key; no process table, native command, descriptor or Session constructor runs.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import errno
import functools
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
_DEFAULT = object()


@functools.lru_cache(maxsize=1)
def sandbox_module():
    spec = importlib.util.spec_from_file_location(
        "_mrk_pure_ci_census_sandbox", ROOT / ".github/scripts/ci_sandbox.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required hosted-owner helper is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def _stat(tid, birth, state="S"):
    # The final ')' belongs to the nested synthetic command name. Birth is
    # field22, index19 of the suffix beginning with the state field.
    return (f"{tid} (synthetic (nested) task) {state} ".encode()
            + b"0 " * 18 + f"{birth} 0\n".encode())


def _status(uids, gids):
    return (b"Name:\tsynthetic\nUid:\t" + " ".join(map(str, uids)).encode()
            + b"\nGid:\t" + " ".join(map(str, gids)).encode() + b"\n")


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []
        self.after_sleep = lambda: None

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        if not 0 < delay <= 0.05:
            raise AssertionError("unexpected fake census delay")
        self.sleeps.append(delay)
        self.now += delay
        self.after_sleep()


class _ProcPath:
    def __init__(self, tree, path):
        self.tree, self.key = tree, str(PurePosixPath(path))

    @property
    def name(self):
        return PurePosixPath(self.key).name

    def __truediv__(self, component):
        return self.tree.path(PurePosixPath(self.key) / component)

    def iterdir(self):
        return self.tree.iterdir(self.key)

    def read_bytes(self):
        return self.tree.read_bytes(self.key)


class _ProcTree:
    """Finite directory/read protocol; unknown fixture paths are test errors."""

    def __init__(self):
        self.reset({
            (41, 41): ((0, 0, 0, 0), (0, 0, 0, 0), 4101, "S"),
            (42, 42): ((0, 0, 0, 0), (0, 0, 0, 0), 4201, "Z"),
        })
        self.counts = Counter()
        self.events = []
        self.hook = lambda *_: _DEFAULT

    def reset(self, rows):
        self.rows = dict(rows)
        self.pids = sorted({pid for pid, _ in rows})
        self.tids = {pid: sorted(tid for p, tid in rows if p == pid) for pid in self.pids}

    def path(self, value):
        return _ProcPath(self, value)

    def event(self, operation, path):
        self.counts[(operation, path)] += 1
        count = self.counts[(operation, path)]
        self.events.append((operation, path, count))
        return self.hook(operation, path, count)

    def iterdir(self, path):
        if path == "/proc":
            names = [*self.pids, "self", "thread-self"]
        else:
            parts = PurePosixPath(path).parts
            if (len(parts) != 4 or parts[:2] != ("/", "proc")
                    or parts[3] != "task" or not parts[2].isdecimal()
                    or int(parts[2]) not in self.tids):
                raise AssertionError("unknown synthetic census directory")
            names = [*self.tids[int(parts[2])], "nonthread"]
        value = self.event("list", path)
        if value is not _DEFAULT:
            names = value
        return (self.path(PurePosixPath(path) / str(name)) for name in names)

    def read_bytes(self, path):
        parts = PurePosixPath(path).parts
        if (len(parts) != 6 or parts[:2] != ("/", "proc") or parts[3] != "task"
                or not parts[2].isdecimal() or not parts[4].isdecimal()
                or parts[5] not in {"stat", "status"}):
            raise AssertionError("unknown synthetic census metadata path")
        key = (int(parts[2]), int(parts[4]))
        if key not in self.rows:
            raise AssertionError("unknown synthetic census row")
        value = self.event("read", path)
        if value is not _DEFAULT:
            return value
        uids, gids, birth, state = self.rows[key]
        return _stat(key[1], birth, state) if parts[5] == "stat" else _status(uids, gids)


def _fault(operation, path, count, value):
    def hook(actual_operation, actual_path, actual_count):
        if (actual_operation, actual_path, actual_count) == (operation, path, count):
            if isinstance(value, BaseException):
                raise value
            return value
        return _DEFAULT
    return hook


@contextmanager
def _pure(module, tree, clock, **overrides):
    interfaces = {
        "Path": tree.path,
        "time": SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep),
        "os": SimpleNamespace(), "subprocess": SimpleNamespace(),
        "signal": SimpleNamespace(), "socket": SimpleNamespace(),
        "pwd": SimpleNamespace(), "grp": SimpleNamespace(),
        "resource": SimpleNamespace(), "selectors": SimpleNamespace(),
        "_small_command": Mock(side_effect=AssertionError("unexpected metadata command")),
    }
    interfaces.update(overrides)
    with patch.multiple(module, **interfaces):
        yield


def _session(module, cleanup_errors=()):
    session = object.__new__(module.Session)  # No native constructor/timer path.
    session.platform, session.uid, session.deadline = "linux", 60001, 10.0
    session.python = PurePosixPath("/synthetic/tools/python")
    session.entry = PurePosixPath("/synthetic/bootstrap/ci_sandbox.py")
    session.work = PurePosixPath("/synthetic/work")
    session.cleanup_errors, session.admission_results = [], []
    session.domain_finality, session._direct_producer_pending = True, False
    # Initial idle admission is synthetic; only the later census is under test.
    session.ensure_idle = Mock(return_value=None)
    session._argv = Mock(return_value=(["synthetic-subject"], {"user": 60001}))
    # Admission/sysctl ownership is tested separately, never by this fake census.
    session._assert_userns_boundary = Mock(return_value=None)
    session._environment = Mock(return_value={"CI": "true"})
    session._cleanup = Mock(return_value=list(cleanup_errors))
    return session


class CICensusTests(unittest.TestCase):
    def setUp(self):
        self.module = sandbox_module()

    def test_complete_census_includes_every_thread_and_all_credentials(self):
        tree, clock = _ProcTree(), _Clock()
        max_id, max_birth = (1 << 32) - 1, (1 << 64) - 1
        tree.reset({
            (41, 41): ((101, 102, 103, 60001), (201, 202, 203, 60002), 4101, "S"),
            (41, 411): ((301, 302, 60001, 304), (401, 402, 60002, 404), 4111, "R"),
            (42, 42): ((60001,) * 4, (60002,) * 4, 4201, "Z"),
            (43, 43): ((max_id,) * 4, (max_id,) * 4, max_birth, "S"),
            (44, 44): ((0,) * 4, (0,) * 4, 0, "S"),
        })
        with _pure(self.module, tree, clock):
            rows = self.module._linux_snapshot(deadline=10.0)
        self.assertEqual(rows, {
            (41, 41): ((101, 102, 103, 60001), (201, 202, 203, 60002), 4101),
            (41, 411): ((301, 302, 60001, 304), (401, 402, 60002, 404), 4111),
            (42, 42): ((60001,) * 4, (60002,) * 4, 4201),
            (43, 43): ((max_id,) * 4, (max_id,) * 4, max_birth),
            (44, 44): ((0,) * 4, (0,) * 4, 0),
        })
        self.assertEqual(tree.counts[("list", "/proc")], 2)
        for pid, tid in rows:
            self.assertEqual(tree.counts[("list", f"/proc/{pid}/task")], 2)
            self.assertEqual(tree.counts[("read", f"/proc/{pid}/task/{tid}/stat")], 2)
            self.assertEqual(tree.counts[("read", f"/proc/{pid}/task/{tid}/status")], 1)
        self.assertEqual(clock.sleeps, [])

    def test_descendant_enoent_discards_the_entire_strict_pass(self):
        seams = (("list", "/proc/42/task", 1), ("read", "/proc/42/task/42/stat", 1),
                 ("read", "/proc/42/task/42/status", 1), ("read", "/proc/42/task/42/stat", 2),
                 ("list", "/proc/42/task", 2))
        for seam in seams:
            with self.subTest(seam=seam):
                tree, clock = _ProcTree(), _Clock()
                error = FileNotFoundError(errno.ENOENT, "synthetic enumerated entry disappeared")
                tree.hook = _fault(*seam, error)
                with _pure(self.module, tree, clock), patch.object(
                        self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader:
                    with self.assertRaises(self.module._CensusUnstable) as raised:
                        self.module._snapshot("linux", deadline=10.0)
                self.assertIs(raised.exception.__cause__, error)
                reader.assert_called_once_with(deadline=10.0)
                self.assertEqual(tree.counts[("read", "/proc/41/task/41/stat")], 2)
                self.assertEqual(tree.counts[("read", "/proc/41/task/41/status")], 1)
                self.assertEqual(tree.counts[("list", "/proc")], 1)
                self.assertEqual(clock.sleeps, [])

    def test_membership_empty_task_and_valid_birth_churn_are_typed(self):
        cases = (
            ("process-membership", "list", "/proc", 2, [41]),
            ("thread-membership", "list", "/proc/42/task", 2, [42, 422]),
            ("empty-task-set", "list", "/proc/42/task", 1, []),
            ("valid-birth-change", "read", "/proc/42/task/42/stat", 2, _stat(42, 4202)),
        )
        for name, operation, path, count, replacement in cases:
            with self.subTest(case=name):
                tree, clock = _ProcTree(), _Clock()
                tree.hook = _fault(operation, path, count, replacement)
                with _pure(self.module, tree, clock), patch.object(
                        self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader:
                    with self.assertRaises(self.module._CensusUnstable):
                        self.module._snapshot("linux", deadline=10.0)
                reader.assert_called_once_with(deadline=10.0)
                self.assertEqual(tree.counts[("read", "/proc/41/task/41/status")], 1)
                self.assertEqual(clock.sleeps, [])

    def test_unknown_malformed_and_oversized_observations_are_fatal(self):
        def check(name, hook, expected=None):
            with self.subTest(case=name):
                tree, clock = _ProcTree(), _Clock()
                tree.hook = hook
                kind = type(expected) if expected is not None else self.module.SessionError
                with _pure(self.module, tree, clock), patch.object(
                        self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader:
                    with self.assertRaises(kind) as raised:
                        self.module._snapshot("linux", deadline=10.0, retry_churn=True)
                if expected is not None:
                    self.assertIs(raised.exception, expected)
                else:
                    self.assertIs(type(raised.exception), self.module.SessionError)
                self.assertNotIsInstance(raised.exception, self.module._CensusUnstable)
                reader.assert_called_once_with(deadline=10.0)
                self.assertEqual(clock.sleeps, [])

        for count in (1, 2):
            error = FileNotFoundError(errno.ENOENT, "synthetic root inventory unavailable")
            check(f"root-enoent-{count}", _fault("list", "/proc", count, error), error)
        for operation, path, count in (("list", "/proc/42/task", 1),
                                      ("read", "/proc/42/task/42/status", 1),
                                      ("read", "/proc/42/task/42/stat", 2),
                                      ("list", "/proc/42/task", 2)):
            for number in (errno.EACCES, errno.EIO):
                error = OSError(number, "synthetic unreadable metadata")
                check((operation, path, count, number), _fault(operation, path, count, error), error)
        for error in (FileNotFoundError(errno.EIO, "not ENOENT"),
                      FileNotFoundError("no errno is not ENOENT"),
                      RuntimeError("synthetic unknown observation failure"),
                      KeyboardInterrupt("synthetic cancellation")):
            check(type(error).__name__, _fault("read", "/proc/42/task/42/status", 1, error), error)

        good_uid, good_gid = b"Uid:\t0 0 0 0\n", b"Gid:\t0 0 0 0\n"
        invalid_statuses = [good_uid, good_gid, good_uid * 2 + good_gid,
                            good_uid + good_gid * 2]
        for key, other in ((b"Uid", good_gid), (b"Gid", good_uid)):
            invalid_statuses.extend(key + b":\t" + value + b"\n" + other for value in (
                b"", b"0 0 0", b"0 0 0 0 0", b"0 0 unknown 0", b"0 0 -1 0", b"0 0 +1 0",
            ))
        overbound_statuses = []
        for field in ("uid", "gid"):
            for index in range(4):
                values = tuple((1 << 32) if i == index else 0 for i in range(4))
                raw = _status(values, (0,) * 4) if field == "uid" else _status((0,) * 4, values)
                invalid_statuses.append(raw)
                overbound_statuses.append((f"overflow-{field}-{index}", raw))
        for index, raw in enumerate(invalid_statuses):
            check(f"credentials-{index}", _fault("read", "/proc/42/task/42/status", 1, raw))
        for index, (before, after) in enumerate((
                (_stat(42, "unknown"), _stat(42, "unknown")),
                (_stat(42, "unknown"), _stat(42, "different")),
                (_stat(42, "unknown"), _stat(42, 4201)),
                (_stat(42, 4201), _stat(42, "unknown")),
                (_stat(42, -1), _stat(42, 4201)),
                (_stat(42, 4201), _stat(42, "+1")),
                (_stat(42, 1 << 64), _stat(42, 4201)),
                (_stat(42, 4201), _stat(42, 1 << 64)),
                (_stat(42, 1 << 64), _stat(42, 1 << 64)),
                (_stat(42, 1 << 64), _stat(42, (1 << 64) + 1)),
                (b"42 no final command marker\n", _stat(42, 4201)),
                (_stat(42, 4201), b"42 (synthetic) S 0\n"))):
            def birth_hook(operation, path, count, pair=(before, after)):
                return pair[count - 1] if (operation, path) == ("read", "/proc/42/task/42/stat") else _DEFAULT
            check(f"malformed-birth-{index}", birth_hook)

        for label, raw in [("missing-gid", good_uid), *overbound_statuses]:
            def malformed_credentials_and_changed_birth(operation, path, count, status=raw):
                if (operation, path) == ("read", "/proc/42/task/42/status"):
                    return status  # Invalid credentials cannot be recast as valid identity churn.
                if (operation, path, count) == ("read", "/proc/42/task/42/stat", 2):
                    return _stat(42, 4202)
                return _DEFAULT

            check((label, "before-valid-birth-change"), malformed_credentials_and_changed_birth)
        for path, count in (("/proc/42/task/42/stat", 1), ("/proc/42/task/42/stat", 2),
                            ("/proc/42/task/42/status", 1)):
            check(("metadata-size", path, count), _fault("read", path, count, b"x" * 65537))
        check("process-count", _fault("list", "/proc", 1, range(1, 32770)))
        # PID41's already observed row plus 131072 more threads exceeds the
        # aggregate bound even though this single task directory does not.
        check("aggregate-thread-count", _fault("list", "/proc/42/task", 1, range(1, 131073)))

    def test_finality_retry_restarts_from_a_fresh_complete_root(self):
        tree, clock = _ProcTree(), _Clock()

        def disappear(operation, path, count):
            if (operation, path, count) == ("list", "/proc/42/task", 1):
                tree.reset({(43, 43): ((7, 8, 9, 10), (11, 12, 13, 14), 4301, "S")})
                raise FileNotFoundError(errno.ENOENT, "synthetic first-pass churn")
            return _DEFAULT

        tree.hook = disappear
        with _pure(self.module, tree, clock), patch.object(
                self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader:
            rows = self.module._snapshot("linux", deadline=5.0, retry_churn=True)
        self.assertEqual(rows, {(43, 43): ((7, 8, 9, 10), (11, 12, 13, 14), 4301)})
        self.assertEqual(tree.counts[("read", "/proc/41/task/41/status")], 1)
        self.assertEqual(tree.counts[("read", "/proc/43/task/43/status")], 1)
        self.assertEqual(tree.counts[("list", "/proc")], 3)
        self.assertEqual([call.kwargs for call in reader.call_args_list], [{"deadline": 5.0}] * 2)
        self.assertEqual(clock.sleeps, [0.01])

    def test_finality_retry_has_eight_attempts_and_one_absolute_deadline(self):
        for succeeds in (True, False):
            with self.subTest(eighth_attempt_succeeds=succeeds):
                tree, clock = _ProcTree(), _Clock()
                failures = [self.module._CensusUnstable(f"synthetic unstable pass {i}") for i in range(8)]
                rows = {(41, 41): ((0,) * 4, (0,) * 4, 4101)}
                reader = Mock(side_effect=failures[:7] + ([rows] if succeeds else failures[7:]))
                with _pure(self.module, tree, clock, _linux_snapshot=reader):
                    if succeeds:
                        self.assertIs(self.module._snapshot("linux", deadline=10.0, retry_churn=True), rows)
                    else:
                        with self.assertRaises(self.module._CensusUnstable) as raised:
                            self.module._snapshot("linux", deadline=10.0, retry_churn=True)
                        self.assertIs(raised.exception, failures[-1])
                self.assertEqual([call.kwargs for call in reader.call_args_list], [{"deadline": 10.0}] * 8)
                self.assertEqual(clock.sleeps, [0.01] * 7)

        for phase in ("already-expired", "metadata-read", "root-recheck", "backoff", "returned-late"):
            with self.subTest(deadline_phase=phase):
                tree, clock = _ProcTree(), _Clock()
                cutoff = 0.005 if phase == "backoff" else 1.0
                original = self.module._linux_snapshot

                def read(*, deadline):
                    if phase == "backoff":
                        raise self.module._CensusUnstable("synthetic bounded backoff")
                    if phase == "returned-late":
                        clock.now = deadline
                        return {}
                    return original(deadline=deadline)

                def expire(operation, path, count):
                    if ((phase == "metadata-read" and (operation, path) == ("read", "/proc/42/task/42/status"))
                            or (phase == "root-recheck" and (operation, path, count) == ("list", "/proc", 2))):
                        clock.now = cutoff
                    return _DEFAULT

                tree.hook = expire
                if phase == "already-expired":
                    clock.now = cutoff
                reader = Mock(side_effect=read)
                with _pure(self.module, tree, clock, _linux_snapshot=reader):
                    with self.assertRaises(self.module.DeadlineExpired):
                        self.module._snapshot("linux", deadline=cutoff, retry_churn=True)
                count = 0 if phase == "already-expired" else 1
                self.assertEqual([call.kwargs for call in reader.call_args_list], [{"deadline": cutoff}] * count)
                self.assertEqual(clock.sleeps, [cutoff] if phase == "backoff" else [])

        tree, clock = _ProcTree(), _Clock()
        fatal = OSError(errno.EIO, "synthetic fatal observation after one transient")
        reader = Mock(side_effect=[self.module._CensusUnstable("transient"), fatal, {}])
        with _pure(self.module, tree, clock, _linux_snapshot=reader):
            with self.assertRaises(OSError) as raised:
                self.module._snapshot("linux", deadline=10.0, retry_churn=True)
        self.assertIs(raised.exception, fatal)
        self.assertEqual(reader.call_count, 2)
        self.assertEqual(clock.sleeps, [0.01])

        for cutoff in (None, float("inf"), float("-inf"), float("nan"), True, "10"):
            with self.subTest(invalid_deadline=cutoff):
                tree, clock, reader = _ProcTree(), _Clock(), Mock(return_value={})
                with _pure(self.module, tree, clock, _linux_snapshot=reader):
                    with self.assertRaises(self.module.SessionError):
                        self.module._snapshot("linux", deadline=cutoff, retry_churn=True)
                reader.assert_not_called()
                self.assertEqual(tree.events, [])
                self.assertEqual(clock.sleeps, [])

        for result in ({(41, 41): ((0,) * 3, (0,) * 3, 4096)}, self.module._CensusUnstable("not a Darwin retry")):
            with self.subTest(darwin_result=type(result).__name__):
                tree, clock, linux = _ProcTree(), _Clock(), Mock()
                mac = Mock(side_effect=result) if isinstance(result, BaseException) else Mock(return_value=result)
                with _pure(self.module, tree, clock, _linux_snapshot=linux, _mac_snapshot=mac):
                    if isinstance(result, BaseException):
                        with self.assertRaises(self.module._CensusUnstable) as raised:
                            self.module._snapshot("darwin", deadline=10.0, retry_churn=True)
                        self.assertIs(raised.exception, result)
                    else:
                        self.assertIs(self.module._snapshot("darwin", deadline=10.0, retry_churn=True), result)
                mac.assert_called_once_with(deadline=10.0)
                linux.assert_not_called()
                self.assertEqual(clock.sleeps, [])

    def test_collision_is_strict_and_finality_unions_two_complete_passes(self):
        tree, clock, uid = _ProcTree(), _Clock(), 60001
        tree.rows[(41, 41)] = ((0, 0, 0, uid), (0,) * 4, 4101, "Z")

        def collision_churn(operation, path, count):
            if (operation, path, count) == ("list", "/proc/42/task", 1):
                tree.reset({})  # A hypothetical retry would erase the observed collision.
                raise FileNotFoundError(errno.ENOENT, "synthetic collision-view churn")
            return _DEFAULT

        tree.hook = collision_churn
        with _pure(self.module, tree, clock), patch.object(
                self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader, patch.object(
                self.module, "_snapshot", wraps=self.module._snapshot) as router:
            with self.assertRaises(self.module._CensusUnstable):
                self.module._domain("linux", uid, collision=True, deadline=10.0)
        reader.assert_called_once_with(deadline=10.0)
        router.assert_called_once_with("linux", deadline=10.0, retry_churn=False)
        self.assertEqual(tree.counts[("read", "/proc/41/task/41/status")], 1)
        self.assertEqual(clock.sleeps, [])

        tree, clock = _ProcTree(), _Clock()
        positive = {(41, 411): ((0, 0, 0, uid), (0,) * 4, 4111)}
        reader = Mock(side_effect=[self.module._CensusUnstable("transient"), positive, {}])
        with _pure(self.module, tree, clock, _linux_snapshot=reader), patch.object(
                self.module, "_snapshot", wraps=self.module._snapshot) as router:
            self.assertEqual(self.module._domain("linux", uid, deadline=10.0), {41})
        self.assertEqual([call.kwargs for call in reader.call_args_list], [{"deadline": 10.0}] * 3)
        self.assertEqual([call.kwargs for call in router.call_args_list],
                         [{"deadline": 10.0, "retry_churn": True}] * 2)
        self.assertEqual(clock.sleeps, [0.01])

        for collision in (False, True):
            with self.subTest(all_credential_positions=collision):
                tree, clock, rows = _ProcTree(), _Clock(), {}
                for index in range(4):
                    ids = tuple(uid if i == index else 0 for i in range(4))
                    rows[(100 + index, 100 + index)] = (ids, (0,) * 4, 1000 + index, "Z")
                    rows[(200 + index, 200 + index)] = ((0,) * 4, ids, 2000 + index, "S")
                rows[(300, 300)] = ((0,) * 4, (0,) * 4, 3000, "S")
                rows[(300, 301)] = ((0, 0, 0, uid), (0,) * 4, 3001, "Z")
                tree.reset(rows)
                with _pure(self.module, tree, clock), patch.object(
                        self.module, "_snapshot", wraps=self.module._snapshot) as router:
                    observed = self.module._domain("linux", uid, collision=collision, deadline=10.0)
                expected = {100, 101, 102, 103, 300} | ({200, 201, 202, 203} if collision else set())
                self.assertEqual(observed, expected)
                self.assertEqual(tree.counts[("list", "/proc")], 4)
                self.assertEqual([call.kwargs for call in router.call_args_list],
                                 [{"deadline": 10.0, "retry_churn": not collision}] * 2)
                self.assertEqual(clock.sleeps, [])

    def test_owner_loss_preserves_cleanup_errors_and_requires_finality(self):
        expected_row = {"name": "supervisor-loss", "ok": True, "subject_owner_exit": 23,
                        "subject_child_wait": "unavailable", "outer_domain_finality": True}
        for case in ("empty", "transient-then-empty", "child-then-empty", "uid-then-empty"):
            with self.subTest(success_case=case):
                tree, clock, session = _ProcTree(), _Clock(), _session(self.module)
                tree.reset({})
                if case == "transient-then-empty":
                    tree.reset({(41, 41): ((0,) * 4, (0,) * 4, 4101, "S")})

                    def churn(operation, path, count):
                        if (operation, path, count) == ("list", "/proc/41/task", 1):
                            tree.reset({})
                            raise FileNotFoundError(errno.ENOENT, "synthetic owner-loss census churn")
                        return _DEFAULT

                    tree.hook = churn
                elif case in {"child-then-empty", "uid-then-empty"}:
                    pid = 4242 if case == "child-then-empty" else 43
                    uids = (0,) * 4 if case == "child-then-empty" else (0, 0, 0, session.uid)
                    tree.reset({(pid, pid): (uids, (0,) * 4, 7001, "Z")})
                    clock.after_sleep = lambda: tree.reset({})
                command = Mock(return_value=b"MRK_OWNER_LOST 4242\n")
                with _pure(self.module, tree, clock, _small_command=command), patch.object(
                        self.module, "_snapshot", wraps=self.module._snapshot) as router, patch.object(
                        self.module, "_domain", wraps=self.module._domain) as domain:
                    session._owner_loss_preflight()
                self.assertEqual(session.admission_results, [expected_row])
                self.assertEqual(session.cleanup_errors, [])
                session.ensure_idle.assert_called_once_with()
                session._cleanup.assert_called_once_with()
                session._argv.assert_called_once_with(
                    [str(session.python), "-I", "-S", "-B", str(session.entry), "--loss-subject"], 10,
                )
                session._assert_userns_boundary.assert_called_once_with()
                session._environment.assert_called_once_with({})
                command.assert_called_once()
                self.assertEqual(command.call_args.kwargs, {"expected_code": 23, "deadline": 10.0})
                argv, seconds = command.call_args.args
                self.assertEqual(seconds, 10)
                self.assertEqual(argv[:-1], [str(session.python), "-I", "-S", "-B",
                                            str(session.entry), "--loss-owner"])
                self.assertEqual(json.loads(argv[-1]), {"command": ["synthetic-subject"],
                    "kwargs": {"user": 60001}, "cwd": str(session.work), "env": {"CI": "true"}})
                self.assertTrue(router.call_args_list)
                self.assertTrue(all(call.kwargs == {"deadline": 5.0, "retry_churn": True}
                                    for call in router.call_args_list))
                self.assertEqual(domain.call_count, 2 if case == "uid-then-empty" else 1)
                self.assertEqual(clock.sleeps, [0.01] if case == "transient-then-empty" else
                                 [0.05] if case in {"child-then-empty", "uid-then-empty"} else [])

        cleanup = ("synthetic first cleanup error", "synthetic second cleanup error")
        timeout_note = "lost-owner platform cleanup remained unknown or incomplete"
        for case in ("census-error", "eventually-empty", "timeout"):
            with self.subTest(cleanup_error_case=case):
                tree, clock, session = _ProcTree(), _Clock(), _session(self.module, cleanup)
                session.cleanup_errors.append("preexisting cleanup evidence")
                retained = ["preexisting cleanup evidence", *cleanup]
                tree.reset({} if case != "timeout" else {
                    (4242, 4242): ((0,) * 4, (0,) * 4, 7001, "Z"),
                })
                if case == "timeout":
                    session.deadline = 0.12
                error = OSError(errno.EIO, "synthetic late census failure")

                def observe(operation, path, count):
                    self.assertEqual(session.cleanup_errors, retained)  # Retention must precede census.
                    if case == "census-error":
                        raise error
                    return _DEFAULT

                tree.hook = observe
                command = Mock(return_value=b"MRK_OWNER_LOST 4242\n")
                kind = OSError if case == "census-error" else self.module.SessionError
                with _pure(self.module, tree, clock, _small_command=command):
                    with self.assertRaises(kind) as raised:
                        session._owner_loss_preflight()
                if case == "census-error":
                    self.assertIs(raised.exception, error)
                else:
                    self.assertEqual(str(raised.exception), "lost-owner native admission cleanup failed")
                self.assertEqual(session.cleanup_errors, retained + ([timeout_note] if case == "timeout" else []))
                self.assertEqual(session.admission_results, [])
                session.ensure_idle.assert_called_once_with()
                session._assert_userns_boundary.assert_called_once_with()
                session._cleanup.assert_called_once_with()
                self.assertGreater(tree.counts[("list", "/proc")], 0)
                if case == "timeout":
                    self.assertEqual(clock.now, session.deadline)
                    self.assertEqual(len(clock.sleeps), 3)

        tree, clock, session = _ProcTree(), _Clock(), _session(self.module)

        def persistent_churn(operation, path, count):
            if (operation, path) == ("list", "/proc/41/task"):
                raise FileNotFoundError(errno.ENOENT, "synthetic persistent owner-loss churn")
            return _DEFAULT

        tree.hook = persistent_churn
        with _pure(self.module, tree, clock, _small_command=Mock(return_value=b"MRK_OWNER_LOST 4242\n")), patch.object(
                self.module, "_linux_snapshot", wraps=self.module._linux_snapshot) as reader:
            with self.assertRaises(self.module._CensusUnstable):
                session._owner_loss_preflight()
        self.assertEqual(session.admission_results, [])
        session.ensure_idle.assert_called_once_with()
        session._assert_userns_boundary.assert_called_once_with()
        self.assertEqual([call.kwargs for call in reader.call_args_list], [{"deadline": 5.0}] * 8)
        self.assertEqual(clock.sleeps, [0.01] * 7)

        for raw in (b"", b"MRK_OWNER_LOST", b"NOT_OWNER_LOST 4242", b"MRK_OWNER_LOST unknown",
                    b"MRK_OWNER_LOST -1", b"MRK_OWNER_LOST 4242 extra"):
            with self.subTest(invalid_footer=raw):
                tree, clock, session = _ProcTree(), _Clock(), _session(self.module)
                with _pure(self.module, tree, clock, _small_command=Mock(return_value=raw)), patch.object(
                        self.module, "_snapshot", wraps=self.module._snapshot) as router:
                    with self.assertRaises(self.module.SessionError):
                        session._owner_loss_preflight()
                session.ensure_idle.assert_called_once_with()
                session._assert_userns_boundary.assert_called_once_with()
                session._cleanup.assert_not_called()
                router.assert_not_called()
                self.assertEqual(tree.events, [])
                self.assertEqual(session.admission_results, [])
                self.assertEqual(clock.sleeps, [])
