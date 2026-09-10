"""Inert storage-profile and callback contracts, not native mount evidence.

Only reviewed helper definitions are loaded lazily. Every project filesystem,
resource, clock and process seam is replaced with the private in-memory fixture.
The only executed test suite inside these tests has three locally defined inert
methods; discovery never imports product tests, helpers or native entry points.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import errno
import functools
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
_DEFAULT = object()
_USERNS = "/proc/sys/user/max_user_namespaces"
_MOUNTINFO = "/proc/self/mountinfo"


@functools.lru_cache(maxsize=2)
def helper_module(name):
    if name not in {"ci_checks", "verify_ci"}:
        raise AssertionError("unsupported inert helper")
    spec = importlib.util.spec_from_file_location(
        "_mrk_python_profile_" + name, ROOT / ".github/scripts" / (name + ".py"),
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required reviewed helper is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


class _Path:
    def __init__(self, fixture, value):
        self.fixture, self.value = fixture, PurePosixPath(value)

    def __str__(self):
        return str(self.value)

    def __fspath__(self):
        return str(self)

    def __truediv__(self, part):
        return self.fixture.path(self.value / part)

    def __eq__(self, other):
        try:
            return self.value == PurePosixPath(other)
        except TypeError:
            return False

    def __hash__(self):
        return hash(self.value)

    @property
    def parent(self):
        return self.fixture.path(self.value.parent)

    @property
    def name(self):
        return self.value.name

    @property
    def parts(self):
        return self.value.parts

    def is_absolute(self):
        return self.value.is_absolute()

    def is_relative_to(self, other):
        return self.value.is_relative_to(PurePosixPath(other))

    def relative_to(self, other):
        return self.fixture.path(self.value.relative_to(PurePosixPath(other)))

    def as_posix(self):
        return self.value.as_posix()

    def resolve(self, *, strict=False):
        self.fixture.event("resolve", str(self), strict)
        return self.fixture.path(self.fixture.aliases.get(str(self), str(self)))

    def is_dir(self):
        node = self.fixture.nodes.get(str(self))
        return node is not None and stat.S_ISDIR(node.st_mode)


class _Entries:
    def __init__(self, fixture, path, names):
        self.fixture, self.path, self.names = fixture, path, iter(names)
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        self.fixture.event("scan-next", self.path, None)
        return SimpleNamespace(name=next(self.names))

    def close(self):
        if self.closed:
            raise AssertionError("fake directory iterator closed twice")
        self.closed = True
        self.fixture.event("scan-close", self.path, None)


class _Profile:
    """Synthetic descriptors retain objects; pathname replacement is separate."""

    def __init__(self):
        self.uid = self.euid = self.gid = self.egid = 60001
        self.groups, self.now, self.platform = [], 1.0, "linux"
        self.nodes, self.fds, self.filesystems, self.aliases = {}, {}, {}, {}
        self.events, self.created, self.removed = [], [], []
        self.close_calls, self.counts, self.next_fd = Counter(), Counter(), 20
        self.hook = lambda *_: _DEFAULT
        self.allow_readonly_create, self.enforce_capacity = False, True
        self.mount_override, self.userns = None, b"0\n"
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.work = self.path("/synthetic/session/work")
        self.checks, self.source = self.work / "checks", self.path("/synthetic/source")
        self.limits = {"FSIZE": ((1 << 32) + 1024**2,) * 2, "CORE": (0, 0),
                       "NOFILE": (1024, 1024), "NPROC": (256, 256), "CPU": (300, 300),
                       "AS": (4 * 1024**3,) * 2}
        self.mounts = [{"path": "/", "device": "0:1", "root": "/", "options": "rw",
                        "filesystem": "tmpfs", "super": "rw"},
                       {"path": str(self.work), "device": "9:9", "root": "/fixture-work", "options": "ro",
                        "filesystem": "ext4", "super": "rw"}]
        self.add_directory(str(self.source), 0o755, uid=0, gid=0, device=1, readonly=True)
        self.add_directory(str(self.work), 0o755, uid=0, gid=0, device=99, readonly=True)
        self.add_directory(str(self.work / "wheels"), 0o700, uid=self.uid, gid=self.gid, device=99, readonly=True)
        work_leaves = [("tmp", 640 * 1024**2)] + [(name, 16 * 1024**2) for name in
            ("home", "config", "cache", "gem-cache", "bundle-config", "bundle-home", "checks")]
        self.quotas = [(str(self.work / name), size) for name, size in work_leaves]
        self.quotas += [("/tmp", 128 * 1024**2), ("/run", 16 * 1024**2), ("/dev/shm", 16 * 1024**2)]
        for index, (path, size) in enumerate(self.quotas, 100):
            self.add_directory(path, 0o1777, uid=0, gid=0, device=index, capacity=size)
            self.mounts.append({"path": path, "device": f"0:{index}", "root": "/", "options": "rw,nosuid,nodev",
                                "filesystem": "tmpfs", "super": f"rw,size={size // 1024}k"})
        self.add_file(_MOUNTINFO, uid=self.uid, gid=self.gid, mode=0o444, device=2)
        self.add_file(_USERNS, uid=0, gid=0, mode=0o644, device=2)

    def path(self, value):
        return _Path(self, value)

    def add_directory(self, path, mode, *, uid, gid, device, readonly=False, capacity=1024**3):
        self.filesystems.setdefault(device, {"capacity": capacity, "used": 0, "readonly": readonly, "overrides": {}})
        self.nodes[path] = SimpleNamespace(st_dev=device, st_ino=len(self.nodes) + 1000,
            st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid, st_nlink=2, st_size=0)

    def add_file(self, path, *, uid, gid, mode=0o600, device=99):
        self.nodes[path] = SimpleNamespace(st_dev=device, st_ino=len(self.nodes) + 10000,
            st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid, st_nlink=1, st_size=0)
        return self.nodes[path]

    def event(self, operation, path, detail):
        self.events.append((operation, path, detail))
        self.counts[(operation, path)] += 1
        return self.hook(operation, path, detail)

    def name(self, value, dir_fd=None):
        path = PurePosixPath(value)
        if not path.is_absolute():
            if dir_fd not in self.fds or not stat.S_ISDIR(self.fds[dir_fd]["node"].st_mode) or len(path.parts) != 1:
                raise AssertionError("relative fake operation lacks its retained directory")
            path = PurePosixPath(self.fds[dir_fd]["path"]) / path
        if ".." in path.parts:
            raise AssertionError("unexpected fixture traversal")
        return str(path)

    def mount_bytes(self):
        if self.mount_override is not None:
            return self.mount_override
        return b"".join(f"{index} 1 {row['device']} {row['root']} {row['path']} {row['options']} - "
                        f"{row['filesystem']} synthetic {row['super']}\n".encode()
                        for index, row in enumerate(self.mounts, 1))

    def open(self, value, flags, mode=0o777, *, dir_fd=None):
        path = self.name(value, dir_fd)
        self.event("open", path, flags)
        if flags & os.O_CREAT:
            if not flags & os.O_EXCL or mode != 0o600 or dir_fd is None:
                raise AssertionError("control must be exclusive descriptor-relative0600 creation")
            if path in self.nodes:
                raise FileExistsError(errno.EEXIST, "synthetic existing control")
            parent = self.fds[dir_fd]["node"]
            if self.filesystems[parent.st_dev]["readonly"] and not self.allow_readonly_create:
                raise OSError(errno.EROFS, "synthetic readonly work")
            self.add_file(path, uid=self.uid, gid=self.gid, device=parent.st_dev)
            self.created.append(path)
            self.event("created", path, None)  # May fail after creation but before a returned FD.
        elif path not in self.nodes:
            raise AssertionError("unknown synthetic profile path")
        node = self.nodes[path]
        if bool(flags & os.O_DIRECTORY) != stat.S_ISDIR(node.st_mode):
            raise AssertionError("synthetic open kind differs from its requested role")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        data = self.mount_bytes() if path == _MOUNTINFO else self.userns if path == _USERNS else b""
        self.fds[fd] = {"path": path, "node": node, "data": data, "position": 0}
        return fd

    def fstat(self, fd):
        row = self.fds[fd]
        self.event("fstat", row["path"], fd)
        return SimpleNamespace(**vars(row["node"]))

    def stat(self, value, *, dir_fd=None, follow_symlinks=True):
        if follow_symlinks:
            raise AssertionError("profile observation must not follow a mutable name")
        path = self.name(value, dir_fd)
        self.event("stat", path, dir_fd)
        if path not in self.nodes:
            if ".mrk-python-profile-" not in path:
                raise AssertionError("unknown synthetic stat path")
            raise FileNotFoundError(errno.ENOENT, "synthetic removed control")
        return SimpleNamespace(**vars(self.nodes[path]))

    def read(self, fd, count):
        row = self.fds[fd]
        value = self.event("read", row["path"], count)
        if value is not _DEFAULT:
            return value
        start = row["position"]
        block = row["data"][start:start + count]
        row["position"] += len(block)
        return block

    def write(self, fd, data):
        row = self.fds[fd]
        value = self.event("write", row["path"], len(data))
        if value is not _DEFAULT:
            return value
        node, filesystem = row["node"], self.filesystems[row["node"].st_dev]
        allocated = ((node.st_size + 4095) // 4096) * 4096
        available = filesystem["capacity"] - filesystem["used"] + allocated - node.st_size
        if self.enforce_capacity and available <= 0:
            raise OSError(errno.ENOSPC, "synthetic tmpfs capacity")
        count = min(len(data), available) if self.enforce_capacity else len(data)
        node.st_size += count
        filesystem["used"] += ((node.st_size + 4095) // 4096) * 4096 - allocated
        return count

    def fsync(self, fd):
        self.event("fsync", self.fds[fd]["path"], fd)

    def close(self, fd):
        self.close_calls[fd] += 1
        row = self.fds.pop(fd)  # An injected failure is deliberately ambiguous after effect.
        self.event("close", row["path"], fd)

    def unlink(self, value, *, dir_fd=None):
        path = self.name(value, dir_fd)
        self.event("unlink", path, dir_fd)
        node = self.nodes.pop(path)
        self.filesystems[node.st_dev]["used"] -= ((node.st_size + 4095) // 4096) * 4096
        self.removed.append(path)
        self.event("unlinked", path, dir_fd)

    def fstatvfs(self, fd):
        row = self.fds[fd]
        self.event("statvfs", row["path"], fd)
        filesystem = self.filesystems[row["node"].st_dev]
        values = {"f_flag": os.ST_RDONLY if filesystem["readonly"] else 0, "f_frsize": 4096,
                  "f_blocks": filesystem["capacity"] // 4096,
                  "f_bavail": (filesystem["capacity"] - filesystem["used"]) // 4096}
        return SimpleNamespace(**{**values, **filesystem["overrides"]})

    def scandir(self, fd):
        path = self.fds[fd]["path"]
        self.event("scandir", path, fd)
        names = [PurePosixPath(name).name for name in self.nodes if PurePosixPath(name).parent == PurePosixPath(path)]
        return _Entries(self, path, names)

    def getrlimit(self, which):
        self.event("getrlimit", which, None)
        return self.limits[which]


@contextmanager
def _pure(module, fixture, **overrides):
    flags = {name: getattr(os, name) for name in
             ("O_RDONLY", "O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY", "ST_RDONLY")}
    system = SimpleNamespace(**flags, open=fixture.open, fstat=fixture.fstat, stat=fixture.stat,
        read=fixture.read, write=fixture.write, fsync=fixture.fsync, close=fixture.close,
        unlink=fixture.unlink, fstatvfs=fixture.fstatvfs, scandir=fixture.scandir,
        getuid=lambda: fixture.uid, geteuid=lambda: fixture.euid, getgid=lambda: fixture.gid,
        getegid=lambda: fixture.egid, getgroups=lambda: list(fixture.groups),
        environ={"MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS": "1"},
        umask=lambda value: fixture.event("umask", "fixed", value),
        chdir=lambda value: fixture.event("chdir", str(value), None))
    limits = SimpleNamespace(**{"RLIMIT_" + name: name for name in fixture.limits}, getrlimit=fixture.getrlimit)
    framework = SimpleNamespace(TestSuite=unittest.TestSuite, TextTestResult=unittest.TextTestResult,
        TextTestRunner=unittest.TextTestRunner, TestLoader=Mock(side_effect=AssertionError("unexpected discovery")))
    values = {"os": system, "resource": limits, "Path": fixture.path,
        "time": SimpleNamespace(monotonic=lambda: fixture.now),
        "sys": SimpleNamespace(platform=fixture.platform, stdout=fixture.stdout, stderr=fixture.stderr,
            exc_info=sys.exc_info, flags=SimpleNamespace(isolated=1, dont_write_bytecode=1)),
        "subprocess": SimpleNamespace(), "selectors": SimpleNamespace(), "shutil": SimpleNamespace(),
        "importlib": SimpleNamespace(), "unittest": framework,
        "expected_python_ids": Mock(side_effect=AssertionError("unexpected inventory")),
        "inspect_installed_wheel": Mock(side_effect=AssertionError("unexpected installed-product inspection")),
        "traceback": SimpleNamespace(extract_tb=lambda _tb: [SimpleNamespace(
            filename=str(fixture.source / "tests/fixed_fixture.py"), lineno=7)])}
    values.update(overrides)
    with patch.multiple(module, **values):
        yield framework


def _profile_details():
    # Expected fixture contract only; this function is not substituted for the
    # actual entry control in tests that claim profile-body coverage.
    return {"name": "linux-python-full-v1", "logical_file_bytes": (1 << 32) + 1024**2,
            "file_data_bytes": 912 * 1024**2, "tmpfs_mounts": 11, "write_controls": 11,
            "readonly_errno": errno.EROFS, "capacity_errno": errno.ENOSPC,
            "capacity_bytes": 16 * 1024**2, "max_user_namespaces": 0}


def _inert_suite(events, *, outcome="os-error", callback_count=1):
    class Fixture(unittest.TestCase):
        def test_01_ok(self):
            events.append("first")

        def test_02_callback(self):
            events.append("second")
            if outcome == "os-error":
                with self.subTest(private="PRIVATE_SUBTEST_PARAMETER"):
                    raise OSError(errno.EFBIG, "PRIVATE_EXCEPTION_MESSAGE", "/PRIVATE_FILENAME")
            elif outcome == "skip":
                self.skipTest("PRIVATE_SKIP_REASON")
            elif outcome == "failure":
                self.fail("PRIVATE_ASSERTION_MESSAGE")

        def test_03_not_run_after_failure(self):
            events.append("third")

    Fixture.__module__, Fixture.__qualname__ = "unit.fixed_fixture", "Fixture"
    names = ("test_01_ok", "test_02_callback", "test_03_not_run_after_failure")
    if callback_count != 1:
        def run(self, result=None):
            result.startTest(self)
            try:
                for _ in range(callback_count):
                    try:
                        raise OSError(errno.EIO, "PRIVATE_REPEATED_CALLBACK")
                    except OSError:
                        result.addError(self, sys.exc_info())
            finally:
                result.stopTest(self)
            return result
        Fixture.run = run
        names = names[:1]
    suite = unittest.TestSuite(Fixture(name) for name in names)
    expected = tuple(sorted(test.id() for test in suite))
    return suite, expected


class CIPythonProfileTests(unittest.TestCase):
    def setUp(self):
        self.module = helper_module("ci_checks")

    def test_complete_profile_checks_fixed_views_and_removes_only_owned_controls(self):
        fixture = _Profile()
        with _pure(self.module, fixture):
            details = self.module._python_full_profile(fixture.checks, deadline=10.0)
        self.assertEqual(details, _profile_details())
        self.assertEqual(len(fixture.created), 12)  # Eleven positives and one capacity control; RO created nothing.
        self.assertEqual(sorted(fixture.created), sorted(fixture.removed))
        self.assertEqual(fixture.fds, {})
        self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))
        self.assertTrue(all(state["used"] == 0 for state in fixture.filesystems.values()))
        self.assertEqual(fixture.counts[("open", _USERNS)], 2)
        self.assertEqual(fixture.counts[("open", _MOUNTINFO)], 2)
        reads = [size for operation, path, size in fixture.events if operation == "read" and path == _USERNS]
        self.assertEqual(reads, [33, 1, 33, 1])
        capacity = str(fixture.checks / ".mrk-python-profile-capacity")
        self.assertEqual(fixture.counts[("write", capacity)], 257)
        first_create = next(i for i, event in enumerate(fixture.events) if event[0] == "created")
        self.assertEqual(sum(event[0] == "statvfs" for event in fixture.events[:first_create]), 13)

    def test_identity_limits_and_mount_contract_fail_before_any_control_creation(self):
        cases = ("wrong-platform", "root", "saved-identity", "extra-group", "work-shape", "work-alias",
                 "old-fsize", "soft-fsize", "cpu", "address-space", "userns-enabled", "userns-malformed",
                 "userns-writable", "work-rw", "missing-mount", "wrong-type", "shared-device",
                 "subtree-bind", "unexpected-work-mount", "wrong-quota", "occupied-data", "bad-flags", "mode")
        for case in cases:
            with self.subTest(case=case):
                fixture, work = _Profile(), None
                if case == "wrong-platform": fixture.platform = "darwin"
                elif case == "root": fixture.uid = fixture.euid = 0
                elif case == "saved-identity": fixture.euid = 60002
                elif case == "extra-group": fixture.groups = [5]
                elif case == "work-shape": work = fixture.work / "other"
                elif case == "work-alias": fixture.aliases[str(fixture.checks)] = "/synthetic/other/checks"
                elif case == "old-fsize": fixture.limits["FSIZE"] = (512 * 1024**2,) * 2
                elif case == "soft-fsize": fixture.limits["FSIZE"] = (512 * 1024**2, (1 << 32) + 1024**2)
                elif case == "cpu": fixture.limits["CPU"] = (301, 301)
                elif case == "address-space": fixture.limits["AS"] = (5 * 1024**3,) * 2
                elif case == "userns-enabled": fixture.userns = b"1\n"
                elif case == "userns-malformed": fixture.userns = b"0\nprivate\n"
                elif case == "userns-writable": fixture.nodes[_USERNS].st_mode |= 0o002
                elif case == "work-rw": fixture.mounts[1]["options"] = "rw"
                elif case == "missing-mount": fixture.mounts.pop()
                elif case == "wrong-type": fixture.mounts[2]["filesystem"] = "ext4"
                elif case == "shared-device": fixture.mounts[3]["device"] = fixture.mounts[2]["device"]
                elif case == "subtree-bind": fixture.mounts[2]["root"] = "/other"
                elif case == "unexpected-work-mount":
                    fixture.mounts.append({**fixture.mounts[2], "path": str(fixture.work / "extra"), "device": "0:999"})
                elif case == "wrong-quota": fixture.filesystems[100]["capacity"] += 4096
                elif case == "occupied-data": fixture.filesystems[100]["used"] = 4096
                elif case == "bad-flags": fixture.filesystems[100]["readonly"] = True
                else: fixture.nodes[str(fixture.work / "tmp")].st_mode = stat.S_IFDIR | 0o700
                with _pure(self.module, fixture):
                    with self.assertRaises(self.module.CheckError):
                        self.module._python_full_profile(work if work is not None else fixture.checks, deadline=10.0)
                self.assertEqual(fixture.created, [])
                self.assertEqual(fixture.fds, {})
                self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))

    def test_proc_readers_are_strict_bounded_and_close_original_handles(self):
        baseline = _Profile().mount_bytes()
        malformed = (b"", baseline[:-1], baseline + baseline.splitlines(keepends=True)[0],
                     baseline.replace(b" - ", b" bad ", 1), baseline.replace(b" 9:9 ", b" x:y ", 1),
                     baseline.replace(b" rw ", b" ro,rw ", 1), baseline.replace(b" /fixture-work ", b" /bad\\999 ", 1),
                     b"x" * (self.module.PROFILE_MOUNTINFO_BYTES + 1),
                     b"1 1 0:1 / / rw - tmpfs synthetic rw\n" * (self.module.PROFILE_MOUNTINFO_ROWS + 1))
        for index, raw in enumerate(malformed):
            with self.subTest(mountinfo=index):
                fixture = _Profile()
                fixture.mount_override = raw
                with _pure(self.module, fixture):
                    with self.assertRaises(self.module.CheckError):
                        self.module._python_full_profile(fixture.checks, deadline=10.0)
                self.assertEqual(fixture.created, [])
                self.assertEqual(fixture.fds, {})
                self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))
        for case in ("read-error", "read-and-close-error", "expired", "identity-drift"):
            with self.subTest(userns=case):
                fixture = _Profile()
                primary = OSError(errno.EIO, "synthetic fixed-node read failure")

                def hook(operation, path, detail):
                    if path == _USERNS and operation == "read":
                        if case == "expired": fixture.now = 10.0
                        elif case == "identity-drift": fixture.nodes[path].st_ino += 1
                        else: raise primary
                    if path == _USERNS and operation == "close" and case == "read-and-close-error":
                        raise OSError(errno.EIO, "synthetic ambiguous close")
                    return _DEFAULT

                fixture.hook = hook
                with _pure(self.module, fixture):
                    with self.assertRaises(OSError if case == "read-error" else self.module.CheckError) as raised:
                        self.module._python_full_profile(fixture.checks, deadline=10.0)
                if case == "read-error": self.assertIs(raised.exception, primary)
                elif case == "read-and-close-error":
                    self.assertIn(primary, raised.exception.__cause__.exceptions)
                    self.assertEqual(raised.exception.cleanup_errors, ["PYTHON_PROFILE_USERNS_CLOSE"])
                self.assertEqual(fixture.created, [])
                self.assertEqual(fixture.fds, {})
                self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))

    def test_real_control_body_rejects_wrong_denials_and_missing_capacity_enforcement(self):
        for case in ("positive-denied", "ro-eacces", "ro-writable", "capacity-eio", "no-enospc", "short-write",
                     "not-empty", "late-topology", "late-userns", "expired-write"):
            with self.subTest(case=case):
                fixture = _Profile()
                if case == "ro-writable": fixture.allow_readonly_create = True
                if case == "no-enospc": fixture.enforce_capacity = False
                if case == "not-empty":
                    fixture.add_file(str(fixture.checks / "unowned"), uid=60002, gid=60002, device=107)

                def hook(operation, path, detail):
                    if operation == "write" and path.endswith(".mrk-python-profile-write"):
                        if case == "positive-denied": raise OSError(errno.EACCES, "synthetic write refusal")
                        if case == "short-write": return 0
                        if case == "expired-write": fixture.now = 10.0
                    if operation == "open" and path.endswith(".mrk-python-profile-readonly") and case == "ro-eacces":
                        raise OSError(errno.EACCES, "not actual readonly refusal")
                    if operation == "write" and path.endswith(".mrk-python-profile-capacity") and case == "capacity-eio":
                        raise OSError(errno.EIO, "not actual capacity refusal")
                    if operation == "open" and path == _MOUNTINFO and fixture.counts[(operation, path)] == 2:
                        if case == "late-topology": fixture.mounts[2]["device"] = "0:999"
                    if operation == "open" and path == _USERNS and fixture.counts[(operation, path)] == 2:
                        if case == "late-userns": fixture.userns = b"1\n"
                    return _DEFAULT

                fixture.hook = hook
                inventory = Mock(side_effect=AssertionError("invalid profile reached inventory"))
                with _pure(self.module, fixture, expected_python_ids=inventory):
                    with self.assertRaises((OSError, self.module.CheckError)):
                        self.module.run_python_tests(fixture.source, "full", 10.0, [], work_root=fixture.checks)
                inventory.assert_not_called()
                self.assertEqual(fixture.fds, {})
                self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))
                if case == "not-empty": self.assertIn(str(fixture.checks / "unowned"), fixture.nodes)

    def test_cleanup_collects_independent_errors_without_adopting_unknown_names(self):
        for case in ("write-close-remove", "created-then-error", "file-replaced", "directory-replaced", "scan-close"):
            with self.subTest(case=case):
                fixture = _Profile()
                target = str(fixture.work / "tmp" / ".mrk-python-profile-write")
                primary = OSError(errno.EIO, "synthetic original write failure")

                def hook(operation, path, detail):
                    if case == "created-then-error" and operation == "created" and path == target:
                        raise primary
                    if case == "write-close-remove" and path == target:
                        if operation == "write": raise primary
                        if operation in {"close", "unlink"}: raise OSError(errno.EIO, "synthetic cleanup failure")
                    if case in {"file-replaced", "directory-replaced"} and operation == "close" and path == target:
                        changed = target if case == "file-replaced" else str(fixture.work / "tmp")
                        original = fixture.nodes[changed]
                        fixture.nodes[changed] = SimpleNamespace(**{**vars(original), "st_ino": original.st_ino + 9999})
                    if case == "scan-close" and operation == "scan-close":
                        raise OSError(errno.EIO, "synthetic iterator close failure")
                    return _DEFAULT

                fixture.hook = hook
                with _pure(self.module, fixture):
                    with self.assertRaises(OSError if case == "created-then-error" else self.module.CheckError) as raised:
                        self.module._python_full_profile(fixture.checks, deadline=10.0)
                if case == "created-then-error": self.assertIs(raised.exception, primary)
                elif case == "write-close-remove":
                    self.assertEqual(raised.exception.cleanup_errors,
                                     ["PYTHON_PROFILE_FILE_CLOSE", "PYTHON_PROFILE_FILE_REMOVE"])
                    self.assertIn(primary, raised.exception.__cause__.exceptions)
                self.assertEqual(fixture.fds, {})
                self.assertTrue(all(count == 1 for count in fixture.close_calls.values()))
                if case != "scan-close":
                    self.assertIn(target, fixture.nodes)
                    self.assertNotIn(target, fixture.removed)

    def test_full_inventory_follows_real_admission_and_wheel_path_does_not_use_it(self):
        for selection, platform in (("full", "linux"), ("wheel", "linux"), ("wheel", "darwin")):
            with self.subTest(selection=selection, platform=platform):
                fixture, events = _Profile(), []
                fixture.platform = platform
                suite, expected = _inert_suite(events, outcome="success")
                discovered = []

                def inventory(source, chosen, *, deadline):
                    self.assertEqual((source, chosen, deadline), (fixture.source, selection, 10.0))
                    self.assertEqual(len(fixture.created), 12 if selection == "full" else 0)
                    self.assertEqual(fixture.fds, {})
                    discovered.append("inventory")
                    return expected

                def discover(path, *, pattern):
                    self.assertEqual(path, str(fixture.source / "tests"))
                    self.assertIn("inventory", discovered)
                    discovered.append(pattern)
                    # Each selected wheel pattern is still visited once, without
                    # loading any project module; the finite inert suite is supplied once.
                    return suite if len(discovered) == 2 else unittest.TestSuite()

                wheel = Mock(return_value={})
                observations = []
                with _pure(self.module, fixture, expected_python_ids=inventory, inspect_installed_wheel=wheel) as framework:
                    framework.TestLoader = lambda: SimpleNamespace(errors=[], discover=discover)
                    details = self.module.run_python_tests(fixture.source, selection, 10.0, observations,
                                                          work_root=fixture.checks)
                self.assertEqual(events, ["first", "second", "third"])
                self.assertEqual(observations, [{"id": identifier, "outcome": "ok"} for identifier in expected])
                self.assertEqual(details["failure_callbacks"], [])
                self.assertEqual(details["executed"], 3)
                if selection == "full":
                    self.assertEqual(details["storage_profile"], _profile_details())
                    wheel.assert_not_called()
                    self.assertEqual(discovered, ["inventory", "test*.py"])
                else:
                    self.assertNotIn("storage_profile", details)
                    self.assertEqual(fixture.events, [])
                    wheel.assert_called_once_with(fixture.source, deadline=10.0)
                    self.assertEqual(discovered, ["inventory", *self.module.WHEEL_PATTERNS])

    def test_actual_failfast_subtest_metadata_survives_main_and_controller_without_private_data(self):
        fixture, events = _Profile(), []
        suite, expected = _inert_suite(events)
        inventory = Mock(return_value=expected)
        loader = SimpleNamespace(errors=[], discover=Mock(return_value=suite))
        with _pure(self.module, fixture, expected_python_ids=inventory) as framework:
            framework.TestLoader = lambda: loader
            status = self.module.main(["--check", "python-full", "--source-root", str(fixture.source),
                                       "--work-root", str(fixture.checks), "--deadline", "10.0"])
        self.assertEqual(status, 1)
        self.assertEqual(events, ["first", "second"])
        stdout = fixture.stdout.getvalue()
        self.assertTrue(stdout.startswith(self.module.RESULT_PREFIX))
        report = json.loads(stdout[len(self.module.RESULT_PREFIX):])
        self.assertFalse(report["ok"])
        self.assertEqual(report["details"]["error"], "TEST_OUTCOME_COUNT")
        self.assertEqual(report["tests"], [{"id": expected[0], "outcome": "ok"},
                                           {"id": expected[1], "outcome": "error"}])
        callback = {"id": expected[1], "outcome": "error", "category": "os-error", "errno": errno.EFBIG}
        self.assertEqual(report["details"]["failure_callbacks"], [callback])
        self.assertEqual(report["details"]["storage_profile"], _profile_details())
        self.assertIn("PRIVATE_SUBTEST_PARAMETER", fixture.stderr.getvalue())
        self.assertNotIn("PRIVATE_", stdout)
        self.assertEqual(fixture.fds, {})
        self.assertEqual(sorted(fixture.created), sorted(fixture.removed))

        controller = helper_module("verify_ci")
        result = SimpleNamespace(returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
            domain_finality=True, timed_out=False, cancelled=False, stdout=stdout.encode(),
            stderr=fixture.stderr.getvalue().encode(), persisted=(), duration=0.01, cleanup_errors=(),
            primary_error="command exited 1", ok=False)
        step = controller.Step("python-full", parser="check")
        paths = SimpleNamespace(source=fixture.source)
        checks = SimpleNamespace(expected_python_ids=Mock(return_value=expected))
        with patch.multiple(controller, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                            time=SimpleNamespace(monotonic=lambda: fixture.now)):
            public = controller.failure_details(result, step, paths, checks=checks, deadline=10.0, platform="linux")
            with self.assertRaises(controller.VerificationError):
                controller.parse_capture(step, result, paths, "linux", checks)
        checks.expected_python_ids.assert_called_once_with(fixture.source, "full", deadline=10.0)
        self.assertEqual(public["failure_callbacks"], [callback])
        self.assertEqual(public["storage_profile"], _profile_details())
        self.assertEqual(public["returncode"], 1)
        self.assertNotIn("PRIVATE_", json.dumps(public))

    def test_callback_bounds_categories_and_late_errors_preserve_failed_outcomes(self):
        identifier = "unit.fixed_fixture.Fixture.test_02_callback"
        cases = ((OSError(errno.EIO, "PRIVATE"), "os-error", errno.EIO),
                 (OSError(True, "PRIVATE"), "os-error", None), (OSError(4096, "PRIVATE"), "os-error", None),
                 (AssertionError("PRIVATE"), "assertion-error", None), (ValueError("PRIVATE"), "value-error", None),
                 (TypeError("PRIVATE"), "type-error", None), (MemoryError("PRIVATE"), "memory-error", None),
                 (RuntimeError("PRIVATE"), "exception", None), (SystemExit("PRIVATE"), "base-exception", None))
        for error, category, number in cases:
            with self.subTest(category=category, errno=number):
                row = self.module._failure_callback(identifier, "error", (type(error), error, None), (identifier,))
                self.assertEqual(row, {"id": identifier, "outcome": "error", "category": category, "errno": number})
                self.assertNotIn("PRIVATE", json.dumps(row))
        self.assertEqual(self.module._failure_callback(identifier, "skip", None, (identifier,)),
                         {"id": identifier, "outcome": "skip", "category": "none", "errno": None})
        self.assertEqual(self.module._failure_callback(identifier, "unexpected-success", None, (identifier,)),
                         {"id": identifier, "outcome": "unexpected-success", "category": "none", "errno": None})
        with self.assertRaises(self.module.CheckError):
            self.module._failure_callback(identifier + " PRIVATE_SUBTEST", "error", None, (identifier,))
        for outcome, error in (("error", None), ("failure", None), ("expected-failure", None),
                               ("skip", (OSError, OSError(errno.EIO, "PRIVATE"), None)), ([], None)):
            with self.subTest(malformed_outcome=outcome):
                with self.assertRaises(self.module.CheckError):
                    self.module._failure_callback(identifier, outcome, error, (identifier,))

        for case in ("bounded", "unexpected-skip", "assertion", "late-deadline"):
            with self.subTest(case=case):
                fixture, events = _Profile(), []
                suite, expected = _inert_suite(events, outcome="skip" if case == "unexpected-skip" else
                                               "failure" if case == "assertion" else "os-error",
                                               callback_count=20 if case == "bounded" else 1)
                observations = []
                with _pure(self.module, fixture, expected_python_ids=Mock(return_value=expected)) as framework:
                    framework.TestLoader = lambda: SimpleNamespace(errors=[], discover=Mock(return_value=suite))
                    if case == "late-deadline":
                        original_runner = framework.TextTestRunner

                        class LateRunner(original_runner):
                            def run(self, tests):
                                value = super().run(tests)
                                fixture.now = 10.0
                                return value

                        framework.TextTestRunner = LateRunner
                    with self.assertRaises(self.module.CheckError) as raised:
                        self.module.run_python_tests(fixture.source, "full", 10.0, observations,
                                                      work_root=fixture.checks)
                expected_outcome = "skip" if case == "unexpected-skip" else "failure" if case == "assertion" else "error"
                self.assertEqual(observations[-1]["outcome"], expected_outcome)
                self.assertTrue(all(set(row) == {"id", "outcome"} for row in observations))
                self.assertEqual(len(raised.exception.failure_callbacks), 16 if case == "bounded" else 1)
                self.assertEqual(raised.exception.failure_callbacks[0]["outcome"], expected_outcome)
                self.assertEqual(raised.exception.storage_profile, _profile_details())
                self.assertEqual(str(raised.exception), "DEADLINE_EXPIRED" if case == "late-deadline" else
                                 "TEST_NOT_SUCCESSFUL" if case == "bounded" else "TEST_OUTCOME_COUNT")
                self.assertEqual(fixture.fds, {})

        # Execute the actual in-memory profile and inert success suite first,
        # then expire the original clock at main's independent final check.
        fixture, events = _Profile(), []
        suite, expected = _inert_suite(events, outcome="success")
        actual_runner = self.module.run_python_tests

        def expire_after_actual_runner(*args, **kwargs):
            result = actual_runner(*args, **kwargs)
            fixture.now = 10.0
            return result

        with _pure(self.module, fixture, expected_python_ids=Mock(return_value=expected),
                   run_python_tests=expire_after_actual_runner) as framework:
            framework.TestLoader = lambda: SimpleNamespace(errors=[], discover=Mock(return_value=suite))
            status = self.module.main(["--check", "python-full", "--source-root", str(fixture.source),
                                       "--work-root", str(fixture.checks), "--deadline", "10.0"])
        self.assertEqual(status, 1)
        self.assertEqual(events, ["first", "second", "third"])
        report = json.loads(fixture.stdout.getvalue()[len(self.module.RESULT_PREFIX):])
        self.assertFalse(report["ok"])
        self.assertEqual(report["details"]["error"], "DEADLINE_EXPIRED")
        self.assertEqual(report["details"]["failure_callbacks"], [])
        self.assertEqual(report["details"]["storage_profile"], _profile_details())
        self.assertEqual(fixture.fds, {})
