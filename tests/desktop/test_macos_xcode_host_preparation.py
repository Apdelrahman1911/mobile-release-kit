"""Twelve focused regressions; NONE is a Mac/native preparation qualification.

Running this file needs an explicit later COMMAND grant. It imports the helper,
creates owned local temporary-directory/pipe fixtures and performs a real
fixture-only 0775 -> 0755 fchmod. It is NOT a read-only DATA/MC6 audit. Darwin
API/process outcomes below are labelled unit DATA, never hosted evidence. No
real sudo, /Applications change, Xcode, compiler or native shim is invoked.
"""

import contextlib
import copy
import ctypes
import errno
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "desktop/tools/macos_xcode_host_preparation.py"
SPEC = importlib.util.spec_from_file_location("_mrk_macos_xcode_host_preparation_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)

NATIVE_PINS = {
    "desktop/src-tauri/src/installed_runtime_macos.rs":
        "ff925a45fb68fcd0c8758d1ac9866f08dded93f5401f0c44b28c2a637ec932bf",
    "desktop/native/macos-installed-native/src/native.m":
        "f53c9b32ba7eb9b42550a6c481d7b3965fe0f1a9896aeb561e9d3318fdc005ef",
    "desktop/src-tauri/src/ios_toolchain.rs":
        "39a618d6c886e986b6ac414d5ebcd2ba02d9e70b0f44f258f3d793338044cbb1",
    "src/mobile_release/ios_archive_operation.py":
        "ca724e7943c9862608f4f23db3ffa4202a3904703600c9c338acb8667ee0a49a",
    "desktop/src-tauri/src/saved_command_owner.rs":
        "d89f2f730c07ae7b3f7a66f9292df621356974668c11f80a74da970532c6a0eb",
    "desktop/src-tauri/src/installed_shell_observation_macos_ios.rs":
        "df48d8a5ef0670b1070ddd1490e4f8d242035f134314b0c3e3c2ed51fe49e5ce",
}


def application(mode=0o775):
    # Deliberately synthetic test DATA, not historical/native FD evidence.
    return [7, 101, stat.S_IFDIR | mode, 0, 80, 2, 64,
            1790486400000000001, 1790486400000000002]


def observation(mode=0o775):
    return {"full9": application(mode), "flags": 0, "birthtimeNs": 100,
            "roster": ["Xcode.app"], "filesystem": {"typeName": "apfs", "fsid": [1, 2]},
            "acl": {"empty": True, "kind": "absent", "present": 0}, "xattrs": []}


def environment():
    source = "0123456789abcdef0123456789abcdef01234567"
    work = M.RUNNER_TEMP + "/mrk-macos-aqua.A1B2C3D4"
    return {"PATH": M.SAFE_PATH, "HOME": work, "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "__CF_USER_TEXT_ENCODING": "0x1F5:0:0",
            "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "RUNNER_TEMP": M.RUNNER_TEMP, "GITHUB_REPOSITORY": M.REPOSITORY,
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": M.REF, "GITHUB_SHA": source,
            "GITHUB_WORKFLOW_REF": M.REPOSITORY + "/" + M.WORKFLOW + "@" + M.REF,
            "GITHUB_WORKFLOW_SHA": source, "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "aqua", "GITHUB_WORKSPACE": M.WORKSPACE,
            "MRK_EXPECTED_SHA": source, "MRK_MACOS_INSTALL_SOURCE_COMMIT": source,
            "MRK_MACOS_WORK": work}


def valid_context():
    return M._validate_context(environment(), (501, 501, 20, 20),
                               ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))


def block(text, marker):
    return text.split("<<'" + marker + "'\n", 1)[1].split("          " + marker + "\n", 1)[0].encode()


class ACLLibraryData:
    """No actual Darwin call. Writes ctypes DATA to the declared pointer types."""
    def __init__(self, present=0, initialize=True, snapshot_result=0, missing=None,
                 wrong_property=None, pointer=0x2000, valid=True, entry=False,
                 first_error=errno.EINVAL, free_result=0, filesec_free_raises=False,
                 changed_snapshot=False):
        self.present, self.initialize = present, initialize
        self.snapshot_result, self.missing = snapshot_result, missing
        self.wrong_property, self.pointer, self.valid = wrong_property, pointer, valid
        self.entry, self.first_error, self.free_result = entry, first_error, free_result
        self.filesec_free_raises, self.changed_snapshot = filesec_free_raises, changed_snapshot
        self.calls = []
        self.expected = application(0o755)

    def filesec_init(self):
        self.calls.append(("filesec_init",))
        if not self.initialize:
            ctypes.set_errno(errno.ENOMEM)
            return None
        return 0x1000

    def fstatx_np(self, descriptor, output, fsec):
        self.calls.append(("fstatx_np", descriptor, fsec))
        if self.snapshot_result:
            ctypes.set_errno(errno.EIO)
            return self.snapshot_result
        value = ctypes.cast(output, ctypes.POINTER(M.DarwinStat)).contents
        sample = self.expected
        value.dev, value.ino, value.mode = sample[0], sample[1], sample[2]
        value.uid, value.gid, value.links, value.size = sample[3:7]
        if self.changed_snapshot:
            value.ino += 1
        value.mtime.seconds, value.mtime.nanoseconds = divmod(sample[7], 1000000000)
        value.ctime.seconds, value.ctime.nanoseconds = divmod(sample[8], 1000000000)
        value.birthtime.seconds, value.birthtime.nanoseconds = 1, 2
        value.flags = 0
        return 0

    def filesec_get_property(self, fsec, prop, output):
        self.calls.append(("filesec_get_property", prop))
        if prop == self.missing:
            ctypes.set_errno(errno.ENOENT)
            return -1
        if prop == 5:
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = self.pointer
        else:
            ctype = ctypes.c_uint16 if prop == 4 else ctypes.c_uint32
            value = {1: self.expected[3], 2: self.expected[4], 4: self.expected[2]}[prop]
            if prop == self.wrong_property:
                value += 1
            ctypes.cast(output, ctypes.POINTER(ctype))[0] = value
        return 0

    def filesec_query_property(self, fsec, prop, output):
        self.calls.append(("filesec_query_property", prop))
        ctypes.cast(output, ctypes.POINTER(ctypes.c_int))[0] = self.present
        return 0

    def acl_valid(self, acl):
        self.calls.append(("acl_valid", acl.value))
        if not self.valid:
            ctypes.set_errno(errno.EINVAL)
            return -1
        return 0

    def acl_get_entry(self, acl, which, output):
        self.calls.append(("acl_get_entry", which))
        if self.entry:
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 0x3000
            return 0
        ctypes.set_errno(self.first_error)
        return -1

    def acl_free(self, acl):
        self.calls.append(("acl_free", acl.value))
        if self.free_result:
            ctypes.set_errno(errno.EIO)
        return self.free_result

    def filesec_free(self, fsec):
        self.calls.append(("filesec_free", fsec))
        if self.filesec_free_raises:
            raise OSError(errno.EIO, "unit-only-void-free-uncertain")


class OrchestrationBookData:
    """Unit-only original-book data; never a hosted observation or FD owner."""
    def __init__(self, mode=0o755, close_errors=(), fail_final=False):
        self.context = valid_context()
        self.errors = []
        self.nodes = {}
        self.absences = []
        self.work_transitions = []
        self.intent_pin = None
        self.source_binding = {"unitDataOnly": True}
        self.work = types.SimpleNamespace(fd=77)
        self.applications = types.SimpleNamespace(pre={"full9": application(mode)})
        self.records = []
        self.checks = []
        self.close_errors = list(close_errors)
        self.close_calls = 0
        self.fail_final = fail_final

    def recheck(self, phase, applications_transition=False):
        self.checks.append((phase, applications_transition))
        if phase == "final-before-closes" and self.fail_final:
            self.errors.append({"unitOnlyFinalPostError": True})

    def receipt(self, name, value, retain=False):
        self.records.append((name, copy.deepcopy(value), retain))
        return {"name": name, "unitDataOnly": True}

    def error(self, *arguments):
        self.errors.append({"unitOnlyError": list(arguments)})

    def close_all(self):
        self.close_calls += 1
        return self.close_errors


def orchestrated_no_effect(book):
    # Every native/process/acquisition boundary is replaced with explicit unit
    # DATA. Any accidental command construction raises before Popen can happen.
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(M.sys, "argv", [M.WORKSPACE + "/" + M.HELPER]))
        stack.enter_context(mock.patch.object(M, "_validate_context", return_value=valid_context()))
        stack.enter_context(mock.patch.object(M, "DarwinAPI", return_value=types.SimpleNamespace(version="26.0")))
        stack.enter_context(mock.patch.object(M, "Originals", return_value=book))
        stack.enter_context(mock.patch.object(M, "_collect_prerequisites"))
        stack.enter_context(mock.patch.object(M, "_bind_source"))
        command = stack.enter_context(mock.patch.object(M, "FixedCommandOwner",
                                                        side_effect=AssertionError("unit-forbids-any-privileged-command")))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        returned = M.main()
        return returned, command.call_count


class ProcessData:
    """Fake PID/raw wait status, real owned pipe bytes/EOF; NOT a native wait."""
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.pid = 76123  # Synthetic DATA: waitpid/kill are always intercepted below.
        self.status_code = returncode
        self.returncode = None
        self.wait_calls = 0
        self.signal_calls = []
        self.stdout = self.pipe(stdout)
        try:
            self.stderr = self.pipe(stderr)
        except BaseException:
            self.stdout.close()
            raise

    @staticmethod
    def pipe(data):
        read_fd, write_fd = os.pipe()
        try:
            # Fixture construction must fail rather than block on pipe capacity.
            os.set_blocking(write_fd, False)
            offset = 0
            while offset < len(data):
                count = os.write(write_fd, data[offset:])
                if count <= 0:
                    raise AssertionError("owned pipe fixture write")
                offset += count
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)
        return os.fdopen(read_fd, "rb", buffering=0)

    def waitpid_data(self, pid, options):
        if pid != self.pid or options != os.WNOHANG:
            raise AssertionError("unit wait must name only original PID with WNOHANG")
        self.wait_calls += 1
        return pid, self.status_code << 8 if self.status_code >= 0 else -self.status_code

    def signal_data(self, pid, number):
        if pid != self.pid or number not in (M.signal.SIGTERM, M.signal.SIGKILL):
            raise AssertionError("unit signal must name only original PID and fixed stop signal")
        self.signal_calls.append((pid, number))

    def poll(self):
        raise AssertionError("CPython synthetic poll result is forbidden")

    def wait(self, timeout):
        raise AssertionError("CPython synthetic wait result is forbidden")

    def terminate(self):
        raise AssertionError("Popen terminate may consume wait status")

    def kill(self):
        raise AssertionError("Popen kill may consume wait status")

    def close_fixture(self):
        for stream in (self.stdout, self.stderr):
            if not stream.closed:
                stream.close()


def signal_policy_data():
    # A mocked readonly snapshot, never proof of a host's real SIGCHLD action.
    return types.SimpleNamespace(waitable_sigchld=mock.Mock(
        return_value={"handler": 0, "mask": 0, "flags": 0}))


@contextlib.contextmanager
def command_data(process, wait=None):
    # All numeric/process boundaries are intercepted. Only the local owned pipe
    # descriptors above are real; no test can wait on or signal PID76123.
    with mock.patch.object(M.subprocess, "Popen", return_value=process) as create, \
            mock.patch.object(M.os, "waitpid", side_effect=process.waitpid_data if wait is None else wait) as waited, \
            mock.patch.object(M.os, "kill", side_effect=process.signal_data) as stopped:
        yield create, waited, stopped


class StreamCloseData:
    def __init__(self, original, after_close=None, uncertain=False):
        self.original, self.after_close, self.uncertain = original, after_close, uncertain
        self.close_calls = 0

    def fileno(self):
        return self.original.fileno()

    @property
    def closed(self):
        return self.original.closed

    def close(self):
        self.close_calls += 1
        if self.uncertain:
            raise OSError(errno.EIO, "unit-capture-close-unknown")
        self.original.close()
        if self.after_close is not None:
            self.after_close()


class MacOSXcodeHostPreparationTests(unittest.TestCase):
    def test_unprepared_native_and_diagnostic_mode_rejection_is_unchanged(self):
        for path, expected in NATIVE_PINS.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), expected)
        runtime = (ROOT / "desktop/src-tauri/src/installed_runtime_macos.rs").read_text()
        self.assertIn("s.st_mode & 0o7022 != 0", runtime)
        self.assertIn("self.original.chain(Path::new(APPLICATIONS)", runtime)
        workflow = (ROOT / M.WORKFLOW).read_text()
        diagnostic = block(workflow, "PY_XCODE")
        self.assertEqual(len(diagnostic), 4423)
        self.assertEqual(hashlib.sha256(diagnostic).hexdigest(),
                         "fa5289e5fd550a286bdf00b97404754caf632abf4a816f590dbaa186a0511a22")
        self.assertIn(b"s.st_mode & 0o022", diagnostic)
        self.assertEqual((stat.S_IFDIR | 0o775) & 0o7022, 0o020)
        self.assertEqual((stat.S_IFDIR | 0o775) & 0o022, 0o020)
        self.assertEqual((stat.S_IFDIR | 0o755) & 0o7022, 0)

    def test_real_owned_fixture_0775_to_0755_is_the_only_mode_transition(self):
        # This is real fixture-local fchmod, not read-only DATA or a system path.
        with tempfile.TemporaryDirectory(prefix="mrk-xcode-host-preparation-data-") as root:
            fixture = Path(root) / "owned-directory"
            fixture.mkdir(mode=0o700)
            self.assertNotEqual(str(fixture), "/Applications")
            descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                self.assertEqual(os.fstat(descriptor).st_uid, os.getuid())
                os.fchmod(descriptor, 0o775)  # Owned fixture construction only.
                before = {"full9": M.full9(os.fstat(descriptor)),
                          "roster": sorted(os.listdir(descriptor)), "fixtureOnly": True}
                self.assertEqual(before["full9"][2], stat.S_IFDIR | 0o775)
                os.fchmod(descriptor, 0o755)
                after = {"full9": M.full9(os.fstat(descriptor)),
                         "roster": sorted(os.listdir(descriptor)), "fixtureOnly": True}
                self.assertEqual(after["full9"], M.full9(os.stat(fixture, follow_symlinks=False)))
                self.assertEqual(after["full9"][2], stat.S_IFDIR | 0o755)
                self.assertTrue(M._same_snapshot(before, after, transition=True))
                self.assertFalse(M._same_snapshot(before, after, transition=False))
                self.assertTrue(M._same_snapshot(after, copy.deepcopy(after), transition=False))
                self.assertFalse(M._same_snapshot(after, before, transition=True))
            finally:
                os.close(descriptor)

    def test_fixed_applications_owner_group_and_modes_are_required(self):
        self.assertEqual(M._application_mode(application()), "chmod")
        self.assertEqual(M._application_mode(application(0o755)), "noop")
        for index, value in ((3, 501), (4, 0), (2, stat.S_IFREG | 0o775),
                             (2, stat.S_IFDIR | 0o777), (2, stat.S_IFDIR | 0o1775),
                             (2, stat.S_IFDIR | 0o4755), (2, stat.S_IFDIR | 0o750),
                             (2, stat.S_IFDIR | 0o555), (2, stat.S_IFDIR | 0o700)):
            candidate = application()
            candidate[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(M.Refused):
                M._application_mode(candidate)
        book = OrchestrationBookData(mode=0o775)
        self.assertEqual(M._eligible_action(book), "chmod")
        book.errors.append({"anotherPrerequisiteFailed": True})
        self.assertIsNone(M._eligible_action(book))

    def test_identity_roster_acl_flags_or_other_metadata_changes_refuse(self):
        before = observation()
        after = observation(0o755)
        after["full9"][8] += 3
        self.assertTrue(M._same_snapshot(before, after, True))
        for index in (0, 1, 3, 4, 5, 6, 7):
            changed = copy.deepcopy(after)
            changed["full9"][index] += 1
            with self.subTest(full9Index=index):
                self.assertFalse(M._same_snapshot(before, changed, True))
        for key, value in (("roster", ["Xcode.app", "unexpected"]), ("flags", M.SF_RESTRICTED),
                           ("birthtimeNs", 101), ("acl", {"empty": False, "kind": "contains-entry", "present": 32}),
                           ("xattrs", [{"name": "unit", "size": 0, "sha256": "0" * 64}]),
                           ("filesystem", {"typeName": "apfs", "fsid": [1, 3]})):
            changed = copy.deepcopy(after)
            changed[key] = value
            with self.subTest(extra=key):
                self.assertFalse(M._same_snapshot(before, changed, True))
        backwards = copy.deepcopy(after)
        backwards["full9"][8] = before["full9"][8] - 1
        self.assertFalse(M._same_snapshot(before, backwards, True))
        noop_before = observation(0o755)
        noop_after = copy.deepcopy(noop_before)
        noop_after["full9"][8] += 1
        self.assertFalse(M._same_snapshot(noop_before, noop_after, False))
        self.assertFalse(M._same_snapshot(noop_before, noop_after, True))
        # Own receipt creation may advance work mtime/ctime, never move them back.
        for index in (7, 8):
            book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
            previous = observation(0o755)
            previous["roster"] = [M.INVENTORY]
            current = copy.deepcopy(previous)
            current["roster"] = sorted([M.INVENTORY, M.INTENT])
            current["full9"][index] -= 1
            book.work = types.SimpleNamespace(expected=previous)
            with mock.patch.object(book, "snapshot", return_value=current), self.assertRaises(M.Refused):
                book.refresh_work(M.INTENT)
        # Result readback must name the same original AFTER the bytes are read.
        book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
        fields = {"st_dev": 7, "st_ino": 11, "st_mode": stat.S_IFREG | 0o400,
                  "st_uid": 501, "st_gid": 20, "st_nlink": 1, "st_size": 2,
                  "st_mtime_ns": 100, "st_ctime_ns": 200}
        current = types.SimpleNamespace(**fields)
        replaced = types.SimpleNamespace(**{**fields, "st_ino": 12})
        book.work = types.SimpleNamespace(fd=78)
        book.result_fd, book.result_bytes = 79, b"{}"
        book.result_pin = {"full9": M.full9(current)}
        with mock.patch.object(M.os, "fstat", return_value=current), \
                mock.patch.object(M.os, "stat", side_effect=[current, replaced]) as named, \
                mock.patch.object(M.os, "lseek"), mock.patch.object(M.os, "read", side_effect=[b"{}", b""]):
            book.recheck("final-before-closes")
        self.assertEqual(named.call_count, 2)
        self.assertTrue(any(e["code"] == "original-result-readback-changed" for e in book.errors))

    def test_all_reachable_prerequisite_failures_precede_any_chmod(self):
        class CollectorData:
            chain = M.Originals.chain

            def __init__(self):
                self.roles, self.errors, self.absences = [], [], []
                self.applications = None

            def open(self, parent, name, kind, policy, role):
                path = "/" if parent is None else parent.path.rstrip("/") + "/" + name
                node = M.Node(path, role, parent, name, kind, policy)
                node.fd = 71  # Synthetic unit handle, never passed to a real syscall.
                node.pre = {"full9": application()}
                self.roles.append(role)
                if role in ("applications", "iphoneos-sdk:4", "signing-recovery:openssl"):
                    self.errors.append({"unitOnlyBlocker": role})
                return node

            def error(self, *arguments):
                self.errors.append({"unitOnlyError": arguments})

            def absence(self, parent, name, role):
                self.absences.append(role)
        book = CollectorData()
        with mock.patch.object(M.os, "stat", return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)), \
                mock.patch.object(M, "FixedCommandOwner", side_effect=AssertionError("must not claim")) as command:
            M._collect_prerequisites(book)
            self.assertIsNone(M._eligible_action(book))
            command.assert_not_called()
        for role in ("xcodebuild", "iphoneos-sdk:4", "signing-recovery:security",
                     "signing-recovery:codesign", "signing-recovery:openssl",
                     "os-provisioner-sudo", "os-provisioner-chmod"):
            self.assertIn(role, book.roles)
        self.assertEqual(len(book.errors), 3)
        self.assertEqual(len(book.absences), 3)
        self.assertGreater(book.roles.index("os-provisioner-chmod"), book.roles.index("iphoneos-sdk:4"))

    def test_only_one_fixed_xcode_sibling_alias_is_accepted(self):
        for target, expected in (("Xcode_26.0.app", "Xcode_26.0.app"),
                                 ("/Applications/Xcode-beta.app", "Xcode-beta.app"),
                                 ("Xcode+26.app", "Xcode+26.app")):
            self.assertEqual(M._sibling(target), expected)
        for target in ("", "Xcode.app", "/Applications/Xcode.app", "../Xcode_26.app",
                       "/tmp/Xcode_26.app", "/Applications/sub/Xcode_26.app",
                       "Xcode_26.app/", "Xcode_26.app\0", "Xcodeé.app", "Xcode" + "A" * 256 + ".app"):
            with self.subTest(target=target), self.assertRaises(M.Refused):
                M._sibling(target)
        book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
        parent = M.Node("/Applications", "unit-parent", None, "/", "directory", "applications")
        parent.fd = 72  # Synthetic only; os.stat/open are both intercepted here.
        second_alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
        with mock.patch.object(M.os, "stat", return_value=second_alias), \
                mock.patch.object(M.os, "open", side_effect=AssertionError("second alias must not be opened")) as opened:
            node = book.open(parent, "Xcode_26.app", "directory", "native", "unit-selected-target")
            self.assertIsNone(node.fd)
            opened.assert_not_called()
        self.assertTrue(any(e["code"] == "unavailable-invalid-type-no-follow" for e in book.errors))
        self.assertIn("os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC", PATH.read_text())

    def test_acl_absence_needs_successful_populated_same_fd_snapshot(self):
        library = ACLLibraryData()
        result = M._acl_snapshot(library, 17, library.expected)
        self.assertTrue(result["empty"])
        self.assertEqual(result["kind"], "absent")
        self.assertEqual(result["snapshotFull9"], library.expected)
        self.assertTrue(result["filesecFreeReturned"])
        self.assertEqual([c for c in library.calls if c[0] == "filesec_get_property"],
                         [("filesec_get_property", 1), ("filesec_get_property", 2), ("filesec_get_property", 4)])
        self.assertNotIn("acl_get_fd_np", [c[0] for c in library.calls])
        self.assertEqual(sum(c[0] == "filesec_free" for c in library.calls), 1)
        self.assertEqual(sum(c[0] == "acl_free" for c in library.calls), 0)
        cases = ({"snapshot_result": -1}, {"missing": 1}, {"missing": 2}, {"missing": 4},
                 {"wrong_property": 1}, {"wrong_property": 2}, {"wrong_property": 4},
                 {"changed_snapshot": True})
        for arguments in cases:
            library = ACLLibraryData(**arguments)
            with self.subTest(arguments=arguments):
                self.assertFalse(M._acl_snapshot(library, 17, library.expected)["empty"])
                self.assertEqual(sum(c[0] == "filesec_free" for c in library.calls), 1)
        unallocated = ACLLibraryData(initialize=False)
        self.assertFalse(M._acl_snapshot(unallocated, 17, unallocated.expected)["empty"])
        self.assertEqual(sum(c[0] == "filesec_free" for c in unallocated.calls), 0)
        # Layout arithmetic alone is test DATA, never actual Darwin ABI proof.
        M._check_abi()
        self.assertEqual(ctypes.sizeof(M.DarwinStat), 144)
        self.assertEqual(ctypes.sizeof(M.DarwinStatFS), 2168)
        self.assertEqual(M.DarwinStat.mtime.offset, 48)
        self.assertEqual(M.DarwinStatFS.flags_ext.offset, 2136)
        self.assertEqual(ctypes.sizeof(M.DarwinSigaction), 16)
        self.assertEqual(M.DarwinSigaction.mask.offset, 8)
        self.assertEqual(M.DarwinSigaction.flags.offset, 12)

    def test_nonempty_acl_invalid_acl_and_free_errors_refuse(self):
        empty = ACLLibraryData(present=32)
        result = M._acl_snapshot(empty, 17, empty.expected)
        self.assertTrue(result["empty"])
        self.assertEqual(result["present"], 32)
        self.assertIn(("acl_get_entry", 0), empty.calls)
        self.assertEqual(sum(c[0] == "acl_free" for c in empty.calls), 1)
        for arguments in ({"entry": True}, {"valid": False}, {"first_error": errno.EIO},
                          {"pointer": None}, {"pointer": 1}, {"free_result": -1},
                          {"filesec_free_raises": True}):
            library = ACLLibraryData(present=32, **arguments)
            with self.subTest(arguments=arguments):
                result = M._acl_snapshot(library, 17, library.expected)
                self.assertFalse(result["empty"])
                self.assertNotEqual(result["phase"], 0)
                self.assertEqual(sum(c[0] == "filesec_free" for c in library.calls), 1)
                self.assertEqual(sum(c[0] == "acl_free" for c in library.calls),
                                 0 if arguments.get("pointer", 0x2000) in (None, 1) else 1)
        absent_free_failure = ACLLibraryData(filesec_free_raises=True)
        self.assertFalse(M._acl_snapshot(absent_free_failure, 17, absent_free_failure.expected)["empty"])

    def test_shared_wrong_source_wrong_platform_or_root_hosts_refuse(self):
        self.assertEqual(set(environment()), M.ENVIRONMENT_KEYS)
        self.assertEqual(len(M.ENVIRONMENT_KEYS), 23)
        self.assertEqual(valid_context()["jobKey"], "aqua")
        another_user = environment()
        another_user["__CF_USER_TEXT_ENCODING"] = "0x3E9:0:0"
        self.assertEqual(M._validate_context(another_user, (1001, 1001, 20, 20),
                                            ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))["uid"], 1001)
        for encoding in ("0x1F6:0:0", "0x1F5:1:1", "not-an-encoding", "0x1f5:0:0",
                         "501:0:0", "0x01F5:0:0", "0x1F5:0:0 "):
            candidate = environment()
            candidate["__CF_USER_TEXT_ENCODING"] = encoding
            with self.subTest(encoding=encoding), self.assertRaisesRegex(
                    M.Refused, "^startup-cf-encoding-not-fixed$"):
                M._validate_context(candidate, (501, 501, 20, 20),
                                    ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))

        class KeysOnly(dict):
            def values(self):
                raise AssertionError("set mismatch must not inspect values")

            def __getitem__(self, key):
                raise AssertionError("set mismatch must not inspect values")

        missing = KeysOnly(environment())
        del missing["__CF_USER_TEXT_ENCODING"]
        with self.assertRaises(M.Refused) as caught:
            M._validate_context(missing, (), (), (), ())
        self.assertIn("missingCount=1", str(caught.exception))
        self.assertIn("missing=['__CF_USER_TEXT_ENCODING']", str(caught.exception))
        self.assertIn("extraCount=0", str(caught.exception))
        unknown = KeysOnly(environment())
        sentinel = "private-value-must-not-be-disclosed"
        # Include raw controls and long escaped non-ASCII names. Both list and
        # per-name bounds matter; no value lookup is allowed even on failure.
        unknown["\x01\t\n\r\x1b" + "\u202e" * 1000] = sentinel
        for number in range(9):
            unknown[f"unreviewed-{number}-" + "\U0001f600" * 1000] = sentinel
        with self.assertRaises(M.Refused) as caught:
            M._validate_context(unknown, (), (), (), ())
        diagnostic = str(caught.exception)
        self.assertTrue(diagnostic.startswith("startup-environment-not-closed "))
        self.assertIn("missingCount=0", diagnostic)
        self.assertIn("extraCount=10", diagnostic)
        self.assertIn("extraListTruncated=True", diagnostic)
        self.assertIn("extraNameTruncated=True", diagnostic)
        self.assertEqual(diagnostic.count("unreviewed-"), 7)
        self.assertLess(len(diagnostic.encode("ascii")), 2048)
        self.assertNotIn(sentinel, diagnostic)
        for control in ("\x01", "\t", "\n", "\r", "\x1b", "\u202e", "\U0001f600"):
            self.assertNotIn(control, diagnostic)
        changes = (("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_REPOSITORY", "other/repository"),
                   ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_REF", "refs/heads/main"),
                   ("GITHUB_WORKFLOW_SHA", "f" * 40), ("MRK_EXPECTED_SHA", "f" * 40),
                   ("GITHUB_JOB", "108550104172"), ("GITHUB_RUN_ID", "0"),
                   ("GITHUB_RUN_ATTEMPT", "-1"), ("RUNNER_ARCH", "X64"),
                   ("HOME", "/Users/runner"), ("GITHUB_WORKSPACE", "/tmp/unreviewed"),
                   ("MRK_MACOS_WORK", M.RUNNER_TEMP + "/mrk-macos-aqua.old"),
                   ("PYTHONPATH", "/tmp/injected"), ("DYLD_INSERT_LIBRARIES", "/tmp/injected.dylib"),
                   ("BASH_ENV", "/tmp/injected"), ("CARGO_HOME", "/tmp/config"))
        with mock.patch.object(M.ctypes, "CDLL", side_effect=AssertionError("wrong context must precede library load")) as load:
            for key, value in changes:
                candidate = environment()
                candidate[key] = value
                with self.subTest(key=key), self.assertRaises(M.Refused):
                    M._validate_context(candidate, (501, 501, 20, 20),
                                        ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))
            for identity in ((0, 0, 0, 0), (501, 0, 20, 20), (501, 501, 20, 0)):
                with self.subTest(identity=identity), self.assertRaises(M.Refused):
                    M._validate_context(environment(), identity, ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))
            for machine in (("Linux", "aarch64"), ("Darwin", "x86_64")):
                with self.subTest(machine=machine), self.assertRaises(M.Refused):
                    M._validate_context(environment(), (501, 501, 20, 20), machine, (3, 14, 7), (1, 1, 1))
            with self.assertRaises(M.Refused):
                M._validate_context(environment(), (501, 501, 20, 20), ("Darwin", "arm64"), (3, 14, 6), (1, 1, 1))
            load.assert_not_called()

    def test_already_protected_is_observed_noop_not_command_success(self):
        book = OrchestrationBookData(mode=0o755)
        returned, commands = orchestrated_no_effect(book)
        self.assertEqual(returned, 0)  # Unit control flow only; all OS boundaries mocked.
        self.assertEqual(commands, 0)
        self.assertEqual(book.close_calls, 1)
        self.assertIn(("post", False), book.checks)
        self.assertIn(("final-before-closes", False), book.checks)
        name, result, retained = book.records[-1]
        self.assertEqual(name, M.RESULT)
        self.assertTrue(retained)
        self.assertFalse(result["prepared"])
        self.assertFalse(result["command"]["claimed"])
        self.assertEqual(result["command"]["retirement"], "not-invoked-observed-noop")
        self.assertFalse(M._command_acknowledged(result["command"]))
        self.assertFalse(result["nativeQualified"])
        self.assertFalse(result["consumerQualified"])
        self.assertFalse(result["disposal"]["physicallyVerified"])
        self.assertIsNone(result["disposal"]["restore0775Command"])

    def test_failed_or_unsettled_command_cannot_publish_prepared(self):
        for code, stdout in ((0, b""), (17, b""), (0, b"x" * (M.MAX_STREAM + 1))):
            process = ProcessData(code, stdout=stdout)
            try:
                owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
                with command_data(process) as (create, waited, stopped):
                    result = owner.run()
                    argv, = create.call_args.args
                    options = create.call_args.kwargs
                    self.assertEqual(argv, M.COMMAND)
                    self.assertEqual(options["env"], {"PATH": M.SAFE_PATH, "HOME": environment()["HOME"],
                                                     "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
                    self.assertEqual(options["cwd"], "/")
                    self.assertEqual(options["stdin"], M.subprocess.DEVNULL)
                    self.assertTrue(options["close_fds"])
                    self.assertTrue(options["start_new_session"])
                    self.assertEqual(process.wait_calls, 1)
                    waited.assert_called_once_with(process.pid, os.WNOHANG)
                    stopped.assert_not_called()
                    self.assertEqual(result["waitedPid"], process.pid)
                    self.assertEqual(result["rawWaitStatus"], code << 8)
                    self.assertTrue(result["stdoutEof"] and result["stderrEof"])
                    self.assertTrue(result["stdoutClosed"] and result["stderrClosed"])
                    self.assertEqual(M._command_acknowledged(result), code == 0 and len(stdout) <= M.MAX_STREAM)
                    self.assertTrue(owner.numeric_retired)
                    self.assertFalse(owner.numeric_route)
                    with self.assertRaises(M.Refused):
                        owner.run()
                    self.assertEqual(create.call_count, 1)
                    if code == 0 and not stdout:
                        for key, value in (("joinedOriginal", False), ("stdoutEof", False), ("stderrEof", False),
                                           ("stdoutClosed", False), ("stderrClosed", False), ("retirement", "unknown"),
                                           ("returncode", None), ("returncode", False), ("errors", ["timeout"]),
                                           ("waitStatusLost", True), ("rawWaitStatus", 17 << 8),
                                           ("waitedPid", process.pid + 1), ("waitApi", "Popen.poll")):
                            changed = copy.deepcopy(result)
                            changed[key] = value
                            with self.subTest(incomplete=key, value=value):
                                self.assertFalse(M._command_acknowledged(changed))
            finally:
                process.close_fixture()
        # A disposed original status is not CPython's synthetic ECHILD exit0.
        for status_loss in ("ECHILD", "foreign-pid", "nonterminal-status", "ambiguous-no-result"):
            process = ProcessData(0)
            try:
                if status_loss == "ECHILD":
                    wait = ChildProcessError(errno.ECHILD, "unit-original-status-disposed")
                elif status_loss == "foreign-pid":
                    wait = lambda pid, options: (pid + 1, 0)
                elif status_loss == "nonterminal-status":
                    wait = lambda pid, options: (pid, 0x7f)
                else:
                    wait = lambda pid, options: (0, 1)
                owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
                with self.subTest(statusLoss=status_loss), command_data(process, wait) as (_, waited, stopped):
                    result = owner.run()
                    self.assertEqual(waited.call_count, 1)
                    stopped.assert_not_called()
                    self.assertTrue(result["waitStatusLost"])
                    self.assertFalse(result["joinedOriginal"])
                    self.assertEqual(result["retirement"], "unknown")
                    self.assertFalse(M._command_acknowledged(result))
                    self.assertTrue(owner.numeric_retired)
                    self.assertFalse(owner.numeric_route)
                    self.assertFalse(process.stdout.closed or process.stderr.closed)
            finally:
                process.close_fixture()  # Unit fixture owner only, not a host-retirement assertion.
        with mock.patch.object(M.subprocess, "Popen", side_effect=OSError(errno.EIO, "unit-spawn-error")) as create, \
                mock.patch.object(M.os, "waitpid", side_effect=AssertionError("no original PID")) as waited, \
                mock.patch.object(M.os, "kill", side_effect=AssertionError("no signal route")) as stopped:
            owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
            result = owner.run()
            self.assertTrue(result["claimed"])
            self.assertEqual(result["retirement"], "unknown")
            self.assertFalse(M._command_acknowledged(result))
            self.assertEqual(create.call_count, 1)
            waited.assert_not_called()
            stopped.assert_not_called()
        # Actual guard function, mocked native sigaction output: never load libc,
        # never install/reset a handler, and reject SIG_IGN/NOCLDWAIT/unknown flags.
        for handler, flags, accepted in ((0, 0, True), (0, M.SA_RESTART, True),
                                         (0, M.SA_NOCLDSTOP, True), (1, 0, False),
                                         (0x2000, 0, False), (0, M.SA_NOCLDWAIT, False),
                                         (0, 0x0040, False), (0, 0x0100, False)):
            calls = []
            def sigaction_data(number, replacement, output):
                calls.append((number, replacement))
                observed = ctypes.cast(output, ctypes.POINTER(M.DarwinSigaction)).contents
                observed.handler, observed.mask, observed.flags = handler, 0, flags
                return 0
            api = M.DarwinAPI.__new__(M.DarwinAPI)
            api.deadline = M.Deadline()
            api.library = types.SimpleNamespace(sigaction=sigaction_data)
            with mock.patch.object(M.signal, "SIGCHLD", M.DARWIN_SIGCHLD), \
                    mock.patch.object(M.signal, "getsignal", return_value=M.signal.SIG_DFL):
                if accepted:
                    self.assertEqual(api.waitable_sigchld(), {"handler": 0, "mask": 0, "flags": flags})
                else:
                    with self.assertRaises(M.Refused):
                        api.waitable_sigchld()
            self.assertEqual(calls, [(M.DARWIN_SIGCHLD, None)])
        refused_policy = signal_policy_data()
        refused_policy.waitable_sigchld.side_effect = M.Refused("unit-native-SIGCHLD-not-waitable")
        owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, refused_policy)
        with mock.patch.object(M.subprocess, "Popen", side_effect=AssertionError("guard precedes claim")) as create:
            with self.assertRaises(M.Refused):
                owner.run()
            create.assert_not_called()
            self.assertFalse(owner.state["claimed"])
        # Real fixture EOF/close crossing the mock 10s clock cannot win the race
        # against command expiry, even with a zero raw terminal status.
        for late in ("EOF", "capture-close"):
            process = ProcessData(0)
            originals = (process.stdout, process.stderr)
            clock = [0.0]
            raw_read = os.read
            def late_read(descriptor, size):
                data = raw_read(descriptor, size)
                if not data:
                    clock[0] = M.COMMAND_SECONDS
                return data
            try:
                if late == "capture-close":
                    process.stdout = StreamCloseData(process.stdout,
                        after_close=lambda: clock.__setitem__(0, M.COMMAND_SECONDS))
                with mock.patch.object(M.time, "monotonic", side_effect=lambda: clock[0]):
                    owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
                    with command_data(process) as (_, waited, stopped), contextlib.ExitStack() as stack:
                        if late == "EOF":
                            stack.enter_context(mock.patch.object(M.os, "read", side_effect=late_read))
                        result = owner.run()
                        self.assertEqual(waited.call_count, 1)
                        stopped.assert_not_called()
                        self.assertEqual(result["retirement"], "settled")
                        self.assertIn("original-command-deadline", result["errors"])
                        self.assertFalse(M._command_acknowledged(result))
            finally:
                for stream in originals:
                    if not stream.closed:
                        stream.close()
        process = ProcessData(0)
        originals = (process.stdout, process.stderr)
        process.stdout = StreamCloseData(process.stdout, uncertain=True)
        try:
            owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
            with command_data(process):
                result = owner.run()
            self.assertEqual(result["retirement"], "unknown")
            self.assertFalse(result["stdoutClosed"])
            self.assertTrue(result["stderrClosed"])
            self.assertEqual(process.stdout.close_calls, 1)
            self.assertFalse(M._command_acknowledged(result))
        finally:
            # Explicit disposal of this test's real owned fixtures, not a second
            # production close attempt or a declaration of command retirement.
            for stream in originals:
                if not stream.closed:
                    stream.close()
        process = ProcessData(0)
        process.stdout.close()
        reader, writer = os.pipe()  # Keep this writer live: original stdout has no EOF.
        process.stdout = os.fdopen(reader, "rb", buffering=0)
        clock = [0.0]
        real_select = M.select.select
        def tick_select(readers, writers, errors, timeout):
            clock[0] += 1.0
            return real_select(readers, writers, errors, 0)
        try:
            with mock.patch.object(M.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(M.select, "select", side_effect=tick_select):
                owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, signal_policy_data())
                with command_data(process) as (_, waited, stopped):
                    result = owner.run()
                    self.assertEqual(waited.call_count, 1)  # Never re-wait after terminal status.
                    stopped.assert_not_called()
                    self.assertTrue(result["joinedOriginal"])
                    self.assertFalse(result["stdoutEof"])
                    self.assertTrue(result["stderrEof"])
                    self.assertEqual(result["retirement"], "unknown")
                    self.assertFalse(M._command_acknowledged(result))
        finally:
            os.close(writer)
            process.close_fixture()
        # Raw no-result waits alone arm stop routes; each signal consumes one.
        # Policy drift or the spent grace budget must forbid the second signal.
        for route_case in ("bounded-stop", "policy-drift", "past-stop-grace"):
            process = ProcessData(0)
            clock = [0.0]
            policy = signal_policy_data()
            if route_case == "policy-drift":
                policy.waitable_sigchld.side_effect = ([{"handler": 0, "mask": 0, "flags": 0}] * 5
                    + [M.Refused("unit-native-SIGCHLD-drift-before-kill")])
            def pending_wait(pid, options):
                self.assertEqual((pid, options), (process.pid, os.WNOHANG))
                process.wait_calls += 1
                if process.wait_calls == 1:
                    clock[0] = M.COMMAND_SECONDS
                if process.wait_calls <= 3 or route_case == "past-stop-grace":
                    return 0, 0
                return pid, int(M.signal.SIGKILL)
            def stop_tick(readers, writers, errors, timeout):
                clock[0] += 3.0 if route_case == "past-stop-grace" and process.signal_calls else 1.0
                return real_select(readers, writers, errors, 0)
            try:
                with mock.patch.object(M.time, "monotonic", side_effect=lambda: clock[0]), \
                        mock.patch.object(M.select, "select", side_effect=stop_tick):
                    owner = M.FixedCommandOwner(environment()["HOME"], M.Deadline(), 38, policy)
                    with command_data(process, pending_wait):
                        result = owner.run()
                self.assertFalse(M._command_acknowledged(result))
                self.assertFalse(owner.numeric_route)
                self.assertTrue(owner.numeric_retired)
                self.assertEqual(process.signal_calls[0], (process.pid, M.signal.SIGTERM))
                if route_case == "bounded-stop":
                    self.assertEqual(process.signal_calls, [(process.pid, M.signal.SIGTERM),
                                                            (process.pid, M.signal.SIGKILL)])
                    self.assertEqual(process.wait_calls, 4)
                    self.assertEqual(result["rawWaitStatus"], int(M.signal.SIGKILL))
                    self.assertEqual(result["retirement"], "settled")
                else:
                    self.assertEqual(len(process.signal_calls), 1)
                    self.assertEqual(result["retirement"], "unknown")
            finally:
                process.close_fixture()
        # Original result/input closes are all attempted even when one fails.
        book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
        for index in (502, 503):
            node = M.Node("/unit/" + str(index), "unit" + str(index), None, "/", "file", "source-file")
            node.fd = index
            book.nodes[node.path] = node
        book.result_fd = 501
        called = []
        def close_data(descriptor):
            called.append(descriptor)
            if descriptor in (501, 503):
                raise OSError(errno.EIO, "unit-close-error")
        with mock.patch.object(M.os, "close", side_effect=close_data):
            errors = book.close_all()
        self.assertEqual(called, [501, 503, 502])
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(node.fd is None for node in book.nodes.values()))
        for failure in (OrchestrationBookData(close_errors=["result-original-close-unknown"]),
                        OrchestrationBookData(fail_final=True)):
            returned, commands = orchestrated_no_effect(failure)
            self.assertEqual(returned, 1)
            self.assertEqual(commands, 0)
            self.assertEqual(failure.close_calls, 1)
            self.assertFalse(failure.records[-1][1]["prepared"])
        deadline = types.SimpleNamespace(end=10**12, check=mock.Mock(side_effect=[None, M.Refused("unit-final-deadline")]))
        with mock.patch.object(M, "Deadline", return_value=deadline):
            returned, _ = orchestrated_no_effect(OrchestrationBookData())
        self.assertEqual(returned, 1)

    def test_workflow_order_fixed_argv_and_unchanged_consumers(self):
        workflow = (ROOT / M.WORKFLOW).read_text()
        names = ["Select DATA stager Python, not the packaged interpreter",
                 "Reserve fresh private work before every candidate and toolchain query",
                 "Bind the complete reviewed first-party checkout before compilation",
                 "Prepare only the fixed disposable Xcode ancestor before any worker",
                 "Select fixed frontend compiler",
                 "Record exact source and actual tool bindings only after host preparation",
                 "Diagnose the real full-Xcode layout before compilation, separately from CLT",
                 "Check current owner pins before native preparation"]
        offsets = [workflow.index("      - name: " + name + "\n") for name in names]
        self.assertEqual(offsets, sorted(offsets))
        reserve = workflow[offsets[1]:offsets[2]]
        self.assertNotIn("subprocess", reserve)
        self.assertNotIn("--version", reserve)
        self.assertNotIn("xcrun", reserve)
        preparation = workflow[offsets[3]:offsets[4]]
        self.assertIn("timeout-minutes: 2", preparation)
        self.assertIn("shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}", preparation)
        self.assertIn("exec /usr/bin/env -i", preparation)
        producer = 'printf -v mrk_cf_encoding \'0x%X:0:0\' "$UID"'
        self.assertIn(producer, preparation)
        self.assertLess(preparation.index(producer), preparation.index("exec /usr/bin/env -i"))
        self.assertIn('__CF_USER_TEXT_ENCODING="$mrk_cf_encoding"', preparation)
        self.assertNotIn("$EUID", preparation)
        self.assertNotIn("$__CF_USER_TEXT_ENCODING", preparation)
        self.assertNotIn("${__CF_USER_TEXT_ENCODING", preparation)
        self.assertIn("'${{ steps.python.outputs.python-path }}' -I -S -B", preparation)
        self.assertNotIn("sudo", preparation)
        inventory = block(workflow, "PY_SOURCE")
        self.assertEqual(len(inventory), 2546)
        self.assertEqual(hashlib.sha256(inventory).hexdigest(),
                         "ccfec063d6e650101ea695cd97a5113f4d108568fc181d1abc6adc9272815a8c")
        self.assertIn('"$MRK_MACOS_WORK/source-binding.json"', workflow)
        self.assertEqual(M.COMMAND, ("/usr/bin/sudo", "-n", "--", "/bin/chmod", "-h", "0755", "/Applications"))
        self.assertNotIn("-R", M.COMMAND)
        self.assertNotIn("-f", M.COMMAND)
        self.assertIn("Application installation uses only standard privileged Installer", workflow)
        self.assertNotIn("Standard Installer only is privileged", workflow)
        self.assertIn("${{ steps.work.outputs.root }}/" + M.INTENT, workflow)
        self.assertIn("${{ steps.work.outputs.root }}/" + M.RESULT, workflow)
        self.assertIn("Nine serial current-iOS Aqua cases through the reviewed original invocation owner", workflow)
        self.assertIn("6b6376420b79bc9a60f6b549700e0e539f1e204d97e1bd07aea8032e3616e7ee", workflow)
        self.assertIn("81fb5b6babb560b27a7a42c69883de2bd65763d1faec4d215df057396dc76169", workflow)
        helper = PATH.read_text()
        self.assertEqual(helper.count("subprocess.Popen("), 1)
        self.assertNotIn("shell=True", helper)
        self.assertNotIn("self.process.poll(", helper)
        self.assertNotIn("self.process.wait(", helper)
        self.assertNotIn("self.process.terminate(", helper)
        self.assertNotIn("self.process.kill(", helper)
        self.assertIn('os.waitpid(self.state["originalPid"], os.WNOHANG)', helper)
        self.assertIn('os.kill(self.state["originalPid"], number)', helper)
        self.assertIn('_call(self.library.sigaction, DARWIN_SIGCHLD, None,', helper)
        self.assertNotIn("signal.signal(", helper)
        self.assertNotIn("os.environ.copy()", helper)
        self.assertNotIn("acl_get_fd_np(", helper)
        self.assertNotIn("os.chown(", helper)
        self.assertNotIn("os.setxattr(", helper)
        self.assertIn("ctypes.CDLL(\"/usr/lib/libSystem.B.dylib\", use_errno=True)", helper)
        self.assertIn("8b810050fab1aaf227de97edcfd0e55f6ae3fc2b", helper)
        self.assertIn('"fstatx_np": (integer, [integer, ctypes.POINTER(DarwinStat), pointer])', helper)
        self.assertIn('"fstatfs": (integer, [integer, ctypes.POINTER(DarwinStatFS)])', helper)
        self.assertIn('"prepared": False', helper)
        self.assertIn("owner.park_until_disposal()", helper)
        self.assertIn("final_errors.extend(book.close_all())", helper)


if __name__ == "__main__":
    unittest.main()
