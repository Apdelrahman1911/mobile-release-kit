"""Focused regressions; NONE is a Mac/native preparation qualification.

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
import json
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
        "8f0082bc3909203b1bf67cbd3a42365e670853a46bae16a71fd9407d0659eaab",
    "desktop/native/macos-installed-native/src/native.m":
        "d65309035ac1ab231fee503ce9dcda570ded45735490ba80c80ef343bf5c7c5f",
    "desktop/src-tauri/src/ios_toolchain.rs":
        "acd508df197ab6369ba29e9f0e3eca781224ba74741af8f757b8d7c93d053b5f",
    "src/mobile_release/ios_archive_operation.py":
        "ca724e7943c9862608f4f23db3ffa4202a3904703600c9c338acb8667ee0a49a",
    "desktop/src-tauri/src/saved_command_owner.rs":
        "6046335845d909d6f3acc028831c017079029540ff6a9987ef907a978aedea4b",
    "desktop/src-tauri/src/installed_shell_observation_macos_ios.rs":
        "fc59e98648ca8c05919271c8f23149263741ab4d488bdba14285593e0fc07216",
}


def application(mode=0o775):
    # Deliberately synthetic test DATA, not historical/native FD evidence.
    return [7, 101, stat.S_IFDIR | mode, 0, 80, 2, 64,
            1790486400000000001, 1790486400000000002]


def observation(mode=0o775):
    return {"full9": application(mode), "flags": 0, "birthtimeNs": 100,
            "roster": ["Xcode.app"], "filesystem": {"typeName": "apfs", "fsid": [1, 2]},
            "acl": {"empty": True, "kind": "absent", "present": 0},
            "aclDiagnostic": {"unitDataOnly": True}, "xattrs": []}


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
        self.receipt_attempts = set()

    def recheck(self, phase, applications_transition=False):
        self.checks.append((phase, applications_transition))
        if phase == "final-before-closes" and self.fail_final:
            self.errors.append({"unitOnlyFinalPostError": True})

    def receipt(self, name, value, retain=False):
        self.receipt_attempts.add(name)
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
        # The original preparer and native consumer own this boundary. A second
        # pathname-based diagnostic previously rejected a valid job-owned alias.
        self.assertNotIn("PY_XCODE", workflow)
        self.assertNotIn("xcode-layout.json", workflow)
        self.assertNotIn("Diagnose the real full-Xcode layout", workflow)
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
        self.assertEqual(M.UF_COMPRESSED, 0x20)
        self.assertEqual(M.UF_HIDDEN, 0x8000)
        for policy, kind, extra in (("native", "directory", M.UF_HIDDEN),
                                    ("native", "file", M.UF_COMPRESSED),
                                    ("sudo", "file", M.UF_COMPRESSED),
                                    ("applications", "directory", 0), ("alias", "alias", 0),
                                    ("work", "directory", 0), ("source-file", "file", 0)):
            with self.subTest(policy=policy, kind=kind):
                allowed = M._observation_flags(policy, kind)
                self.assertEqual(allowed, M.KNOWN_PROTECTIVE_FLAGS | extra)
                for forbidden in (0x80, 0x2, 0x4, 0x8, 0x20000, 0x40000, 0x40000000):
                    self.assertNotEqual(forbidden & ~allowed, 0)
        self.assertEqual(M.MODE_ONLY_FLAGS & (M.UF_HIDDEN | M.UF_COMPRESSED), 0)

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
        # APFS counts each known child. These are labelled synthetic snapshots,
        # not a claim about the failed run's unpersisted post-result state.
        previous = observation(0o700)
        previous["full9"][3:6] = [501, 20, 3]
        previous["roster"] = [M.INVENTORY]
        current = copy.deepcopy(previous)
        current["full9"][5] = 4
        current["full9"][6] += 32
        current["full9"][7] += 1
        current["full9"][8] += 1
        current["roster"] = sorted([M.INVENTORY, M.INTENT])
        def transition(candidate, snapshot_error=False):
            book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
            book.work = types.SimpleNamespace(expected=copy.deepcopy(previous))
            def observe(*arguments):
                if snapshot_error:
                    book.error("unit", "work", "unit-snapshot-error")
                return candidate
            with mock.patch.object(book, "snapshot", side_effect=observe):
                book.refresh_work(M.INTENT)
            return book
        accepted = transition(copy.deepcopy(current))
        self.assertEqual(accepted.work.expected, current)
        self.assertEqual(accepted.work_names, current["roster"])
        self.assertEqual(len(accepted.work_transitions), 1)
        for fault in ("nlink-stays", "nlink-jumps", "identity", "extra-name", "flags",
                      "clock", "incomplete", "snapshot-error"):
            candidate = copy.deepcopy(current)
            if fault == "nlink-stays": candidate["full9"][5] = 3
            elif fault == "nlink-jumps": candidate["full9"][5] = 5
            elif fault == "identity": candidate["full9"][1] += 1
            elif fault == "extra-name": candidate["roster"].append("unit-unrelated")
            elif fault == "flags": candidate["flags"] = M.UF_HIDDEN
            elif fault == "clock": candidate["full9"][8] = previous["full9"][8] - 1
            elif fault == "incomplete": del candidate["acl"]
            with self.subTest(workFault=fault), self.assertRaisesRegex(
                    M.Refused, "^private-work-changed-beyond-own-receipt:"):
                transition(candidate, snapshot_error=fault == "snapshot-error")
        # Result readback must name the same original AFTER the bytes are read.
        book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
        fields = {"st_dev": 7, "st_ino": 11, "st_mode": stat.S_IFREG | 0o400,
                  "st_uid": 501, "st_gid": 20, "st_nlink": 1, "st_size": 2,
                  "st_mtime_ns": 100, "st_ctime_ns": 200}
        current = types.SimpleNamespace(**fields)
        replaced = types.SimpleNamespace(**{**fields, "st_ino": 12})
        book.work = types.SimpleNamespace(fd=78)
        book.result_fd, book.result_bytes = 79, b"{}"
        book.result_pin = {"name": M.RESULT, "full9": M.full9(current)}
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
        for owner, account, accepted in ((0, 501, True), (501, 501, True),
                                          (502, 501, False), (0, 0, False), (501, 0, False)):
            with self.subTest(aliasOwner=owner, account=account):
                self.assertEqual(M._selection_alias_owner(owner, account), accepted)
        # Only the selection alias allows the actual account. The concrete
        # sibling directory/tools still require root; no mode repair occurs.
        for kind, policy, owner, accepted in (("alias", "alias", 0, True),
                ("alias", "alias", 501, True), ("alias", "alias", 502, False),
                ("directory", "native", 0, True), ("directory", "native", 501, False)):
            mode = (stat.S_IFLNK if kind == "alias" else stat.S_IFDIR) | 0o755
            current = types.SimpleNamespace(st_mode=mode, st_uid=owner, st_gid=80, st_nlink=1, st_size=20)
            book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
            node = M.Node("/Applications/Xcode.app", "unit-selection", None, "Xcode.app", kind, policy)
            with self.subTest(kind=kind, owner=owner):
                self.assertTrue(book.metadata(node, current, "unit"))
                self.assertEqual(not book.errors, accepted)
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
        self.assertEqual(M.O_EXEC, 0x40000000)
        self.assertEqual(M.O_SYMLINK, 0x00200000)
        # Every syscall is intercepted: these FD integers are unit DATA only.
        for kind, policy, name, parent_path, expected_flags in (
                ("alias", "alias", "Xcode.app", "/Applications", M.O_SYMLINK | os.O_RDONLY),
                ("file", "sudo", "sudo", "/usr/bin", M.O_EXEC | os.O_NOFOLLOW),
                ("file", "native", "codesign", "/usr/bin", os.O_RDONLY | os.O_NOFOLLOW)):
            mode = (stat.S_IFLNK | 0o777) if kind == "alias" else stat.S_IFREG | 0o4555
            fields = dict(st_dev=7, st_ino=111, st_mode=mode, st_uid=0, st_gid=0,
                          st_nlink=1, st_size=12, st_mtime_ns=100, st_ctime_ns=101)
            named = types.SimpleNamespace(**fields)
            book = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
            parent = types.SimpleNamespace(path=parent_path, fd=72)
            snap = {"full9": M.full9(named), "aliasTarget": "Xcode_26.app"}
            with self.subTest(openRole=policy), mock.patch.object(book, "named_stat", return_value=named), \
                    mock.patch.object(book, "snapshot", return_value=snap), \
                    mock.patch.object(M.os, "open", return_value=71) as opened, \
                    mock.patch.object(M.os, "fstat", return_value=named), \
                    mock.patch.object(M.os, "close") as closed:
                node = book.open(parent, name, kind, policy, "unit-role")
                self.assertEqual(node.fd, 71)
                opened.assert_called_once_with(name, expected_flags | os.O_NONBLOCK | os.O_CLOEXEC,
                                               dir_fd=72)
                self.assertEqual(book.errors, [])
                self.assertEqual(book.close_all(), [])
                closed.assert_called_once_with(71)

    def test_sudo_snapshot_basis_requires_exact_role_protected_original_and_root_mount(self):
        # Entirely synthetic policy DATA, never a hosted filesystem observation.
        node = M.Node("/usr/bin/sudo", "os-provisioner-sudo", None, "sudo", "file", "sudo")
        fs = {"typeName": "apfs", "fsid": [1, 2], "owner": 0, "type": 26,
              "flags": M.MNT_RDONLY | M.MNT_LOCAL | M.MNT_ROOTFS | M.MNT_SNAPSHOT,
              "subtype": 0, "flagsExt": 0, "mountOn": "/", "mountFrom": "/dev/unit-snapshot"}
        snapshot = {"full9": [7, 111, stat.S_IFREG | 0o4511, 0, 0, 1, 120, 100, 101],
                    "flags": M.SF_RESTRICTED | M.UF_COMPRESSED, "filesystem": fs}
        basis = M._sudo_xattr_basis(node, snapshot, copy.deepcopy(fs))
        self.assertFalse(basis["observed"])
        self.assertEqual(basis["basis"], "same-held-readonly-root-apfs-snapshot")
        self.assertEqual(basis["filesystem"], fs)
        for field, value in (("path", "/tmp/sudo"), ("role", "another-tool"),
                              ("kind", "directory"), ("policy", "native")):
            changed = copy.copy(node)
            setattr(changed, field, value)
            with self.subTest(roleField=field), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(changed, snapshot, fs)
        for index, value in ((2, stat.S_IFREG | 0o511), (2, stat.S_IFREG | 0o4531),
                             (2, stat.S_IFREG | 0o4400), (2, stat.S_IFDIR | 0o4511),
                             (3, 501), (4, 80), (5, 2)):
            changed = copy.deepcopy(snapshot)
            changed["full9"][index] = value
            with self.subTest(originalField=index, value=value), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, changed, fs)
        for flags in (0, M.UF_COMPRESSED, M.SF_RESTRICTED | 0x40000000):
            with self.subTest(fileFlags=flags), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, {**snapshot, "flags": flags}, fs)
        for bit in (M.MNT_RDONLY, M.MNT_LOCAL, M.MNT_ROOTFS, M.MNT_SNAPSHOT):
            changed = {**fs, "flags": fs["flags"] & ~bit}
            with self.subTest(requiredMountBit=bit), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, {**snapshot, "filesystem": changed}, changed)
        for bit in (M.MNT_NOEXEC, M.MNT_NOSUID, M.MNT_UNION, M.MNT_IGNORE_OWNERSHIP, M.MNT_AUTOMOUNTED):
            changed = {**fs, "flags": fs["flags"] | bit}
            with self.subTest(forbiddenMountBit=bit), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, {**snapshot, "filesystem": changed}, changed)
        for key, value in (("typeName", "hfs"), ("owner", 501), ("mountOn", "/System/Volumes/Data")):
            changed = {**fs, key: value}
            with self.subTest(mountPolicy=key), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, {**snapshot, "filesystem": changed}, changed)
        for key, value in (("fsid", [1, 3]), ("type", 27), ("subtype", 1), ("flagsExt", 1),
                           ("mountFrom", "/dev/another-snapshot")):
            with self.subTest(rootMismatch=key), self.assertRaises(M.Refused):
                M._sudo_xattr_basis(node, snapshot, {**fs, key: value})
        changed = copy.deepcopy(snapshot)
        changed["xattrs"] = None
        changed["xattrStability"] = basis
        later = copy.deepcopy(changed)
        later["xattrStability"]["filesystem"]["fsid"][1] += 1
        self.assertFalse(M._same_snapshot(changed, later))

    def test_snapshot_uses_same_held_root_not_an_xattr_error_fallback(self):
        fs = {"typeName": "apfs", "fsid": [1, 2], "owner": 0, "type": 26,
              "flags": M.MNT_RDONLY | M.MNT_LOCAL | M.MNT_ROOTFS | M.MNT_SNAPSHOT,
              "subtype": 0, "flagsExt": 0, "mountOn": "/", "mountFrom": "/dev/unit-snapshot"}

        def observed(policy="sudo", changed_root=False, missing_root=False):
            api = types.SimpleNamespace(library=None,
                filesystem=mock.Mock(side_effect=lambda fd: ({**fs, "fsid": [1, 3]}
                    if fd == 72 and changed_root else copy.deepcopy(fs))),
                xattrs=mock.Mock(side_effect=OSError(errno.EACCES, "unit-only-unreadable")))
            book = M.Originals(api, {"uid": 501, "gid": 20}, M.Deadline())
            root = M.Node("/", "root", None, "/", "directory", "native")
            root.fd = 72  # Unit DATA only; every syscall below is intercepted.
            root.expected = {"filesystem": copy.deepcopy(fs)}
            if not missing_root:
                book.nodes["/"] = root
            node = M.Node("/usr/bin/sudo" if policy == "sudo" else "/usr/bin/codesign",
                          "os-provisioner-sudo" if policy == "sudo" else "signing-recovery:codesign",
                          root, "sudo" if policy == "sudo" else "codesign", "file", policy)
            node.fd = 71
            fields = dict(st_dev=7, st_ino=111,
                          st_mode=stat.S_IFREG | (0o4511 if policy == "sudo" else 0o755),
                          st_uid=0, st_gid=0, st_nlink=1, st_size=120,
                          st_mtime_ns=100, st_ctime_ns=101, st_flags=M.SF_RESTRICTED)
            current = types.SimpleNamespace(**fields)
            acl = {"empty": True, "kind": "absent", "present": 0, "errno": 0,
                   "snapshotFlags": current.st_flags, "snapshotBirthtimeNs": 99}
            with mock.patch.object(M.os, "fstat", return_value=current), \
                    mock.patch.object(book, "named_stat", return_value=current), \
                    mock.patch.object(M, "_acl_snapshot", return_value=acl):
                value = book.snapshot(node, "unit")
            return value, book, api

        value, book, api = observed()
        self.assertEqual(book.errors, [])
        self.assertIsNone(value["xattrs"])
        self.assertFalse(value["xattrStability"]["observed"])
        self.assertEqual(api.filesystem.call_args_list, [mock.call(71), mock.call(72)])
        api.xattrs.assert_not_called()
        for options in ({"changed_root": True}, {"missing_root": True}):
            value, book, api = observed(**options)
            self.assertTrue(book.errors)
            self.assertNotIn("xattrStability", value)
            book.applications = types.SimpleNamespace(pre={"full9": application(0o755)})
            self.assertIsNone(M._eligible_action(book))
        value, book, api = observed(policy="native")
        api.xattrs.assert_called_once_with(71)
        # OSError(EACCES, ...) is the standard PermissionError subclass.
        self.assertEqual(book.errors, [{"stage": "unit", "role": "signing-recovery:codesign",
                                        "code": "xattr-PermissionError", "errno": errno.EACCES}])
        self.assertNotIn("xattrStability", value)

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

        # Inert CDLL-shaped DATA exercises the actual fixed prototype binder.
        # No library is loaded and no filesystem/ACL/system call is performed.
        class FunctionData:
            def __init__(self, library, name):
                self.library, self.name = library, name

            def __call__(self, *arguments):
                self.library.calls.append(self.name)
                if self.name == "issetugid":
                    return 0
                if self.name == "sysctlbyname":
                    self.library.case.assertEqual(arguments[0], b"kern.osproductversion")
                    arguments[1].value = b"26.0"
                    ctypes.cast(arguments[2], ctypes.POINTER(ctypes.c_size_t)).contents.value = 5
                    return 0
                raise AssertionError("unit prototype binding must not invoke another native function")

        class LibraryData:
            def __init__(self, case, missing=None):
                self.case, self.missing = case, missing
                self.lookups, self.calls, self.functions = [], [], {}

            def __getattr__(self, name):
                self.lookups.append(name)
                if name == self.missing:
                    raise AttributeError(name)
                function = FunctionData(self, name)
                self.functions[name] = function
                return function

        for target, stat_name, fs_name in (
                (M.ARM_TARGET, "fstatx_np", "fstatfs"),
                (M.INTEL_TARGET, "fstatx_np$INODE64", "fstatfs$INODE64")):
            native = LibraryData(self)
            deadline = types.SimpleNamespace(check=lambda: None)
            with self.subTest(target=target), mock.patch.object(M.ctypes, "CDLL", return_value=native) as load:
                api = M.DarwinAPI(deadline, target=target)
                load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
                self.assertIs(api.deadline, deadline)
                self.assertEqual(api.version, "26.0")
            self.assertEqual(native.lookups, ["issetugid", "sigaction", "sysctlbyname", fs_name,
                "filesec_init", "filesec_free", stat_name, "filesec_get_property",
                "filesec_query_property", "acl_valid", "acl_get_entry", "acl_free", "flistxattr", "fgetxattr"])
            self.assertEqual(native.calls, ["issetugid", "sysctlbyname"])
            self.assertIs(native.fstatx_np, native.functions[stat_name])
            self.assertIs(native.fstatfs, native.functions[fs_name])
            self.assertIs(native.fstatx_np.restype, ctypes.c_int)
            self.assertEqual(native.fstatx_np.argtypes,
                             [ctypes.c_int, ctypes.POINTER(M.DarwinStat), ctypes.c_void_p])
            self.assertEqual(native.fstatfs.argtypes, [ctypes.c_int, ctypes.POINTER(M.DarwinStatFS)])
            for missing in (stat_name, fs_name):
                native = LibraryData(self, missing)
                with self.subTest(target=target, missing=missing), \
                        mock.patch.object(M.ctypes, "CDLL", return_value=native) as load, \
                        self.assertRaises(AttributeError):
                    M.DarwinAPI(deadline, target=target)
                self.assertEqual(load.call_count, 1)
                self.assertEqual(native.lookups.count(missing), 1)
                self.assertNotIn("fstatx_np" if "$" in stat_name else "fstatx_np$INODE64", native.lookups)
                self.assertNotIn("fstatfs" if "$" in fs_name else "fstatfs$INODE64", native.lookups)
                self.assertEqual(native.calls, [])
        with mock.patch.object(M.ctypes, "CDLL") as load, self.assertRaises(M.Refused):
            M.DarwinAPI(types.SimpleNamespace(check=lambda: None), target="i686-apple-darwin")
        load.assert_not_called()


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

        intel = environment()
        intel["RUNNER_ARCH"] = "X64"
        self.assertEqual(M._validate_context(intel, (501, 501, 20, 20),
            ("Darwin", "x86_64"), (3, 14, 7), (1, 1, 1), target=M.INTEL_TARGET)["machine"], "x86_64")
        for target, candidate, machine in (
                (M.ARM_TARGET, intel, "x86_64"), (M.INTEL_TARGET, environment(), "arm64"),
                (M.INTEL_TARGET, intel, "arm64"), (M.INTEL_TARGET, environment(), "x86_64"),
                ("i686-apple-darwin", intel, "x86_64"), ("", intel, "x86_64")):
            with self.subTest(target=target, machine=machine), self.assertRaises(M.Refused):
                M._validate_context(candidate, (501, 501, 20, 20),
                    ("Darwin", machine), (3, 14, 7), (1, 1, 1), target=target)

        # Actual entry routing, with every native/book effect stopped at the
        # original constructor seam. Same deadline and exact argv, no renewal.
        launches = (((), False, M.ARM_TARGET), ((M.CLASSIFICATION_ARG,), True, M.ARM_TARGET))
        launches += tuple((prefix + ("--target", target), bool(prefix), target)
                          for target in (M.ARM_TARGET, M.INTEL_TARGET)
                          for prefix in ((), (M.CLASSIFICATION_ARG,)))
        for arguments, classification, target in launches:
            self.assertEqual(M._entry_arguments(arguments), (classification, target))
            launch = (M.WORKSPACE + "/" + M.HELPER,) + arguments
            context = valid_context()
            context["machine"] = "arm64" if target == M.ARM_TARGET else "x86_64"
            book = types.SimpleNamespace(context=context, work=None, work_admitted=False,
                errors=[], receipt_attempts=set(), budget={"uncertain": False, "live": 0},
                error=lambda *args: None, close_all=mock.Mock(return_value=[]))
            deadline = types.SimpleNamespace(check=mock.Mock())
            with self.subTest(arguments=arguments), contextlib.ExitStack() as stack:
                made = stack.enter_context(mock.patch.object(M, "Deadline", return_value=deadline))
                stack.enter_context(mock.patch.object(M.sys, "argv", list(launch)))
                checked = stack.enter_context(mock.patch.object(M, "_validate_context", return_value=context))
                native = stack.enter_context(mock.patch.object(M, "DarwinAPI", return_value=types.SimpleNamespace(version="26.0")))
                originals = stack.enter_context(mock.patch.object(M, "Originals", return_value=book))
                for name in ("_collect_prerequisites", "_classify_installed"):
                    stack.enter_context(mock.patch.object(M, name, side_effect=M.Refused("unit-stop-before-effects")))
                command = stack.enter_context(mock.patch.object(M, "FixedCommandOwner",
                    side_effect=AssertionError("unit forbids preparation command")))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertEqual(M.main(), 1)
                made.assert_called_once_with()
                self.assertEqual(checked.call_args.kwargs, {"target": target})
                native.assert_called_once_with(deadline, target=target)
                self.assertIs(originals.call_args.args[2], deadline)
                self.assertEqual(originals.call_args.kwargs, {"classification": True} if classification else {})
                self.assertEqual(book.launch_argv, launch)
                book.close_all.assert_called_once_with()
                command.assert_not_called()
        for arguments in (("--target",), ("--target", "i686-apple-darwin"),
                ("--target", M.INTEL_TARGET, M.CLASSIFICATION_ARG),
                (M.CLASSIFICATION_ARG, "--target"), (M.CLASSIFICATION_ARG, "extra"),
                (M.CLASSIFICATION_ARG, M.CLASSIFICATION_ARG),
                ("--target", M.ARM_TARGET, "extra"), ("--target", M.ARM_TARGET, "extra", "extra")):
            with self.subTest(arguments=arguments), \
                    mock.patch.object(M.sys, "argv", [M.WORKSPACE + "/" + M.HELPER, *arguments]), \
                    mock.patch.object(M, "_validate_context") as checked, \
                    mock.patch.object(M.ctypes, "CDLL") as load, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(M.main(), 1)
                checked.assert_not_called()
                load.assert_not_called()

        # Real source-binding predicates, inert held-book DATA. In particular,
        # the workflow cap cannot become the helper/global cap or skip hashes.
        def source_book(workflow_size=319057, helper_size=16, mismatch=None):
            material = {M.WORKFLOW: b"w" * workflow_size, M.HELPER: b"h" * helper_size, M.TEST_SOURCE: b"t"}
            files = [{"path": name, "gitMode": "100644", "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                for name, data in sorted(material.items())]
            if mismatch is not None:
                row = next(row for row in files if row["path"] == M.WORKFLOW)
                row[mismatch] = row["size"] + 1 if mismatch == "size" else "0" * (40 if mismatch == "blob" else 64)
            context = valid_context()
            raw = json.dumps({"source": context["source"], "tree": M._inventory_tree(files), "files": files}).encode()
            book = types.SimpleNamespace(context=context, errors=[], classification=False,
                launch_argv=(M.WORKSPACE + "/" + M.HELPER, "--target", M.ARM_TARGET), reads=[])
            book.context_chain = lambda *args: types.SimpleNamespace(pre={"roster": [M.INVENTORY]})
            book.chain = lambda *args: None
            book.open = lambda parent, name, kind, policy, role: role
            def read(role, limit):
                book.reads.append((role, limit))
                data = raw if role == "complete-source-inventory" else material[role.removeprefix("source:")]
                if len(data) > limit:
                    raise M.Refused("unit-original-read-bound")
                return data
            book.read = read
            return book

        def bind(book, current_argv=None):
            with mock.patch.object(M.os, "getcwd", return_value=M.WORKSPACE), \
                    mock.patch.object(M, "__file__", M.WORKSPACE + "/" + M.HELPER), \
                    mock.patch.object(M.sys, "argv", list(book.launch_argv if current_argv is None else current_argv)):
                M._bind_source(book)

        for workflow_size, helper_size in ((319057, 16), (512 * 1024, 131072)):
            book = source_book(workflow_size, helper_size)
            bind(book)
            self.assertEqual(book.reads, [("complete-source-inventory", 2 * 1024 * 1024),
                ("source:" + M.WORKFLOW, 512 * 1024), ("source:" + M.HELPER, 131072)])
            self.assertEqual([row["size"] for row in book.source_binding["heldSourceBindings"]],
                             [workflow_size, helper_size])
        for arguments in ({"workflow_size": 512 * 1024 + 1}, {"helper_size": 131073},
                          {"mismatch": "size"}, {"mismatch": "sha256"}, {"mismatch": "blob"}):
            book = source_book(**arguments)
            with self.subTest(source=arguments), self.assertRaises(M.Refused):
                bind(book)
            self.assertFalse(hasattr(book, "source_binding"))
        for suffix in ((), (M.CLASSIFICATION_ARG,), ("--target", M.INTEL_TARGET)):
            book = source_book()
            with self.subTest(mutatedArgv=suffix), self.assertRaisesRegex(M.Refused, "^fixed-helper-launch-path-required$"):
                bind(book, (M.WORKSPACE + "/" + M.HELPER,) + suffix)
            self.assertFalse(hasattr(book, "source_binding"))
        for classification, target in ((True, M.ARM_TARGET), (False, M.INTEL_TARGET)):
            book = source_book()
            book.launch_argv = (M.WORKSPACE + "/" + M.HELPER,) + ((M.CLASSIFICATION_ARG,) if classification else ()) + ("--target", target)
            with self.subTest(bookMode=classification, bookTarget=target), self.assertRaisesRegex(
                    M.Refused, "^fixed-helper-launch-path-required$"):
                bind(book)


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
        # An exclusive result collision is one attempt, never overwrite/retry.
        originals = M.Originals(None, {"uid": 501, "gid": 20}, M.Deadline())
        originals.work = types.SimpleNamespace(fd=77)
        originals.work_admitted = True
        with mock.patch.object(M.os, "open", side_effect=FileExistsError(errno.EEXIST, "unit")) as opened:
            with self.assertRaises(FileExistsError):
                originals.receipt(M.RESULT, {"unitDataOnly": True})
            with self.assertRaisesRegex(M.Refused, "^receipt-name-already-attempted$"):
                originals.receipt(M.RESULT, {"unitDataOnly": True})
            self.assertEqual(opened.call_count, 1)
        # Main must preserve a failed attempted result and close originals,
        # rather than hide its postcondition failure behind a second EEXIST.
        failed = OrchestrationBookData()
        record = failed.receipt
        def failed_result(name, value, retain=False):
            pin = record(name, value, retain)
            if name == M.RESULT:
                raise M.Refused("unit-own-result-postcondition")
            return pin
        with mock.patch.object(failed, "receipt", side_effect=failed_result):
            returned, command_calls = orchestrated_no_effect(failed)
        self.assertEqual((returned, command_calls, failed.close_calls), (1, 0, 1))
        self.assertEqual([name for name, _, _ in failed.records].count(M.RESULT), 1)

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
                 "Record exact source and actual tool bindings only after route admission",
                 "Check current owner pins before native preparation"]
        offsets = [workflow.index("      - name: " + name + "\n") for name in names]
        self.assertEqual(offsets, sorted(offsets))
        reserve = workflow[offsets[1]:offsets[2]]
        self.assertNotIn("subprocess", reserve)
        self.assertNotIn("--version", reserve)
        self.assertNotIn("xcrun", reserve)
        preparation = workflow[offsets[3]:offsets[4]]
        self.assertEqual(workflow.count("      MRK_MACOS_AQUA_SCOPE: project-fields-android-inputs\n"), 1)
        admission = workflow.split("      - name: Admit only this exact disposable-hosted source route\n", 1)[1].split("\n      - name:", 1)[0]
        guard = '[[ "$MRK_MACOS_AQUA_SCOPE" == project-fields || "$MRK_MACOS_AQUA_SCOPE" == ios-current-synthetic || "$MRK_MACOS_AQUA_SCOPE" == xcode-installed-classification || "$MRK_MACOS_AQUA_SCOPE" == android-inputs || "$MRK_MACOS_AQUA_SCOPE" == project-fields-android-inputs ]]'
        self.assertIn(guard, admission)
        self.assertLess(admission.index(guard), admission.index("/usr/bin/uname"))
        self.assertEqual([line.strip() for line in preparation.splitlines() if line.strip().startswith("if:")],
                         ["if: success() && env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic'"])
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
        native_step = "Nine serial current-iOS Aqua cases through the reviewed original invocation owner"
        self.assertIn(native_step, workflow)
        self.assertLess(offsets[-1], workflow.index("      - name: " + native_step + "\n"))
        self.assertIn('"scopes": selected_scopes, "caseNames": case_names', workflow)
        self.assertIn('if aqua_scope not in scope_cases: raise ValueError("Aqua scope refused")', workflow)
        self.assertIn('"unselectedScopes": [scope for scope in native_scopes if scope not in selected_scopes]', workflow)
        self.assertIn("bb4f8aa1b9cf4dd0f3cad56ff37246be7839e41c7d86065c798deb9600aeea37", workflow)
        self.assertIn("f6a35d56777797d3a11032c0e800751f3a5ff9cff49ba62c69df700d82618371", workflow)
        diagnostics = block(workflow, "PY_DIAGNOSTICS").decode()
        self.assertIn('admitted_scopes = ("project-fields", "ios-current-synthetic", "android-inputs", "project-fields-android-inputs")', diagnostics)
        self.assertIn('if aqua_scope not in admitted_scopes: raise ValueError("Aqua scope refused")', diagnostics)
        self.assertIn('"requestedScope": aqua_scope', diagnostics)
        self.assertIn('"unselectedScopes": [scope for scope in native_scopes if scope not in selected_scopes]', diagnostics)
        self.assertIn('"scope": "bounded-diagnostic-snapshots-only-not-original-process-family-finality"', diagnostics)
        self.assertIn('name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ env.MRK_MACOS_AQUA_SCOPE }}', workflow)
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


class InstalledXcodesData:
    """Inert native/filesystem DATA. Every OS boundary below is intercepted.

    Runs the real ledger, metadata, snapshot, POST, report and close logic; the
    synthetic FD integers are never passed to an actual syscall or process.
    """
    def __init__(self, names=("Xcode_26.app",), common_extra=0):
        self.entries, self.contents, self.aliases = {}, {}, {}
        self.descriptors, self.positions, self.events = {}, {}, []
        self.next_fd = 701
        self.common_extra = common_extra
        self.close_unknown = None
        self.scan_close_unknown = None
        self.open_failure = None
        self.acl_unavailable = None
        self.drift = None
        self.late_close = None
        self.clock = [0.0]
        self.report = None
        self.stderr = io.StringIO()
        self.book = None
        self.add("/", stat.S_IFDIR | 0o755)
        self.add("/Applications", stat.S_IFDIR | 0o775, gid=80)
        self.add("/unit-work", stat.S_IFDIR | 0o700, uid=501, gid=20)
        self.add("/unit-work/" + M.INVENTORY, stat.S_IFREG | 0o600, uid=501, gid=20)
        for number in range(common_extra):
            self.add("/unit-common-" + str(number), stat.S_IFDIR | 0o755)
        for name in names:
            root = "/Applications/" + name
            for suffix in ("", "/Contents", "/Contents/Developer", "/Contents/Developer/usr",
                           "/Contents/Developer/usr/bin", "/Contents/Developer/Platforms",
                           "/Contents/Developer/Platforms/iPhoneOS.platform",
                           "/Contents/Developer/Platforms/iPhoneOS.platform/Developer",
                           "/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs",
                           "/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"):
                self.add(root + suffix, stat.S_IFDIR | 0o755)
            self.add(root + "/Contents/Developer/usr/bin/xcodebuild", stat.S_IFREG | 0o755)
        self.api = types.SimpleNamespace(version="26.unit-DATA", library=object(),
            filesystem=lambda fd: {"typeName": "apfs", "flags": M.MNT_LOCAL, "owner": 0, "fsid": [7, 8]},
            xattrs=lambda fd: [])

    def add(self, path, mode, uid=0, gid=0):
        self.entries[path] = types.SimpleNamespace(st_dev=7, st_ino=2**54 + len(self.entries),
            st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=1 if not stat.S_ISDIR(mode) else 2,
            st_size=0, st_mtime_ns=1790486400000000001, st_ctime_ns=1790486400000000002, st_flags=0)
        self.contents[path] = bytearray()
        parent = path.rsplit("/", 1)[0] or "/"
        if path != "/" and parent in self.entries:
            self.entries[parent].st_nlink += 1

    def alias(self, target="Xcode_26.app"):
        self.add("/Applications/Xcode.app", stat.S_IFLNK | 0o777, uid=501, gid=20)
        self.entries["/Applications/Xcode.app"].st_size = len(target)
        self.aliases["/Applications/Xcode.app"] = target

    def path(self, name, dir_fd=None):
        if dir_fd is None:
            return name
        return self.descriptors[dir_fd].rstrip("/") + "/" + name

    def named(self, name, *, dir_fd=None, follow_symlinks=False):
        if follow_symlinks:
            raise AssertionError("classification must never follow a DATA alias")
        return copy.copy(self.entries[self.path(name, dir_fd)])

    def opened(self, name, flags, mode=0o600, *, dir_fd=None):
        path = self.path(name, dir_fd)
        self.events.append(("open", path))
        if path == self.open_failure:
            raise OSError(errno.EIO, "unit-original-open-failed")
        if flags & os.O_CREAT:
            if path in self.entries:
                raise FileExistsError(errno.EEXIST, "unit-exclusive-collision")
            self.add(path, stat.S_IFREG | mode, uid=501, gid=20)
            parent = self.entries[self.descriptors[dir_fd]]
            parent.st_size += 32
            parent.st_mtime_ns += 1
            parent.st_ctime_ns += 1
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.descriptors[fd], self.positions[fd] = path, 0
        return fd

    def closed(self, fd):
        path = self.descriptors.pop(fd)
        self.positions.pop(fd)
        self.events.append(("close", path))
        if path == self.late_close:
            self.clock[0] = M.PREPARATION_SECONDS
        if path == self.close_unknown:
            raise OSError(errno.EIO, "unit-once-consuming-close-unknown")

    def scan(self, fd):
        path = self.descriptors[fd]
        names = [p.rsplit("/", 1)[-1] for p in self.entries if p != "/" and (p.rsplit("/", 1)[0] or "/") == path]
        fixture = self
        class IteratorData:
            def __init__(self):
                self.iterator = iter([types.SimpleNamespace(name=name) for name in sorted(names)])
            def __iter__(self): return self
            def __next__(self): return next(self.iterator)
            def close(self):
                fixture.events.append(("scan-close", path))
                if path == fixture.scan_close_unknown:
                    raise OSError(errno.EIO, "unit-scan-original-close-unknown")
        return IteratorData()

    def acl(self, library, fd, expected):
        path = self.descriptors[fd]
        value = {"empty": True, "kind": "absent", "present": 0, "phase": 0, "errno": 0,
                 "snapshotFull9": list(expected), "snapshotFlags": self.entries[path].st_flags,
                 "snapshotBirthtimeNs": 100, "filesecFreeReturned": True, "aclFreeResult": None}
        if path == self.acl_unavailable:
            value.update(empty=False, kind="unavailable", phase=2, errno=errno.EIO)
        if path == self.drift:
            self.entries[path].st_ctime_ns += 1
        return value

    def write(self, fd, data):
        path = self.descriptors[fd]
        self.contents[path].extend(data)
        self.positions[fd] += len(data)
        self.entries[path].st_size = len(self.contents[path])
        return len(data)

    def read(self, fd, size):
        offset = self.positions[fd]
        data = bytes(self.contents[self.descriptors[fd]][offset:offset + size])
        self.positions[fd] += len(data)
        return data

    def seek(self, fd, offset, whence):
        if whence != os.SEEK_SET:
            raise AssertionError("unit-fixed-seek-only")
        self.positions[fd] = offset
        return offset

    def bind(self, book):
        self.book = book
        root = book.nodes["/"]
        book.work = book.open(root, "unit-work", "directory", "work", "unit-work")
        book.work_admitted = True
        book.source_binding = {"unitDataOnly": True}
        for number in range(self.common_extra):
            book.open(root, "unit-common-" + str(number), "directory", "source-directory", "unit-common-" + str(number))

    @contextlib.contextmanager
    def patched(self):
        with contextlib.ExitStack() as stack:
            for name, function in (("stat", self.named), ("open", self.opened), ("close", self.closed),
                    ("fstat", lambda fd: copy.copy(self.entries[self.descriptors[fd]])),
                    ("scandir", self.scan), ("write", self.write), ("read", self.read), ("lseek", self.seek),
                    ("fsync", lambda fd: None),
                    ("fchmod", lambda fd, mode: setattr(self.entries[self.descriptors[fd]], "st_mode", stat.S_IFREG | mode)),
                    ("readlink", lambda name, dir_fd: self.aliases[self.path(name, dir_fd)])):
                stack.enter_context(mock.patch.object(M.os, name, side_effect=function))
            stack.enter_context(mock.patch.object(M, "_acl_snapshot", side_effect=self.acl))
            stack.enter_context(mock.patch.object(M, "_bind_source", side_effect=self.bind))
            stack.enter_context(mock.patch.object(M, "_validate_context", return_value=valid_context()))
            stack.enter_context(mock.patch.object(M, "DarwinAPI", return_value=self.api))
            stack.enter_context(mock.patch.object(M.time, "monotonic", side_effect=lambda: self.clock[0]))
            stack.enter_context(mock.patch.object(M.sys, "argv", [M.WORKSPACE + "/" + M.HELPER, M.CLASSIFICATION_ARG]))
            for name in ("FixedCommandOwner", "_collect_prerequisites"):
                stack.enter_context(mock.patch.object(M, name, side_effect=AssertionError("classification forbids preparation")))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            yield

    def run(self):
        with self.patched():
            status = M.main()
        raw = self.contents.get("/unit-work/" + M.CLASSIFICATION_RESULT)
        self.report = json.loads(raw) if raw else None
        return status


class MacOSXcodeClassificationTests(unittest.TestCase):
    def test_complete_chain_and_alias_are_observation_not_preparation(self):
        fixture = InstalledXcodesData()
        fixture.alias()
        self.assertEqual(fixture.run(), 0)
        report = fixture.report
        self.assertFalse(any(report[key] for key in ("prepared", "consumerQualified", "nativeQualified")))
        self.assertEqual(report["command"], {"claimed": False, "retirement": "not-started"})
        self.assertIsNone(report["intent"])
        self.assertEqual(report["applicationsActionStillRequired"], "chmod")
        self.assertTrue(report["classification"]["complete"])
        selection, concrete = report["classification"]["observations"]
        self.assertEqual((selection["outcome"], selection["selectionDataOnly"], selection["selectionTarget"]),
                         ("ineligible", True, "Xcode_26.app"))
        self.assertEqual((concrete["outcome"], concrete["completeChain"], len(concrete["objects"])), ("eligible", True, 11))
        self.assertTrue(all(item["strictPostMatched"] and item["finalClose"] == "closed" for item in concrete["objects"]))
        self.assertGreater(concrete["objects"][0]["preFull9"][1], 2**53)
        self.assertEqual(fixture.descriptors, {})
        self.assertEqual(fixture.book.budget["live"], 0)
        self.assertNotIn("/unit-work/" + M.INTENT, fixture.contents)
        self.assertNotIn("/unit-work/" + M.RESULT, fixture.contents)
        for forbidden in ("/usr/bin/sudo", "/bin/chmod", "/usr/bin/security", "/usr/bin/codesign"):
            self.assertNotIn(("open", forbidden), fixture.events)
        direct = InstalledXcodesData(names=("Xcode.app",))
        self.assertEqual(direct.run(), 0)
        self.assertEqual(direct.report["classification"]["observations"][0]["outcome"], "eligible")

    def test_stable_owner_mode_lower_tool_sdk_and_alias_type_negatives(self):
        for suffix, field, value in (("", "st_uid", 501), ("", "st_mode", stat.S_IFDIR | 0o777),
                ("/Contents/Developer/usr/bin/xcodebuild", "st_uid", 501),
                ("/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk", "st_uid", 501),
                ("/Contents/Developer/usr/bin/xcodebuild", "st_mode", stat.S_IFLNK | 0o777)):
            with self.subTest(suffix=suffix, field=field):
                fixture = InstalledXcodesData()
                fixture.alias()
                path = "/Applications/Xcode_26.app" + suffix
                setattr(fixture.entries[path], field, value)
                self.assertEqual(fixture.run(), 0)  # Complete negative is diagnostic success only.
                result = fixture.report["classification"]["observations"][-1]
                self.assertEqual(result["outcome"], "ineligible")
                self.assertFalse(result["completeChain"])
                self.assertTrue(result["reasons"])
                self.assertEqual(fixture.descriptors, {})
                if stat.S_ISLNK(fixture.entries[path].st_mode):
                    self.assertNotIn(("open", path), fixture.events)

    def test_sequential_aggregate40_custody_includes_scans_and_receipt(self):
        fixture = InstalledXcodesData(names=("Xcode_A.app", "Xcode_B.app"), common_extra=25)
        self.assertEqual(fixture.run(), 0)
        self.assertEqual(fixture.book.budget, {"live": 0, "peak": 40, "uncertain": False})
        last_a = max(index for index, event in enumerate(fixture.events) if event[0] == "close" and event[1].startswith("/Applications/Xcode_A.app"))
        first_b = min(index for index, event in enumerate(fixture.events) if event[0] == "open" and event[1].startswith("/Applications/Xcode_B.app"))
        self.assertLess(last_a, first_b)
        common_close = fixture.events.index(("close", "/Applications"))
        result_close = fixture.events.index(("close", "/unit-work/" + M.CLASSIFICATION_RESULT))
        self.assertLess(first_b, result_close)
        self.assertLess(result_close, common_close)
        book = M.Originals(None, valid_context(), M.Deadline(), budget={"live": 40, "peak": 40, "uncertain": False}, classification=True)
        book.work = types.SimpleNamespace(fd=1)
        book.work_admitted = True
        with mock.patch.object(M.os, "open", side_effect=AssertionError("over-budget open forbidden")) as opened:
            with self.assertRaisesRegex(M.Refused, "receipt-descriptor-bound"):
                book.receipt(M.CLASSIFICATION_RESULT, {})
            opened.assert_not_called()
        for classification, forbidden in ((True, M.INTENT), (True, M.RESULT), (False, M.CLASSIFICATION_RESULT)):
            ledger = M.Originals(None, valid_context(), M.Deadline(), classification=classification)
            ledger.work, ledger.work_admitted = types.SimpleNamespace(fd=1), True
            with self.assertRaisesRegex(M.Refused, "receipt-private-work-unavailable"):
                ledger.receipt(forbidden, {})

    def test_uncertain_reads_topology_partial_open_and_close_stop_next_candidate(self):
        for failure in ("acl_unavailable", "drift", "open_failure", "close_unknown"):
            with self.subTest(failure=failure):
                fixture = InstalledXcodesData(names=("Xcode_A.app", "Xcode_B.app"))
                path = "/Applications/Xcode_A.app/Contents/Developer/usr/bin/xcodebuild"
                setattr(fixture, failure, path)
                self.assertEqual(fixture.run(), 1)
                self.assertFalse(any(event[0] == "open" and event[1].startswith("/Applications/Xcode_B.app") for event in fixture.events))
                self.assertEqual(fixture.descriptors, {})
                closes = [event for event in fixture.events if event == ("close", path)]
                self.assertEqual(len(closes), 0 if failure == "open_failure" else 1)
                if failure == "close_unknown":
                    self.assertTrue(fixture.book.budget["uncertain"])
                    self.assertEqual(fixture.book.budget["live"], 1)
                    # Keep this ledger in its original fixture clock; do not renew its deadline.
                    with mock.patch.object(M.time, "monotonic", side_effect=lambda: fixture.clock[0]), \
                            self.assertRaisesRegex(M.Refused, "original-close-uncertain"):
                        fixture.book.reserve("unit")
                    self.assertIn("xcodebuild:original-close-unknown", fixture.stderr.getvalue())
                    close_index = fixture.events.index(("close", path))
                    self.assertFalse(any(event[0] == "open" for event in fixture.events[close_index + 1:]))
                else:
                    self.assertIsNotNone(fixture.report)
                    self.assertFalse(fixture.report["classification"]["complete"])
                    self.assertEqual(fixture.report["classification"]["observations"][0]["outcome"], "unresolved")

    def test_same_absolute_deadline_report_bound_and_final_close_are_not_success(self):
        for path in ("/Applications/Xcode_A.app", "/unit-work/" + M.CLASSIFICATION_RESULT, "/"):
            with self.subTest(lateClose=path):
                fixture = InstalledXcodesData(names=("Xcode_A.app", "Xcode_B.app"))
                fixture.late_close = path
                self.assertEqual(fixture.run(), 1)
                self.assertEqual(fixture.descriptors, {})
                if path.startswith("/Applications/"):
                    self.assertNotIn(("open", "/Applications/Xcode_B.app"), fixture.events)
        fixture = InstalledXcodesData(names=("Xcode_A.app", "Xcode_B.app"))
        with mock.patch.object(M, "MAX_RECORD", 12288):
            self.assertEqual(fixture.run(), 1)
        self.assertNotIn(("open", "/Applications/Xcode_B.app"), fixture.events)
        self.assertFalse(fixture.report["classification"]["complete"])
        self.assertEqual(fixture.report["classification"]["omittedObservations"], 1)
        self.assertLessEqual(len(fixture.contents["/unit-work/" + M.CLASSIFICATION_RESULT]), 12288)
        fixture = InstalledXcodesData()
        fixture.close_unknown = "/unit-work/" + M.CLASSIFICATION_RESULT
        self.assertEqual(fixture.run(), 1)
        self.assertTrue(fixture.book.budget["uncertain"])
        self.assertEqual(fixture.descriptors, {})
        for argv in (["--classify"], [M.CLASSIFICATION_ARG, "extra"], [M.CLASSIFICATION_ARG, M.CLASSIFICATION_ARG]):
            with mock.patch.object(M.sys, "argv", [M.WORKSPACE + "/" + M.HELPER, *argv]), \
                    mock.patch.object(M, "DarwinAPI", side_effect=AssertionError("invalid argv before native load")) as api, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(M.main(), 1)
                api.assert_not_called()

    def test_roster_bound_and_transient_scan_close_uncertainty_stop_observation(self):
        fixture = InstalledXcodesData()
        for number in range(M.MAX_ENTRIES):
            fixture.add("/Applications/unselected-" + str(number), stat.S_IFDIR | 0o755)
        self.assertEqual(fixture.run(), 1)
        self.assertNotIn(("open", "/Applications/Xcode_26.app"), fixture.events)
        self.assertEqual(fixture.descriptors, {})
        fixture = InstalledXcodesData()
        fixture.scan_close_unknown = "/Applications"
        self.assertEqual(fixture.run(), 1)
        self.assertIn('"role":"applications"', fixture.stderr.getvalue())
        self.assertIn('"code":"roster-original-close-unknown"', fixture.stderr.getvalue())
        closed = fixture.events.index(("scan-close", "/Applications"))
        self.assertFalse(any(event[0] == "open" for event in fixture.events[closed + 1:]))
        self.assertEqual(fixture.descriptors, {})
        ledger = M.Originals(None, valid_context(), M.Deadline(), classification=True)
        iterator = types.SimpleNamespace(close=mock.Mock(side_effect=OSError(errno.EIO, "unit-scan-close-unknown")))
        class ScanData:
            def __iter__(self): return iter(())
            def close(self): iterator.close()
        with mock.patch.object(M.os, "scandir", return_value=ScanData()):
            with self.assertRaises(OSError):
                ledger.roster(types.SimpleNamespace(fd=77, role="unit-scan"))
        iterator.close.assert_called_once_with()
        self.assertEqual(ledger.budget, {"live": 1, "peak": 1, "uncertain": True})
        with self.assertRaisesRegex(M.Refused, "original-close-uncertain"):
            ledger.reserve("unit")


if __name__ == "__main__":
    unittest.main()
