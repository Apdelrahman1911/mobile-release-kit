"""Passive closed-source/fixture tests; no Mac, vendor, process or service IO."""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INPUTS = load("_tool_execution_inputs", "macos_tool_setup_inputs.py")
A = load("_tool_execution_preparation", "macos_android_dependency_preparation.py")
N = load("_tool_execution_clock", "macos_normal_ui_runner.py")
P = load("_tool_execution_relative", "macos_android_supplier_preparation.py")
OBS = load("_tool_execution_observer", "macos_aqua_qualification.py")
T = OBS.TOOLS


def service(ready=True, *, nonentry=False):
    return {"mechanism": "same-original-tool-service-prerequisite-v1",
        "execution": "ready" if ready else "not-executed-prerequisite",
        "finding": "ready" if ready else "service-unavailable" if nonentry else "approval-required",
        "requestCalls": 1, "checkCalls": int(ready), "normalQuitOriginal": 2,
        "requestAdmitted": not nonentry, "checkAdmitted": ready,
        "requestSettled": not nonentry, "checkSettled": ready, "knownNonentry": nonentry,
        "sameOriginalBindings": True, "allOriginalsSettled": True, "projectSentinelPreserved": True,
        "sourceInputsRead": False, "toolAcquisitionEntered": False, "settingsOpened": False,
        "serviceUnregistered": False, "productionQualified": False}


class PassiveOnly(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no native/process")))
        self.stack.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no HTTP")))
        self.stack.enter_context(patch.object(A, "N", N))
        self.stack.enter_context(patch.object(A, "P", P))


class ServiceReports(PassiveOnly):
    def test_ready_and_known_nonentry_are_distinct_after_real_caller_boundary(self):
        for value in (service(), service(False), service(False, nonentry=True)):
            self.assertIs(T.service_report(value, OBS.need), value)
            binding = OBS.Binding("a" * 40, "1", "1")
            expected = OBS.expected_result(binding, T.SERVICE_CASE)
            self.assertIsNone(expected["toolSetup"])
            expected["toolSetup"] = value
            framed = OBS.MARKER + json.dumps(expected, separators=(",", ":")).encode() + b"\n"
            self.assertEqual(OBS.parse_result(framed, b"", binding, T.SERVICE_CASE)["toolSetup"], value)
        # Request settled, followed by typed pre-admission Check refusal.
        value = service(False, nonentry=True)
        value.update(checkCalls=1, requestAdmitted=True, requestSettled=True)
        self.assertIs(T.service_report(value, OBS.need), value)

    def test_lost_admission_unknown_or_extra_registration_cannot_be_a_report(self):
        changes = (dict(requestCalls=2), dict(checkCalls=2), dict(requestCalls=True),
                   dict(requestSettled=False), dict(checkSettled=False), dict(knownNonentry=True),
                   dict(normalQuitOriginal=1), dict(allOriginalsSettled=False), dict(sourceInputsRead=True),
                   dict(settingsOpened=True), dict(serviceUnregistered=True), dict(productionQualified=True),
                   dict(finding="unknown"), dict(path="/not-an-authority"))
        for change in changes:
            value = service()
            value.update(change)
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                T.service_report(value, OBS.need)
        value = service(False, nonentry=True)
        value["requestAdmitted"] = True  # Admitted/lost is never typed nonentry.
        with self.assertRaises(OBS.Refused):
            T.service_report(value, OBS.need)

    def test_service_fixture_is_only_seven_project_files_no_source_preparation(self):
        self.assertEqual(OBS.selected_cases(T.SERVICE_SCOPE), T.SERVICE_CASES)
        self.assertEqual(OBS.case_timeout(T.SERVICE_CASE), 765)
        fixtures = OBS.Fixtures(OBS.Binding("a" * 40, "1", "1"), 501, 20, T.SERVICE_SCOPE)
        self.assertIsNone(fixtures.path)  # Actual pwd/held ancestry precedes use.
        files, directories = OBS.fixture_data(T.SERVICE_CASE, False)
        self.assertEqual(set(files), {"app/build.gradle.kts", "build.gradle.kts", "gradle/wrapper/gradle-wrapper.properties",
                                     "release/mobile-release.json", "version.properties", "keep.txt", ".gitignore"})
        self.assertEqual(len(directories), 5)
        self.assertIsNone(fixtures.tool_namespace)
        self.assertEqual(fixtures.tool_entered, set())

    def test_service_and_tool_project_roots_share_native_home_abi_not_tmp_or_home_env(self):
        binding = OBS.Binding("a" * 40, "2", "1")
        with patch.dict(os.environ, {"HOME": "/foreign", "TMPDIR": "/foreign"}):
            for flag, suffix in (("tool_setup", T.SCOPE), ("tool_service", T.SERVICE_SCOPE)):
                path = binding.root(**{flag: True}, native_home="/Users/runner")
                self.assertEqual(path, Path("/Users/runner/Library/Application Support")
                                 / f"mrk-macos-aqua-{binding.source}-2-1-{suffix}")
                self.assertNotEqual(path.parent, Path("/private/tmp"))
                with self.assertRaises(OBS.Refused):
                    binding.root(**{flag: True})
        # Existing identity/non-tools namespaces are unchanged.
        self.assertEqual(binding.root(identity_native=True).parent, Path("/private/tmp"))

    def test_tool_parent_replacement_refuses_and_same_existing_close_retains_fds(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-parent-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        (home / "Library").mkdir(mode=0o700)
        support = home / "Library/Application Support"
        support.mkdir(mode=0o700)
        fixtures = OBS.Fixtures(OBS.Binding("a" * 40, "2", "1"), 501, 20, T.SERVICE_SCOPE)
        self.addCleanup(fixtures.close)
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_dir=str(home))
        with patch("pwd.getpwuid", return_value=account):
            T.prepare_namespace(fixtures, OBS.need, OBS.signature)
        self.assertFalse(fixtures.path.exists())  # This test creates no fixture.
        retained = set(fixtures.fds)
        self.assertGreater(len(retained), 2)
        support.rename(home / "Library/retained")
        support.mkdir(mode=0o700)
        with self.assertRaises(OBS.Refused):
            T.namespace_current(fixtures, OBS.need, OBS.signature)
        self.assertEqual(fixtures.fds, retained)
        fixtures.close()
        self.assertFalse(fixtures.fds)


class FixturePreparation(PassiveOnly):
    def test_unreturned_child_retains_all_roots_and_close_failure_never_masks_first_error(self):
        roots = [{"fds": [1], "originals": ["first"]}, {"fds": [2], "originals": ["second"]}]
        attempt = {"roots": roots, "inflight": True}
        first = RuntimeError("inert original failure")
        close = OSError("inert close failure")
        # DATA-only original-book routing, not an actual descriptor/close proof.
        with patch.object(INPUTS, "_ATTEMPT", attempt), patch.object(A, "close_chain", side_effect=[close, None]) as consume:
            self.assertIs(INPUTS._close(A, first), first)
            consume.assert_not_called()
            attempt["inflight"] = False
            self.assertIs(INPUTS._close(A, first), first)
            self.assertEqual(consume.call_args_list, [unittest.mock.call([2], ["second"]),
                                                     unittest.mock.call([1], ["first"])])
        self.assertEqual(attempt["roots"], roots)

    def test_existing_task_leaf_is_not_adopted_overwritten_or_deleted(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-collision-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        parent = A.admit_work(root)
        self.addCleanup(lambda: A.close_chain(parent["fds"], parent["originals"]) if parent["fds"] else None)
        existing = root / INPUTS.CASES[0]
        existing.mkdir(mode=0o700)
        marker = existing / "preserve"
        marker.write_bytes(b"retained original interruption\n")
        before = A.nine(existing.stat())
        attempt = {"roots": [], "inflight": False}
        context = ("a" * 40, "2", "1", root, root, os.getuid(), os.getgid())
        with patch.object(INPUTS, "_ATTEMPT", attempt), patch.object(INPUTS, "_CONTEXT", context):
            with self.assertRaises(FileExistsError):
                INPUTS._new(A, parent, INPUTS.CASES[0], N.PhaseClock(810, now=lambda: 10))
        self.assertEqual(attempt["roots"], [])
        self.assertEqual(A.nine(existing.stat()), before)
        self.assertEqual(marker.read_bytes(), b"retained original interruption\n")

    def test_fixed_native_home_layout_and_no_tmp_or_environment_fallback(self):
        root = INPUTS.source_root("a" * 40, "2", "1", "/Users/runner", A.need)
        self.assertEqual(root, Path("/Users/runner/Library/Application Support/mrk-macos-tool-inputs-" + "a" * 40 + "-2-1"))
        with patch.dict(os.environ, {"HOME": "/foreign"}):
            self.assertEqual(INPUTS.source_root("a" * 40, "2", "1", "/Users/runner", A.need), root)
        for home in ("/", "relative", "/Users/runner/../other", "/Users//runner"):
            with self.subTest(home=home), self.assertRaises(A.Refused):
                INPUTS.source_root("a" * 40, "2", "1", home, A.need)
        # Real ordinary ancestry refusal, not a pretend successful Mac source.
        if Path("/tmp").is_dir() and Path("/tmp").stat().st_mode & 0o022:
            with self.assertRaises(A.Refused):
                A.chain(Path("/tmp"), retained=True)
        self.assertEqual(INPUTS.CASES, T.RUN_ORDER)

    def test_actual_current_catalogue_three_subsets_fit_each_existing_original(self):
        clock = N.PhaseClock(1200, now=lambda: 10)
        with patch.object(A, "SOURCE", ROOT):
            values = INPUTS.expected_cases(A, A.ui_source_roster(clock))
        self.assertEqual(tuple(sum(v[2] for v in value.values()) for value in values), INPUTS.BYTES)
        self.assertEqual(tuple(sum(v[0] == "file" for v in value.values()) for value in values), INPUTS.FILES)
        self.assertEqual(sum(INPUTS.BYTES), 783964776)
        self.assertTrue(all(len(value) <= A.ENTRIES and count <= A.FILES for value, count in zip(values, INPUTS.FILES)))
        self.assertTrue(all("build-tools" not in path and v[0] != "metadata" for value in values for path, v in value.items()))
        self.assertTrue(any(path.startswith("jdk/") for path in values[0]))
        self.assertTrue(all(path.startswith("sdk/") or path == "sdk" for value in values[1:] for path in value))
        archives = [r for r in A.ARCHIVES if r["role"] in INPUTS.ROLES]
        self.assertEqual([r["role"] for r in archives], list(INPUTS.ROLES))
        self.assertEqual(sum(r["bytes"] for r in archives), INPUTS.ARCHIVE_BYTES)

    def test_same_clock_aggregate_read_and_prewrite_debits_never_reset_per_case(self):
        clock = N.PhaseClock(810, now=lambda: 10)
        shared = INPUTS._Reads(A, clock)
        self.assertEqual(shared.maximum + INPUTS.parent_read_reserve(A), A.READ_BYTES)
        shared.reads = shared.maximum - 1
        shared.read(1)
        with self.assertRaises(A.Refused):
            shared.read(1)
        shared.writes = A.TOOL_BYTES - 1
        shared.file(1)
        with self.assertRaises(A.Refused):
            shared.file(1)
        self.assertEqual(shared.writes, A.TOOL_BYTES)
        self.assertEqual(clock.deadline - clock.started, 810_000_000_000)

    def test_new_source_uses_same_writer_roster_sealer_and_post_on_tiny_public_fixture(self):
        # A task-owned protected Linux DATA tree exercises byte/mode/close
        # mechanics only, not Mac ancestry, ACL, native acceptance or an archive.
        temporary = tempfile.TemporaryDirectory(prefix=".tool-input-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source, work = root / "source", root / "work"
        source.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        held = A.admit_work(source)
        self.addCleanup(lambda: A.close_chain(held["fds"], held["originals"]) if held["fds"] else None)
        body = b"public synthetic fixture\n"
        path = "sdk/platforms/android-35/source.properties"
        sha = hashlib.sha256(body).hexdigest()
        expected = {p: ("directory", 0o755, 0, None) for p in ("sdk", "sdk/platforms", "sdk/platforms/android-35")}
        expected[path] = ("file", 0o644, len(body), sha)
        clock = N.PhaseClock(810, now=lambda: 10)
        shared = INPUTS._Reads(A, clock)
        original = INPUTS._case_type(A)(work, held, expected, 1, shared)
        self.assertIs(original.clock, clock)
        original.role = next(r for r in original.archives if r["role"] == "sdk-platform")
        row = ("android-35/source.properties", "file", 0o100644, len(body), sha)
        original.begin(row)
        original.block(row[0], 0, body)
        original.end(row)
        roster = original.seal()
        self.assertEqual(shared.writes, len(body))
        self.assertEqual((source / path).read_bytes(), body)
        self.assertEqual((source / path).stat().st_mode & 0o777, 0o644)
        self.assertEqual(source.stat().st_mode & 0o777, 0o700)
        self.assertEqual(A._ui_tool_post(work, clock, expected, source), (roster, len(body), 1, 3))
        (source / path).write_bytes(b"changed synthetic bytes\n")
        with self.assertRaises(A.Refused):
            A._ui_tool_post(work, clock, expected, source)
        self.assertFalse(original.active)
        self.assertIsNone(original.archive_fd)

    def test_archive_reopen_refuses_tamper_before_correspondence_and_consumes_own_fd(self):
        temporary = tempfile.TemporaryDirectory(prefix=".tool-archive-passive-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source, work = root / "source", root / "work"
        source.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        path = work / "platform"
        path.write_bytes(b"original")
        path.chmod(0o600)
        before = A.nine(path.stat())
        role = {"role": "sdk-platform", "bytes": 8, "sha256": hashlib.sha256(b"original").hexdigest(), "archivePrefix": "android-35"}
        held = A.admit_work(source)
        self.addCleanup(lambda: A.close_chain(held["fds"], held["originals"]) if held["fds"] else None)
        compile_call = self.stack.enter_context(patch.object(A, "C", SimpleNamespace(compile_archive=lambda *args, **kw: self.fail("tamper reached parser"))))
        with patch.object(A, "ARCHIVES", [role]):
            original = INPUTS._case_type(A)(work, held, {}, 1, INPUTS._Reads(A, N.PhaseClock(810, now=lambda: 10)))
        path.write_bytes(b"tampered")
        with self.assertRaises(A.Refused):
            original.replay_platform((path, before))
        self.assertIsNone(original.archive_fd)
        self.assertEqual(path.read_bytes(), b"tampered")


if __name__ == "__main__":
    unittest.main()
