"""Pure coordinator regressions, not hosted isolation or native-test evidence.

Filesystem cases use only task-owned temporary data; root chown is always an
inert double and chmod is either forbidden or confined to enumerated fixtures.
Finalization uses an inert Session double, never the real owner or a process.
Ruby completion text is synthetic parser input, never a native test receipt.
"""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import dataclasses
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from .test_ci_verification import ROOT, controller_module, fixture_paths


def report_fixture(ok=True):
    result = {"schema": 1, "ok": ok, "cleanup_errors": [],
              "rows": [{"id": "source-integrity", "status": "PASS" if ok else "FAIL"}]}
    if not ok:
        result["error"] = "UPSTREAM_FIXTURE_FAILURE"
    return result


def session_fixture(events, *, close_action=None, finish_action=None):
    """Only the finalizer's tiny result contract; no Session construction/import."""
    session = SimpleNamespace(domain_finality=False, persisted_bytes=0, failure=None, cleanup_errors=[])

    def close(*, keep_timer):
        events.append(("close", keep_timer))
        session.domain_finality, session.persisted_bytes = True, 37
        if close_action is not None:
            close_action(session)

    def finish():
        events.append(("finish",))
        if finish_action is not None:
            finish_action(session)

    session.close, session.finish = close, finish
    return session


class CICoordinatorFilesystemTests(unittest.TestCase):
    def test_regular_reader_rejects_aliases_and_multiple_links_without_reading_the_target(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-reader-") as temporary:
            root = Path(temporary).resolve()
            actual = root / "actual"
            actual.mkdir()
            target = actual / "data"
            target.write_bytes(b"owned fixture bytes")
            alias = root / "ancestor-alias"
            alias.symlink_to(actual, target_is_directory=True)
            leaf = actual / "leaf-alias"
            leaf.symlink_to(target)
            opened, read = Mock(wraps=os.open), Mock(wraps=os.read)
            facade = SimpleNamespace(open=opened, read=read, fstat=os.fstat, close=os.close,
                                     O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
            with patch.object(controller, "os", facade), \
                    patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                self.assertEqual(controller.read_regular(target, deadline=2.0), b"owned fixture bytes")
                for path in (Path("relative-fixture"), alias / "data"):
                    opened.reset_mock()
                    read.reset_mock()
                    with self.subTest(path=path), self.assertRaisesRegex(controller.VerificationError, "FILE_PARENT_ALIAS"):
                        controller.read_regular(path, deadline=2.0)
                    opened.assert_not_called()
                    read.assert_not_called()
                read.reset_mock()
                with self.assertRaises(OSError):
                    controller.read_regular(leaf, deadline=2.0)
                read.assert_not_called()
                linked = root / "another-name"
                os.link(target, linked)
                with self.assertRaisesRegex(controller.VerificationError, "FILE_TYPE_OR_BOUND"):
                    controller.read_regular(target, deadline=2.0)
                read.assert_not_called()
            self.assertEqual(target.read_bytes(), b"owned fixture bytes")
            self.assertEqual(linked.stat().st_ino, target.stat().st_ino)

    def test_freeze_rejects_alias_roots_unapproved_links_hardlinks_and_walk_errors_before_changes(self):
        controller = controller_module()
        cases = {"root-link": "FREEZE_ROOT_NOT_DIRECTORY", "ancestor-link": "FREEZE_ROOT_NOT_DIRECTORY",
                 "regular-root": "FREEZE_ROOT_NOT_DIRECTORY", "unapproved-link": "FREEZE_UNAPPROVED_LINK",
                 "hardlink": "FREEZE_HARDLINK", "walk-error": "FILESYSTEM_WALK_FAILED"}
        with tempfile.TemporaryDirectory(prefix="mrk-ci-freeze-reject-") as temporary:
            base = Path(temporary).resolve()
            for case, error in cases.items():
                with self.subTest(case=case):
                    parent = base / case
                    parent.mkdir()
                    actual = parent / "actual"
                    actual.mkdir()
                    root = actual
                    foreign = parent / "outside-the-selected-tree"
                    foreign.write_bytes(b"must remain unchanged")
                    foreign.chmod(0o600)
                    if case == "root-link":
                        root = parent / "alias"
                        root.symlink_to(actual, target_is_directory=True)
                    elif case == "ancestor-link":
                        (actual / "child").mkdir()
                        (parent / "alias").symlink_to(actual, target_is_directory=True)
                        root = parent / "alias/child"
                    elif case == "regular-root":
                        root = foreign
                    elif case == "unapproved-link":
                        (root / "entry").symlink_to(foreign)
                    elif case == "hardlink":
                        os.link(foreign, root / "entry")

                    def broken_walk(_root, *, followlinks, onerror):
                        self.assertIs(followlinks, False)
                        onerror(OSError("synthetic directory enumeration failure"))
                        raise AssertionError("walk failure was ignored")

                    walk = Mock(wraps=broken_walk if case == "walk-error" else os.walk)
                    chown = Mock()
                    chmod = Mock(side_effect=AssertionError("rejected fixture must not be chmodded"))
                    with patch.object(controller, "os", SimpleNamespace(walk=walk, chown=chown, chmod=chmod)), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                        with self.assertRaisesRegex(controller.VerificationError, error):
                            controller.freeze_tree(root, deadline=2.0)
                    chown.assert_not_called()
                    chmod.assert_not_called()
                    if case in {"root-link", "ancestor-link", "regular-root"}:
                        walk.assert_not_called()
                    self.assertEqual(foreign.read_bytes(), b"must remain unchanged")
                    self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o600)

    def test_freeze_keeps_confined_venv_links_and_never_chmods_their_provider_targets(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-freeze-venv-") as temporary:
            base = Path(temporary).resolve()
            root, provider = base / "venv", base / "provider"
            directories = [root, root / "bin", root / "lib", root / "lib/python3.11",
                           root / "lib/python3.11/site-packages"]
            for directory in directories:
                directory.mkdir()
            provider.mkdir()
            external = provider / "python"
            external.write_bytes(b"provider fixture, never executed")
            external.chmod(0o700)
            binary = root / "bin/python"
            binary.write_bytes(b"owned fixture, never executed")
            binary.chmod(0o700)
            package = root / "lib/python3.11/site-packages/fixture.py"
            package.write_bytes(b"# data-only fixture\n")
            package.chmod(0o600)
            links = (root / "lib64", root / "bin/python3", root / "bin/provider-python")
            links[0].symlink_to("lib", target_is_directory=True)
            links[1].symlink_to("python")
            links[2].symlink_to(external)
            permitted = {*directories, binary, package}
            changed = []

            def chmod(path, mode):
                path = Path(path)
                self.assertIn(path, permitted)
                self.assertFalse(path.is_symlink())
                changed.append(path)
                os.chmod(path, mode)

            chown = Mock()  # Never attempt an actual root-only ownership change.
            try:
                with patch.object(controller, "os", SimpleNamespace(walk=os.walk, chown=chown, chmod=chmod)), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                    controller.freeze_tree(root, deadline=2.0, link_roots=(root, provider))
                self.assertEqual(set(changed), permitted)
                for directory in directories:
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE(package.stat().st_mode), 0o444)
                self.assertTrue(all(path.is_symlink() for path in links))
                self.assertEqual([path.resolve() for path in links], [root / "lib", binary, external])
                for link in links:
                    calls = [call for call in chown.call_args_list if Path(call.args[0]) == link]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0].args[1:], (0, 0))
                    self.assertEqual(calls[0].kwargs, {"follow_symlinks": False})
                self.assertEqual(external.read_bytes(), b"provider fixture, never executed")
                self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)
            finally:
                # Restore only these pre-enumerated task-owned real directories,
                # so ordinary non-root TemporaryDirectory cleanup also works.
                for directory in directories:
                    directory.chmod(0o700)


class CICoordinatorResultTests(unittest.TestCase):
    def test_failed_ruby_diagnostics_keep_only_source_known_ids_and_locations(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        step = controller.Step("ruby-native-capture", parser="minitest")
        known, assertion = controller.ruby_expected_ids(ROOT, step.id)[:2]
        private = "private-fixture-value-must-not-be-published"
        text = (f"1) Error:\n{known}:\nRuntimeError: {private}\n"
                f" /private/{private}/source/tests/workflow/test_native_upload_validation.rb:42:in method\n"
                f"2) Failure:\n{assertion} [/private/{private}/source/tests/workflow/test_native_upload_validation.rb:45]:\n"
                "UnknownSuite#test_private_value:\n"
                f" /private/{private}/private_fixture.rb:17\n"
                "13 runs, 100 assertions, 1 failures, 1 errors, 0 skips\n"
                'MRK_CHECK_RESULT={"details":{},"details":{}}\n'
                'MRK_CHECK_RESULT={"details":null}\n'
                'MRK_CHECK_RESULT={"details":{"error":NaN}}\n')
        captured = SimpleNamespace(returncode=7, waited=True, stdout_eof=True, stderr_eof=True,
                                   domain_finality=True, timed_out=False, cancelled=False,
                                   stdout=text.encode(), stderr=b"",
                                   persisted=(len(text), 0), duration=0.2, cleanup_errors=())
        details = controller.failure_details(captured, step, paths)
        self.assertEqual(details["returncode"], 7)
        self.assertEqual(details["failed_tests"], sorted([known, assertion]))
        self.assertEqual(details["ruby_locations"], [("tests/workflow/test_native_upload_validation.rb", 42),
                                                    ("tests/workflow/test_native_upload_validation.rb", 45)])
        self.assertEqual(details["minitest_observations"], [[13, 100, 1, 1, 0]])
        for hidden in (private, "UnknownSuite", "test_private_value", "private_fixture.rb", "/private/"):
            self.assertNotIn(hidden, json.dumps(details))
        # Malformed diagnostic text or unavailable diagnostic source cannot
        # replace the actual failed command's status with a parser exception.
        with patch.object(controller, "ruby_expected_ids", side_effect=controller.VerificationError("RUBY_STATIC_INVENTORY")):
            unavailable = controller.failure_details(captured, step, paths)
        self.assertEqual(unavailable["returncode"], 7)
        self.assertTrue(unavailable["ruby_diagnostics_unavailable"])
        self.assertNotIn("failed_tests", unavailable)
        with patch.object(controller, "strict_json", side_effect=RecursionError):
            self.assertEqual(controller.failure_details(captured)["returncode"], 7)

    def test_every_ruby_suite_requires_its_exact_class_and_method_completion_inventory(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        suites = {
            "ruby-support": ("test_fastlane_support.rb", {"FastlaneReleaseSupportTest"}, 12),
            "ruby-native-capture": ("test_native_upload_validation.rb", {"NativeUploadValidationTest"}, 13),
            "ruby-play_store": ("test_play_store.rb", {"PreservingSupplyUploaderTests"}, 35),
            "ruby-play_lanes": ("test_play_lanes.rb", {"PlayReleaseLanesTest", "BoundedPlayImageTest"}, 46),
            "ruby-apple_store": ("test_apple_store.rb", {"AppleOperationTransportTest", "AppleStoreContractTest"}, 7),
            "ruby-apple_lanes": ("test_apple_lanes.rb", {"AppleReleaseLanesTest"}, 23),
            "ruby-apple_production": ("test_apple_production.rb", {"AppleProductionTest", "AppleCreateRetryContractTest"}, 47),
            "ruby-apple_production_lane": ("test_apple_production_lane.rb", {"AppleProductionLaneTest"}, 2),
            "ruby-apple_asset_upload": ("test_apple_asset_upload.rb", {"AppleAssetUploadTest"}, 8),
            "ruby-ios_upload_validation": ("test_ios_upload_validation.rb", {"IosUploadValidationTest"}, 26),
            "ruby-android_upload_validation": ("test_android_upload_validation.rb", {"AndroidUploadValidationTest"}, 26),
            "ruby-workflow-yaml": ("test_workflow_yaml.rb", {"WorkflowYamlStructureTest"}, 1),
        }
        shared_literal = {
            "test_deadline_terminates_validator_without_authorizing_upload",
            "test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits",
            "test_descendant_boundary_survives_delayed_start_and_late_parent_record",
            "test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record",
            "test_fixture_detects_leader_only_cleanup_and_missing_deadline",
            "test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed",
            "test_slow_cleanup_cannot_supply_a_positive_deadline_wait",
            "test_driver_termination_stops_startup_and_orphan_via_control_eof",
            "test_process_observation_rejects_errors_malformed_output_and_foreign_groups",
            "test_setup_primary_survives_cleanup_failure_and_real_queued_cancellation",
            "test_indeterminate_observations_never_prove_readiness_or_renew_native_death_budget",
        }
        shared = (ROOT / "tests/workflow/upload_process_fixture.rb").read_text().split("  module Contracts\n")
        self.assertEqual(len(shared), 2)
        self.assertEqual({line.removeprefix("    def ").strip() for line in shared[1].splitlines()
                          if line.startswith("    def test_")}, shared_literal)
        shared_ids = shared_literal | {
            "test_process_ownership_" + family + "_through_both_real_fixture_callers"
            for family in ("async", "signals", "policies", "unknown")
        }
        gates = {step.id: step for step in controller.catalog(paths, "linux", deadline=20.0)
                 if step.parser == "minitest"}
        self.assertEqual(set(gates), set(suites))
        for gate, (filename, expected_classes, count) in suites.items():
            with self.subTest(gate=gate):
                # Independent line-by-line source inventory, not the production
                # collector's regex/class-body splitting or its returned IDs.
                owner, classes, ids = None, set(), []
                for line in (ROOT / "tests/workflow" / filename).read_text().splitlines():
                    if line.startswith("class "):
                        owner = line.split()[1] if line.rstrip().endswith(" < Minitest::Test") else None
                        if owner is not None:
                            classes.add(owner)
                    elif line == "end":
                        owner = None
                    elif owner is not None and line.startswith("  def test_"):
                        name = line.removeprefix("  def ").strip()
                        self.assertRegex(name, r"^test_[A-Za-z0-9_]+$")
                        ids.append(owner + "#" + name)
                    elif owner is not None and line == "  include UploadProcessFixture::Contracts":
                        ids.extend(owner + "#" + name for name in shared_ids)
                expected = tuple(sorted(ids))
                self.assertEqual(classes, expected_classes)
                self.assertEqual(len(expected), count)
                self.assertEqual(len(set(expected)), count)
                self.assertEqual(controller.ruby_expected_ids(ROOT, gate), expected)
                self.assertEqual(gates[gate].expected_tests, count)

                def capture(completed):
                    text = "".join(identifier + " = 0.00 s = .\n" for identifier in completed)
                    text += f"\n{count} runs, {count * 3} assertions, 0 failures, 0 errors, 0 skips\n"
                    return SimpleNamespace(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                                           domain_finality=True, primary_error=None, cleanup_errors=(),
                                           stdout=text.encode("ascii"), stderr=b"", duration=0.01)

                parsed = controller.parse_capture(gates[gate], capture(reversed(expected)), paths, "linux", None)
                self.assertTrue(parsed.ok)
                self.assertEqual(sorted(parsed.details["completed"]), list(expected))
                wrong_method = expected[0].split("#")[0] + "#test_unknown_fixture_contract"
                wrong_class = "WrongFixtureSuite#" + expected[0].split("#")[1]
                mutations = [(wrong_method, *expected[1:]), (wrong_class, *expected[1:])]
                if count > 1:
                    mutations.append((expected[1], *expected[1:]))  # Same count, duplicate ID.
                for mutated in mutations:
                    with self.assertRaisesRegex(controller.VerificationError, "MINITEST_COMPLETION_INVENTORY"):
                        controller.parse_capture(gates[gate], capture(mutated), paths, "linux", None)
        # QA-003 is a separate source patch with additional native obligations.
        # Its mere presence cannot silently inherit this smaller fixed matrix.
        with tempfile.TemporaryDirectory(prefix="mrk-ci-catalog-boundary-") as temporary:
            other_source = Path(temporary).resolve()
            sentinel = other_source / "src/mobile_release/local_signing.py"
            sentinel.parent.mkdir(parents=True)
            sentinel.write_bytes(b"raise AssertionError('data-only fixture must never be imported')\n")
            for platform in ("linux", "macos"):
                with self.subTest(unintegrated_source=platform), self.assertRaisesRegex(
                        controller.VerificationError, "LOCAL_SIGNING_MATRIX_REQUIRES_CATALOG_AMENDMENT"):
                    controller.catalog(dataclasses.replace(paths, source=other_source), platform, deadline=20.0)

    def test_final_report_preserves_upstream_status_and_publishes_finality_before_finishing(self):
        controller = controller_module()
        summary, runner_temp = Path("/fixture/step_summary_contract"), Path("/fixture")
        for initially_ok in (True, False):
            with self.subTest(initially_ok=initially_ok):
                events, published = [], []
                report = report_fixture(initially_ok)
                original_rows = copy.deepcopy(report["rows"])
                session = session_fixture(events)

                def publish(path, value, *, runner_temp: Path, deadline):
                    self.assertEqual((path, runner_temp, deadline), (summary, Path("/fixture"), 20.0))
                    events.append(("publish", deadline))
                    published.append(copy.deepcopy(value))

                with patch.object(controller, "publish_summary", publish), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=summary, runner_temp=runner_temp,
                                                        start=10.0, deadline=20.0)
                self.assertEqual(status, 0 if initially_ok else 1)
                self.assertIs(report["ok"], initially_ok)
                self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])
                self.assertEqual(report["rows"], original_rows)
                self.assertEqual(report["cleanup_errors"], [])
                self.assertTrue(published[0]["finality"])
                self.assertEqual(published[0]["persisted_capture_bytes"], 37)
                self.assertEqual(published[0]["seconds"], 2.0)
                self.assertIs(published[0]["ok"], initially_ok)
                if not initially_ok:
                    self.assertEqual(report["error"], "UPSTREAM_FIXTURE_FAILURE")
        for missing in ("session", "summary", "runner-temp"):
            with self.subTest(missing=missing):
                events = []
                report = report_fixture()
                session = None if missing == "session" else session_fixture(events)
                with patch.object(controller, "publish_summary") as publisher, \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=None if missing == "summary" else summary,
                                                        runner_temp=None if missing == "runner-temp" else runner_temp,
                                                        start=10.0, deadline=20.0)
                self.assertEqual(status, 1)
                self.assertFalse(report["ok"])
                publisher.assert_not_called()
                self.assertEqual(events, [] if session is None else [("close", True), ("finish",)])
                self.assertEqual(report["error"], "SUCCESS_WITHOUT_ORIGINAL_SESSION" if session is None
                                 else "NO_SAFE_SUMMARY_DESTINATION")

    def test_cleanup_publication_and_cancellation_failures_never_return_success_and_always_finish(self):
        controller = controller_module()
        cases = [(stage, exception) for stage in ("close", "publish", "finish")
                 for exception in (OSError, KeyboardInterrupt, SystemExit)]
        cases += [(stage, None) for stage in ("no-finality", "latched-failure", "cleanup-errors", "all-three")]
        for stage, exception in cases:
            for upstream_failed in (False, True):
                with self.subTest(stage=stage, exception=exception, upstream_failed=upstream_failed):
                    events, published = [], []
                    report = report_fixture(not upstream_failed)

                    def close_action(session):
                        if stage in {"close", "all-three"}:
                            raise (exception or OSError)("synthetic late close failure")
                        if stage == "no-finality":
                            session.domain_finality = False
                        if stage == "latched-failure":
                            session.failure = "EARLIER_SESSION_FAILURE"
                        if stage == "cleanup-errors":
                            session.cleanup_errors.append("SYNTHETIC_CLEANUP_FAILURE")

                    def finish_action(_session):
                        if stage in {"finish", "all-three"}:
                            raise (exception or OSError)("synthetic timer restoration failure")

                    def publish(_path, value, **kwargs):
                        events.append(("publish", kwargs["deadline"]))
                        published.append(copy.deepcopy(value))
                        if stage in {"publish", "all-three"}:
                            raise (exception or OSError)("synthetic publication failure")

                    session = session_fixture(events, close_action=close_action, finish_action=finish_action)
                    with patch.object(controller, "publish_summary", publish), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                        status = controller.finalize_report(report, session, summary=Path("/fixture/step_summary_contract"),
                                                            runner_temp=Path("/fixture"), start=10.0, deadline=20.0)
                    self.assertEqual(status, 1)
                    self.assertFalse(report["ok"])
                    self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])
                    self.assertEqual(report["persisted_capture_bytes"], 37)
                    if stage in {"close", "no-finality", "latched-failure", "cleanup-errors", "all-three"}:
                        self.assertFalse(published[0]["ok"])
                    if stage in {"close", "finish"}:
                        self.assertEqual(report["cleanup_errors"][0]["exception"], exception.__name__)
                    if stage == "all-three":
                        self.assertEqual(len(report["cleanup_errors"]), 2)
                    if upstream_failed:
                        self.assertEqual(report["error"], "UPSTREAM_FIXTURE_FAILURE")

    def test_original_deadline_covers_close_publication_finish_and_final_return(self):
        controller = controller_module()
        for phase in ("already-expired", "close", "publish", "finish", "final-return"):
            with self.subTest(phase=phase):
                events = []
                clock = SimpleNamespace(value=20.0 if phase == "already-expired" else 12.0)
                report = report_fixture()

                def now():
                    return 20.0 if phase == "final-return" and events and events[-1] == ("finish",) else clock.value

                def close_action(_session):
                    if phase == "close":
                        clock.value = 20.0

                def finish_action(_session):
                    if phase == "finish":
                        clock.value = 20.0

                def publish(_path, _report, **kwargs):
                    self.assertEqual(kwargs["deadline"], 20.0)
                    events.append(("publish", kwargs["deadline"]))
                    if phase == "publish":
                        clock.value = 20.0
                    # Deliberately return success-shaped output even at expiry:
                    # finalizer's own original-cutoff gate must still reject it.

                session = session_fixture(events, close_action=close_action, finish_action=finish_action)
                with patch.object(controller, "publish_summary", publish), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=now)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=Path("/fixture/step_summary_contract"),
                                                        runner_temp=Path("/fixture"), start=10.0, deadline=20.0)
                self.assertEqual(status, 1)
                self.assertFalse(report["ok"])
                self.assertEqual(report["error"], "AGGREGATE_DEADLINE")
                self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])

    def test_summary_write_sync_close_and_print_aftereffects_are_bounded_by_original_deadline(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-summary-") as temporary:
            root = Path(temporary).resolve()
            for phase in ("none", "write", "fsync", "descriptor-close", "print"):
                with self.subTest(late_aftereffect=phase):
                    summary = root / ("step_summary_" + phase)
                    summary.write_bytes(b"")
                    report, events, emitted, descriptors = report_fixture(), [], [], []
                    clock = SimpleNamespace(value=12.0)

                    def after_effect(name):
                        events.append((name,))
                        if phase == name:
                            clock.value = 20.0

                    def opened(path, flags):
                        self.assertEqual(path, summary)
                        self.assertEqual(flags, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
                        descriptor = os.open(path, flags)
                        descriptors.append(descriptor)
                        return descriptor

                    def write(descriptor, value):
                        self.assertEqual(descriptors, [descriptor])
                        count = os.write(descriptor, value)
                        after_effect("write")
                        return count

                    def sync(descriptor):
                        self.assertEqual(descriptors, [descriptor])
                        os.fsync(descriptor)
                        after_effect("fsync")

                    def close(descriptor):
                        self.assertEqual(descriptors, [descriptor])
                        os.close(descriptor)
                        after_effect("descriptor-close")

                    def printed(text, *, flush):
                        self.assertIs(flush, True)
                        emitted.append(text)
                        if text.startswith("MRK_CI_RESULT="):
                            after_effect("print")

                    facade = SimpleNamespace(open=opened, fstat=os.fstat, write=write, fsync=sync, close=close,
                                             O_WRONLY=os.O_WRONLY, O_APPEND=os.O_APPEND,
                                             O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
                    session = session_fixture(events)
                    with patch.object(controller, "os", facade), patch.object(controller, "print", printed, create=True), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: clock.value)):
                        status = controller.finalize_report(report, session, summary=summary, runner_temp=root,
                                                            start=10.0, deadline=20.0)
                    self.assertEqual(status, 0 if phase == "none" else 1)
                    self.assertIs(report["ok"], phase == "none")
                    self.assertEqual(events[0], ("close", True))
                    self.assertEqual(events[-1], ("finish",))
                    self.assertEqual(events.count(("descriptor-close",)), 1)
                    self.assertEqual(len(descriptors), 1)
                    self.assertTrue(summary.read_bytes().startswith(b"## Mobile Release Kit isolated verification\n"))
                    self.assertEqual(any(line.startswith("MRK_CI_RESULT=") for line in emitted), phase in {"none", "print"})
                    if phase != "none":
                        self.assertEqual(report["error"], "AGGREGATE_DEADLINE")


if __name__ == "__main__":
    unittest.main()
