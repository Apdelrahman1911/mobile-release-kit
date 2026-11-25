"""Inert adapter/DTO regressions, NOT project/filesystem/native qualification.

No descriptor, project, signal handler, command, network or worker is acquired.
Every effect boundary exercised below is replaced before calling the subject.
Synthetic identities, closed flags and returned scope DATA never qualify a
runtime or claim actual original cleanup. Native recovery still needs its own
source-bound reviewed project fixture.
"""
from __future__ import annotations

import json
import stat
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import build_inputs as core
from mobile_release import desktop_project_recovery as service
from mobile_release import _desktop_project_recovery_protocol as wire
from mobile_release import _desktop_saved_command_control as shared
from mobile_release._desktop_project_recovery_control import ProjectRecoveryInput
from mobile_release._desktop_preflight_control import PreflightInput
from mobile_release._desktop_android_build_control import AndroidBuildInput
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError


SESSION = "c" * 32
STAMP = "d" * 64
ROOT = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}
EXPECTED = (1, 2, ROOT["mode"], 123, 123)


def observed(quiescence="original", status="pending"):
    return {"status": status, "session": SESSION,
            "roles": ["android-services"] if status == "pending" else [], "quiescence": quiescence}


def request_data(action="inspect"):
    return {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
            "context": {"projectId": "inert-project", "draftRevision": 2, "baselineGeneration": 3,
                        "action": action, "review": observed() if action == "recover" else None},
            "native": {"profile": "linux-gnu-x86_64", "projectRoot": "/inert/project",
                       "rootIdentity": dict(ROOT), "cwd": "/inert/cwd", "reviewStamp": STAMP if action == "recover" else None}}


def request(action="inspect"):
    return wire.parse_request(json.dumps(request_data(action)).encode("ascii") + b"\n")


class ProtocolTests(unittest.TestCase):
    def test_request_is_closed_and_none_is_never_a_recovery_grant(self):
        self.assertEqual(request().context["action"], "inspect")
        self.assertEqual(request("recover").native["reviewStamp"], STAMP)
        for value in ("none", "original", "operator"):
            result = wire.observation(observed(value))
            self.assertEqual(wire.eligible(result), value != "none")
        for change in ("manual", "command", "confirm", "session", "environment"):
            data = request_data(); data[change] = "UNTRUSTED"
            with self.subTest(change=change), self.assertRaises(wire.ProtocolError):
                wire.parse_request(json.dumps(data).encode("ascii") + b"\n")
        for change in ("review", "stamp", "root"):
            data = request_data(); data["context"][change] = "UNTRUSTED"
            with self.subTest(change=change), self.assertRaises(wire.ProtocolError):
                wire.parse_request(json.dumps(data).encode("ascii") + b"\n")
        data = request_data("recover"); data["context"]["review"]["quiescence"] = "none"
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(json.dumps(data).encode("ascii") + b"\n")
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(b'{"protocol":"one","protocol":"two"}\n')

    def test_recovery_domain_cannot_dispatch_commands_or_borrow_sources(self):
        source = ProjectRecoveryInput(100)
        self.assertIs(shared.source_domain(source), shared.SavedCommandDomain.ProjectRecovery)
        self.assertEqual(source.work_end, 220)
        with self.assertRaises(wire.ProtocolError):
            source.remaining_timeout(10)
        with self.assertRaises(wire.ProtocolError):
            source.command_limits(10, False, 1024)
        for wrong in (PreflightInput(100), AndroidBuildInput(100)):
            guard = DefaultCancellation(ValueError, "inert")
            with self.assertRaises(ValueError):
                guard._install_project_recovery_source(wrong)
            self.assertIsNone(wrong.guard)


class _InertCase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # These refusal sentinels are not invoked by normal test control flow.
        for target, names in ((core.os, ("open", "close", "mkdir", "unlink", "rmdir", "fsync", "stat", "fstat")),
                              (DefaultCancellation, ("activate", "install", "restore")),
                              (ProjectRecoveryInput, ("acquire", "request", "poll", "close"))):
            for name in names:
                self.patch(target, name, side_effect=AssertionError("unexpected effect boundary: " + name))

    def patch(self, target, name, **kwargs):
        return self.stack.enter_context(patch.object(target, name, **kwargs))


class CoreSeamTests(_InertCase):
    def test_actual_acquired_root_is_checked_before_lock_or_private_namespace(self):
        # Call the actual _Project.acquire ordering with an inert directory
        # slot; no constructor or ancestry traversal is used.
        try:
            import fcntl
        except ImportError:
            self.skipTest("POSIX project recovery is explicitly unsupported on this host")
        events = []
        project = object.__new__(core._Project)
        project.directory = SimpleNamespace(acquire=lambda: events.append("root-acquired"), fd=91)
        project.expected_root = EXPECTED
        project.guard = SimpleNamespace()
        self.patch(core.os, "fstat", side_effect=lambda fd: (events.append(("fstat", fd)) or
            SimpleNamespace(st_dev=1, st_ino=99, st_mode=ROOT["mode"], st_uid=123, st_gid=123)))
        rename = self.patch(core, "_rename_function", side_effect=AssertionError("root mismatch reached native rename setup"))
        lock = self.patch(fcntl, "flock", side_effect=AssertionError("root mismatch reached project lock"))
        names = self.patch(core, "_init_pending_names_locked", side_effect=AssertionError("root mismatch reached private namespace"))
        with self.assertRaises(core.BuildInputRootChanged):
            project.acquire()
        self.assertEqual(events, ["root-acquired", ("fstat", 91)])
        rename.assert_not_called(); lock.assert_not_called(); names.assert_not_called()

    def test_busy_is_typed_and_fatal_or_wrong_root_is_not_a_conflict_observation(self):
        for error, expected in ((core.BuildInputBusy("not parsed"), "busy"),
                                (core.BuildInputError("another owner holds this project"), "conflict")):
            @contextmanager
            def refused(*args, **kwargs):
                raise error
                yield  # pragma: no cover - contextmanager shape only
            self.patch(core, "_inspection", new=refused)
            actual = core._desktop_inspect_build_inputs(Path("/inert"), expected_root=EXPECTED, cancellation=object())
            self.assertEqual(actual.status, expected)
            self.assertIsNone(actual.review_stamp)
        for error in (ProcessCleanupError("inert close failure"), core.BuildInputRootChanged("inert root")):
            @contextmanager
            def refused(*args, **kwargs):
                raise error
                yield
            self.patch(core, "_inspection", new=refused)
            with self.assertRaises(type(error)):
                core._desktop_inspect_build_inputs(Path("/inert"), expected_root=EXPECTED, cancellation=object())

    def _pending(self, *, stamp=STAMP, quiescence="original", finish_error=None):
        state = {"held": False, "finished": False, "checks": 0}
        owner = SimpleNamespace(token=SESSION, quiescence=quiescence, records=[{"conflict": True}])
        def finish():
            self.assertTrue(state["held"])
            state["finished"] = True
            if finish_error is not None:
                raise finish_error
        owner._finish = Mock(side_effect=finish)
        project = SimpleNamespace(meta=SimpleNamespace(number=91))
        @contextmanager
        def inspection(root, cancellation, *, expected_root=None):
            self.assertEqual(expected_root, EXPECTED)
            self.assertFalse(state["held"])
            state["held"] = True
            try:
                yield project
            finally:
                state["held"] = False
        @contextmanager
        def pending(selected):
            self.assertIs(selected, project); self.assertTrue(state["held"])
            yield owner
        def review(selected, **kwargs):
            self.assertIs(selected, project); self.assertTrue(state["held"])
            self.assertIs(kwargs["owner"], owner)
            state["checks"] += 1
            return stamp
        self.patch(core, "_inspection", new=inspection)
        self.patch(core, "_pending_inspection", new=pending)
        self.patch(core, "_terminal_control", return_value=None)
        self.patch(core, "_stat", return_value={"present": True})
        self.patch(core, "_recovery_stamp", side_effect=review)
        return state, owner

    def test_review_recheck_and_existing_recovery_body_share_the_original_lock(self):
        state, owner = self._pending()
        actual = core._desktop_recover_build_inputs(Path("/inert"), session=SESSION, review_stamp=STAMP,
                                                    expected_root=EXPECTED, cancellation=object())
        self.assertEqual(actual, {"status": "recovered", "session": SESSION})
        self.assertEqual(state, {"held": False, "finished": True, "checks": 1})
        owner._finish.assert_called_once_with()
        self.assertFalse(owner.records[0]["conflict"])

    def test_checkpoint_drift_missing_quiescence_and_disappeared_namespace_never_recover(self):
        for stamp, quiescence, absent, reason in (("e" * 64, "original", False, "review-stale"),
                                                 (STAMP, "none", False, "manual-required"),
                                                 (STAMP, "original", True, "review-stale")):
            state, owner = self._pending(stamp=stamp, quiescence=quiescence)
            if absent:
                self.patch(core, "_stat", return_value=None)
            with self.subTest(reason=reason), self.assertRaises(core._DesktopRecoveryRefused) as caught:
                core._desktop_recover_build_inputs(Path("/inert"), session=SESSION, review_stamp=STAMP,
                                                   expected_root=EXPECTED, cancellation=object())
            self.assertEqual(caught.exception.reason, reason)
            self.assertFalse(state["held"] or state["finished"])
            owner._finish.assert_not_called()
            self.assertTrue(owner.records[0]["conflict"])

    def test_conflicting_file_and_interrupted_partial_cleanup_are_not_absent_or_recovered(self):
        for error in (core.BuildInputError("inert foreign file retained"), KeyboardInterrupt()):
            state, owner = self._pending(finish_error=error)
            with self.assertRaises(type(error)):
                core._desktop_recover_build_inputs(Path("/inert"), session=SESSION, review_stamp=STAMP,
                                                   expected_root=EXPECTED, cancellation=object())
            self.assertTrue(state["finished"]); self.assertFalse(state["held"])
            owner._finish.assert_called_once_with()

    def test_cleanup_only_rechecks_under_lock_then_reuses_terminal_retirement_only(self):
        for stamp in (STAMP, "e" * 64):
            state = {"held": False}
            project = object()
            terminal = ({"session": SESSION, "quiescence": "original"}, {"binding": "inert"})
            @contextmanager
            def inspection(root, cancellation, *, expected_root=None):
                self.assertEqual(expected_root, EXPECTED)
                state["held"] = True
                try:
                    yield project
                finally:
                    state["held"] = False
            def reviewed(selected, **kwargs):
                self.assertIs(selected, project); self.assertTrue(state["held"])
                self.assertEqual(kwargs, {"terminal": terminal})
                return stamp
            def retired(selected, *values):
                self.assertIs(selected, project); self.assertTrue(state["held"])
                self.assertEqual(values, terminal)
            self.patch(core, "_inspection", new=inspection)
            self.patch(core, "_terminal_control", return_value=terminal)
            self.patch(core, "_recovery_stamp", side_effect=reviewed)
            retire = self.patch(core, "_retire_terminal", side_effect=retired)
            pending = self.patch(core, "_pending_inspection", side_effect=AssertionError("terminal cleanup reached file restoration"))
            if stamp == STAMP:
                self.assertEqual(core._desktop_recover_build_inputs(Path("/inert"), session=SESSION, review_stamp=STAMP,
                    expected_root=EXPECTED, cancellation=object()), {"status": "recovered", "session": SESSION})
                retire.assert_called_once()
            else:
                with self.assertRaises(core._DesktopRecoveryRefused) as caught:
                    core._desktop_recover_build_inputs(Path("/inert"), session=SESSION, review_stamp=STAMP,
                        expected_root=EXPECTED, cancellation=object())
                self.assertEqual(caught.exception.reason, "review-stale")
                retire.assert_not_called()
            pending.assert_not_called(); self.assertFalse(state["held"])

    def test_legacy_status_and_absent_recovery_keep_their_public_shape(self):
        project = SimpleNamespace(meta=SimpleNamespace(number=None))
        @contextmanager
        def inspection(root, cancellation):
            yield project
        self.patch(core, "_inspection", new=inspection)
        self.patch(core, "_terminal_control", return_value=None)
        self.assertEqual(core.build_inputs_status(Path("/inert")), {"status": "idle"})
        self.assertEqual(core.recover_build_inputs(Path("/inert"), session=SESSION, confirm=core._CONFIRM),
                         {"status": "absent", "session": SESSION})

    def test_stamp_changes_with_validated_checkpoint_or_control_binding(self):
        project = SimpleNamespace(guard=SimpleNamespace(check=Mock()), check=Mock(), identity={"inode": 2}, meta_identity={"inode": 3})
        owner = SimpleNamespace(project=project, token=SESSION, identity={"inode": 4}, controls={"header.json": {"sha256": "a" * 64}},
                                seq=0, previous="b" * 64, quiescence="original")
        first = core._recovery_stamp(project, owner=owner)
        owner.seq = 1
        self.assertNotEqual(core._recovery_stamp(project, owner=owner), first)
        owner.seq = 0; owner.controls["header.json"]["sha256"] = "e" * 64
        self.assertNotEqual(core._recovery_stamp(project, owner=owner), first)


class ServiceTests(_InertCase):
    def original(self, action="inspect"):
        self.patch(service.os, "getcwd", return_value="/inert/cwd")
        self.patch(service.sys, "platform", new="linux")
        self.patch(service.time, "monotonic", return_value=110.0)
        guard = DefaultCancellation(ProcessCleanupError, "inert original")
        source = ProjectRecoveryInput(100)
        source.acquired = source.active = source.request_returned = True
        guard._install_project_recovery_source(source)
        self.patch(guard, "check", return_value=None)
        return service.ProjectRecoveryRun(request(action), guard, source), guard, source

    def terminal_data(self, operation, guard, source):
        operation.close()
        # Predicate DATA only: no real input/handler was acquired or closed.
        source.closed = True
        guard._restoration = "RESTORED"
        return operation.terminal()

    def test_inspection_forwards_actual_root_identity_and_only_recorded_quiescence(self):
        for finality in ("none", "original", "operator"):
            operation, guard, source = self.original()
            inspect = self.patch(service, "_desktop_inspect_build_inputs", return_value=core._DesktopRecoveryInspection(
                "pending", SESSION, ("android-services",), finality, STAMP))
            operation.run()
            inspect.assert_called_once_with(Path("/inert/project"), expected_root=EXPECTED, cancellation=guard)
            terminal = self.terminal_data(operation, guard, source)
            self.assertEqual(terminal["result"]["observation"]["quiescence"], finality)
            self.assertEqual(terminal["reviewStamp"], None if finality == "none" else STAMP)
            self.assertEqual(terminal["effect"], "inspection")
            self.assertEqual(terminal["lifetime"]["commands"], 0)

    def test_cancellation_after_recovery_attempt_suppresses_candidate_without_claiming_rollback(self):
        operation, guard, source = self.original("recover")
        recover = self.patch(service, "_desktop_recover_build_inputs", return_value={"status": "recovered", "session": SESSION})
        operation.run()
        recover.assert_called_once_with(Path("/inert/project"), session=SESSION, review_stamp=STAMP,
                                        expected_root=EXPECTED, cancellation=guard)
        guard.cancelled = True
        terminal = self.terminal_data(operation, guard, source)
        self.assertEqual((terminal["outcome"], terminal["reason"], terminal["effect"]), ("cancelled", "cancelled", "recovery-attempted"))
        self.assertIsNone(terminal["result"]); self.assertIsNone(terminal["reviewStamp"])

    def test_descriptor_original_is_retained_before_open_and_unknown_cannot_be_closed_by_replay(self):
        operation, guard, source = self.original()
        slot = core._FD(guard)  # NEW only: construction acquires no host resource.
        self.assertIs(source.descriptors[0], slot)
        self.assertFalse(source.resources_closed())
        slot.close()  # NEW/no-effect settlement does not call os.close.
        self.assertTrue(source.resources_closed())
        with self.assertRaises(wire.ProtocolError):
            source.register_descriptor(slot)
        slot.close_state = "UNKNOWN"  # Negative predicate DATA, not a lost real FD.
        with self.assertRaises(wire.ProtocolError):
            operation.close()
        self.assertTrue(guard.lifetime_ledger.fatal)
        source.closed = True; guard._restoration = "RESTORED"
        terminal = operation.terminal()
        self.assertEqual((terminal["outcome"], terminal["reason"]), ("unknown", "cleanup-unknown"))
        self.assertFalse(terminal["lifetime"]["resourcesClosed"])


if __name__ == "__main__":
    unittest.main()
