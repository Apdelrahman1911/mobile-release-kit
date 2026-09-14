"""Matrix contracts and original-owner integration, never raw launcher cleanup.

The Recorder/Bridge/Oracle classes are inert or use only private fixture files.
PersistentSigningTests starts genuine case/command owners and is admitted only
by the existing outer ordinary verification capture, not on a shared host.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import signal
import stat
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from workflow import local_signing_bridge as bridge
from workflow import local_signing_case_owner as owner
from workflow import local_signing_persistent_fixture as fixture
from unit import local_signing_persistent as persistent_model
from unit.local_signing_persistent import PROFILE, UUID, OwnerResolutionRefused, PersistentSigningModel, facts, initialize, write_json


class PersistentWorkerRecorderTests(unittest.TestCase):
    """No fork, native wait, process signal or actual descriptor is acquired."""

    @contextmanager
    def recorded_owner(self, *, fault=None):
        events = []
        pipes = iter(((101, 102), (103, 104)))
        waits = iter(((0, 0), (701, 0)))
        terminal = {"expired-zero": b"EXPIRED 0\n", "deadline": b"EXPIRED -9\n"}.get(fault, b"SETTLED 0\n")
        messages = iter((b"ARMED 702\n", terminal, b""))
        clock = SimpleNamespace(now=10.0, sleep=lambda _seconds: None)
        clock.monotonic = lambda: clock.now
        native = SimpleNamespace(**vars(os))
        native.getpid, native.getpgrp = lambda: 700, lambda: 699
        native.pipe = lambda: next(pipes)
        native.set_blocking = lambda fd, blocking: events.append(("blocking", fd, blocking))
        native.fork = lambda: events.append(("fork",)) or 701
        native.killpg = lambda pid, sig: events.append(("signal", pid, sig))
        close_failed = []

        def close(fd):
            events.append(("close", fd))
            if fault == "close" and not close_failed:
                close_failed.append(fd)
                raise OSError("inert ambiguous close")

        def wait(pid, flags):
            events.append(("wait", pid, flags))
            if fault == "wait":
                raise OSError("inert lost wait result")
            return next(waits)

        def receive(fd, data, deadline):
            events.append(("receive", fd, deadline))
            value = next(messages)
            if fault == "late-zero" and value == terminal:
                clock.now = 31.0  # Past original30, before cleanup35.
            data.extend(value)
            return bool(value)

        def record(path, value):
            events.append(("record", path.name, value))
            if fault == "record":
                raise OSError("inert record refusal")

        native.close, native.waitpid = close, wait
        task = Mock(side_effect=AssertionError("an inert owner must never dispatch a task"))
        with patch.multiple(owner, os=native, time=clock, receive=receive,
                            send=lambda fd, data, deadline: events.append(("send", data, deadline)),
                            absent=lambda group, **kw: events.append(("absent", group, kw["route_live"])) or True):
            yield SimpleNamespace(events=events, native=native, task=task, record=record)
        task.assert_not_called()

    def invoke(self, rig):
        return owner.run_worker(Path("/inert/case"), "case", rig.task,
                                timeout=20, deadline=40.0, write_json=rig.record)

    def test_pinned_group_is_retired_before_first_anchor_wait_including_zero(self):
        with self.recorded_owner() as rig:
            value = self.invoke(rig)
        self.assertEqual(value["exit"], 0)
        first_wait = next(index for index, item in enumerate(rig.events) if item[0] == "wait")
        self.assertTrue(any(item[0] == "absent" for item in rig.events[:first_wait]))
        self.assertFalse(any(item[0] in {"absent", "signal"} for item in rig.events[first_wait:]))
        self.assertEqual([item[1] for item in rig.events if item[0] == "send"], [b"RUN\n", b"RELEASE\n"])
        self.assertEqual(sorted(item[1] for item in rig.events if item[0] == "close"), [101, 102, 103, 104])
        self.assertTrue(value["originalAnchorWait"] and value["originalWorkerWait"] and value["originalStatusEOF"])

    def test_record_failure_revokes_run_and_cleans_only_original_unpolled_group(self):
        with self.recorded_owner(fault="record") as rig, self.assertRaisesRegex(OSError, "record refusal"):
            self.invoke(rig)
        self.assertFalse(any(item[0] == "send" for item in rig.events))
        self.assertIn(("signal", 701, signal.SIGKILL), rig.events)
        self.assertFalse(any(item[0] == "signal" and item[1] == 702 for item in rig.events))
        self.assertEqual(sorted(item[1] for item in rig.events if item[0] == "close"), [101, 102, 103, 104])

    def test_late_zero_never_becomes_success_via_cleanup_tail(self):
        for fault in ("late-zero", "expired-zero"):
            with self.subTest(fault=fault), self.recorded_owner(fault=fault) as rig, self.assertRaisesRegex(
                    AssertionError, "original run deadline"):
                self.invoke(rig)
            first_wait = next(index for index, item in enumerate(rig.events) if item[0] == "wait")
            self.assertFalse(any(item[0] in {"absent", "signal"} for item in rig.events[first_wait:]))
        with self.recorded_owner(fault="deadline") as rig:
            observed = owner.run_worker(Path("/inert/case"), "deadline", rig.task, timeout=20,
                                        expect=-signal.SIGKILL, deadline=40.0, write_json=rig.record)
        self.assertTrue(observed["deadlineTest"] and observed["runDeadlineExpired"])
        for line in (b"SETTLED +0", b"SETTLED 00", b"EXPIRED -09", b"EXPIRED  0", b"SETTLED 256", b"SETTLED 0 extra"):
            with self.subTest(line=line), self.assertRaises(AssertionError):
                owner.terminal_record(line)

    def test_lost_wait_never_rearms_route_or_claims_success(self):
        with self.recorded_owner(fault="wait") as rig, self.assertRaisesRegex(OSError, "lost wait"):
            self.invoke(rig)
        first = next(index for index, item in enumerate(rig.events) if item[0] == "wait")
        self.assertEqual(sum(item[0] == "wait" for item in rig.events), 1)
        self.assertFalse(any(item[0] in {"absent", "signal"} for item in rig.events[first:]))

    def test_close_once_collection_preserves_other_original_cleanup(self):
        handles = owner.Handles()
        handles.values = {"first": 51, "second": 52}
        calls = []
        def close(fd):
            calls.append(fd)
            if fd == 51:
                self.assertNotIn("first", handles.values)
                raise OSError("lost close result")
        with patch.object(owner, "os", SimpleNamespace(close=close)):
            handles.close_except()
            handles.close_except()
        self.assertEqual(calls, [51, 52])
        self.assertEqual(len(handles.errors), 1)
        self.assertEqual(handles.values, {})

    def test_invalid_or_expired_endpoint_precedes_every_acquisition(self):
        for cutoff in (float("nan"), float("inf"), True, 9.0, 10.0):
            with self.subTest(cutoff=cutoff), self.recorded_owner() as rig, self.assertRaises(AssertionError):
                owner.run_worker(Path("/inert/case"), "case", rig.task, deadline=cutoff, write_json=rig.record)
            self.assertEqual(rig.events, [])

    def test_original_fork_unknown_and_wait_attempts_are_irreversible(self):
        slot = owner.OriginalWait()
        with patch.object(owner, "os", SimpleNamespace(fork=Mock(side_effect=OSError("fork result unavailable")))):
            with self.assertRaises(OSError): slot.fork()
            self.assertTrue(slot.attempted and slot.unknown)
            with self.assertRaises(AssertionError): slot.fork()
            with self.assertRaises(AssertionError): slot.wait()
        slot = owner.OriginalWait()
        with patch.object(owner, "os", SimpleNamespace(fork=lambda: 75, WNOHANG=1,
                                                        waitpid=Mock(side_effect=[(0, 0), OSError("wait unknown")]))):
            self.assertEqual(slot.fork(), 75)
            self.assertIsNone(slot.wait())
            self.assertTrue(slot.retired)
            with self.assertRaises(OSError): slot.wait()
            self.assertTrue(slot.retired and slot.unknown)
            with self.assertRaises(AssertionError): slot.wait()

    def test_case_unknown_is_absorbing_and_never_becomes_a_deletion_receipt(self):
        with tempfile.TemporaryDirectory(prefix="mrk-inert-custody-") as directory:
            root = Path(directory)
            key = str(root)
            try:
                with patch.object(owner, "run_worker", side_effect=OSError("original unknown")) as run:
                    with self.assertRaises(OSError): fixture.run_worker(root, "case", lambda: None)
                    self.assertIsNone(fixture._CASE_CUSTODY[key])
                    with self.assertRaisesRegex(AssertionError, "prior case custody"):
                        fixture.run_worker(root, "case", lambda: None)
                    run.assert_called_once()
                with self.assertRaisesRegex(AssertionError, "unconfirmed"):
                    fixture.remove_case(root)
                self.assertTrue(root.is_dir())
            finally:
                fixture._CASE_CUSTODY.pop(key, None)  # Inert recorder: no worker was ever acquired.

    def test_known_custody_and_debt_cannot_rebind_a_replaced_directory_before_dispatch(self):
        with tempfile.TemporaryDirectory(prefix="mrk-inert-replaced-case-") as temporary, \
                patch.dict(fixture._CASE_CUSTODY, {}, clear=True), \
                patch.dict(fixture._CASE_RECOVERY_DEBT, {}, clear=True):
            root = Path(temporary)
            identity = fixture._directory_identity(root)
            fixture._CASE_CUSTODY[str(root)] = identity
            fixture.require_fresh_recovery(root)
            replacement = (identity[0], identity[1] + 1, *identity[2:])
            with patch.object(fixture, "_directory_identity", return_value=replacement), \
                    patch.object(owner, "run_worker") as launch:
                with self.assertRaisesRegex(AssertionError, "prior case directory changed"):
                    fixture.run_worker(root, "not-dispatched", lambda: None)
                with self.assertRaisesRegex(AssertionError, "prior case directory changed"):
                    fixture.require_fresh_recovery(root)
                launch.assert_not_called()
            self.assertEqual(fixture._CASE_CUSTODY[str(root)], identity)
            self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)

    def test_post_cut_failure_and_failed_fresh_recovery_retain_original_c_debt(self):
        # Pure custody recorder: no original child or command is launched.
        with tempfile.TemporaryDirectory(prefix="mrk-inert-debt-") as directory, \
                patch.dict(fixture._CASE_CUSTODY, {}, clear=True), \
                patch.dict(fixture._CASE_RECOVERY_DEBT, {}, clear=True):
            root = Path(directory) / "case"
            root.mkdir(mode=0o700)
            fixture.require_fresh_recovery(root)
            identity = fixture._directory_identity(root)
            self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)
            fixture._CASE_CUSTODY[str(root)] = identity  # Inert original A/W/G result.
            try:
                raise AssertionError("post-seed assertion failed")
            except AssertionError:
                with self.assertRaisesRegex(AssertionError, "recovery debt"):
                    fixture.remove_case(root)
            for error in (OSError("fresh recovery failed"), KeyboardInterrupt()):
                with patch.object(fixture, "run_worker", side_effect=error), self.assertRaises(type(error)):
                    fixture.recover_final(root)
                self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)
                self.assertEqual(fixture._CASE_CUSTODY[str(root)], identity)
            recorder = PersistentSigningTests("test_one_real_model_command_bridge_finishes_before_success")
            recorder.root = Path(directory)
            with self.assertRaisesRegex(AssertionError, "fixture files retained"):
                recorder.tearDown()
            self.assertTrue(root.is_dir())

    def test_debt_clears_only_after_fresh_helper_success_and_exact_original_case(self):
        with tempfile.TemporaryDirectory(prefix="mrk-inert-debt-settlement-") as directory, \
                patch.dict(fixture._CASE_CUSTODY, {}, clear=True), \
                patch.dict(fixture._CASE_RECOVERY_DEBT, {}, clear=True):
            root = Path(directory)
            fixture.require_fresh_recovery(root)
            identity = fixture._directory_identity(root)
            fixture._CASE_CUSTODY[str(root)] = identity
            def completed(*_args, **_kwargs):
                self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)
                write_json(root / "final-automatic.json", {"refused": None, "result": {"status": "recovered"}})
            with patch.object(fixture, "run_worker", side_effect=completed) as run:
                self.assertEqual(fixture.recover_final(root), {"automatic": "recovered", "manual": None})
            run.assert_called_once()
            self.assertNotIn(str(root), fixture._CASE_RECOVERY_DEBT)
            fixture.require_fresh_recovery(root)
            fixture._CASE_CUSTODY[str(root)] = None
            with patch.object(fixture, "run_worker", side_effect=completed), self.assertRaisesRegex(AssertionError, "unconfirmed"):
                fixture.recover_final(root)
            self.assertIsNone(fixture._CASE_CUSTODY[str(root)])
            self.assertIn(str(root), fixture._CASE_RECOVERY_DEBT)

    def test_unpublished_thread_start_failure_retains_original_namespace_and_start_debt(self):
        # No thread, descriptor or process is acquired by these explicit doubles.
        namespace = SimpleNamespace(open=Mock(return_value=51), close=Mock(return_value=True),
                                    close_errors=[], remove=Mock())
        original = SimpleNamespace(start=Mock(side_effect=KeyboardInterrupt()), ident=None,
                                   is_alive=Mock(return_value=False), join=Mock())
        model = object.__new__(PersistentSigningModel)
        model.root = Path("/inert/original-case")
        retained = []
        with patch.object(bridge, "Namespace", return_value=namespace), \
                patch.object(persistent_model, "threading", SimpleNamespace(Event=persistent_model.threading.Event,
                                                                          Thread=Mock(return_value=original))), \
                patch.object(persistent_model, "_RETAINED_MODEL_LIFETIMES", retained), \
                self.assertRaises(KeyboardInterrupt) as caught:
            model(["security", "default-keychain", "-d", "user"])
        original.start.assert_called_once()
        original.join.assert_not_called()
        original.is_alive.assert_not_called()
        namespace.close.assert_not_called()
        namespace.remove.assert_not_called()
        self.assertEqual(len(retained), 1)
        self.assertIs(retained[0][0], namespace)
        self.assertIs(retained[0][1], original)
        self.assertTrue(retained[0][3].is_set())
        self.assertTrue(caught.exception._model_cleanup_errors)

    @contextmanager
    def recorded_model(self, returned, *, command_error=None, service_error=None, eof_error=None):
        """Run the actual orchestration with no thread, FIFO, FD or child."""
        from mobile_release import owned_process
        calls, events, threads, opened = [], {}, [], {}
        names = iter(("stop", "service-finished", "target-returned"))
        token = []

        class Event:
            def __init__(self):
                self.name, self.value = next(names), False
                events[self.name] = self
            def is_set(self): return self.value
            def set(self):
                calls.append(("set", self.name))
                self.value = True

        class Thread:
            def __init__(self, *, target, name, daemon):
                self.target, self.alive = target, False
                threads.append(self)
            def start(self):
                calls.append(("start",))
                self.alive = True
            def join(self, *, timeout):
                calls.append(("join", events["stop"].is_set(), events["target-returned"].is_set(), timeout))
                self.target()  # Synchronous original service body, explicit channel doubles below.
                self.alive = False
            def is_alive(self): return self.alive

        class Channel:
            def __init__(self, descriptor, deadline, *, stop=None, peer_finished=None):
                self.descriptor, self.stop, self.peer_finished = descriptor, stop, peer_finished
                self.established = False
                self.index = 0
                calls.append(("channel", descriptor, deadline, peer_finished))
            def receive(self):
                if service_error is not None:
                    raise service_error
                if self.stop.is_set():
                    raise AssertionError("inert original service retired")
                self.index += 1
                return ({"version": 1, "kind": "HELLO", "token": token[0]} if self.index == 1 else
                        {"version": 1, "sequence": 1, "kind": "DONE", "value": None})
            def send(self, value): calls.append(("send", value["kind"]))
            def require_eof(self):
                calls.append(("eof",))
                if eof_error is not None:
                    raise eof_error

        def open_node(name, flags, deadline):
            descriptor = 51 if name == "events.fifo" else 52
            opened[name] = descriptor
            return descriptor

        def close_node(name):
            opened.pop(name, None)

        def close():
            self.assertFalse(threads[0].alive)
            calls.append(("close",))
            return True

        def remove():
            self.assertFalse(opened)
            self.assertFalse(threads[0].alive)
            calls.append(("remove",))

        namespace = SimpleNamespace(path=Path("/inert/bridge"), binding={}, close_errors=[],
            open=Mock(side_effect=open_node), close_node=Mock(side_effect=close_node),
            close=Mock(side_effect=close), remove=Mock(side_effect=remove))

        def run(command, **kwargs):
            calls.append(("run-owned",))
            token.append(command[-1])
            if command_error is not None:
                raise command_error
            return returned

        model = object.__new__(PersistentSigningModel)
        model.root, model.trace, model.recovery, model.auto_add = Path("/inert/original-case"), None, False, False
        model.path = SimpleNamespace(read_bytes=lambda: b'{"actual_state_reload":true}')
        retained = []
        clock = SimpleNamespace(monotonic=lambda: 10.0)
        with patch.object(bridge, "Namespace", return_value=namespace), \
                patch.object(bridge, "Channel", Channel), patch.object(bridge, "time", clock), \
                patch.object(persistent_model, "threading", SimpleNamespace(Event=Event, Thread=Thread)), \
                patch.object(persistent_model, "time", clock), \
                patch.object(persistent_model, "_RETAINED_MODEL_LIFETIMES", retained), \
                patch.object(owned_process, "run_owned", side_effect=run) as launch, \
                patch.object(owner, "observe_adapter_target_result", create=True) as diagnostic:
            yield SimpleNamespace(model=model, calls=calls, events=events, namespace=namespace,
                                  retained=retained, launch=launch, diagnostic=diagnostic)

    def test_actual_target_failure_precedes_join_and_keeps_independent_service_failure(self):
        for code, stderr in ((1, "PRIVATE actual target failure"), (0, "PRIVATE unexpected stderr")):
            with self.subTest(code=code):
                returned = persistent_model.subprocess.CompletedProcess(["actual-target"], code, "", stderr)
                observation = OSError("PRIVATE independent service failure")
                with self.recorded_model(returned, service_error=observation) as rig:
                    # Projection is optional even after it has observed the actual result.
                    rig.diagnostic.side_effect = RuntimeError("PRIVATE diagnostic failure")
                    with self.assertRaisesRegex(AssertionError, "target result differs") as caught:
                        rig.model(["security", "default-keychain", "-d", "user"])
                    self.assertEqual([call[1:3] for call in rig.calls if call[0] == "join"], [(True, False)])
                    self.assertIn(observation, caught.exception._model_cleanup_errors)
                    self.assertFalse(rig.events["target-returned"].is_set())
                    self.assertTrue(rig.events["service-finished"].is_set())
                    self.assertFalse(rig.retained)
                    rig.namespace.remove.assert_not_called()
                    rig.namespace.close.assert_called_once()
                    rig.diagnostic.assert_called_once_with(returned)

    def test_original_command_exception_never_advertises_a_return_or_loses_its_primary(self):
        first, observation = KeyboardInterrupt(), OSError("PRIVATE independent service failure")
        with self.recorded_model(None, command_error=first, service_error=observation) as rig:
            with self.assertRaises(KeyboardInterrupt) as caught:
                rig.model(["security", "default-keychain", "-d", "user"])
            self.assertIs(caught.exception, first)
            self.assertEqual(first._model_cleanup_errors, (observation,))
            self.assertFalse(rig.events["target-returned"].is_set())
            self.assertEqual([call[1:3] for call in rig.calls if call[0] == "join"], [(True, False)])
            rig.diagnostic.assert_not_called()
            rig.namespace.remove.assert_not_called()
            self.assertFalse(rig.retained)

    def test_matching_result_preserves_done_eof_race_and_exact_expected_nonzero_policy(self):
        for code, stderr, capture in ((0, "", True), (7, "fictional selected stderr", True), (7, "", False)):
            with self.subTest(code=code, capture=capture):
                returned = persistent_model.subprocess.CompletedProcess(["actual-target"], code, "actual output", stderr)
                policy = {"returncode": code, "perform_effect": code == 0, "stdout": None,
                          "stderr": "fictional selected stderr" if code else ""}
                with self.recorded_model(returned) as rig:
                    result = rig.model(["security", "default-keychain", "-d", "user"],
                                       result_policy=policy, capture=capture)
                    self.assertEqual([call[1:3] for call in rig.calls if call[0] == "join"], [(False, True)])
                    self.assertIn(("send", "DONE-ACK"), rig.calls)
                    self.assertIn(("eof",), rig.calls)
                    channels = [call for call in rig.calls if call[0] == "channel"]
                    self.assertIs(channels[0][3], rig.events["target-returned"])
                    self.assertIsNone(channels[1][3])
                    self.assertTrue(all(call[2] == 40.0 for call in channels))
                    self.assertEqual([call[3] for call in rig.calls if call[0] == "join"], [30.0])
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (returned.returncode, returned.stdout, returned.stderr))
                    self.assertEqual(result.args, ["security", "default-keychain", "-d", "user"])
                    self.assertEqual(returned.args, ["actual-target"])
                    self.assertEqual(rig.model.state, {"actual_state_reload": True})
                    rig.namespace.remove.assert_called_once()
                    rig.namespace.close.assert_not_called()
                    rig.diagnostic.assert_not_called()
                    self.assertFalse(rig.retained)

        observation = OSError("PRIVATE actual service EOF failure")
        returned = persistent_model.subprocess.CompletedProcess(["actual-target"], 0, "", "")
        with self.recorded_model(returned, eof_error=observation) as rig:
            with self.assertRaisesRegex(AssertionError, "model observation failed") as caught:
                rig.model(["security", "default-keychain", "-d", "user"])
            self.assertIs(caught.exception.__cause__, observation)
            self.assertFalse(hasattr(caught.exception, "_model_cleanup_errors"))  # Already retained as the actual cause.
            rig.namespace.remove.assert_not_called()
            rig.diagnostic.assert_called_once_with(returned)


class PersistentBridgeRecorderTests(unittest.TestCase):
    """Strict bounded transport with entirely in-memory I/O doubles."""

    @staticmethod
    def frame(value):
        content = json.dumps(value).encode("ascii")
        return len(content).to_bytes(4, "big") + content

    @contextmanager
    def fifo_double(self, *, supported=False, platform="darwin", result=0, number=0):
        """Public ABI arguments only; no library load, syscall, path or cwd IO."""
        native = SimpleNamespace(mkfifo=Mock(), supports_dir_fd=set())
        if supported:
            native.supports_dir_fd.add(native.mkfifo)
        function = Mock(return_value=result)
        c = SimpleNamespace(**{name: getattr(bridge.ctypes, name) for name in
            ("c_int", "c_char_p", "c_uint16", "c_void_p", "sizeof")})
        c.CDLL = Mock(return_value=SimpleNamespace(mkfifoat=function))
        c.set_errno, c.get_errno = Mock(), Mock(return_value=number)
        with patch.object(bridge, "os", native), patch.object(bridge, "ctypes", c), \
                patch.object(bridge, "sys", SimpleNamespace(platform=platform)):
            yield SimpleNamespace(os=native, ctypes=c, function=function)

    def test_fifo_python_capability_keeps_original_dirfd_and_never_retries_failed_creation(self):
        with self.fifo_double(supported=True) as rig:
            bridge._create_fifo(51, "events.fifo")
            rig.os.mkfifo.assert_called_once_with("events.fifo", 0o600, dir_fd=51)
            rig.ctypes.CDLL.assert_not_called()
        first = FileExistsError("inert original collision")
        with self.fifo_double(supported=True) as rig:
            rig.os.mkfifo.side_effect = first
            with self.assertRaises(FileExistsError) as caught:
                bridge._create_fifo(51, "acks.fifo")
            self.assertIs(caught.exception, first)
            rig.os.mkfifo.assert_called_once_with("acks.fifo", 0o600, dir_fd=51)
            rig.ctypes.CDLL.assert_not_called()
        for directory, name in ((True, "events.fifo"), (-1, "events.fifo"), (2**31, "events.fifo"),
                                (51.0, "events.fifo"), (51, "../events.fifo"), (51, "/events.fifo"), (51, b"events.fifo")):
            with self.subTest(directory=directory, name=name), self.fifo_double(supported=True) as rig:
                with self.assertRaisesRegex(AssertionError, "fixed FIFO creation"):
                    bridge._create_fifo(directory, name)
                rig.os.mkfifo.assert_not_called()
                rig.ctypes.CDLL.assert_not_called()
        with self.fifo_double(platform="linux") as rig:
            with self.assertRaises(NotImplementedError):
                bridge._create_fifo(51, "events.fifo")
            rig.os.mkfifo.assert_not_called()
            rig.ctypes.CDLL.assert_not_called()

    def test_darwin_fifo_uses_only_fixed_public_signature_and_actual_errno_without_fallback(self):
        with self.fifo_double() as rig:
            order = []
            rig.ctypes.set_errno.side_effect = lambda value: order.append(("clear", value))
            rig.function.side_effect = lambda *args: order.append(("call", args)) or 0
            rig.ctypes.get_errno.side_effect = lambda: order.append(("errno",)) or 0
            bridge._create_fifo(51, "events.fifo")
            rig.ctypes.CDLL.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
            self.assertEqual(rig.function.argtypes, (rig.ctypes.c_int, rig.ctypes.c_char_p, rig.ctypes.c_uint16))
            self.assertIs(rig.function.restype, rig.ctypes.c_int)
            self.assertEqual(order, [("clear", 0), ("call", (51, b"events.fifo", 0o600)), ("errno",)])
            rig.os.mkfifo.assert_not_called()
        for result, number in ((-1, 17), (-1, 0), (-1, True), (-1, 4096), (1, 0), (True, 0)):
            with self.subTest(result=result, number=number), self.fifo_double(result=result, number=number) as rig:
                with self.assertRaises(OSError if result == -1 and number == 17 else AssertionError) as caught:
                    bridge._create_fifo(51, "acks.fifo")
                if result == -1 and number == 17:
                    self.assertEqual(caught.exception.errno, 17)
                rig.function.assert_called_once_with(51, b"acks.fifo", 0o600)
                rig.ctypes.CDLL.assert_called_once()
                rig.os.mkfifo.assert_not_called()
        for missing in ("library", "symbol", "abi"):
            with self.subTest(missing=missing), self.fifo_double() as rig:
                if missing == "library":
                    rig.ctypes.CDLL.side_effect = OSError("inert library unavailable")
                elif missing == "symbol":
                    rig.ctypes.CDLL.return_value = SimpleNamespace()
                else:
                    rig.ctypes.sizeof = lambda _kind: 0
                with self.assertRaises(AssertionError if missing == "abi" else NotImplementedError):
                    bridge._create_fifo(51, "events.fifo")
                rig.function.assert_not_called()
                rig.os.mkfifo.assert_not_called()

    def test_returned_target_requires_actual_eof_and_drains_bytes_after_stale_readiness(self):
        for ready in (False, True):
            with self.subTest(ready=ready):
                finished = SimpleNamespace(is_set=lambda: True)
                channel = bridge.Channel(51, 20.0, peer_finished=finished)
                read = Mock(return_value=b"")
                with patch.object(bridge, "os", SimpleNamespace(read=read)), \
                        patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([51] if ready else [], [], []))), \
                        patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                        self.assertRaisesRegex(AssertionError, "returned before HELLO"):
                    channel.receive()
                read.assert_called_once()
                self.assertFalse(channel.eof)  # An unexpected EOF is not a success receipt.
                self.assertFalse(channel.established)
                self.assertEqual(channel.frames, 0)

        completed = [False]
        channel = bridge.Channel(51, 20.0, peer_finished=SimpleNamespace(is_set=lambda: completed[0]))
        frames = self.frame({"kind": "HELLO"}) + self.frame({"kind": "DONE"})
        read = Mock(side_effect=(BlockingIOError(bridge.errno.EAGAIN, "inert no data"), frames))
        def selected(*_):
            completed[0] = True  # Target returns after this stale readiness observation.
            return [], [], []
        with patch.object(bridge, "os", SimpleNamespace(read=read)), \
                patch.object(bridge, "select", SimpleNamespace(select=selected)), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            self.assertEqual(channel.receive(), {"kind": "HELLO"})
            self.assertEqual(channel.receive(), {"kind": "DONE"})
        self.assertEqual(read.call_count, 2)
        self.assertEqual(channel.frames, 2)
        self.assertEqual(channel.deadline, 20.0)

    def test_returned_hint_cannot_refresh_clock_accept_partial_frame_or_override_stop(self):
        for prefix in (b"", self.frame({"kind": "HELLO"})[:5]):
            with self.subTest(prefix=prefix):
                clock = [10.0]
                channel = bridge.Channel(51, 10.5, peer_finished=SimpleNamespace(is_set=lambda: True))
                channel.buffer.extend(prefix)
                def selected(*_):
                    clock[0] += .2
                    return [], [], []
                read = Mock(side_effect=BlockingIOError(bridge.errno.EWOULDBLOCK, "inert outstanding writer"))
                with patch.object(bridge, "os", SimpleNamespace(read=read)), \
                        patch.object(bridge, "select", SimpleNamespace(select=selected)), \
                        patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                        self.assertRaisesRegex(AssertionError, "cutoff expired"):
                    channel.receive()
                self.assertGreater(read.call_count, 0)
                self.assertEqual(channel.frames, 0)
                self.assertEqual(channel.deadline, 10.5)
                self.assertFalse(channel.eof)
        channel = bridge.Channel(51, 20.0, stop=SimpleNamespace(is_set=lambda: True),
                                 peer_finished=SimpleNamespace(is_set=lambda: True))
        channel.buffer.extend(self.frame({"kind": "HELLO"}))
        with patch.object(bridge, "os", SimpleNamespace(read=Mock(side_effect=AssertionError("no IO after stop")))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                self.assertRaisesRegex(AssertionError, "service retired"):
            channel.receive()

    def test_done_eof_after_returned_hint_still_needs_the_original_expected_eof(self):
        channel = bridge.Channel(51, 20.0, peer_finished=SimpleNamespace(is_set=lambda: True))
        channel.established = True
        with patch.object(bridge, "os", SimpleNamespace(read=Mock(return_value=b""))) as native, \
                patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([51], [], []))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            channel.require_eof()
        native.read.assert_called_once_with(51, 1)
        self.assertTrue(channel.eof)

    def test_pre_writer_eof_cannot_admit_an_effect_but_original_peer_eof_fails(self):
        frame = self.frame({"kind": "HELLO"})
        channel = bridge.Channel(51, 20.0)
        values = iter((b"", frame[:3], frame[3:]))
        with patch.object(bridge, "os", SimpleNamespace(read=lambda *_: next(values))), \
                patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([51], [], []))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda _: None)):
            self.assertEqual(channel.receive(), {"kind": "HELLO"})
        channel.established = True
        with patch.object(bridge, "os", SimpleNamespace(read=lambda *_: b"")), \
                patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([51], [], []))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                self.assertRaisesRegex(AssertionError, "original peer EOF"):
            channel.receive()

    def test_withheld_ack_and_partial_frame_keep_the_original_deadline(self):
        clock = [10.0]
        def pause(_): clock[0] += .2
        channel = bridge.Channel(51, 10.5)
        with patch.object(bridge, "os", SimpleNamespace(read=lambda *_: b"")), \
                patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([51], [], []))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=pause)), \
                self.assertRaisesRegex(AssertionError, "cutoff expired"):
            channel.receive()
        self.assertEqual(channel.deadline, 10.5)
        self.assertEqual(channel.frames, 0)
        for buffer in (b"\0\0\0\0", (bridge.MAX_FRAME + 1).to_bytes(4, "big")):
            channel = bridge.Channel(51, 20.0)
            channel.buffer.extend(buffer)
            with patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)), self.assertRaisesRegex(
                    AssertionError, "advertised frame bound"):
                channel.receive()

    def test_decode_crossing_original_cutoff_or_retirement_never_accepts_an_ack(self):
        for expired in (True, False):
            clock, stop = [10.0], [False]
            channel = bridge.Channel(51, 11.0, stop=SimpleNamespace(is_set=lambda: stop[0]))
            channel.buffer.extend(self.frame({"kind": "PARTIAL-ACK", "value": False}))
            action = Mock()
            def decode(_data):
                if expired: clock[0] = 11.0
                else: stop[0] = True
                return {"kind": "PARTIAL-ACK", "value": False}
            with patch.object(bridge, "decode", side_effect=decode), \
                    patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: clock[0])), self.assertRaises(AssertionError):
                channel.receive()
                action()
            action.assert_not_called()
            self.assertEqual(channel.deadline, 11.0)

    def test_duplicate_nonfinite_nonascii_frames_and_replayed_ack_are_refused(self):
        for content in (b'{"a":1,"a":1}', b'{"a":NaN}', b'\xff', b'{"a":'):
            with self.subTest(content=content), self.assertRaises((AssertionError, ValueError, UnicodeError)):
                bridge.decode(content)
        good = {"version": 1, "sequence": 1, "kind": "BEGIN-ACK", "value": None}
        for changes in ({"version": True}, {"sequence": True}, {"sequence": 0}, {"kind": "END-ACK"}, {"extra": 1}):
            events = SimpleNamespace(send=Mock())
            acks = SimpleNamespace(receive=Mock(return_value={**good, **changes}))
            trace = bridge.RemoteTrace(events, acks)
            with self.subTest(changes=changes), self.assertRaisesRegex(AssertionError, "wrong or replayed"):
                trace.request("BEGIN", {})
            self.assertEqual(trace.sequence, 1)
            events.send.assert_called_once()

    def test_failed_send_consumes_slot_and_close_failures_cannot_rearm_descriptors(self):
        channel = bridge.Channel(51, 20.0)
        with patch.object(bridge, "os", SimpleNamespace(write=lambda *_: 0)), \
                patch.object(bridge, "select", SimpleNamespace(select=lambda *_: ([], [51], []))), \
                patch.object(bridge, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                self.assertRaisesRegex(AssertionError, "frame write"):
            channel.send({"kind": "BEGIN"})
        self.assertEqual(channel.frames, 1)
        namespace = object.__new__(bridge.Namespace)
        namespace.directory, namespace.descriptors, namespace.close_errors = 53, {"events.fifo": 51, "acks.fifo": 52}, []
        calls = []
        def close(fd):
            calls.append(fd)
            self.assertNotIn(fd, namespace.descriptors.values())
            if fd == 51: raise OSError("inert close unknown")
        with patch.object(bridge, "os", SimpleNamespace(close=close)):
            self.assertFalse(namespace.close())
            self.assertFalse(namespace.close())
        self.assertEqual(calls, [51, 52, 53])
        self.assertIsNone(namespace.directory)

    def test_malformed_begin_ack_never_allows_the_real_effect_or_persisted_save(self):
        valid = {"index": 7, "operation": "native-effect/preference/default", "slot": "native", "origin": "model",
                 "phase": "setup", "occurrence": 2, "details": {}}
        changes = (None, {}, {**valid, "index": True}, {**valid, "index": 0}, {**valid, "occurrence": True},
                   {**valid, "phase": "unknown"}, {**valid, "operation": "native-effect/preference/search"},
                   {**valid, "slot": "/other"}, {**valid, "origin": "replacement"}, {**valid, "details": None},
                   {**valid, "succeeded": True})
        for value in changes:
            with self.subTest(value=value):
                remote = bridge.RemoteTrace(SimpleNamespace(send=Mock()), SimpleNamespace(receive=Mock(return_value={
                    "version": 1, "sequence": 1, "kind": "BEGIN-ACK", "value": value})))
                model = object.__new__(PersistentSigningModel)
                model.trace, model.save = remote, Mock()
                action = Mock()
                with self.assertRaisesRegex(AssertionError, "BEGIN ACK"):
                    model.effect("preference/default", action)
                action.assert_not_called()
                model.save.assert_not_called()
        for kind in ("END", "DONE"):
            for value in ({}, False, 0, "", []):
                remote = bridge.RemoteTrace(SimpleNamespace(send=Mock()), SimpleNamespace(receive=Mock(return_value={
                    "version": 1, "sequence": 1, "kind": kind + "-ACK", "value": value})))
                with self.subTest(kind=kind, value=value), self.assertRaisesRegex(AssertionError, "terminal ACK"):
                    remote.request(kind, None)

    def test_target_policy_is_finite_data_not_an_arbitrary_success_receipt(self):
        self.assertEqual(bridge.result_policy(), {"returncode": 0, "perform_effect": True, "stdout": None, "stderr": ""})
        baseline = bridge.result_policy()
        for changes in ({"returncode": True}, {"returncode": -1}, {"returncode": 256},
                        {"perform_effect": False}, {"stdout": "x" * 8193}, {"stderr": None}, {"callback": lambda: None}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(AssertionError):
                bridge.result_policy({**baseline, **changes})
        self.assertEqual(bridge.result_policy({**baseline, "returncode": 7, "perform_effect": False})["returncode"], 7)


class PersistentOracleTests(unittest.TestCase):
    """Private regular-file comparisons; no case, signing command or native API."""

    @contextmanager
    def focused_foreign_fixture(self):
        # Synthetic DATA only: this never claims an actual production manual
        # gate. The genuine15 integration test supplies that separate evidence.
        with tempfile.TemporaryDirectory(prefix="mrk-focused-owner-data-") as temporary, \
                patch.dict(fixture._CASE_CUSTODY, {}, clear=True), \
                patch.dict(fixture._CASE_RECOVERY_DEBT, {}, clear=True):
            root = Path(temporary)
            initialize(root)
            model = PersistentSigningModel(root)
            database = root / "home" / fixture.signing.LEASE_DIRECTORY / ("session-" + "a" * 32) / "keychain" / fixture.signing.DB_NAME
            database.parent.mkdir(parents=True, mode=0o700)
            database.write_bytes(b"original fictional owned database")
            database.chmod(0o600)
            model.oracle.record(database, "native")
            original = facts(database)
            replacement = root / "fixture-foreign-db"
            replacement.write_bytes(b"independent fictional replacement database")
            replacement.chmod(0o600)
            replacement.replace(database)
            model.oracle.record_foreign(database, original)
            model.state["keychain"] = str(database)
            model.state["preferences"] = {"default": str(database),
                "search": [model.state["original"]["search"][1], str(database), model.state["original"]["search"][0]]}
            model.save()
            fixture._CASE_CUSTODY[str(root)] = fixture._directory_identity(root)
            fixture.require_fresh_recovery(root)
            receipts = {database.relative_to(root).as_posix(): fixture.focused_receipt(root, database)}
            plan = fixture.focused_owner_plan(root, "foreign-native-db", receipts)
            yield root, model, database, plan

    def test_focused_owner_prevalidates_edit_preferences_inventory_and_archive_collision(self):
        for change in ("receipt", "preferences", "inventory", "archive"):
            with self.subTest(change=change), self.focused_foreign_fixture() as (root, model, database, plan):
                if change == "receipt":
                    # Identical bytes with a changed link count still contradict
                    # the independently bound receipt, although facts() agrees.
                    os.link(database, root / "unexpected-fixture-link")
                elif change == "preferences":
                    model.state["preferences"]["search"].reverse()
                    model.save()
                elif change == "inventory":
                    sentinel = Path(model.state["original"]["default"])
                    sentinel.write_bytes(b"changed unrelated fixture sentinel")
                else:
                    (root / "fixture-owner-archive").mkdir(mode=0o700)
                before = model.path.read_bytes(), model.oracle.path.read_bytes(), database.read_bytes()
                with self.assertRaises(AssertionError):
                    fixture.resolve_focused_fixture(root, model, plan)
                self.assertEqual((model.path.read_bytes(), model.oracle.path.read_bytes(), database.read_bytes()), before)
                self.assertIn(str(root), fixture._CASE_RECOVERY_DEBT)
                self.assertFalse((root / "fixture-owner-archive/foreign-native.keychain-db").exists())

    def test_foreign_fixture_archive_keeps_exact_inode_history_and_only_detaches_its_references(self):
        with self.focused_foreign_fixture() as (root, model, database, plan):
            original = facts(database)
            history = copy.deepcopy(model.oracle.read()["foreignChanges"])
            expected = {"default": model.state["original"]["default"],
                        "search": [item for item in plan["preferences"]["search"] if item != str(database)]}
            fixture.resolve_focused_fixture(root, model, plan)
            archive = root / "fixture-owner-archive/foreign-native.keychain-db"
            self.assertFalse(database.exists())
            self.assertEqual(facts(archive), original)
            self.assertEqual(model.state["preferences"], expected)
            self.assertEqual(model.oracle.read()["foreignChanges"], history)
            self.assertIn(str(root), fixture._CASE_RECOVERY_DEBT)  # Callback is not finality.
            with self.assertRaisesRegex(AssertionError, "repeated fixture archive"):
                model.oracle.record_fixture_foreign_db_archive(database, archive)
            model.oracle.assert_sentinels()
            archive.write_bytes(b"fixture archive changed after owner action")
            with self.assertRaisesRegex(AssertionError, "unrelated fixture state"):
                model.oracle.assert_sentinels()

    def test_partial_fixture_archive_failure_and_intermediate_manual_success_cannot_clear_debt(self):
        with self.focused_foreign_fixture() as (root, model, database, plan):
            before = model.path.read_bytes(), model.oracle.path.read_bytes()
            with patch.object(fixture.os, "unlink", side_effect=OSError("fixture unlink result unavailable")), \
                    self.assertRaisesRegex(OSError, "fixture unlink result"):
                fixture.resolve_focused_fixture(root, model, plan)
            archive = root / "fixture-owner-archive/foreign-native.keychain-db"
            self.assertEqual(facts(database), facts(archive))
            self.assertEqual((model.path.read_bytes(), model.oracle.path.read_bytes()), before)
            with self.assertRaisesRegex(AssertionError, "recovery debt"):
                fixture.remove_case(root)
        with self.focused_foreign_fixture() as (root, model, _database, plan):
            def intermediate(*_args, **_kwargs):
                write_json(root / "focused-fixture-owner.json", {"result": {"status": "recovered"},
                    "preferences": plan["expectedPreferences"], "manualFixtureAction": True})
            with patch.object(fixture, "run_worker", side_effect=intermediate):
                self.assertEqual(fixture.settle_focused_fixture(root, plan), plan["expectedPreferences"])
            self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], plan["identity"])
            with self.assertRaisesRegex(AssertionError, "recovery debt"):
                fixture.remove_case(root)

    def test_original_c_prefix_requires_exact_inode_bytes_and_positive_once_close(self):
        with tempfile.TemporaryDirectory(prefix="mrk-c-prefix-") as temporary:
            root = Path(temporary)
            path = root / "command-final.pending"
            operand = b'{"actual":"original-C-fence"}'
            prefix = operand[:13]
            path.write_bytes(prefix)
            path.chmod(0o600)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.addCleanup(os.close, directory)
            session = object()
            trace = object.__new__(fixture.Trace)
            trace._fence_namespace = lambda: (session, directory)
            info = path.stat()
            creation = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
            observation = SimpleNamespace(identity_state=1, creation_identity=creation, written=len(prefix), operand=operand)
            value = trace._fence_prefix(observation)
            self.assertEqual(value["actualReadHex"], prefix.hex())
            self.assertTrue(value["originalReadClosed"] and value["finalAbsentBeforeAndAfter"])
            for changes in ({"creation_identity": (0, *creation[1:])}, {"operand": b"x" * len(operand)},
                            {"written": len(prefix) - 1}, {"identity_state": 2}):
                with self.subTest(changes=tuple(changes)), self.assertRaises(AssertionError):
                    trace._fence_prefix(SimpleNamespace(**{**vars(observation), **changes}))
            (root / "command-final.json").write_bytes(b"already-final")
            with self.assertRaisesRegex(AssertionError, "final fence already exists"):
                trace._fence_prefix(observation)

    def test_prefix_read_primary_and_independent_close_error_are_both_preserved(self):
        with tempfile.TemporaryDirectory(prefix="mrk-c-prefix-errors-") as temporary:
            root = Path(temporary)
            pending = root / "command-final.pending"
            pending.write_bytes(b"prefix")
            pending.chmod(0o600)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = pending.stat()
                observation = SimpleNamespace(identity_state=1,
                    creation_identity=(info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink),
                    written=6, operand=b"prefix-more")
                trace = object.__new__(fixture.Trace)
                session = object()
                trace._fence_namespace = lambda: (session, directory)
                primary, secondary = OSError("read failed"), OSError("close result unavailable")
                native, closes = SimpleNamespace(**vars(os)), []
                native.read = Mock(side_effect=primary)
                def close(fd):
                    closes.append(fd)
                    os.close(fd)
                    raise secondary
                native.close = close
                with patch.object(fixture, "os", native), self.assertRaises(OSError) as caught:
                    trace._fence_prefix(observation)
                self.assertIs(caught.exception, primary)
                self.assertEqual(primary._fence_prefix_close_errors, (secondary,))
                self.assertEqual(len(closes), 1)
            finally:
                os.close(directory)

    def test_owner_prevalidates_all_resources_before_preferences_or_unlinks(self):
        with tempfile.TemporaryDirectory(prefix="mrk-persistent-oracle-") as temporary:
            for variant in ("database-inplace", "database-replaced", "profile-replaced"):
                with self.subTest(variant=variant):
                    case = Path(temporary) / variant
                    case.mkdir(mode=0o700)
                    initialize(case)
                    model = PersistentSigningModel(case)
                    database, profile = case / "fictional-db", case / "fictional-owned-profile"
                    for path, kind in ((database, "native"), (profile, "profile")):
                        path.write_bytes(b"independently owned fictional data")
                        path.chmod(0o600)
                        model.oracle.record(path, kind)
                    model.state["keychain"] = str(database)
                    model.state["preferences"] = {"default": str(database), "search": [str(database)]}
                    model.save()
                    target = profile if variant == "profile-replaced" else database
                    if variant.endswith("inplace"):
                        target.write_bytes(b"unknown edit, no owner annotation")
                    else:
                        replacement = case / "external-replacement"
                        replacement.write_bytes(b"unknown inode, no owner annotation")
                        replacement.chmod(0o600)
                        replacement.replace(target)
                    observed, native_state = {path: facts(path) for path in (database, profile)}, model.path.read_bytes()
                    with self.assertRaises(OwnerResolutionRefused): model.oracle.resolve_owned(model)
                    self.assertEqual(model.path.read_bytes(), native_state)
                    self.assertEqual({path: facts(path) for path in observed}, observed)
                    model.oracle.assert_sentinels()


class PersistentSigningTests(unittest.TestCase):
    """Genuine original case/command integration; requires outer disposable capture."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mrk-persistent-signing-")).resolve()

    def tearDown(self):
        # Preserve uncertainty. No destructor, recorded PID, wait-then-signal or
        # guessed process identity is used to authorize cleanup after failure.
        owned = {key: value for key, value in fixture._CASE_CUSTODY.items()
                 if Path(key).is_relative_to(self.root)}
        debt = [key for key in fixture._CASE_RECOVERY_DEBT if Path(key).is_relative_to(self.root)]
        self.assertFalse(debt or any(value is None for value in owned.values()),
                         "original case/C finality unconfirmed; fixture files retained")
        for key in sorted(owned, key=len, reverse=True):
            fixture.remove_case(Path(key))
        shutil.rmtree(self.root)

    def test_actual_case_wait_eof_barrier_crash_and_deadline_settle_before_return(self):
        for mode in ("healthy", "crash", "deadline"):
            with self.subTest(mode=mode):
                case = self.root / mode
                case.mkdir(mode=0o700)
                def task():
                    write_json(case / "task-started.json", {"started": True})
                    if mode == "crash": os._exit(fixture.CRASH)
                    if mode == "deadline": time.sleep(30)
                    return {"completed": True}
                value = fixture.run_worker(case, mode, task, timeout=.25 if mode == "deadline" else 5,
                    expect={"healthy": 0, "crash": fixture.CRASH, "deadline": -signal.SIGKILL}[mode])
                self.assertTrue((case / "task-started.json").is_file())
                self.assertTrue(value["originalAnchorWait"] and value["originalWorkerWait"] and value["originalStatusEOF"])
                self.assertTrue(value["groupAbsentBeforeAnchorWait"])
                self.assertEqual((case / (mode + ".json")).exists(), mode == "healthy")
                fixture.remove_case(case)

    def test_one_real_model_command_bridge_finishes_before_success(self):
        case = self.root / "one-model-command"
        case.mkdir(mode=0o700)
        initialize(case)
        def task():
            model = PersistentSigningModel(case)
            result = model(["security", "default-keychain", "-d", "user"])
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertIn(model.state["original"]["default"], result.stdout)
            self.assertFalse(list(case.glob("model-bridge-*")))
            return {"actual_model_command": True}
        fixture.run_worker(case, "healthy", task, timeout=10)
        self.assertEqual(json.loads((case / "healthy.json").read_bytes()), {"actual_model_command": True})
        fixture.remove_case(case)

    def test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery(self):
        def one_journalled_query(case, trace):
            model = PersistentSigningModel(case)
            with fixture.signing.local_signing_lease(home=case / "home") as lease:
                session = lease.session()
                session.bind_runner(model)
                session.open(create=True)
                session.prepare(PROFILE, UUID)
                model.trace = trace
                with trace.installed():
                    session.run(["security", "default-keychain", "-d", "user"], kind="observe")
                model.trace = None
                session.cleanup_native()
                session.cleanup_profile()
                session.finish()
            return trace.result()
        healthy = self.root / "query-inventory"
        healthy.mkdir(mode=0o700)
        initialize(healthy)
        fixture.run_worker(healthy, "query", lambda: one_journalled_query(healthy, fixture.Trace(healthy, "query")))
        inventory = json.loads((healthy / "query.json").read_bytes())
        event = next(item for item in inventory["events"] if item["operation"] == "command-fence/PENDING_WRITE")
        fixture.remove_case(healthy)
        case = self.root / "original-c-cut"
        case.mkdir(mode=0o700)
        initialize(case)
        fixture.require_fresh_recovery(case)
        fixture.run_worker(case, "seed", lambda: one_journalled_query(case, fixture.Trace(
            case, "seed", {"event": event, "edge": "partial"})), expect=fixture.CRASH)
        cut = json.loads((case / "seed-cut.json").read_bytes())
        original = cut["originalCFenceObservation"]
        self.assertTrue(original["originalWorker"] and original["originalReadClosed"])
        self.assertEqual(bytes.fromhex(original["actualReadHex"]), bytes.fromhex(original["operandHex"])[:original["written"]])
        self.assertEqual(fixture.recover_final(case)["automatic"], "recovered")
        fixture.remove_case(case)

    def original_inventory(self):
        inventory_case = self.root / "inventory"
        inventory_case.mkdir(mode=0o700)
        inventory = fixture.inventory_original(inventory_case)
        operations = {event["operation"] for event in inventory["events"]}
        self.assertTrue({"buffer.write", "buffer.flush", "buffer.close", "link", "native/build", "native/import",
                         "native-effect/replace/" + fixture.signing.DB_NAME,
                         "command-fence/PENDING_WRITE", "command-fence/DATA_FSYNC", "command-fence/FINAL_LINK",
                         "command-fence/DIRECTORY_FSYNC"} <= operations)
        self.assertEqual(inventory["snapshot"]["preferences"], inventory["snapshot"]["original"])
        self.assertFalse(inventory["snapshot"]["ownedRemaining"])
        fixture.remove_case(inventory_case)
        return inventory

    def test_genuine_model_inventory_active_build_pending_contrast(self):
        inventory = self.original_inventory()
        # Reproduce the recorded pending-write contrast from the actual new
        # inventory; do not relabel the historical EEXIST failure without fresh
        # execution evidence. No pending journal or native outcome is invented.
        cut_case = self.root / "active-build-pending"
        cut_case.mkdir(mode=0o700)
        fixture.require_fresh_recovery(cut_case)
        fixture.seed_case(cut_case, fixture.seeds(inventory)["active-build-pending"])
        self.assertEqual(fixture.recover_final(cut_case)["automatic"], "recovered")
        fixture.remove_case(cut_case)

    def test_genuine_model_inventory_and_foreign_manual_cases(self):
        inventory = self.original_inventory()
        result = fixture.focused_cases(self.root, inventory)
        self.assertEqual(result["count"], 15)
        self.assertTrue(result["allExactChildrenReapedAndGroupsAbsent"])
        evidence = json.loads((self.root / "focused-evidence.json").read_bytes())
        for name in ("foreign-default", "reordered-search", "deleted-search", "foreign-profile"):
            self.assertEqual(evidence[name]["result"]["status"], "recovered-with-conflict")
        for name in ("profile-inplace-edit", "terminal-profile-reappeared", "terminal-native-reappeared",
                     "manual-wrong", "manual-eof", "manual-cancel"):
            self.assertEqual(evidence[name]["freshAdmission"], "pending")
            self.assertTrue(evidence[name]["resourcesPreserved"])
        self.assertEqual(evidence["borrowed-profile"], {"automatic": "recovered", "manual": None})
        self.assertEqual(evidence["auto-add-ambiguous-create"]["automatic"], "refused-unknown-resource")
        for mode in ("none", "resolve"):
            observed = evidence["foreign-native-db"][mode]
            self.assertEqual(observed["freshAdmission"], "pending")
            self.assertTrue(observed["resourcesPreserved"])
            self.assertEqual(observed["before"]["preferences"], observed["after"]["preferences"])


if __name__ == "__main__":
    unittest.main()
