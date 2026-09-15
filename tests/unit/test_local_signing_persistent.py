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
from workflow import local_signing_matrix_contract as matrix_contract
from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_fixture as semantic
from unit import local_signing_persistent as persistent_model
from unit.local_signing_persistent import PROFILE, UUID, OwnerResolutionRefused, PersistentSigningModel, facts, initialize, write_json


class PersistentWorkerRecorderTests(unittest.TestCase):
    """No fork, native wait, process signal or actual descriptor is acquired."""

    def test_fictional_profile_preserves_explicit_payload_and_original_reader(self):
        from mobile_release import ios_profiles
        from unit.ios_entitlement_helpers import profile
        from unit.local_signing_helpers import fictional_signing_profile

        path, content = Path("/inert/original-profile"), b"original-reader-bytes"
        payload = {"UUID": "44444444-5555-6666-7777-888888888888", "nested": {"values": ["original"]}}
        events = []
        guard = SimpleNamespace(check=lambda: events.append("check"))

        def read(selected, *, cancellation):
            self.assertIs(selected, path)
            self.assertIs(cancellation, guard)
            events.append("read")
            return content

        with patch.object(ios_profiles, "read_profile_bytes", side_effect=read) as reader:
            actual, metadata = fictional_signing_profile(path, cancellation=guard, payload=payload)
            self.assertIs(actual, content)
            self.assertEqual(metadata, payload)
            self.assertIsNot(metadata, payload)
            metadata["nested"]["values"].append("returned")
            self.assertEqual(payload["nested"]["values"], ["original"])
            payload["nested"]["values"].append("caller")
            self.assertEqual(metadata["nested"]["values"], ["original", "returned"])
            actual, default = fictional_signing_profile(path, cancellation=guard)
            self.assertIs(actual, content)
            self.assertEqual(default, profile())
            self.assertEqual(reader.call_count, 2)
        self.assertEqual(events, ["check", "read", "check", "read"])

        cancelled = RuntimeError("inert original cancellation")
        guard.check = Mock(side_effect=cancelled)
        with patch.object(ios_profiles, "read_profile_bytes") as reader:
            with self.assertRaises(RuntimeError) as caught:
                fictional_signing_profile(path, cancellation=guard, payload=payload)
            self.assertIs(caught.exception, cancelled)
            reader.assert_not_called()
        guard.check = Mock()
        failure = OSError("inert original read failure")
        with patch.object(ios_profiles, "read_profile_bytes", side_effect=failure) as reader:
            with self.assertRaises(OSError) as caught:
                fictional_signing_profile(path, cancellation=guard, payload=payload)
            self.assertIs(caught.exception, failure)
            guard.check.assert_called_once_with()
            reader.assert_called_once_with(path, cancellation=guard)

    def test_post_result_cleanup_requires_live_original_finality(self):
        from mobile_release import _command_process as commands
        from workflow import profile_installation_fixture as signal_fixture

        engine, nonce = object(), b"n" * 32
        result = SimpleNamespace(returncode=0)

        def incomplete_scope(outcome):
            # Negative data shapes only: no engine, authority constructor,
            # finality receipt, process, descriptor or fence is acquired.
            scope = object.__new__(commands.AccountExecutionScope)
            slot = object.__new__(commands.CommandOutcomeSlot)
            binding = object.__new__(commands.JournalledCommandBinding)
            scope.nonce, scope._outcome, scope._binding = nonce, slot, binding
            slot._engine, slot._value = engine, outcome
            binding._scope = scope
            return {"execution_scope": scope, "journal_binding": binding}

        def incomplete_outcome(**changed):
            fields = {"_engine": engine, "nonce": nonce, "create_w": commands.RouteHistory(False, False),
                      "run_tool": commands.RouteHistory(False, False), "no_target": None,
                      "termination": "normal-exit", "returncode": 0, "result_integrity": "complete",
                      "original_finality": None}
            return commands.OriginalCommandOutcome(**{**fields, **changed})

        foreign_binding = incomplete_scope(incomplete_outcome())
        foreign_binding["journal_binding"] = object()
        cases = (
            ("missing-scope", {}, "original scope"),
            ("foreign-scope", {"execution_scope": object()}, "original scope"),
            ("missing-outcome", incomplete_scope(None), "original outcome"),
            ("foreign-outcome", incomplete_scope(object()), "original outcome"),
            ("foreign-binding", foreign_binding, "foreign binding or outcome"),
            ("foreign-generation", incomplete_scope(incomplete_outcome(_engine=object())), "foreign binding or outcome"),
            ("incomplete-result", incomplete_scope(incomplete_outcome(result_integrity="unknown")), "complete normal result"),
            ("unknown-result", incomplete_scope(incomplete_outcome(termination="signal-wait", returncode=-15)), "complete normal result"),
            ("missing-finality", incomplete_scope(incomplete_outcome()), "original finality is missing"),
            ("foreign-finality", incomplete_scope(incomplete_outcome(
                original_finality=SimpleNamespace(_engine=engine))), "original finality is missing"),
        )
        with patch.object(commands.OriginalCommandOutcome, "require_binding",
                          side_effect=AssertionError("inert rejection must precede any binding consumption")) as consume:
            for name, options, message in cases:
                with self.subTest(name=name), self.assertRaisesRegex(AssertionError, message):
                    signal_fixture.observe_live_post_result_finality(options, result)
            consume.assert_not_called()

    def test_adapter_command_origins_follow_original_return_before_bounded_read_and_fresh_slot(self):
        origins = {name: "__init__.py" if name == "mobile_release" else name.split(".")[-1] + ".py"
                   for name in ("mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
                                "mobile_release._native_process", "mobile_release._command_process")}
        expected_package = Path("/inert/selected/mobile_release")
        for mode in ("good", "unconfirmed", "missing-worker", "wrong-result"):
            with self.subTest(mode=mode):
                events, payload = [], {}
                subject = PersistentSigningTests("test_one_real_model_command_bridge_finishes_before_success")
                subject.root = Path("/inert/case")
                subject._adapter_command_worker_origins = {"stale": "must be cleared"}

                class Model:
                    state = {"original": {"default": "inert-default"}}

                    def __call__(self, argv):
                        events.append("command-return")
                        return SimpleNamespace(returncode=0, stderr="", stdout="inert-default")

                def collect(package, role, *, deadline):
                    self.assertEqual((package, role, deadline), (expected_package, "commandWorker", 20.0))
                    self.assertEqual(events[-1], "command-return")
                    self.assertIsNone(subject._adapter_command_worker_origins)
                    events.append("worker-origins")
                    value = dict(origins)
                    if mode == "missing-worker": value.pop("mobile_release._command_process")
                    return value

                def worker(root, name, task, *, timeout):
                    self.assertEqual((root, name, timeout), (subject.root / "one-model-command", "healthy", 10))
                    self.assertIsNone(subject._adapter_command_worker_origins)
                    # Expected package was captured before dispatch, not selected from this worker's metadata.
                    fixture.signing.__file__ = "/inert/foreign/mobile_release/local_signing.py"
                    payload.update(task())
                    events.append("original-return")
                    return {"exit": 0, "originalAnchorWait": True, "originalWorkerWait": mode != "unconfirmed",
                            "originalStatusEOF": True, "groupAbsentBeforeAnchorWait": True,
                            "deadlineTest": False, "runDeadlineExpired": False}

                def read(root, name):
                    self.assertEqual(events[-1], "original-return")
                    self.assertIsNone(subject._adapter_command_worker_origins)
                    events.append("bounded-read")
                    if mode == "wrong-result": payload["actual_model_command"] = False
                    return payload

                with patch.object(fixture.signing, "__file__", str(expected_package / "local_signing.py")), \
                        patch.object(fixture, "PHASE_DEADLINE", 20.0), \
                        patch.object(Path, "resolve", new=lambda path, **_kw: path), \
                        patch.object(Path, "mkdir", return_value=None), patch.object(Path, "glob", return_value=()), \
                        patch(__name__ + ".initialize", side_effect=lambda root: events.append("initialize")), \
                        patch(__name__ + ".PersistentSigningModel", side_effect=lambda root: Model()), \
                        patch.object(matrix_contract, "actual_adapter_origins", side_effect=collect), \
                        patch.object(fixture, "run_worker", side_effect=worker), \
                        patch.object(fixture, "read_case_json", side_effect=read), \
                        patch.object(fixture, "remove_case", side_effect=lambda root: events.append("cleanup")), \
                        patch.object(owner, "run_worker", side_effect=AssertionError("inert test must not dispatch")):
                    if mode == "good":
                        subject.test_one_real_model_command_bridge_finishes_before_success()
                        payload["origins"].clear()
                        self.assertEqual(subject._adapter_command_worker_origins, origins)
                    else:
                        with self.assertRaises(ValueError if mode == "missing-worker" else AssertionError):
                            subject.test_one_real_model_command_bridge_finishes_before_success()
                        self.assertIsNone(subject._adapter_command_worker_origins)
                expected = ["initialize", "command-return", "worker-origins", "original-return"]
                if mode != "unconfirmed": expected.append("bounded-read")
                if mode == "good": expected.append("cleanup")
                self.assertEqual(events, expected)

    class Page:
        """Inert mapping; neither this class nor its close acquires a resource."""
        def __init__(self):
            self.data = bytearray(4096)
            self.reads = self.closes = 0
            self.read_error = self.write_error = self.close_error = None
        def __getitem__(self, key):
            self.reads += 1
            if self.read_error is not None:
                raise self.read_error
            return bytes(self.data[key])
        def __setitem__(self, key, value):
            if self.write_error is not None:
                raise self.write_error
            self.data[key] = value
        def close(self):
            self.closes += 1
            if self.close_error is not None:
                raise self.close_error

    @contextmanager
    def progress_page(self):
        class Thread:
            pass
        main, service = Thread(), Thread()
        state = SimpleNamespace(pid=702, thread=main, now=10.0)
        context = object()
        page = owner._AdapterProgress(context, "query", 10.0, 700)
        page.mapping = self.Page()
        def snapshot():
            previous, state.pid = state.pid, 700
            try:
                return page.snapshot(702)
            finally:
                state.pid = previous
        with patch.multiple(owner, os=SimpleNamespace(getpid=lambda: state.pid),
                            threading=SimpleNamespace(Thread=Thread, current_thread=lambda: state.thread,
                                                      main_thread=lambda: main),
                            time=SimpleNamespace(monotonic=lambda: state.now),
                            ADAPTER_DIAGNOSTIC_CONTEXT=context, _ADAPTER_PROGRESS_WRITER=None):
            page.bind_worker()
            yield SimpleNamespace(page=page, state=state, main=main, service=service, context=context,
                                  snapshot=snapshot, hook=owner.adapter_progress)

    def test_progress_exact_writers_original_join_and_command_accounting(self):
        with self.progress_page() as rig:
            rig.hook("task-entered")
            self.assertEqual(rig.hook("begin"), 1)
            rig.hook("bind-service", command=1, service=rig.service)
            rig.hook("run-owned", command=1)
            before = bytes(rig.page.mapping.data)
            rig.hook("HELLO", command=1)  # Main never writes the service slot.
            rig.state.pid = 703
            rig.hook("task-returned")
            rig.state.pid, rig.state.thread = 702, object()
            rig.hook("task-returned")
            rig.hook("HELLO", command=1)
            self.assertEqual(bytes(rig.page.mapping.data), before)
            rig.state.thread = rig.service
            rig.hook("HELLO", command=True)
            self.assertEqual(bytes(rig.page.mapping.data), before)
            for stage in ("HELLO", "BEGIN", "EFFECT", "END", "DONE", "EOF"):
                rig.hook(stage, command=1)
            service_sequence = rig.page.sequences[1]
            rig.state.thread = rig.main
            self.assertIsNone(rig.hook("begin"))  # Service completion alone cannot authorize new binding.
            rig.hook("target-return", command=1)
            self.assertEqual(rig.snapshot()["owner"]["completed"], 0)
            rig.hook("service-joined", command=1, service=object())
            self.assertFalse(rig.page.joined)
            rig.hook("service-joined", command=1, service=rig.service)
            rig.state.now = 11.25
            rig.hook("model-return", command=1)
            rig.hook("model-return", command=1)
            self.assertEqual(rig.snapshot()["owner"], {"stage": "model-return", "elapsedMs": 1250, "command": 1,
                                                       "completed": 1, "totalMs": 1250, "maxMs": 1250})
            self.assertEqual(rig.hook("begin"), 2)
            self.assertIsNone(rig.snapshot()["service"])  # Earlier EOF is stale, never next-command evidence.
            next_service = type(rig.service)()
            rig.hook("bind-service", command=2, service=next_service)
            rig.state.thread = rig.service
            rig.hook("EOF", command=2)  # Even the current ordinal cannot adopt an earlier Thread object.
            self.assertEqual(rig.page.sequences[1], service_sequence)
            rig.state.thread = next_service
            rig.hook("EOF", command=1)
            self.assertEqual(rig.page.sequences[1], service_sequence)
            rig.hook("HELLO", command=2)
            self.assertGreater(rig.page.sequences[1], service_sequence)
            self.assertEqual(rig.snapshot()["service"]["command"], 2)
            rig.state.thread = rig.main
            with patch.object(owner, "ADAPTER_DIAGNOSTIC_CONTEXT", object()):
                before = bytes(rig.page.mapping.data)
                rig.hook("task-returned")
                self.assertEqual(bytes(rig.page.mapping.data), before)

    def test_progress_single_copy_rejects_torn_wrong_generation_and_overflow(self):
        with self.progress_page() as rig:
            rig.hook("begin")
            baseline = bytes(rig.page.mapping.data)
            good = rig.page.record.unpack(baseline[:rig.page.record.size])
            for field, value in ((0, 0), (0, 3), (11, 4), (1, 2), (2, 2), (3, 703), (4, 99),
                                 (5, 0), (6, 99), (7, 1 << 31), (8, 2), (10, 1)):
                with self.subTest(field=field, value=value):
                    changed = list(good)
                    changed[field] = value
                    rig.page.mapping.data[:rig.page.record.size] = rig.page.record.pack(*changed)
                    reads = rig.page.mapping.reads
                    self.assertIsNone(rig.snapshot()["owner"])
                    self.assertEqual(rig.page.mapping.reads, reads + 1)
            rig.page.mapping.data[:] = baseline
            rig.page.sequences[0] = owner.ADAPTER_PROGRESS_MAX - 1
            rig.hook("run-owned", command=1)
            self.assertTrue(rig.page.disabled[0])
            self.assertIsNone(rig.snapshot()["owner"])
            final_sequence = rig.page.sequences[0]
            self.assertIsNone(rig.hook("begin"))
            self.assertEqual(rig.page.sequences[0], final_sequence)
        for change in ("elapsed", "completed", "total"):
            with self.subTest(overflow=change), self.progress_page() as rig:
                rig.hook("begin")
                if change == "elapsed":
                    rig.state.now = 10.0 + (1 << 31)
                else:
                    setattr(rig.page, change, 1 << 31)
                rig.hook("run-owned", command=1)
                self.assertTrue(rig.page.disabled[0])
                self.assertIsNone(rig.snapshot()["owner"])

    def test_progress_optional_io_and_normal_cancellation_do_not_become_success(self):
        for error in (OSError("inert optional IO"), KeyboardInterrupt(), SystemExit(17)):
            with self.subTest(error=type(error).__name__), self.progress_page() as rig:
                rig.page.mapping.write_error = error
                if isinstance(error, Exception):
                    rig.hook("task-entered")
                    self.assertTrue(rig.page.disabled[0])
                else:
                    with self.assertRaises(type(error)) as caught:
                        rig.hook("task-entered")
                    self.assertIs(caught.exception, error)
                rig.page.mapping.read_error = error
                if isinstance(error, Exception):
                    self.assertIsNone(rig.snapshot())
                else:
                    with self.assertRaises(type(error)) as caught:
                        rig.snapshot()
                    self.assertIs(caught.exception, error)

    def test_prefix_helper_traces_acquisition_through_original_close(self):
        # Execute the actual shared helper, but replace every outer worker,
        # account/model and filesystem entry before reaching it. No setUp or
        # genuine case launch is invoked by this scope-only regression.
        events, active = [], False
        model = SimpleNamespace(trace=None, state={"original": {"default": "inert", "search": []}})
        trace = SimpleNamespace(selector=None)

        def note(operation, *, model_traced=False):
            self.assertTrue(active, operation + " preceded original Trace installation")
            self.assertIs(model.trace, trace if model_traced else None)
            events.append(operation)

        @contextmanager
        def installed():
            nonlocal active
            self.assertFalse(active)
            active = True
            events.append("trace-enter")
            try:
                yield
            finally:
                active = False
                events.append("trace-exit")

        def result():
            self.assertFalse(active)
            events.append("result")
            return {}

        trace.installed, trace.result = installed, result
        session = SimpleNamespace(
            bind_runner=lambda runner: note("bind"),
            open=lambda *, create: note("session-open"),
            prepare=lambda content, uuid: note("prepare"),
            run=lambda argv, *, kind: note("query", model_traced=True),
            cleanup_native=lambda: note("cleanup-native"),
            cleanup_profile=lambda: note("cleanup-profile"),
            finish=lambda: note("finish"),
        )

        def new_session():
            note("session")
            return session

        @contextmanager
        def lease(*, home):
            note("lease-open")
            try:
                yield SimpleNamespace(session=new_session)
            finally:
                note("lease-close")

        root = Path("/inert/prefix-scope")
        def postconditions(observed_root, *, expected_preferences):
            self.assertFalse(active)
            self.assertEqual(observed_root, root)
            self.assertIs(expected_preferences, model.state["original"])
            events.append("postconditions")
        with patch.object(fixture, "PersistentSigningModel", return_value=model), \
                patch.object(fixture.signing, "local_signing_lease", new=lease), \
                patch.object(fixture, "assert_positive_postconditions", new=postconditions):
            semantic.one_journalled_query(root, trace, phase="setup")
        self.assertEqual(events, ["trace-enter", "lease-open", "session", "bind", "session-open", "prepare",
                                  "query", "cleanup-native", "cleanup-profile", "finish", "lease-close",
                                  "trace-exit", "postconditions", "result"])

    def test_trace_dirfd_provenance_dup_retirement_and_excluded_origins(self):
        with patch.object(fixture, "ResourceOracle"):
            trace = fixture.Trace(Path("/inert/case"), "inert-descriptors")
        calls = []
        numbers = iter((101, 102, 103, 102, 201, 202, 203, 204, 205))

        def opened(path, flags, **kwargs):
            calls.append(("open", path, flags, kwargs))
            return next(numbers)

        def duplicated(fd):
            calls.append(("dup", fd))
            return next(numbers)

        def closed(fd):
            calls.append(("close", fd))

        opening, duplicate, close = (trace.wrapper(name, actual) for name, actual in (
            ("open", opened), ("dup", duplicated), ("close", closed)))

        def caller(module):
            namespace = {"__name__": module}
            exec(compile("def call(operation, *args, **kwargs):\n    return operation(*args, **kwargs)\n",
                         "<inert-trace-origin>", "exec"), namespace)
            return namespace["call"]

        production = caller("mobile_release.local_signing")
        with self.assertRaises(KeyError):
            production(opening, "state.json", os.O_RDONLY, dir_fd=909)
        self.assertEqual((calls, trace.events, trace.descriptors), ([], [], {}))
        home = production(opening, "/inert/case/home", os.O_RDONLY)
        directory = production(opening, "session", os.O_RDONLY, dir_fd=home)
        copy = production(duplicate, directory)
        self.assertEqual(trace.descriptors, {101: "/inert/case/home", 102: "/inert/case/home/session",
                                             103: "/inert/case/home/session"})
        production(close, directory)
        before = len(calls), len(trace.events)
        with self.assertRaises(KeyError):
            production(opening, "state.json", os.O_RDONLY, dir_fd=directory)
        self.assertEqual((len(calls), len(trace.events)), before)
        descriptor = production(opening, "state.json", os.O_RDONLY, dir_fd=copy)
        self.assertEqual(descriptor, directory)  # A newly observed open may reuse the retired number.
        self.assertEqual(trace.descriptors[descriptor], "/inert/case/home/session/state.json")
        for descriptor in (descriptor, copy, home):
            production(close, descriptor)
        self.assertEqual(trace.descriptors, {})
        recorded = len(trace.events)
        for module in ("mobile_release._command_process", "mobile_release._native_process",
                       "mobile_release.owned_process", "unit.inert", "workflow.inert"):
            excluded = caller(module)
            descriptor = production(excluded, opening, "/inert/excluded", os.O_RDONLY)
            production(excluded, close, descriptor)
            self.assertEqual((len(trace.events), trace.descriptors), (recorded, {}))
        self.assertFalse(any(event["slot"] == "unmapped-descriptor" for event in trace.events))

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

    def test_progress_launcher_allocates_inside_lifetime_and_reads_only_after_original_settlement(self):
        for fault in (None, "deadline", "record", "wait"):
            with self.subTest(fault=fault), self.recorded_owner(fault=fault) as rig:
                context = object()
                events = rig.events
                class Page(self.Page):
                    def __getitem__(self, key):
                        events.append(("progress-read",))
                        return super().__getitem__(key)
                page = Page()
                def allocate(*args):
                    self.assertEqual(args, (-1, 4096))
                    events.append(("progress-allocate",))
                    return page
                with patch.multiple(owner, ADAPTER_DIAGNOSTIC_CONTEXT=context, ADAPTER_CASE_FAILURE=None,
                                    ADAPTER_CASE_PROGRESS=None, mmap=SimpleNamespace(mmap=allocate)):
                    if fault is None:
                        owner.run_worker(Path("/inert"), "query", rig.task, write_json=rig.record)
                        self.assertIsNone(owner.adapter_case_progress(context))  # Success emits no progress.
                    else:
                        with self.assertRaises((AssertionError, OSError)):
                            owner.run_worker(Path("/inert"), "query", rig.task, write_json=rig.record)
                    if fault == "deadline":
                        self.assertEqual(owner.adapter_case_failure(context), (0, -9, 0, True, True))
                        self.assertEqual(owner.adapter_case_progress(context), {"case": "query", "owner": None, "service": None})
                        self.assertIsNone(owner.adapter_case_progress(object()))
                self.assertEqual(page.reads, int(fault in (None, "deadline")))
                self.assertEqual(page.closes, 1)
                self.assertEqual(events[0], ("progress-allocate",))
                if page.reads:
                    read = events.index(("progress-read",))
                    before = events[:read]
                    self.assertEqual(sum(row[0] == "receive" for row in before), 3)  # ARMED, terminal, original EOF.
                    self.assertEqual(sum(row[0] == "wait" for row in before), 2)
                    self.assertTrue(any(row[0] == "absent" for row in before))

    def test_progress_allocation_read_and_once_close_errors_preserve_original_primary(self):
        for error in (OSError("inert allocation"), KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(allocation=type(error).__name__), self.recorded_owner() as rig, \
                    patch.multiple(owner, ADAPTER_DIAGNOSTIC_CONTEXT=object(), ADAPTER_CASE_FAILURE=None,
                                   ADAPTER_CASE_PROGRESS=None, mmap=SimpleNamespace(mmap=Mock(side_effect=error))):
                if isinstance(error, Exception):
                    owner.run_worker(Path("/inert"), "query", rig.task, write_json=rig.record)
                else:
                    with self.assertRaises(type(error)) as caught:
                        owner.run_worker(Path("/inert"), "query", rig.task, write_json=rig.record)
                    self.assertIs(caught.exception, error)
                    self.assertFalse(rig.events)  # Interrupted allocation admitted no pipe or fork.
        for fault in (None, "deadline"):
            for operation in ("read", "close"):
                with self.subTest(fault=fault, operation=operation), self.recorded_owner(fault=fault) as rig:
                    page, retained = self.Page(), []
                    error = KeyboardInterrupt() if operation == "read" else OSError("inert ambiguous close")
                    setattr(page, operation + "_error", error)
                    with patch.multiple(owner, ADAPTER_DIAGNOSTIC_CONTEXT=object(), ADAPTER_CASE_FAILURE=None,
                                        ADAPTER_CASE_PROGRESS=None, _RETAINED_ADAPTER_PROGRESS=retained,
                                        mmap=SimpleNamespace(mmap=lambda *_: page)):
                        expected = AssertionError if fault else KeyboardInterrupt if operation == "read" else BaseExceptionGroup
                        with self.assertRaises(expected) as caught:
                            owner.run_worker(Path("/inert"), "query", rig.task, write_json=rig.record)
                        if fault:
                            self.assertIn("observed -9", str(caught.exception))
                            self.assertIn(error, caught.exception._case_cleanup_errors)
                        elif operation == "read":
                            self.assertIs(caught.exception, error)
                        else:
                            self.assertEqual(caught.exception.exceptions, (error,))
                        if operation == "close":
                            self.assertEqual(len(retained), 1)
                            self.assertIs(retained[0].mapping, page)
                            retained[0].close([])  # Already claimed, never retried even after failure.
                        self.assertEqual(page.closes, 1)
        with self.progress_page() as rig, patch.object(owner, "_RETAINED_ADAPTER_PROGRESS", []) as retained:
            error, errors = SystemExit(23), []
            rig.page.mapping.close_error = error
            rig.page.close(errors)  # W cannot claim the launcher's close.
            self.assertEqual(rig.page.mapping.closes, 0)
            rig.state.pid = 700
            rig.page.close(errors)
            rig.page.close(errors)
            self.assertEqual((errors, rig.page.mapping.closes), ([error], 1))
            self.assertEqual(retained, [rig.page])

    def test_recovery_progress_observes_existing_busy_loop_without_an_extra_query(self):
        statuses = [{"status": "busy"}, {"status": "busy"}, {"status": "idle"}]
        with patch.object(fixture.signing, "signing_status", side_effect=statuses) as query, \
                patch.object(owner, "CASE_DEADLINE", 20.0), patch.object(owner, "remaining", return_value=1.0), \
                patch.object(owner, "adapter_progress") as progress, \
                patch.object(fixture, "time", SimpleNamespace(sleep=lambda _seconds: None)), \
                patch.object(fixture, "snapshot", side_effect=ValueError("inert stop before recovery IO")), \
                self.assertRaisesRegex(ValueError, "inert stop"):
            fixture.recovery_flow(Path("/inert"), None)
        self.assertEqual(query.call_count, 3)
        self.assertEqual([row.args[0] for row in progress.call_args_list], ["recovery-check", "recovery-busy", "recovery-ready"])

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
            recorder._root_identity = fixture._directory_identity(recorder.root)
            recorder._semantic_adapter_complete = None
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
        def progress(stage, **kwargs):
            calls.append(("progress", stage, kwargs))
            return 1 if stage == "begin" else None
        with patch.object(bridge, "Namespace", return_value=namespace), \
                patch.object(bridge, "Channel", Channel), patch.object(bridge, "time", clock), \
                patch.object(persistent_model, "threading", SimpleNamespace(Event=Event, Thread=Thread)), \
                patch.object(persistent_model, "time", clock), \
                patch.object(persistent_model, "_RETAINED_MODEL_LIFETIMES", retained), \
                patch.object(owned_process, "run_owned", side_effect=run) as launch, \
                patch.object(owner, "adapter_progress", side_effect=progress) as progress_hook, \
                patch.object(owner, "observe_adapter_target_result", create=True) as diagnostic:
            yield SimpleNamespace(model=model, calls=calls, events=events, namespace=namespace,
                                  retained=retained, launch=launch, diagnostic=diagnostic, progress=progress_hook)

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
                    stages = [call.args[0] for call in rig.progress.call_args_list]
                    self.assertIn("target-return", stages)
                    self.assertNotIn("model-return", stages)
                    rig.launch.assert_called_once()

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
            self.assertNotIn("target-return", [call.args[0] for call in rig.progress.call_args_list])
            self.assertNotIn("model-return", [call.args[0] for call in rig.progress.call_args_list])
            rig.launch.assert_called_once()

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
                    self.assertEqual([call.args[0] for call in rig.progress.call_args_list],
                        ["begin", "bind-service", "run-owned", "target-return", "HELLO", "DONE", "EOF",
                         "service-joined", "model-return"])
                    self.assertLess(next(i for i, call in enumerate(rig.calls) if call[:2] == ("progress", "bind-service")),
                                    rig.calls.index(("start",)))
                    self.assertLess(rig.calls.index(("remove",)),
                                    next(i for i, call in enumerate(rig.calls) if call[:2] == ("progress", "model-return")))
                    rig.launch.assert_called_once()

        observation = OSError("PRIVATE actual service EOF failure")
        returned = persistent_model.subprocess.CompletedProcess(["actual-target"], 0, "", "")
        with self.recorded_model(returned, eof_error=observation) as rig:
            with self.assertRaisesRegex(AssertionError, "model observation failed") as caught:
                rig.model(["security", "default-keychain", "-d", "user"])
            self.assertIs(caught.exception.__cause__, observation)
            self.assertFalse(hasattr(caught.exception, "_model_cleanup_errors"))  # Already retained as the actual cause.
            rig.namespace.remove.assert_not_called()
            rig.diagnostic.assert_called_once_with(returned)
            self.assertNotIn("model-return", [call.args[0] for call in rig.progress.call_args_list])


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
            with patch.object(fixture, "run_worker", side_effect=intermediate), \
                    self.assertRaisesRegex(AssertionError, "missing original case return"):
                fixture.settle_focused_fixture(root, plan)
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
        self._root_identity = fixture._directory_identity(self.root)
        self._semantic_adapter_complete = None

    def tearDown(self):
        # Preserve uncertainty. No destructor, recorded PID, wait-then-signal or
        # guessed process identity is used to authorize cleanup after failure.
        self.assertEqual(fixture._directory_identity(self.root), self._root_identity,
                         "original adapter root changed; fixture evidence retained")
        owned = {key: value for key, value in fixture._CASE_CUSTODY.items()
                 if Path(key).is_relative_to(self.root)}
        debt = [key for key in fixture._CASE_RECOVERY_DEBT if Path(key).is_relative_to(self.root)]
        self.assertFalse(debt or any(value is None for value in owned.values()),
                         "original case/C finality unconfirmed; fixture files retained")
        self.assertIsNot(self._semantic_adapter_complete, False,
                         "semantic adapter assertions incomplete; fixture evidence retained")
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
        self._adapter_command_worker_origins = None  # A reused TestCase cannot supply stale evidence.
        package = Path(fixture.signing.__file__).resolve(strict=True).parent  # Before the original worker fork.
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
            return {"actual_model_command": True, "origins": matrix_contract.actual_adapter_origins(
                package, "commandWorker", deadline=fixture.PHASE_DEADLINE)}
        returned = fixture.run_worker(case, "healthy", task, timeout=10)
        fixture.assert_original_return(returned, expected=0)
        record = fixture.read_case_json(case, "healthy")
        self.assertEqual(set(record), {"actual_model_command", "origins"})
        self.assertIs(record["actual_model_command"], True)
        self._adapter_command_worker_origins = dict(matrix_contract.validate_adapter_origins(record["origins"], "commandWorker"))
        fixture.remove_case(case)

    def test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery(self):
        evidence = self.semantic_adapter("C/fence/04")
        self.assertEqual([step["name"] for step in evidence["steps"]], ["seed", "semantic-main"])
        cut = evidence["steps"][0]["observation"]
        self.assertEqual(cut["edge"], "partial")
        original = cut["originalCFenceObservation"]
        self.assertTrue(original["originalWorker"] and original["originalReadClosed"])
        self.assertTrue(0 < original["written"] < original["total"])
        self.assertEqual(bytes.fromhex(original["actualReadHex"]), bytes.fromhex(original["operandHex"])[:original["written"]])
        final = evidence["steps"][1]
        self.assertEqual((final["manual"], final["expected"], final["observation"]["result"]["status"]),
                         ("none", "recovered", "recovered"))
        self.assertTrue(final["observation"]["idleAndRenewedAdmission"])
        self.assertEqual(evidence["negativeEvidence"], [])
        self._semantic_adapter_complete = True

    def semantic_adapter(self, identifier):
        from workflow.local_signing_regression_catalog import semantic_contributions
        self.assertIn(identifier, {"C/fence/04", "S/active-build-pending/none"})
        self._semantic_adapter_complete = False
        value = semantic.run_case(self.root, identifier)
        stem = "semantic-" + fixture.digest(identifier) + "-complete"
        self.assertEqual(value, {"caseId": identifier, "status": "semantic-subset-case", "evidence": stem + ".json",
                                 "caseRemoved": True, "originalWorkersSettled": True,
                                 "regressionContributions": list(semantic_contributions(identifier))})
        evidence = fixture.read_case_json(self.root, stem)
        self.assertEqual(evidence["schema"], "mrk-signing-semantic-case-v1")
        self.assertEqual(evidence["case"], semantic.catalog.case(identifier).record())
        self.assertFalse((self.root / "case").exists())
        return evidence

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
        evidence = self.semantic_adapter("S/active-build-pending/none")
        self.assertEqual([step["name"] for step in evidence["steps"]], ["seed", "semantic-main", "semantic-resolution"])
        cut = evidence["steps"][0]["observation"]
        self.assertEqual(cut["selector"]["occurrence"], 3)
        self.assertTrue(cut["physicalWrite"]["properPrefix"])
        # Live SETTLED/native-new was not committed: the durable ARMED state
        # still records the previous DB inode.  A genuine C pair is not native
        # ownership adoption.  Automatic refusal must survive owner cleanup.
        durable = cut["snapshot"]["controls"]["state.json"]["value"]
        live = cut["context"]["liveState"]
        self.assertEqual((durable["inflight"]["phase"], live["inflight"]["phase"]), ("ARMED", "SETTLED"))
        self.assertNotEqual(durable["native"][fixture.signing.DB_NAME], live["native"][fixture.signing.DB_NAME])
        negative, final = evidence["steps"][1:]
        self.assertEqual((negative["manual"], negative["expected"]), ("none", "refused-unknown-resource"))
        self.assertIsNotNone(negative["observation"]["refused"])
        self.assertFalse(negative["observation"]["idleAndRenewedAdmission"])
        self.assertEqual(len(evidence["negativeEvidence"]), 1)
        self.assertEqual(fixture.read_case_json(self.root, Path(evidence["negativeEvidence"][0]).stem), negative)
        self.assertEqual((final["manual"], final["expected"], final["observation"]["result"]["status"]),
                         ("resolve", "recovered-with-conflict", "recovered-with-conflict"))
        self.assertTrue(final["observation"]["idleAndRenewedAdmission"])
        self._semantic_adapter_complete = True

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
