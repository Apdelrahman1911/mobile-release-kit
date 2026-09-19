"""Inert contracts for the closed hosted shim/observer, not hosted evidence.

Only two fixed non-main source definitions are loaded. No product process owner
is imported and no helper/main, process, descriptor, signal, thread or native
routine is executed. All method effects below use closed in-memory stand-ins.
The separately reviewed lead command owns execution of this finite selection.
"""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch


def definition(key):
    # No arbitrary source selector, sys.path change, package import or __main__.
    files = {"observer": ("workflow/command_bootstrap_fixture.py", "_mrk_environment_observer_contract"),
             "shim": ("native_desktop_environment.py", "_mrk_environment_shim_contract")}
    relative, name = files[key]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / relative)
    if spec is None or spec.loader is None:
        raise AssertionError("missing fixed definition loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeFS:
    """No fallback to a real OS method; every number/path is inert DATA."""
    O_RDONLY, O_WRONLY, O_RDWR = os.O_RDONLY, os.O_WRONLY, os.O_RDWR
    O_CREAT, O_EXCL, O_APPEND = os.O_CREAT, os.O_EXCL, os.O_APPEND
    O_CLOEXEC, O_NOFOLLOW = getattr(os, "O_CLOEXEC", 0), getattr(os, "O_NOFOLLOW", 0)

    def __init__(self):
        self.files, self.fds, self.calls = {}, {}, []
        self.next_fd, self.next_inode = 900000, 100
        self.open_error = self.read_error = self.pread_error = self.write_error = None
        self.open_hook = self.close_hook = None
        self.close_errors, self.partial = {}, None
        self.path = types.SimpleNamespace(join=lambda *parts: str(PurePosixPath(*parts)),
                                          isabs=lambda path: PurePosixPath(path).is_absolute())
        fs = self

        class FixedPath(PurePosixPath):
            def mkdir(self, *, mode):
                fs.calls.append(("mkdir", str(self), mode))
                if str(self) in fs.files:
                    raise AssertionError("fake directory already exists")
                fs.add(str(self), mode=stat.S_IFDIR | mode)

            def lstat(self):
                fs.calls.append(("lstat", str(self)))
                return fs.details(fs.files[str(self)])

            def resolve(self):
                if not self.is_absolute():
                    raise AssertionError("fake paths are already absolute")
                return self

            def is_symlink(self):
                return stat.S_ISLNK(fs.files[str(self)].mode)

        self.Path = FixedPath

    def add(self, path, data=b"", *, mode=stat.S_IFREG | 0o600):
        if path in self.files:
            raise AssertionError("fake path reused")
        self.next_inode += 1
        entry = types.SimpleNamespace(data=bytearray(data), mode=mode, inode=self.next_inode)
        self.files[path] = entry
        return entry

    @staticmethod
    def details(entry):
        return types.SimpleNamespace(st_dev=1, st_ino=entry.inode, st_uid=1000, st_gid=1000,
            st_mode=entry.mode, st_nlink=1, st_size=len(entry.data), st_mtime_ns=1, st_ctime_ns=1)

    @staticmethod
    def getpid():
        return 200

    @staticmethod
    def getppid():
        return 100

    @staticmethod
    def getuid():
        return 1000

    def open(self, path, flags, mode=0o600):
        path = str(path)
        self.calls.append(("open", path, flags))
        if self.open_hook is not None:
            self.open_hook(path, flags)
        if flags & self.O_CREAT:
            if not flags & self.O_EXCL or path in self.files:
                raise AssertionError("only exclusive fake creation")
            self.add(path, mode=stat.S_IFREG | mode)
        entry = self.files[path]
        self.next_fd += 1
        self.fds[self.next_fd] = types.SimpleNamespace(entry=entry, flags=flags, offset=0)
        if self.open_error is not None:
            raise self.open_error  # Consumed fake acquisition with lost return.
        return self.next_fd

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        return self.details(self.fds[fd].entry)

    def write(self, fd, data):
        data = bytes(data)
        self.calls.append(("write", fd, len(data)))
        slot = self.fds[fd]
        if not slot.flags & self.O_APPEND:
            raise AssertionError("only held append writers in these tests")
        count = len(data) if self.partial is None else min(self.partial, len(data))
        slot.entry.data.extend(data[:count])
        if self.write_error is not None:
            raise self.write_error
        return count

    def read(self, fd, size):
        self.calls.append(("read", fd, size))
        if self.read_error is not None:
            raise self.read_error
        slot = self.fds[fd]
        raw = bytes(slot.entry.data[slot.offset:slot.offset + size])
        slot.offset += len(raw)
        return raw

    def pread(self, fd, size, offset):
        self.calls.append(("pread", fd, size, offset))
        if self.pread_error is not None:
            raise self.pread_error
        return bytes(self.fds[fd].entry.data[offset:offset + size])

    def close(self, fd):
        self.calls.append(("close", fd))
        if self.close_hook is not None:
            self.close_hook(fd)
        self.fds.pop(fd)  # Consumed even when its return is deliberately lost.
        if fd in self.close_errors:
            raise self.close_errors[fd]


def command_fixture(events):
    """Definitions only; no actual command/bootstrap/native owner is imported."""
    class Outer:
        def publish(actual):
            events.append(("publish", actual))
            return actual.outcome

        def _pump(actual):
            events.append(("pump", actual))
            return "original-pump-return"

    class Custodian:
        def __init__(self, context):
            events.append(("custodian-init", self, context))
            self.ctx = context

        def finish(self):
            raise AssertionError("unselected fake finish")

        def _source_io(self):
            events.append(("source-io", self))
            return "original-source-return"

    class Anchor:
        def __init__(self, context):
            events.append(("anchor-init", self, context))
            self.ctx = context

        def finish(self):
            raise AssertionError("unselected fake finish")

    class AnchorGroup:
        def terminate(self):
            raise AssertionError("unselected fake terminate")

        def probe(self):
            raise AssertionError("unselected fake probe")

    class SelfGroup:
        def terminate(self):
            raise AssertionError("unselected fake terminate")

    class ProcessError(Exception):
        pass

    def accept_stop(context, content):
        events.append(("accept-stop", context, content))
        result = ProcessError("original inert STOP")
        context.stop_received = context.stopped = True
        if context.primary is None:
            context.primary = result
        context.failure_cutoff = context.run
        return result

    return types.SimpleNamespace(_BOOTSTRAP="original-bootstrap", _Outer=Outer,
        _Custodian=Custodian, _Anchor=Anchor, _AnchorGroup=AnchorGroup, _SelfGroup=SelfGroup,
        _command_event=lambda *_args, **_kwargs: None, _command_spec=lambda *_args, **_kwargs: None,
        _accept_stop=accept_stop, ProcessError=ProcessError, HELPER_UNKNOWN=70)


def control_data():
    return {"schemaVersion": 1, "case": "L3a", "runId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "inert_project", "draftRevision": 2, "baselineGeneration": 3,
                    "platform": "android", "operation": "build"},
        "profile": "linux-gnu-x86_64", "python": "/inert/python", "core": "/inert/core",
        "cwd": "/inert/runtime", "projectRoot": "/inert/project", "inputManifestSha256": "c" * 64,
        "shimSha256": "d" * 64, "observerSha256": "e" * 64, "relayIdentity": [1, 100, 1000, stat.S_IFREG | 0o600]}


def engine_fixture(shim, value, *, initialize_error=None):
    events, box = [], {}
    started = 100.0

    class Request:
        pass

    class Guard:
        def check(self):
            events.append(("check", self))
            if self.cancelled:
                raise InterruptedError("inert original STOP latch")

    class Input:
        def stop(self, reason):
            events.append(("stop", self, reason))
            self.stop_reason, self.guard.cancelled = reason, True

    class Service:
        pass

    class Engine:
        def __init__(self, original_started):
            events.append(("initialize", self, box["observation"].engine is self))
            if initialize_error is not None:
                raise initialize_error
            self.started = original_started
            self.guard, self.input = Guard(), Input()
            self.guard.cancelled = False
            self.guard._environment_source = None
            self.guard.handler_state = "NEW"
            self.input.guard, self.input.acquired = None, False
            self.input.active = self.input.request_returned = self.input.close_claimed = self.input.closed = False
            self.input.custody_unknown, self.input.stop_reason = False, "none"
            self.input.work_end = started + 6.0
            self.request = self.service = None
            self.output = types.SimpleNamespace(owned=False, close_claimed=False, closed=False)
            self.error_output = types.SimpleNamespace(owned=False, close_claimed=False, closed=False)

    observation = shim.EngineObservation(Engine, Request, Guard, Input, Service, value, started)
    box["observation"] = observation

    def activate(actual):
        actual.input.acquired = actual.input.active = actual.input.request_returned = True
        actual.input.guard = actual.guard
        actual.guard._environment_source = actual.input
        actual.guard.handler_state = "INSTALLED"
        actual.request = Request()
        actual.request.run_id, actual.request.owner_generation = value["runId"], value["ownerGeneration"]
        actual.request.context = copy.deepcopy(value["context"])
        actual.request.native = {key: value[key] for key in ("profile", "projectRoot", "cwd")}
        actual.service = Service()
        actual.service.request, actual.service.guard, actual.service.source = actual.request, actual.guard, actual.input
        actual.service.lookup = types.SimpleNamespace(closed=False)
        verdict = types.SimpleNamespace(complete=True, fatal=False, contained=True, cleanup_complete=True,
                                        profile_calls=0, command_dispatched=True)
        actual.guard.lifetime_ledger = types.SimpleNamespace(verdict=lambda: verdict)
        return actual

    return types.SimpleNamespace(Engine=Engine, Request=Request, observation=observation,
                                 events=events, started=started, activate=activate)


@unittest.skipUnless(os.name == "posix", "closed hosted fixture requires POSIX definitions")
class NativeEnvironmentFixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.owner_modules = {name: sys.modules.get(name) for name in
            ("mobile_release._command_process", "mobile_release._native_process")}
        self.observer, self.shim = definition("observer"), definition("shim")
        self.fs, self.events, self.serial = FakeFS(), [], 0
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for module in (self.observer, self.shim):
            self.stack.enter_context(patch.object(module, "os", self.fs))
            self.stack.enter_context(patch.object(module, "Path", self.fs.Path))
            self.stack.enter_context(patch.object(module, "signal", types.SimpleNamespace()))
        self.stack.enter_context(patch.object(self.observer, "fcntl", types.SimpleNamespace()))

        def no_pause():
            raise AssertionError("retention loop is never selected by inert contracts")

        self.stack.enter_context(patch.object(self.shim, "_PAUSE", no_pause))
        self.stack.enter_context(patch.object(self.observer, "sys", types.SimpleNamespace(
            argv=["inert"] * 6 + ["5000000000", "9000000000", "f" * 32])))
        self.stack.enter_context(patch.object(self.observer, "time", types.SimpleNamespace(monotonic_ns=lambda: 2_000_000_000)))
        self.stack.enter_context(patch.object(self.shim, "time", types.SimpleNamespace(monotonic=lambda: 103.25)))
        self.stack.enter_context(patch.object(self.observer, "build_bootstrap", lambda _original, _settings: "fixed-inert-recipe"))

    def tearDown(self):
        self.assertEqual({name: sys.modules.get(name) for name in self.owner_modules}, self.owner_modules)

    def calls(self, operation):
        return [call for call in self.fs.calls if call[0] == operation]

    def settings(self):
        self.serial += 1
        root = f"/inert/roles-{self.serial}"
        identities = []
        for role in self.observer.ROLES:
            entry = self.fs.add(root + "/" + role + ".trace")
            identities.append((1, entry.inode, 1000))
        return self.observer.OBSERVE_HELD, "/inert/fixed.py", root, tuple(identities)

    def relay(self, case="L4", *, acquire=True):
        self.serial += 1
        path = f"/inert/relay-{self.serial}/relay.trace"
        entry = self.fs.add(path)
        relay = self.observer.ObserveRelay(path, (1, entry.inode, 1000, entry.mode), case=case,
                                            run_id="a" * 32, owner_generation="b" * 32)
        if acquire:
            relay.acquire()
        return relay

    def prepared(self):
        relay = self.relay()
        command = command_fixture(self.events)
        self.serial += 1
        case = self.observer.CommandCase(command, f"/inert/command-{self.serial}", "observe-held")
        case.prepare_held(relay)
        return command, case, relay

    @staticmethod
    def final_facts(*, ready=False, stop=None):
        return {"intercepts": 1, "readyObserved": ready, "noNextCall": True,
            "reason": "cancelled" if stop is not None else "command-incomplete", "coreCode": 0,
            "commandNonce": "f" * 32, "recipeSha256": "e" * 64, "resultIntegrity": "incomplete",
            "dispatched": True, "contained": True, "cleanupComplete": True,
            "cWait": 2, "aWait": 2, "cFinish": 2, "aFinish": 2,
            "targetWait": {"kind": "signal", "code": 15}, "targetMarker": True, "readersJoined": True,
            "traceCloses": {"o": True, "c": True, "a": True, "w": True}, "stopBeforeWorkNs": stop,
            "capture": {"stdout": 8192, "stderr": 8193, "limit": 16384, "overflow": True}}

    @staticmethod
    def unused_facts():
        return {"intercepts": 0, "readyObserved": False, "observerClosed": True, "noNextCall": True,
                "reason": "git-not-admitted", "coreCode": 0}

    def test_definition_loads_are_non_main_without_product_owner_import(self):
        self.assertEqual(self.observer.__name__, "_mrk_environment_observer_contract")
        self.assertEqual(self.shim.__name__, "_mrk_environment_shim_contract")
        self.assertIsNone(self.shim._ENTRY_STARTED)
        self.assertEqual(self.shim._ROOTS, [])
        self.assertEqual(self.observer._RETAINED_CASES, [])
        self.assertEqual(self.observer._RETAINED_RELAYS, [])
        self.assertEqual(self.fs.calls, [])

    def test_held_record_has_no_constructor_io_and_is_published_before_open(self):
        settings, loader = self.settings(), {"_role": "C"}
        inert = self.observer._Record(loader, settings)
        self.assertEqual((inert.descriptor_state, self.fs.calls), ("NEW", []))

        def before_open(_path, _flags):
            record = loader["_mrk_fir03_record"]
            self.assertIsInstance(record, self.observer._Record)
            self.assertEqual(record.descriptor_state, "OPENING")
            self.assertIsNone(record.descriptor)

        self.fs.open_hook = before_open
        record = self.observer._record(loader, settings)
        self.assertEqual(record.descriptor_state, "OPEN")
        self.assertEqual(len(self.calls("open")), 1)
        self.assertEqual(set(self.observer.parse_trace(bytes(self.fs.files[record.path].data))), {"boot"})

    def test_record_lost_acquisition_stays_original_opening_without_retry(self):
        settings, loader = self.settings(), {"_role": "A"}
        first = RuntimeError("inert lost open return")
        self.fs.open_error = first
        with self.assertRaises(RuntimeError) as caught:
            self.observer._record(loader, settings)
        self.assertIs(caught.exception, first)
        record = loader["_mrk_fir03_record"]
        self.assertEqual(record.descriptor_state, "OPENING")
        self.assertTrue(record.broken)
        self.assertIs(record.errors[0], first)
        self.assertIsNone(record.descriptor)
        self.assertIs(self.observer._record(loader, settings), record)
        with self.assertRaises(AssertionError):
            record.acquire_observe_held()
        self.assertEqual(len(self.calls("open")), 1)
        self.assertEqual(len(self.fs.fds), 1)

    def test_record_lost_close_retires_before_effect_and_never_retries(self):
        record = self.observer._record({"_role": "C"}, self.settings())
        descriptor = record.descriptor
        first = RuntimeError("inert lost close return")
        self.fs.close_errors[descriptor] = first

        def before_close(fd):
            self.assertEqual(fd, descriptor)
            self.assertIsNone(record.descriptor)
            self.assertEqual(record.descriptor_state, "UNKNOWN")

        self.fs.close_hook = before_close
        record.close_owned()
        record.close_owned()
        self.assertEqual(record.descriptor_state, "UNKNOWN")
        self.assertTrue(record.broken)
        self.assertIs(record.errors[0], first)
        self.assertEqual(self.calls("close"), [("close", descriptor)])

    def test_broken_held_boot_refuses_before_original_helper(self):
        calls = []
        loader = {"_role": "C", "helper_main": lambda: calls.append("helper")}
        command = command_fixture(self.events)
        self.fs.write_error = RuntimeError("inert boot write loss")
        with self.assertRaises(AssertionError):
            self.observer.install(command, loader, self.settings())
        self.assertEqual(calls, [])
        self.assertEqual(command._BOOTSTRAP, "original-bootstrap")
        self.assertTrue(loader["_mrk_fir03_record"].sealed)
        self.assertEqual(loader["_mrk_fir03_record"].descriptor_state, "CLOSED")

    def test_both_owner_normal_returns_need_the_original_writer_close(self):
        for role in ("C", "A"):
            for code in (0, 2):
                for lost in (False, True):
                    with self.subTest(role=role, code=code, lost=lost):
                        calls = []
                        loader = {"_role": role, "helper_main": lambda: calls.append("helper") or code}
                        command = command_fixture(self.events)
                        self.observer.install(command, loader, self.settings())
                        record = loader["_mrk_fir03_record"]
                        if lost:
                            self.fs.close_errors[record.descriptor] = RuntimeError("inert gate close")
                        self.assertEqual(loader["helper_main"](), 70 if lost else code)
                        self.assertEqual(calls, ["helper"])
                        self.assertTrue(record.sealed)
                        self.assertEqual(record.descriptor_state, "UNKNOWN" if lost else "CLOSED")

    def test_original_helper_exception_identity_survives_close_failure(self):
        for role in ("C", "A"):
            with self.subTest(role=role):
                first = RuntimeError("inert original helper failure")

                def helper():
                    raise first

                loader = {"_role": role, "helper_main": helper}
                self.observer.install(command_fixture(self.events), loader, self.settings())
                record = loader["_mrk_fir03_record"]
                close_error = RuntimeError("inert close failure")
                self.fs.close_errors[record.descriptor] = close_error
                with self.assertRaises(RuntimeError) as caught:
                    loader["helper_main"]()
                self.assertIs(caught.exception, first)
                self.assertIs(record.errors[0], close_error)
                self.assertEqual(record.descriptor_state, "UNKNOWN")

    def test_worker_only_boot_closes_before_unwrapped_helper(self):
        loader = {"_role": "W"}

        def helper():
            record = loader["_mrk_fir03_record"]
            self.assertTrue(record.sealed)
            self.assertEqual(record.descriptor_state, "CLOSED")
            return 2

        loader["helper_main"] = helper
        command = types.SimpleNamespace(_BOOTSTRAP="original-bootstrap")  # No send/owner/self-stop aliases.
        self.observer.install(command, loader, self.settings())
        self.assertIs(loader["helper_main"], helper)
        self.assertEqual(helper(), 2)
        record = loader["_mrk_fir03_record"]
        self.assertEqual(record.seen, {"boot"})
        self.assertEqual(len(self.calls("open")), 1)
        self.assertEqual(len(self.calls("close")), 1)

    def test_reporting_failure_requests_the_bound_context_and_keeps_both_errors(self):
        for role in ("C", "A"):
            with self.subTest(role=role):
                loader, command = {"_role": role, "helper_main": lambda: 2}, command_fixture(self.events)
                self.observer.install(command, loader, self.settings())
                record = loader["_mrk_fir03_record"]
                first, second, observed = RuntimeError("inert write loss"), RuntimeError("inert STOP loss"), []

                def remember(error):
                    observed.append(error)
                    raise second

                context = types.SimpleNamespace(record=remember)
                owner = (command._Custodian if role == "C" else command._Anchor)(context)
                self.assertIs(record.context, context)
                self.assertIs(owner.ctx, context)
                self.fs.write_error = first
                record.emit("inert_report")
                self.assertEqual(observed, [first])
                self.assertEqual(record.errors, [first, second])
                self.assertTrue(record.broken)
                self.fs.write_error = None

    def test_c_stop_receipt_comes_after_same_original_accept_before_work_end(self):
        loader, command = {"_role": "C", "helper_main": lambda: 2}, command_fixture(self.events)
        self.observer.install(command, loader, self.settings())
        record = loader["_mrk_fir03_record"]
        context = types.SimpleNamespace(primary=None, failure_cutoff=None, cleanup_unknown=False, stopped=False,
            stop_received=False, launch_retired=False, run=5_000_000_000, record=lambda _error: None)
        command._Custodian(context)
        record.emit("target_ready", run=context.run, hard=9_000_000_000, at=1_000_000_000, marker="environment-target-v1")
        clocks = iter((2_000_000_000, 2_000_000_001))
        self.observer.time = types.SimpleNamespace(monotonic_ns=lambda: next(clocks))
        result = command._accept_stop(context, b"original-inert-frame")
        self.assertIs(context.primary, result)
        self.assertIs(type(result), command.ProcessError)
        rows = self.observer.parse_trace(bytes(self.fs.files[record.path].data))
        self.assertEqual(rows["stop_received"]["remaining"], 2_999_999_999)
        self.assertEqual(rows["stop_received"]["at"], 2_000_000_001)
        self.assertEqual([event[0] for event in self.events], ["custodian-init", "accept-stop"])

    def test_c_stop_late_prior_failure_or_original_raise_never_forges_receipt(self):
        for mode in ("late", "prior", "raise", "clock-loss"):
            with self.subTest(mode=mode):
                loader, command = {"_role": "C", "helper_main": lambda: 2}, command_fixture(self.events)
                first = RuntimeError("inert original stop failure")
                if mode == "raise":
                    def refuse(_context, _content):
                        raise first
                    command._accept_stop = refuse
                self.observer.install(command, loader, self.settings())
                record = loader["_mrk_fir03_record"]
                context = types.SimpleNamespace(primary=first if mode == "prior" else None, failure_cutoff=None,
                    cleanup_unknown=False, stopped=False, stop_received=False, launch_retired=False,
                    run=5_000_000_000, record=lambda _error: None)
                command._Custodian(context)
                record.emit("target_ready", run=context.run, hard=9_000_000_000, at=1_000_000_000, marker="environment-target-v1")
                if mode == "clock-loss":
                    def clock():
                        raise first
                    self.observer.time = types.SimpleNamespace(monotonic_ns=clock)
                else:
                    self.observer.time = types.SimpleNamespace(monotonic_ns=lambda: 5_000_000_000 if mode == "late" else 2_000_000_000)
                if mode == "raise":
                    with self.assertRaises(RuntimeError) as caught:
                        command._accept_stop(context, b"original-inert-frame")
                    self.assertIs(caught.exception, first)
                else:
                    result = command._accept_stop(context, b"original-inert-frame")
                    self.assertIs(type(result), command.ProcessError)
                self.assertNotIn("stop_received", self.observer.parse_trace(bytes(self.fs.files[record.path].data)))
                if mode == "clock-loss":
                    self.assertIs(record.errors[0], first)
                    self.assertTrue(context.stop_received)  # Original operation still called once.

    def test_relay_ready_final_and_actual_close_are_distinct_one_use_gates(self):
        relay = self.relay("L3a", acquire=False)
        self.assertIn(relay, self.observer._RETAINED_RELAYS)
        self.assertEqual(self.fs.calls, [])
        relay.acquire()
        relay.ready(nonce="f" * 32, recipe="e" * 64, remaining=2_000_000_000, source_delay=1)
        relay.finish("settled", self.final_facts(ready=True, stop=1_500_000_000))
        with self.assertRaises(AssertionError):
            relay.release()
        raw = bytes(self.fs.files[relay.path].data)
        rows = [self.shim.json.loads(line) for line in raw.splitlines()]
        self.assertEqual([row["event"] for row in rows], ["target-ready", "settled"])
        self.assertTrue(all("relayClosed" not in row for row in rows))
        self.assertLessEqual(len(raw), relay.BYTE_LIMIT)
        self.assertTrue(all(len(line) + 1 <= relay.ROW_LIMIT for line in raw.splitlines()))
        self.assertTrue(relay.close_owned())
        self.assertTrue(relay.close_owned())
        self.assertEqual(len(self.calls("close")), 1)
        relay.release()
        self.assertNotIn(relay, self.observer._RETAINED_RELAYS)

    def test_relay_lost_acquisition_keeps_original_slot_without_reopen(self):
        relay = self.relay(acquire=False)
        first = RuntimeError("inert relay open loss")

        def before_open(_path, _flags):
            self.assertIn(relay, self.observer._RETAINED_RELAYS)
            self.assertEqual(relay.state, "OPENING")

        self.fs.open_hook, self.fs.open_error = before_open, first
        with self.assertRaises(RuntimeError) as caught:
            relay.acquire()
        self.assertIs(caught.exception, first)
        self.assertEqual(relay.state, "OPENING")
        self.assertTrue(relay.broken)
        self.assertIs(relay.errors[0], first)
        self.assertIsNone(relay.fd)
        with self.assertRaises(AssertionError):
            relay.acquire()
        self.assertFalse(relay.close_owned())
        self.assertEqual(len(self.calls("open")), 1)
        self.assertEqual(self.calls("close"), [])

    def test_relay_consuming_write_or_close_loss_never_retries_or_releases(self):
        relay = self.relay()
        self.fs.partial = 1
        with self.assertRaises(AssertionError):
            relay.ready(nonce="f" * 32, recipe="e" * 64, remaining=2_000_000_000, source_delay=0)
        with self.assertRaises(AssertionError):
            relay.ready(nonce="f" * 32, recipe="e" * 64, remaining=2_000_000_000, source_delay=0)
        self.assertEqual(len(self.calls("write")), 1)
        self.assertTrue(relay.ready_sent)
        self.assertFalse(relay.close_owned())
        with self.assertRaises(AssertionError):
            relay.release()
        self.fs.partial = None
        other = self.relay()
        other.finish("unexecuted", self.unused_facts())
        descriptor = other.fd
        close_error = RuntimeError("inert relay close loss")
        self.fs.close_errors[descriptor] = close_error

        def before_close(_fd):
            self.assertIsNone(other.fd)
            self.assertEqual(other.state, "UNKNOWN")

        self.fs.close_hook = before_close
        self.assertFalse(other.close_owned())
        self.assertFalse(other.close_owned())
        self.assertEqual([call for call in self.calls("close") if call[1] == descriptor], [("close", descriptor)])
        self.assertIs(other.errors[0], close_error)
        self.assertIn(other, self.observer._RETAINED_RELAYS)

    def test_relay_rejects_open_schema_fake_lifetimes_and_invalid_stop_proof(self):
        variants = [("intercepts", True), ("cWait", 70), ("aFinish", 0), ("noNextCall", False),
            ("targetWait", {"kind": "unknown", "code": 0}), ("traceCloses", {"o": True, "c": True}),
            ("capture", {"stdout": 8192, "stderr": 8193, "limit": 8192, "overflow": True}),
            ("extra", "forbidden"), ("stopBeforeWorkNs", 1)]
        for key, value in variants:
            with self.subTest(key=key):
                relay = self.relay(acquire=False)
                facts = self.final_facts()
                facts[key] = value
                with self.assertRaises(AssertionError):
                    relay.finish("settled", facts)
                self.assertTrue(relay.broken)
        for stop in (None, True, 0, 3_000_000_001):
            with self.subTest(stop=stop):
                relay = self.relay("L3a", acquire=False)
                relay.ready_sent = True  # Synthetic parser-state DATA only.
                with self.assertRaises(AssertionError):
                    relay.finish("settled", self.final_facts(ready=True, stop=stop))
        self.assertEqual(self.fs.calls, [])

    def test_prepare_leaves_selector_originals_unpatched_and_unused_readers_close(self):
        command, case, _relay = self.prepared()
        self.assertEqual(command._BOOTSTRAP, "original-bootstrap")
        self.assertIs(command._Outer.publish, case.original[1])
        self.assertIs(command._Outer._pump, case.original[2])
        self.assertFalse(case.held_active)
        self.assertIn(case, self.observer._RETAINED_CASES)
        case.close_unactivated()
        self.assertEqual(case.snapshots, {"C": b"", "A": b"", "W": b""})
        self.assertTrue(all(slot["state"] == "CLOSED" for slot in case.slots))
        self.assertTrue(case.held_settled and case.released)
        self.assertIsNone(case.outcome)
        self.assertEqual(self.events, [])
        self.assertNotIn(case, self.observer._RETAINED_CASES)

    def test_unused_close_failure_retains_case_and_never_claims_unexecuted_settlement(self):
        command, case, _relay = self.prepared()
        descriptor = case.readers["C"]["fd"]
        first = RuntimeError("inert unused reader close loss")
        self.fs.close_errors[descriptor] = first
        with self.assertRaises(AssertionError):
            case.close_unactivated()
        self.assertIs(case.errors[0], first)
        self.assertEqual(case.readers["C"]["state"], "UNKNOWN")
        self.assertFalse(case.held_settled or case.released)
        self.assertIn(case, self.observer._RETAINED_CASES)
        counts = len(self.calls("open")), len(self.calls("close"))
        with self.assertRaises(AssertionError):
            case.close_unactivated()
        self.assertEqual(counts, (len(self.calls("open")), len(self.calls("close"))))
        self.assertEqual(command._BOOTSTRAP, "original-bootstrap")

    def test_pump_reporting_failure_calls_same_original_stop_after_original_pump(self):
        for stop_fails in (False, True):
            with self.subTest(stop_fails=stop_fails):
                command, case, _relay = self.prepared()
                first, second, order = RuntimeError("inert readiness loss"), RuntimeError("inert STOP loss"), []
                guard = types.SimpleNamespace()
                source = types.SimpleNamespace(guard=guard)

                def stop(reason):
                    order.append(("stop", reason))
                    if stop_fails:
                        raise second

                source.stop, guard._environment_source = stop, source
                actual = types.SimpleNamespace(guard=guard)

                def failed_ready(engine):
                    self.assertIs(engine, actual)
                    self.assertEqual(self.events[-1], ("pump", actual))
                    order.append(("ready",))
                    raise first

                case._held_ready = failed_ready
                case.activate_held()
                if stop_fails:
                    with self.assertRaises(RuntimeError) as caught:
                        command._Outer._pump(actual)
                    self.assertIs(caught.exception, first)
                    self.assertEqual(case.errors, [first, second])
                else:
                    self.assertEqual(command._Outer._pump(actual), "original-pump-return")
                    self.assertEqual(case.errors, [first])
                self.assertEqual(order, [("ready",), ("stop", "cancelled")])
                self.assertIs(case.engine, actual)
                self.assertIn(case, self.observer._RETAINED_CASES)

    def test_read_slot_preserves_first_error_and_unknown_acquisition_or_close(self):
        self.fs.add("/inert/control.json", b"{}", mode=stat.S_IFREG | 0o400)
        slot = self.shim.ReadSlot()
        self.assertIn(slot, self.shim._ROOTS)
        first, second = RuntimeError("inert first read failure"), RuntimeError("inert later close loss")
        self.fs.read_error = first

        def set_close_loss(_path, _flags):
            self.fs.close_errors[self.fs.next_fd + 1] = second

        self.fs.open_hook = set_close_loss
        with self.assertRaises(self.shim.RetainedUnknown):
            slot.content("/inert/control.json", 32, mode=0o400)
        self.assertIs(slot.error, first)
        self.assertEqual(slot.state, "UNKNOWN")
        self.assertIsNone(slot.fd)
        counts = len(self.calls("open")), len(self.calls("close"))
        with self.assertRaises(AssertionError):
            slot.content("/inert/control.json", 32, mode=0o400)
        self.assertEqual(counts, (len(self.calls("open")), len(self.calls("close"))))
        other = self.shim.ReadSlot()
        self.fs.open_hook = None
        self.fs.open_error = second
        with self.assertRaises(self.shim.RetainedUnknown):
            other.content("/inert/control.json", 32, mode=0o400)
        self.assertEqual(other.state, "OPENING")
        self.assertIs(other.error, second)
        self.assertEqual(len(self.calls("close")), counts[1])

    def test_control_schema_fixed_helper_aggregate_and_git_paths_are_closed_data(self):
        value = control_data()
        encode = lambda item: self.shim.json.dumps(item, separators=(",", ":")).encode()
        self.assertEqual(self.shim.parse_control(encode(value)), value)
        bad = []
        for key, replacement in (("schemaVersion", True), ("case", "shell"), ("python", "relative"),
            ("core", "/inert/../core"), ("runId", "A" * 32), ("argv", ["forbidden"]),
            ("relayIdentity", [1, 100, 1000, stat.S_IFREG | 0o644])):
            other = copy.deepcopy(value)
            other[key] = replacement
            bad.append(encode(other))
        for key, replacement in (("draftRevision", True), ("baselineGeneration", 2**32 - 1), ("platform", "ios")):
            other = copy.deepcopy(value)
            other["context"][key] = replacement
            bad.append(encode(other))
        bad.extend((b"", b"x" * (self.shim.CONTROL_LIMIT + 1),
                    encode(value).replace(b'"case":', b'"case":"L4","case":', 1)))
        for raw in bad:
            with self.subTest(length=len(raw)), self.assertRaises((AssertionError, ValueError)):
                self.shim.parse_control(raw)
        self.assertEqual(self.shim.READY_MARKER, self.observer.OBSERVE_READY)
        self.assertEqual(self.shim.CAP_STDOUT + self.shim.CAP_STDERR, 16385)
        self.assertTrue(len(self.shim.READY_MARKER) < self.shim.CAP_STDOUT < 16384)
        self.assertLess(self.shim.CAP_STDERR, 16384)
        self.assertTrue(self.shim._git_path("/usr/bin/git", "linux-gnu-x86_64"))
        self.assertFalse(self.shim._git_path("/usr/local/bin/git", "linux-gnu-x86_64"))
        self.assertTrue(self.shim._git_path("/Applications/Xcode_26.3.app/Contents/Developer/usr/bin/git", "macos-arm64"))
        self.assertFalse(self.shim._git_path("/inert/git", "macos-arm64"))
        self.assertEqual(self.fs.calls, [])

    def test_engine_observer_captures_before_unchanged_initializer_even_on_failure(self):
        first = RuntimeError("inert original initializer loss")
        fixture = engine_fixture(self.shim, control_data(), initialize_error=first)
        observation = fixture.observation
        observation.install()
        with self.assertRaises(RuntimeError) as caught:
            fixture.Engine(fixture.started)
        self.assertIs(caught.exception, first)
        self.assertIs(fixture.events[0][1], observation.engine)
        self.assertTrue(fixture.events[0][2])
        observation.stop()  # Never acquired input; no synthetic acquisition/STOP.
        self.assertFalse(observation.stop_attempted)
        self.assertEqual(len(fixture.events), 1)
        with self.assertRaises(AssertionError):
            fixture.Engine(fixture.started)
        with self.assertRaises(AssertionError):
            observation.restore()
        self.assertIs(fixture.Engine.__init__, observation.initialize)
        self.assertEqual(self.fs.calls, [])

    def test_engine_binding_uses_actual_request_context_native_and_object_identities(self):
        fixture = engine_fixture(self.shim, control_data())
        observation = fixture.observation
        observation.install()
        actual = fixture.activate(fixture.Engine(fixture.started))
        self.assertEqual(observation.bind(), (actual.guard, actual.input))
        mutations = [(actual.request, "run_id", "c" * 32), (actual.request, "owner_generation", "d" * 32),
            (actual.request, "context", {**actual.request.context, "draftRevision": 4}),
            (actual.request, "native", {**actual.request.native, "projectRoot": "/inert/other"}),
            (actual.request, "native", {**actual.request.native, "profile": "macos-arm64"}),
            (actual.request, "native", {**actual.request.native, "cwd": "/inert/other"}),
            (actual.service, "request", object())]
        for target, key, replacement in mutations:
            previous = getattr(target, key)
            with self.subTest(key=key):
                setattr(target, key, replacement)
                with self.assertRaises(AssertionError):
                    observation.bind()
                setattr(target, key, previous)
        replacement = fixture.Request()
        replacement.__dict__.update(actual.request.__dict__)
        actual.request = actual.service.request = replacement
        with self.assertRaises(AssertionError):
            observation.bind()  # Equal fields cannot replace the actual original.

    def test_engine_restore_requires_positive_original_input_output_and_lookup_closes(self):
        fixture = engine_fixture(self.shim, control_data())
        observation = fixture.observation
        original = fixture.Engine.__init__
        observation.install()
        actual = fixture.activate(fixture.Engine(fixture.started))
        with self.assertRaises(AssertionError):
            observation.settled()
        with self.assertRaises(AssertionError):
            observation.restore()
        actual.guard.handler_state, actual.guard._environment_source = "RESTORED", None
        actual.input.closed = actual.input.close_claimed = actual.service.lookup.closed = True
        for slot in (actual.output, actual.error_output):
            slot.owned = slot.close_claimed = slot.closed = True
        observation.settled()
        observation.restore()
        self.assertIs(fixture.Engine.__init__, original)
        self.assertIs(observation.engine, actual)
        self.assertEqual(len(fixture.events), 1)

    def test_outer_failure_retains_actual_error_and_stops_only_actual_acquired_input_once(self):
        fixture = engine_fixture(self.shim, control_data())
        observation = fixture.observation
        observation.install()
        actual = fixture.Engine(fixture.started)
        self.shim._ENGINE_OBSERVATION = observation
        first = RuntimeError("inert reporting/assertion failure")
        self.shim._stop_before_retention(first)
        self.assertIn(first, self.shim._ROOTS)
        self.assertFalse(observation.stop_attempted)
        fixture.activate(actual)
        self.shim._stop_before_retention(first)
        self.shim._stop_before_retention(first)
        self.assertEqual([event for event in fixture.events if event[0] == "stop"], [("stop", actual.input, "cancelled")])
        self.assertTrue(observation.stop_attempted)
        self.assertIs(fixture.Engine.__init__, observation.initialize)
        with self.assertRaises(AssertionError):
            observation.restore()
        other = engine_fixture(self.shim, control_data())
        other.observation.install()
        second_actual = other.activate(other.Engine(other.started))
        second, attempts = RuntimeError("inert original STOP loss"), []

        def failed_stop(reason):
            attempts.append(reason)
            raise second

        second_actual.input.stop = failed_stop
        self.shim._ENGINE_OBSERVATION = other.observation
        self.shim._stop_before_retention(first)
        other.observation.stop()
        self.assertEqual(attempts, ["cancelled"])
        self.assertIs(other.observation.errors[0], second)
        self.assertIn(first, self.shim._ROOTS)

    def test_settled_relay_facts_use_observed_capture_and_original_stop_receipt(self):
        class ProcessError(Exception):
            pass

        error = ProcessError("inert original command error")
        error.dispatched = error.contained = error.cleanup_complete = True
        verdict = types.SimpleNamespace(complete=True, fatal=False, contained=True, cleanup_complete=True,
                                        command_dispatched=True, profile_calls=0)
        guard = types.SimpleNamespace(lifetime_ledger=types.SimpleNamespace(verdict=lambda: verdict), handler_state="RESTORED")
        source = types.SimpleNamespace(closed=True, stop_reason="none")
        seam = types.SimpleNamespace(intercepts=1, no_next=True, error=error, guard=guard, source=source)
        owner = types.SimpleNamespace(wait=types.SimpleNamespace(status_code=2), outputs=[self.shim.READY_MARKER, b""],
                                      ctx=types.SimpleNamespace(run=5_000_000_000, tasks=[types.SimpleNamespace(joined=True)]))
        outcome = types.SimpleNamespace(original_finality=object(), run_tool=types.SimpleNamespace(attempted=True),
            no_target=None, result_integrity="incomplete", _engine=owner, nonce=bytes.fromhex("f" * 32))
        capture = {"stdout": 8192, "stderr": 8193, "limit": 16384, "overflow": True, "failed": False}
        rows = {"C": {"capture": capture, "owner_wait": {"code": 2}, "owner_finish": {"code": 2}, "owner_io": {"joined": True}},
                "A": {"owner_wait": {"kind": "signal", "code": 15}, "owner_finish": {"code": 2}, "owner_io": {"joined": True}},
                "W": {"boot": {}}}
        observed = []
        case = types.SimpleNamespace(held_settled=True, released=True, errors=[], require_finality=lambda: observed.append("checked"),
            outcome=outcome, rows=rows, slots=[{"state": "CLOSED"}], recipe="fixed-inert-recipe")
        relay = types.SimpleNamespace(broken=False, ready_sent=False)
        value = {**control_data(), "case": "L4"}
        facts = self.shim._settled_facts(value, seam, case, relay, ProcessError)
        self.assertEqual(facts["capture"], {key: capture[key] for key in ("stdout", "stderr", "limit", "overflow")})
        self.assertIsNone(facts["stopBeforeWorkNs"])
        capture["stdout"] -= 1
        with self.assertRaises(AssertionError):
            self.shim._settled_facts(value, seam, case, relay, ProcessError)
        capture.update(stdout=len(self.shim.READY_MARKER), stderr=0, overflow=False)
        value["case"], source.stop_reason, relay.ready_sent = "L3a", "cancelled", True
        rows["C"]["target_ready"] = {"run": owner.ctx.run, "at": 1_000_000_000}
        rows["C"]["stop_received"] = {"run": owner.ctx.run, "at": 2_000_000_000, "remaining": 3_000_000_000}
        facts = self.shim._settled_facts(value, seam, case, relay, ProcessError)
        self.assertEqual(facts["stopBeforeWorkNs"], 3_000_000_000)
        source.stop_reason = "timed-out"
        with self.assertRaises(AssertionError):
            self.shim._settled_facts(value, seam, case, relay, ProcessError)
        source.stop_reason = "cancelled"
        rows["C"]["stop_received"]["remaining"] = 0
        with self.assertRaises(AssertionError):
            self.shim._settled_facts(value, seam, case, relay, ProcessError)
        self.assertEqual(len(observed), 5)
        self.assertEqual(self.fs.calls, [])

    def test_git_seam_leaves_selector_original_and_intercepts_once_with_same_guard(self):
        for case_id in ("L4", "L5"):
            with self.subTest(case=case_id):
                value = control_data()
                value.update(case=case_id, profile="macos-arm64")
                fixture = engine_fixture(self.shim, value)
                fixture.observation.install()
                actual = fixture.activate(fixture.Engine(fixture.started))
                order, first, selector_result = [], RuntimeError("inert original command error"), object()

                class Case:
                    def __enter__(self):
                        order.append("enter")

                    def __exit__(self, kind, error, traceback):
                        order.append(("exit", error))
                        return False

                def original(argv, **options):
                    order.append(("call", argv, options))
                    if argv == ("/usr/bin/xcode-select", "-p"):
                        return selector_result
                    raise first

                seam = self.shim.GitSeam(value, Case(), original, fixture.observation, lambda *_args: {"FIXED": "1"})
                options = dict(environ={"FIXED": "1"}, cwd=self.fs.Path(value["cwd"]), timeout=3,
                               capture=True, text=False, output_limit=16384, cancellation=actual.guard)
                self.assertIs(seam(("/usr/bin/xcode-select", "-p"), **options), selector_result)
                self.assertEqual(len(order), 1)
                with self.assertRaises(RuntimeError) as caught:
                    seam(("/Library/Developer/CommandLineTools/usr/bin/git", "--version"), **options)
                self.assertIs(caught.exception, first)
                self.assertIs(seam.error, first)
                target = order[2]
                self.assertEqual(target[1], (value["python"], "-I", "-S", "-B", self.shim.__file__, "--target-cap"))
                self.assertIs(target[2]["cancellation"], actual.guard)
                self.assertEqual(target[2]["timeout"], 2)
                self.assertEqual(order[3], ("exit", first))
                with self.assertRaises(AssertionError):
                    seam(("/Library/Developer/CommandLineTools/usr/bin/git", "--version"), **options)
                self.assertEqual(len(order), 4)
                self.assertEqual(seam.intercepts, 1)
                self.assertFalse(seam.no_next)

    def test_git_seam_insufficient_original_work_margin_requests_stop_without_dispatch(self):
        value = control_data()
        fixture = engine_fixture(self.shim, value)
        fixture.observation.install()
        actual = fixture.activate(fixture.Engine(fixture.started))
        actual.input.work_end = 103.5
        calls = []
        seam = self.shim.GitSeam(value, object(), lambda *_args, **_kwargs: calls.append("forbidden"),
                                fixture.observation, lambda *_args: {})
        with self.assertRaises(InterruptedError):
            seam(("/usr/bin/git", "--version"), environ={}, cwd=self.fs.Path(value["cwd"]), timeout=1,
                 capture=True, text=False, output_limit=16384, cancellation=actual.guard)
        self.assertEqual(calls, [])
        self.assertEqual(seam.intercepts, 0)
        self.assertEqual(seam.missing_reason, "insufficient-work-margin")
        self.assertEqual(actual.input.stop_reason, "timed-out")


class OfflineCLIContractTests(unittest.TestCase):
    """Closed selector/owner bookkeeping with in-memory originals, not native evidence."""
    def setUp(self):
        self.modules = {name: module for name, module in sys.modules.items() if name.startswith("mobile_release")}
        self.shim, self.fs = definition("shim"), FakeFS()
        self.fs.lstat = lambda path: self.fs.details(self.fs.files[str(path)])
        self.fs.path.lexists = lambda path: str(path) in self.fs.files
        self.shim.os, self.shim.Path = self.fs, self.fs.Path
        self.clock = types.SimpleNamespace(check=lambda: None)

    def tearDown(self):
        self.assertEqual({name: module for name, module in sys.modules.items() if name.startswith("mobile_release")}, self.modules)

    @staticmethod
    def control():
        return {"schemaVersion": 1, "scope": "offline-preflight-native-v1", "inputsSha256": "a" * 64,
                "sourceSha": "b" * 40, "sourceTree": "c" * 40, "runId": "12", "attempt": "1", "platform": "linux",
                "python": "/inert/python", "core": "/inert/source/src", "source": "/inert/source", "root": "/inert/task",
                "startedNs": 1_000_000_000, "deadlineNs": 91_000_000_000}

    def observation(self):
        class Outer:
            def publish(actual):
                return actual.outcome
        class Guard:
            def __init__(actual, *args, **kwargs):
                actual.handler_state = "RESTORED"
                actual.lifetime_ledger = types.SimpleNamespace(verdict=lambda: types.SimpleNamespace(
                    complete=True, fatal=False, contained=True, cleanup_complete=True, profile_calls=0))
        class Invocation:
            def __init__(actual, *args, **kwargs):
                actual.cancellation, actual.closed = Guard(), True
            def _offline_preflight_closed(actual, guard):
                return actual.closed and guard is actual.cancellation
        class FD:
            def __init__(actual, *args, **kwargs):
                actual.number, actual.close_state = None, "CLOSED"
        fs, events = self.fs, []
        class Temporary:
            def __init__(actual, name):
                actual.name = name
                fs.add(name, mode=stat.S_IFDIR | 0o700)
            def cleanup(actual):
                events.append(("cleanup", actual))
                del fs.files[actual.name]
        command = types.SimpleNamespace(_Outer=Outer, run_command=lambda *_args, **_kwargs: None, _RETAINED=[])
        inputs = types.SimpleNamespace(InvocationCustody=Invocation, _FD=FD, _ENV_OWNER=None, _ENV_TAINTED=False)
        observation = self.shim.OfflineCLIObservation(command, inputs, Guard,
            types.SimpleNamespace(TemporaryDirectory=Temporary), self.clock)
        return observation, types.SimpleNamespace(command=command, inputs=inputs, Guard=Guard,
            Invocation=Invocation, temporary=Temporary, events=events)

    def install(self, observation):
        # None of these namespaces is a host/product module. No effect fallback.
        def unused(*args, **kwargs):
            raise AssertionError("unselected inert method")
        class Archive:
            __init__ = close = open = unused
        inspect = lambda *_args, **_kwargs: ()
        self.fs.fdopen, self.fs.scandir = unused, unused
        observation.install(builtins=types.SimpleNamespace(open=unused), io=types.SimpleNamespace(open=unused),
            zipfile=types.SimpleNamespace(ZipFile=Archive), config=types.SimpleNamespace(load_config=unused),
            macho=types.SimpleNamespace(inspect_macho=inspect),
            artifacts=types.SimpleNamespace(inspect_macho=inspect, _source_descriptor=unused),
            metadata=types.SimpleNamespace(_read_android_release_note=unused))

    def test_selector_control_and_original_deadline_are_closed(self):
        import json
        value = self.control()
        self.assertEqual(self.shim.parse_offline_cli_control(json.dumps(value).encode()), value)
        self.assertEqual(len(set(self.shim.OFFLINE_CLI_IDS)), 11)
        self.assertTrue(all(name.startswith("tests.unit.") for name in self.shim.OFFLINE_CLI_IDS))
        for key, replacement in (("extra", True), ("schemaVersion", True), ("deadlineNs", value["deadlineNs"] + 1),
                                  ("startedNs", False), ("core", "/different/src"), ("scope", "environment-diagnostics-native-v1"),
                                  ("source", "/inert/../source"), ("runId", "0"), ("sourceSha", "0" * 40)):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.shim.parse_offline_cli_control(json.dumps({**value, key: replacement}).encode())
        with self.assertRaises(AssertionError):
            self.shim.parse_offline_cli_control(b'{"schemaVersion":1,"schemaVersion":1}')

    def test_saved_configs_bind_exact_utf8_bytes_and_order(self):
        import hashlib
        raw = '{"value":"original\\r\\n"}\n'
        rows = [{"case": name, "rawText": raw, "size": len(raw.encode()),
                 "sha256": hashlib.sha256(raw.encode()).hexdigest()} for name in self.shim.OFFLINE_CASES]
        self.assertIs(self.shim.offline_saved_configs(rows), rows)
        for kind in ("order", "bytes", "digest", "length", "extra"):
            changed = copy.deepcopy(rows)
            if kind == "order":
                changed[0], changed[1] = changed[1], changed[0]
            elif kind == "bytes":
                changed[0]["rawText"] = raw.rstrip()
            elif kind == "digest":
                changed[0]["sha256"] = "0" * 64
            elif kind == "length":
                changed[0]["size"] = True
            else:
                changed[0]["repair"] = True
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                self.shim.offline_saved_configs(changed)

    def test_import_routes_bind_tests_namespace_and_workflow_modules(self):
        source = self.fs.Path("/inert/source")
        self.assertEqual(self.shim._offline_cli_import_paths("/inert/source/src", source),
                         ("/inert/source/src", "/inert/source", "/inert/source/tests"))
        with self.assertRaises(AssertionError):
            self.shim._offline_cli_import_paths("/other/src", source)
        paths = {"mobile_release": "src/mobile_release/__init__.py", "tests.unit": "tests/unit/__init__.py",
                 "workflow": "tests/workflow/__init__.py", "workflow.profile_resource_fixture": "tests/workflow/profile_resource_fixture.py"}
        modules = {name: types.SimpleNamespace(__file__=str(source / path)) for name, path in paths.items()}
        modules["tests"] = types.SimpleNamespace(__path__=[str(source / "tests")])
        self.shim.sys = types.SimpleNamespace(modules=modules)
        names = frozenset(paths.values())
        self.shim._offline_cli_modules(source, names)
        for changed in (["/ambient/tests"], [str(source / "tests"), "/ambient/tests"], []):
            modules["tests"].__path__ = changed
            with self.subTest(namespace=changed), self.assertRaises(AssertionError):
                self.shim._offline_cli_modules(source, names)
        modules["tests"].__path__ = [str(source / "tests")]
        modules["workflow.profile_resource_fixture"].__file__ = str(source / "tests/unit/__init__.py")
        with self.assertRaises(AssertionError):
            self.shim._offline_cli_modules(source, names)
        modules["workflow.profile_resource_fixture"].__file__ = str(source / paths["workflow.profile_resource_fixture"])
        with self.assertRaises(AssertionError):
            self.shim._offline_cli_modules(source, names - {paths["workflow.profile_resource_fixture"]})

    def test_closed_swallowed_scanner_error_latches_failure_not_unknown(self):
        observation, _ = self.observation()
        self.install(observation)
        events, problem = [], OSError("inert scanner failure")
        class Iterator:
            def __enter__(actual):
                return actual
            def __next__(actual):
                raise problem
            def __exit__(actual, *_error):
                events.append("original-exit")
                return False
        adapter = observation.scanner(lambda *_args: Iterator())("/inert/scan")
        try:
            with adapter:
                next(adapter)
        except OSError:
            pass  # Models glob's swallowed error, not successful traversal.
        self.assertEqual(events, ["original-exit"])
        self.assertEqual(observation.resources[-1]["state"], "CLOSED")
        self.assertIs(observation.resources[-1]["error"], problem)
        observation.require_closed()
        self.assertTrue(observation.scan_failed())
        observation.restore()  # Positive original close allows safe restoration.
        self.assertTrue(observation.closed)
        self.assertTrue(observation.scan_failed())  # Restoration cannot repair success.

    def test_diagnostic_is_fixed_bounded_original_stderr_and_never_retried(self):
        calls = []
        self.shim._CLI_MODE, self.shim._CLI_STAGE = True, "leaf-4"
        def failed(number, raw):
            calls.append((number, raw))
            raise OSError("inert diagnostic write failure")
        self.shim._CLI_DIAGNOSTIC_WRITE = failed
        self.shim._offline_cli_diagnostic("test-failed")
        self.shim._offline_cli_diagnostic("unsettled-originals")
        self.assertEqual(calls, [(2, b"OFFLINE_CLI11_FAILURE stage=leaf-4 kind=test-failed\n")])
        self.shim._CLI_DIAGNOSTIC_WRITTEN = False
        self.shim._CLI_STAGE = "/private/untrusted-value"
        self.shim._offline_cli_diagnostic("untrusted reason")
        self.assertEqual(calls[-1], (2, b"OFFLINE_CLI11_FAILURE stage=entry kind=admission-failed\n"))

    def test_scanner_original_close_return_and_failure_are_distinct(self):
        events = []
        class Iterator:
            def __init__(actual, failed=False):
                actual.values, actual.failed = iter([object()]), failed
            def __next__(actual):
                return next(actual.values)
            def __enter__(actual):
                return actual
            def close(actual):
                events.append(actual)
                if actual.failed:
                    raise ValueError("inert lost original close")
            def __exit__(actual, *_error):
                actual.close()
                return False
        row, original = {"state": "OPEN"}, Iterator()
        adapter = self.shim.OfflineIterator(row, original)
        self.assertIs(adapter.__enter__(), adapter)
        self.assertEqual(len(list(adapter)), 1)
        self.assertEqual(row["state"], "CLOSED")
        adapter.__exit__(None, None, None)
        adapter.close()
        self.assertEqual(events, [original])
        broken_row, broken = {"state": "OPEN"}, Iterator(True)
        broken_adapter = self.shim.OfflineIterator(broken_row, broken)
        with self.assertRaises(ValueError):
            broken_adapter.close()
        self.assertEqual(broken_row["state"], "UNKNOWN")
        with self.assertRaises(AssertionError):
            broken_adapter.close()
        self.assertEqual(events, [original, broken])

    def test_original_stream_identity_context_close_and_handoff_loss(self):
        observation, _ = self.observation()
        calls = []
        class Stream:
            closed = False
            def __enter__(actual):
                return actual
            def __exit__(actual, *_error):
                actual.close()
            def close(actual):
                calls.append(actual)
                actual.closed = True
        row, original = observation.row("stream"), Stream()
        self.assertIs(observation.stream(row, original), original)
        with original as returned:
            self.assertIs(returned, original)
        self.assertEqual(row["state"], "CLOSED")
        original.close()
        self.assertEqual(calls, [original])
        def refused(_number):
            raise OSError(9, "inert handoff failed")
        with self.assertRaises(OSError):
            observation.opener(refused, descriptor=True)(900001)
        self.assertEqual(observation.resources[-1]["state"], "OPENING")
        with self.assertRaises(self.shim.OfflineCLIUnknown):
            observation.require_closed()

    def test_command_attempt_precedes_call_and_missing_publication_stays_unknown(self):
        observation, _ = self.observation()
        outcome = types.SimpleNamespace(original_finality=object())
        engine = types.SimpleNamespace(outcome=outcome, slot=types.SimpleNamespace(read=lambda: outcome))
        def run():
            self.assertEqual(observation.commands, [None])
            self.assertEqual(observation.active, [0])
            self.assertIs(observation.publish(engine), outcome)
            return "original-return"
        observation.original_run = run
        self.assertEqual(observation.command_call(), "original-return")
        observation.require_closed()
        observation.original_run = lambda: (_ for _ in ()).throw(ValueError("inert lost publication"))
        with self.assertRaises(ValueError):
            observation.command_call()
        self.assertEqual(observation.commands, [outcome, None])
        with self.assertRaises(self.shim.OfflineCLIUnknown):
            observation.require_closed()
        self.assertTrue(issubclass(self.shim.OfflineCLIUnknown, KeyboardInterrupt))

    def test_nested_temp_routing_keeps_outer_and_allows_closed_inner_cleanup(self):
        observation, model = self.observation()
        self.install(observation)
        outer = model.temporary("/inert/outer")
        parent = model.Invocation()
        parent.closed, parent.cancellation.handler_state = False, "ACTIVE"
        inner = model.temporary("/inert/inner")
        inner.cleanup()
        self.assertEqual(model.events, [("cleanup", inner)])
        with self.assertRaises(self.shim.OfflineCLIUnknown):
            outer.cleanup()
        self.assertIn(outer.name, self.fs.files)
        self.assertEqual(model.events, [("cleanup", inner)])
        parent.closed, parent.cancellation.handler_state = True, "RESTORED"
        observation.require_closed()  # Model-only facts, not native recovery.

    def test_facility_restoration_waits_for_original_invocation(self):
        observation, model = self.observation()
        events = []
        class Manager:
            def __enter__(actual):
                return actual
            def __exit__(actual, *_error):
                events.append("original-exit")
                return False
        wrapped = observation.context(Manager, facility=True)()
        wrapped.__enter__()
        parent = model.Invocation()
        parent.closed = False
        observation.invocations.append({"owner": parent, "ready": True})
        with self.assertRaises(self.shim.OfflineCLIUnknown):
            wrapped.__exit__(None, None, None)
        self.assertEqual(events, [])
        self.assertEqual(observation.resources[0]["state"], "OPEN")

    def test_closed_assertion_failure_is_not_unknown_but_alias_drift_refuses(self):
        observation, _ = self.observation()
        self.install(observation)
        try:
            raise AssertionError("inert ordinary assertion")
        except AssertionError:
            observation.leaf_closed()
        owner, name, _original, _replacement = observation.patches[-1]
        setattr(owner, name, object())
        with self.assertRaises(AssertionError):
            observation.restore()
        self.assertFalse(observation.closed)

    def test_clock_uses_original_endpoint_and_restores_only_its_handler(self):
        calls, handlers, tick, timer = [], {14: 0}, [50_000_000_000], [0.0, 0.0]
        def setter(number, value):
            previous, handlers[number] = handlers[number], value
            calls.append(("handler", number, value))
            return previous
        def arm(kind, value):
            previous = tuple(timer)
            timer[:] = [value, 0.0]
            calls.append(("timer", kind, value))
            return previous
        self.shim.time = types.SimpleNamespace(monotonic_ns=lambda: tick[0])
        self.shim.signal = types.SimpleNamespace(SIGALRM=14, ITIMER_REAL=0, SIG_DFL=0,
            getsignal=handlers.__getitem__, signal=setter, getitimer=lambda _kind: tuple(timer), setitimer=arm)
        clock = self.shim.OfflineCLIClock(1_000_000_000, 91_000_000_000)
        clock.install()
        self.assertEqual([call[2] for call in calls if call[0] == "timer"], [41.0])
        tick[0] = 91_000_000_000
        with self.assertRaises(self.shim.OfflineCLIDeadline):
            clock.check()
        tick[0] = 50_000_000_000
        with self.assertRaises(self.shim.OfflineCLIDeadline):
            clock.check()
        clock.finish()
        self.assertEqual(clock.state, "CLOSED")
        self.assertEqual(handlers, {14: 0})
        self.assertEqual([call[2] for call in calls if call[0] == "timer"], [41.0, 0.0])
