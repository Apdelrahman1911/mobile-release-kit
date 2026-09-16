"""Inert PP3 seams: no child, signal setter, worker or native launch is executed.

Real POSIX signal/process evidence remains in process_fixture and the root-owned
native batch. These modeled wait/kill receipts are not substitutes for it.
"""
from __future__ import annotations

import os
import signal
import sys
import tempfile
import unittest
import weakref
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import build_inputs as inputs
from mobile_release import cancellation as cancellation_module
from mobile_release import workflow
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError, ProcessError

from .test_workflow_recovery import FakeGitHub, Lifecycle, context


PID = 234567
STDOUT = 876543


class ModelStdout:
    def __init__(self, model):
        self.model, self.closed = model, False

    def fileno(self):
        return STDOUT

    def close(self):
        self.model.events.append("stdout-close")
        self.closed = True
        if self.model.on_close is not None:
            self.model.on_close()


class ModelProcess:
    def __init__(self, model):
        self.pid, self.returncode = PID, None
        self.stdout = ModelStdout(model)

    def wait(self, *args, **kwargs):
        raise AssertionError("Popen.wait must not perform a hidden or repeated reap")

    def poll(self):
        raise AssertionError("Popen.poll must not consume Transport's original wait")


class ModelSelector:
    def __init__(self, model):
        self.model, self.mapping = model, {}

    def register(self, stream, events):
        self.mapping[STDOUT] = SimpleNamespace(fd=STDOUT, fileobj=stream)

    def get_map(self):
        return self.mapping

    def select(self, timeout):
        self.model.events.append("select")
        if self.model.on_select is not None:
            self.model.on_select()
        return [(item, workflow.selectors.EVENT_READ) for item in self.mapping.values()]

    def unregister(self, stream):
        del self.mapping[STDOUT]

    def close(self):
        self.model.events.append("selector-close")
        self.mapping.clear()


class TransportModel:
    def __init__(self, case, guard):
        self.case, self.guard = case, guard
        self.events, self.owners = [], []
        self.process = ModelProcess(self)
        self.blocks = [b"verified\n", b""]
        self.receipts = [(PID, 0)]
        self.on_spawn = self.on_select = self.on_kill = self.on_wait = self.on_close = None

    def install(self, stack):
        original_init = workflow._TransportProcess.__init__

        def capture(owner, guard):
            original_init(owner, guard)
            self.case.assertIs(guard, self.case.guard)
            self.owners.append(owner)

        stack.enter_context(patch.object(workflow._TransportProcess, "__init__", new=capture))
        self.spawn_mock = stack.enter_context(patch.object(workflow.subprocess, "Popen", side_effect=self.spawn))
        stack.enter_context(patch.object(workflow.selectors, "DefaultSelector", side_effect=lambda: ModelSelector(self)))
        stack.enter_context(patch.object(workflow.os, "read", side_effect=self.read))
        stack.enter_context(patch.object(workflow.os, "killpg", side_effect=self.kill))
        stack.enter_context(patch.object(workflow.os, "waitpid", side_effect=self.wait))

    def spawn(self, arguments, **options):
        self.events.append("spawn")
        self.case.assertEqual(arguments[0], "gh")
        self.case.assertTrue(options["start_new_session"])
        self.case.assertEqual(options["stderr"], workflow.subprocess.DEVNULL)
        self.case.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", options["env"])
        self.case.assertIn(self.owners[0], workflow._TRANSPORT_OWNERS.values())
        self.case.assertGreater(self.guard.depth, 0)
        if self.on_spawn is not None:
            self.on_spawn()
        return self.process

    def read(self, descriptor, count):
        self.case.assertEqual(descriptor, STDOUT)
        return self.blocks.pop(0)

    def kill(self, pid, signum):
        self.events.append("kill")
        self.case.assertEqual((pid, signum), (PID, signal.SIGKILL))
        self.case.assertEqual(self.owners[0].wait_state, "OPEN")
        self.case.assertIsNone(self.process.returncode)
        if self.on_kill is not None:
            self.on_kill()

    def wait(self, pid, flags):
        self.events.append("wait")
        self.case.assertEqual((pid, flags), (PID, os.WNOHANG))
        self.case.assertGreater(self.guard.depth, 0)
        self.case.assertEqual(self.owners[0].wait_state, "ATTEMPTED")
        if self.on_wait is not None:
            self.on_wait()
        value = self.receipts.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class TransportCancellationTests(unittest.TestCase):
    def setUp(self):
        from mobile_release import _profile_process, ios_profiles
        # Inert fixture registrations share one test-owned registry. Register
        # restorations first so original aliases return only after every
        # fixture/model cleanup, including failed setup or body execution.
        registry = weakref.WeakSet()
        for module in (cancellation_module, ios_profiles, _profile_process, inputs):
            self.enterContext(patch.object(module, "_FORK_RESOURCES", registry))
        # Clearing is permitted only for this family's entirely inert records,
        # never for a preceding test's actual unresolved native resources.
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)
        self.addCleanup(workflow._TRANSPORT_OWNERS.clear)
        temporary = tempfile.TemporaryDirectory(prefix="mrk-transport-cancellation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.guard = self.new_guard()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("kill", "killpg", "fork", "execve", "pipe", "waitpid"):
            self.stack.enter_context(patch.object(command.os, name, side_effect=AssertionError("unexpected process effect")))
        for target, name in ((command.native, "create"), (command.threading.Thread, "start"),
                             (command.subprocess, "Popen"), (workflow.signal, "signal")):
            self.stack.enter_context(patch.object(target, name, side_effect=AssertionError("unexpected native/worker/signal effect")))
        original_owner = inputs.cancellation_owner
        self.stack.enter_context(patch.object(inputs, "cancellation_owner",
            side_effect=lambda requested, error, message: original_owner(self.guard if requested is None else requested, error, message)))

    def new_guard(self):
        guard = DefaultCancellation(ProcessCleanupError, "synthetic transport owner")
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        return guard

    def model(self):
        model = TransportModel(self, self.guard)
        model.install(self.stack)
        return model

    def call(self, **kwargs):
        return workflow.Transport().run(["gh", "api", "--method", "GET", "fixed"], cancellation=self.guard, **kwargs)

    def test_outer_namespace_signal_during_spawn_handoff_keeps_original_cleanup_custody(self):
        model = self.model()
        app = self.root / "app"
        app.mkdir()
        model.on_spawn = lambda: self.guard.interrupt(signal.SIGTERM, sys._getframe())
        with self.assertRaises(KeyboardInterrupt):
            with inputs.app_private_namespace(app, cancellation=self.guard) as original:
                self.assertIs(original.cancellation, self.guard)
                self.call(output=self.root / "download")
        self.assertEqual(["spawn", "kill", "wait", "stdout-close"], model.events)
        self.assertEqual("REAPED", model.owners[0].wait_state)
        self.assertEqual("CLOSED", model.owners[0].output.close_state)
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)
        self.assertEqual("NOT_ATTEMPTED", self.guard._restoration)

    def test_first_signal_during_normal_close_cannot_escape_cleanup_or_return_success(self):
        model = self.model()
        model.on_close = lambda: self.guard.interrupt(signal.SIGTERM, sys._getframe())
        with self.assertRaises(KeyboardInterrupt):
            self.call()
        self.assertNotIn("kill", model.events)
        self.assertEqual(1, model.events.count("wait"))
        self.assertTrue(model.process.stdout.closed)
        self.assertTrue(model.owners[0].settled())
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)

    def test_claimed_scope_deferred_entry_failure_rescues_cleanup_before_owned_restore(self):
        model = self.model()
        primary = SystemExit(9)
        gap = MemoryError("claimed scope before original cleanup callback entry")
        model.on_select = lambda: (_ for _ in ()).throw(primary)
        model.on_kill = lambda: self.guard.interrupt(signal.SIGTERM, sys._getframe())
        self.guard._installation, self.guard._activated, self.guard.depth = "NOT_INSTALLED", False, 1
        original_deferred = self.guard.deferred
        original_scope_init = workflow._TransportScope.__init__
        scopes, injected = [], []

        def capture(scope, owner):
            original_scope_init(scope, owner)
            scopes.append(scope)

        def deferred(**kwargs):
            if scopes and scopes[0].claimed and not model.owners[0].cleanup_entered and not injected:
                self.assertIs(scopes[0]._first_error, primary)
                injected.append(gap)
                raise gap
            return original_deferred(**kwargs)

        def install():
            model.events.append("install")
            self.guard._installation = "INSTALLED"

        def restore():
            self.assertTrue(model.owners[0].cleanup_entered)
            self.assertTrue(model.owners[0].settled())
            model.events.append("restore")
            self.guard._restoration = "RESTORED"

        with patch.object(workflow, "cancellation_owner", return_value=(self.guard, True)), \
                patch.object(workflow._TransportScope, "__init__", new=capture), \
                patch.object(self.guard, "deferred", new=deferred), \
                patch.object(self.guard, "install", new=install), patch.object(self.guard, "restore", new=restore):
            with self.assertRaises(SystemExit) as caught:
                self.call()
        self.assertIs(caught.exception, primary)
        self.assertEqual([gap], injected)
        self.assertIn(gap, scopes[0]._cleanup_errors)
        self.assertLess(model.events.index("stdout-close"), model.events.index("restore"))
        self.assertEqual(1, model.events.count("kill"))
        self.assertEqual(1, model.events.count("wait"))
        self.assertTrue(self.guard.lifetime_ledger.fatal)
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)

    def test_zero_and_nonzero_terminal_receipts_never_signal_after_reap(self):
        for code in (0, 7):
            with self.subTest(code=code), ExitStack() as local:
                self.guard = self.new_guard()
                model = TransportModel(self, self.guard)
                model.install(local)
                model.receipts = [(PID, code << 8)]
                if code:
                    with self.assertRaisesRegex(workflow.WorkflowError, "no fallback"):
                        self.call()
                else:
                    self.assertEqual(b"verified\n", self.call())
                self.assertEqual(code, model.process.returncode)
                self.assertNotIn("kill", model.events)
                self.assertEqual(1, model.events.count("wait"))
                self.assertEqual({}, workflow._TRANSPORT_OWNERS)

    def test_eof_but_live_positive_idle_receipt_preserves_bounded_cleanup_route(self):
        model = self.model()
        model.blocks = [b""]
        # os.waitpid returns built-in integer status, not a signal enum.
        model.receipts = [(0, 0), (PID, int(signal.SIGKILL))]
        # Body deadline expires only after the genuine idle receipt. Cleanup
        # receives its separate finite deadline and retains the original route.
        now = [0.0]
        with patch.object(workflow.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(workflow.time, "sleep", side_effect=lambda delay: now.__setitem__(0, 2.0)):
            with self.assertRaisesRegex(workflow.WorkflowError, "timed out"):
                self.call(timeout=1)
        self.assertEqual(["wait", "kill", "wait"], [event for event in model.events if event in {"wait", "kill"}])
        self.assertEqual(-signal.SIGKILL, model.process.returncode)
        self.assertTrue(model.owners[0].settled())
        self.assertIsNone(model.owners[0].first_cleanup_error)
        self.assertFalse(self.guard.lifetime_ledger.fatal)
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)

    def test_cleanup_wait_budget_exhaustion_retains_original_without_retry(self):
        model = self.model()
        primary = KeyboardInterrupt()
        model.on_select = lambda: (_ for _ in ()).throw(primary)
        model.receipts = [(0, 0), (0, 0)]
        now, sleeps = [0.0], []

        def pause(delay):
            self.assertLessEqual(delay, 0.05)
            sleeps.append(delay)
            now[0] += 3.0  # Model scheduler delay, not an unbounded requested sleep.

        with patch.object(workflow.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(workflow.time, "sleep", side_effect=pause):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.call(output=self.root / "timed-out-cleanup")
        self.assertIs(caught.exception, primary)
        self.assertEqual(2, len(sleeps))
        self.assertEqual(1, model.events.count("kill"))
        self.assertEqual(2, model.events.count("wait"))
        self.assertIsNone(model.process.returncode)
        owner = model.owners[0]
        self.assertTrue(owner.cleanup_entered and owner.unsettled)
        self.assertTrue(model.process.stdout.closed)
        self.assertEqual("CLOSED", owner.selector_state)
        self.assertEqual("CLOSED", owner.output.close_state)
        self.assertIn(owner, workflow._TRANSPORT_OWNERS.values())
        self.assertTrue(self.guard.lifetime_ledger.fatal)

    def test_lost_wait_return_is_unknown_never_retried_and_blocks_new_transport(self):
        model = self.model()
        lost = ChildProcessError("modeled loss after original reap")
        model.receipts = [lost]
        with self.assertRaises(ProcessError):
            self.call()
        owner = model.owners[0]
        self.assertEqual("UNKNOWN", owner.wait_state)
        self.assertIsNone(model.process.returncode)  # Never manufacture0 for Popen finalization.
        self.assertIn(owner, workflow._TRANSPORT_OWNERS.values())
        self.assertIs(owner.process, model.process)
        self.assertNotIn("kill", model.events)
        self.assertEqual(1, model.events.count("wait"))
        self.guard = self.new_guard()
        with self.assertRaisesRegex(workflow.WorkflowError, "ownership is unresolved"):
            self.call()
        self.assertEqual(1, model.spawn_mock.call_count)

    def test_lost_spawn_return_does_not_adopt_a_later_pid_or_claim_no_child(self):
        model = self.model()
        model.on_spawn = lambda: (_ for _ in ()).throw(OSError("modeled after-spawn return loss"))
        with self.assertRaises(ProcessError):
            self.call()
        owner = model.owners[0]
        self.assertEqual("UNKNOWN", owner.spawn_state)
        self.assertIsNone(owner.process)
        self.assertNotIn("kill", model.events)
        self.assertNotIn("wait", model.events)
        self.assertIn(owner, workflow._TRANSPORT_OWNERS.values())
        self.assertTrue(self.guard.lifetime_ledger.fatal)

    def test_cleanup_signal_and_kill_error_preserve_primary_and_independent_closes(self):
        model = self.model()
        primary = KeyboardInterrupt()
        model.on_select = lambda: (_ for _ in ()).throw(primary)

        def kill_failure():
            self.guard.interrupt(signal.SIGTERM, sys._getframe())
            raise OSError("modeled loss after signal dispatch")

        model.on_kill = kill_failure
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.call(output=self.root / "partial")
        self.assertIs(caught.exception, primary)
        self.assertEqual(1, model.events.count("kill"))
        self.assertEqual(1, model.events.count("wait"))
        self.assertTrue(model.process.stdout.closed)
        self.assertEqual("CLOSED", model.owners[0].selector_state)
        self.assertEqual("CLOSED", model.owners[0].output.close_state)
        self.assertEqual("UNKNOWN", model.owners[0].signal_state)
        self.assertTrue(self.guard.lifetime_ledger.fatal)

    def test_lost_stdout_close_return_is_not_retried_or_allowed_to_return_bytes(self):
        model = self.model()
        model.on_close = lambda: (_ for _ in ()).throw(OSError("modeled after-close return loss"))
        with self.assertRaises(ProcessError):
            self.call(output=self.root / "retained")
        self.assertEqual(1, model.events.count("stdout-close"))
        self.assertEqual("UNKNOWN", model.owners[0].stdout_state)
        self.assertEqual("CLOSED", model.owners[0].output.close_state)
        self.assertIn(model.owners[0], workflow._TRANSPORT_OWNERS.values())
        self.assertNotIn("kill", model.events)

    def test_nonzero_binary_output_is_retained_and_retry_cannot_replace_it(self):
        model = self.model()
        model.blocks = [b"\x00\xffretained-zip-bytes", b""]
        model.receipts = [(PID, 7 << 8)]
        target = self.root / "download.zip"
        with self.assertRaises(workflow.WorkflowError):
            self.call(output=target)
        self.assertEqual(b"\x00\xffretained-zip-bytes", target.read_bytes())
        self.assertEqual(0o600, target.stat().st_mode & 0o777)
        with self.assertRaises(workflow.WorkflowError):
            self.call(output=target)
        self.assertEqual(1, model.spawn_mock.call_count)
        self.assertEqual(b"\x00\xffretained-zip-bytes", target.read_bytes())
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)

    def test_immutable_client_views_forward_exact_guard_without_overwriting_prior_binding(self):
        api = FakeGitHub()
        client = api.client(context())
        view = client.with_cancellation(self.guard)
        self.assertIsNot(client, view)
        self.assertIsNone(client.cancellation)
        self.assertIs(view.cancellation, self.guard)
        with self.assertRaises(AttributeError):
            view.cancellation = self.new_guard()
        self.assertIs(client._trees, view._trees)
        self.assertIs(client.transport, view.transport)
        calls = []
        original = api.run

        def run(arguments, **options):
            self.assertIs(options["cancellation"], self.guard)
            self.guard._borrowable()
            calls.append(arguments)
            return original(arguments, **options)

        with patch.object(api, "run", side_effect=run):
            self.assertEqual("3" * 40, view.tree("2" * 40))
        self.assertTrue(calls)
        with self.assertRaisesRegex(workflow.WorkflowError, "different cancellation"):
            view.with_cancellation(self.new_guard())
        self.assertIsNone(client.cancellation)
        self.assertIs(view.cancellation, self.guard)

    def test_actual_seal_and_package_clients_share_outer_zero_handler_owner(self):
        api = FakeGitHub()
        original_run = api.run
        observed = []

        def run(arguments, **options):
            self.assertIs(options["cancellation"], self.guard)
            self.guard._borrowable()
            observed.append(tuple(arguments[:3]))
            return original_run(arguments, **options)

        with patch.object(api, "run", side_effect=run):
            lifecycle = Lifecycle(self.root, api)
            selected, app, intent = lifecycle.prepare("candidate")
            package = lifecycle.finish("candidate", selected, app, intent,
                                       destination=app / ".mobile-release/package/candidate/android")
        self.assertTrue((package / "workflow-provenance.json").is_file())
        self.assertIn(("gh", "api", "--hostname"), observed)
        self.assertIn(("gh", "attestation", "verify"), observed)
        self.assertEqual("NOT_ATTEMPTED", self.guard._restoration)
        self.assertEqual({}, workflow._TRANSPORT_OWNERS)


if __name__ == "__main__":
    unittest.main()
