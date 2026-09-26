"""Inert two-domain lifecycle contracts; NOT native/runtime qualification.

No test acquires a descriptor, installs/restores a signal handler, launches a
command, creates a thread/project, or performs cleanup on the host. Exact owner
types and their flags below are predicate DATA only, never real close receipts.
All IO/command seams are replaced before a selected method can reach them.
This source requires separate source/command review before any execution.
"""
from __future__ import annotations

import json
import stat
import sys
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from mobile_release import _desktop_saved_command_control as control
from mobile_release import _desktop_saved_command_engine as engine
from mobile_release import _desktop_android_build_protocol as android_wire
from mobile_release import _desktop_preflight_protocol as offline_wire
from mobile_release import owned_process
from mobile_release._desktop_android_build_control import AndroidBuildInput
from mobile_release._desktop_android_build_engine import _Engine as AndroidEngine
from mobile_release._desktop_edit_control import EditInput
from mobile_release._desktop_environment_control import EnvironmentInput
from mobile_release._desktop_preflight_budget import OfflinePreflightBudget, budget_for
from mobile_release._desktop_preflight_control import PreflightInput
from mobile_release._desktop_preflight_engine import _Engine as PreflightEngine
from mobile_release.cancellation import CleanupScope, DefaultCancellation


SOURCES = (PreflightInput, AndroidBuildInput)
ENGINES = (PreflightEngine, AndroidEngine)


def pipe(number=0):
    return types.SimpleNamespace(st_dev=1, st_ino=100 + number, st_mode=stat.S_IFIFO | 0o600)


def identity(number=0):
    value = pipe(number)
    return value.st_dev, value.st_ino, value.st_mode


def bound_source(kind):
    guard = DefaultCancellation(ValueError, "inert original guard")
    source = kind(100)
    source.acquired = source.active = source.request_returned = True
    source.fd, source.identity = 0, identity()
    guard._install_saved_command_source(source)
    return guard, source


def request_data(android=False):
    root = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}
    context = {"projectId": "inert-project", "draftRevision": 2, "baselineGeneration": 3,
               "savedConfig": {"bytes": 1, "sha256": "c" * 64}, "platform": "android",
               "operation": "android-build-inspect" if android else "offline-preflight"}
    native = {"profile": "linux-gnu-x86_64", "projectRoot": "/inert/project", "cwd": "/inert/runtime",
              "rootIdentity": root}
    if android:
        context["artifactValidation"] = {"mode": "structure-and-version", "uploadCertificateSha256": None}
        context["savedVersion"] = {"source": "release/version.properties", "bytes": 1,
                                   "sha256": "d" * 64, "name": "1.2.3", "build": 7}
        native["toolchain"] = {"schemaVersion": 1, "profile": android_wire.TOOLCHAIN_PROFILE,
                               "root": "/inert/toolchain", "rootIdentity": {**root, "inode": "3"},
                               "inventorySha256": "e" * 64}
    return {"protocol": android_wire.PROTOCOL if android else offline_wire.PROTOCOL,
            "operationId": "a" * 32, "ownerGeneration": "b" * 32, "context": context, "native": native}


def request_bytes(android=False):
    return json.dumps(request_data(android), separators=(",", ":")).encode("ascii") + b"\n"


def inert_operation(source):
    # Construction is deliberately bypassed: only the exact-type/source/guard
    # predicate is exercised. No admission, invocation, tool or file is owned.
    from mobile_release.android_build_operation import AndroidBuildOperation
    operation = object.__new__(AndroidBuildOperation)
    operation.source, operation.guard = source, source.guard
    operation._pending = "bundletool"
    source.bind_operation(operation)
    return operation


class SavedCommandBindingTests(unittest.TestCase):
    def test_finite_domains_share_methods_but_not_offline_type_or_budget(self):
        self.assertEqual(set(control.SavedCommandDomain), {
            control.SavedCommandDomain.OfflinePreflight, control.SavedCommandDomain.AndroidBuild})
        self.assertIs(PreflightInput.poll, AndroidBuildInput.poll)
        self.assertIs(PreflightInput.close, AndroidBuildInput.close)
        self.assertIs(PreflightEngine.run, AndroidEngine.run)
        self.assertIs(PreflightEngine.cleanup, AndroidEngine.cleanup)
        self.assertIs(PreflightEngine.close_output, AndroidEngine.close_output)
        with self.assertRaises(ValueError):
            control._protocol("offline-preflight")
        offline_guard, offline = bound_source(PreflightInput)
        android_guard, android = bound_source(AndroidBuildInput)
        self.assertEqual((offline.work_end, android.work_end), (1900, 3100))
        self.assertIs(offline_guard._preflight_source, offline)
        self.assertIsNone(offline_guard._android_build_source)
        self.assertIs(android_guard._android_build_source, android)
        self.assertIsNone(android_guard._preflight_source)
        self.assertNotIsInstance(android, PreflightInput)
        self.assertIsNone(budget_for(android_guard))
        with self.assertRaises(ValueError):
            OfflinePreflightBudget(Path("/inert/project"), android_guard, android)
        with self.assertRaises(AttributeError):
            android_guard._preflight_source = android

    def test_exact_sources_and_domain_cannot_be_substituted(self):
        class Derived(PreflightInput):
            pass

        for source in (Derived(100), control._SavedCommandInput(100, domain=control.SavedCommandDomain.OfflinePreflight),
                       types.SimpleNamespace(domain=control.SavedCommandDomain.OfflinePreflight)):
            with self.subTest(source=type(source)), self.assertRaises(ValueError):
                DefaultCancellation(ValueError, "inert")._install_saved_command_source(source)
        for kind in SOURCES:
            guard, source = bound_source(kind)
            source._domain = (control.SavedCommandDomain.AndroidBuild if kind is PreflightInput
                              else control.SavedCommandDomain.OfflinePreflight)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                guard._saved_command_input()

    def test_all_desktop_sources_are_mutually_exclusive_even_after_removal(self):
        kinds = ((EditInput, "edit"), (EnvironmentInput, "environment"),
                 (PreflightInput, "preflight"), (AndroidBuildInput, "android_build"))
        for first_kind, first_name in kinds:
            for second_kind, second_name in kinds:
                for removed in (False, True):
                    with self.subTest(first=first_name, second=second_name, removed=removed):
                        guard = DefaultCancellation(ValueError, "inert")
                        first, second = first_kind(100), second_kind(100)
                        first.acquired = second.acquired = True
                        getattr(guard, f"_install_{first_name}_source")(first)
                        if removed:
                            first.closed = True  # Predicate DATA, not an actual close.
                            getattr(guard, f"_remove_{first_name}_source")(first)
                        with self.assertRaises(ValueError):
                            getattr(guard, f"_install_{second_name}_source")(second)
                        self.assertIsNone(second.guard)

    def test_wrong_offline_or_android_install_hook_never_binds(self):
        for kind, wrong in ((AndroidBuildInput, "preflight"), (PreflightInput, "android_build")):
            guard, source = DefaultCancellation(ValueError, "inert"), kind(100)
            source.acquired = True
            with self.assertRaises(ValueError):
                getattr(guard, f"_install_{wrong}_source")(source)
            self.assertIsNone(source.guard)
            self.assertIsNone(guard._saved_command_source)

    def test_android_operation_is_once_bound_and_exact(self):
        guard, source = bound_source(AndroidBuildInput)
        operation = inert_operation(source)
        self.assertIs(source.require_operation(), operation)
        self.assertIsNone(guard._preflight_source)
        with self.assertRaises(android_wire.ProtocolError):
            source.bind_operation(operation)
        operation.source = object()
        with self.assertRaises(android_wire.ProtocolError):
            source.require_operation()


class SavedCommandInputTests(unittest.TestCase):
    def test_original_request_type_and_one_request_only(self):
        for kind, wire in ((PreflightInput, offline_wire), (AndroidBuildInput, android_wire)):
            guard, source = bound_source(kind)
            source.active = source.request_returned = False
            source.buffer.extend(request_bytes(kind is AndroidBuildInput))
            with self.subTest(kind=kind), patch.object(source, "poll", return_value=None):
                request = source.request()
                expected = android_wire.AndroidBuildRequest if kind is AndroidBuildInput else offline_wire.PreflightRequest
                self.assertIs(type(request), expected)
                with self.assertRaises(wire.ProtocolError):
                    source.request()
                self.assertTrue(source.active and source.request_returned)
                self.assertIs(source.guard, guard)

    def test_held_eof_extra_bytes_and_read_failure_remain_distinct(self):
        for kind in SOURCES:
            for raw, fatal in ((b"", False), (b"unexpected", False), (OSError("inert read"), True)):
                guard, source = bound_source(kind)
                with self.subTest(kind=kind, raw=raw), patch.object(control.time, "monotonic", return_value=110), \
                        patch.object(control.os, "fstat", return_value=pipe()), \
                        patch.object(control.os, "read", side_effect=[raw]) as read:
                    source.poll(guard)
                self.assertEqual(source.stop_reason, "cancelled")
                self.assertTrue(guard.cancelled)
                self.assertEqual(guard.lifetime_ledger.fatal, fatal)
                self.assertEqual(source.first_failure, 110)
                read.assert_called_once_with(0, 1)

    def test_prefetched_leftover_stops_before_request_return_or_new_read(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            source.buffer.extend(b"extra")
            with self.subTest(kind=kind), patch.object(control.time, "monotonic", return_value=110), \
                    patch.object(control.os, "read", side_effect=AssertionError("unowned new read")) as read:
                source.poll(guard)
            read.assert_not_called()
            self.assertTrue(guard.cancelled)
        for kind in SOURCES:
            guard, source = bound_source(kind)
            source.active = source.request_returned = False
            source.buffer.extend(request_bytes(kind is AndroidBuildInput) + b"extra")
            with self.subTest(kind=kind), patch.object(control.time, "monotonic", return_value=110), \
                    patch.object(control.os, "fstat", return_value=pipe()), \
                    patch.object(control.os, "read", side_effect=BlockingIOError):
                with self.assertRaises(KeyboardInterrupt):
                    source.request()
            self.assertFalse(source.request_returned)

    def test_domain_request_limit_is_charged_before_larger_read(self):
        for kind, maximum in ((PreflightInput, 16 * 1024), (AndroidBuildInput, 32 * 1024)):
            guard, source = bound_source(kind)
            source.active = source.request_returned = False
            with self.subTest(kind=kind), patch.object(control.time, "monotonic", return_value=110), \
                    patch.object(control.os, "fstat", return_value=pipe()), \
                    patch.object(control.os, "read", return_value=b"x" * (maximum + 1)) as read:
                source.poll(guard)
            read.assert_called_once_with(0, maximum + 1)
            self.assertEqual(len(source.buffer), maximum + 1)
            self.assertTrue(guard.cancelled)

    def test_identity_change_is_fatal_not_eof_and_never_closes_replacement(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            with self.subTest(kind=kind), patch.object(control.time, "monotonic", return_value=110), \
                    patch.object(control.os, "fstat", return_value=pipe(99)), \
                    patch.object(control.os, "read") as read, patch.object(control.os, "close") as close:
                source.poll(guard)
                with self.assertRaises(ValueError):
                    source.close()
            self.assertTrue(source.custody_unknown and guard.lifetime_ledger.fatal)
            self.assertFalse(source.closed)
            read.assert_not_called()
            close.assert_not_called()

    def test_original_close_is_consumed_once_and_never_retried_after_return_loss(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            with self.subTest(kind=kind), patch.object(control.os, "fstat", return_value=pipe()), \
                    patch.object(control.os, "close", side_effect=OSError("inert close return loss")) as close:
                with self.assertRaises(OSError):
                    source.close()
                with self.assertRaises(ValueError):
                    source.close()
            close.assert_called_once_with(0)
            self.assertIsNone(source.fd)
            self.assertTrue(source.close_claimed and not source.closed and guard.lifetime_ledger.fatal)
            self.assertIs(guard._saved_command_source, source)

    def test_known_input_close_removes_only_original_slot(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            with self.subTest(kind=kind), patch.object(control.os, "fstat", return_value=pipe()), \
                    patch.object(control.os, "close") as close:
                source.close()
                source.close()
            close.assert_called_once_with(0)
            self.assertTrue(source.closed)
            self.assertIsNone(guard._saved_command_source)
            self.assertIsNone(guard._preflight_source)
            self.assertIsNone(guard._android_build_source)


class SavedCommandFailureTests(unittest.TestCase):
    def test_constructor_handoff_closes_original_before_input_and_never_retries(self):
        # Exercise actual engine.run/cleanup/terminal refusal, replacing only
        # the service construction and host IO/signal seams. These descriptors
        # and close flags are inert predicate DATA, not native finality proof.
        for cleanup_fails in (False, True):
            original, events, operations = AndroidEngine(100), [], []
            primary = ValueError("inert constructor return loss")
            secondary = OSError("inert operation close return loss")
            original.input.buffer.extend(request_bytes(True))

            def construct(request, guard, source):
                operation = inert_operation(source)
                operations.append(operation)
                operation.closed = Mock(return_value=False)

                def close_operation():
                    events.append("operation")
                    self.assertIs(original.primary, primary)
                    self.assertIs(guard.lifetime_ledger._primary, primary)
                    self.assertEqual(source.first_failure, 123)
                    self.assertFalse(source.close_claimed)
                    if cleanup_fails:
                        raise secondary
                    operation.closed.return_value = True

                operation.close = Mock(side_effect=close_operation)
                raise primary

            service_module = types.ModuleType("mobile_release.desktop_android_build")
            service_module.AndroidBuildRun = construct
            with self.subTest(cleanup_fails=cleanup_fails), ExitStack() as patches:
                patches.enter_context(patch.dict(sys.modules, {service_module.__name__: service_module}))
                patches.enter_context(patch.object(control.time, "monotonic", return_value=123))
                patches.enter_context(patch.object(control.os, "fstat", side_effect=pipe))
                patches.enter_context(patch.object(control.os, "set_blocking"))
                patches.enter_context(patch.object(control.os, "close", side_effect=lambda fd: events.append(fd)))
                patches.enter_context(patch.object(original.input, "poll", return_value=None))
                patches.enter_context(patch.object(original.guard, "install", return_value=None))
                patches.enter_context(patch.object(original.guard, "activate", return_value=None))
                patches.enter_context(patch.object(original.guard, "restore", side_effect=lambda: events.append("restore")))
                write = patches.enter_context(patch.object(original, "write"))
                retained = patches.enter_context(patch.object(engine, "_RETAINED", []))
                self.assertEqual(engine.run_engine(original), 78)
                original.cleanup()  # A replay cannot retry the consuming close.
                self.assertEqual(retained, [original] if cleanup_fails else [])
                write.assert_not_called()  # No accepted or manufactured terminal.
            self.assertEqual(events, ["operation", 0, "restore", 2, 1])
            self.assertEqual(len(operations), 1)
            operations[0].close.assert_called_once_with()
            self.assertIs(original.input.operation, operations[0])
            self.assertIsNone(original.service)
            self.assertIs(original.primary, primary)
            self.assertIsNone(original.guard._saved_command_source)

    def test_returned_service_is_the_only_operation_cleanup_route(self):
        original = AndroidEngine(100)
        original.input.acquired = original.input.active = original.input.request_returned = True
        original.guard._install_android_build_source(original.input)
        operation = inert_operation(original.input)
        operation.close = Mock(side_effect=AssertionError("unexpected fallback cleanup"))
        original.service = types.SimpleNamespace(operation=operation, close=Mock())
        original.cleanup()  # No descriptors were acquired by this predicate test.
        original.service.close.assert_called_once_with()
        operation.close.assert_not_called()
        self.assertFalse(original._android_handoff_close_claimed)
        self.assertTrue(original.input.closed)

    def test_failure_before_source_installation_is_latched_before_engine_cleanup(self):
        for kind in ENGINES:
            original, observations = kind(100), []
            primary = ValueError("inert pre-install failure")

            def cleanup():
                observations.append((original.input.first_failure, original.primary))

            with self.subTest(kind=kind), ExitStack() as patches:
                patches.enter_context(patch.object(control.time, "monotonic", return_value=123))
                patches.enter_context(patch.object(original, "run", side_effect=primary))
                patches.enter_context(patch.object(original, "cleanup", side_effect=cleanup))
                patches.enter_context(patch.object(original.guard, "restore", return_value=None))
                patches.enter_context(patch.object(original, "terminal", side_effect=ValueError("inert no request")))
                patches.enter_context(patch.object(original, "close_output", return_value=None))
                patches.enter_context(patch.object(engine, "_RETAINED", []))
                self.assertEqual(engine.run_engine(original), 78)
            self.assertEqual(observations, [(123, primary)])
            self.assertIs(original.guard.lifetime_ledger._primary, primary)

    def test_first_failure_precedes_cleanup_and_later_stop_does_not_renew_it(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            primary, secondary, observations = KeyboardInterrupt(), OSError("inert cleanup"), []

            def cleanup():
                observations.append(source.first_failure)
                raise secondary

            scope = CleanupScope(guard, cleanup, owns_cancellation=False, first_primary=True)
            with self.subTest(kind=kind), patch.object(control.time, "monotonic", return_value=123):
                self.assertFalse(scope.__exit__(type(primary), primary, None))
            with patch.object(control.time, "monotonic", return_value=456):
                source.stop("cancelled")
                source.stop("timed-out")
                scope.__exit__(None, None, None)
            self.assertEqual(observations, [123])
            self.assertEqual(source.first_failure, 123)
            self.assertEqual(source.stop_reason, "cancelled")
            self.assertIs(guard.lifetime_ledger._primary, primary)
            self.assertTrue(guard.lifetime_ledger.fatal)

    def test_same_original_W_H_and_first_failure_cutoff_for_both_engines(self):
        for kind, work, hard in ((PreflightEngine, 1800, 1810), (AndroidEngine, 3000, 3010)):
            for first_failure, now in ((None, 100 + hard), (123, 133)):
                original = kind(100)
                original.frames = 1
                original.output.owned, original.output.identity = True, identity(1)
                original.input.first_failure = first_failure
                with self.subTest(kind=kind, failure=first_failure), patch.object(engine.time, "monotonic", return_value=now), \
                        patch.object(engine.os, "write") as write:
                    with self.assertRaises(ValueError):
                        original.write(b"terminal\n", terminal=True)
                    write.assert_not_called()
                self.assertTrue(original.terminal_claimed)
            original = kind(100)
            original.output.owned, original.output.identity = True, identity(1)
            with patch.object(engine.time, "monotonic", return_value=100 + work), patch.object(engine.os, "write") as write:
                with self.assertRaises(ValueError):
                    original.write(b"accepted\n")
                write.assert_not_called()

    def test_output_close_order_no_retry_and_sticky_unknown_retention(self):
        for kind in ENGINES:
            original = kind(100)
            original.input.closed = True  # Predicate DATA, not host closure.
            failures_at_remaining_close = []
            for slot in (original.output, original.error_output):
                slot.owned, slot.identity = True, identity(slot.number)

            def close(number):
                if number == 2:
                    raise OSError("inert original close return loss")
                failures_at_remaining_close.append(original.input.first_failure)

            with self.subTest(kind=kind), patch.object(engine.os, "fstat", side_effect=pipe), \
                    patch.object(engine.time, "monotonic", return_value=123), \
                    patch.object(engine.os, "close", side_effect=close) as closed, \
                    patch.object(engine, "_RETAINED", []) as retained:
                with self.assertRaises(OSError):
                    original.close_output()
                original.close_output()
                original.retain_unknown()
                original.retain_unknown()
                self.assertEqual([call.args[0] for call in closed.call_args_list], [2, 1])
                self.assertEqual(failures_at_remaining_close, [123])
                self.assertEqual(retained, [original])
            self.assertTrue(original.output.closed)
            self.assertFalse(original.error_output.closed)
            self.assertTrue(original.guard.lifetime_ledger.fatal)

    def test_wire_limits_and_terminal_claim_are_not_extended(self):
        for kind, maximum in ((PreflightEngine, 2), (AndroidEngine, 8)):
            original = kind(100)
            original.frames = maximum
            with self.subTest(kind=kind), patch.object(engine.os, "write") as write:
                with self.assertRaises(ValueError):
                    original.write(b"terminal\n", terminal=True)
                original.frames = 1
                original.output_bytes = 64 * 1024
                with self.assertRaises(ValueError):
                    original.write(b"x", terminal=True)
                original.output_bytes = 0
                original.terminal_claimed = True
                with self.assertRaises(ValueError):
                    original.write(b"x", terminal=True)
                write.assert_not_called()


class SavedCommandDispatchTests(unittest.TestCase):
    def test_missing_original_budget_or_operation_refuses_before_dispatch(self):
        for kind in SOURCES:
            guard, source = bound_source(kind)
            command = Mock(side_effect=AssertionError("unexpected command"))
            with self.subTest(kind=kind), patch.object(source, "poll", return_value=None), \
                    patch.object(control.time, "monotonic", return_value=110), \
                    patch.dict(sys.modules, {"mobile_release._command_process": types.SimpleNamespace(run_command=command)}):
                with self.assertRaises(ValueError):
                    owned_process.run_owned(["inert"], cancellation=guard)
                command.assert_not_called()

    def test_offline_command_preserves_budget_capture_and_original_command_arguments(self):
        guard, source = bound_source(PreflightInput)
        budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
        result, callback = object(), Mock()
        command = Mock(return_value=result)
        module = types.SimpleNamespace(run_command=command)
        with patch.dict(sys.modules, {"mobile_release._command_process": module}), \
                patch.object(source, "poll", return_value=None), patch.object(budget, "checkpoint"), \
                patch.object(control.time, "monotonic", return_value=1800):
            actual = owned_process.run_owned(["inert"], environ={"FIXED": "value"}, cwd=Path("/inert/project"),
                                            timeout=200, output_limit=2 * 1024 * 1024, cancellation=guard,
                                            capture=True, text=False, on_start=callback)
        self.assertIs(actual, result)
        self.assertEqual(command.call_args.kwargs["timeout"], 100)
        self.assertEqual(command.call_args.kwargs["output_limit"], 1024 * 1024)
        self.assertIs(command.call_args.kwargs["on_start"], callback)
        self.assertFalse(command.call_args.kwargs["text"])
        self.assertEqual(command.call_args.kwargs["environ"], {"FIXED": "value"})
        self.assertEqual(budget.counters["capture"], 1024 * 1024)
        self.assertIsNone(source.first_failure)
        callback.assert_not_called()

    def test_android_limits_use_only_original_operation_and_never_offline_budget(self):
        guard, source = bound_source(AndroidBuildInput)
        operation = inert_operation(source)
        command = Mock(return_value=object())
        with patch.dict(sys.modules, {"mobile_release._command_process": types.SimpleNamespace(run_command=command)}), \
                patch.object(source, "poll", return_value=None), patch.object(operation, "checkpoint"), \
                patch.object(operation, "command_limits", return_value=(60, 2 * 1024 * 1024)) as limits, \
                patch.object(control.time, "monotonic", return_value=3000):
            owned_process.run_owned(["inert"], timeout=2700, output_limit=4 * 1024 * 1024, cancellation=guard)
        limits.assert_called_once_with(100, True, 4 * 1024 * 1024)
        self.assertEqual(command.call_args.kwargs["timeout"], 60)
        self.assertEqual(command.call_args.kwargs["output_limit"], 2 * 1024 * 1024)
        self.assertIsNone(budget_for(guard))

    def test_android_operation_cannot_increase_fixed_domain_limits(self):
        for selected in ((61, 1), (60, 2 * 1024 * 1024 + 1), (True, 1), (60, 0)):
            guard, source = bound_source(AndroidBuildInput)
            operation = inert_operation(source)
            command = Mock(side_effect=AssertionError("unexpected command"))
            with self.subTest(selected=selected), patch.object(source, "poll", return_value=None), \
                    patch.object(operation, "checkpoint"), patch.object(operation, "command_limits", return_value=selected), \
                    patch.object(control.time, "monotonic", return_value=110), \
                    patch.dict(sys.modules, {"mobile_release._command_process": types.SimpleNamespace(run_command=command)}):
                with self.assertRaises(android_wire.ProtocolError):
                    owned_process.run_owned(["inert"], timeout=2700, output_limit=4 * 1024 * 1024, cancellation=guard)
                command.assert_not_called()

    def test_android_signature_caps_remain_role_specific_and_tighten_to_original_endpoint(self):
        for role, ceiling in (("gradle", 2700), ("bundletool", 60), ("jarsigner", 120), ("keytool", 30)):
            for remaining in (7, 2000):
                guard, source = bound_source(AndroidBuildInput)
                operation = inert_operation(source)
                operation._pending = role
                expected = min(ceiling, remaining)
                with self.subTest(role=role, remaining=remaining), patch.object(source, "poll"), \
                        patch.object(operation, "checkpoint"), patch.object(operation, "command_limits", return_value=(expected, 1)), \
                        patch.object(control.time, "monotonic", return_value=source.work_end - remaining):
                    self.assertEqual(source.command_limits(2700, role != "gradle", 1), (expected, 1))
        # A jarsigner allowance cannot be borrowed by bundletool or keytool.
        for role in ("bundletool", "keytool"):
            guard, source = bound_source(AndroidBuildInput)
            operation = inert_operation(source)
            operation._pending = role
            with self.subTest(role=role), patch.object(source, "poll"), patch.object(operation, "checkpoint"), \
                    patch.object(operation, "command_limits", return_value=(120, 1)), \
                    patch.object(control.time, "monotonic", return_value=110), self.assertRaises(android_wire.ProtocolError):
                source.command_limits(120, True, 1)

    def test_no_saved_command_source_leaves_cli_edit_environment_arguments_unchanged(self):
        for kind in (None, EditInput, EnvironmentInput):
            guard = None if kind is None else DefaultCancellation(ValueError, "inert")
            if kind is not None:
                source = kind(100)
                source.acquired = True
                getattr(guard, "_install_edit_source" if kind is EditInput else "_install_environment_source")(source)
            command = Mock(return_value=object())
            with self.subTest(kind=kind), patch.dict(sys.modules, {
                    "mobile_release._command_process": types.SimpleNamespace(run_command=command)}):
                owned_process.run_owned(["inert"], timeout=8765, output_limit=3 * 1024 * 1024,
                                        cancellation=guard, cleanup=True, capture=False)
            self.assertEqual(command.call_args.kwargs["timeout"], 8765)
            self.assertEqual(command.call_args.kwargs["output_limit"], 3 * 1024 * 1024)
            self.assertTrue(command.call_args.kwargs["cleanup"])

    def test_saved_source_refuses_cleanup_route_before_command_dispatch(self):
        for kind in SOURCES:
            guard, _ = bound_source(kind)
            command = Mock(side_effect=AssertionError("unexpected command"))
            with self.subTest(kind=kind), patch.dict(sys.modules, {
                    "mobile_release._command_process": types.SimpleNamespace(run_command=command)}):
                with self.assertRaises(ValueError):
                    owned_process.run_owned(["inert"], cancellation=guard, cleanup=True)
                command.assert_not_called()

    def test_android_progress_is_bound_to_original_engine_service_and_encoder(self):
        from mobile_release.desktop_android_build import AndroidBuildRun
        original = AndroidEngine(100)
        source, guard = original.input, original.guard
        source.acquired = source.active = source.request_returned = True
        guard._install_android_build_source(source)
        operation = inert_operation(source)
        original.request = android_wire.parse_request(request_bytes(True))
        original._android_frames = android_wire.AndroidBuildFrames(original.request)
        service = object.__new__(AndroidBuildRun)
        service.request, service.source, service.guard, service.operation = original.request, source, guard, operation
        original.service = service
        original.output.owned, original.output.identity = True, identity(1)
        with ExitStack() as patches:
            patches.enter_context(patch.object(source, "poll", return_value=None))
            patches.enter_context(patch.object(engine.time, "monotonic", return_value=110))
            patches.enter_context(patch.object(engine.os, "fstat", return_value=pipe(1)))
            writes = patches.enter_context(patch.object(engine.os, "write", side_effect=lambda _fd, data: len(data)))
            original.write(original._response("accepted", {"schemaVersion": 1, "context": original.request.context}))
            source.progress("inputs-bound")
            source.progress("building")
            with self.assertRaises(android_wire.ProtocolError):
                source.progress("inputs-bound")
            before = writes.call_count
            with self.assertRaises(android_wire.ProtocolError):
                source.progress("capturing")  # Rejected encoder is sticky.
            self.assertEqual(writes.call_count, before)
            service.source = object()
            with self.assertRaises(android_wire.ProtocolError):
                source.progress("inspecting")
        self.assertEqual(original.frames, 3)


if __name__ == "__main__":
    unittest.main()
