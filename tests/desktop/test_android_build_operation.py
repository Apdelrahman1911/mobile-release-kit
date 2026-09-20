"""Inert original-operation contracts, not native ownership qualification.

No descriptor, project lock, process, tool, signal handler or host directory is
acquired. Predicate owners are original Python types with explicit DATA state;
all filesystem/command boundaries are replaced before selected methods run.
"""
from __future__ import annotations

import json
import stat
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from mobile_release import android_build_operation as subject, build_inputs
from mobile_release._desktop_android_build_control import AndroidBuildInput
from mobile_release._desktop_android_build_protocol import ProtocolError, TOOLCHAIN_PROFILE, parse_request
from mobile_release._desktop_preflight_control import PreflightInput
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError


def directory(inode):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_uid=123, st_gid=123,
                                 st_mode=stat.S_IFDIR | 0o700)


@contextmanager
def original():
    binding = {"device": "1", "inode": "50", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}
    request = parse_request(json.dumps({
        "protocol": "mrk-android-build/1", "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "inert", "draftRevision": 1, "baselineGeneration": 1,
                    "savedConfig": {"bytes": 1, "sha256": "c" * 64}, "platform": "android",
                    "operation": "android-build-inspect", "savedVersion": {
                        "source": "gradle.properties", "bytes": 1, "sha256": "d" * 64,
                        "name": "1.2.3", "build": 7}},
        "native": {"profile": "linux-gnu-x86_64", "projectRoot": "/inert/project", "cwd": "/inert/runtime",
                   "rootIdentity": binding, "toolchain": {"schemaVersion": 1, "profile": TOOLCHAIN_PROFILE,
                        "root": "/inert/tools", "rootIdentity": {**binding, "inode": "51"},
                        "inventorySha256": "e" * 64}},
    }, separators=(",", ":")).encode("ascii") + b"\n")
    guard, source = DefaultCancellation(ProcessCleanupError, "inert"), AndroidBuildInput(100)
    source.acquired = source.active = source.request_returned = True
    guard._install_android_build_source(source)
    guard.depth = 0  # Predicate state only; no handlers were installed.
    with patch.object(subject.time, "monotonic", return_value=100), patch.object(source, "poll"):
        operation = subject.AndroidBuildOperation(request, guard, source)
        yield operation


def project_data(operation):
    invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
    project = object.__new__(build_inputs._Project)
    project.root, project.guard, project.claimed = operation.root, operation.guard, False
    project.directory = types.SimpleNamespace(fd=50, check=Mock(), slots=[])
    project.meta = types.SimpleNamespace(number=None, close_state="CLOSED")
    invocation.project_owner = invocation._original_project = project
    invocation.project_started = invocation.active = invocation.reserved = True
    return invocation, project


def namespace_data(operation):
    namespace = build_inputs._StoreNamespace(
        operation.root, operation.guard, include_store=False,
        _descendants=("desktop-android-build", operation.operation_id),
        _exclusive_index=2, _android_operation=operation,
    )
    operation.files.namespace = namespace
    namespace.parent_acquired = True
    for number, slot in enumerate(namespace.slots, 10):
        slot.number, slot.open_state = number, "OPEN"
        namespace.identities[number - 10] = build_inputs._directory(directory(number))
    return namespace


class AndroidOperationTests(unittest.TestCase):
    def test_invocation_binding_precedes_failed_acquire_and_is_not_replaced(self):
        with original() as operation:
            failure, seen = build_inputs.BuildInputError("inert admission"), []

            def acquire(invocation):
                self.assertIs(operation.invocation, invocation)
                seen.append(invocation)
                raise failure

            operation.invocation_attempted = True
            # This case tests invocation binding and failed acquisition, not
            # native handler installation. Model the already-admitted original
            # cancellation borrow; never install real signal handlers here.
            with patch.object(build_inputs, "cancellation_owner", return_value=(operation.guard, False)) as borrow, \
                    patch.object(build_inputs.InvocationCustody, "acquire", acquire):
                with self.assertRaises(build_inputs.BuildInputError) as raised:
                    with build_inputs.invocation_custody(operation.root, mode="build", cancellation=operation.guard):
                        self.fail("failed admission cannot yield")
            borrow.assert_called_once_with(operation.guard, ProcessCleanupError,
                                           "build-input cancellation ownership did not settle")
            self.assertIs(raised.exception, failure)
            self.assertEqual(seen, [operation.invocation])
            self.assertTrue(operation.invocation.claimed)
            self.assertTrue(operation.invocation._android_build_closed(operation))
            with self.assertRaises(ProtocolError):
                build_inputs.InvocationCustody(operation.root, "build", operation.guard)

    def test_wrong_root_mode_guard_and_offline_source_cannot_bind(self):
        for root, mode in ((Path("/different"), "build"), (Path("/inert/project"), "online")):
            with self.subTest(root=root, mode=mode), original() as operation:
                with patch.object(build_inputs.InvocationCustody, "acquire") as acquire:
                    with self.assertRaises(ProtocolError):
                        build_inputs.InvocationCustody(root, mode, operation.guard)
                    acquire.assert_not_called()
                self.assertIsNone(operation.invocation)
        with original() as operation:
            other = DefaultCancellation(ProcessCleanupError, "inert other")
            foreign = build_inputs.InvocationCustody(operation.root, "build", other)
            with self.assertRaises(ProtocolError):
                operation.bind_invocation(foreign)
            offline = PreflightInput(100)
            with self.assertRaises(ProtocolError):
                subject.AndroidBuildOperation(operation.request, operation.guard, offline)

    def test_cancelled_namespace_cleanup_checks_originals_without_work_gate(self):
        for stop in ("cancelled", "timed-out"):
            with self.subTest(stop=stop), original() as operation:
                invocation, project = project_data(operation)
                namespace = namespace_data(operation)
                operation.source.stop(stop)
                operation.close_claimed = True
                named = dict(zip(namespace.components, (10, 11, 12)))
                with patch.object(build_inputs, "_ENV_OWNER", invocation), \
                        patch.object(build_inputs, "_ENV_TAINTED", False), \
                        patch.object(build_inputs.os, "fstat", side_effect=directory), \
                        patch.object(build_inputs.os, "stat", side_effect=lambda name, **_: directory(named[name])), \
                        patch.object(build_inputs, "_exact_reserved_names", side_effect=lambda fd, names, **_: names), \
                        patch.object(build_inputs.os, "close") as close, \
                        patch.object(operation.guard, "check", side_effect=AssertionError("work gate re-entry")):
                    namespace.cleanup()
                    namespace.cleanup()
                self.assertEqual([call.args[0] for call in close.call_args_list], [12, 11, 10])
                self.assertTrue(namespace.closed())
                self.assertFalse(operation.guard.lifetime_ledger.fatal)
                self.assertEqual(operation.source.first_failure, 100)
                project.directory.check.assert_called_once_with()
                self.assertFalse(namespace.parent.slots)  # No replacement path root acquired.

    def test_cleanup_refuses_replaced_project_but_attempts_all_original_closes(self):
        with original() as operation:
            invocation, _ = project_data(operation)
            namespace = namespace_data(operation)
            invocation.project_owner = object()
            operation.close_claimed = True
            with patch.object(build_inputs, "_ENV_OWNER", invocation), \
                    patch.object(build_inputs, "_ENV_TAINTED", False), \
                    patch.object(build_inputs.os, "close") as close, \
                    patch.object(build_inputs.os, "open", side_effect=AssertionError("new root")):
                with self.assertRaises(ProcessCleanupError):
                    namespace.cleanup()
                namespace.cleanup()
            self.assertEqual([call.args[0] for call in close.call_args_list], [12, 11, 10])
            self.assertFalse(namespace.closed())
            self.assertTrue(operation.guard.lifetime_ledger.fatal)

    def test_names_route_is_original_bounded_and_nonrecursive(self):
        with original() as operation:
            def names(fd, limit):
                operation.charge("names", 1, 1)
                return {"inert"}

            with patch.object(operation.files, "names", side_effect=names) as routed, \
                    patch.object(operation, "checkpoint", side_effect=AssertionError("recursive admission")), \
                    patch.object(build_inputs.os, "listdir", side_effect=AssertionError("unbounded listing")):
                self.assertEqual(build_inputs._names(50, limit=9, cancellation=operation.guard), {"inert"})
                routed.assert_called_once_with(50, limit=9)
                with self.assertRaises(subject.AndroidBuildError) as raised:
                    build_inputs._names(50, limit=9, cancellation=operation.guard)
                self.assertEqual(raised.exception.reason, "input-limit")

    def test_ignore_policy_shares_text_budget_and_original_receipt_before_mkdir(self):
        with original() as operation:
            _, project = project_data(operation)
            raw = b"/.mobile-release/\n"
            operation.counters["tool-selection-bytes"] = 512 * 1024 - len(raw)
            with patch.object(operation, "checkpoint"), patch.object(operation.files, "read_input", return_value=raw) as read:
                self.assertEqual(operation._project_ignore_policy(), raw)
                self.assertEqual(operation._project_ignore_policy(), raw)
            self.assertEqual(operation.counters["tool-selection-bytes"], 512 * 1024)
            self.assertEqual(read.call_args_list[0].kwargs["limit"], len(raw))
            with patch.object(project, "check"), patch.object(operation, "checkpoint"), \
                    patch.object(operation.files, "read_input", return_value=None), \
                    patch.object(build_inputs, "_read_file", side_effect=AssertionError("legacy reader")), \
                    patch.object(build_inputs, "_mkdir_private") as mkdir:
                with self.assertRaises(build_inputs.BuildInputError):
                    project.ensure_meta()
                mkdir.assert_not_called()
        with original() as operation, patch.object(operation, "checkpoint"), \
                patch.object(operation.files, "read_input") as read:
            operation.counters["tool-selection-bytes"] = 512 * 1024
            with self.assertRaises(subject.AndroidBuildError):
                operation._project_ignore_policy()
            read.assert_not_called()

    def test_command_roles_capture_mode_and_actual_return_accounting(self):
        with original() as operation, patch.object(subject.AndroidBuildOperation, "checkpoint"):
            with self.assertRaises(ProtocolError):
                operation._arm("bundletool")
            operation._arm("gradle")
            with self.assertRaises(ProtocolError):
                operation.command_limits(2700, True, 100)
            self.assertEqual(operation.command_limits(9999, False, 8 * 1024 * 1024), (2700, 2 * 1024 * 1024))
            with self.assertRaises(ProtocolError):
                operation.command_limits(2700, False, 100)
            facts = types.SimpleNamespace(cleanup_complete=True, contained=True, fatal=False,
                                           command_dispatched=True, commands=1, profile_calls=0)
            with patch.object(operation.guard.lifetime_ledger, "verdict", return_value=facts):
                operation.returned("gradle", 17)
                operation.source.stop("cancelled")
                self.assertEqual(operation.command_outcome(), {"outcome": "exited", "exitCode": 17})
                with self.assertRaises(ProtocolError):
                    operation._arm("bundletool")
            with self.assertRaises(ProtocolError):
                operation._arm("gradle")
        with original() as operation:
            operation.command_error("gradle", OSError("private error must not be an exit code"))
            self.assertEqual(operation.command_outcome(), {"outcome": "not-dispatched", "exitCode": None})
            self.assertEqual(operation.source.first_failure, 100)

    def test_close_attempts_independent_owners_and_never_retries_failed_work(self):
        with original() as operation:
            first, second, events = subject.AndroidBuildError("work-retained"), OSError("inert tool close"), []

            def fail_work():
                events.append("work")
                raise first

            def fail_tools():
                events.append("tools")
                raise second

            operation.files.finish_work = Mock(side_effect=fail_work)
            operation.files.close = Mock(side_effect=lambda: events.append("files"))
            operation.files.closed = Mock(return_value=True)
            operation.tools = types.SimpleNamespace(close=Mock(side_effect=fail_tools), closed=Mock(return_value=False))
            with self.assertRaises(subject.AndroidBuildError) as raised:
                operation.close()
            self.assertIs(raised.exception, first)
            with self.assertRaises(ProtocolError):
                operation.close()
            self.assertEqual(events, ["work", "files", "tools"])
            self.assertEqual(operation.cleanup_errors, [first, second])
            self.assertEqual(operation.source.first_failure, 100)
            self.assertFalse(operation.closed())

    def test_closure_after_source_removal_requires_original_invocation_completion(self):
        with original() as operation:
            invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            operation.invocation_attempted = operation.close_claimed = operation.resources_closed = True
            operation.files.closed = Mock(return_value=True)
            invocation.claimed = invocation._cleanup_complete = True
            operation.source.closed = True  # Predicate DATA, no inherited FD.
            operation.guard._remove_android_build_source(operation.source)
            self.assertTrue(operation.closed())
            invocation._cleanup_complete = False
            self.assertFalse(operation.closed())
