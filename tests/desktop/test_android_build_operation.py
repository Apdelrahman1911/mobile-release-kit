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
from mobile_release.owned_process import ProcessCleanupError, ProcessError


def directory(inode):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_uid=123, st_gid=123,
                                 st_mode=stat.S_IFDIR | 0o700)


@contextmanager
def original(*, signature=False, signed=False):
    signature = signature or signed
    binding = {"device": "1", "inode": "50", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}
    data = {
        "protocol": "mrk-android-build/3", "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "inert", "draftRevision": 1, "baselineGeneration": 1,
                    "savedConfig": {"bytes": 1, "sha256": "c" * 64}, "platform": "android",
                    "operation": "android-build-inspect", "savedVersion": {
                        "source": "gradle.properties", "bytes": 1, "sha256": "d" * 64,
                        "name": "1.2.3", "build": 7},
                    "signing": None,
                    "artifactValidation": {"mode": "upload-signature" if signature else "structure-and-version",
                                           "uploadCertificateSha256": "a" * 64 if signature else None}},
        "native": {"profile": "linux-gnu-x86_64", "projectRoot": "/inert/project", "cwd": "/inert/runtime",
                   "rootIdentity": binding, "toolchain": {"schemaVersion": 1, "profile": TOOLCHAIN_PROFILE,
                        "root": "/inert/tools", "rootIdentity": {**binding, "inode": "51"},
                        "inventorySha256": "e" * 64}},
    }
    if signed:
        data["context"]["signing"] = {"source": "assigned-session", "contextRevision": 1, "assignments": [
            {"kind": "android-keystore", "recordId": "f" * 32, "recordRevision": 1, "contextRevision": 1}]}
        data["native"]["signingContext"] = {"bytes": 1, "sha256": "e" * 64}
    request = parse_request(json.dumps(data, separators=(",", ":")).encode("ascii") + b"\n")
    guard, source = DefaultCancellation(ProcessCleanupError, "inert"), AndroidBuildInput(100)
    source.acquired = source.active = source.request_returned = True
    guard._install_android_build_source(source)
    source._request_material(request)
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

    def test_upload_tool_preflight_precedes_project_reads_namespace_and_gradle(self):
        for signature, missing in ((False, False), (True, False), (True, True)):
            with self.subTest(signature=signature, missing=missing), original(signature=signature) as operation:
                operation.inputs = types.SimpleNamespace(check_signer=signature)
                events, tool_inputs = [], {"inert": b"DATA"}

                def preflight():
                    events.append("signature-preflight")
                    if missing:
                        raise subject.AndroidBuildError("toolchain-mismatch")

                tools = types.SimpleNamespace(acquire=Mock(side_effect=lambda: events.append("acquire")),
                    require_signature_tools=Mock(side_effect=preflight),
                    check_project_inputs=Mock(side_effect=lambda data: events.append("project-selection")),
                    check=Mock(side_effect=lambda: events.append("tools-check")))

                def read_project():
                    events.append("project-reads")
                    return tool_inputs

                with patch("mobile_release.android_build_tools.AndroidValidationTools", return_value=tools) as constructed, \
                     patch.object(operation, "checkpoint"), patch.object(operation, "check_inputs"), \
                     patch.object(operation, "_project_tool_inputs", side_effect=read_project) as project_reads, \
                     patch.object(operation.files, "prepare_namespace", side_effect=lambda: events.append("namespace")) as namespace, \
                     patch("mobile_release.android.run_owned") as dispatched:
                    if missing:
                        with self.assertRaises(subject.AndroidBuildError):
                            operation.prepare()
                        self.assertEqual(events, ["acquire", "signature-preflight"])
                        self.assertFalse(operation.prepared)
                        project_reads.assert_not_called(); namespace.assert_not_called()
                    else:
                        operation.prepare()
                        self.assertTrue(operation.prepared)
                        self.assertEqual(events, ["acquire", *(["signature-preflight"] if signature else []),
                                                  "project-reads", "project-selection", "namespace", "tools-check"])
                        tools.check_project_inputs.assert_called_once_with(tool_inputs)
                    constructed.assert_called_once_with(operation, operation.request.native["toolchain"])
                    dispatched.assert_not_called()
                self.assertIs(operation.tools, tools)
                self.assertEqual(tools.require_signature_tools.call_count, int(signature))

    def test_signature_roles_are_one_ordered_attempt_each_with_exact_capture_limits(self):
        with original(signature=True) as operation, patch.object(subject.AndroidBuildOperation, "checkpoint"):
            operation.inputs = types.SimpleNamespace(check_signer=True)
            operation._artifact = object()  # Predicate DATA; no artifact read occurs here.
            facts = types.SimpleNamespace(cleanup_complete=True, contained=True, fatal=False,
                                           command_dispatched=False, commands=0, profile_calls=0)
            with patch.object(operation.guard.lifetime_ledger, "verdict", return_value=facts):
                for role, cap in (("gradle", 2700), ("bundletool", 60), ("jarsigner", 120), ("keytool", 30)):
                    for later in tuple(operation._roles)[facts.commands + 1:]:
                        with self.assertRaises(ProtocolError):
                            operation._arm(later)
                    if role == "keytool":
                        with self.assertRaises(ProtocolError):
                            operation._arm(role)  # Actual return alone is not common signature-policy acceptance.
                        operation._signature_passed = True
                    operation._arm(role)
                    self.assertEqual(operation.command_limits(9999, role != "gradle", 9 * 1024 * 1024),
                                     (cap, 2 * 1024 * 1024))
                    with self.assertRaises(ProtocolError):
                        operation.command_limits(cap, role != "gradle", 1)
                    facts.commands += 1
                    facts.command_dispatched = True
                    operation.returned(role, 4 if role == "jarsigner" else 0)
                    with self.assertRaises(ProtocolError):
                        operation._arm(role)
                self.assertEqual(facts.commands, 4)
                self.assertEqual(operation.command_outcome(), {"outcome": "exited", "exitCode": 0})
        with original() as operation, patch.object(subject.AndroidBuildOperation, "checkpoint"):
            for role in ("jarsigner", "keytool", "ambient-java"):
                with self.assertRaises(ProtocolError):
                    operation._arm(role)

    def test_unknown_or_lost_signature_return_cannot_arm_keytool(self):
        for fatal in (False, True):
            with self.subTest(fatal=fatal), original(signature=True) as operation, \
                    patch.object(subject.AndroidBuildOperation, "checkpoint"):
                operation.inputs = types.SimpleNamespace(check_signer=True)
                operation._artifact = object()
                operation._roles.update(gradle="returned", bundletool="returned", jarsigner="attempted")
                operation._returned.update(gradle=0, bundletool=0)
                operation._pending = "jarsigner"
                operation.guard.lifetime_ledger._commands = 3
                operation.guard.lifetime_ledger._command_dispatched = True
                operation.command_error("jarsigner", ProcessCleanupError("inert") if fatal else OSError("inert lost return"))
                with self.assertRaises(ProtocolError):
                    operation._arm("keytool")
                self.assertNotIn("jarsigner", operation._returned)

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

    def test_signed_roles_are_six_once_only_and_preflight_does_not_become_gradle(self):
        with original(signed=True) as operation, patch.object(operation, "checkpoint"), \
                patch.object(operation.signing, "require_materialized"), \
                patch.object(operation.signing, "inputs_closed", return_value=True):
            operation.inputs = types.SimpleNamespace(check_signer=True)
            operation.files.signing_input = types.SimpleNamespace(_native=True)
            ledger = operation.guard.lifetime_ledger
            roles = (("keytool-validate", "validating-signing", 30), ("gradle", "building", 2700),
                     ("jarsigner-sign", "signing", 120), ("bundletool", "inspecting", 60),
                     ("jarsigner", "inspecting", 120), ("keytool", "inspecting", 30))
            for index, (role, stage, ceiling) in enumerate(roles):
                operation.stage = stage
                if role == "keytool":
                    operation._signature_passed = True  # DATA stands for separately tested shared policy.
                operation._arm(role)
                self.assertEqual(operation.command_limits(9000, role != "gradle", 9 * 1024 * 1024),
                                 (ceiling, 2 * 1024 * 1024))
                ledger._commands, ledger._command_dispatched = index + 1, True
                operation.returned(role, 0)
                if role == "keytool-validate":
                    self.assertEqual(operation.command_outcome(), {"outcome": "not-dispatched", "exitCode": None})
                    operation.stage = "building"
                    with self.assertRaises(ProtocolError):
                        operation._arm("gradle")  # keytool0 alone is not complete credential/Firebase policy.
                    operation.signing.validation_passed = True
                if role == "jarsigner-sign":
                    operation._artifact = object()  # Separate immutable-final construction is tested in files.
                with self.assertRaises(ProtocolError):
                    operation._arm(role)
            self.assertEqual(tuple(operation._roles), tuple(item[0] for item in roles))
            self.assertEqual(operation.command_outcome(), {"outcome": "exited", "exitCode": 0})

    def test_after_preflight_only_own_role_can_prove_no_dispatch_or_an_exit(self):
        for lost_return in (False, True):
            with self.subTest(lost_return=lost_return), original(signed=True) as operation, \
                    patch.object(operation, "checkpoint"), patch.object(operation.signing, "require_materialized"):
                operation.stage = "validating-signing"
                operation._arm("keytool-validate")
                operation.command_limits(30, True, 100)
                ledger = operation.guard.lifetime_ledger
                ledger._commands, ledger._command_dispatched = 1, True
                operation.returned("keytool-validate", 0)
                operation.signing.validation_passed = True
                operation.stage = "building"
                operation._arm("gradle")
                operation.command_limits(2700, False, 100)
                ledger._commands = 2
                error = OSError("PRIVATE missing return") if lost_return else ProcessError("PRIVATE no exec", dispatched=False)
                operation.command_error("gradle", error)
                self.assertEqual(operation.command_outcome(), {
                    "outcome": "unknown" if lost_return else "not-dispatched", "exitCode": None})
                self.assertTrue(ledger.verdict().command_dispatched)
                self.assertEqual(operation.role_outcome("keytool-validate"), {"outcome": "exited", "exitCode": 0})
                self.assertNotIn("gradle", operation._returned)

    def test_android_journal_is_rooted_before_failed_scratch_constructor_and_cleanup_is_once(self):
        with original(signed=True) as operation:
            invocation, project = project_data(operation)
            operation.stage = "materializing-signing"
            operation.signing.validation_passed = True
            failure = RuntimeError("inert scratch constructor return lost")
            with patch.object(build_inputs, "FiniteScratch", side_effect=failure), \
                    patch.object(build_inputs.uuid, "uuid4", return_value=types.SimpleNamespace(hex="f" * 32)):
                with self.assertRaises(RuntimeError) as raised:
                    build_inputs.BuildInputs(invocation, project)
            child = operation.signing.materialization
            self.assertIs(raised.exception, failure)
            self.assertIsNotNone(child)
            self.assertIsNone(child.scratch)
            operation.signing.close()
            operation.signing.close()
            self.assertTrue(child.claimed and child._cleanup_complete)
            self.assertTrue(operation.signing.inputs_closed())

    def test_signed_close_failure_does_not_skip_files_tools_or_advance_stage(self):
        with original(signed=True) as operation:
            events = []
            operation.stage = "building"
            failure = ProcessCleanupError("inert original input closure")

            def input_close():
                events.append("inputs")
                raise failure

            operation.signing.close = Mock(side_effect=input_close)
            operation.signing.inputs_closed = Mock(return_value=False)
            operation.files.finish_work = Mock(side_effect=lambda: events.append("work"))
            operation.files.close = Mock(side_effect=lambda: events.append("files"))
            operation.files.closed = Mock(return_value=True)
            operation.tools = types.SimpleNamespace(close=Mock(side_effect=lambda: events.append("tools")),
                                                     closed=Mock(return_value=True))
            with self.assertRaises(ProcessCleanupError) as raised:
                operation.close()
            self.assertIs(raised.exception, failure)
            self.assertEqual(events, ["inputs", "work", "files", "tools"])
            self.assertEqual(operation.stage, "building")
            self.assertFalse(operation.resources_closed)

    def test_signed_root_allows_only_its_child_and_does_not_loosen_unsigned_or_offline(self):
        for signed in (False, True):
            with self.subTest(signed=signed), original(signed=signed) as operation:
                invocation, project = project_data(operation)
                child = object.__new__(build_inputs.BuildInputs)
                invocation.child = child
                if signed:
                    operation.signing.materialization = child
                with patch.object(build_inputs, "_ENV_OWNER", invocation), \
                        patch.object(build_inputs, "_ENV_TAINTED", False), \
                        patch.object(project, "check"), patch.object(operation.guard, "check"), \
                        patch.object(build_inputs.os, "fstat", return_value=directory(50)) as inspected, \
                        patch.object(build_inputs.os, "open") as opened:
                    if signed:
                        number, identity = invocation._android_build_root(operation)
                        self.assertEqual(number, 50)
                        self.assertEqual(identity, operation.request.native["rootIdentity"])
                        inspected.assert_called_once_with(50)
                        invocation.child = object()
                    with self.assertRaises(build_inputs.BuildInputError):
                        invocation._android_build_root(operation)
                    with self.assertRaises(build_inputs.BuildInputError):
                        invocation._unsigned_build_root(operation.guard)
                    with self.assertRaises(build_inputs.BuildInputError):
                        invocation._offline_preflight_root(operation.guard)
                opened.assert_not_called()


def materialized_data(operation):
    """Finite owner/values DATA; no constructor acquisition or project mutation."""
    from mobile_release.credentials import _MaterializedBuildEnvironment
    invocation, project = project_data(operation)
    child = object.__new__(build_inputs.BuildInputs)
    child.invocation, child.project, child.cancellation = invocation, project, operation.guard
    child.prepared, child.claimed = True, False
    snapshot = object()
    child.scratch = types.SimpleNamespace(require_input=Mock(return_value=snapshot),
        require=Mock(return_value=Path("/inert/private/android-keystore")))
    invocation.child = operation.signing.materialization = child
    operation.signing.validation_passed = True
    operation.signing.values = {"MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": " PRIVATE store ",
        "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "upload-key", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": " PRIVATE key "}
    materialized = _MaterializedBuildEnvironment({**operation.signing.values,
        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": "/inert/private/android-keystore"}, child, None)
    return child, materialized


class SignedMaterialBindingTests(unittest.TestCase):
    def test_materialized_values_recheck_original_child_guard_null_lease_and_exact_keys(self):
        for fault in ("child", "guard", "lease", "specifier", "live", "path", "password", "extra"):
            with self.subTest(fault=fault), original(signed=True) as operation, patch.object(operation, "checkpoint"):
                child, values = materialized_data(operation)
                operation.signing.bind_materialized(values)
                if fault == "child":
                    child.invocation.child = object()
                elif fault == "guard":
                    values._cancellation = object()
                elif fault == "lease":
                    values._lease = object()
                elif fault == "specifier":
                    values._specifier = "unexpected-Apple-profile"
                elif fault == "live":
                    values._live = False
                elif fault == "path":
                    values["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"] = "/inert/other"
                elif fault == "password":
                    values["MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"] = "trimmed-or-changed"
                else:
                    values["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH"] = "/inert/not-selected"
                with self.assertRaises(ProtocolError):
                    operation.signing.require_materialized(child)

    def test_only_selected_consumers_receive_passwords_and_expired_mapping_is_retired(self):
        with original(signed=True) as operation, patch.object(operation, "checkpoint"):
            child, values = materialized_data(operation)
            operation.signing.bind_materialized(values)
            operation.inputs = types.SimpleNamespace(release=object())
            operation.files = types.SimpleNamespace(work_path=Path("/inert/work"))
            operation.tools = types.SimpleNamespace(command_environment=Mock(
                side_effect=lambda *_: {"LANG": "C.UTF-8", "MOBILE_RELEASE_REQUIRE_SIGNING": "false"}))
            for role in ("keytool-validate", "gradle", "jarsigner-sign", "bundletool", "jarsigner", "keytool"):
                operation._pending = role
                environment = operation.command_environment()
                if role in {"keytool-validate", "jarsigner-sign"}:
                    self.assertEqual(environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"], " PRIVATE store ")
                    self.assertEqual(environment["MOBILE_RELEASE_ANDROID_KEY_PASSWORD"], " PRIVATE key ")
                    self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH", environment)
                    self.assertNotIn("MOBILE_RELEASE_ANDROID_KEY_ALIAS", environment)
                elif role == "gradle":
                    self.assertEqual(environment["MOBILE_RELEASE_REQUIRE_SIGNING"], "true")
                    self.assertTrue(all(environment[name] == value for name, value in values.items()))
                else:
                    self.assertFalse(any("PRIVATE" in value for value in environment.values()))
                    self.assertFalse(any(name.startswith("MOBILE_RELEASE_ANDROID_") for name in environment))
            with patch.object(operation.signing, "inputs_closed", return_value=True), \
                    patch.object(operation, "closed", return_value=True):
                with self.assertRaises(ProtocolError):
                    operation.signing.retire_values()  # Neither predicate can retire a live materializer mapping.
                self.assertTrue(values)
                values._live = False
                operation.signing.retire_values()
            self.assertFalse(values)
            self.assertIsNone(operation.signing.values)


# Original Python types below are predicate DATA only. No _Outer/_Wire/native
# constructor, stream, process, handler or command is acquired by these tests.
def signing_dispatch_data(operation):
    from mobile_release import _command_process as commands
    from mobile_release._desktop_android_build_engine import _Engine
    from mobile_release._desktop_saved_command_control import SavedCommandDomain
    from mobile_release.desktop_android_build import AndroidBuildRun
    source, signing = operation.source, operation.signing
    service = object.__new__(AndroidBuildRun)
    service.operation, service.source, service.guard, service.request = operation, source, operation.guard, operation.request
    application = object.__new__(_Engine)
    application._domain = SavedCommandDomain.AndroidBuild
    application.input, application.guard, application.request, application.service = source, operation.guard, operation.request, service
    source._bind_engine(application)
    signing.config_bound = signing.validation_passed = True
    operation.stage, operation._pending = "signing", "jarsigner-sign"
    operation._roles.update({"keytool-validate": "returned", "gradle": "returned", "jarsigner-sign": "attempted"})
    operation._returned.update({"keytool-validate": 0, "gradle": 0})
    operation._command_before["jarsigner-sign"] = 2
    operation._dispatch["jarsigner-sign"] = None
    engine = object.__new__(commands._Outer)
    engine.guard, engine.owns, engine.scope, engine.binding = operation.guard, False, None, None
    engine._store_timing, engine._android_signing, engine.nonce = None, signing, b"s" * 16
    engine.phase, engine.cleanup_entered, engine.ready, engine.sealed = "NEW", False, False, False
    engine.protocol_failed = engine.output_failed = False
    engine.ctx = types.SimpleNamespace(guard=operation.guard, suppress_cancel=False,
        launch_retired=False, stopped=False, primary=None)
    engine.run_route = commands._Route(commands.Tag.RUN_TOOL)
    engine.wire = object.__new__(commands._Wire)
    engine.wire.ctx, engine.wire.out, engine.wire.sent = engine.ctx, None, []
    engine.wire.write_failed = engine.wire.write_in_flight = engine.wire.poisoned = False
    engine.slot = commands.CommandOutcomeSlot(None, engine.nonce, _key=commands._KEY)
    engine.slot._bind(engine)
    ledger = operation.guard.lifetime_ledger
    ledger._commands, ledger._command_dispatched = 2, True
    ledger._bind_command(engine.slot)
    return engine


def signing_sent_data(engine):
    from mobile_release import _command_process as commands
    engine.phase, engine.ready = "RUNNING", True
    engine.run_route.queue(); engine.run_route.attempt()
    engine.wire.sent.append(commands.Tag.RUN_TOOL)


class SigningDispatchTests(unittest.TestCase):
    def test_internal_signing_stage_is_reached_but_not_early_progress_or_successor_authority(self):
        with original(signed=True) as operation, patch.object(operation, "checkpoint"), \
                patch.object(operation.source, "progress") as progress:
            operation.stage = "capturing"
            operation.advance("signing")
            self.assertEqual(operation.stage, "signing")
            progress.assert_not_called()
            self.assertFalse(operation.signing.dispatch_claimed)
            with self.assertRaises(ProtocolError):
                operation.advance("restoring-signing")
            progress.assert_not_called()
            operation._returned["jarsigner-sign"] = 0  # A return label alone cannot replace the event.
            with patch.object(operation, "commands_settled", return_value=True), \
                    patch.object(operation.files, "capture_signed") as capture, self.assertRaises(ProtocolError):
                operation.capture_signed()
            capture.assert_not_called()
        with original() as operation, patch.object(operation, "checkpoint"), \
                patch.object(operation.source, "progress") as progress:
            operation.advance("building")
            progress.assert_called_once_with("building")

    def test_exact_slot_binding_is_resource_free_before_original_cleanup_scope(self):
        with original(signed=True) as operation:
            engine = signing_dispatch_data(operation)
            with patch.object(operation, "checkpoint", side_effect=AssertionError("no admission at slot bind")), \
                    patch.object(operation.guard, "check", side_effect=AssertionError("no STOP polling at slot bind")), \
                    patch.object(operation.source, "poll", side_effect=AssertionError("no input read at slot bind")), \
                    patch.object(subject.os, "open", side_effect=AssertionError("no descriptor at slot bind")):
                operation.signing.bind_command_slot(engine, engine.slot)
            self.assertIs(operation.signing.command_slot, engine.slot)
            self.assertIsNone(engine.slot.read())
            self.assertEqual(engine.phase, "NEW")
            self.assertIsNone(operation.source.first_failure)
            with self.assertRaises(ProtocolError):
                operation.signing.bind_command_slot(engine, engine.slot)

    def test_wrong_slot_source_role_and_cleanup_cannot_bind_signing_observation(self):
        for mutation in ("slot", "guard", "source-engine", "role", "order", "cleanup", "suppressed"):
            with self.subTest(mutation=mutation), original(signed=True) as operation:
                engine = signing_dispatch_data(operation)
                slot = engine.slot
                if mutation == "slot": slot = object()
                elif mutation == "guard": engine.guard = object()
                elif mutation == "source-engine": operation.source._engine.guard = object()
                elif mutation == "role": operation._pending = "gradle"
                elif mutation == "order": operation._command_before["jarsigner-sign"] = 1
                elif mutation == "cleanup": engine.cleanup_entered = True
                else: engine.ctx.suppress_cancel = True
                with self.assertRaises(ProtocolError):
                    operation.signing.bind_command_slot(engine, slot)
                self.assertIsNone(operation.signing.command_slot)
                self.assertFalse(operation.signing.dispatch_claimed)

    def test_complete_send_precedes_once_only_original_signing_progress(self):
        from mobile_release import _command_process as commands
        with original(signed=True) as operation, patch.object(operation.source, "progress") as progress:
            engine = signing_dispatch_data(operation)
            operation.signing.bind_command_slot(engine, engine.slot)
            engine.phase, engine.ready = "WAIT_READY", True
            events = []
            def sent(wire, tag, body, pump, *, route):
                self.assertIs(wire, engine.wire); self.assertIs(route, engine.run_route)
                self.assertIs(tag, commands.Tag.RUN_TOOL)
                self.assertFalse(operation.signing.dispatch_claimed)
                route.queue(); route.attempt(); wire.sent.append(tag); events.append("send-returned")
            def published(stage):
                self.assertEqual(stage, "signing")
                self.assertTrue(operation.signing.dispatch_claimed)
                self.assertFalse(operation.signing.dispatch_published)
                events.append("progress")
            progress.side_effect = published
            with patch.object(commands, "_send", side_effect=sent):
                engine._dispatch_run_tool()
            self.assertEqual(events, ["send-returned", "progress"])
            self.assertTrue(operation.signing.dispatch_published)
            with self.assertRaises(ProtocolError):
                operation.signing.command_dispatched(engine, engine.slot)
            self.assertEqual(progress.call_count, 1)

    def test_partial_or_failed_run_tool_send_never_publishes_a_signing_event(self):
        from mobile_release import _command_process as commands
        for partial in (False, True):
            with self.subTest(partial=partial), original(signed=True) as operation, \
                    patch.object(operation.source, "progress") as progress:
                engine = signing_dispatch_data(operation)
                operation.signing.bind_command_slot(engine, engine.slot)
                engine.phase, engine.ready = "WAIT_READY", True
                error = OSError("inert original send return lost")
                def send(*args, **kwargs):
                    if partial:
                        engine.run_route.queue(); engine.run_route.attempt()
                        engine.wire.out, engine.wire.write_failed = b"inert partial", True
                    raise error
                with patch.object(commands, "_send", side_effect=send), self.assertRaises(OSError) as caught:
                    engine._dispatch_run_tool()
                self.assertIs(caught.exception, error)
                self.assertFalse(operation.signing.dispatch_claimed)
                self.assertFalse(operation.signing.dispatch_published)
                progress.assert_not_called()

    def test_natural_producer_seal_during_successful_send_keeps_truthful_dispatch_without_reviving_launch(self):
        from mobile_release import _command_process as commands
        with original(signed=True) as operation, patch.object(operation.source, "progress") as progress:
            engine = signing_dispatch_data(operation)
            operation.signing.bind_command_slot(engine, engine.slot)
            engine.phase, engine.ready = "WAIT_READY", True
            def sent(wire, tag, body, pump, *, route):
                route.queue(); route.attempt(); wire.sent.append(tag)
                # Predicate model of _flush's final pump reading the original
                # PRODUCERS_SEALED. The full send did return successfully.
                engine.sealed = engine.ctx.launch_retired = True
                route.retire()
            with patch.object(commands, "_send", side_effect=sent):
                engine._dispatch_run_tool()
            progress.assert_called_once_with("signing")
            self.assertTrue(operation.signing.dispatch_published)
            self.assertTrue(engine.sealed and engine.run_route.retired and engine.ctx.launch_retired)
            self.assertEqual(engine.phase, "RUNNING")
            self.assertIsNone(engine.slot.read())
            self.assertNotIn("jarsigner-sign", operation._returned)

    def test_wrong_partial_retired_or_published_slot_cannot_emit_progress(self):
        for mutation in ("wrong-slot", "wrong-application", "wrong-service", "no-send", "partial", "retired",
                         "manual-retirement", "unretired-seal", "cleanup", "failed", "returned", "wrong-order"):
            with self.subTest(mutation=mutation), original(signed=True) as operation, \
                    patch.object(operation.source, "progress") as progress:
                engine = signing_dispatch_data(operation)
                operation.signing.bind_command_slot(engine, engine.slot)
                signing_sent_data(engine)
                slot = engine.slot
                if mutation == "wrong-slot": slot = object()
                elif mutation == "wrong-application": operation.source._engine = object()
                elif mutation == "wrong-service": operation.source._engine.service = object()
                elif mutation == "no-send": engine.wire.sent.clear()
                elif mutation == "partial": engine.wire.out = b"inert partial"
                elif mutation == "retired": engine.run_route.retire()
                elif mutation == "manual-retirement":
                    engine.run_route.retire(); engine.ctx.launch_retired = True
                elif mutation == "unretired-seal": engine.sealed = True
                elif mutation == "cleanup": engine.cleanup_entered = True
                elif mutation == "failed": engine.ctx.primary = OSError("inert earlier failure")
                elif mutation == "wrong-order": operation._command_before["jarsigner-sign"] = 1
                else: engine.slot._value = object()
                with self.assertRaises(ProtocolError):
                    operation.signing.command_dispatched(engine, slot)
                progress.assert_not_called()
                self.assertFalse(operation.signing.dispatch_claimed)
                self.assertEqual(operation.failure, "signing-incomplete")
                self.assertEqual(operation.source.first_failure, 100)

    def test_progress_failure_consumes_event_before_write_and_latches_both_originals(self):
        with original(signed=True) as operation:
            engine = signing_dispatch_data(operation)
            operation.signing.bind_command_slot(engine, engine.slot)
            signing_sent_data(engine)
            error = OSError("inert progress write return lost")
            ledger = operation.guard.lifetime_ledger
            with patch.object(operation.source, "progress", side_effect=error) as progress, \
                    patch.object(ledger, "_remember", wraps=ledger._remember) as remember:
                with self.assertRaises(OSError) as caught:
                    operation.signing.command_dispatched(engine, engine.slot)
                self.assertIs(caught.exception, error)
                self.assertTrue(operation.signing.dispatch_claimed)
                self.assertFalse(operation.signing.dispatch_published)
                self.assertEqual(operation.stage, "signing")
                self.assertEqual(operation.failure, "signing-incomplete")
                self.assertEqual(operation.source.first_failure, 100)
                remember.assert_called_once_with(error)
                self.assertIs(ledger._primary, error)
                with self.assertRaises(ProtocolError):
                    operation.signing.command_dispatched(engine, engine.slot)
                self.assertEqual(progress.call_count, 1)
                self.assertIs(ledger._primary, error)
                self.assertEqual(operation.source.first_failure, 100)
                self.assertNotIn("jarsigner-sign", operation._returned)

    def test_observed_late_normal_exit_is_not_capture_or_successor_authority(self):
        from mobile_release import _command_process as commands
        for code in (0, 1):
            with self.subTest(code=code), original(signed=True) as operation:
                engine = signing_dispatch_data(operation)
                operation.signing.bind_command_slot(engine, engine.slot)
                final = object.__new__(commands.OriginalCommandFinality); final._engine = engine
                observed = commands.OriginalCommandOutcome(engine, engine.nonce,
                    commands.RouteHistory(True, True), commands.RouteHistory(True, True), None,
                    "normal-exit", code, "complete", final)
                engine.slot._publish(engine, observed); engine.phase = "CLOSED"
                operation.guard.lifetime_ledger._finish_command(engine.slot,
                    dispatched=True, contained=True, cleanup_complete=True)
                operation.command_error("jarsigner-sign", KeyboardInterrupt())
                self.assertEqual(operation.role_outcome("jarsigner-sign"), {"outcome": "exited", "exitCode": code})
                self.assertNotIn("jarsigner-sign", operation._returned)
                self.assertIsNone(operation._artifact)
                self.assertEqual(operation._roles["jarsigner-sign"], "failed")
                with self.assertRaises(ProtocolError): operation.capture_signed()
                with patch.object(operation, "checkpoint"), self.assertRaises(ProtocolError): operation._arm("bundletool")

    def test_incomplete_or_unbound_original_outcome_keeps_signer_unknown(self):
        from mobile_release import _command_process as commands
        from dataclasses import replace
        for mutation in ("unpublished", "foreign", "foreign-application", "foreign-service", "nonce", "finality",
                         "foreign-finality", "signal", "no-create", "route", "untyped-route", "retired", "live", "boolean", "negative"):
            with self.subTest(mutation=mutation), original(signed=True) as operation:
                engine = signing_dispatch_data(operation)
                operation.signing.bind_command_slot(engine, engine.slot)
                final = object.__new__(commands.OriginalCommandFinality); final._engine = engine
                observed = commands.OriginalCommandOutcome(engine, engine.nonce,
                    commands.RouteHistory(True, True), commands.RouteHistory(True, True), None,
                    "normal-exit", 0, "complete", final)
                engine.phase = "CLOSED"
                if mutation == "foreign": observed = replace(observed, _engine=object())
                elif mutation == "foreign-application": operation.source._engine = object()
                elif mutation == "foreign-service": operation.source._engine.service = object()
                elif mutation == "nonce": observed = replace(observed, nonce=b"x" * 16)
                elif mutation == "finality": observed = replace(observed, original_finality=None)
                elif mutation == "foreign-finality": final._engine = object()
                elif mutation == "signal": observed = replace(observed, termination="signal-wait", returncode=-15)
                elif mutation == "no-create": observed = replace(observed, create_w=commands.RouteHistory(False, True))
                elif mutation == "route": observed = replace(observed, run_tool=commands.RouteHistory(False, True))
                elif mutation == "untyped-route": observed = replace(observed, run_tool=types.SimpleNamespace(attempted=True, retired=True))
                elif mutation == "retired": observed = replace(observed, run_tool=commands.RouteHistory(True, False))
                elif mutation == "live": engine.phase = "RUNNING"
                elif mutation == "boolean": observed = replace(observed, returncode=True)
                elif mutation == "negative": observed = replace(observed, returncode=-1)
                if mutation != "unpublished": engine.slot._value = observed  # Explicit malformed predicate DATA.
                self.assertIsNone(operation.signing.observed_exit())
                self.assertEqual(operation.role_outcome("jarsigner-sign"), {"outcome": "unknown", "exitCode": None})
                self.assertNotIn("jarsigner-sign", operation._returned)

    def test_non_signing_command_send_has_no_android_callback(self):
        from mobile_release import _command_process as commands
        engine = object.__new__(commands._Outer)
        engine.phase, engine.ready, engine.sealed = "WAIT_READY", True, False
        engine.wire, engine.nonce = object(), b"n" * 16
        engine.run_route = commands._Route(commands.Tag.RUN_TOOL)
        engine._android_signing = None
        with patch.object(commands, "_send") as send:
            engine._dispatch_run_tool()
        self.assertEqual(send.call_count, 1)
        self.assertEqual(engine.phase, "RUNNING")
