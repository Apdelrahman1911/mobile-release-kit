"""Inert signed/recovery adapter regressions; NOT native or Apple qualification.

Only original Python object types, synthetic policy and explicit memory DATA
are exercised. No file/descriptor, account, native command, signal handler,
credential, Store, subprocess or network resource is acquired by this suite.
"""
from __future__ import annotations

import copy
import json
import os
import plistlib
import stat
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_ios_archive as inert
from mobile_release import build_inputs, credentials, local_signing, owned_process
from mobile_release import _desktop_ios_recovery_protocol as recovery_wire
from mobile_release import _desktop_ios_signing_material as private
from mobile_release import _desktop_ios_signed_operation as signed_module
from mobile_release import _command_process as commands
from mobile_release._desktop_saved_command_control import _SavedCommandInput
from mobile_release._desktop_ios_archive_control import IOSArchiveInput
from mobile_release._desktop_ios_archive_protocol import ProtocolError
from mobile_release.cancellation import DefaultCancellation
from mobile_release.config import ReleaseConfig
from mobile_release.desktop_ios_archive import IOSArchiveRun
from mobile_release.ios_archive_operation import IOSArchiveError, IOSArchiveOperation


def signed_configuration():
    value = inert.configuration()
    value["ios"].update(teamId="INERT12345", distributionCertificateSha256="c" * 64)
    return value


def signed_request(config=None, *, raw=None):
    config = signed_configuration() if config is None else config
    canonical = json.dumps(config, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    raw = canonical if raw is None else raw
    value = inert.request_data()
    value["protocol"] = inert.wire.SIGNED_PROTOCOL
    value["context"].update(operation="ios-signed-export", savedConfig=inert.comparison(raw), signing={
        "teamId": "INERT12345", "distributionCertificateSha256": "c" * 64,
        "assignments": [{"kind": kind, "recordId": letter * 32, "recordRevision": 1, "contextRevision": 1}
                        for kind, letter in (("apple-p12", "d"), ("apple-profile", "e"))]})
    tool = value["native"]["toolchain"]["xcodebuildIdentity"]
    value["native"].update(signingTools={name: dict(tool) for name in ("security", "codesign", "openssl")},
                            signingContext=inert.comparison(canonical))
    return inert.wire.parse_request(inert.encode(value) + b"\n")


def recovery_request(action="inspect"):
    value = inert.request_data()
    value["protocol"] = recovery_wire.PROTOCOL
    value["context"] = {"projectId": "inert-ios", "platform": "ios", "operation": "ios-local-recovery",
                        "recovery": {"action": action, **({} if action == "inspect" else {"session": "f" * 32})}}
    value["native"]["security"] = value["native"].pop("toolchain")["xcodebuildIdentity"]
    return inert.wire.parse_request(inert.encode(value) + b"\n")


@contextmanager
def original(request=None):
    request = signed_request() if request is None else request
    guard, source = DefaultCancellation(owned_process.ProcessCleanupError, "inert signed DATA"), IOSArchiveInput(100)
    source.acquired = source.active = source.request_returned = True
    source._request_material(request)
    guard._install_ios_archive_source(source)
    guard.depth = 0  # No handler has been installed.
    with patch.object(signed_module.time, "monotonic", return_value=100), patch.object(source, "poll"), \
            patch.object(os, "open", side_effect=AssertionError("no native open")), \
            patch.object(os, "close", side_effect=AssertionError("no native close")), \
            patch.object(os, "unlink", side_effect=AssertionError("no native unlink")), \
            patch.object(os, "rmdir", side_effect=AssertionError("no native rmdir")), \
            patch.object(os, "scandir", side_effect=AssertionError("no native scan")), \
            patch.object(commands, "run_command", side_effect=AssertionError("no native command")), \
            patch.object(local_signing, "run_owned", side_effect=AssertionError("no native account command")):
        yield IOSArchiveOperation(request, guard, source)


@contextmanager
def admitted_invocation(operation):
    # Constructor binds the actual type before acquisition. Reservation values
    # below are explicit DATA, not a held environment lock or project receipt.
    invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
    invocation.active = invocation.reserved = True
    with patch.object(build_inputs, "_ENV_OWNER", invocation):
        yield invocation


def account_data(operation):
    signing = operation.signing
    signing.phase = "recovering-account" if operation.source.recovery else "admitting"
    lease = local_signing.SigningLease(operation.guard)
    lease.home, lease.path = Path("/inert/account"), Path("/inert/account/.mobile-release-signing")
    lease.locked, lease._recovery_mode = True, operation.source.recovery
    signing.phase = "recovering-account" if operation.source.recovery else "materializing-signing"
    session = local_signing.SigningSession(lease, token="f" * 32)
    lease.active = session
    return lease, session


@contextmanager
def memory_input(operation, frame, *, chunk=17, eof=False):
    source = operation.source
    source.fd = 9173  # Synthetic integer; all descriptor APIs below are replaced.
    source.identity = (1, 2, stat.S_IFIFO | 0o600)
    source.material_receiving = True
    pending = bytearray(frame)
    def read(number, maximum):
        if number != source.fd:
            raise AssertionError("foreign DATA read")
        if not pending:
            if eof:
                return b""
            raise BlockingIOError
        count = min(maximum, chunk, len(pending))
        data = bytes(pending[:count]); del pending[:count]
        return data
    with patch.object(source, "poll", side_effect=lambda guard: _SavedCommandInput.poll(source, guard)), \
            patch.object(os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2, st_mode=source.identity[2])), \
            patch.object(os, "read", side_effect=read), patch.object(private.select, "select", return_value=([], [], [])):
        yield source


def material_frame(request, contents=(b"inert-p12", b"inert-password", b"inert-profile")):
    roles = private.roles_for(request.context)
    header = inert.encode({"schemaVersion": 1, "files": [{"role": role, "bytes": len(content)}
                         for role, content in zip(roles, contents)]}) + b"\n"
    return private.PREFIX + header + b"".join(contents) + private.SUFFIX


class SignedMaterialTests(unittest.TestCase):
    def test_header_rejects_reordering_duplicates_boolean_size_and_overflow_without_reflection(self):
        roles = ("apple-p12", "p12-password", "apple-profile")
        value = {"schemaVersion": 1, "files": [{"role": role, "bytes": 1} for role in roles]}
        self.assertEqual(private.parse_header(inert.encode(value) + b"\n", roles), (1, 1, 1))
        for change in (lambda v: v["files"].reverse(), lambda v: v["files"][0].update(bytes=True),
                       lambda v: v["files"][0].update(bytes=private.LIMITS["apple-p12"] + 1),
                       lambda v: v.update(secret="inert-never-reflect")):
            data = copy.deepcopy(value); change(data)
            with self.assertRaises(ProtocolError) as failure:
                private.parse_header(inert.encode(data) + b"\n", roles)
            self.assertNotIn("inert-never-reflect", str(failure.exception))
        with self.assertRaises(ProtocolError):
            private.parse_header(b'{"schemaVersion":1,"schemaVersion":1,"files":[]}\n', roles)

    def test_one_private_frame_is_incremental_and_extra_input_becomes_stop(self):
        for extra in (b"", b"extra"):
            with self.subTest(extra=bool(extra)), original() as operation, \
                    memory_input(operation, material_frame(operation.request) + extra) as source:
                received = private.read_material(source, operation.request)
                self.assertIs(source.material, received)
                self.assertEqual(received._files[private.FILES["apple-p12"]], b"inert-p12")
                source.material_pending = source.material_receiving = False
                if extra:
                    with self.assertRaises(KeyboardInterrupt): operation.guard.check()
                    self.assertEqual(source.stop_reason, "cancelled")
                else:
                    operation.guard.check()
                    self.assertEqual(source.stop_reason, "none")

    def test_truncated_or_relabelled_private_input_never_publishes_a_material_owner(self):
        for change in (lambda f: f[:-1], lambda f: b"BAD" + f[3:]):
            with original() as operation, memory_input(operation, change(material_frame(operation.request)), eof=True) as source:
                with self.assertRaises((ProtocolError, KeyboardInterrupt)):
                    private.read_material(source, operation.request)
                self.assertIsNone(source.material)

    def test_canonical_unicode_draft_and_raw_saved_bytes_are_separate_exact_bindings(self):
        config = signed_configuration(); config["ios"]["scheme"] = "Café 日本語"
        raw = json.dumps(config, ensure_ascii=True, indent=2).encode()
        request = signed_request(config, raw=raw)
        with original(request) as operation, patch.object(operation, "checkpoint"):
            operation.inputs = SimpleNamespace(config=ReleaseConfig(operation.root / "release/mobile-release.json", operation.root, config))
            received = private.PrivateIOSMaterial(operation.source, request.context, (b"P12-data", b"password-data", b"profile-data"))
            operation.source.material = received
            operation.signing.bind_values()
            values = operation.signing.values
            self.assertEqual(dict(values), {private.SCALARS["p12-password"]: "password-data"})
            self.assertIs(values.material(private.FILES["apple-p12"], root=operation.root, cancellation=operation.guard),
                          received._files[private.FILES["apple-p12"]])
            self.assertNotEqual(request.context["savedConfig"], request.native["signingContext"])
            selected = credentials.credential_values_for_purpose(operation.inputs.config, values,
                stage="candidate", purpose="signing", platforms=("ios",))
            self.assertIs(type(selected), private.CapturedBuildValues)
            self.assertIsNone(selected.material(private.FILES["ios-firebase"], root=operation.root, cancellation=operation.guard))
        with original(request) as operation, patch.object(operation, "checkpoint"):
            changed = copy.deepcopy(config); changed["ios"]["scheme"] = "Different"
            operation.inputs = SimpleNamespace(config=ReleaseConfig(operation.root / "release/mobile-release.json", operation.root, changed))
            operation.source.material = private.PrivateIOSMaterial(operation.source, request.context, (b"p", b"x", b"r"))
            with self.assertRaises(IOSArchiveError) as failure: operation.signing.bind_values()
            self.assertEqual(failure.exception.reason, "stale-intent")
            self.assertIsNone(operation.signing.values)

    def test_private_retirement_requires_original_consumer_closure_and_stale_context_refuses(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            received = private.PrivateIOSMaterial(operation.source, operation.request.context, (b"p", b"x", b"r"))
            operation.source.material = received
            received.bind(operation)
            with self.assertRaises(ProtocolError): received.retire()
            operation.source.closed = True
            with patch.object(operation, "commands_settled", return_value=False):
                with self.assertRaises(ProtocolError): received.retire()
            self.assertFalse(received._retired)
            with patch.object(operation, "commands_settled", return_value=True), \
                    patch.object(operation, "snapshot_closed", return_value=True), patch.object(operation, "closed", return_value=True):
                received.retire()
            self.assertTrue(received._retired); self.assertFalse(received._files or received._scalars)
            with self.assertRaises(ProtocolError): received.check()


class SignedOwnershipTests(unittest.TestCase):
    def test_export_uses_shared_offline_policy_and_rechecks_same_options_without_resetting_archive(self):
        from mobile_release import ios
        for drift in (False, True):
            with original() as operation:
                operation.signing.phase = "building"
                operation.signing.profile_specifier = "A" * 8 + "-" + "B" * 4 + "-" + "C" * 4 + "-" + "D" * 4 + "-" + "E" * 12
                operation.inputs = SimpleNamespace(config=ReleaseConfig(operation.root / "release/mobile-release.json",
                    operation.root, signed_configuration()))
                namespace = SimpleNamespace(fd=71, path=operation.root / ".mobile-release/desktop-ios-archive" / operation.operation_id,
                                            check=Mock())
                operation.files.namespace = namespace
                archive = SimpleNamespace(path=namespace.path / "archive.xcarchive", check=Mock())
                operation._artifact = archive
                export = SimpleNamespace(directory=True, slot=SimpleNamespace(number=72))
                ipa = SimpleNamespace(directory=False, parent_record=export, name="Inert.ipa", identity={"size": 4})
                options = object(); checked = []
                def verify(original, content):
                    self.assertIs(original, options)
                    checked.append(content)
                    if drift and len(checked) == 2:
                        raise IOSArchiveError("artifact-changed")
                def exported(role, argv):
                    self.assertEqual(role, "export")
                    self.assertEqual(argv, (operation.request.native["toolchain"]["developerDir"] + "/usr/bin/xcodebuild",
                        "-exportArchive", "-archivePath", str(archive.path), "-exportPath", str(namespace.path / "export"),
                        "-exportOptionsPlist", str(namespace.path / "work/ExportOptions.plist")))
                    operation._returned["export"] = 0  # Inert result DATA; no native execution.
                with patch.object(operation, "require"), patch.object(operation, "checkpoint"), \
                        patch.object(operation, "artifact", return_value=archive), patch.object(operation, "_run", side_effect=exported), \
                        patch.object(operation.files, "names", side_effect=[{"work", "archive.xcarchive"},
                            {"work", "archive.xcarchive", "export"}, {"Inert.ipa", "ExportSummary.plist"}]), \
                        patch.object(operation.files, "work_path", side_effect=lambda name: namespace.path / "work" / name), \
                        patch.object(operation.files, "write_export_options", return_value=options), \
                        patch.object(operation.files, "check_export_options", side_effect=verify), \
                        patch.object(operation.files, "_hold", side_effect=[export, ipa]), patch.object(operation.files, "check_held"):
                    if drift:
                        with self.assertRaises(IOSArchiveError): operation.run_export()
                        self.assertIsNone(operation._ipa)
                    else:
                        operation.run_export()
                        self.assertIs(operation._ipa.original, ipa)
                self.assertIs(operation._artifact, archive)
                self.assertEqual(len(checked), 2); self.assertEqual(checked[0], checked[1])
                policy = plistlib.loads(checked[0])
                self.assertEqual(policy, ios._export_options("org.example.inert", "INERT12345", operation.signing.profile_specifier))
                self.assertFalse(policy["uploadSymbols"] or policy["stripSwiftSymbols"])
                self.assertEqual((policy["destination"], policy["signingStyle"], policy["thinning"]), ("export", "manual", "<none>"))

    def test_mode_clocks_keep_original_start_and_first_failure_clamps_without_renewal(self):
        for request, ends in ((signed_request(), (5500, 5620, 5630)), (recovery_request(), (220, 340, 350))):
            with original(request) as operation:
                source = operation.source
                self.assertEqual((source.work_end, source.cleanup_endpoint(), source.hard_endpoint()), ends)
                with patch.object(signed_module.time, "monotonic", return_value=105): source.failure_observed()
                with patch.object(signed_module.time, "monotonic", return_value=117): source.failure_observed()
                self.assertEqual((source.first_failure, source.cleanup_endpoint(), source.hard_endpoint()), (105, 225, 235))

    def test_account_constructor_requires_original_environment_before_project_and_private_material(self):
        with original() as operation:
            with self.assertRaises(ProtocolError): local_signing.SigningLease(operation.guard)
            with admitted_invocation(operation) as invocation:
                invocation.project_started = True
                with self.assertRaises(ProtocolError): local_signing.SigningLease(operation.guard)
                invocation.project_started = False
                lease = local_signing.SigningLease(operation.guard)
                self.assertIs(operation.signing.lease, lease)
                with self.assertRaises(ProtocolError): operation.source.receive_material(operation)
                self.assertIsNone(operation.source.material)

    def test_cleanup_flag_cannot_replace_original_scope_authorization_or_stop_recovery(self):
        with original(recovery_request("account")) as operation, admitted_invocation(operation):
            lease, session = account_data(operation); session.cleaning = True
            authorization = local_signing._RecoveryAttempt(session, _key=local_signing._RECOVERY_KEY)
            session._recovery_attempt = authorization
            source = object.__new__(commands.AccountExecutionSource)
            source._lease, source._authorization = lease, authorization
            scope = commands.AccountExecutionScope(source, b"s" * 16, _key=commands._KEY)
            with patch.object(lease, "assert_owner"):
                self.assertEqual(operation.signing._admit(["security", "list-keychains", "-d", "user"], scope, None, True),
                                 ("account-recovery", 30))
                source._authorization = object()
                with self.assertRaises(ProtocolError): operation.signing._admit(["security", "list-keychains"], scope, None, True)
                source._authorization = authorization
                with self.assertRaises(ProtocolError): operation.signing._admit(["security", "create-keychain"], scope, None, True)
                operation.source.failure_observed()
                with operation.guard.deferred(check_on_exit=False):
                    with self.assertRaises(IOSArchiveError): operation.signing._admit(["security", "list-keychains"], scope, None, True)

    def test_recovery_runner_does_not_suppress_original_stop_as_implicit_cleanup(self):
        @contextmanager
        def admitted(*args, **kwargs):
            yield ("/usr/bin/security", "list-keychains"), {"LANG": "C"}, 3, 1024
        with original(recovery_request("account")) as operation, patch.object(operation.signing, "command", admitted), \
                patch.object(commands, "run_command", return_value="inert-return") as command:
            self.assertEqual(owned_process.run_owned(["security", "list-keychains"], cancellation=operation.guard,
                                                    cleanup=True), "inert-return")
            self.assertIs(command.call_args.kwargs["cleanup"], False)
            self.assertIsNone(command.call_args.kwargs["on_start"])
            self.assertIs(command.call_args.kwargs["cancellation"], operation.guard)

    def test_request_budget_charges_actual_arguments_and_rejects_unbounded_environment_before_entry(self):
        reserve = signed_module.SignedIOSOperation.request_reservation
        self.assertGreater(reserve(("/usr/bin/security", "list-keychains"), {"HOME": "/inert/account"}, Path("/inert")), 0)
        for arguments, environment in ((("security", "x"), {}), (("/usr/bin/security",), {"X": "z" * 65537}),
                                       (("/usr/bin/security",), {str(i): "v" for i in range(65)})):
            with self.assertRaises(ProtocolError): reserve(arguments, environment, Path("/inert"))

    def test_command_retains_original_capture_and_missing_later_slot_never_inherits_earlier_finality(self):
        with original() as operation, patch.object(operation.signing, "_admit", return_value=("account-setup", 30)), \
                patch.object(operation.signing, "command_environment", return_value={}), \
                patch.object(operation.signing, "check_tool_bindings"), \
                patch.object(commands.os, "urandom", return_value=b"i" * 16):
            signing = operation.signing
            with signing.command(["/usr/bin/security", "list-keychains"], environ={}, cwd=Path("/inert"), timeout=30,
                                 capture=True, text=True, output_limit=1024, cleanup=False, scope=None, binding=None):
                engine = commands._Outer(operation.guard, False, 30, None, None, suppress_cancel=False)
                # Original types with explicit finality predicate DATA. Never
                # a native child/wait receipt; no engine body/cleanup is run.
                wait = SimpleNamespace(status_kind="exit", status_code=0)
                engine.child, engine.wait = SimpleNamespace(receipt=wait), wait
                engine.terminal = {"producer": True, "stdout": 4, "stderr": 0}
                engine.sealed = True; engine.wire = SimpleNamespace(eof=True, poisoned=False)
                engine.readers = [object(), object()]; engine.output_eof = [True, True]
                engine.handlers_complete = engine.local_cleanup_complete = True
                engine.outputs[0].extend(b"DATA"); engine.decoded = ("DATA", "")
                final = object.__new__(commands.OriginalCommandFinality); final._engine = engine
                outcome = commands.OriginalCommandOutcome(engine, engine.nonce, commands.RouteHistory(True, True),
                    commands.RouteHistory(True, True), None, "normal-exit", 0, "complete", final)
                engine.phase = "CLOSED"; engine.slot._publish(engine, outcome)
                operation.guard.lifetime_ledger._finish_command(engine.slot, dispatched=True, contained=True, cleanup_complete=True)
            self.assertEqual(engine.outputs[0], b"DATA"); self.assertEqual(engine.decoded, ("DATA", ""))
            self.assertTrue(signing.commands_settled())
            self.assertLess(signing.capture_reserved, signed_module.COMMAND_METADATA_RESERVE + 12 * 1024 + 4096)
            later = signed_module._Command("account-setup", None, None, False, 1024, entered=True, state="ENTERED")
            signing.commands.append(later)
            self.assertFalse(signing.commands_settled())
            self.assertIs(operation.command_dispatch(), True)  # Earlier dispatch is still irrevocable, never a success proof.

    def test_only_same_final_command_can_persist_settlement_after_stop_without_new_work(self):
        for missing_original in (False, True):
            with original() as operation, admitted_invocation(operation):
                lease, session = account_data(operation)
                source = object.__new__(commands.AccountExecutionSource)
                source._lease, source._authorization = lease, None
                scope = commands.AccountExecutionScope(source, b"s" * 16, _key=commands._KEY)
                binding = object.__new__(commands.JournalledCommandBinding)
                binding._scope, binding._session = scope, session
                binding._fence_observation = commands.FenceObservationPolicy.OFF
                scope._binding = binding
                session._command_scope, session._command_binding = scope, binding
                session.state = {"revision": 0, "native": {}, "inflight": {"phase": "PREPARED", "kind": "observe"}}
                signing = operation.signing
                with patch.object(signing, "_admit", return_value=("account-setup", 30)), \
                        patch.object(signing, "command_environment", return_value={}), \
                        patch.object(signing, "check_tool_bindings"), patch.object(source, "_check"):
                    with signing.command(["/usr/bin/security", "list-keychains"], environ={}, cwd=operation.root,
                            timeout=30, capture=True, text=True, output_limit=1024, cleanup=False, scope=scope, binding=binding):
                        engine = commands._Outer(operation.guard, False, 30, scope, binding, suppress_cancel=False)
                        # No native resources were entered. These retirement
                        # flags are inert predicate DATA, not Mac qualification.
                        engine.create_route.retired = engine.run_route.retired = True
                        engine.handlers_complete = engine.local_cleanup_complete = True
                        engine.publish()
                operation.source.stop("cancelled")
                first = operation.source.first_failure
                if missing_original:
                    engine.phase = "UNKNOWN"
                writes = []
                def write(name, value, **kwargs):
                    session.assert_owner()
                    self.assertIs(signing.settling_command, signing.commands[-1])
                    self.assertFalse(signing.commands_settled())
                    with self.assertRaises(ProtocolError):
                        with signing.command(["/usr/bin/security", "list-keychains"], environ={}, cwd=operation.root,
                                timeout=30, capture=True, text=True, output_limit=1024, cleanup=True, scope=scope, binding=binding):
                            self.fail("settlement cannot dispatch another command")
                    writes.append(name)
                with patch.object(lease, "assert_owner"), patch.object(local_signing, "_names", return_value=set()), \
                        patch.object(session, "_write", side_effect=write), operation.guard.deferred(check_on_exit=False):
                    if missing_original:
                        with self.assertRaises(ProtocolError): session.finish_original_command_if_settled()
                        self.assertFalse(writes); self.assertFalse(session._command_finished)
                    else:
                        self.assertTrue(session.finish_original_command_if_settled())
                        self.assertEqual(writes, ["state.json", "state.json"])
                        self.assertIsNone(session.state["inflight"])
                        with self.assertRaises(KeyboardInterrupt): session.assert_owner()
                self.assertIsNone(signing.settling_command)
                self.assertEqual(operation.source.first_failure, first)
                self.assertEqual(operation.source.stop_reason, "cancelled")
        with original(recovery_request("account")) as operation, admitted_invocation(operation):
            lease, session = account_data(operation); session.cleaning = True
            operation.source.stop("cancelled")
            with patch.object(lease, "assert_owner"), operation.guard.deferred(check_on_exit=False):
                with self.assertRaises(KeyboardInterrupt): session.finish_original_command_if_settled()
                self.assertIsNone(operation.signing.settling_command)


class RecoveryTests(unittest.TestCase):
    def service(self, operation):
        service = object.__new__(IOSArchiveRun)
        service.request, service.operation = operation.request, operation
        service.guard, service.source = operation.guard, operation.source
        service.primary = service._candidate = service.recovery_report = None
        service.findings = []
        return service

    def test_inspect_closes_account_before_project_and_never_runs_recovery_commands(self):
        with original(recovery_request()) as operation:
            service = self.service(operation); events = []
            def account(**kwargs):
                self.assertIs(kwargs["cancellation"], operation.guard); events.append("account-returned")
                return {"status": "pending", "session": "f" * 32}
            def project(root, **kwargs):
                self.assertEqual(events, ["account-returned"]); self.assertIs(kwargs["cancellation"], operation.guard)
                return {"status": "idle"}
            with patch.object(operation, "advance", side_effect=lambda stage: setattr(operation, "stage", stage)), \
                    patch.object(operation.files, "check_tools"), patch.object(local_signing, "signing_status", side_effect=account), \
                    patch.object(build_inputs, "build_inputs_status", side_effect=project), \
                    patch.object(local_signing, "recover_signing", side_effect=AssertionError("inspect cannot recover")), \
                    patch.object(build_inputs, "recover_build_inputs", side_effect=AssertionError("inspect cannot recover")):
                service._recovery_body()
            self.assertEqual(service.recovery_report["account"], {"status": "pending", "session": "f" * 32, "next": "ordinary"})
            self.assertEqual(operation.stage, "disposing-work"); self.assertIsNone(service.primary)
            recovery_wire.report(service.recovery_report, operation.request.context)

    def test_known_account_failure_latches_before_opposite_scope_and_unknown_hides_report(self):
        with original(recovery_request()) as operation:
            service = self.service(operation)
            with patch.object(operation, "advance", side_effect=lambda stage: setattr(operation, "stage", stage)), \
                    patch.object(local_signing, "signing_status", return_value={"status": "busy"}), \
                    patch.object(build_inputs, "build_inputs_status", side_effect=AssertionError("opposite scope after F")) as project:
                service._recovery_body(); project.assert_not_called()
            self.assertEqual(service.recovery_report["project"]["status"], "not-inspected")
            self.assertIsNotNone(operation.source.first_failure)
            operation.source.closed = True; operation.guard._restoration = "RESTORED"
            with patch.object(operation, "closed", return_value=True), patch.object(operation.files, "closed", return_value=True), \
                    patch.object(operation, "snapshot_closed", return_value=True):
                terminal = service.terminal()
                self.assertEqual(terminal["outcome"], "refused"); self.assertIsNotNone(terminal["report"])
                with patch.object(operation.signing, "account_closed", return_value=False):
                    terminal = service.terminal()
                    self.assertEqual(terminal["outcome"], "unknown"); self.assertIsNone(terminal["report"])

    def test_project_action_preserves_manual_requirement_and_never_enters_account(self):
        with original(recovery_request("project")) as operation:
            service = self.service(operation)
            with patch.object(operation, "advance", side_effect=lambda stage: setattr(operation, "stage", stage)), \
                    patch.object(local_signing, "signing_status", side_effect=AssertionError("opposite scope")), \
                    patch.object(local_signing, "recover_signing", side_effect=AssertionError("opposite scope")), \
                    patch.object(build_inputs, "recover_build_inputs", side_effect=build_inputs.BuildInputManualRecoveryRequired("inert")) as recover:
                service._recovery_body()
            self.assertIsNone(service.recovery_report["account"])
            self.assertEqual(service.recovery_report["project"], {"status": "manual-required", "session": "f" * 32, "next": "manual"})
            self.assertEqual(recover.call_args.kwargs, {"session": "f" * 32, "confirm": recovery_wire.PROJECT_CONFIRMATION,
                "manual": False, "cancellation": operation.guard})
            recovery_wire.report(service.recovery_report, operation.request.context)

    def test_account_stop_between_inspection_and_removal_prevents_effect_but_not_independent_close(self):
        with original(recovery_request("account")) as operation, admitted_invocation(operation):
            lease, session = account_data(operation); session.cleaning = True
            def names(number):
                operation.source.failure_observed(); return set()
            with patch.object(lease, "assert_owner"), patch.object(local_signing, "_names", side_effect=names), \
                    patch.object(os, "rmdir", side_effect=AssertionError("no effect after F")) as remove:
                with operation.guard.deferred(check_on_exit=False):
                    with self.assertRaises(IOSArchiveError): session._remove_empty_session()
                remove.assert_not_called()
                session.close()  # None/NEW descriptor slots only; no native close.
            self.assertTrue(session.closed); self.assertFalse(session._disposal_complete)

    def test_recovery_pending_inputs_need_original_close_not_disposal_or_opposite_lease(self):
        with original(recovery_request("project")) as operation, admitted_invocation(operation):
            signing = operation.signing; signing.phase = "recovering-project"
            expected = operation.request.native["rootIdentity"]
            project = build_inputs._Project(operation.root, operation.guard, recovery=True, expected_root=(
                int(expected["device"]), int(expected["inode"]), expected["mode"], expected["uid"], expected["gid"]))
            signing.bind_recovery_project(project)
            child = build_inputs.BuildInputs(None, project); signing.bind_recovery_inspection(child)
            child.created = child.scratch.created = True  # Preserved pending DATA, not new files.
            self.assertFalse(signing.inputs_closed())
            signing.inspection_closing(child)
            child.slot.close(); child.scratch.slot.close(); child.scratch.parent.close()
            signing.inspection_closed(child); project.cleanup()
            self.assertTrue(signing.inputs_closed())
            self.assertTrue(child.created and child.scratch.created)
            child.slot.close_state = "UNKNOWN"
            self.assertFalse(signing.inputs_closed())

    def test_project_root_is_bound_before_admission_and_stop_blocks_read_or_open(self):
        with original(recovery_request("project")) as operation, admitted_invocation(operation):
            operation.signing.phase = "recovering-project"
            @contextmanager
            def no_effect_scope(owner, guard, owns):
                self.assertIs(operation.signing.recovery_project, owner)
                self.assertEqual(owner.expected_root, (1, 2, stat.S_IFDIR | 0o755, 0, 0))
                yield owner
            with patch.object(build_inputs, "_scope", no_effect_scope), \
                    patch.object(build_inputs, "cancellation_owner", return_value=(operation.guard, False)):
                with build_inputs._inspection(operation.root, operation.guard): pass
            operation.source.failure_observed()
            with operation.guard.deferred(check_on_exit=False), patch.object(os, "read", side_effect=AssertionError("no read after F")) as read:
                with self.assertRaises(IOSArchiveError): build_inputs._read_file(99, "inert", operation.guard, 32)
                with self.assertRaises(IOSArchiveError): build_inputs._FD(operation.guard).open("inert", os.O_RDONLY)
                read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
