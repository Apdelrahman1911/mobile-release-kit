"""Inert signed-Android contracts, not native JDK or project qualification.

All material, descriptors, command receipts and ownership predicates here are
synthetic DATA. Native IO/process seams are replaced before use. These tests
neither create a key nor sign/build an artifact or contact a Store.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_android_build_protocol as protocol
import test_android_build_service as service_data
from mobile_release import android, build_inputs, credentials, discovery, owned_process
from mobile_release import _command_process as commands
from mobile_release import _desktop_android_signing_material as private
from mobile_release import android_build_operation as operation_module
from mobile_release import desktop_android_build as service
from mobile_release._desktop_android_build_control import AndroidBuildInput
from mobile_release._desktop_saved_command_control import _SavedCommandInput
from mobile_release.android_build_operation import AndroidBuildError, AndroidBuildOperation
from mobile_release.cancellation import DefaultCancellation
from mobile_release.reporting import Finding, Status

wire = protocol.wire


@contextmanager
def original(request=None):
    request = wire.parse_request(protocol.encoded(protocol.signed_request_data())) if request is None else request
    guard, source = DefaultCancellation(owned_process.ProcessCleanupError, "inert Android DATA"), AndroidBuildInput(100)
    source.acquired = source.active = source.request_returned = True
    source._request_material(request)
    guard._install_android_build_source(source)
    guard.depth = 0
    with ExitStack() as stack:
        stack.enter_context(patch.object(operation_module.time, "monotonic", return_value=100))
        stack.enter_context(patch.object(source, "poll"))
        for target, names in ((os, ("open", "close", "unlink", "rmdir", "scandir")),
                              (commands, ("run_command",)), (owned_process, ("run_owned",)),
                              (android, ("run_owned", "discover_project", "private_build_directory"))):
            for name in names:
                stack.enter_context(patch.object(target, name, side_effect=AssertionError("unexpected native boundary: " + name)))
        yield AndroidBuildOperation(request, guard, source)


@contextmanager
def memory_input(operation, frame, *, chunk=17, eof=False):
    source = operation.source
    source.fd = 9173  # Synthetic only: every descriptor boundary is replaced.
    source.identity = (1, 2, stat.S_IFIFO | 0o600)
    source.material_receiving = True
    pending = bytearray(frame)

    def read(number, maximum):
        if number != source.fd: raise AssertionError("foreign DATA read")
        if not pending:
            if eof: return b""
            raise BlockingIOError
        count = min(maximum, chunk, len(pending))
        result = bytes(pending[:count]); del pending[:count]
        return result

    with patch.object(source, "poll", side_effect=lambda guard: _SavedCommandInput.poll(source, guard)), \
         patch.object(os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2, st_mode=source.identity[2])), \
         patch.object(os, "read", side_effect=read), patch.object(private.select, "select", return_value=([], [], [])):
        yield source


def frame(request, contents=(b"inert-jks", b"store-secret", b"upload-key", b"key-secret")):
    roles = private.roles_for(request.context)
    header = protocol.encoded({"schemaVersion": 1, "files": [
        {"role": role, "bytes": len(content)} for role, content in zip(roles, contents)]})
    return private.PREFIX + header + b"".join(contents) + private.SUFFIX


class AndroidSignedMaterialTests(unittest.TestCase):
    def test_saved_raw_and_native_canonical_configuration_are_separate_exact_bindings(self):
        _, bound = service_data.values(signature=True)
        data = copy.deepcopy(bound.config.data)
        data["metadata"]["root"] = "release/Café 日本語"
        raw = json.dumps(data, indent=2, ensure_ascii=True).encode("utf-8")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        version = bound.saved.version_raw
        compare = lambda value: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        for changed in (False, True):
            request = protocol.signed_request_data()
            request["context"]["artifactValidation"]["uploadCertificateSha256"] = data["android"]["uploadCertificateSha256"]
            request["context"].update(savedConfig=compare(raw), savedVersion={
                **compare(version), "source": bound.saved.configuration.source,
                "name": bound.release.name, "build": bound.release.build})
            request["native"]["signingContext"] = compare(canonical)
            if changed: request["native"]["signingContext"]["sha256"] = "0" * 64
            request = wire.parse_request(protocol.encoded(request))
            self.assertNotEqual(request.context["savedConfig"], request.native["signingContext"])
            with original(request) as operation, patch.object(operation, "checkpoint"), \
                 patch.object(operation.files, "read_input", side_effect=(raw, version)), \
                 patch.object(operation, "check_inputs"), patch.object(operation.source, "receive_material") as received:
                if changed:
                    with self.assertRaises(AndroidBuildError) as failure: operation.bind_inputs()
                    self.assertEqual(failure.exception.reason, "stale-intent")
                    self.assertEqual(operation.source.first_failure, 100)
                else:
                    result = operation.bind_inputs()
                    self.assertEqual(result.config.data["metadata"]["root"], "release/Café 日本語")
                    self.assertEqual(result.saved.configuration.raw, raw)
                received.assert_not_called()

    def test_private_frame_is_incremental_and_extra_bytes_are_stop_not_a_second_request(self):
        for extra in (b"", b"extra"):
            with self.subTest(extra=bool(extra)), original() as operation, memory_input(operation, frame(operation.request) + extra) as source:
                material = private.read_material(source, operation.request)
                self.assertIs(source.material, material)
                self.assertEqual(material._files[private.FILES["android-keystore"]], b"inert-jks")
                source.material_pending = source.material_receiving = False
                if extra:
                    with self.assertRaises(KeyboardInterrupt): operation.guard.check()
                    self.assertEqual(source.stop_reason, "cancelled")
                else:
                    operation.guard.check()

    def test_malformed_header_body_role_and_alias_do_not_publish_material(self):
        roles = private.roles_for(protocol.signed_request_data()["context"])
        good = {"schemaVersion": 1, "files": [{"role": role, "bytes": 1} for role in roles]}
        self.assertEqual(private.parse_header(protocol.encoded(good), roles), (1, 1, 1, 1))
        for mutate in (lambda v: v["files"].reverse(), lambda v: v["files"][0].update(bytes=True),
                       lambda v: v["files"][0].update(bytes=private.LIMITS["android-keystore"] + 1),
                       lambda v: v["files"][0].update(role="apple-p12"), lambda v: v.update(secret="PRIVATE")):
            value = copy.deepcopy(good); mutate(value)
            with self.assertRaises(wire.ProtocolError): private.parse_header(protocol.encoded(value), roles)
        with self.assertRaises(wire.ProtocolError):
            private.parse_header(b'{"schemaVersion":1,"schemaVersion":1,"files":[]}\n', roles)
        for change in (lambda b: b[:-1], lambda b: b.replace(private.PREFIX, b"MRK-IOS-MATERIAL/1\n", 1)):
            with original() as operation, memory_input(operation, change(frame(operation.request)), eof=True) as source:
                with self.assertRaises((wire.ProtocolError, KeyboardInterrupt)): private.read_material(source, operation.request)
                self.assertIsNone(source.material)
        for alias in (b"-option", b"bad\0alias", b"\xff"):
            with original() as operation:
                with self.assertRaises(wire.ProtocolError):
                    private.PrivateAndroidMaterial(operation.source, operation.request.context, (b"jks", b"pw", alias, b"pw"))

    def test_mapping_keeps_files_private_and_retirement_requires_original_closure(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            material = private.PrivateAndroidMaterial(operation.source, operation.request.context,
                (b"jks", b"store-secret", b"alias", b"key-secret"))
            operation.source.material = material
            operation.signing.bind_values()
            values = operation.signing.values
            self.assertEqual(dict(values), {private.SCALARS["store-password"]: "store-secret",
                private.SCALARS["key-alias"]: "alias", private.SCALARS["key-password"]: "key-secret"})
            self.assertIs(values.material(private.FILES["android-keystore"], root=operation.root, cancellation=operation.guard),
                          material._files[private.FILES["android-keystore"]])
            with self.assertRaises(wire.ProtocolError):
                values.material(private.FILES["android-keystore"], root=Path("/foreign"), cancellation=operation.guard)
            with self.assertRaises(wire.ProtocolError): material.retire()
            operation.source.closed = True
            with patch.object(operation, "commands_settled", return_value=True), patch.object(operation, "closed", return_value=False):
                with self.assertRaises(wire.ProtocolError): material.retire()
                self.assertTrue(material._files)
            with patch.object(operation, "commands_settled", return_value=True), patch.object(operation, "closed", return_value=True):
                material.retire()
            self.assertTrue(material._retired)
            with self.assertRaises(wire.ProtocolError): dict(values)

    def test_typed_material_cannot_be_donated_to_store_ios_or_another_child(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            material = private.PrivateAndroidMaterial(operation.source, operation.request.context, (b"jks", b"pw", b"alias", b"pw"))
            operation.source.material = material
            operation.signing.bind_values()
            values = operation.signing.values
            _, bound = service_data.values(signature=True)
            for purpose, platforms in (("store", ("android",)), ("signing", ("ios",)), ("signing", ("android", "ios"))):
                with self.assertRaises(credentials.CredentialError):
                    credentials.credential_values_for_purpose(bound.config, values, stage="candidate", purpose=purpose, platforms=platforms)
            with self.assertRaises(wire.ProtocolError): values.for_invocation(object())
        from mobile_release._desktop_ios_signing_material import CapturedBuildValues
        # A type-only object has no payload; the wrong-domain gate must reject
        # before attempting to inspect it, enter an invocation or select files.
        foreign = object.__new__(CapturedBuildValues)
        _, bound = service_data.values(signature=True)
        with self.assertRaises(credentials.CredentialError):
            credentials.credential_values_for_purpose(bound.config, foreign, stage="candidate", purpose="signing", platforms=("android",))
        with patch.object(credentials, "invocation_custody", side_effect=AssertionError("wrong-domain invocation")):
            with self.assertRaises(credentials.CredentialError):
                with credentials.materialize_build_inputs(bound.config, values=foreign, platforms=("android",)):
                    self.fail("iOS values entered Android materialization")

    def test_required_firebase_uses_saved_module_and_original_child_without_rediscovery(self):
        _, bound = service_data.values(signature=True)
        bound.config.data["services"]["androidFirebase"] = "required"
        bound.config.data["android"]["module"] = ":feature:mobile"
        raw = json.dumps(bound.config.data, separators=(",", ":")).encode("utf-8")
        selected = replace(bound.saved.configuration, raw=raw, module=":feature:mobile")
        bound = replace(bound, saved=replace(bound.saved, configuration=selected), task=":feature:mobile:bundleRelease")
        request_data = protocol.signed_request_data(firebase=True)
        request_data["context"].update(savedConfig={"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            savedVersion={"source": selected.source, "bytes": len(bound.saved.version_raw),
                          "sha256": hashlib.sha256(bound.saved.version_raw).hexdigest(),
                          "name": bound.release.name, "build": bound.release.build})
        request_data["context"]["artifactValidation"]["uploadCertificateSha256"] = selected.upload_certificate_sha256
        canonical = json.dumps(bound.config.data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        request_data["native"]["signingContext"] = {"bytes": len(canonical), "sha256": hashlib.sha256(canonical).hexdigest()}
        request_data["native"]["projectRoot"] = str(bound.config.root)
        request = wire.parse_request(protocol.encoded(request_data))
        firebase = protocol.encoded({"project_info": {"project_id": "inert-project", "project_number": "123"},
            "client": [{"client_info": {"android_client_info": {"package_name": selected.application_id}},
                        "api_key": [{"current_key": "inert-public-key"}]}]})
        with original(request) as operation, patch.object(operation, "checkpoint"), \
             patch.object(operation, "check_inputs") as recheck:
            operation.inputs = bound
            material = private.PrivateAndroidMaterial(operation.source, operation.request.context,
                (b"inert-jks", b"store-secret", b"upload-key", b"key-secret", firebase))
            operation.source.material = material
            signing = operation.signing
            signing.bind_values()
            signing.phase = "materializing"
            invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            invocation.project_owner = SimpleNamespace(root=operation.root, guard=operation.guard)
            child = build_inputs.BuildInputs(invocation, invocation.project_owner)
            invocation.child = child
            signing.bind_materialization(child)
            scratch = child.scratch
            keystore = material._files[private.FILES["android-keystore"]]
            snapshot = build_inputs.InputSnapshot(len(keystore), hashlib.sha256(keystore).hexdigest(),
                                                 scratch, "android-keystore", object())
            # Predicate DATA only: no scratch acquire, file open, journal
            # replacement, environment reservation or native command occurs.
            scratch.active = True
            staged = []

            def replace_all(replacements):
                self.assertIs(invocation.child, child)
                self.assertIs(signing.materialization, child)
                self.assertIsNone(invocation.signing_lease)
                self.assertEqual(len(replacements), 1)
                replacement = replacements[0]
                self.assertIs(type(replacement), build_inputs.TargetReplacement)
                self.assertEqual((replacement.role, replacement.relative, replacement.content),
                    ("android-services", PurePosixPath("feature/mobile/google-services.json"), firebase))
                staged.extend(replacements)
                child.prepared = True

            def project_path(config, relative):
                self.assertIs(config, bound.config)
                self.assertIn(relative, ("feature/mobile", "feature/mobile/google-services.json"))
                return config.root / relative

            with patch.object(invocation, "require"), \
                 patch.object(scratch, "put", return_value=snapshot) as put, \
                 patch.object(scratch, "require", return_value=operation.root / ".private/inert-keystore"), \
                 patch.object(child, "replace_all", side_effect=replace_all), \
                 patch.object(type(bound.config), "project_path", new=project_path), \
                 patch.object(Path, "is_dir", return_value=True), \
                 patch.object(discovery, "discover_project", side_effect=AssertionError("ambient rediscovery")), \
                 patch.object(discovery, "selected_android_module", side_effect=AssertionError("ambient module selection")):
                with credentials.materialize_build_inputs(bound.config, values=signing.values, platforms=("android",),
                        signing_lease=None, cancellation=operation.guard, build_inputs=child) as environment:
                    self.assertIs(environment._inputs, child)
                    self.assertIs(environment._invocation, invocation)
                    self.assertTrue(environment._live)
                    self.assertEqual(environment[private.SCALARS["key-alias"]], "upload-key")
                self.assertFalse(environment._live)
                put.assert_called_once_with("android-keystore", material._files[private.FILES["android-keystore"]])
            self.assertEqual(len(staged), 1)
            recheck.assert_called_once_with()

    def test_six_roles_are_one_original_ledger_and_do_not_renew_deadline(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            roles = ("keytool-input", "gradle", "aab-sign", "bundletool", "jarsigner", "keytool")
            self.assertEqual(tuple(operation._roles), roles)
            operation.inputs = SimpleNamespace(check_signer=True)
            operation.files.signing_candidate = SimpleNamespace(_native=True, integrity_checked=True)
            ledger = operation.guard.lifetime_ledger
            for index, (role, ceiling) in enumerate(zip(roles, (30, 2700, 120, 60, 120, 30))):
                for later in roles[index + 1:]:
                    with self.assertRaises(wire.ProtocolError): operation._arm(later)
                if role == "gradle": operation.signing.input_checked = True
                if role == "bundletool": operation._artifact = object()
                if role == "keytool": operation._signature_passed = True
                operation._arm(role)
                self.assertEqual(operation.command_limits(9000, role != "gradle", 10**8), (ceiling, 2 * 1024 * 1024))
                ledger._commands, ledger._command_dispatched = index + 1, True
                operation.returned(role, 0)
                with self.assertRaises(wire.ProtocolError): operation._arm(role)
            self.assertEqual(operation.source.work_end, 3100)
            self.assertEqual(ledger.verdict().profile_calls, 0)

    def test_input_precheck_dispatch_is_not_reported_as_no_command(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            signing = operation.signing
            signing.phase = "materializing"
            operation.tools = SimpleNamespace(keystore_input_command=lambda: ("/inert/keytool", "-list"))
            with patch.object(signing, "command_environment", return_value={"INERT": "private"}), \
                 patch.object(signing, "command_inputs") as recheck, \
                 patch.object(credentials, "android_material_finding", return_value=Finding("credential-material.android", Status.INVALID, "inert")), \
                 patch.object(owned_process, "run_owned") as run:
                def dispatch(*args, **kwargs):
                    operation.command_limits(kwargs["timeout"], kwargs["capture"], kwargs["output_limit"])
                    operation.guard.lifetime_ledger._commands = 1
                    operation.guard.lifetime_ledger._command_dispatched = True
                    return SimpleNamespace(returncode=1, stdout="PRIVATE", stderr="PRIVATE")
                run.side_effect = dispatch
                operation.inputs = SimpleNamespace(config=object())
                with self.assertRaises(AndroidBuildError) as failure: signing.validate_input()
            self.assertEqual(failure.exception.reason, "signing-validation-failed")
            self.assertEqual(operation.command_outcome(), {"outcome": "unknown", "exitCode": None})
            self.assertEqual(operation.source.first_failure, 100)
            self.assertEqual(operation._roles["gradle"], "new")
            recheck.assert_not_called()  # Known failure is latched before private rehash.

    def test_nonzero_signer_latches_failure_before_private_postcheck_and_native_scope_exit(self):
        with original() as operation, patch.object(operation, "checkpoint"), patch.object(operation, "require"):
            operation.inputs = SimpleNamespace(config=object())
            operation._roles.update({"keytool-input": "returned", "gradle": "returned"})
            operation._returned.update({"keytool-input": 0, "gradle": 0})
            operation.signing.input_checked = True
            child = operation.signing.materialization = object()
            candidate = SimpleNamespace(path=Path("/inert/candidate"), _native=True, integrity_checked=True)
            operation.files.signing_candidate = candidate
            operation.tools = SimpleNamespace(aab_sign_command=lambda value: ("/inert/jarsigner",))
            ledger = operation.guard.lifetime_ledger; ledger._commands, ledger._command_dispatched = 2, True
            exited = []
            @contextmanager
            def native_input():
                try:
                    yield candidate.path
                finally:
                    exited.append(operation.source.first_failure)
            candidate.native_signing_input = native_input
            def dispatch(*args, **kwargs):
                operation.command_limits(kwargs["timeout"], kwargs["capture"], kwargs["output_limit"])
                ledger._commands = 3
                return SimpleNamespace(returncode=1, stdout="PRIVATE", stderr="PRIVATE")
            with patch.object(operation.signing, "command_environment", return_value={}), \
                 patch.object(operation.signing, "command_inputs") as recheck, \
                 patch.object(android, "run_owned", side_effect=dispatch):
                with self.assertRaises(AndroidBuildError) as failure:
                    android._canonicalize_aab_signature(candidate.path, project_root=operation.root,
                        cancellation=operation.guard, build_inputs=child, operation=operation)
            self.assertEqual(failure.exception.reason, "signing-command-failed")
            self.assertEqual(exited, [100]); recheck.assert_not_called()
            self.assertEqual(operation._roles["bundletool"], "new")

    def test_partial_child_binding_keeps_original_for_one_fallback_close(self):
        with original() as operation, patch.object(operation, "checkpoint"):
            invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            project = SimpleNamespace(root=operation.root, guard=operation.guard)
            invocation.project_owner = project
            signing = operation.signing; signing.values = object(); signing.phase = "materializing"
            with patch.object(invocation, "require"), patch.object(build_inputs.BuildInputs, "cleanup") as cleanup, \
                 patch.object(signing, "bind_materialization", side_effect=wire.ProtocolError("inert binding")):
                with self.assertRaises(wire.ProtocolError):
                    with invocation.materialization(signing_lease=None): self.fail("must not enter")
                child = signing.materialization
                self.assertIsNotNone(child)
                self.assertIs(child.scratch, signing.scratch)
                self.assertIsNone(invocation.child)
                with patch.object(signing, "inputs_closed", return_value=True): signing.close()
                cleanup.assert_called_once_with()

    def test_early_materializer_failure_is_latched_before_restoration_and_not_relabelled(self):
        for where in ("entry", "build", "restore"):
            with self.subTest(where=where), original() as operation, patch.object(operation, "checkpoint"):
                events = []
                _, bound = service_data.values(signature=True)
                signing = operation.signing
                child, materialized = object(), object()
                error = build_inputs.BuildInputError("inert failure")
                run = object.__new__(service.AndroidBuildRun)
                run.operation, run.guard, run.source = operation, operation.guard, operation.source
                run.primary = run.primary_signing_phase = None

                @contextmanager
                def child_scope(**kwargs):
                    self.assertIsNone(kwargs["signing_lease"])
                    try: yield child
                    finally:
                        events.append(("restore", operation.source.first_failure))
                        if where == "restore": raise error

                @contextmanager
                def materialize(*args, **kwargs):
                    self.assertEqual(kwargs["platforms"], ("android",))
                    self.assertIs(kwargs["build_inputs"], child)
                    self.assertIsNone(kwargs["signing_lease"])
                    if where == "entry": raise error
                    try: yield materialized
                    finally: events.append(("material-retired", operation.source.first_failure))

                operation.invocation = SimpleNamespace(signing_lease=None, materialization=child_scope)
                with patch.object(operation.source, "receive_material"), patch.object(signing, "bind_values"), \
                     patch.object(signing, "bind_materialized"), patch.object(signing, "validate_input"), \
                     patch.object(operation, "advance"), patch.object(credentials, "materialize_build_inputs", materialize), \
                     patch.object(service, "run_android_build", side_effect=error if where == "build" else None):
                    with self.assertRaises(build_inputs.BuildInputError): run._signed_body(bound)
                self.assertIs(run.primary, error)
                if where != "restore": self.assertEqual(events[-1], ("restore", 100))
                self.assertEqual(run.primary_signing_phase, {"entry": "materializing", "build": "building", "restore": "restoring-inputs"}[where])
                _, reason = run._failure({"outcome": "not-dispatched", "exitCode": None})
                self.assertEqual(reason, "build-inputs-unrestored" if where == "restore" else "project-admission-refused")


class AndroidSignedServiceTests(service_data._InertCase):
    def test_final_validation_follows_material_retirement_and_same_child_restoration(self):
        from mobile_release.android_build_signing import SignedAndroidOperation

        for result in ("success", "post-sign-corruption", "restoration-error", "unclosed-child"):
            with self.subTest(result=result):
                subject = service_data._InertRun(self, signature=True)
                operation, source = subject.operation, subject.source
                data = protocol.signed_request_data()
                for name in ("savedConfig", "savedVersion", "artifactValidation"):
                    data["context"][name] = subject.request.context[name]
                data["native"].update(projectRoot=str(operation.root), cwd="/inert/cwd")
                canonical = json.dumps(subject.bound.config.data, sort_keys=True, ensure_ascii=False,
                                       separators=(",", ":"), allow_nan=False).encode("utf-8")
                data["native"]["signingContext"] = {"bytes": len(canonical), "sha256": hashlib.sha256(canonical).hexdigest()}
                request = wire.parse_request(protocol.encoded(data))
                subject.request = subject.run.request = operation.request = request
                source.signed = True
                operation.signing = signing = SignedAndroidOperation(operation)
                operation._roles = {role: "new" for role in ("keytool-input", "gradle", "aab-sign", "bundletool", "jarsigner", "keytool")}
                signing.values = object()  # Values/binding are independently exercised above.
                invocation = subject.invocation
                child = object.__new__(build_inputs.BuildInputs)
                child.invocation, child.cancellation = invocation, subject.guard
                child.claimed = False
                signing.materialization = child
                environment = credentials._MaterializedBuildEnvironment({"INERT_PRIVATE": "not-public"}, child, None)
                restored = False
                events = subject.events

                @contextmanager
                def child_scope(*, signing_lease):
                    nonlocal restored
                    self.assertIsNone(signing_lease)
                    invocation.child = child
                    events.append("child-enter")
                    try:
                        yield child
                    finally:
                        self.assertFalse(environment._live)
                        events.append("restore-original-child")
                        child.claimed = True
                        invocation.child = None
                        restored = result not in {"restoration-error", "unclosed-child"}
                        if result == "restoration-error":
                            raise build_inputs.BuildInputError("inert restoration refusal")

                @contextmanager
                def materialize(config, *, values, platforms, signing_lease, cancellation, build_inputs):
                    self.assertIs(config, subject.bound.config)
                    self.assertIs(values, signing.values)
                    self.assertEqual(platforms, ("android",))
                    self.assertIsNone(signing_lease)
                    self.assertIs(cancellation, subject.guard)
                    self.assertIs(build_inputs, child)
                    try:
                        yield environment
                    finally:
                        environment._live = False
                        events.append("material-view-retired")

                def build(config, *, signed, cancellation, build_inputs, operation):
                    self.assertIs(config, subject.bound.config)
                    self.assertTrue(signed)
                    self.assertIs(cancellation, subject.guard)
                    self.assertIs(build_inputs, child)
                    self.assertIs(operation, subject.operation)
                    self.assertTrue(environment._live)
                    self.assertIs(signing.materialized, environment)
                    events.append("signed-build")
                    for role in ("keytool-input", "gradle", "aab-sign"):
                        operation._roles[role], operation._returned[role] = "returned", 0
                    subject.ledger._commands, subject.ledger._command_dispatched = 3, True
                    subject.disposition.update(work="retained-work", artifacts="retained-incomplete")
                    operation.advance("capturing")
                    operation.advance("signing")

                def inspect(*args, **kwargs):
                    self.assertTrue(restored and child.claimed and signing.materialized_retired)
                    self.assertIsNone(invocation.child)
                    self.assertIs(signing.materialized, environment)
                    self.assertFalse(environment._live)
                    self.assertEqual(environment, {})  # Actual facet.close retired its mapping.
                    self.assertIs(kwargs["artifact"], subject.artifact)
                    events.append("final-validator")
                    if result == "post-sign-corruption":
                        # Exercise the actual final validator's corruption
                        # policy with only its bounded integrity-reader seam
                        # returning bad post-sign DATA; never fabricate a JAR.
                        inspector = subject.inspector()
                        inspector.side_effect = service_data.AndroidZipError("content")
                        return subject.validate()
                    subject.ledger._commands = 6
                    operation.zip_metadata = subject.metadata
                    return subject.findings

                self.patched(service.sys, "platform", new="darwin")
                self.patched(source, "receive_material")
                self.patched(signing, "bind_values")
                self.patched(signing, "command_inputs", return_value=None)
                self.patched(signing, "validate_input")
                self.patched(signing, "inputs_closed", side_effect=lambda: restored)
                self.patched(invocation, "materialization", side_effect=child_scope)
                self.patched(credentials, "materialize_build_inputs", side_effect=materialize)
                subject.build_call.side_effect = build
                subject.inspect_call.side_effect = inspect
                if result == "success":
                    subject.run.run()
                    self.assertIsNotNone(subject.run._candidate)
                    self.assertIsNone(subject.run.primary)
                else:
                    with self.assertRaises((AndroidBuildError, build_inputs.BuildInputError)):
                        subject.run.run()
                    self.assertIsNone(subject.run._candidate)
                self.assertLess(events.index("material-view-retired"), events.index("restore-original-child"))
                if result in {"success", "post-sign-corruption"}:
                    self.assertLess(events.index("restore-original-child"), events.index("final-validator"))
                else:
                    self.assertNotIn("final-validator", events)
                if result == "post-sign-corruption":
                    self.assertEqual(subject.run.primary.reason, "signing-validation-failed")
                    subject.artifact.native_input.assert_not_called()
