"""Check-only wiring/policy tests, not native/key/Apple qualification.

Protocol and original-owner predicate tests are inert.  The validator cases use
real tiny private scratch files but synthetic P12/PEM/key text and fake CMS and
OpenSSL responses; no command, keychain, account, network or real key is used.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from mobile_release import _desktop_ios_archive_protocol as archive
from mobile_release import _desktop_ios_signing_reuse_protocol as wire
from mobile_release import _desktop_ios_signed_operation as signed
from mobile_release import _desktop_ios_signing_material as material
from mobile_release import _command_process as commands
from mobile_release import build_inputs, credentials, ios_profiles, local_signing, owned_process
from mobile_release import ios_signing_reuse as reuse
from mobile_release._desktop_ios_archive_control import IOSArchiveInput
from mobile_release._desktop_ios_archive_selection import select_saved_ios_configuration, bind_saved_ios_version, IOSSelectionRefused
from mobile_release.cancellation import DefaultCancellation
from mobile_release.config import ReleaseConfig
from mobile_release.desktop_ios_archive import IOSArchiveRun
from mobile_release.ios_archive_operation import IOSArchiveOperation, IOSArchiveError, BoundIOSInputs
from mobile_release.reporting import Finding, Status


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def fingerprint(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def configuration():
    return {"schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main", "projectReadTokenRequired": True},
        "android": {"enabled": False},
        "ios": {"enabled": True, "bundleId": "org.example.synthetic", "identityStatus": "unverified",
                "teamId": "SYNTH12345", "distributionCertificateSha256": "c" * 64,
                "symbols": {"policy": "required", "uploadCommand": ["synthetic-must-not-run"]}},
        "metadata": {"root": "release/store", "androidLocales": [], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def request_data(config=None):
    config = configuration() if config is None else config
    version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
    directory = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0}
    assignments = [{"kind": kind, "recordId": letter * 32, "recordRevision": 1, "contextRevision": 2}
                   for kind, letter in (("apple-p12", "d"), ("apple-profile", "e"))]
    if config["services"]["iosFirebase"] == "required":
        assignments.append({"kind": "ios-firebase", "recordId": "f" * 32, "recordRevision": 1, "contextRevision": 2})
    return {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "_synthetic-ios", "draftRevision": 1, "baselineGeneration": 2,
            "platform": "ios", "operation": wire.OPERATION, "action": wire.ACTION,
            "savedConfig": fingerprint(encode(config)),
            "savedVersion": {"source": "release/version.properties", **fingerprint(version), "name": "1.2.3", "build": 7},
            "signing": {"teamId": "SYNTH12345", "distributionCertificateSha256": config["ios"]["distributionCertificateSha256"],
                        "assignments": assignments}},
        "native": {"profile": "macos-arm64", "projectRoot": "/synthetic/project", "rootIdentity": directory,
            "cwd": "/synthetic/runtime", "signingContext": fingerprint(encode(config)),
            "openssl": {**directory, "inode": "4", "mode": stat.S_IFREG | 0o755,
                        "links": 1, "size": 1024, "mtimeNs": "100", "ctimeNs": "100"}}}


def request(config=None):
    return archive.parse_request(encode(request_data(config)) + b"\n")


def bound_inputs(operation, config=None):
    config = configuration() if config is None else config
    data, selected = select_saved_ios_configuration(encode(config), operation.request.context["savedConfig"], signing_check=True)
    saved = bind_saved_ios_version(selected, b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n", operation.request.context["savedVersion"])
    return BoundIOSInputs(ReleaseConfig(operation.root / "release/mobile-release.json", operation.root, data), saved)


@contextmanager
def inert_original(selected=None):
    """Actual Python classes without admitting any descriptor/handler/native IO."""
    selected = request() if selected is None else selected
    source, guard = IOSArchiveInput(100), DefaultCancellation(owned_process.ProcessCleanupError, "synthetic check")
    source.acquired = source.active = source.request_returned = True
    source._request_material(selected)
    guard._install_ios_archive_source(source)
    guard.depth = 0
    with patch.object(source, "poll"), patch.object(signed.time, "monotonic", return_value=100), \
            patch.object(os, "open", side_effect=AssertionError("no native open in inert owner test")), \
            patch.object(os, "close", side_effect=AssertionError("no native close in inert owner test")), \
            patch.object(commands, "run_command", side_effect=AssertionError("no native command")):
        yield IOSArchiveOperation(selected, guard, source)


def result_data(selected):
    checks = [{"check": name, "status": "PASS"} for name in sorted(wire.expected_checks(selected.context))]
    return {"schemaVersion": 1, "scope": wire.SCOPE, "checkedAt": "2026-10-20T00:00:00Z",
            "usedConfig": selected.context["savedConfig"], "usedVersion": selected.context["savedVersion"],
            "usedSigning": selected.context["signing"], "checks": checks, "limitations": list(wire.LIMITATIONS)}


def terminal_data(selected):
    result = result_data(selected)
    return {"schemaVersion": 1, "context": selected.context, "outcome": "complete", "reason": "none",
            "activity": {"stage": wire.STAGES[-1], "findings": result["checks"]},
            "disposition": {"snapshot": "not-created", "work": "not-created", "output": "not-created", "relativeDirectory": None},
            "result": result,
            "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
                         "commands": 5, "profileCalls": 1, "stopObserved": "none",
                         **{name: True for name in archive.SIGNED_CLOSE_FIELDS}}}


class SigningReuseProtocolTests(unittest.TestCase):
    def test_mode_round_trip_and_only_p12_profile_optional_required_firebase(self):
        for firebase in ("disabled", "required"):
            config = configuration(); config["services"]["iosFirebase"] = firebase
            selected = request(config)
            self.assertEqual(archive.protocol(selected.context), wire.PROTOCOL)
            self.assertEqual(archive.stages(selected.context), wire.STAGES)
            self.assertTrue(archive.is_signed(selected.context))
            self.assertFalse(archive.candidate_create(selected.context) or archive.is_recovery(selected.context))
            self.assertEqual(material.roles_for(selected.context), ("apple-p12", "p12-password", "apple-profile")
                             + (("ios-firebase",) if firebase == "required" else ()))
            archive.validate_terminal(terminal_data(selected), selected)  # DATA, not native completion.

    def test_other_modes_consents_tools_roles_and_unknown_fields_are_not_relabelled(self):
        mutations = (
            lambda v: v.update(protocol=archive.SIGNED_PROTOCOL),
            lambda v: v["context"].update(operation="ios-candidate-inputs"),
            lambda v: v["context"].update(action="create"),
            lambda v: v["context"].update(recovery={"action": "inspect"}),
            lambda v: v["context"].update(consent=archive.SIGNED_CONSENT),
            lambda v: v["native"].update(toolchain={}),
            lambda v: v["native"].update(signingTools={}),
            lambda v: v["native"]["openssl"].update(uid=501),
            lambda v: v["native"]["openssl"].update(mode=stat.S_IFREG | 0o777),
            lambda v: v["context"]["signing"]["assignments"].append(
                {"kind": "project-read-token", "recordId": "f" * 32, "recordRevision": 1, "contextRevision": 2}),
        )
        for mutation in mutations:
            data = request_data(); mutation(data)
            with self.subTest(mutation=mutation), self.assertRaises(archive.ProtocolError):
                archive.parse_request(encode(data) + b"\n")
        for key in ("signing", "action"):
            data = request_data(); del data["context"][key]
            with self.assertRaises(archive.ProtocolError): archive.parse_request(encode(data) + b"\n")

    def test_private_material_header_cannot_add_project_token(self):
        roles = material.roles_for(request().context)
        value = {"schemaVersion": 1, "files": [{"role": role, "bytes": 1} for role in roles]}
        self.assertEqual(material.parse_header(encode(value) + b"\n", roles), (1, 1, 1))
        value["files"].append({"role": "project-read-token", "bytes": 1})
        with self.assertRaises(archive.ProtocolError): material.parse_header(encode(value) + b"\n", roles)

    def test_result_cannot_claim_binding_readiness_artifacts_or_foreign_refs(self):
        selected = request()
        for mutate in (lambda v: v["result"].update(credentialReady=True),
                       lambda v: v["result"].update(scope=archive.SIGNED_SCOPE),
                       lambda v: v["result"]["usedSigning"]["assignments"][0].update(recordRevision=2),
                       lambda v: v["disposition"].update(output="retained-local-result"),
                       lambda v: v["result"].update(checkedAt="2026-02-31T00:00:00Z"),
                       lambda v: v["result"].update(checks=[])):
            value = copy.deepcopy(terminal_data(selected)); mutate(value)
            with self.assertRaises(archive.ProtocolError): archive.validate_terminal(value, selected)

    def test_counts_never_replace_individual_closure_or_stop_veto(self):
        selected = request()
        for name in archive.SIGNED_CLOSE_FIELDS:
            value = terminal_data(selected); value["lifetime"][name] = False
            with self.subTest(close=name), self.assertRaises(archive.ProtocolError): archive.validate_terminal(value, selected)
            value.update(outcome="unknown", reason="cleanup-unknown", result=None)
            archive.validate_terminal(value, selected)
        for changes in ({"commands": 4}, {"commands": 8}, {"profileCalls": 0}, {"profileCalls": 2},
                        {"commandDispatched": False}, {"stopObserved": "cancelled"}, {"fatal": True}):
            value = terminal_data(selected); value["lifetime"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(archive.ProtocolError): archive.validate_terminal(value, selected)

    def test_same_original_finite_frames_and_order(self):
        selected = request(); frames = archive.IOSArchiveFrames(selected)
        frames.response("accepted", {"schemaVersion": 1, "context": selected.context})
        for stage in wire.STAGES: frames.response("progress", {"schemaVersion": 1, "stage": stage})
        frames.response("terminal", terminal_data(selected))
        self.assertEqual(frames.frames, len(wire.STAGES) + 2)
        with self.assertRaises(archive.ProtocolError): frames.response("terminal", terminal_data(selected))
        frames = archive.IOSArchiveFrames(selected)
        frames.response("accepted", {"schemaVersion": 1, "context": selected.context})
        frames.response("progress", {"schemaVersion": 1, "stage": wire.STAGES[2]})
        with self.assertRaises(archive.ProtocolError): frames.response("progress", {"schemaVersion": 1, "stage": wire.STAGES[1]})


class SigningReuseOriginalTests(unittest.TestCase):
    def test_original_source_start_and_first_failure_clamp_without_signed_recovery_extension(self):
        selected = request(); source = IOSArchiveInput(100)
        with patch.object(signed.time, "monotonic", return_value=140): source._request_material(selected)
        self.assertEqual((source.work_end, source.cleanup_endpoint(), source.hard_endpoint()), (400, 410, 410))
        self.assertTrue(source.account_lifecycle and source.signed and source.signing_check and source.material_pending)
        with patch.object(signed.time, "monotonic", return_value=150): source.failure_observed()
        self.assertEqual((source.cleanup_endpoint(), source.hard_endpoint()), (160, 160))
        with patch.object(signed.time, "monotonic", return_value=175): source.failure_observed()
        self.assertEqual(source.first_failure, 150)
        self.assertEqual(source.hard_endpoint(), 160)

    def test_check_saved_selection_needs_no_build_container_and_preserves_old_default(self):
        raw = encode(configuration())
        with self.assertRaises(IOSSelectionRefused) as error: select_saved_ios_configuration(raw, fingerprint(raw))
        self.assertEqual(error.exception.reason, "container-required")
        data, selected = select_saved_ios_configuration(raw, fingerprint(raw), signing_check=True)
        self.assertIsNone(selected.container); self.assertIsNone(selected.scheme)
        self.assertTrue(data["source"]["projectReadTokenRequired"])
        for altered in (raw + b" ", raw.replace(b"synthetic", b"changed")):
            with self.assertRaises(IOSSelectionRefused): select_saved_ios_configuration(altered, fingerprint(raw), signing_check=True)

    def test_actual_private_binding_excludes_token_and_refuses_changed_context(self):
        with inert_original() as operation, patch.object(operation, "checkpoint"):
            operation.inputs = bound_inputs(operation)
            private = material.PrivateIOSMaterial(operation.source, operation.request.context,
                (b"synthetic-p12-not-a-key", b"synthetic-password", b"synthetic-profile-not-cms"))
            operation.source.material = private
            operation.signing.bind_values()
            self.assertEqual(dict(operation.signing.values), {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "synthetic-password"})
            self.assertNotIn("MOBILE_RELEASE_PROJECT_READ_TOKEN", operation.signing.values)
            self.assertTrue(operation.inputs.config.section("source")["projectReadTokenRequired"])
            operation.request.context["signing"]["assignments"][0]["recordRevision"] += 1
            with self.assertRaises(archive.ProtocolError): operation.signing.values.get("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD")

    def test_role_refusal_before_any_scope_or_build_install_admission(self):
        with inert_original() as operation, patch.object(operation, "checkpoint"), patch.object(operation.signing, "_scope") as scope:
            signing = operation.signing; signing.phase = "validating-signing"
            for argv, cleanup in ((["/usr/bin/security", "import"], False), (["xcodebuild", "archive"], False),
                                  (["/usr/bin/openssl", "req"], False), (["/usr/bin/openssl", "x509"], True)):
                with self.assertRaises(archive.ProtocolError): signing._admit(argv, object(), None, cleanup)
                scope.assert_not_called()
            operation._pending = "archive"
            with self.assertRaises(archive.ProtocolError): signing._admit(["/usr/bin/openssl", "x509"], object(), None, False)
            operation._pending = None
            signing.phase = "materializing-signing"
            with self.assertRaises(archive.ProtocolError): signing._admit(["/usr/bin/openssl", "pkcs12"], object(), None, False)
            signing.phase = "validating-signing"
            self.assertEqual(signing._admit(["/usr/bin/openssl", "pkey"], object(), None, False), ("credential-validation", 30))
            self.assertEqual(operation.roles, ())
            with self.assertRaises(archive.ProtocolError): operation._arm("archive")
            with self.assertRaises(archive.ProtocolError): signing.bind_session(object())
            with self.assertRaises(archive.ProtocolError): signing.bind_materialization(object())

    def test_only_validation_scratch_can_bind_and_unclosed_original_prevents_settlement(self):
        with inert_original() as operation:
            operation.signing.phase = "validating-signing"
            scratch = build_inputs.FiniteScratch("signing-validation", operation.guard, Path("/synthetic/tmp"))
            self.assertIs(operation.signing.scratches[0], scratch)
            self.assertFalse(operation.signing.inputs_closed())  # No actual originals closed.
            with self.assertRaises(archive.ProtocolError): build_inputs.FiniteScratch("build", operation.guard, Path("/synthetic/tmp"))
            with self.assertRaises(archive.ProtocolError): build_inputs.FiniteScratch("signing-validation", operation.guard, Path("/synthetic/tmp"))

    def test_early_original_worker_branch_never_enters_build_namespace_or_install(self):
        with inert_original() as operation, patch.object(operation, "checkpoint"), \
                patch.object(operation, "check_inputs") as current, \
                patch.object(operation.source, "progress"), patch.object(operation.files, "acquire_tools"), \
                patch.object(operation.files, "check_tools"), \
                patch.object(operation, "prepare", side_effect=AssertionError("no archive prepare")), \
                patch.object(operation.files, "acquire_namespace", side_effect=AssertionError("no namespace")), \
                patch.object(credentials, "materialize_build_inputs", side_effect=AssertionError("no install")):
            operation.inputs = bound_inputs(operation)
            operation.source.material = material.PrivateIOSMaterial(operation.source, operation.request.context,
                (b"synthetic-p12", b"synthetic-password", b"synthetic-profile"))
            source = object(); operation.signing.lease = Mock(active=None)
            operation.signing.lease.execution_source.return_value = source
            run = object.__new__(IOSArchiveRun)
            run.operation, run.source, run.guard, run.request = operation, operation.source, operation.guard, operation.request
            run._candidate = run._candidate_inputs = run._local_handoff = None
            rows = [Finding(code, Status.PASS, "synthetic private detail", category="credentials") for code in
                    ("credential-material.apple-p12", "credential-material.apple-profile")]
            with patch.object(credentials, "validate_signing_material", return_value=rows) as validator:
                run._build_bound(operation.inputs)
                self.assertIs(validator.call_args.kwargs["values"], operation.signing.values)
                self.assertIs(validator.call_args.kwargs["execution_source"], source)
                self.assertIs(validator.call_args.kwargs["cancellation"], operation.guard)
                self.assertEqual(validator.call_args.kwargs["platforms"], ("ios",))
            self.assertGreaterEqual(current.call_count, 2)
            self.assertEqual(operation.stage, "checking-inputs")
            self.assertIsNone(operation.files.namespace); self.assertIsNone(operation.files.work)
            self.assertIsNone(operation.signing.session); self.assertIsNone(operation.signing.materialization)
            self.assertNotIn("synthetic private detail", encode(run._candidate).decode())
            self.assertEqual(run._candidate["scope"], wire.SCOPE)  # Inert DATA, not a native terminal.


class SigningReuseValidatorTests(unittest.TestCase):
    def invoke(self, defect=None, *, legacy=False):
        """Real validator+scratch, fake CMS/OpenSSL.  No native finality asserted."""
        der = b"obvious synthetic DER fixture, not a real certificate"
        pem = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----\n"
        config_data = configuration()
        config_data["ios"]["distributionCertificateSha256"] = hashlib.sha256(der).hexdigest()
        payload = {"CreationDate": datetime(2020, 1, 1, tzinfo=timezone.utc),
            "ExpirationDate": datetime(2099, 1, 1, tzinfo=timezone.utc), "TeamIdentifier": ["SYNTH12345"],
            "DeveloperCertificates": [der], "Entitlements": {"application-identifier": "SYNTH12345.org.example.synthetic",
                "get-task-allow": False, "beta-reports-active": True}}
        if defect == "profile-team": payload["TeamIdentifier"] = ["OTHER12345"]
        if defect == "profile-bundle": payload["Entitlements"]["application-identifier"] = "SYNTH12345.org.example.other"
        if defect == "profile-leaf": payload["DeveloperCertificates"] = [b"different synthetic leaf"]
        if defect == "profile-expired": payload["ExpirationDate"] = datetime(2021, 1, 1, tzinfo=timezone.utc)
        calls, paths = [], set()
        execution = object()
        def fake_openssl(argv, *, environ, execution_source, cancellation):
            calls.append(tuple(argv)); self.assertIs(execution_source, execution)
            self.assertIsNotNone(cancellation)
            self.assertEqual(argv[0], "openssl")
            if "-in" in argv:
                path = Path(argv[argv.index("-in") + 1]); paths.add(path)
                self.assertTrue(path.is_file()); self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            if defect == "interrupted": raise KeyboardInterrupt("synthetic first interruption")
            if argv[1] == "pkcs12":
                if defect == "password" or legacy and "-legacy" not in argv:
                    return subprocess.CompletedProcess(argv, 1, "", "synthetic denied password")
                return subprocess.CompletedProcess(argv, 0, pem if "-clcerts" in argv else "SYNTHETIC PRIVATE KEY NOT USABLE", "")
            if argv[1] == "x509" and "-checkend" in argv:
                fp = "d" * 64 if defect == "fingerprint" else config_data["ios"]["distributionCertificateSha256"]
                team = "OTHER12345" if defect == "certificate-team" else "SYNTH12345"
                end = "Jan  1 00:00:00 2021 GMT" if defect == "certificate-expired" else "Jan  1 00:00:00 2099 GMT"
                purpose = "not a signing purpose" if defect == "purpose" else "Code Signing"
                output = (f"sha256 Fingerprint={fp}\nsubject=OU = {team}, CN = Apple Distribution: Synthetic\n"
                          f"notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter={end}\n{purpose}\n")
                return subprocess.CompletedProcess(argv, 0, output, "")
            return subprocess.CompletedProcess(argv, 0, "OTHER PUBLIC KEY" if defect == "key" and argv[1] == "pkey" else "SYNTHETIC MATCHING PUBLIC KEY", "")
        with tempfile.TemporaryDirectory(prefix="mrk-ios-signing-reuse-") as temp:
            root = Path(temp); config = ReleaseConfig(root / "release/mobile-release.json", root, config_data)
            values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(b"synthetic not a P12").decode(),
                      "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(b"synthetic not CMS").decode(),
                      "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "synthetic-private-password"}
            with patch.dict(os.environ, {"TMPDIR": temp}), \
                    patch.object(credentials, "_run_private", side_effect=fake_openssl), \
                    patch.object(ios_profiles, "load_authenticated_profile", return_value=payload), \
                    patch.object(credentials, "consume_profile_evidence"), \
                    patch.object(credentials, "materialize_build_inputs", side_effect=AssertionError("no build inputs")), \
                    patch.object(local_signing, "SigningSession", side_effect=AssertionError("no Keychain session")):
                if defect == "interrupted":
                    with self.assertRaises(KeyboardInterrupt): credentials.validate_signing_material(config, values=values,
                        platforms=("ios",), execution_source=execution)
                    rows = None
                else:
                    rows = credentials.validate_signing_material(config, values=values, platforms=("ios",), execution_source=execution)
            self.assertTrue(all(not path.exists() for path in paths))
            self.assertEqual(list(root.iterdir()), [])  # Actual finite private scratch originals closed/removed.
        return rows, calls

    def test_existing_validator_checks_synthetic_key_profile_and_removes_real_private_scratch(self):
        rows, calls = self.invoke()
        self.assertEqual(reuse.public_findings(rows), [{"check": "signing-material", "status": "PASS"},
                                                     {"check": "profile-material", "status": "PASS"}])
        self.assertEqual(len(calls), 5)

    def test_known_failed_legacy_extracts_remain_within_fixed_seven_call_roster(self):
        rows, calls = self.invoke(legacy=True)
        self.assertTrue(all(row.status is Status.PASS for row in rows))
        self.assertEqual(len(calls), wire.COMMAND_LIMIT)
        self.assertEqual(sum("-legacy" in call for call in calls), 2)

    def test_password_key_fingerprint_team_purpose_profile_and_expiry_refuse_reuse(self):
        for defect in ("password", "key", "fingerprint", "certificate-team", "purpose", "certificate-expired",
                       "profile-team", "profile-bundle", "profile-leaf", "profile-expired"):
            with self.subTest(defect=defect):
                rows, calls = self.invoke(defect)
                self.assertTrue(any(row.status is not Status.PASS for row in rows))
                self.assertLessEqual(len(calls), wire.COMMAND_LIMIT)

    def test_first_interruption_never_retries_or_enters_build_and_scratch_closes(self):
        rows, calls = self.invoke("interrupted")
        self.assertIsNone(rows); self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
