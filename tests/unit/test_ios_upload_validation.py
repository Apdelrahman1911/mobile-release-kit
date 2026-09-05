from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.credentials import artifact_validation_environment
from mobile_release.errors import MobileReleaseError, ValidationError
from mobile_release.ios import SigningValidityInterval, validate_ipa_current_signing
from mobile_release.inspection import MAX_INSPECTION_SECONDS
from mobile_release.ios_upload_validation import main, validate_current_upload
from mobile_release.provenance import seal, sha256_file
from mobile_release.reporting import Finding, Status

from .evidence_helpers import build_lifecycle
from .helpers import ios_config, write_project
from .ios_entitlement_helpers import (
    NativeProfileSeam, add_discardable_root_dictionary, binary_dictionary, modernize_ipa_fixture,
    rewrite_zip_members, signed_entitlements,
)


class IosCurrentUploadTests(unittest.TestCase):
    """Exercise actual input bindings; native signature seams are synthetic.

    These tests do not claim an Apple signature or Store validation. Ruby tests
    independently launch the fixed isolated interpreter and run actual lanes.
    """

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="mrk-current-upload-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = load_config(write_project(self.root, ios_config(), platform="ios"))
        self.docs = build_lifecycle(self.config, platform="ios")
        self.intent = self.docs["candidate_intent"]
        self.intent_path = self.root / "candidate-operation-intent.json"
        self.intent_path.write_text(json.dumps(self.intent), encoding="utf-8")
        self.ipa = self.root / "app.ipa"
        self.now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        self.interval = SigningValidityInterval(
            self.now - timedelta(hours=1), self.now + timedelta(hours=1)
        )
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("mobile_release.ios._utc_now", return_value=self.now))
        self.native = stack.enter_context(
            patch("mobile_release.ios_upload_validation.validate_ipa_current_signing", return_value=([], self.interval))
        )
        self.signer = stack.enter_context(
            patch("mobile_release.ios_upload_validation.ipa_signing_evidence", return_value=self.docs["signing"])
        )

    def validate(self, **overrides):
        arguments = {
            "app_root": self.root,
            "config_path": self.config.path,
            "intent_path": self.intent_path,
            "ipa_path": self.ipa,
            "intent_sha256": self.intent["integrity"]["sha256"],
        }
        return validate_current_upload(**{**arguments, **overrides})

    def test_current_gate_uses_approved_identity_and_exact_original_ipa(self) -> None:
        result = self.validate()
        self.assertEqual(result, {
            "documentType": "ios-current-upload-validation",
            "schemaVersion": 1,
            "operationIntentSha256": self.intent["integrity"]["sha256"],
            "ipaSha256": sha256_file(self.ipa),
            "ipaSize": self.ipa.stat().st_size,
            "notBefore": "2026-09-05T11:00:00Z",
            "notAfter": "2026-09-05T13:00:00Z",
        })
        inspected = self.native.call_args.args[0]
        deadline = self.native.call_args.kwargs["deadline"]
        self.assertNotEqual(inspected, self.ipa)
        self.assertEqual(inspected.name, self.ipa.name)
        self.assertFalse(inspected.exists(), "private snapshot must be cleaned")
        self.native.assert_called_once_with(
            inspected, expected_bundle_id="com.example.reader",
            expected_team_id="ABCDE12345", expected_fingerprint="b" * 64,
            release=self.config.release_version(), require_tools=True,
            deadline=deadline,
        )
        self.signer.assert_called_once_with(inspected, deadline=deadline)

    def test_real_current_entitlement_failure_cannot_authorize_a_new_upload(self) -> None:
        modernize_ipa_fixture(self.ipa)
        payload = {key: value for key, value in self.intent.items() if key != "integrity"}
        record = next(item for item in payload["artifacts"] if item["logicalName"] == "ios-ipa")
        record.update(sha256=sha256_file(self.ipa), size=self.ipa.stat().st_size)
        self.intent = seal(payload)
        self.intent_path.write_text(json.dumps(self.intent))
        self.native.side_effect = validate_ipa_current_signing
        native = NativeProfileSeam()
        native.claims["Reader.app"] = {**signed_entitlements(), "com.apple.developer.associated-domains": ["applinks:fictional.example"]}
        with patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/fictional/tool"), patch("mobile_release.ios.subprocess.run", side_effect=native):
            with self.assertRaisesRegex(ValidationError, "new IPA upload is ineligible.*not authorized"):
                self.validate()
        self.signer.assert_not_called()
        self.assertTrue(any("--entitlements" in argv for argv, _ in native.calls))
        self.assertFalse(any("--extract-certificates" in argv for argv, _ in native.calls))

    def test_malformed_primary_plist_stops_current_upload_before_native_inspection(self) -> None:
        with zipfile.ZipFile(self.ipa) as archive:
            original = archive.read("Payload/Reader.app/Info.plist")
        self.assertEqual(original.count(b"</dict>"), 1)
        for malformed in (add_discardable_root_dictionary(original), original.replace(
                b"</dict>", b"<key>ReviewProbe</key><data>Y&#81;==</data></dict>"),
                binary_dictionary(b"\x5f\x00\x01A")):
            rewrite_zip_members(self.ipa, {"Payload/Reader.app/Info.plist": malformed})
            payload = {key: value for key, value in self.intent.items() if key != "integrity"}
            record = next(item for item in payload["artifacts"] if item["logicalName"] == "ios-ipa")
            record.update(sha256=sha256_file(self.ipa), size=self.ipa.stat().st_size)
            self.intent = seal(payload)
            self.intent_path.write_text(json.dumps(self.intent))
            self.native.side_effect = validate_ipa_current_signing
            with patch("mobile_release.ios._run_native", side_effect=AssertionError("must fail before native inspection")):
                with self.assertRaisesRegex(ValidationError, "new IPA upload is ineligible.*plist"):
                    self.validate()
            self.signer.assert_not_called()

    def test_no_authenticated_historical_intent_can_replace_current_signing_eligibility(self) -> None:
        for status in (Status.FAIL, Status.BLOCKED, Status.SKIP):
            self.native.return_value = ([Finding("native", status, "native validation unavailable")], None)
            with self.subTest(status=status), self.assertRaisesRegex(ValidationError, "ineligible"):
                self.validate()
        self.signer.assert_not_called()
        for interval in (
            None,
            SigningValidityInterval(self.now - timedelta(days=1), self.now),
            SigningValidityInterval(self.now + timedelta(seconds=1), self.now + timedelta(hours=1)),
        ):
            self.native.return_value = ([], interval)
            with self.subTest(interval=interval), self.assertRaises(ValidationError):
                self.validate()

    def test_intent_digest_stage_or_version_tampering_fails_before_native_validation(self) -> None:
        for digest in ("b" * 64, "A" * 64, "a" * 63, "a" * 64 + "\n"):
            with self.subTest(digest=digest), self.assertRaises(ValidationError):
                self.validate(intent_sha256=digest)
        original = self.intent_path.read_bytes()
        for document in (
            {**self.intent, "createdAt": "2026-01-02T00:00:00Z"},
            self.docs["external_intent"], self.docs["production_intent"],
        ):
            self.intent_path.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(stage=document["stage"]), self.assertRaises(ValidationError):
                self.validate(intent_sha256=document["integrity"]["sha256"])
        self.intent_path.write_bytes(original)
        version_path = self.config.project_path(self.config.section("version")["source"])
        version_path.write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "version"):
            self.validate()
        self.native.assert_not_called()

    def test_changed_configuration_and_identity_do_not_reach_native_inspection(self) -> None:
        original = self.config.path.read_bytes()
        for change in ({"bundleId": "com.example.other"}, {"teamId": "OTHER12345"}, {"identityStatus": "blocked"}):
            value = json.loads(original)
            value["ios"].update(change)
            self.config.path.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(change=change), self.assertRaises(MobileReleaseError):
                self.validate()
        self.config.path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValidationError, "configuration differs"):
            self.validate()
        self.native.assert_not_called()

    def test_mismatched_signer_or_profile_never_authorizes_upload(self) -> None:
        for field, value in (
            ("certificateSha256", "c" * 64), ("teamId", "OTHER12345"),
            ("profileUuid", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
            ("profileExpiresAt", "2028-01-01T00:00:00Z"),
        ):
            self.signer.return_value = {**self.docs["signing"], field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, "signer/profile"):
                self.validate()

    def test_changed_or_renamed_exact_ipa_is_rejected_before_native_validation(self) -> None:
        other = self.root / "different.ipa"
        other.write_bytes(self.ipa.read_bytes())
        with self.assertRaisesRegex(ValidationError, "exact artifact"):
            self.validate(ipa_path=other)
        self.ipa.write_bytes(b"x" * self.ipa.stat().st_size)
        with self.assertRaisesRegex(ValidationError, "exact artifact"):
            self.validate()
        self.native.assert_not_called()

    def test_artifact_change_during_native_or_identity_checks_fails_closed(self) -> None:
        original = self.ipa.read_bytes()
        for boundary in ("native", "identity"):
            self.ipa.write_bytes(original)
            def change_during_validation(*_args, **_kwargs):
                self.ipa.write_bytes(b"x" * len(original))
                return ([], self.interval) if boundary == "native" else self.docs["signing"]
            seam = self.native if boundary == "native" else self.signer
            seam.side_effect = change_during_validation
            with self.subTest(boundary=boundary), self.assertRaisesRegex(ValidationError, "changed after snapshotting"):
                self.validate()
            seam.side_effect = None

    def test_current_upload_native_gate_never_inspects_an_aba_replacement(self):
        original = self.ipa.read_bytes()
        observed = []

        def native(path, **_kwargs):
            self.ipa.write_bytes(b"temporarily substituted B")
            try:
                observed.append(path.read_bytes())
                return [], self.interval
            finally:
                self.ipa.write_bytes(original)

        self.native.side_effect = native
        result = self.validate()
        self.assertEqual(observed, [original])
        self.assertEqual(result["ipaSha256"], sha256_file(self.ipa))

    def test_deadline_expiry_in_native_or_evidence_work_never_authorizes_new_send(self):
        original = self.ipa.read_bytes()
        for phase in ("native", "evidence"):
            self.native.reset_mock()
            self.signer.reset_mock()
            private_inputs = []
            with self.subTest(phase=phase), patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
                def expire(path, *, deadline, **_kwargs):
                    private_inputs.append(path)
                    deadline.check()
                    clock.return_value = MAX_INSPECTION_SECONDS
                    return ([], self.interval) if phase == "native" else self.docs["signing"]

                seam = self.native if phase == "native" else self.signer
                seam.side_effect = expire
                try:
                    with self.assertRaisesRegex(ValidationError, "shared time bound"):
                        self.validate()
                finally:
                    seam.side_effect = None
                if phase == "native":
                    self.signer.assert_not_called()
                else:
                    self.assertIs(self.native.call_args.kwargs["deadline"], self.signer.call_args.kwargs["deadline"])
            self.assertEqual(len(private_inputs), 1)
            self.assertFalse(private_inputs[0].exists())
            self.assertEqual(self.ipa.read_bytes(), original)

    def test_outside_relative_or_symlink_inputs_cannot_reach_native_tools(self) -> None:
        link = self.root / "alias.ipa"
        link.symlink_to(self.ipa)
        app_link = self.root / "app-link"
        app_link.symlink_to(self.root, target_is_directory=True)
        with tempfile.TemporaryDirectory(prefix="mrk-other-input-") as temporary:
            outside = Path(temporary).resolve() / "app.ipa"
            outside.write_bytes(self.ipa.read_bytes())
            for override in (
                {"app_root": Path(".")}, {"app_root": app_link},
                {"ipa_path": Path("app.ipa")}, {"ipa_path": outside}, {"ipa_path": link},
                {"intent_path": self.root / "missing-intent.json"},
            ):
                with self.subTest(override=override), self.assertRaises(MobileReleaseError):
                    self.validate(**override)
        self.native.assert_not_called()

    def test_main_scrubs_capabilities_again_and_never_prints_native_failure_output(self) -> None:
        argv = [
            "--app-root", str(self.root), "--config-path", str(self.config.path),
            "--operation-intent", str(self.intent_path), "--ipa", str(self.ipa),
            "--intent-sha256", self.intent["integrity"]["sha256"],
        ]
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(self.root),
            **{key: "fictional-sensitive-value" for key in (
                "GH_TOKEN", "GITHUB_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
                "MOBILE_RELEASE_IOS_CERTIFICATE_P12_BASE64", "PYTHONPATH",
            )},
        }
        observed = {}
        def fail_native(*_args, **_kwargs):
            observed.update(os.environ)
            raise subprocess.CalledProcessError(1, "synthetic-native-tool", "fictional-private-profile", "fictional-sensitive-value")
        self.native.side_effect = fail_native
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment, clear=True), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(argv), 1)
        self.assertEqual(observed, artifact_validation_environment(environment))
        self.assertEqual(out.getvalue(), "")
        self.assertIn("no upload is authorized", err.getvalue())
        self.assertNotIn("fictional", err.getvalue())


if __name__ == "__main__":
    unittest.main()
