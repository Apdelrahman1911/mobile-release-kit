from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mobile_release.android import _bundletool_manifest
from mobile_release.android_upload_validation import main, validate_current_upload
from mobile_release.config import load_config
from mobile_release.credentials import artifact_validation_environment
from mobile_release.errors import MobileReleaseError, ValidationError
from mobile_release.provenance import seal, sha256_file, verify_sealed
from mobile_release.reporting import Finding, Status

from .evidence_helpers import build_lifecycle
from .helpers import android_config, write_project


def jarsigner_output(*, warning: str = "") -> str:
    """OpenJDK21 diagnostic fixture; these ZIPs are NOT cryptographically signed."""
    return (
        "jar verified, with signer errors.\n\nError:\n"
        "This jar contains entries whose certificate chain is invalid. Reason: "
        "PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: "
        "unable to find valid certification path to requested target\n"
        "This jar contains entries whose signer certificate is self-signed.\n\nWarning:\n"
        + warning
        + "This jar contains signatures that do not include a timestamp. Without a timestamp, "
        "users may not be able to validate this jar after any of the signer certificates expire "
        "(as early as 2027-04-01).\n\nRe-run with the -verbose and -certs options for more details.\n"
    )


class AndroidCurrentUploadTests(unittest.TestCase):
    """Real input/ZIP/JDK-output policy with explicit native-command seams."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="mrk-aab-upload-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = load_config(write_project(self.root, android_config()))
        self.docs = build_lifecycle(self.config)
        self.aab = self.root / "app.aab"
        with zipfile.ZipFile(self.aab, "a") as archive:
            archive.writestr("base/manifest/AndroidManifest.xml", b"synthetic native seam")
            archive.writestr("base/dex/classes.dex", b"non-executable fixture")
            archive.writestr("BundleConfig.pb", b"synthetic native seam")
        payload = verify_sealed(self.docs["candidate_intent"])
        record = next(item for item in payload["artifacts"] if item["logicalName"] == "android-aab")
        record.update(size=self.aab.stat().st_size, sha256=sha256_file(self.aab))
        self.intent = seal(payload)
        self.intent_path = self.root / "intent.json"
        self.intent_path.write_text(json.dumps(self.intent))
        self.warning = ""
        self.fingerprint = "AA"
        self.missing_tool = None
        self.native_calls = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.manifest = self.stack.enter_context(patch(
            "mobile_release.android._bundletool_manifest",
            return_value='<manifest package="com.example.reader" android:versionCode="42" android:versionName="1.2.3" />',
        ))
        self.native = self.stack.enter_context(patch("mobile_release.android.subprocess.run", side_effect=self.native_command))

    def native_command(self, argv, **kwargs):
        self.native_calls.append((list(argv), kwargs))
        if argv[0] == self.missing_tool:
            raise FileNotFoundError("synthetic unavailable tool")
        if argv[0] == "jarsigner":
            self.assertEqual(argv, ["jarsigner", "-verify", "-strict", str(self.aab)])
            return subprocess.CompletedProcess(argv, 4, jarsigner_output(warning=self.warning), "")
        if argv[0] == "keytool":
            self.assertEqual(argv, ["keytool", "-printcert", "-jarfile", str(self.aab)])
            return subprocess.CompletedProcess(argv, 0, "Signer #1:\n\nCertificate #1:\nSHA256: " + ":".join([self.fingerprint] * 32) + "\n", "")
        raise AssertionError(f"unexpected native invocation: {argv[0]}")

    def validate(self, **overrides):
        return validate_current_upload(**{
            "app_root": self.root, "config_path": self.config.path,
            "intent_path": self.intent_path, "aab_path": self.aab,
            "intent_sha256": self.intent["integrity"]["sha256"], **overrides,
        })

    def test_exact_artifact_requires_all_current_native_gates(self) -> None:
        result = self.validate()
        self.assertEqual(result, {
            "documentType": "android-current-upload-validation", "schemaVersion": 1,
            "operationIntentSha256": self.intent["integrity"]["sha256"],
            "aabSha256": sha256_file(self.aab), "aabSize": self.aab.stat().st_size,
        })
        self.manifest.assert_called_once_with(self.aab)
        self.assertEqual([argv[0] for argv, _ in self.native_calls], ["jarsigner", "keytool"])
        for _, kwargs in self.native_calls:
            self.assertEqual(kwargs["env"], artifact_validation_environment(os.environ))

    def test_current_warning_expiry_wrong_signer_and_missing_tools_never_allow_new_upload(self) -> None:
        for warning in (
            "This jar contains entries whose signer certificate will expire within six months. \n",
            "This jar contains entries whose signer certificate has expired.\n",
            "This jar contains entries whose signer certificate is not yet valid.\n",
        ):
            self.warning = warning
            with self.subTest(warning=warning), self.assertRaisesRegex(ValidationError, "ineligible"):
                self.validate()
        self.warning = ""
        self.fingerprint = "BB"
        with self.assertRaisesRegex(ValidationError, "ineligible"):
            self.validate()
        self.fingerprint = "AA"
        for tool in ("jarsigner", "keytool"):
            self.missing_tool = tool
            with self.subTest(tool=tool), self.assertRaisesRegex(ValidationError, "ineligible"):
                self.validate()
        self.missing_tool = None
        self.manifest.return_value = None
        with self.assertRaisesRegex(ValidationError, "ineligible"):
            self.validate()

    def test_actual_bundletool_missing_or_wrong_pin_is_rejected_without_java(self) -> None:
        self.manifest.side_effect = _bundletool_manifest
        bad_jar = self.root / "bundletool-all-1.18.3.jar"
        bad_jar.write_bytes(b"not the reviewed bundletool")
        for jar in (None, str(self.root / "missing.jar"), str(bad_jar)):
            environment = {} if jar is None else {"MOBILE_RELEASE_BUNDLETOOL_JAR": jar}
            with self.subTest(jar=jar), patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(ValidationError, "ineligible"):
                self.validate()
        self.assertNotIn("java", [argv[0] for argv, _ in self.native_calls])

    def test_fail_skip_or_incomplete_native_result_cannot_be_reused_as_a_pass(self) -> None:
        for result in ([], [Finding("android.aab.structure", Status.PASS, "partial")], *[
            [Finding("native", status, "not eligible")] for status in (Status.SKIP, Status.FAIL, Status.BLOCKED)
        ]):
            with patch("mobile_release.android_upload_validation.validate_aab", return_value=result), self.subTest(result=result), self.assertRaisesRegex(ValidationError, "ineligible"):
                self.validate()

    def test_intent_digest_platform_stage_version_config_and_public_signer_bindings(self) -> None:
        for digest in ("b" * 64, "a" * 63, "A" * 64, "a" * 64 + "\n"):
            with self.subTest(digest=digest), self.assertRaises(ValidationError):
                self.validate(intent_sha256=digest)
        original = self.intent_path.read_bytes()
        for document in (self.docs["external_intent"], self.docs["production_intent"], {**self.intent, "createdAt": "2026-01-02T00:00:00Z"}):
            self.intent_path.write_text(json.dumps(document))
            with self.subTest(stage=document["stage"]), self.assertRaises(ValidationError):
                self.validate(intent_sha256=document["integrity"]["sha256"])
        changed = verify_sealed(self.intent)
        changed["signing"][0]["certificateSha256"] = "b" * 64
        document = seal(changed)
        self.intent_path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValidationError, "signer differs"):
            self.validate(intent_sha256=document["integrity"]["sha256"])
        self.intent_path.write_bytes(original)
        config_bytes = self.config.path.read_bytes()
        for override in ({"applicationId": "com.example.other"}, {"uploadCertificateSha256": "b" * 64}, {"identityStatus": "blocked"}):
            value = json.loads(config_bytes)
            value["android"].update(override)
            self.config.path.write_text(json.dumps(value))
            with self.subTest(override=override), self.assertRaises(MobileReleaseError):
                self.validate()
        self.config.path.write_bytes(config_bytes + b"\n")
        with self.assertRaisesRegex(ValidationError, "configuration differs"):
            self.validate()
        self.config.path.write_bytes(config_bytes)
        self.config.project_path(self.config.section("version")["source"]).write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
        with self.assertRaisesRegex(ValidationError, "version differs"):
            self.validate()
        self.manifest.assert_not_called()
        self.assertEqual(self.native_calls, [])

    def test_renamed_changed_relative_outside_or_symlink_inputs_fail_before_native_checks(self) -> None:
        other = self.root / "different.aab"
        other.write_bytes(self.aab.read_bytes())
        link = self.root / "link.aab"
        link.symlink_to(self.aab)
        root_link = self.root / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve() / "app.aab"
            outside.write_bytes(self.aab.read_bytes())
            for override in ({"aab_path": other}, {"aab_path": link}, {"aab_path": outside}, {"aab_path": Path("app.aab")}, {"app_root": root_link}, {"app_root": Path(".")}):
                with self.subTest(override=override), self.assertRaises(MobileReleaseError):
                    self.validate(**override)
        self.aab.write_bytes(b"x" * self.aab.stat().st_size)
        with self.assertRaisesRegex(ValidationError, "exact artifact"):
            self.validate()
        self.manifest.assert_not_called()

    def test_byte_or_path_substitution_during_native_validation_is_rejected(self) -> None:
        original = self.aab.read_bytes()
        for change in ("bytes", "symlink"):
            self.aab.unlink()
            self.aab.write_bytes(original)
            def mutate(*args, **kwargs):
                if change == "bytes":
                    self.aab.write_bytes(b"x" * len(original))
                else:
                    other = self.root / "copy.aab"
                    other.write_bytes(original)
                    self.aab.unlink()
                    self.aab.symlink_to(other)
                return [Finding(f"android.aab.{name}", Status.PASS, "synthetic complete result") for name in ("structure", "manifest", "signature", "signer")]
            with patch("mobile_release.android_upload_validation.validate_aab", side_effect=mutate), self.subTest(change=change), self.assertRaises(MobileReleaseError):
                self.validate()

    def test_main_scrubs_runtime_authority_and_reports_native_failure_without_output(self) -> None:
        argv = ["--app-root", str(self.root), "--config-path", str(self.config.path), "--operation-intent", str(self.intent_path), "--aab", str(self.aab), "--intent-sha256", self.intent["integrity"]["sha256"]]
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "JAVA_HOME": "/public/jdk", "MOBILE_RELEASE_BUNDLETOOL_JAR": "/public/pinned.jar"}
        for name in ("GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", "PYTHONPATH", "PYTHONHOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
            environment[name] = "synthetic-private-value"
        seen = {}
        def fail_native(*args, **kwargs):
            seen.update(os.environ)
            raise subprocess.CalledProcessError(1, "native", "synthetic-private-output", "synthetic-private-value")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment, clear=True), patch("mobile_release.android_upload_validation.validate_aab", side_effect=fail_native), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(argv), 1)
        expected = artifact_validation_environment(environment)
        expected["MOBILE_RELEASE_BUNDLETOOL_JAR"] = "/public/pinned.jar"
        self.assertEqual(seen, expected)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("no upload is authorized", stderr.getvalue())
        self.assertNotIn("synthetic-private", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
