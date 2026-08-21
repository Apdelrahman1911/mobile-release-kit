from __future__ import annotations

import hashlib
import sys
import tempfile
import types
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.ios import (
    _nested_codesign_identities,
    _validate_nested_bundle_security,
    ipa_signing_evidence,
    validate_ipa,
)
from mobile_release.reporting import FAILING_STATUSES


class IosArtifactTests(unittest.TestCase):
    @staticmethod
    def _ipa(path: Path) -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Reader.app/Info.plist", b"test-plist")
            archive.writestr("Payload/Reader.app/Reader", b"executable")
            archive.writestr("Payload/Reader.app/_CodeSignature/CodeResources", b"signature")
            archive.writestr("Payload/Reader.app/embedded.mobileprovision", b"profile")

    @staticmethod
    def _profile(certificate: bytes, *, beta: bool = True) -> dict[str, object]:
        return {
            "Entitlements": {
                "application-identifier": "ABCDE12345.com.example.reader",
                "get-task-allow": False,
                "beta-reports-active": beta,
            },
            "TeamIdentifier": ["ABCDE12345"],
            "ExpirationDate": datetime(2099, 1, 1, tzinfo=timezone.utc),
            "DeveloperCertificates": [certificate],
            "UUID": "12345678-1234-1234-1234-1234567890AB",
        }

    @staticmethod
    def _signed_entitlements(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "application-identifier": "ABCDE12345.com.example.reader",
            "com.apple.developer.team-identifier": "ABCDE12345",
            "get-task-allow": False,
        }
        value.update(overrides)
        return value

    @staticmethod
    def _plist_module() -> types.ModuleType:
        module = types.ModuleType("plistlib")
        module.InvalidFileException = ValueError
        module.loads = lambda _value: {
            "CFBundleIdentifier": "com.example.reader",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "CFBundleExecutable": "Reader",
        }
        return module

    def test_final_ipa_requires_beta_profile_and_actual_signer_membership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "Reader.ipa"
            self._ipa(ipa)
            signer_certificate = b"actual signer certificate"
            signer = hashlib.sha256(signer_certificate).hexdigest()
            common = {
                "expected_bundle_id": "com.example.reader",
                "expected_team_id": "ABCDE12345",
                "expected_fingerprint": signer,
                "release": ReleaseVersion("1.2.3", 42),
                "require_tools": True,
            }
            with patch.dict(sys.modules, {"plistlib": self._plist_module()}), patch(
                "mobile_release.ios._profile_details",
                return_value=self._profile(signer_certificate, beta=False),
            ), patch(
                "mobile_release.ios._codesign_entitlements",
                return_value=self._signed_entitlements(),
            ), patch("mobile_release.ios._codesign_fingerprint", return_value=signer), patch(
                "mobile_release.ios._nested_codesign_identities", return_value=[]
            ):
                findings = validate_ipa(ipa, **common)
            self.assertTrue(any("TestFlight" in item.message for item in findings))

            with patch.dict(sys.modules, {"plistlib": self._plist_module()}), patch(
                "mobile_release.ios._profile_details",
                return_value=self._profile(b"different authorized certificate"),
            ), patch(
                "mobile_release.ios._codesign_entitlements",
                return_value=self._signed_entitlements(),
            ), patch("mobile_release.ios._codesign_fingerprint", return_value=signer), patch(
                "mobile_release.ios._nested_codesign_identities", return_value=[]
            ):
                findings = validate_ipa(ipa, **common)
            self.assertTrue(any("not authorized" in item.message for item in findings))

            with patch.dict(sys.modules, {"plistlib": self._plist_module()}), patch(
                "mobile_release.ios._profile_details",
                return_value=self._profile(signer_certificate),
            ), patch(
                "mobile_release.ios._codesign_entitlements",
                return_value=self._signed_entitlements(),
            ), patch("mobile_release.ios._codesign_fingerprint", return_value=signer), patch(
                "mobile_release.ios._nested_codesign_identities", return_value=[]
            ):
                findings = validate_ipa(ipa, **common)
            self.assertFalse(any(item.status in FAILING_STATUSES for item in findings))

    def test_signing_evidence_uses_actual_app_signer_not_first_profile_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "Reader.ipa"
            self._ipa(ipa)
            signer_certificate = b"actual signer certificate"
            signer = hashlib.sha256(signer_certificate).hexdigest()
            profile = self._profile(b"older certificate")
            profile["DeveloperCertificates"] = [b"older certificate", signer_certificate]
            with patch("mobile_release.ios._profile_details", return_value=profile), patch(
                "mobile_release.ios._codesign_fingerprint", return_value=signer
            ):
                evidence = ipa_signing_evidence(ipa)
            self.assertEqual(evidence["certificateSha256"], signer)

    def test_nested_app_profile_entitlements_and_signer_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extension = Path(temporary) / "ReaderWidget.appex"
            extension.mkdir()
            (extension / "Info.plist").write_bytes(b"nested-info")
            (extension / "embedded.mobileprovision").write_bytes(b"profile")
            certificate = b"nested signer certificate"
            fingerprint = hashlib.sha256(certificate).hexdigest()
            entitlements = {
                "application-identifier": "ABCDE12345.com.example.reader.widget",
                "com.apple.developer.team-identifier": "ABCDE12345",
                "get-task-allow": False,
                "aps-environment": "production",
            }
            profile = self._profile(certificate)
            profile["Entitlements"]["application-identifier"] = entitlements[
                "application-identifier"
            ]
            profile["Entitlements"]["aps-environment"] = "production"
            plist_module = types.ModuleType("plistlib")
            plist_module.InvalidFileException = ValueError
            plist_module.loads = lambda _value: {
                "CFBundleIdentifier": "com.example.reader.widget"
            }
            with patch.dict(sys.modules, {"plistlib": plist_module}), patch(
                "mobile_release.ios._profile_details", return_value=profile
            ):
                _validate_nested_bundle_security(
                    extension,
                    entitlements=entitlements,
                    team_id="ABCDE12345",
                    signer_fingerprint=fingerprint,
                )

                invalid_entitlements = dict(entitlements, **{"get-task-allow": True})
                with self.assertRaisesRegex(ValidationError, "entitlements"):
                    _validate_nested_bundle_security(
                        extension,
                        entitlements=invalid_entitlements,
                        team_id="ABCDE12345",
                        signer_fingerprint=fingerprint,
                    )

                profile["Entitlements"]["aps-environment"] = "development"
                with self.assertRaisesRegex(ValidationError, "production environment"):
                    _validate_nested_bundle_security(
                        extension,
                        entitlements=entitlements,
                        team_id="ABCDE12345",
                        signer_fingerprint=fingerprint,
                    )

    def test_nested_code_inventory_includes_bundles_and_standalone_macho(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "Reader.app"
            app.mkdir()
            executable = app / "Reader"
            executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"binary")
            helper = app / "Helpers/NoSuffix"
            helper.parent.mkdir()
            helper.write_bytes(b"\xca\xfe\xba\xbe" + b"helper")
            resource = app / "Resources/data.bin"
            resource.parent.mkdir()
            resource.write_bytes(b"data")
            bundle = app / "Assets.bundle"
            (bundle / "_CodeSignature").mkdir(parents=True)
            (bundle / "_CodeSignature/CodeResources").write_bytes(b"signature")

            def fake_codesign(argv: list[str], **_kwargs: object) -> object:
                if "--verbose=4" in argv:
                    return type(
                        "Completed",
                        (),
                        {
                            "returncode": 0,
                            "stdout": "",
                            "stderr": "TeamIdentifier=ABCDE12345\n",
                        },
                    )()
                return type(
                    "Completed", (), {"returncode": 0, "stdout": b"", "stderr": b""}
                )()

            with patch("mobile_release.ios.sys.platform", "darwin"), patch(
                "mobile_release.ios.shutil.which", return_value="/usr/bin/tool"
            ), patch("mobile_release.ios.subprocess.run", side_effect=fake_codesign), patch(
                "mobile_release.ios._codesign_leaf_fingerprint", return_value="a" * 64
            ):
                identities = _nested_codesign_identities(app, root / "certificates")
            self.assertIsNotNone(identities)
            paths = {item[0] for item in identities or []}
            self.assertIn(executable, paths)
            self.assertIn(helper, paths)
            self.assertIn(bundle, paths)
            self.assertNotIn(resource, paths)


if __name__ == "__main__":
    unittest.main()
