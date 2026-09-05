from __future__ import annotations

import hashlib
import os
import plistlib
import sys
import tempfile
import types
import unittest
import zipfile
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.ios import (
    SigningValidityInterval,
    _codesign_fingerprint,
    _codesign_leaf_fingerprint,
    _nested_codesign_identities,
    _openssl_certificate_date,
    _profile_validity,
    _validate_nested_bundle_security,
    ipa_signing_evidence,
    validate_ipa,
    validate_ipa_current_signing,
    validate_preparation_signing_time,
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
            "CreationDate": datetime(2020, 1, 1, tzinfo=timezone.utc),
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

    def test_profile_validity_rejects_missing_malformed_and_noncurrent_bounds(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        good = {"CreationDate": now - timedelta(days=1), "ExpirationDate": now + timedelta(days=1)}
        invalid = [
            {}, {**good, "CreationDate": None}, {**good, "ExpirationDate": "2099-01-01"},
            {**good, "CreationDate": now + timedelta(seconds=1)},
            {**good, "ExpirationDate": now},
            {**good, "ExpirationDate": now - timedelta(seconds=1)},
            {"CreationDate": now + timedelta(days=2), "ExpirationDate": now + timedelta(days=1)},
            {"CreationDate": now, "ExpirationDate": now},
        ]
        with patch("mobile_release.ios._utc_now", return_value=now):
            for profile in invalid:
                with self.subTest(profile=profile), self.assertRaises(ValidationError):
                    _profile_validity(profile)
            self.assertEqual(_profile_validity({**good, "CreationDate": now}).lower_bound, now)

    def test_profile_plist_dates_are_utc_not_runner_local_and_offsets_normalize(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        expected = SigningValidityInterval(now, now + timedelta(hours=1))
        with patch("mobile_release.ios._utc_now", return_value=now):
            naive = _profile_validity({"CreationDate": now.replace(tzinfo=None), "ExpirationDate": (now + timedelta(hours=1)).replace(tzinfo=None)})
            offset = timezone(timedelta(hours=5, minutes=30))
            aware = _profile_validity({"CreationDate": now.astimezone(offset), "ExpirationDate": (now + timedelta(hours=1)).astimezone(offset)})
        self.assertEqual(naive, expected)
        self.assertEqual(aware, expected)
        class UndefinedTimezone(tzinfo):
            def utcoffset(self, _dt):
                return None
        with self.assertRaises(ValidationError):
            _profile_validity({"CreationDate": now.replace(tzinfo=UndefinedTimezone()), "ExpirationDate": expected.upper_bound})

    def test_preparation_observation_requires_exact_real_utc_and_original_interval(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        interval = SigningValidityInterval(now, now + timedelta(seconds=1))
        validate_preparation_signing_time(interval, "2026-09-05T12:00:00Z")
        for value in (
            "2026-09-05T11:59:59Z", "2026-09-05T12:00:01Z", "2026-09-05T12:00:00+00:00",
            "2026-09-05T12:00:00.0Z", "2026-02-30T12:00:00Z", "2026-09-05", None, 1,
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_preparation_signing_time(interval, value)

    def _fake_native_certificate(self, *, before: str, after: str, calls: list) -> object:
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if "--extract-certificates" in argv:
                prefix = Path(argv[argv.index("--extract-certificates") + 1])
                Path(str(prefix) + "0").write_bytes(b"synthetic certificate, never a real signature")
                return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            if "x509" in argv:
                return types.SimpleNamespace(returncode=0, stdout=f"sha256 Fingerprint={':'.join(['AA'] * 32)}\nnotBefore={before}\nnotAfter={after}\n", stderr="")
            # Deliberately emulate default codesign accepting an expired or
            # postdated leaf certificate. The extracted actual dates must win.
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        return run

    def test_successful_codesign_does_not_authorize_expired_or_future_leaf(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        for before, after in (
            ("Sep  1 12:00:00 2026 GMT", "Sep  5 12:00:00 2026 GMT"),
            ("Sep  5 12:00:01 2026 GMT", "Sep  6 12:00:00 2026 GMT"),
            ("Sep  6 12:00:00 2026 GMT", "Sep  5 12:00:00 2026 GMT"),
        ):
            calls = []
            with self.subTest(before=before, after=after), tempfile.TemporaryDirectory() as temporary, patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/usr/bin/tool"), patch("mobile_release.ios._utc_now", return_value=now), patch("mobile_release.ios.subprocess.run", side_effect=self._fake_native_certificate(before=before, after=after, calls=calls)):
                with self.assertRaises(ValidationError):
                    _codesign_fingerprint(Path(temporary) / "Reader.app", Path(temporary))
            self.assertEqual(len(calls), 3)
            self.assertIn("--verify", calls[0][0])
            self.assertIn("--extract-certificates", calls[1][0])
            self.assertIn("-dates", calls[2][0])

    def test_extracted_leaf_interval_is_returned_with_current_lower_boundary_inclusive(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        calls, intervals = [], []
        with tempfile.TemporaryDirectory() as temporary, patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/usr/bin/tool"), patch("mobile_release.ios._utc_now", return_value=now), patch("mobile_release.ios.subprocess.run", side_effect=self._fake_native_certificate(before="Sep  5 12:00:00 2026 GMT", after="Sep  6 12:00:00 2026 GMT", calls=calls)):
            self.assertEqual(_codesign_fingerprint(Path(temporary) / "Reader.app", Path(temporary), _validity_intervals=intervals), "aa" * 32)
        self.assertEqual(intervals, [SigningValidityInterval(now, now + timedelta(days=1))])

    def test_native_certificate_dates_missing_duplicate_or_ambiguous_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for dates in (
                "", "notBefore=Sep  1 12:00:00 2026 GMT\n", "notBefore=bad\nnotAfter=Sep  6 12:00:00 2026 GMT\n",
                "notBefore=Sep  1 12:00:00 2026 GMT\nnotBefore=Sep  1 12:00:00 2026 GMT\nnotAfter=Sep  6 12:00:00 2026 GMT\n",
                "notBefore=Sep  1 12:00:00 2026 GMT\nnotAfter=Sep  6 12:00:00 2026 GMT\nnotAfter=Sep  6 12:00:00 2026 GMT\n",
            ):
                (root / "leaf0").write_bytes(b"fake leaf")
                completed = types.SimpleNamespace(returncode=0, stdout=f"sha256 Fingerprint={'AA:' * 31}AA\n{dates}", stderr="")
                with self.subTest(dates=dates), patch("mobile_release.ios.subprocess.run", return_value=completed), self.assertRaises(ValidationError):
                    _codesign_leaf_fingerprint(root / "Reader", root / "leaf")
        for date in ("Sep  1 12:00:00 2026", "Sep  1 12:00:00 2026 +00:00", "Feb 30 12:00:00 2026 GMT", "Sep  1 12:00:60 2026 GMT", "SEP  1 12:00:00 2026 GMT"):
            with self.subTest(date=date), self.assertRaises(ValidationError):
                _openssl_certificate_date(date)

    def test_codesign_failure_is_never_ignored_for_historical_or_expires_signatures(self) -> None:
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"certificate expired and resources may be corrupt")
        with patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/usr/bin/tool"), patch("mobile_release.ios.subprocess.run", side_effect=run):
            with self.assertRaisesRegex(ValidationError, "codesign rejected"):
                _codesign_fingerprint(Path("Reader.app"), Path("temporary"))
        self.assertEqual(len(calls), 1)

    def test_primary_and_nested_profile_creation_and_expiration_are_required(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        certificate = b"actual signer certificate"
        signer = hashlib.sha256(certificate).hexdigest()
        for field, value in (("CreationDate", None), ("CreationDate", now + timedelta(seconds=1)), ("ExpirationDate", now)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                root = Path(temporary)
                ipa = root / "Reader.ipa"
                self._ipa(ipa)
                extension = root / "ReaderWidget.appex"
                extension.mkdir()
                (extension / "Info.plist").write_bytes(b"nested-info")
                (extension / "embedded.mobileprovision").write_bytes(b"profile")
                profile = self._profile(certificate)
                profile[field] = value
                stack.enter_context(patch.dict(sys.modules, {"plistlib": self._plist_module()}))
                stack.enter_context(patch("mobile_release.ios._utc_now", return_value=now))
                stack.enter_context(patch("mobile_release.ios._profile_details", return_value=profile))
                native = stack.enter_context(patch("mobile_release.ios._codesign_fingerprint", return_value=signer))
                result = validate_ipa(ipa, expected_bundle_id="com.example.reader", expected_team_id="ABCDE12345", expected_fingerprint=signer, release=ReleaseVersion("1.2.3", 42), require_tools=True)
                self.assertTrue(any(item.status in FAILING_STATUSES for item in result))
                self.assertEqual(native.call_count, 0)
                with self.assertRaises(ValidationError):
                    _validate_nested_bundle_security(extension, entitlements=self._signed_entitlements(), team_id="ABCDE12345", signer_fingerprint=signer)

    def test_current_validation_intersects_all_profile_and_leaf_bounds_and_rechecks_now(self) -> None:
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        certificate = b"actual signer certificate"
        signer = hashlib.sha256(certificate).hexdigest()
        leaf = SigningValidityInterval(now - timedelta(days=2), now + timedelta(days=2))
        nested = SigningValidityInterval(now - timedelta(hours=1), now + timedelta(hours=1))
        def primary(_app, _temporary, *, _validity_intervals=None):
            _validity_intervals.append(leaf)
            return signer
        def nested_codesign(_app, _temporary, *, _validity_intervals=None):
            _validity_intervals.append(nested)
            return []
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            ipa = Path(temporary) / "Reader.ipa"
            self._ipa(ipa)
            stack.enter_context(patch.dict(sys.modules, {"plistlib": self._plist_module()}))
            stack.enter_context(patch("mobile_release.ios._profile_details", return_value=self._profile(certificate)))
            stack.enter_context(patch("mobile_release.ios._codesign_entitlements", return_value=self._signed_entitlements()))
            stack.enter_context(patch("mobile_release.ios._codesign_fingerprint", side_effect=primary))
            stack.enter_context(patch("mobile_release.ios._nested_codesign_identities", side_effect=nested_codesign))
            with patch("mobile_release.ios._utc_now", return_value=now):
                findings, interval = validate_ipa_current_signing(ipa, expected_bundle_id="com.example.reader", expected_team_id="ABCDE12345", expected_fingerprint=signer, release=ReleaseVersion("1.2.3", 42))
            self.assertFalse(any(item.status in FAILING_STATUSES for item in findings))
            self.assertEqual(interval, nested)
            with patch("mobile_release.ios._utc_now", side_effect=(now, nested.upper_bound)):
                findings, interval = validate_ipa_current_signing(ipa, expected_bundle_id="com.example.reader", expected_team_id="ABCDE12345", expected_fingerprint=signer, release=ReleaseVersion("1.2.3", 42))
            self.assertIsNone(interval)
            self.assertTrue(any(item.status in FAILING_STATUSES for item in findings))

    def test_real_nested_inventory_and_plists_enforce_every_current_date_interval(self) -> None:
        """Mock native cryptography only, not ZIP/plist/inventory/date policy.

        These intentionally unsigned synthetic files prove dispatch/validation
        plumbing, not a real Apple distribution signature or CMS trust chain.
        """
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        certificate = b"synthetic public certificate, not an Apple signer"
        fingerprint = hashlib.sha256(certificate).hexdigest()
        secret_names = (
            "GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL", "GOOGLE_APPLICATION_CREDENTIALS",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", "MOBILE_RELEASE_IOS_CERTIFICATE_P12_BASE64",
        )
        for defect in (None, "framework-expired", "framework-future", "extension-expired", "extension-future"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                root = Path(temporary)
                ipa = root / "Reader.ipa"
                extracted_leaf_paths = {}
                native_calls = []
                with zipfile.ZipFile(ipa, "w") as archive:
                    for bundle, bundle_id in (
                        ("Payload/Reader.app", "com.example.reader"),
                        ("Payload/Reader.app/PlugIns/Widget.appex", "com.example.reader.widget"),
                    ):
                        name = Path(bundle).stem
                        archive.writestr(bundle + "/Info.plist", plistlib.dumps({
                            "CFBundleIdentifier": bundle_id, "CFBundleExecutable": name,
                            "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "42",
                        }))
                        archive.writestr(bundle + "/" + name, b"\xcf\xfa\xed\xfe" + b"synthetic")
                        archive.writestr(bundle + "/_CodeSignature/CodeResources", b"synthetic signature")
                        profile = self._profile(certificate)
                        profile["Entitlements"]["application-identifier"] = f"ABCDE12345.{bundle_id}"
                        lower, upper = now - timedelta(days=1), now + timedelta(days=1)
                        if bundle.endswith(".appex"):
                            lower, upper = now - timedelta(minutes=10), now + timedelta(minutes=10)
                            if defect == "extension-expired":
                                upper = now
                            elif defect == "extension-future":
                                lower = now + timedelta(seconds=1)
                        profile["CreationDate"] = lower.replace(tzinfo=None)
                        profile["ExpirationDate"] = upper.replace(tzinfo=None)
                        archive.writestr(bundle + "/embedded.mobileprovision", plistlib.dumps(profile))
                    archive.writestr("Payload/Reader.app/Frameworks/ReaderKit.framework/ReaderKit", b"\xcf\xfa\xed\xfe" + b"synthetic framework")
                    archive.writestr("Payload/Reader.app/Frameworks/ReaderKit.framework/_CodeSignature/CodeResources", b"synthetic signature")

                def native(argv, **kwargs):
                    native_calls.append(argv)
                    self.assertFalse(set(secret_names) & kwargs["env"].keys())
                    if argv[0] == "security":
                        return types.SimpleNamespace(returncode=0, stdout=Path(argv[-1]).read_bytes(), stderr=b"")
                    if "--entitlements" in argv:
                        bundle_id = "com.example.reader.widget" if ".appex" in argv[-1] else "com.example.reader"
                        value = self._signed_entitlements(**{"application-identifier": f"ABCDE12345.{bundle_id}"})
                        return types.SimpleNamespace(returncode=0, stdout=plistlib.dumps(value), stderr=b"")
                    if "--extract-certificates" in argv:
                        prefix = Path(argv[argv.index("--extract-certificates") + 1])
                        leaf = Path(str(prefix) + "0")
                        leaf.write_bytes(certificate)
                        extracted_leaf_paths[str(leaf)] = argv[-1]
                        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
                    if argv[0] == "openssl":
                        code_path = extracted_leaf_paths[argv[argv.index("-in") + 1]]
                        lower, upper = now - timedelta(hours=1), now + timedelta(hours=1)
                        if ".framework" in code_path:
                            lower, upper = now - timedelta(minutes=1), now + timedelta(seconds=30)
                            if defect == "framework-expired":
                                upper = now
                            elif defect == "framework-future":
                                lower = now + timedelta(seconds=1)
                        before = lower.strftime("%b %d %H:%M:%S %Y GMT")
                        after = upper.strftime("%b %d %H:%M:%S %Y GMT")
                        return types.SimpleNamespace(returncode=0, stdout=f"sha256 Fingerprint={fingerprint}\nnotBefore={before}\nnotAfter={after}\n", stderr="")
                    if "--verbose=4" in argv:
                        return types.SimpleNamespace(returncode=0, stdout="", stderr="TeamIdentifier=ABCDE12345\n")
                    # Successful native verification alone cannot bypass any
                    # profile/leaf validity interval checked by Python.
                    return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

                stack.enter_context(patch.dict(os.environ, {key: "fictional-sensitive-value" for key in secret_names}))
                stack.enter_context(patch("mobile_release.ios.sys.platform", "darwin"))
                stack.enter_context(patch("mobile_release.ios.shutil.which", return_value="/usr/bin/tool"))
                stack.enter_context(patch("mobile_release.ios._utc_now", return_value=now))
                stack.enter_context(patch("mobile_release.ios.subprocess.run", side_effect=native))
                findings, interval = validate_ipa_current_signing(
                    ipa, expected_bundle_id="com.example.reader", expected_team_id="ABCDE12345",
                    expected_fingerprint=fingerprint, release=ReleaseVersion("1.2.3", 42),
                )
                if defect is None:
                    self.assertFalse(any(item.status in FAILING_STATUSES for item in findings), findings)
                    self.assertEqual(interval, SigningValidityInterval(now - timedelta(minutes=1), now + timedelta(seconds=30)))
                    inspected = set(extracted_leaf_paths.values())
                    for suffix in ("/Reader.app", "/Reader", "/Widget.appex", "/Widget", "/ReaderKit.framework", "/ReaderKit"):
                        self.assertTrue(any(path.endswith(suffix) for path in inspected), suffix)
                    self.assertEqual(sum(argv[0] == "security" for argv in native_calls), 2)
                else:
                    self.assertIsNone(interval)
                    self.assertTrue(any(item.status in FAILING_STATUSES for item in findings), defect)


if __name__ == "__main__":
    unittest.main()
