"""Production CMS parser/crypto/policy regressions; no real consumer material."""
from __future__ import annotations

import hashlib
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.ios_profile_auth import cms_payload_and_certificates, verify_cms
from mobile_release.ios_profile_trust import APPLE_ROOT_SHA256, apple_roots, pem_certificates, verify_profile_signer
from mobile_release.ios_profiles import decode_authenticated_profile, read_profile_bytes

from .ios_entitlement_helpers import modern_profile_bytes, profile, tlv
from .ios_profile_helpers import framed_cms, pem, public_certificates, signed_cms, synthetic_identity


class CMSFramingTests(unittest.TestCase):
    def test_parser_extracts_only_the_attached_payload_and_original_certificates(self):
        certificate = b"\x30\x01\x00"
        for version in (b"\x01", b"\x03"):
            self.assertEqual(cms_payload_and_certificates(framed_cms(version=version)),
                             (b"fictional payload", (certificate,)))
        # A successfully framed envelope still requires native signature/trust.
        with tempfile.TemporaryDirectory() as name, patch("mobile_release.ios_profile_auth.subprocess.run", return_value=SimpleNamespace(returncode=1)), patch("mobile_release.ios_profile_auth.verify_profile_signer") as trust:
            with self.assertRaises(ValidationError):
                verify_cms(framed_cms(), Path(name))
        trust.assert_not_called()

    def test_every_unsupported_or_ambiguous_shape_is_rejected_before_native_work(self):
        good = framed_cms()
        cases = [b"", None, bytearray(good), good + b"\0", good + good,
                 tlv(48, tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01") + tlv(0xa0, tlv(4, b"unsigned"))),
                 b"\x30\x80" + good[2:] + b"\0\0", b"\x30\x81\x01\0", b"\x30\x85" + b"\xff" * 8,
                 framed_cms(payload=b""), framed_cms(detached=True), framed_cms(signer_count=0),
                 framed_cms(signer_count=2), framed_cms(version=b"\0"), framed_cms(version=b"\0\x01"),
                 framed_cms(digest_count=0), framed_cms(digest_count=2), framed_cms(content_type=b"encrypted"),
                 framed_cms(digest_oid=b"\x2b\x0e\x03\x02\x1a"),  # SHA-1
                 framed_cms(signer_digest=b"\x2b\x0e\x03\x02\x1a"),  # strong unused entry is not authority
                 framed_cms(digest_oid=b"\x2a\x86\x48\x86\xf7\x0d\x02\x05"),  # MD5
                 framed_cms(certificates=()), framed_cms(certificates=(b"\x31\x00",)),
                 framed_cms(certificates=(b"\x30\x01\0",) * 2),
                 framed_cms(certificates=tuple(tlv(48, bytes([i])) for i in range(17))),
                 framed_cms(certificates=(tlv(48, b"\0" * 65536),)),
                 b"x" * (4 * 1024 * 1024 + 1)]
        cases.extend(good[:index] for index in range(len(good)))
        with patch("mobile_release.ios_profile_auth.subprocess.run") as native:
            for index, raw in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(ValidationError):
                    cms_payload_and_certificates(raw)
        native.assert_not_called()

    def test_pem_and_anchor_pins_are_independent_of_presented_certificates(self):
        roots = apple_roots()
        self.assertEqual({hashlib.sha256(item).hexdigest() for item in roots}, APPLE_ROOT_SHA256)
        for raw in (b"", b"private-canary" + pem(roots[0]), pem(roots[0]) * 2,
                    pem(roots[0]) + b"garbage", pem(b"\0").replace(b"AA==", b"AB==")):
            with self.subTest(raw=raw[:12]), self.assertRaises(ValidationError) as error:
                pem_certificates(raw)
            self.assertNotIn("private-canary", str(error.exception))
        with patch("mobile_release.ios_profiles.read_profile_bytes", return_value=b"".join(pem(raw) for raw in (*roots[:2], b"fake-root"))):
            with self.assertRaises(ValidationError):
                apple_roots()

    def test_failed_native_outputs_and_wrong_signer_cannot_authorize_any_content(self):
        for native_status, payload, signer in ((1, b"fictional payload", b"\x30\x01\0"),
                                               (0, b"substituted", b"\x30\x01\0"),
                                               (0, b"fictional payload", b"not-in-original-set")):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                def native(*args, **kwargs):
                    (root / "native-content.bin").write_bytes(payload)
                    (root / "native-signer.pem").write_bytes(pem(signer))
                    return SimpleNamespace(returncode=native_status)
                with patch("mobile_release.ios_profile_auth.subprocess.run", side_effect=native), patch("mobile_release.ios_profile_auth.verify_profile_signer") as trust:
                    with self.assertRaises(ValidationError):
                        verify_cms(framed_cms(), root)
                trust.assert_not_called()

    def test_profile_requires_both_authentications_in_order_then_complete_correlation(self):
        outer = modern_profile_bytes(profile())
        inner = plistlib.loads(outer)["DER-Encoded-Profile"]
        deadline = InspectionDeadline()
        for failed_call in (1, 2):
            seen = []
            def authenticate(raw, *, deadline):
                seen.append(raw)
                if len(seen) == failed_call:
                    raise ValidationError("fixed issuer rejection")
                return outer
            with patch("mobile_release.ios_profiles.authenticate_cms", side_effect=authenticate), patch("mobile_release.ios_der.decode_der_dictionary") as decode:
                with self.assertRaisesRegex(ValidationError, "issuer rejection"):
                    decode_authenticated_profile(b"original signed outer", deadline=deadline)
            decode.assert_not_called()
            self.assertEqual(seen, [b"original signed outer", inner][:failed_call])
        with patch("mobile_release.ios_profiles.authenticate_cms", side_effect=[outer, inner]) as authentication:
            self.assertEqual(decode_authenticated_profile(b"original signed outer", deadline=deadline)["UUID"], profile()["UUID"])
        self.assertEqual([call.args[0] for call in authentication.call_args_list], [b"original signed outer", inner])
        self.assertTrue(all(call.kwargs["deadline"] is deadline for call in authentication.call_args_list))

    def test_regular_file_snapshot_rejects_links_special_empty_large_and_changed_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "profile"
            source.write_bytes(b"original")
            self.assertEqual(read_profile_bytes(source), b"original")
            (root / "symlink").symlink_to(source)
            os.mkfifo(root / "fifo")
            (root / "empty").touch()
            for path in (root, root / "symlink", root / "fifo", root / "empty", root / "missing"):
                with self.subTest(path=path.name), self.assertRaises(ValidationError):
                    read_profile_bytes(path)
            with self.assertRaises(ValidationError):
                read_profile_bytes(source, maximum=3)
            actual = os.fstat
            def change(descriptor):
                before = actual(descriptor)
                source.write_bytes(b"replaced")
                return before
            with patch("mobile_release.ios_profiles.os.fstat", side_effect=change), self.assertRaisesRegex(ValidationError, "changed"):
                read_profile_bytes(source)


@unittest.skipUnless(sys.platform == "darwin", "production Apple profile policy requires macOS")
class NativeProfileAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="mrk-synthetic-profile-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        synthetic_identity(cls.root)
        outer = plistlib.loads(modern_profile_bytes(profile()))
        cls.inner_payload = outer["DER-Encoded-Profile"]
        outer["DER-Encoded-Profile"] = signed_cms(cls.root, cls.inner_payload, "inner")
        cls.outer_payload = plistlib.dumps(outer)
        cls.signed = signed_cms(cls.root, cls.outer_payload, "outer")

    def verify_in_new_directory(self, raw):
        with tempfile.TemporaryDirectory(prefix="mrk-native-cms-") as directory:
            return verify_cms(raw, Path(directory))

    def test_real_production_policy_accepts_apple_public_issuer_not_test_or_macos_purpose(self):
        certificates = public_certificates()
        intermediate = certificates["AppleiPhoneCA.cer"]
        leaf = certificates["ios_provisioning_profile.cer"]
        verify_profile_signer(leaf, (intermediate, leaf))
        for name in ("test_ios_provisioning_profile.cer", "mac_provisioning_profile.cer"):
            with self.subTest(purpose=name), self.assertRaises(ValidationError):
                verify_profile_signer(certificates[name], (certificates[name], intermediate))

    def test_actual_signature_integrity_and_exact_signer_are_checked_before_policy(self):
        with patch("mobile_release.ios_profile_auth.verify_profile_signer") as policy:
            self.assertEqual(self.verify_in_new_directory(self.signed), self.outer_payload)
        signer, presented = policy.call_args.args
        self.assertEqual(signer, pem_certificates((self.root / "fictional.pem").read_bytes())[0])
        self.assertIn(signer, presented)
        modified = self.signed.replace(b"com.example.reader", b"com.example.forged", 1)
        self.assertNotEqual(modified, self.signed)
        with patch("mobile_release.ios_profile_auth.verify_profile_signer") as policy, self.assertRaises(ValidationError):
            self.verify_in_new_directory(modified)
        policy.assert_not_called()

    def test_default_policy_rejects_even_valid_signature_with_production_looking_fake_issuer(self):
        with self.assertRaises(ValidationError):
            self.verify_in_new_directory(self.signed)
        # A presented real root/leaf cannot confer authority on the actual fake signer.
        signer = pem_certificates((self.root / "fictional.pem").read_bytes())[0]
        with self.assertRaises(ValidationError):
            verify_profile_signer(signer, (signer, *public_certificates().values(), *apple_roots()))

    def test_complete_two_layer_synthetic_signature_succeeds_only_with_explicit_policy_seam(self):
        # Keep REAL native crypto, both parsers, and complete DER/plist correlation.
        def crypto(raw, *, deadline):
            deadline.check()
            return self.verify_in_new_directory(raw)
        with patch("mobile_release.ios_profiles.authenticate_cms", side_effect=crypto), patch("mobile_release.ios_profile_auth.verify_profile_signer") as policy:
            decoded = decode_authenticated_profile(self.signed)
        self.assertEqual(decoded["Entitlements"], profile()["Entitlements"])
        self.assertEqual(policy.call_count, 2)
        # Same bytes through the real isolated worker/default policy MUST reject.
        with self.assertRaisesRegex(ValidationError, "could not be authenticated"):
            decode_authenticated_profile(self.signed)

    def test_signed_outer_cannot_authorize_unsigned_or_substituted_inner_profile(self):
        original = plistlib.loads(self.outer_payload)
        for inner in (self.inner_payload, original["DER-Encoded-Profile"].replace(b"com.example.reader", b"com.example.forged", 1)):
            changed = signed_cms(self.root, plistlib.dumps({**original, "DER-Encoded-Profile": inner}), "bad-inner-" + hashlib.sha256(inner).hexdigest()[:12])
            def crypto(raw, *, deadline):
                return self.verify_in_new_directory(raw)
            with patch("mobile_release.ios_profiles.authenticate_cms", side_effect=crypto), patch("mobile_release.ios_profile_auth.verify_profile_signer") as policy:
                with self.assertRaises(ValidationError):
                    decode_authenticated_profile(changed)
            self.assertEqual(policy.call_count, 1, "inner rejection must occur before its issuer-policy seam")


if __name__ == "__main__":
    unittest.main()
