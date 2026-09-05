from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import struct
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.inspection import MAX_INSPECTION_SECONDS
from mobile_release.ios import _codesign_entitlements, _codesign_leaf_fingerprint, _profile_details, ipa_signing_evidence, validate_ipa_current_signing
from mobile_release.ios_der import decode_der_dictionary
from mobile_release.ios_entitlements import (
    correlate_profile, load_plist_dictionary, typed_value, validate_profile_entitlements,
)
from mobile_release.reporting import FAILING_STATUSES

from .ios_artifact_helpers import artifact_set, fat_image, native_image, zip_tree
from .ios_entitlement_helpers import (
    BUNDLE, CERTIFICATE, TEAM, NativeProfileSeam, add_discardable_root_dictionary,
    der_entitlements, der_value, malformed_xml_cases, modern_profile_bytes, profile,
    signed_entitlements, supported_xml_lexical_cases, tlv,
)


class EntitlementAllowlistTests(unittest.TestCase):
    def test_generic_real_comparison_preserves_sign_and_exact_types(self):
        # Diagnostic of the shared typed comparer, not a DER-float capability:
        # actual modern entitlement DER does not support real-number claims.
        for value in (-0.0, 0.0, 1.25):
            validate_profile_entitlements({"future": value}, {"future": value})
            validate_profile_entitlements({"future": [value]}, {"future": [value, "unused"]})
        for claim, grant in ((-0.0, 0.0), ([-0.0], [0.0]), ({"x": -0.0}, {"x": 0.0}),
                             (0.0, 0), (0.0, False), (0.0, "0x0.0p+0")):
            with self.subTest(claim=claim, grant=grant), self.assertRaises(ValidationError):
                validate_profile_entitlements({"future": claim}, {"future": grant})
        validate_profile_entitlements({"future": [-0.0, 0.0]}, {"future": [-0.0, 0.0]})

    def test_every_app_key_needs_a_grant_and_errors_do_not_echo_private_keys_values(self):
        for key, value in (("com.apple.developer.associated-domains", ["applinks:private.example"]),
                           ("private-key-canary\n", "private-value-canary"), ("future.boolean", False)):
            with self.subTest(key=key), self.assertRaises(ValidationError) as error:
                validate_profile_entitlements({key: value}, {})
            self.assertNotIn(key, str(error.exception))
            self.assertNotIn("private-", str(error.exception))

    def test_extra_profile_grants_do_not_require_unused_app_capabilities(self):
        validate_profile_entitlements(signed_entitlements(), {
            **signed_entitlements(), "aps-environment": "production", "future.entitlement": ["unused"],
        })

    def test_unknown_scalars_are_exact_typed_not_truthiness_coercions(self):
        for value in (False, True, 0, 1, "1", "true", b"1", {"x": [True]}):
            validate_profile_entitlements({"future": value}, {"future": value})
        for claim, grant in ((True, 1), (False, 0), ("1", 1), (1, "1"), ({"x": True}, {"x": 1}),
                             ({"x": True}, {"x": True, "y": True})):
            with self.subTest(claim=claim, grant=grant), self.assertRaises(ValidationError):
                validate_profile_entitlements({"future": claim}, {"future": grant})

    def test_arrays_are_typed_subsets_but_unknown_compounds_are_exact(self):
        validate_profile_entitlements({"future": [True, {"x": [1]}]}, {"future": [{"x": [1]}, True, "extra"]})
        for claim, grant in (([False], [0]), ([{"x": 1}], [{"x": 1, "y": 2}]), (["b"], ["a"]),
                             ([], "*"), ([], {}), ([], False), (["a"], "a")):
            with self.subTest(claim=claim, grant=grant), self.assertRaises(ValidationError):
                validate_profile_entitlements({"future": claim}, {"future": grant})
        validate_profile_entitlements({"future": []}, {"future": []})

    def test_keychain_and_cloud_identifiers_use_bounded_prefix_grants(self):
        for key in ("keychain-access-groups", "com.apple.developer.icloud-container-identifiers",
                    "com.apple.developer.ubiquity-container-identifiers"):
            validate_profile_entitlements({key: ["ABCDE12345.reader", "com.apple.token"]},
                                          {key: ["ABCDE12345.*", "com.apple.token"]})
            for claim, grant in (("ABCDE12345reader", "ABCDE12345.*"), ("EVIL.reader", "ABCDE12345.*"),
                                 ("ABCDE12345.*", "ABCDE12345.*"), ("ABCDE12345.reader", "*"),
                                 ("ABCDE12345.reader", "ABCDE*.reader"), ("ABCDE12345.reader", "ABCDE12345.**"),
                                 ("ABCDE12345.reader", "ABCDE12345.?")):
                with self.subTest(key=key, claim=claim, grant=grant), self.assertRaises(ValidationError):
                    validate_profile_entitlements({key: [claim]}, {key: [grant]})
        key = "com.apple.developer.ubiquity-kvstore-identifier"
        validate_profile_entitlements({key: "ABCDE12345.reader"}, {key: "ABCDE12345.*"})
        with self.assertRaises(ValidationError):
            validate_profile_entitlements({key: ["ABCDE12345.reader"]}, {key: "ABCDE12345.*"})

    def test_app_group_and_merchant_grants_are_exact_not_invented_team_prefixes(self):
        for key, allowed in (("com.apple.security.application-groups", "group.example.shared"),
                             ("com.apple.developer.in-app-payments", "merchant.example.reader")):
            validate_profile_entitlements({key: [allowed]}, {key: [allowed, "group.example.other"]})
            for claims, grants in (([allowed], ["group.example.*"]), ([allowed], ["other.value"]),
                                   ([allowed + "*"], [allowed + "*"]), ([], [allowed]), (allowed, [allowed])):
                with self.subTest(key=key, claims=claims), self.assertRaises(ValidationError):
                    validate_profile_entitlements({key: claims}, {key: grants})

    def test_associated_domains_have_explicit_profile_wildcard_not_shell_glob(self):
        key, claims = "com.apple.developer.associated-domains", ["applinks:*.example.test", "webcredentials:example.test"]
        for grant in ("*", ["*"], claims + ["activitycontinuation:other.example"]):
            validate_profile_entitlements({key: claims}, {key: grant})
        for claim, grant in ((claims, ["applinks:*"]), (["*"], "*"), ([], "*"), ("applinks:example.test", "*"),
                             ([True], "*"), (claims, {"grant": "*"})):
            with self.subTest(claim=claim, grant=grant), self.assertRaises(ValidationError):
                validate_profile_entitlements({key: claim}, {key: grant})

    def test_documented_icloud_services_scalar_wildcard_and_array_subset(self):
        key = "com.apple.developer.icloud-services"
        for grants in ("*", ["*"], ["CloudKit", "CloudDocuments"]):
            validate_profile_entitlements({key: ["CloudKit"]}, {key: grants})
        for claim, grant in ((["*"], "*"), (["Unknown"], "*"), (["CloudKit", 1], "*"),
                             (["CloudKit"], ["CloudDocuments"]), ("CloudKit", "*"), ([], "*")):
            with self.subTest(claim=claim), self.assertRaises(ValidationError):
                validate_profile_entitlements({key: claim}, {key: grant})
        with self.assertRaises(ValidationError):
            validate_profile_entitlements({"future": ["CloudKit"]}, {"future": "*"})

    def test_production_environments_allow_icloud_selection_without_enabling_debug(self):
        cloud = "com.apple.developer.icloud-container-environment"
        validate_profile_entitlements({cloud: "Production"}, {cloud: ["Development", "Production"]})
        validate_profile_entitlements({}, {cloud: "Production", "aps-environment": "production"})
        for app, grants in (({cloud: "Development"}, {cloud: ["Development", "Production"]}),
                            ({"aps-environment": "development"}, {"aps-environment": "development"}),
                            ({"aps-environment": "production"}, {"aps-environment": ["production"]})):
            with self.subTest(app=app), self.assertRaises(ValidationError):
                validate_profile_entitlements(app, grants)
        for value in (True, 1, 0, "false", [], None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_profile_entitlements({"get-task-allow": value}, {"get-task-allow": value})

    def test_identity_wildcards_and_wrong_known_claim_types_cannot_use_exact_fastpath(self):
        for value in ("ABCDE12345.*", [], True, 123, ""):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_profile_entitlements({"application-identifier": value}, {"application-identifier": value})

    def test_matching_checks_shared_deadline_and_large_lists_without_quadratic_comparison(self):
        grants = [f"group.example.{index}" for index in range(4000)]
        validate_profile_entitlements({"future": grants[::-1]}, {"future": grants})
        deadline = InspectionDeadline()
        deadline._expires_at = 0
        with self.assertRaisesRegex(ValidationError, "shared time bound"):
            validate_profile_entitlements({"future": grants}, {"future": grants}, deadline=deadline)


class EntitlementDecodingTests(unittest.TestCase):
    def test_original_numeric_reference_digit_count_not_normalized_magnitude(self):
        from mobile_release.ios_artifacts import typed_plist
        with tempfile.TemporaryDirectory(prefix="mrk-reference-") as directory:
            path = Path(directory) / "Info.plist"
            for spelling in ("#00000065", "#x00000041", "#00000049", "#x00000031"):
                for tag in ("string", "key", "real"):
                    if tag == "real" and spelling in {"#00000065", "#x00000041"}:
                        continue
                    value = "A" if spelling in {"#00000065", "#x00000041"} else "1"
                    for extra in ("", "0", "0000"):
                        reference = spelling[:2] + extra + spelling[2:] if spelling.startswith("#x") else "#" + extra + spelling[1:]
                        body = f'<key>&{reference};</key><true/>' if tag == "key" else f'<key>x</key><{tag}>&{reference};</{tag}>'
                        source = f'<plist><dict>{body}</dict></plist>'
                        expected = {value: True} if tag == "key" else {"x": 1.0 if tag == "real" else value}
                        for encoding, bom in (("utf-8", b""), ("utf-8", b"\xef\xbb\xbf"), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                            raw = bom + source.encode(encoding); path.write_bytes(raw)
                            with self.subTest(tag=tag, reference=reference, encoding=encoding, bom=bool(bom)):
                                if extra:
                                    for reader in (lambda: load_plist_dictionary(raw), lambda: typed_plist(path)):
                                        with self.assertRaisesRegex(ValidationError, "reference spelling"):
                                            reader()
                                else:
                                    self.assertEqual(load_plist_dictionary(raw), expected)
                                    self.assertEqual(typed_plist(path), typed_value(expected))
            raw = b'<plist><dict><key>x</key><string><![CDATA[&#000000065;]]>&amp;#000000065;&#x0010FFFF;</string></dict></plist>'
            self.assertEqual(load_plist_dictionary(raw), {"x": "&#000000065;&#000000065;\U0010ffff"})

    def test_complete_xml_grammar_rejects_every_malformed_raw_case_with_private_errors(self):
        for name, raw in malformed_xml_cases().items():
            with self.subTest(case=name), self.assertRaises(ValidationError) as error:
                load_plist_dictionary(raw)
            self.assertNotIn("canary", str(error.exception))

    def test_original_lexical_text_preserves_native_values_and_byte_offsets(self):
        for name, (source, expected) in supported_xml_lexical_cases().items():
            for encoding, bom in (("utf-8", b""), ("utf-8", b"\xef\xbb\xbf"),
                                  ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                with self.subTest(case=name, encoding=encoding, bom=bool(bom)):
                    self.assertEqual(load_plist_dictionary(bom + source.encode(encoding)), expected)
        for encoding, bom in (("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
            for declaration in ('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>',
                                f'<?xml version="1.0" encoding="{encoding.replace("16-", "16")}"?>'):
                with self.subTest(encoding=encoding, declaration=declaration):
                    self.assertEqual(load_plist_dictionary(bom + (declaration + '<plist><dict/></plist>').encode(encoding)), {})
        raw = '<plist ><dict ><key >😀</key><string >a</string><key /><string /></dict></plist>'
        self.assertEqual(load_plist_dictionary(raw.encode()), {"😀": "a", "": ""})

    def test_original_cr_keys_are_unique_after_actual_reference_and_cdata_decoding(self):
        for equivalent in ("a&#13;", "<![CDATA[a\r]]>"):
            raw = f'<plist><dict><key>a\r</key><true/><key>{equivalent}</key><false/></dict></plist>'
            for encoding, bom in (("utf-8", b""), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                with self.subTest(encoding=encoding, equivalent=equivalent), self.assertRaisesRegex(ValidationError, "duplicate"):
                    load_plist_dictionary(bom + raw.encode(encoding))

    def test_each_opening_tag_is_bounded_and_lexical_traversal_checks_shared_deadline(self):
        import mobile_release.ios_entitlements as policy
        with self.assertRaisesRegex(ValidationError, "opening tag.*bound"):
            load_plist_dictionary(b'<plist><dict><key/><string' + b' ' * 8192 + b'/></dict></plist>')
        text, searched = "left&amp;right&amp;tail", []
        raw = f'<plist><dict><key>x</key><string>{text}</string></dict></plist>'.encode()
        original = policy.XML_TEXT_TOKEN
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()
            def search(source, position):
                marker = original.search(source, position)
                if source == text:
                    searched.append(position)
                    clock.return_value = MAX_INSPECTION_SECONDS
                return marker
            with patch.object(policy, "XML_TEXT_TOKEN") as tokens:
                tokens.search.side_effect = search
                with self.assertRaisesRegex(ValidationError, "shared time bound"):
                    load_plist_dictionary(raw, deadline=deadline)
        self.assertEqual(searched, [0], "expiry must interrupt the actual lexical traversal, not only parse entry")

    def test_strict_xml_and_binary_values_round_trip_without_type_or_content_loss(self):
        values = {"": "", "unicode": "مرحبا 😀 & < >", "empty": [[], {}, b""],
                  "nested": {"bool": True, "integer": 1, "real": 1.25},
                  "bounds": [-(1 << 63), (1 << 64) - 1], "data": b"\x00\xffdata",
                  "date": datetime(2026, 9, 5)}
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            raw = plistlib.dumps(values, fmt=fmt)
            self.assertEqual(typed_value(load_plist_dictionary(raw)), typed_value(values))
        source = plistlib.dumps(values).decode()
        # Actual current dsymutil uses this standard historical public label.
        self.assertEqual(typed_value(load_plist_dictionary(source.replace("-//Apple//", "-//Apple Computer//").encode())), typed_value(values))
        for scheme in ("http", "https"):
            xml = source.replace("http://", scheme + "://").replace('<plist version="1.0">', "<plist\nversion = '1.0' >")
            for encoding, bom in (("utf-8", b""), ("utf-8", b"\xef\xbb\xbf"), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                declared = "UTF-16" if encoding.startswith("utf-16") else "UTF-8"
                raw = bom + xml.replace('encoding="UTF-8"', f'encoding="{declared}"').encode(encoding)
                with self.subTest(scheme=scheme, encoding=encoding, bom=bool(bom)):
                    self.assertEqual(typed_value(load_plist_dictionary(raw)), typed_value(values))
        raw = b'''<plist><dict><key/><string/><key>refs</key><string>&amp;&#65;&#x42;&lt;</string>
            <key>numbers</key><array><integer>+1</integer><integer>0Xff</integer><integer>-0xff</integer>
            <real>.5</real><real>1e-2</real></array><key>data</key><data>Y Q==\n</data></dict></plist>'''
        self.assertEqual(load_plist_dictionary(raw), {"": "", "refs": "&AB<", "numbers": [1, 255, -255, .5, .01], "data": b"a"})

    def test_xml_root_lexical_bound_and_event_limits_precede_allocation_and_traversal(self):
        import mobile_release.ios_entitlements as policy
        raw = b'<plist><dict><key>x</key><string>value</string></dict></plist>'
        with patch.object(policy, "MAX_VALUE_NODES", 3), patch.object(policy, "_XMLFrame", wraps=policy._XMLFrame) as frames, self.assertRaisesRegex(ValidationError, "XML plist complexity"):
            load_plist_dictionary(raw)
        self.assertEqual(frames.call_count, 3, "the excess XML value cannot allocate a frame")
        with patch.object(policy, "MAX_VALUE_DEPTH", 0):
            self.assertEqual(load_plist_dictionary(b"<plist><dict/></plist>"), {})
            with self.assertRaisesRegex(ValidationError, "XML plist complexity"):
                load_plist_dictionary(raw)
        with patch.object(policy, "MAX_PLIST_BYTES", 8), patch("xml.parsers.expat.ParserCreate", side_effect=AssertionError("size before parser")), self.assertRaises(ValidationError):
            load_plist_dictionary(raw)
        self.assertEqual(load_plist_dictionary(b"<plist" + b" " * 1024 + b"><dict/></plist>"), {})
        with self.assertRaisesRegex(ValidationError, "root tag.*bound"):
            load_plist_dictionary(b"<plist" + b" " * 8192 + b"><dict/></plist>")
        original, entered = policy._XMLFrame, []
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()
            def allocate(tag):
                entered.append(tag)
                if tag == "key":
                    clock.return_value = MAX_INSPECTION_SECONDS
                return original(tag)
            with patch.object(policy, "_XMLFrame", side_effect=allocate), patch.object(policy, "typed_value", side_effect=AssertionError("deadline must expire during parsing")), self.assertRaisesRegex(ValidationError, "shared time bound"):
                load_plist_dictionary(raw, deadline=deadline)
        self.assertEqual(entered, ["plist", "dict", "key"])

    def test_real_plist_encodings_preserve_types_and_reject_duplicate_keys(self):
        claims = {"bool": True, "int": 1, "nested": [{"x": "value"}], "data": b"data"}
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            self.assertEqual(typed_value(load_plist_dictionary(plistlib.dumps(claims, fmt=fmt))), typed_value(claims))
        duplicate_xml = b'<plist><dict><key>x</key><true/><key>x</key><false/></dict></plist>'
        objects = b"\xd2\x01\x01\x02\x03\x51x\x10\x01\x10\x02"
        duplicate_binary = b"bplist00" + objects + bytes((8, 13, 15, 17)) + b"\0" * 6 + bytes((1, 1)) + struct.pack(">3Q", 4, 0, 19)
        for raw in (duplicate_xml, duplicate_binary):
            with self.subTest(raw=raw[:8]), self.assertRaisesRegex(ValidationError, "duplicate"):
                load_plist_dictionary(raw)

    def test_plist_preallocation_complexity_cycle_and_value_bounds(self):
        raw = bytearray(plistlib.dumps({"x": 1}, fmt=plistlib.FMT_BINARY))
        raw[-24:-16] = (10**9).to_bytes(8, "big")
        with patch("plistlib.loads", side_effect=AssertionError("must reject before allocation")), self.assertRaises(ValidationError):
            load_plist_dictionary(bytes(raw))
        cyclic = []; cyclic.append(cyclic)
        for value in ({"x": cyclic}, {"x": None}, {"x": float("nan")}, {"x": plistlib.UID(1)}, {1: True}):
            with self.subTest(value_type=type(value)), self.assertRaises(ValidationError):
                typed_value(value)
        deep = {}
        for _ in range(66):
            deep = {"next": deep}
        with self.assertRaises(ValidationError):
            load_plist_dictionary(plistlib.dumps(deep))
        with patch("mobile_release.ios_entitlements.MAX_PLIST_BYTES", 10), self.assertRaises(ValidationError):
            load_plist_dictionary(plistlib.dumps({"x": 1}))

    def test_v0_v1_der_and_modern_profile_use_typed_dictionaries(self):
        claims = {"bool": True, "int": -1, "nested": {"list": ["x", False]}, "data": b"data"}
        for raw in (der_value(claims, dictionary_tag=49), der_entitlements(claims)):
            self.assertEqual(typed_value(decode_der_dictionary(raw)), typed_value(claims))
        outer = profile()
        encoded = plistlib.loads(modern_profile_bytes(outer))
        authoritative = decode_der_dictionary(encoded["DER-Encoded-Profile"], profile=True)
        effective = correlate_profile(outer, authoritative)
        self.assertEqual(typed_value(effective), typed_value(outer))
        self.assertEqual(authoritative["DeveloperCertificates"], [hashlib.sha256(CERTIFICATE).digest()])

    def test_der_malformed_tags_lengths_values_duplicates_versions_and_trailing_fail(self):
        pair = tlv(48, der_value("x") + der_value(True))
        cases = [b"", b"\x31\x80\0\0", b"\x31\x81\0", b"\x31\x82\0\x80" + b"x" * 128,
                 der_entitlements({}) + b"extra", tlv(49, pair + pair), tlv(49, tlv(48, der_value(1) + der_value(True))),
                 tlv(49, tlv(48, der_value("x") + tlv(1, b"\x01"))),
                 tlv(49, tlv(48, der_value("x") + tlv(2, b"\0\x01"))),
                 tlv(49, tlv(48, der_value("x") + tlv(2, b"\xff\xff"))),
                 tlv(49, tlv(48, der_value("x") + tlv(12, b"\xff"))),
                 tlv(49, tlv(48, der_value("x") + tlv(5, b""))),
                 tlv(0x70, der_value(2) + der_value({})), tlv(0x70, der_value(True) + der_value({})),
                 tlv(0x70, der_value(1) + der_value([])), tlv(49, tlv(48, der_value("x") + der_value(True) + der_value(False)))]
        for raw in cases:
            with self.subTest(raw=raw[:12]), self.assertRaises(ValidationError):
                decode_der_dictionary(raw)
        with self.assertRaises(ValidationError):
            decode_der_dictionary(der_entitlements({}), profile=True)

    def test_der_dates_must_be_real_exact_utc_and_boundaries_are_unambiguous(self):
        for raw, expected in ((b"491231235959Z", 2049), (b"500101000000Z", 1950)):
            value = decode_der_dictionary(tlv(49, tlv(48, der_value("date") + tlv(23, raw))), profile=True)
            self.assertEqual(value["date"].year, expected)
            self.assertEqual(value["date"].tzinfo, timezone.utc)
        for tag, raw in ((23, b"260230000000Z"), (23, b"260901000060Z"), (24, b"20990101000000+0000"),
                         (24, b"20990101000000.0Z"), (23, b"260901000000")):
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                decode_der_dictionary(tlv(49, tlv(48, der_value("date") + tlv(tag, raw))), profile=True)

    def test_der_size_node_depth_and_deadline_limits(self):
        with patch("mobile_release.ios_der.MAX_DER_BYTES", 8), self.assertRaises(ValidationError):
            decode_der_dictionary(der_entitlements({"x": True}))
        with patch("mobile_release.ios_der.MAX_DER_NODES", 3), self.assertRaises(ValidationError):
            decode_der_dictionary(der_entitlements({"x": True}))
        deep = {}
        for _ in range(70):
            deep = {"next": deep}
        with self.assertRaises(ValidationError):
            decode_der_dictionary(der_entitlements(deep))
        deadline = InspectionDeadline(); deadline._expires_at = 0
        with self.assertRaisesRegex(ValidationError, "shared time bound"):
            decode_der_dictionary(der_entitlements({}), deadline=deadline)

    def test_authoritative_profile_security_changes_cannot_hide_in_outer_plist(self):
        outer = profile()
        for field, changed in (("Entitlements", {**outer["Entitlements"], "private-entitlement-canary": True}),
                               ("DeveloperCertificates", [b"wrong certificate"]), ("TeamIdentifier", ["OTHER12345"]),
                               ("CreationDate", datetime(2021, 1, 1)), ("ExpirationDate", datetime(2098, 1, 1)),
                               ("UUID", "99999999-9999-9999-9999-999999999999"), ("ProvisionedDevices", ["private-device-canary"]),
                               ("ProvisionsAllDevices", True)):
            different = {**outer, field: changed}
            authoritative = decode_der_dictionary(plistlib.loads(modern_profile_bytes(outer, authoritative=different))["DER-Encoded-Profile"], profile=True)
            with self.subTest(field=field), self.assertRaises(ValidationError) as error:
                correlate_profile(outer, authoritative)
            self.assertNotIn("private-", str(error.exception))

    def test_authoritative_profile_missing_security_fields_and_certificate_members_fail(self):
        outer = profile()
        authoritative = decode_der_dictionary(plistlib.loads(modern_profile_bytes(outer))["DER-Encoded-Profile"], profile=True)
        for field in ("Entitlements", "TeamIdentifier", "UUID", "CreationDate", "ExpirationDate", "DeveloperCertificates"):
            for side in ("outer", "authoritative"):
                left, right = dict(outer), dict(authoritative)
                del (left if side == "outer" else right)[field]
                with self.subTest(field=field, side=side), self.assertRaises(ValidationError):
                    correlate_profile(left, right)
        for values in ([], [b""], ["not-bytes"], [b"too-short"], [hashlib.sha256(CERTIFICATE).digest()] * 2):
            with self.subTest(values=values), self.assertRaises(ValidationError):
                correlate_profile(outer, {**authoritative, "DeveloperCertificates": values})


class SignedEntitlementInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-entitlements-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = artifact_set(self.root, detached=False)
        self.exported = self.root / "export/Payload/Reader.app"
        self.native = NativeProfileSeam()
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("mobile_release.ios.sys.platform", "darwin"))
        self.stack.enter_context(patch("mobile_release.ios.shutil.which", return_value="/fictional/native/tool"))
        self.stack.enter_context(patch("mobile_release.ios.subprocess.run", side_effect=self.native))
        self.stack.enter_context(patch("mobile_release.ios_profiles.authenticate_cms", side_effect=self.native.authenticate_cms))
        self.install_profiles()

    def install_profiles(self):
        for root in (self.exported, self.paths["ios-archive"] / "Products/Applications/Reader.app"):
            for bundle in [root, *root.rglob("*.appex"), *root.rglob("*.app")]:
                identity = plistlib.loads((bundle / "Info.plist").read_bytes())["CFBundleIdentifier"]
                (bundle / "embedded.mobileprovision").write_bytes(modern_profile_bytes(profile(bundle_id=identity)))

    def validate(self):
        zip_tree(self.root / "export", self.paths["ios-ipa"])
        return validate_ipa_current_signing(self.paths["ios-ipa"], expected_bundle_id=BUNDLE, expected_team_id=TEAM,
                                            expected_fingerprint=hashlib.sha256(CERTIFICATE).hexdigest(),
                                            release=ReleaseVersion("1.2.3", 42))

    def assert_rejected(self, text=""):
        findings, interval = self.validate()
        self.assertIsNone(interval)
        failures = [item for item in findings if item.status in FAILING_STATUSES]
        self.assertTrue(failures, findings)
        self.assertTrue(any(text in item.message for item in failures), failures)
        self.assertFalse(any("private-native-canary" in item.message for item in findings))
        return failures

    def test_real_zip_plist_der_and_native_inventory_accept_only_each_own_profile(self):
        findings, interval = self.validate()
        self.assertIsNotNone(interval, findings)
        self.assertFalse(any(item.status in FAILING_STATUSES for item in findings))
        names = {Path(argv[-1]).name for argv, _ in self.native.calls if "--entitlements" in argv}
        self.assertTrue({"Reader.app", "Widget.appex", "ReaderKit.framework", "ReaderKit", "libexample.dylib", "helper"} <= names, names)
        self.assertNotIn("Widget", names, "exact declared app executable is already inspected through its bundle")
        self.assertNotIn("Reader", names)
        self.assertTrue(all(not path.exists() for path in self.native.extracted))

    def test_issuer_rejection_in_either_bundle_stops_current_validation_and_public_evidence(self):
        for relative in ("", "PlugIns/Widget.appex"):
            rejected = (self.exported / relative / "embedded.mobileprovision").read_bytes()
            def authenticate(raw, *, deadline):
                if raw == rejected:
                    raise ValidationError("fixed Apple issuer rejection")
                return self.native.authenticate_cms(raw, deadline=deadline)
            with self.subTest(bundle=relative), patch("mobile_release.ios_profiles.authenticate_cms", side_effect=authenticate):
                self.assert_rejected("Apple issuer rejection")
        with patch("mobile_release.ios_profiles.authenticate_cms", side_effect=ValidationError("fixed Apple issuer rejection")):
            with self.assertRaisesRegex(ValidationError, "Apple issuer rejection"):
                ipa_signing_evidence(self.paths["ios-ipa"])

    def test_main_and_extension_app_only_claims_fail_not_parent_profile_adoption(self):
        for name in ("Reader.app", "Widget.appex"):
            identity = BUNDLE if name == "Reader.app" else BUNDLE + ".widget"
            self.native.claims = {name: {**signed_entitlements(identity), "com.apple.developer.associated-domains": ["applinks:private.example"]}}
            with self.subTest(name=name):
                self.assert_rejected("not authorized")
        outer = profile()
        outer["Entitlements"]["com.apple.developer.associated-domains"] = "*"
        (self.exported / "embedded.mobileprovision").write_bytes(modern_profile_bytes(outer))
        self.assert_rejected("not authorized")

    def test_framework_dylib_helper_resource_and_unsupported_xpc_claims_fail(self):
        resource = self.exported / "Resources.bundle/_CodeSignature"
        resource.mkdir(parents=True)
        (resource / "CodeResources").write_bytes(b"fictional signature")
        xpc = self.exported / "Helpers/Worker.xpc"
        xpc.mkdir(parents=True)
        (xpc / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": BUNDLE + ".worker", "CFBundleExecutable": "Worker"}))
        (xpc / "Worker").write_bytes(native_image("Worker"))
        for name in ("ReaderKit.framework", "ReaderKit", "libexample.dylib", "helper", "Resources.bundle", "Worker.xpc", "Worker"):
            self.native.claims = {name: {"private-entitlement-canary": True}}
            with self.subTest(name=name):
                self.assert_rejected("profileless nested code")
        self.native.claims = {}
        self.assertIsNotNone(self.validate()[1], "profileless signed code with no claims is supported")

    def test_nested_watch_style_application_gets_its_own_profile(self):
        watch = self.exported / "Watch/Companion.app"
        shutil.copytree(self.exported / "PlugIns/Widget.appex", watch)
        self.native.claims["Companion.app"] = {**signed_entitlements(BUNDLE + ".widget"), "ungranted": True}
        self.assert_rejected("not authorized")

    def test_nonhost_slice_entitlement_changes_cannot_hide_behind_default_display(self):
        (self.exported / "Reader").write_bytes(fat_image([native_image(), native_image("other-arch", cpu=0x1000007, subtype=3)]))
        self.native.claims[("Reader.app", "16777223,3")] = {**signed_entitlements(), "ungranted": True}
        self.assert_rejected("architectures")
        self.assertIn("16777223,3", {argv[argv.index("--architecture") + 1] for argv, _ in self.native.calls if "--entitlements" in argv})

    def test_nonhost_certificate_mismatch_and_missing_stale_leaf_fail(self):
        binary = self.root / "universal"
        binary.write_bytes(fat_image([native_image(), native_image("other-arch", cpu=0x1000007, subtype=3)]))
        (self.root / "old0").write_bytes(CERTIFICATE)
        self.native.certificates[("universal", "16777223,3")] = b"different certificate"
        with self.assertRaisesRegex(ValidationError, "same leaf signer"):
            _codesign_leaf_fingerprint(binary, self.root / "old")
        self.native.certificates.clear()
        self.native.missing_certificates.add(("universal", "16777223,3"))
        with self.assertRaisesRegex(ValidationError, "could not extract"):
            _codesign_leaf_fingerprint(binary, self.root / "old")
        self.assertEqual((self.root / "old0").read_bytes(), CERTIFICATE)
        self.assertEqual(len(self.native.extracted), len(set(self.native.extracted)))
        self.assertTrue(all(not path.exists() for path in self.native.extracted))

    def test_nonhost_team_mismatch_duplicate_or_invalid_display_fails(self):
        helper = self.exported / "Helpers/helper"
        helper.write_bytes(fat_image([native_image("helper"), native_image("other-helper", cpu=0x1000007, subtype=3)]))
        for output in ("TeamIdentifier=OTHER12345\n", f"TeamIdentifier={TEAM}\nTeamIdentifier={TEAM}\n", "TeamIdentifier=bad\n", ""):
            self.native.teams[("helper", "16777223,3")] = output
            with self.subTest(output=output):
                self.assert_rejected("TeamIdentifier")

    def test_no_entitlements_success_is_not_native_failure_or_primary_authority(self):
        self.native.claims["Reader.app"] = None
        self.assert_rejected("signed entitlements")
        self.native.claims.clear()
        self.native.failures.add(("--entitlements", "ReaderKit.framework", "16777228,0"))
        self.assert_rejected("could not inspect")

    def test_profile_legacy_missing_malformed_and_conflicting_authoritative_der_fail(self):
        location = self.exported / "embedded.mobileprovision"
        for raw in (plistlib.dumps(profile()), plistlib.dumps({**profile(), "DER-Encoded-Profile": b"bad"}),
                    modern_profile_bytes(profile(), authoritative={**profile(), "ProvisionsAllDevices": True})):
            location.write_bytes(raw)
            with self.subTest(raw_prefix=raw[:10]):
                self.assert_rejected()

    def test_malformed_profile_and_native_xml_views_cannot_discard_a_dictionary(self):
        for relative in ("", "PlugIns/Widget.appex"):
            location = self.exported / relative / "embedded.mobileprovision"
            original = location.read_bytes()
            location.write_bytes(add_discardable_root_dictionary(original))
            with self.subTest(profile=relative):
                self.assert_rejected("XML plist")
            location.write_bytes(original)
        real = self.native.__call__
        for bundle in ("Reader.app", "Widget.appex"):
            def malformed(argv, **kwargs):
                result = real(argv, **kwargs)
                if "--xml" in argv and Path(argv[-1]).name == bundle:
                    result.stdout = add_discardable_root_dictionary(result.stdout)
                return result
            with self.subTest(entitlements=bundle), patch("mobile_release.ios.subprocess.run", side_effect=malformed):
                self.assert_rejected("XML plist")

    def test_profile_content_reader_authenticates_exact_outer_and_inner_bytes(self):
        location = self.exported / "embedded.mobileprovision"
        result = _profile_details(location)
        self.assertEqual(result["Entitlements"], profile()["Entitlements"])
        self.assertEqual(self.native.cms_calls, [location.read_bytes(), plistlib.loads(location.read_bytes())["DER-Encoded-Profile"]])
        self.assertTrue(location.is_file())

    def test_all_new_native_profile_slice_calls_receive_no_credentials_or_runtime_injection(self):
        canaries = {key: "private-native-canary" for key in (
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "GOOGLE_APPLICATION_CREDENTIALS", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH_TOKEN",
            "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "OPENSSL_CONF", "BUNDLE_GEMFILE",
        )}
        with patch.dict(os.environ, {**canaries, "PATH": "/fictional/native"}, clear=True):
            findings, interval = self.validate()
        self.assertIsNotNone(interval, findings)
        self.assertTrue(self.native.cms_calls)
        self.assertTrue(any("--architecture" in argv for argv, _ in self.native.calls))
        for argv, kwargs in self.native.calls:
            with self.subTest(operation=argv[0]):
                environment = kwargs["env"]
                self.assertFalse(set(canaries) & environment.keys())
                self.assertNotIn("private-native-canary", environment.values())
                self.assertEqual(environment["PATH"], "/fictional/native")
                self.assertEqual(environment["LC_ALL"], "C")

    def test_safe_basename_and_all_architecture_decode_views_are_enforced(self):
        info = self.exported / "Info.plist"
        original = plistlib.loads(info.read_bytes())
        for name in ("../Reader", "/Reader", "Reader\\other", ".", "", True):
            info.write_bytes(plistlib.dumps({**original, "CFBundleExecutable": name}))
            with self.subTest(name=name):
                self.assert_rejected()
        info.write_bytes(plistlib.dumps(original))
        real = self.native.__call__
        def conflicting(argv, **kwargs):
            result = real(argv, **kwargs)
            if "--xml" in argv:
                result.stdout = plistlib.dumps({"not-the-der-view": True})
            return result
        with patch("mobile_release.ios.subprocess.run", side_effect=conflicting), self.assertRaisesRegex(ValidationError, "DER/XML views disagree"):
            _codesign_entitlements(self.exported)


if __name__ == "__main__":
    unittest.main()
