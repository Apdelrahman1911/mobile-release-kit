"""Credential-free real Apple-tool probes, NOT a distribution-export rehearsal.

These tests never contact a Store, use a protected identity, or modify SDK files.
They run on the actual local Xcode; skipped hosts are not native verification.
"""
from __future__ import annotations

import hashlib
import math
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.ios import _codesign_entitlements
from mobile_release.ios_der import decode_der_dictionary
from mobile_release.ios_entitlements import load_plist_dictionary, typed_value
from mobile_release.ios_artifacts import inspect_ios_artifact_set, snapshot_ios_artifacts
from mobile_release.macho import inspect_macho

from .ios_artifact_helpers import artifact_set, zip_tree
from .ios_entitlement_helpers import binary_dictionary, malformed_binary_cases, supported_xml_lexical_cases


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("plutil"),
                     "native property-list value comparison requires macOS plutil")
class NativePlistTests(unittest.TestCase):
    @staticmethod
    def native_number_bits(data, *, dates=False):
        # Independent oracle over native-generated object bytes. Sending date
        # output through datetime on both sides would hide precision differences.
        width, _, count, _, table = struct.unpack(">6xBBQQQ", data[-32:])
        result = []
        for index in range(count):
            position = int.from_bytes(data[table + index * width:table + (index + 1) * width], "big")
            marker = data[position]
            if dates and marker == 0x33:
                result.append(data[position + 1:position + 9])
            elif not dates and marker in (0x22, 0x23):
                length = 4 if marker == 0x22 else 8
                value = struct.unpack(">f" if marker == 0x22 else ">d", data[position + 1:position + 1 + length])[0]
                result.append(struct.pack(">d", value))
        return result

    def test_native_real_bits_preserve_signed_zero_width_and_finite_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="mrk-native-real-") as directory:
            path = Path(directory) / "owned.plist"
            for value in (-0.0, 0.0, 1.5, -1.5, .1, math.ldexp(1, -149), math.ldexp(1, -1074),
                          float.fromhex("0x1.fffffep127"), float.fromhex("0x1.fffffffffffffp1023")):
                cases = [(plistlib.dumps({"x": value}), value), (binary_dictionary(b"\x23" + struct.pack(">d", value)), value)]
                if abs(value) <= float.fromhex("0x1.fffffep127"):
                    raw = struct.pack(">f", value)
                    cases.append((binary_dictionary(b"\x22" + raw), struct.unpack(">f", raw)[0]))
                for raw, expected in cases:
                    path.write_bytes(raw)
                    with self.subTest(value=value, encoding=raw[:8]):
                        result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                                capture_output=True, timeout=30, check=True)
                        bits = struct.pack(">d", expected)
                        self.assertEqual(self.native_number_bits(result.stdout), [bits])
                        self.assertEqual(struct.pack(">d", load_plist_dictionary(raw)["x"]), bits)

    def test_native_date_bits_and_wide_integer_semantics_are_not_rounded_into_equality(self):
        with tempfile.TemporaryDirectory(prefix="mrk-native-date-") as directory:
            path = Path(directory) / "owned.plist"
            for seconds in (0.0, 1e-6, -1e-6, .123456, -.123456, 810000000.123456, 1e-7, 2e-7, -0.0):
                bits = struct.pack(">d", seconds)
                raw = binary_dictionary(b"\x33" + bits)
                path.write_bytes(raw)
                result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                        capture_output=True, timeout=30, check=True)
                with self.subTest(seconds=seconds):
                    if bits == struct.pack(">d", -0.0):
                        # Native does not retain this spelling as the epoch.
                        self.assertNotEqual(self.native_number_bits(result.stdout, dates=True), [b"\0" * 8])
                    else:
                        self.assertEqual(self.native_number_bits(result.stdout, dates=True), [bits])
                    if seconds in (1e-7, 2e-7) or bits == struct.pack(">d", -0.0):
                        with self.assertRaises(ValidationError):
                            load_plist_dictionary(raw)
                    else:
                        load_plist_dictionary(raw)
            path.write_bytes(binary_dictionary(b"\x14" + b"\xff" * 16))
            result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                    capture_output=True, timeout=30, check=True)
            self.assertEqual(plistlib.loads(result.stdout), {"x": (1 << 64) - 1})
            with self.assertRaises(ValidationError):
                load_plist_dictionary(path.read_bytes())

    def test_native_binary_invalid_markers_and_spans_are_rejected_before_conversion(self):
        cases = malformed_binary_cases()
        with tempfile.TemporaryDirectory(prefix="mrk-native-binary-") as directory:
            path = Path(directory) / "owned.plist"
            for name in ("indexed-fill", "truncated-body-13-0", "truncated-body-23-3",
                         "invalid-length-5f-00", "invalid-length-4f-50", "invalid-length-af-e0", "invalid-length-df-a0"):
                path.write_bytes(cases[name])
                result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                        capture_output=True, timeout=30)
                with self.subTest(case=name):
                    self.assertNotEqual(result.returncode, 0)
                    with self.assertRaises(ValidationError):
                        load_plist_dictionary(cases[name])
            for width in range(1, 9):
                raw = binary_dictionary(b"\x5f\x11\0\x01A", offset_width=width, reference_width=width,
                                        order=[2, 0, 1], padding=b"\0\x0f")
                path.write_bytes(raw)
                result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                        capture_output=True, timeout=30, check=True)
                self.assertEqual(plistlib.loads(result.stdout), {"x": "A"})
                self.assertEqual(load_plist_dictionary(raw), {"x": "A"})

    def test_native_original_numeric_reference_eight_nine_digit_boundary(self):
        with tempfile.TemporaryDirectory(prefix="mrk-native-reference-") as directory:
            path = Path(directory) / "owned.plist"
            for tag in ("string", "key", "real"):
                for hexadecimal in (False, True):
                    for digits in (8, 9):
                        reference = "#x" + "31".zfill(digits) if hexadecimal else "#" + "49".zfill(digits)
                        body = f'<key>&{reference};</key><true/>' if tag == "key" else f'<key>x</key><{tag}>&{reference};</{tag}>'
                        for encoding, bom in (("utf-8", b""), ("utf-8", b"\xef\xbb\xbf"), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                            raw = bom + f'<plist><dict>{body}</dict></plist>'.encode(encoding)
                            path.write_bytes(raw)
                            result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                                    capture_output=True, timeout=30)
                            with self.subTest(tag=tag, reference=reference, encoding=encoding, bom=bool(bom)):
                                if digits == 9:
                                    self.assertNotEqual(result.returncode, 0)
                                    with self.assertRaises(ValidationError):
                                        load_plist_dictionary(raw)
                                else:
                                    self.assertEqual(result.returncode, 0)
                                    expected = {"1": True} if tag == "key" else {"x": 1.0 if tag == "real" else "1"}
                                    self.assertEqual(plistlib.loads(result.stdout), expected)
                                    self.assertEqual(load_plist_dictionary(raw), expected)

    def test_supported_lexical_values_match_actual_native_binary_conversion(self):
        with tempfile.TemporaryDirectory(prefix="mrk-native-plist-") as directory:
            path = Path(directory) / "owned.plist"
            for name, (source, expected) in supported_xml_lexical_cases().items():
                for encoding, bom in (("utf-8", b""), ("utf-8", b"\xef\xbb\xbf"),
                                      ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
                    raw = bom + source.encode(encoding)
                    path.write_bytes(raw)
                    with self.subTest(case=name, encoding=encoding, bom=bool(bom)):
                        result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                                capture_output=True, timeout=30, check=True)
                        native = plistlib.loads(result.stdout)
                        self.assertEqual(native, expected)
                        self.assertEqual(load_plist_dictionary(raw), native)

    def test_native_data_reference_divergence_is_rejected_not_normalized(self):
        with tempfile.TemporaryDirectory(prefix="mrk-native-plist-") as directory:
            path = Path(directory) / "owned.plist"
            raw = b'<plist><dict><key>x</key><data>Y&#81;==</data></dict></plist>'
            path.write_bytes(raw)
            result = subprocess.run(["plutil", "-convert", "binary1", "-o", "-", str(path)],
                                    capture_output=True, timeout=30, check=True)
            self.assertEqual(plistlib.loads(result.stdout), {"x": b"c\xcd"})
            with self.assertRaises(ValidationError):
                load_plist_dictionary(raw)


@unittest.skipUnless(sys.platform == "darwin" and all(shutil.which(name) for name in ("xcrun", "codesign")),
                     "real Apple native tools require a macOS host")
class NativeMachOTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-native-correlation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sdk = self.run_tool("xcrun", "--sdk", "iphoneos", "--show-sdk-path").strip()
        self.source = self.root / "sample.c"
        self.source.write_text("int exported(void){return 3;} int main(void){return exported();}\n")

    @staticmethod
    def run_tool(*argv):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=90)
        if result.returncode:
            raise AssertionError(f"native synthetic tool failed ({argv[0]}, exit {result.returncode}): {result.stderr}")
        return result.stdout

    def compile(self, name="app", *, arch="arm64", library=False, unsigned=False):
        path = self.root / name
        self.run_tool("xcrun", "clang", "-target", f"{arch}-apple-ios15.0", "-isysroot", self.sdk,
                      "-g", str(self.source), *( ["-dynamiclib"] if library else []),
                      *( ["-Wl,-no_adhoc_codesign"] if unsigned else []), "-o", str(path))
        return path

    def sign(self, path, identifier):
        self.run_tool("codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", identifier, str(path))
        self.run_tool("codesign", "--verify", "--strict", str(path))

    @staticmethod
    def signature(path):
        raw = path.read_bytes()
        position = 32
        for _ in range(struct.unpack_from("<I", raw, 16)[0]):
            command, size = struct.unpack_from("<2I", raw, position)
            if command == 0x1D:
                offset, length = struct.unpack_from("<2I", raw, position + 8)
                return offset, length, struct.unpack_from(">I", raw, offset + 4)[0]
            position += size
        raise AssertionError("synthetic signed image lacks signature")

    def test_real_unsigned_and_signature_growth_shrink_with_residual_slack(self):
        for library in (False, True):
            with self.subTest(library=library):
                path = self.compile("library" if library else "app", library=library, unsigned=True)
                original = inspect_macho(path)
                self.sign(path, "com.example." + "long" * 200)
                self.assertEqual(original, inspect_macho(path))
                self.sign(path, "com.example.short")
                self.assertEqual(original, inspect_macho(path))
                offset, length, envelope = self.signature(path)
                raw = bytearray(path.read_bytes())
                self.assertTrue(any(raw[offset + envelope:offset + length]), "native shrink probe must actually exercise retained slack")
                digest = hashlib.sha256(raw).hexdigest()
                raw[offset + length - 1] ^= 1
                path.write_bytes(raw)
                self.run_tool("codesign", "--verify", "--strict", str(path))
                self.assertEqual(original, inspect_macho(path))
                self.assertNotEqual(digest, hashlib.sha256(raw).hexdigest())
                # Allocation slack can differ; newly claiming it as an
                # unindexed part of the SuperBlob must still be rejected.
                struct.pack_into(">I", raw, offset + 4, length)
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValidationError, "envelope"):
                    inspect_macho(path)

    def test_real_fat_resigning_relocates_slices_without_changing_images(self):
        first, second = self.compile(), self.compile("app-arm64e", arch="arm64e")
        fat = self.root / "universal"
        self.run_tool("xcrun", "lipo", "-create", str(first), str(second), "-output", str(fat))
        original = inspect_macho(fat)
        self.assertEqual(len(original), 2)
        self.sign(fat, "com.example." + "large" * 12000)
        self.assertEqual(original, inspect_macho(fat))
        self.sign(fat, "com.example.small")
        self.assertEqual(original, inspect_macho(fat))

    def test_real_native_der_and_nonhost_slice_entitlement_mismatch(self):
        paths = [self.compile(), self.compile("app-arm64e", arch="arm64e")]
        entitlements = self.root / "entitlements.plist"
        original = {"test.example.claim": ["first"], "test.example.number": 1, "test.example.boolean": True}
        for index, path in enumerate(paths):
            claims = {**original, "test.example.claim": ["first" if index == 0 else "second"]}
            entitlements.write_bytes(plistlib.dumps(claims))
            self.run_tool("codesign", "--force", "--sign", "-", "--entitlements", str(entitlements),
                          "--generate-entitlement-der", str(path))
            # Differential proof: independently native-generated DER, parsed
            # without deriving the fixture from our decoder or grant matcher.
            native = subprocess.run(["codesign", "-d", "--entitlements", "-", "--der", str(path)], capture_output=True, timeout=30, check=True)
            self.assertEqual(typed_value(decode_der_dictionary(native.stdout)), typed_value(claims))
        fat = self.root / "universal-entitlements"
        self.run_tool("xcrun", "lipo", "-create", *map(str, paths), "-output", str(fat))
        with self.assertRaisesRegex(ValidationError, "architectures"):
            _codesign_entitlements(fat)
        entitlements.write_bytes(plistlib.dumps(original))
        self.run_tool("codesign", "--force", "--sign", "-", "--entitlements", str(entitlements),
                      "--generate-entitlement-der", str(fat))
        self.run_tool("codesign", "--verify", "--all-architectures", "--strict", str(fat))
        self.assertEqual(_codesign_entitlements(fat), original)

    def test_real_resigned_same_uuid_changed_code_or_linkedit_remains_different(self):
        path = self.compile()
        self.sign(path, "com.example.reader")
        source = path.read_bytes()
        original = inspect_macho(path)
        position, code_offset, string_offset = 32, None, None
        for _ in range(struct.unpack_from("<I", source, 16)[0]):
            command, length = struct.unpack_from("<II", source, position)
            if command == 0x19 and source[position + 8:position + 24].rstrip(b"\0") == b"__TEXT":
                code_offset = struct.unpack_from("<I", source, position + 72 + 48)[0]
            if command == 2:
                string_offset = struct.unpack_from("<I", source, position + 16)[0]
            position += length
        for offset in (code_offset, string_offset + 1):
            with self.subTest(offset=offset):
                altered = bytearray(source)
                altered[offset] ^= 1
                path.write_bytes(altered)
                self.sign(path, "com.example.reader")
                different = inspect_macho(path)
                self.assertEqual(original[0].key, different[0].key)
                self.assertNotEqual(original, different)

    def test_real_sdk_support_copy_unsigned_to_signed_keeps_vendor_original(self):
        toolchain = Path(self.run_tool("xcrun", "--find", "swift").strip()).parents[2]
        vendor = toolchain / "usr/lib/swift-5.0/iphoneos/libswiftCoreGraphics.dylib"
        self.assertTrue(vendor.is_file(), "actual Xcode SDK support library is required for this probe")
        before = hashlib.sha256(vendor.read_bytes()).hexdigest()
        copy = self.root / vendor.name
        shutil.copyfile(vendor, copy)
        original = inspect_macho(copy)
        self.sign(copy, "com.example.synthetic.support")
        self.assertEqual(original, inspect_macho(copy))
        self.assertEqual(before, hashlib.sha256(vendor.read_bytes()).hexdigest())

    def test_real_dsym_and_independently_valid_different_build_pair_rejected(self):
        original = self.compile()
        self.sign(original, "com.example.reader")
        dsym = self.root / "native.dSYM"
        self.run_tool("xcrun", "dsymutil", str(original), "-o", str(dsym))
        symbols = inspect_macho(dsym / "Contents/Resources/DWARF/app", dsym=True)
        self.assertEqual({value.key for value in symbols}, {value.key for value in inspect_macho(original)})
        fixture = self.root / "fixture"
        fixture.mkdir()
        paths = artifact_set(fixture, nested=False, detached=False)
        archived = paths["ios-archive"] / "Products/Applications/Reader.app/Reader"
        exported = fixture / "export/Payload/Reader.app/Reader"
        shutil.copyfile(original, archived)
        shutil.copyfile(original, exported)
        retained = paths["ios-archive"] / "dSYMs"
        shutil.rmtree(retained)
        shutil.copytree(dsym, retained / "Native.dSYM")
        zip_tree(fixture / "export", paths["ios-ipa"])
        with snapshot_ios_artifacts(paths) as snapshot:
            self.assertEqual(inspect_ios_artifact_set(snapshot, expected_bundle_id="com.example.reader", release=ReleaseVersion("1.2.3", 42), symbols_policy="retain")["presentSymbolSlices"], 1)
        self.source.write_text("int main(void){return 4;}\n")
        different = self.compile("other")
        self.sign(different, "com.example.reader")
        shutil.copyfile(different, exported)
        zip_tree(fixture / "export", paths["ios-ipa"])
        with snapshot_ios_artifacts(paths) as snapshot, self.assertRaisesRegex(ValidationError, "Mach-O identity/content differs"):
            inspect_ios_artifact_set(snapshot, expected_bundle_id="com.example.reader", release=ReleaseVersion("1.2.3", 42), symbols_policy="retain")


if __name__ == "__main__":
    unittest.main()
