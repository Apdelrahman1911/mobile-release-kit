"""Credential-free real Apple-tool probes, NOT a distribution-export rehearsal.

These tests never contact a Store, use a protected identity, or modify SDK files.
They run on the actual local Xcode; skipped hosts are not native verification.
"""
from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.ios_artifacts import inspect_ios_artifact_set, snapshot_ios_artifacts
from mobile_release.macho import inspect_macho

from .ios_artifact_helpers import artifact_set, zip_tree


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
