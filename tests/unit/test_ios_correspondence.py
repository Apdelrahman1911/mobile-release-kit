from __future__ import annotations

import io
import os
import plistlib
import shutil
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch

from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release.ios_artifacts import (
    inspect_ios_artifact_set, safe_extract_zip, snapshot_ios_artifacts, typed_plist,
)
from mobile_release.macho import inspect_macho

from .ios_artifact_helpers import artifact_set, fat_image, native_image, packed_artifact_set, zip_tree


class MachOCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "native"

    def inspect(self, contents: bytes, *, dsym=False):
        self.path.write_bytes(contents)
        return inspect_macho(self.path, dsym=dsym)

    @staticmethod
    def commands(raw):
        position = 32
        result = {}
        for _ in range(struct.unpack_from("<I", raw, 16)[0]):
            command, length = struct.unpack_from("<II", raw, position)
            result.setdefault(command, []).append(position)
            position += length
        return result

    def test_thin_endianness_width_signature_only_and_unsigned_correspondence(self):
        for wide in (False, True):
            for endian in ("<", ">"):
                with self.subTest(wide=wide, endian=endian):
                    original = self.inspect(native_image(wide=wide, endian=endian))
                    self.assertEqual(original, self.inspect(native_image(wide=wide, endian=endian, signature=b"other larger signing data")))
                    self.assertEqual(original, self.inspect(native_image(wide=wide, endian=endian, signature=None)))
                    changed = self.inspect(native_image(wide=wide, endian=endian, code=b"DIFFERENT instructions"))
                    self.assertEqual(original[0].uuid, changed[0].uuid)
                    self.assertNotEqual(original, changed)

    def test_fat_reordered_relocated_slices_and_both_container_widths(self):
        for endian in ("<", ">"):
            for wide in (False, True):
                a = native_image(subtype=0)
                b = native_image(subtype=2)
                original = self.inspect(fat_image([a, b], wide=wide, endian=endian))
                resigned = self.inspect(fat_image([native_image(subtype=2, signature=b"x" * 9000), a], wide=wide, endian=endian, reverse=True))
                self.assertEqual(original, resigned)

    def test_same_uuid_cannot_hide_linkedit_header_flags_commands_or_unreferenced_gap_bytes(self):
        source = native_image()
        original = self.inspect(source)
        # All are ordinary included bytes, even the gap outside section data.
        for index in (24, 1024, 2048, 4113):
            with self.subTest(index=index):
                altered = bytearray(source)
                altered[index] ^= 1
                other = self.inspect(altered)
                self.assertEqual(original[0].key, other[0].key)
                self.assertNotEqual(original[0].image_sha256, other[0].image_sha256)

    def test_malformed_native_structures_fail_closed(self):
        source = native_image()
        commands = self.commands(source)
        signature = commands[0x1D][0]
        link = commands[0x19][1]
        uuid_command = commands[0x1B][0]
        patches = {
            "command count": (16, "I", 4097),
            "command bytes": (20, "I", len(source)),
            "unknown command": (uuid_command, "I", 0x123456),
            "unaligned command": (uuid_command + 4, "I", 23),
            "zero UUID 1": (uuid_command + 8, "Q", 0),
            "signature start": (signature + 8, "I", 1024),
            "signature size": (signature + 12, "I", len(source)),
            "linkedit exec": (link + 56, "I", 5),
            "linkedit virtual size": (link + 32, "Q", 999),
            "linkedit overlap": (link + 40, "Q", 2048),
            "section outside parent": (32 + 72 + 48, "I", 4096),
            "section virtual overflow": (32 + 72 + 40, "Q", 2**63),
            "symbol table outside linkedit": (commands[2][0] + 8, "I", 1024),
        }
        for name, (offset, fmt, value) in patches.items():
            with self.subTest(name=name):
                altered = bytearray(source)
                struct.pack_into("<" + fmt, altered, offset, value)
                if name == "zero UUID 1":
                    struct.pack_into("<Q", altered, offset + 8, 0)
                with self.assertRaises(ValidationError):
                    self.inspect(altered)
        for raw in (source[:27], source[:-1], source + b"extra", source[:500]):
            with self.assertRaises(ValidationError):
                self.inspect(raw)

    def test_signature_envelope_code_limit_and_index_bounds(self):
        raw = native_image()
        sig = struct.unpack_from("<I", raw, self.commands(raw)[0x1D][0] + 8)[0]
        for offset, value in ((0, 0), (4, 0xFFFFFFFF), (8, 513), (16, 0),
                              (20, 0), (24, 0xFFFFFFFF), (20 + 32, 1024), (20 + 28, 1)):
            with self.subTest(offset=offset):
                altered = bytearray(raw)
                struct.pack_into(">I", altered, sig + offset, value)
                with self.assertRaises(ValidationError):
                    self.inspect(altered)

    def test_fat_duplicate_cpu_overlap_padding_and_disagreement(self):
        with self.assertRaises(ValidationError):
            self.inspect(fat_image([native_image(), native_image()]))
        source = fat_image([native_image(), native_image(subtype=2)])
        for name, offset, value in (("overlap", 36, 4096), ("cpu mismatch", 8, 7), ("alignment", 24, 31)):
            with self.subTest(name=name):
                bad = bytearray(source)
                struct.pack_into(">I", bad, offset, value)
                with self.assertRaises(ValidationError):
                    self.inspect(bad)
        bad = bytearray(source)
        bad[128] = 1
        with self.assertRaises(ValidationError):
            self.inspect(bad)

    def test_dsym_is_not_a_signable_image_and_supports_virtual_sections_and_later_dwarf(self):
        symbols = self.inspect(native_image(dsym=True), dsym=True)
        self.assertEqual(symbols[0].key, self.inspect(native_image())[0].key)
        self.assertIsNone(symbols[0].image_sha256)
        for contents, dsym in ((native_image(), True), (native_image(dsym=True), False)):
            with self.assertRaises(ValidationError):
                self.inspect(contents, dsym=dsym)
        bad = bytearray(native_image(dsym=True))
        dwarf_segment = self.commands(bad)[0x19][-1]
        struct.pack_into("<I", bad, dwarf_segment + 72 + 48, 999999)
        with self.assertRaises(ValidationError):
            self.inspect(bad, dsym=True)

    def test_preserved_vendor_llvm_segment_is_hashed_not_stripped_or_ignored(self):
        raw = bytearray(native_image(file_type=6))
        count, size = struct.unpack_from("<II", raw, 16)
        # Split the original file-backed __TEXT container so an independent
        # vendor __LLVM segment owns the next 2 KiB. No referenced data moves.
        struct.pack_into("<Q", raw, 32 + 32, 2048)
        struct.pack_into("<Q", raw, 32 + 48, 2048)
        segment = struct.pack("<II16sQQQQIIII", 0x19, 152, b"__LLVM",
                              0x10800, 2048, 2048, 2048, 1, 1, 1, 0)
        segment += struct.pack("<16s16sQQ8I", b"__bitcode", b"__LLVM",
                               0x10800, 32, 2048, 2, 0, 0, 0, 0, 0, 0)
        raw[32 + size:32 + size + len(segment)] = segment
        struct.pack_into("<II", raw, 16, count + 1, size + len(segment))
        raw[2048:2080] = b"preserved vendor LLVM content".ljust(32, b"\0")
        original = self.inspect(raw)
        raw[2048] ^= 1
        changed = self.inspect(raw)
        self.assertEqual(original[0].key, changed[0].key)
        self.assertNotEqual(original, changed)


class IOSSetCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def inspect(self, paths, *, policy="retain"):
        with snapshot_ios_artifacts(paths) as snapshot:
            return inspect_ios_artifact_set(snapshot, expected_bundle_id="com.example.reader",
                                            release=ReleaseVersion("1.2.3", 42), symbols_policy=policy)

    def test_full_nested_pair_both_tree_and_packed_symbols_correspond(self):
        for packed in (False, True):
            with self.subTest(packed=packed):
                root = self.root / str(packed)
                root.mkdir()
                paths = (packed_artifact_set if packed else artifact_set)(root)
                self.assertEqual(self.inspect(paths), {"nativePaths": 5, "nativeIdentities": 5, "presentSymbolSlices": 5})

    def test_main_extension_framework_dylib_and_helper_substitution_independently_rejected(self):
        for relative in ("Reader", "PlugIns/Widget.appex/Widget", "Frameworks/ReaderKit.framework/ReaderKit",
                         "Frameworks/libexample.dylib", "Helpers/helper"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                paths = artifact_set(root)
                changed = root / "export/Payload/Reader.app" / relative
                original = changed.read_bytes()
                changed.write_bytes(original[:1024] + b"X" + original[1025:])  # same UUID, other code
                zip_tree(root / "export", paths["ios-ipa"])
                with self.assertRaisesRegex(ValidationError, "Mach-O identity/content differs"):
                    self.inspect(paths)

    def test_archive_substitution_and_symbol_substitution_are_independent(self):
        for where in ("archive", "archive-symbol", "detached-symbol"):
            with self.subTest(where=where), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                paths = artifact_set(root)
                if where == "archive":
                    (paths["ios-archive"] / "Products/Applications/Reader.app/Reader").write_bytes(native_image(code=b"unrelated archive"))
                elif where == "archive-symbol":
                    (paths["ios-archive"] / "dSYMs/Reader.dSYM/Contents/Resources/DWARF/Reader").write_bytes(native_image("other", dsym=True))
                else:
                    (paths["ios-dsyms"] / "Reader.dSYM/Contents/Resources/DWARF/Reader").write_bytes(native_image("other", dsym=True))
                with self.assertRaises(ValidationError):
                    self.inspect(paths)

    def test_changed_resource_bundle_identity_typed_values_and_layout_rejected(self):
        for where in ("resource", "framework-id", "app-version", "typed-plist", "extra-helper", "missing-extension", "rename-framework"):
            with self.subTest(where=where), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                paths = artifact_set(root)
                app = root / "export/Payload/Reader.app"
                if where == "resource":
                    (app / "resource.txt").write_text("different")
                elif where == "extra-helper":
                    (app / "extra").write_bytes(native_image("extra"))
                elif where == "missing-extension":
                    shutil.rmtree(app / "PlugIns")
                elif where == "rename-framework":
                    (app / "Frameworks/ReaderKit.framework").rename(app / "Frameworks/Different.framework")
                else:
                    info = app / ("Frameworks/ReaderKit.framework/Info.plist" if where == "framework-id" else "Info.plist")
                    data = plistlib.loads(info.read_bytes())
                    if where == "framework-id":
                        data["CFBundleIdentifier"] += ".wrong"
                    elif where == "app-version":
                        data["CFBundleVersion"] = "43"
                    else:
                        data["CFBundleVersion"] = 42
                    info.write_bytes(plistlib.dumps(data))
                zip_tree(root / "export", paths["ios-ipa"])
                with self.assertRaises(ValidationError):
                    self.inspect(paths)

    def test_xml_binary_plists_equivalent_but_typed_inequality_not_collapsed(self):
        paths = artifact_set(self.root)
        info = self.root / "export/Payload/Reader.app/Info.plist"
        info.write_bytes(plistlib.dumps(plistlib.loads(info.read_bytes()), fmt=plistlib.FMT_BINARY))
        zip_tree(self.root / "export", paths["ios-ipa"])
        self.assertEqual(self.inspect(paths)["nativePaths"], 5)
        for a, b in ((True, 1), (b"one", "one"), (1, 1.0)):
            first, second = self.root / "a.plist", self.root / "b.plist"
            first.write_bytes(plistlib.dumps({"value": a}))
            second.write_bytes(plistlib.dumps({"value": b}))
            self.assertNotEqual(typed_plist(first), typed_plist(second))

    def test_duplicate_xml_and_binary_plist_keys_rejected(self):
        path = self.root / "Info.plist"
        path.write_bytes(b'<plist version="1.0"><dict><key>x</key><integer>1</integer><key>x</key><integer>2</integer></dict></plist>')
        with self.assertRaises(ValidationError):
            typed_plist(path)
        # Hand-built binary dictionary with two references to the same key.
        objects = b"\xd2\x01\x01\x02\x03\x51x\x10\x01\x10\x02"
        offsets = bytes((8, 13, 15, 17))
        trailer = b"\0" * 6 + bytes((1, 1)) + struct.pack(">3Q", 4, 0, 19)
        path.write_bytes(b"bplist00" + objects + offsets + trailer)
        self.assertEqual(plistlib.loads(path.read_bytes()), {"x": 2})  # default silently overwrites
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            typed_plist(path)
        for content in (b"bplist00", b"<plist><dict>", plistlib.dumps({"x": float("nan")}), plistlib.dumps({"x": plistlib.UID(1)}, fmt=plistlib.FMT_BINARY)):
            path.write_bytes(content)
            with self.assertRaises(ValidationError):
                typed_plist(path)

    def test_duplicate_identical_code_paths_allowed_conflicting_uuid_and_duplicate_dsyms_rejected(self):
        paths = artifact_set(self.root)
        original = paths["ios-archive"] / "Products/Applications/Reader.app/Frameworks/ReaderKit.framework"
        exported = self.root / "export/Payload/Reader.app/Frameworks/ReaderKit.framework"
        for source in (original, exported):
            shutil.copytree(source, source.parent / "Copy.framework")
        zip_tree(self.root / "export", paths["ios-ipa"])
        result = self.inspect(paths)
        self.assertEqual((result["nativePaths"], result["nativeIdentities"]), (6, 5))
        for source in (original, exported):
            (source.parent / "Copy.framework/ReaderKit").write_bytes(native_image("ReaderKit", code=b"different", file_type=6))
        zip_tree(self.root / "export", paths["ios-ipa"])
        with self.assertRaisesRegex(ValidationError, "conflicting"):
            self.inspect(paths)
        for source in (original, exported):
            shutil.rmtree(source.parent / "Copy.framework")
        zip_tree(self.root / "export", paths["ios-ipa"])
        shutil.copytree(paths["ios-archive"] / "dSYMs/ReaderKit.dSYM", paths["ios-archive"] / "dSYMs/Copy.dSYM")
        with self.assertRaisesRegex(ValidationError, "duplicated"):
            self.inspect(paths)

    def test_present_symbols_always_validated_main_policy_and_mrk009_missing_nested_boundary(self):
        paths = artifact_set(self.root, detached=False)
        shutil.rmtree(paths["ios-archive"] / "dSYMs/helper.dSYM")
        # This issue validates present symbols; MRK-009 will enforce missing
        # nested/per-slice coverage. Do not disguise that still-open limitation.
        self.assertEqual(self.inspect(paths)["presentSymbolSlices"], 4)
        shutil.rmtree(paths["ios-archive"] / "dSYMs/Reader.dSYM")
        with self.assertRaisesRegex(ValidationError, "main-app"):
            self.inspect(paths)
        self.assertEqual(self.inspect(paths, policy="disabled")["presentSymbolSlices"], 3)
        (paths["ios-archive"] / "dSYMs/Widget.dSYM/Contents/Resources/DWARF/Widget").write_bytes(native_image("unknown", dsym=True))
        with self.assertRaises(ValidationError):
            self.inspect(paths, policy="disabled")

    def test_missing_archive_rejected_under_all_symbol_policies(self):
        paths = artifact_set(self.root)
        del paths["ios-archive"]
        for policy in ("disabled", "retain", "required"):
            with self.subTest(policy=policy), self.assertRaisesRegex(ValidationError, "retained xcarchive"):
                self.inspect(paths, policy=policy)

    def test_native_payload_cannot_hide_in_signature_profile_exclusions(self):
        paths = artifact_set(self.root)
        app = self.root / "export/Payload/Reader.app"
        for name in ("_CodeSignature/CodeResources", "embedded.mobileprovision", "_CodeSignature/extra"):
            with self.subTest(name=name):
                destination = app / name
                previous = destination.read_bytes() if destination.exists() else None
                destination.write_bytes(native_image("hidden"))
                zip_tree(self.root / "export", paths["ios-ipa"])
                with self.assertRaises(ValidationError):
                    self.inspect(paths)
                if previous is None:
                    destination.unlink()
                else:
                    destination.write_bytes(previous)

    def test_swift_support_extra_architecture_resigning_and_strict_counterparts(self):
        paths = artifact_set(self.root, detached=False)
        support = fat_image([native_image("runtime", file_type=6, signature=None),
                             native_image("runtime", subtype=2, file_type=6, signature=None)])
        for root in (paths["ios-archive"], self.root / "export"):
            directory = root / "SwiftSupport/iphoneos"
            directory.mkdir(parents=True)
            (directory / "libexample.dylib").write_bytes(support)
        zip_tree(self.root / "export", paths["ios-ipa"])
        self.assertEqual(self.inspect(paths)["nativePaths"], 5)
        source = self.root / "export/SwiftSupport/iphoneos/libexample.dylib"
        for contents in (native_image("unrelated", file_type=6), native_image("runtime", file_type=6, code=b"other"), native_image("runtime", file_type=6, signature=None)):
            with self.subTest(size=len(contents)):
                source.write_bytes(contents)
                zip_tree(self.root / "export", paths["ios-ipa"])
                with self.assertRaises(ValidationError):
                    self.inspect(paths)
        source.write_bytes(support)
        source.rename(source.with_name("unknown.dylib"))
        zip_tree(self.root / "export", paths["ios-ipa"])
        with self.assertRaises(ValidationError):
            self.inspect(paths)

    def test_unimplemented_ancillary_roots_fail_clearly(self):
        paths = artifact_set(self.root)
        for root in ("WatchKitSupport2", "OnDemandResources", "BCSymbolMaps", "Unknown"):
            folder = self.root / "export" / root
            folder.mkdir()
            (folder / "data").write_bytes(b"unsupported")
            zip_tree(self.root / "export", paths["ios-ipa"])
            with self.assertRaisesRegex(ValidationError, "unsupported IPA root"):
                self.inspect(paths)
            shutil.rmtree(folder)

    def test_private_snapshot_prevents_source_aba_and_detects_persistent_changes(self):
        paths = artifact_set(self.root)
        original = paths["ios-ipa"].read_bytes()
        with snapshot_ios_artifacts(paths) as snapshot:
            paths["ios-ipa"].write_bytes(b"other input during validation")
            # Inspector/native callers receive this copy, not the source path.
            self.assertEqual(snapshot.paths["ios-ipa"].read_bytes(), original)
            self.assertNotEqual(snapshot.paths["ios-ipa"], paths["ios-ipa"])
            self.assertEqual(stat.S_IMODE(snapshot.paths["ios-ipa"].stat().st_mode) & 0o222, 0)
            with self.assertRaisesRegex(ValidationError, "changed"):
                snapshot.assert_unchanged()
            paths["ios-ipa"].write_bytes(original)
            self.assertEqual(inspect_ios_artifact_set(snapshot, expected_bundle_id="com.example.reader", release=ReleaseVersion("1.2.3", 42), symbols_policy="retain")["nativePaths"], 5)
            retained_path = snapshot.paths["ios-ipa"]
        self.assertFalse(retained_path.exists())

    def test_input_tree_symlink_fifo_collisions_and_count_limits(self):
        paths = artifact_set(self.root)
        app = paths["ios-archive"] / "Products/Applications/Reader.app"
        for kind in ("symlink", "fifo", "collision"):
            extra = app / ("RESOURCE.TXT" if kind == "collision" else "unsafe")
            if kind == "symlink":
                extra.symlink_to(app / "Reader")
            elif kind == "fifo":
                os.mkfifo(extra)
            else:
                extra.write_bytes(b"collision")
            with self.subTest(kind=kind), self.assertRaises(ValidationError):
                self.inspect(paths)
            extra.unlink()
        with patch("mobile_release.ios_artifacts.MAX_FILES", 2), self.assertRaises(ValidationError):
            self.inspect(paths)


class IOSZipSafetyTests(unittest.TestCase):
    @staticmethod
    def ordinary_zip(count=1, *, comment=b""):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for index in range(count):
                archive.writestr(f"file-{index}", b"correlated fixture")
            archive.comment = comment
        return output.getvalue()

    def rejected_before_zipinfo_allocation(self, raw):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input.zip"
            path.write_bytes(raw)
            with patch("mobile_release.ios_artifacts.zipfile.ZipFile", side_effect=AssertionError("ZipInfo allocation reached")) as parser:
                with self.assertRaises(ValidationError):
                    safe_extract_zip(path, root / "output")
                parser.assert_not_called()
            self.assertFalse((root / "output").exists())

    def test_directory_counts_offsets_and_end_selection_guard_before_allocation(self):
        original = self.ordinary_zip(2)
        # An attacker cannot hide two actual entries behind a one-entry EOCD,
        # introduce a split disk, truncate a range, or exploit parser disagreement.
        for index, value in ((1, 1), (2, 1), (3, 1), (5, 0), (6, 0)):
            end = list(struct.unpack("<4s4H2IH", original[-22:]))
            end[index] = value
            with self.subTest(field=index):
                self.rejected_before_zipinfo_allocation(original[:-22] + struct.pack("<4s4H2IH", *end))
        end = list(struct.unpack("<4s4H2IH", original[-22:]))
        end[3] = end[4] = 1
        self.rejected_before_zipinfo_allocation(original[:-22] + struct.pack("<4s4H2IH", *end))
        with patch("mobile_release.ios_artifacts.MAX_FILES", 1):
            self.rejected_before_zipinfo_allocation(original)
        for raw in (original[:-1], original + b"trailer", b"MZ" + original,
                    self.ordinary_zip(comment=b"comment PK\x05\x06 hidden EOCD")):
            self.rejected_before_zipinfo_allocation(raw)
        directory = struct.unpack("<4s4H2IH", original[-22:])[6]
        for relative, fmt, value in ((28, "H", 0), (30, "H", 65535), (34, "H", 1), (42, "I", directory)):
            bad = bytearray(original)
            struct.pack_into("<" + fmt, bad, directory + relative, value)
            with self.subTest(central=relative):
                self.rejected_before_zipinfo_allocation(bad)

    def test_zip64_end_records_and_local_offsets_are_checked_before_allocation(self):
        original = self.ordinary_zip()
        end = struct.unpack("<4s4H2IH", original[-22:])
        offset = len(original) - 22
        large = (original[:-22] + struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, end[5], end[6])
                 + struct.pack("<4sIQI", b"PK\x06\x07", 0, offset, 1)
                 + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input.zip"
            path.write_bytes(large)
            safe_extract_zip(path, root / "output")
            self.assertEqual((root / "output/file-0").read_bytes(), b"correlated fixture")
        for relative, fmt, value in ((4, "Q", 1 << 63), (16, "I", 1), (24, "Q", 2), (32, "Q", 100001),
                                      (40, "Q", 1 << 40), (60, "I", 1), (64, "Q", 0), (72, "I", 2)):
            bad = bytearray(large)
            struct.pack_into("<" + fmt, bad, offset + relative, value)
            with self.subTest(zip64=relative):
                self.rejected_before_zipinfo_allocation(bad)
        # ZIP64 central-local offset requires an in-bounds single-disk extra,
        # not an implicit fallback to an unchecked 32-bit offset.
        bad = bytearray(original)
        struct.pack_into("<I", bad, end[6] + 42, 0xFFFFFFFF)
        self.rejected_before_zipinfo_allocation(bad)

    def test_zip_entry_path_type_compression_conflicts_and_roots(self):
        cases = (["../escape"], ["/absolute"], ["d/../escape"], ["a\\b"], ["a//b"],
                 ["a", "a"], ["a", "a/b"], ["A/x", "a/y"], ["café/x", "cafe\u0301/y"])
        for names in cases:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                zip_path = root / "input.zip"
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(zip_path, "w") as archive:
                        for name in names:
                            archive.writestr(name, b"value")
                with self.assertRaises(ValidationError):
                    safe_extract_zip(zip_path, root / "output")
                self.assertFalse((root / "escape").exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kind in (stat.S_IFLNK, stat.S_IFIFO):
                zip_path = root / "input.zip"
                with zipfile.ZipFile(zip_path, "w") as archive:
                    info = zipfile.ZipInfo("unsafe")
                    info.external_attr = (kind | 0o777) << 16
                    archive.writestr(info, b"target")
                with self.assertRaises(ValidationError):
                    safe_extract_zip(zip_path, root / "output")

    def test_bounded_central_directory_expansion_and_crc_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "input.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("data", b"payload")
            with patch("mobile_release.ios_artifacts.MAX_ZIP_DIRECTORY", 1), self.assertRaises(ValidationError):
                safe_extract_zip(zip_path, root / "output")
            with patch("mobile_release.ios_artifacts.MAX_FILE_BYTES", 30), self.assertRaises(ValidationError):
                safe_extract_zip(zip_path, root / "output")
            altered = bytearray(zip_path.read_bytes())
            altered[34] ^= 1  # CRC-protected local member payload
            zip_path.write_bytes(altered)
            with self.assertRaises(ValidationError):
                safe_extract_zip(zip_path, root / "output")


class IOSPreflightCorrespondenceTests(unittest.TestCase):
    def test_native_deadline_expiry_is_failed_not_correspondence_pass(self):
        from mobile_release.config import load_config
        from mobile_release.inspection import MAX_INSPECTION_SECONDS
        from mobile_release.preflight import preflight
        from mobile_release.reporting import Report, Status
        from .helpers import ios_config, write_project

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            paths = artifact_set(root)
            original = paths["ios-ipa"].read_bytes()
            private_inputs, phases = [], []
            clock = stack.enter_context(patch("mobile_release.inspection.time.monotonic", return_value=0))
            stack.enter_context(patch("mobile_release.preflight.doctor", return_value=Report("synthetic prerequisites")))

            def native(path, *, deadline, **_kwargs):
                private_inputs.append(path)
                deadline.check()
                clock.return_value = MAX_INSPECTION_SECONDS
                return []

            def checks(_config, phase, **_kwargs):
                phases.append(phase)
                return []

            stack.enter_context(patch("mobile_release.preflight.validate_ipa", side_effect=native))
            stack.enter_context(patch("mobile_release.preflight.run_project_checks", side_effect=checks))
            report = preflight(config, mode="offline", platforms=("ios",), run_builds=False, artifacts=paths)
            findings = [item for item in report.findings if item.code == "ios.artifacts.correspondence"]
            self.assertEqual([item.status for item in findings], [Status.FAIL])
            self.assertIn("shared time bound", findings[0].message)
            self.assertNotIn("iosArtifact", phases)
            self.assertEqual(len(private_inputs), 1)
            self.assertFalse(private_inputs[0].exists())
            self.assertEqual(paths["ios-ipa"].read_bytes(), original)

    def test_real_preflight_pair_gate_and_offline_ipa_only_status(self):
        from mobile_release.config import load_config
        from mobile_release.preflight import preflight
        from mobile_release.reporting import Report, Status
        from .helpers import ios_config, write_project

        for mode, has_archive, mismatch in (("signing", True, False), ("signing", True, True),
                                           ("signing", False, False), ("offline", False, False)):
            with self.subTest(mode=mode, archive=has_archive, mismatch=mismatch), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                root = Path(tmp)
                config = load_config(write_project(root, ios_config(), platform="ios"))
                paths = artifact_set(root)
                if mismatch:
                    (root / "export/Payload/Reader.app/Reader").write_bytes(native_image(code=b"substituted"))
                    zip_tree(root / "export", paths["ios-ipa"])
                if not has_archive:
                    del paths["ios-archive"]
                    del paths["ios-dsyms"]
                stack.enter_context(patch("mobile_release.preflight.doctor", return_value=Report("synthetic prerequisites")))
                stack.enter_context(patch("mobile_release.preflight.credential_findings", return_value=[]))
                stack.enter_context(patch("mobile_release.preflight.validate_signing_material", return_value=[]))
                native = stack.enter_context(patch("mobile_release.preflight.validate_ipa", return_value=[]))
                report = preflight(config, mode=mode, platforms=("ios",), run_builds=False, artifacts=paths)
                correspondence = [item for item in report.findings if item.code == "ios.artifacts.correspondence"]
                self.assertEqual(len(correspondence), 1, report.findings)
                expected = Status.SKIP if mode == "offline" else Status.FAIL if mismatch or not has_archive else Status.PASS
                self.assertEqual(correspondence[0].status, expected)
                if mismatch:
                    native.assert_not_called()
                else:
                    self.assertNotEqual(native.call_args.args[0], paths["ios-ipa"])

    def test_project_artifact_check_cannot_modify_the_original_after_validation(self):
        from mobile_release.config import load_config
        from mobile_release.preflight import preflight
        from mobile_release.reporting import Report, Status
        from .helpers import ios_config, write_project

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            paths = artifact_set(root)
            def checks(_config, phase, *, environ):
                self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", environ)
                self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", environ)
                if phase == "iosArtifact":
                    paths["ios-ipa"].write_bytes(b"modified by a project check")
                return []
            stack.enter_context(patch("mobile_release.preflight.doctor", return_value=Report("synthetic prerequisites")))
            stack.enter_context(patch("mobile_release.preflight.run_project_checks", side_effect=checks))
            stack.enter_context(patch("mobile_release.preflight.validate_ipa", return_value=[]))
            report = preflight(config, mode="offline", platforms=("ios",), run_builds=False, artifacts=paths)
            self.assertEqual([item.status for item in report.findings if item.code == "ios.artifacts.correspondence"], [Status.FAIL])


if __name__ == "__main__":
    unittest.main()
