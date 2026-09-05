"""Bound service ZIP parsing without allocating untrusted central directories."""
from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from mobile_release.workflow import (
    MAX_EVIDENCE, MAX_FILES, MAX_ZIP_DIRECTORY, MAX_ZIP_NAME_BYTES,
    WorkflowError, _extract_zip, _validate_zip_directory,
)


class WorkflowZipDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-zip-directory-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "artifact.zip"
        self.destination = self.root / "output"
        self.destination.mkdir()

    def ordinary(self, count=1, *, comment=b"", name=None, extra=b"", member_comment=b"", compression=zipfile.ZIP_DEFLATED):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=compression) as stream:
            for index in range(count):
                member = zipfile.ZipInfo(name or f"file-{index}.json")
                member.compress_type = compression
                member.extra, member.comment = extra, member_comment
                stream.writestr(member, b'{"fixture":true}\n')
            stream.comment = comment
        return data.getvalue()

    def rejected_before_parser(self, body: bytes):
        self.archive.write_bytes(body)
        before = {path.relative_to(self.destination): path.read_bytes() for path in self.destination.rglob("*") if path.is_file()}
        with patch("mobile_release.workflow.zipfile.ZipFile", side_effect=AssertionError("ZipInfo allocation reached")) as parser:
            with self.assertRaises(WorkflowError):
                _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
            parser.assert_not_called()
        self.assertEqual({path.relative_to(self.destination): path.read_bytes() for path in self.destination.rglob("*") if path.is_file()}, before)

    @staticmethod
    def end_changed(body: bytes, **fields):
        # Fixtures produced here have no archive comment unless tested explicitly.
        result = list(struct.unpack("<4s4H2IH", body[-22:]))
        names = ("signature", "disk", "directory_disk", "disk_count", "count", "size", "offset", "comment")
        for key, value in fields.items():
            result[names.index(key)] = value
        return body[:-22] + struct.pack("<4s4H2IH", *result)

    @staticmethod
    def zip64_end(*, count: int, directory_size: int, directory_offset: int, zip64_offset: int):
        return (
            struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, directory_size, directory_offset)
            + struct.pack("<4sIQI", b"PK\x06\x07", 0, zip64_offset, 1)
            + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        )

    def test_entry_count_is_bounded_before_zipfile_construction(self):
        for count in (MAX_FILES + 1, 8192):
            with self.subTest(count=count):
                self.rejected_before_parser(self.ordinary(count))

    def test_forged_small_end_count_cannot_hide_actual_directory_count(self):
        body = self.ordinary(MAX_FILES + 1)
        for count in (1, MAX_FILES):
            with self.subTest(count=count):
                self.rejected_before_parser(self.end_changed(body, count=count, disk_count=count))

    def test_directory_byte_bound_precedes_any_directory_allocation(self):
        # Sparse file: no large test allocation and no payload read is needed.
        size = MAX_ZIP_DIRECTORY + 1
        with self.archive.open("wb") as stream:
            stream.write(b"PK\x03\x04")
            stream.seek(4 + size)
            stream.write(struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, size, 4, 0))
        with patch("mobile_release.workflow.zipfile.ZipFile") as parser:
            with self.assertRaisesRegex(WorkflowError, "bounded size"):
                _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
            parser.assert_not_called()

    def test_invalid_counts_offsets_extents_and_disk_layouts_fail_before_parser(self):
        body = self.ordinary()
        end = struct.unpack("<4s4H2IH", body[-22:])
        for fields in (
            {"count": 0, "disk_count": 0}, {"count": 2, "disk_count": 2},
            {"count": 2}, {"disk": 1}, {"directory_disk": 1},
            {"size": end[5] - 1}, {"size": end[5] + 1}, {"offset": 0},
            {"offset": end[6] + 1}, {"offset": 0xFFFFFFFF},
            {"count": 0xFFFF, "disk_count": 0xFFFF},
        ):
            with self.subTest(fields=fields):
                self.rejected_before_parser(self.end_changed(body, **fields))
        self.rejected_before_parser(body[:-1])
        self.rejected_before_parser(body + b"trailing data")
        self.rejected_before_parser(b"self-extracting prefix" + body)
        # Even offsets adjusted to include a prefix cannot turn it into the
        # supported service format.
        self.rejected_before_parser(self.end_changed(b"MZ" + body, offset=end[6] + 2))

    def test_malformed_central_record_lengths_signatures_and_names_fail_before_parser(self):
        body = self.ordinary()
        offset = struct.unpack("<4s4H2IH", body[-22:])[6]
        for field_offset, packed in ((0, b"BAD!"), (28, struct.pack("<H", 0)), (30, struct.pack("<H", 65535)), (32, struct.pack("<H", 65535)), (34, struct.pack("<H", 1)), (42, struct.pack("<I", offset))):
            modified = bytearray(body)
            modified[offset + field_offset:offset + field_offset + len(packed)] = packed
            with self.subTest(field_offset=field_offset):
                self.rejected_before_parser(bytes(modified))
        self.rejected_before_parser(self.ordinary(name="x" * (MAX_ZIP_NAME_BYTES + 1)))

    def test_maximum_comments_and_bounded_extras_remain_supported(self):
        extra = struct.pack("<HH", 0xCAFE, 65531) + b"x" * 65531
        self.archive.write_bytes(self.ordinary(comment=b"c" * 65535, extra=extra, member_comment=b"m" * 65535))
        _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
        self.assertEqual((self.destination / "file-0.json").read_bytes(), b'{"fixture":true}\n')

    def test_ordinary_stored_deflated_and_descriptor_service_zips_extract(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            destination = self.destination / str(method)
            destination.mkdir()
            self.archive.write_bytes(self.ordinary(count=MAX_FILES, compression=method))
            self.assertEqual(_validate_zip_directory(self.archive), MAX_FILES)
            _extract_zip(self.archive, destination, MAX_EVIDENCE)
            self.assertEqual(len(list(destination.iterdir())), MAX_FILES)
        class Unseekable(io.BytesIO):
            def seekable(self):
                return False
            def seek(self, *_args):
                raise OSError("streaming ZIP fixture")
        data = Unseekable()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            stream.writestr("streamed.json", b"safe streaming payload")
        self.archive.write_bytes(data.getvalue())
        _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
        self.assertEqual((self.destination / "streamed.json").read_bytes(), b"safe streaming payload")

    def test_standard_zip64_end_records_are_supported_without_requiring_large_payloads(self):
        body = self.ordinary()
        end = struct.unpack("<4s4H2IH", body[-22:])
        large = body[:-22] + self.zip64_end(count=1, directory_size=end[5], directory_offset=end[6], zip64_offset=len(body) - 22)
        self.archive.write_bytes(large)
        _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
        self.assertEqual((self.destination / "file-0.json").read_bytes(), b'{"fixture":true}\n')
        for relative, value in ((4, 1 << 63), (16, 1), (24, 2), (32, MAX_FILES + 1), (40, MAX_ZIP_DIRECTORY + 1), (56 + 4, 1), (56 + 8, 0), (56 + 16, 2)):
            modified = bytearray(large)
            size = 4 if relative in (16, 60, 72) else 8
            struct.pack_into("<I" if size == 4 else "<Q", modified, len(body) - 22 + relative, value)
            with self.subTest(relative=relative):
                self.rejected_before_parser(bytes(modified))
        # The toolkit deliberately excludes extended end records from its
        # bounded service profile, even where ZipFile supports extensions.
        modified = bytearray(large)
        struct.pack_into("<Q", modified, len(body) - 22 + 4, 48)
        self.rejected_before_parser(bytes(modified))

    def test_no_comment_end_record_with_signature_bytes_in_its_offset_extracts(self):
        # EOCD's offset can legitimately encode its own PK\x05\x06 signature.
        # Keep the wire file sparse and compute/verify CRC in bounded chunks;
        # the actual extractor must read every byte, not merely pass preflight.
        name = b"padding.bin"
        offset = 0x06054B50
        size = offset - 30 - len(name)
        block, crc, left = b"\0" * (1024 * 1024), 0, size
        while left:
            length = min(left, len(block))
            crc = zlib.crc32(block[:length], crc)
            left -= length
        local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, size, size, len(name), 0) + name
        central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, crc, size, size, len(name), 0, 0, 0, 0, 0, 0) + name
        with self.archive.open("wb") as stream:
            stream.write(local)
            stream.seek(offset)
            stream.write(central)
            stream.write(struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), offset, 0))
        self.assertEqual(_validate_zip_directory(self.archive), 1)
        _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
        extracted = self.destination / "padding.bin"
        self.assertEqual(extracted.stat().st_size, size)
        with extracted.open("rb") as stream:
            actual_crc = 0
            while data := stream.read(len(block)):
                actual_crc = zlib.crc32(data, actual_crc)
        self.assertEqual(actual_crc, crc)

    def test_sparse_over_four_gib_zip64_offsets_do_not_require_large_allocations(self):
        # Two tiny stored files separated by a sparse >4GiB interval exercise
        # 64-bit central/local offsets through the actual stdlib parser. No
        # multi-gigabyte allocation/read/extraction or shared cache is involved.
        first, second = self.ordinary(name="first.json", compression=zipfile.ZIP_STORED), self.ordinary(name="second.json", compression=zipfile.ZIP_STORED)
        first_end, second_end = (struct.unpack("<4s4H2IH", body[-22:]) for body in (first, second))
        second_offset = (1 << 32) + 128
        directory_offset = second_offset + second_end[6]
        second_directory = bytearray(second[second_end[6]:-22])
        struct.pack_into("<I", second_directory, 42, 0xFFFFFFFF)
        struct.pack_into("<H", second_directory, 30, 12)
        second_directory += struct.pack("<HHQ", 1, 8, second_offset)
        directory = first[first_end[6]:-22] + second_directory
        with self.archive.open("wb") as stream:
            stream.write(first[:first_end[6]])
            stream.seek(second_offset)
            stream.write(second[:second_end[6]])
            stream.write(directory)
            stream.write(self.zip64_end(count=2, directory_size=len(directory), directory_offset=directory_offset, zip64_offset=directory_offset + len(directory)))
        self.assertGreater(self.archive.stat().st_size, 1 << 32)
        self.assertEqual(_validate_zip_directory(self.archive), 2)
        _extract_zip(self.archive, self.destination, MAX_EVIDENCE)
        self.assertEqual({path.name: path.read_bytes() for path in self.destination.iterdir()}, {name: b'{"fixture":true}\n' for name in ("first.json", "second.json")})


if __name__ == "__main__":
    unittest.main()
