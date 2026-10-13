"""In-memory archive DATA regressions; no supplier/native/network operation.

The archive writer libraries create synthetic bytes ONLY. The actual scanner
never opens/extracts paths, runs a vendor, resets an owner's clock or closes
an original. These tests do not supply official correspondence evidence.
"""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile
import unittest
from unittest import mock
import zipfile
import zlib

_SOURCE = Path(__file__).resolve().parents[2] / "desktop/tools/macos_android_supplier_correspondence.py"
_NAME = "mrk_macos_supplier_correspondence_data_tests"
_SPEC = importlib.util.spec_from_file_location(_NAME, _SOURCE)
M = importlib.util.module_from_spec(_SPEC)
# Dataclass annotations need the actual definition module, not a fake provider.
if _NAME in sys.modules:
    raise RuntimeError("unexpected correspondence test module collision")
sys.modules[_NAME] = M
_SPEC.loader.exec_module(M)

class Original:
    def __init__(self, data):
        self.data = data
        self.calls = []
        self.deadline = False
        self.changed = False
        self.short = False
        self.checks = 0
        self.bindings = 0
    def checkpoint(self):
        self.checks += 1
        if self.deadline:
            raise M.Refused("original_endpoint")
    def verify_binding(self):
        self.bindings += 1
        if self.changed:
            raise M.Refused("original_binding")
    def read_at(self, at, count):
        self.calls.append((at, count))
        result = self.data[at:at + count]
        return result[:-1] if self.short and result else result

def pin(data, label="gradle"):
    return M.Pin(label, len(data), hashlib.sha256(data).hexdigest())

def zip_bytes(rows, descriptor=False, method=zipfile.ZIP_DEFLATED):
    class Streaming:
        def __init__(self): self.data = bytearray()
        def tell(self): return len(self.data)
        def seek(self, *_): raise OSError("in-memory nonseekable fixture")
        def write(self, data): self.data.extend(data); return len(data)
        def flush(self): pass
    output = Streaming() if descriptor else io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data, mode in rows:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = method
            archive.writestr(info, data)
    return bytes(output.data) if descriptor else output.getvalue()

def tar_bytes(rows, pax=None, format_=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=format_) as archive:
        for name, data, kind, target in rows:
            info = tarfile.TarInfo(name)
            info.mode = 0o755
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            info.linkname = target
            if pax:
                info.pax_headers = pax.copy()
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return gzip.compress(output.getvalue(), mtime=0)


def zip_extra_bytes(local_extra, central_extra):
    """One inert Stored ZIP with deliberately independent header extras."""
    name = b"data"
    data = b"x"
    crc = zlib.crc32(data)
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, 0, 0,
                        crc, 1, 1, len(name), len(local_extra)) + name + local_extra + data
    central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 0x0314, 20, 0, 0, 0, 0,
                          crc, 1, 1, len(name), len(central_extra), 0, 0, 0,
                          0o100644 << 16, 0) + name + central_extra
    return local + central + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1,
                                          len(central), len(local), 0)

def tar_header_change(tar, offset, changes):
    """Repair only the inert tar header checksum after explicit DATA edits."""
    out = bytearray(tar)
    for at, value in changes:
        out[offset + at:offset + at + len(value)] = value
    out[offset + 148:offset + 156] = b"        "
    checksum = sum(out[offset:offset + 512])
    out[offset + 148:offset + 156] = ("%06o\0 " % checksum).encode("ascii")
    return bytes(out)

def publish(raw, label="gradle"):
    owner = Original(raw)
    report = M.compile_archive(owner, pin(raw, label))
    output = []
    receipt = report.publish(output.append)
    return owner, report, json.loads(output[0]), receipt

class CorrespondenceDataTests(unittest.TestCase):
    def test_zip_all_members_modes_and_same_original_extent_are_bound(self):
        raw = zip_bytes([("dist/", b"", stat.S_IFDIR | 0o755),
                         ("dist/launch", b"#!/bin/sh\n", stat.S_IFREG | 0o755),
                         ("dist/A$Inner.class", b"\xca\xfe\xba\xbe\x00", stat.S_IFREG | 0o644)])
        owner, report, data, receipt = publish(raw)
        self.assertFalse(data["supplierAuthority"])
        self.assertFalse(data["nativeClosure"])
        self.assertTrue(data["completeMemberHashes"])
        self.assertEqual(data["members"], 3)
        self.assertEqual(data["files"], 2)
        rows = {r[0]: dict(zip(data["columns"], r)) for r in data["rows"]}
        row = rows["dist/A$Inner.class"]
        self.assertEqual(row["sha256"], hashlib.sha256(b"\xca\xfe\xba\xbe\x00").hexdigest())
        self.assertEqual(rows["dist/launch"]["mode"], stat.S_IFREG | 0o755)
        self.assertEqual(rows["dist/launch"]["formatHint"], "shell")
        self.assertGreater(row["dataOffset"], row["localHeaderOffset"])
        self.assertEqual(receipt["issuedReadBytes"], sum(n for _, n in owner.calls))
        self.assertTrue(all(n <= M.WINDOW for _, n in owner.calls))
        self.assertGreaterEqual(owner.bindings, 6)
        with self.assertRaisesRegex(M.Refused, "report_finality"):
            report.publish(lambda _: self.fail("second publication"))

        # The observed legacy sentinel stays raw inert directory DATA. No mode
        # is normalized or granted to a path, and ordinary Pin stays strict.
        def directory_sentinel(rows, method=zipfile.ZIP_STORED):
            body = bytearray(zip_bytes(rows, method=method))
            at = struct.unpack_from("<I", body, len(body) - 6)[0]
            for _ in rows:
                self.assertEqual(body[at:at + 4], b"PK\x01\x02")
                name_len, extra_len, comment_len = struct.unpack_from("<3H", body, at + 28)
                name = body[at + 46:at + 46 + name_len]
                if name.endswith(b"/"):
                    struct.pack_into("<I", body, at + 38, 0xffff0010)
                at += 46 + name_len + extra_len + comment_len
            self.assertEqual(at, len(body) - 22)
            return bytes(body)

        sentinel = directory_sentinel([("META-INF/maven/", b"", stat.S_IFDIR | 0o755)])
        owner = Original(sentinel)
        report = M.compile_opaque_zip(owner, M.OpaqueZipPin(len(sentinel), hashlib.sha256(sentinel).hexdigest()))
        output = []
        receipt = report.publish(output.append)
        self.assertEqual(len(output), 1)
        data = json.loads(output[0])
        self.assertEqual(data["kind"], "offline-opaque-zip-correspondence-data")
        self.assertIsNone(data["label"])
        self.assertFalse(data["supplierAuthority"])
        self.assertFalse(data["nativeClosure"])
        self.assertTrue(data["completeMemberHashes"])
        self.assertEqual((data["members"], data["files"], data["aliases"], data["expandedBytes"]), (1, 0, 0, 0))
        self.assertEqual(tuple(data["columns"]), M.COLUMNS)
        row = dict(zip(data["columns"], data["rows"][0]))
        self.assertEqual((row["name"], row["kind"], row["mode"], row["creatorSystem"]),
                         ("META-INF/maven", "directory", 65535, 3))
        self.assertEqual((row["size"], row["compressedSize"], row["crc32"], row["flags"], row["method"]),
                         (0, 0, 0, 0, 0))
        self.assertIsNone(row["sha256"])
        self.assertIsNone(row["formatHint"])
        self.assertEqual((receipt["bytes"], receipt["sha256"]),
                         (len(output[0]), hashlib.sha256(output[0]).hexdigest()))
        self.assertEqual(receipt["issuedReadBytes"], sum(n for _, n in owner.calls))
        self.assertTrue(all(n <= M.WINDOW for _, n in owner.calls))
        self.assertGreaterEqual(owner.bindings, 6)
        with self.assertRaisesRegex(M.Refused, "report_finality"):
            report.publish(lambda _: self.fail("second opaque publication"))
        for label in ("gradle", "bundletool"):
            with self.subTest(sentinel_strict_label=label), self.assertRaisesRegex(M.Refused, "zip_member_mode_or_creator"):
                publish(sentinel, label)

        def refuse_sentinel(body, reason):
            with self.assertRaisesRegex(M.Refused, reason):
                M.compile_opaque_zip(Original(body), M.OpaqueZipPin(len(body), hashlib.sha256(body).hexdigest()))

        central = struct.unpack_from("<I", sentinel, len(sentinel) - 6)[0]
        for field, value, format_ in (
            (38, 0xffff0000, "<I"), (38, 0xfffe0010, "<I"), (38, 0xffff0011, "<I"),
            (4, 20, "<H"), (4, (19 << 8) | 20, "<H"),
            (8, 0x800, "<H"), (8, 8, "<H"), (10, 8, "<H"), (16, 1, "<I"),
        ):
            damaged = bytearray(sentinel)
            struct.pack_into(format_, damaged, central + field, value)
            with self.subTest(sentinel_field=field, value=value):
                refuse_sentinel(bytes(damaged), "zip_member_mode_or_creator")
        refuse_sentinel(sentinel.replace(b"META-INF/maven/", b"META-INF/mavenX"),
                        "zip_member_mode_or_creator")
        refuse_sentinel(directory_sentinel([("META-INF/maven/", b"x", stat.S_IFDIR | 0o755)]),
                        "zip_member_mode_or_creator")
        refuse_sentinel(directory_sentinel([("META-INF/maven/", b"", stat.S_IFDIR | 0o755)],
                                           method=zipfile.ZIP_DEFLATED), "zip_member_mode_or_creator")
        for offset in (14, 18, 22):
            damaged = bytearray(sentinel)
            struct.pack_into("<I", damaged, offset, 1)
            with self.subTest(sentinel_local_field=offset):
                refuse_sentinel(bytes(damaged), "zip_local_sizes_or_extent")
        for name in ("../maven/", "/META-INF/maven/", "META-INF/../maven/"):
            with self.subTest(sentinel_path=name):
                refuse_sentinel(directory_sentinel([(name, b"", stat.S_IFDIR | 0o755)]),
                                "opaque_zip_name_structure")
        duplicate = directory_sentinel([("META-INF/maven/", b"", stat.S_IFDIR | 0o755),
                                        ("META-INF/mavez/", b"", stat.S_IFDIR | 0o755)])
        self.assertEqual(duplicate.count(b"META-INF/mavez/"), 2)
        refuse_sentinel(duplicate.replace(b"META-INF/mavez/", b"META-INF/maven/"),
                        "duplicate_or_case_colliding_member")
        refuse_sentinel(directory_sentinel([("META-INF", b"file", stat.S_IFREG | 0o644),
                                            ("META-INF/maven/", b"", stat.S_IFDIR | 0o755)]),
                        "non_directory_member_parent")
        refuse_sentinel(sentinel.replace(b"META-INF/maven/", b"META-INF/mavez/", 1),
                        "zip_local_name_disagreement")

    def test_descriptor_and_stored_archives_use_the_same_member_hash(self):
        for descriptor in (False, True):
            for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(descriptor=descriptor, method=method):
                    raw = zip_bytes([("a", b"payload" * 12000, stat.S_IFREG | 0o644),
                                     ("empty/", b"", stat.S_IFDIR | 0o755)],
                                    descriptor=descriptor, method=method)
                    _, _, data, _ = publish(raw)
                    self.assertEqual(data["rows"][0][4], hashlib.sha256(b"payload" * 12000).hexdigest())
                    directory = dict(zip(data["columns"], data["rows"][1]))
                    self.assertEqual((directory["kind"], directory["size"], directory["sha256"]),
                                     ("directory", 0, None))
                    self.assertEqual(bool(directory["flags"] & 8), descriptor)

        def inspect_inner(raw):
            report = M.compile_opaque_zip(Original(raw), M.OpaqueZipPin(
                len(raw), hashlib.sha256(raw).hexdigest()))
            rows = []
            summary = report.consume_rows(rows.append)
            return {**summary, "rows": rows, "columns": M.COLUMNS}

        # Java's empty META-INF directory: DOS creator, no mode, UTF-8 plus
        # descriptor, and the two-byte empty DEFLATE framing. No vendor code.
        java = bytearray(zip_bytes([("META-INF/", b"", stat.S_IFDIR | 0o755)], descriptor=True))
        central = java.index(b"PK\x01\x02")
        descriptor_at = java.index(b"PK\x07\x08")
        struct.pack_into("<H", java, 6, 0x0808)
        struct.pack_into("<H", java, central + 4, 20)
        struct.pack_into("<H", java, central + 8, 0x0808)
        struct.pack_into("<I", java, central + 38, 0)
        for signed in (True, False):
            body = bytearray(java)
            if not signed:
                del body[descriptor_at:descriptor_at + 4]
                struct.pack_into("<I", body, len(body) - 6, central - 4)
            data = inspect_inner(bytes(body))
            row = dict(zip(data["columns"], data["rows"][0]))
            self.assertEqual((data["files"], row["kind"], row["size"], row["sha256"]),
                             (0, "directory", 0, None))
            self.assertEqual((row["flags"], row["compressedSize"], row["creatorSystem"]),
                             (0x0808, 2, 0))

        bad_descriptor = bytearray(java)
        struct.pack_into("<I", bad_descriptor, descriptor_at + 4, 1)
        nonempty = bytearray(java)
        struct.pack_into("<I", nonempty, central + 24, 1)
        struct.pack_into("<I", nonempty, descriptor_at + 12, 1)
        bad_crc = bytearray(java)
        struct.pack_into("<I", bad_crc, central + 16, 1)
        struct.pack_into("<I", bad_crc, descriptor_at + 4, 1)
        trailing = bytearray(java[:descriptor_at] + b"\0" + java[descriptor_at:])
        struct.pack_into("<I", trailing, descriptor_at + 1 + 8, 3)
        struct.pack_into("<I", trailing, central + 1 + 20, 3)
        struct.pack_into("<I", trailing, len(trailing) - 6, central + 1)
        for body, reason in ((bad_descriptor, "zip_descriptor_disagreement"),
                             (nonempty, "zip_non_regular_member"),
                             (bad_crc, "zip_member_crc_or_length"),
                             (trailing, "zip_deflate_trailing_data")):
            with self.subTest(reason=reason), self.assertRaisesRegex(M.Refused, reason):
                inspect_inner(bytes(body))

        # The authenticated ct.sym observation has exactly two terminal slashes.
        # Opaque names retain the one remaining slash after the existing marker
        # removal; neither names nor raw local/CD agreement are normalized.
        for descriptor in (False, True):
            for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(opaque_directory_descriptor=descriptor, method=method):
                    doubled = zip_bytes([
                        ("8/java.base/", b"", stat.S_IFDIR | 0o755),
                        ("8/java.base//", b"", stat.S_IFDIR | 0o755),
                        ("8/java.base/lang/Number.sig", b"opaque DATA", stat.S_IFREG | 0o644),
                    ], descriptor=descriptor, method=method)
                    data = inspect_inner(doubled)
                    by_name = {row[0]: dict(zip(data["columns"], row)) for row in data["rows"]}
                    self.assertEqual(set(by_name), {"8/java.base", "8/java.base/",
                                                   "8/java.base/lang/Number.sig"})
                    self.assertEqual((data["members"], data["files"]), (3, 1))
                    directory = by_name["8/java.base/"]
                    self.assertEqual((directory["kind"], directory["size"], directory["sha256"]),
                                     ("directory", 0, None))
                    self.assertEqual(bool(directory["flags"] & 8), descriptor)
                    self.assertEqual(by_name["8/java.base/lang/Number.sig"]["sha256"],
                                     hashlib.sha256(b"opaque DATA").hexdigest())
        # Ordinary supplier/bundletool path grammar and non-directory calls
        # must not borrow the inert opaque-directory exception.
        for label in ("gradle", "bundletool"):
            with self.subTest(strict_label=label), self.assertRaisesRegex(M.Refused, "archive_name_grammar"):
                publish(doubled, label)
        with self.assertRaisesRegex(M.Refused, "opaque_zip_name_structure"):
            M._opaque_name(b"8/java.base//", directory=False)
        for name, payload, mode, reason in (
            ("8/java.base///", b"", stat.S_IFDIR | 0o755, "opaque_zip_name_structure"),
            ("8//java.base/", b"", stat.S_IFDIR | 0o755, "opaque_zip_name_structure"),
            ("/8/java.base//", b"", stat.S_IFDIR | 0o755, "opaque_zip_name_structure"),
            ("8/../java.base//", b"", stat.S_IFDIR | 0o755, "opaque_zip_name_structure"),
            ("8/./java.base//", b"", stat.S_IFDIR | 0o755, "opaque_zip_name_structure"),
            ("8/java.base//", b"", stat.S_IFREG | 0o644, "zip_non_regular_member"),
            ("8/java.base//", b"nonempty", stat.S_IFDIR | 0o755, "zip_non_regular_member"),
        ):
            with self.subTest(opaque_name=name, reason=reason), self.assertRaisesRegex(M.Refused, reason):
                inspect_inner(zip_bytes([(name, payload, mode)], descriptor=True))
        duplicate = zip_bytes([("8/java.base//", b"", stat.S_IFDIR | 0o755),
                               ("8/java.basz//", b"", stat.S_IFDIR | 0o755)])
        self.assertEqual(duplicate.count(b"8/java.basz//"), 2)
        duplicate = duplicate.replace(b"8/java.basz//", b"8/java.base//")
        with self.assertRaisesRegex(M.Refused, "duplicate_or_case_colliding_member"):
            inspect_inner(duplicate)
        with self.assertRaisesRegex(M.Refused, "non_directory_member_parent"):
            inspect_inner(zip_bytes([("8/java.base", b"file", stat.S_IFREG | 0o644),
                                     ("8/java.base//", b"", stat.S_IFDIR | 0o755)]))
        # A local name cannot disagree even when both spellings would now be
        # valid DATA: change only the first, fixed-length local name occurrence.
        mismatch = doubled.replace(b"8/java.base//", b"8/java.basz//", 1)
        with self.assertRaisesRegex(M.Refused, "zip_local_name_disagreement"):
            inspect_inner(mismatch)

        # A stored manifest's exact local (0, 0, N) placeholder is opaque-only.
        # Central size/CRC and every payload byte still determine the full row.
        manifest_body = b"Manifest-Version: 1.0\nCreated-By: inert test\n\n"
        manifest_name = "META-INF/MANIFEST.MF"
        strict = zip_bytes([(manifest_name, manifest_body, stat.S_IFREG | 0o644)], method=zipfile.ZIP_STORED)
        strict_rows = inspect_inner(strict)["rows"]
        def manifest_placeholder(raw):
            body = bytearray(raw)
            self.assertEqual(body[:4], b"PK\x03\x04")
            struct.pack_into("<2I", body, 14, 0, 0)
            return bytes(body)
        placeholder = manifest_placeholder(strict)
        owner = Original(placeholder)
        report = M.compile_opaque_zip(owner, M.OpaqueZipPin(len(placeholder), hashlib.sha256(placeholder).hexdigest()))
        rows = []
        summary = report.consume_rows(rows.append)
        self.assertEqual(rows, strict_rows)
        self.assertEqual((summary["members"], summary["files"], summary["expandedBytes"]),
                         (1, 1, len(manifest_body)))
        row = dict(zip(M.COLUMNS, rows[0]))
        crc = zlib.crc32(manifest_body) & 0xffffffff
        self.assertEqual((row["name"], row["kind"], row["size"], row["compressedSize"],
                          row["method"], row["flags"], row["crc32"]),
                         (manifest_name, "file", len(manifest_body), len(manifest_body), 0, 0, crc))
        self.assertEqual(row["sha256"], hashlib.sha256(manifest_body).hexdigest())
        self.assertEqual(summary["issuedReadBytes"], sum(n for _, n in owner.calls))
        self.assertTrue(all(n <= M.WINDOW for _, n in owner.calls))
        self.assertGreaterEqual(owner.bindings, 5)
        with self.assertRaisesRegex(M.Refused, "report_finality"):
            report.consume_rows(lambda _: self.fail("second manifest drain"))
        for label in ("gradle", "bundletool"):
            with self.subTest(manifest_strict_label=label), self.assertRaisesRegex(M.Refused, "zip_local_sizes_or_extent"):
                publish(placeholder, label)

        central = struct.unpack_from("<I", placeholder, len(placeholder) - 6)[0]
        for offset, value in ((14, 1 if crc != 1 else 2), (18, 1), (22, len(manifest_body) + 1)):
            damaged = bytearray(placeholder)
            struct.pack_into("<I", damaged, offset, value)
            with self.subTest(manifest_local_field=offset), self.assertRaisesRegex(M.Refused, "zip_local_sizes_or_extent"):
                inspect_inner(bytes(damaged))
        for raw in (
            zip_bytes([("META-INF/MANIFEST.MX", manifest_body, stat.S_IFREG | 0o644)], method=zipfile.ZIP_STORED),
            zip_bytes([(manifest_name, manifest_body, stat.S_IFREG | 0o644)], method=zipfile.ZIP_DEFLATED),
        ):
            with self.subTest(manifest_other_encoding=hashlib.sha256(raw).hexdigest()), \
                    self.assertRaisesRegex(M.Refused, "zip_local_sizes_or_extent"):
                inspect_inner(manifest_placeholder(raw))
        for flags, reason in ((0x800, "zip_local_sizes_or_extent"), (8, "zip_descriptor_local_disagreement")):
            damaged = bytearray(placeholder)
            struct.pack_into("<H", damaged, 6, flags)
            struct.pack_into("<H", damaged, central + 8, flags)
            with self.subTest(manifest_flags=flags), self.assertRaisesRegex(M.Refused, reason):
                inspect_inner(bytes(damaged))
        bad_crc = bytearray(placeholder)
        struct.pack_into("<I", bad_crc, central + 16, crc ^ 1)
        bad_payload = bytearray(placeholder)
        bad_payload[row["dataOffset"]] ^= 1
        for damaged in (bad_crc, bad_payload):
            with self.assertRaisesRegex(M.Refused, "zip_member_crc_or_length"):
                inspect_inner(bytes(damaged))
        gap = bytearray(placeholder[:central] + b"\0" + placeholder[central:])
        struct.pack_into("<I", gap, len(gap) - 6, central + 1)
        with self.assertRaisesRegex(M.Refused, "zip_local_sizes_or_extent"):
            inspect_inner(bytes(gap))
        overlap = bytearray(placeholder)
        struct.pack_into("<2I", overlap, central + 20, len(manifest_body) + 1, len(manifest_body) + 1)
        with self.assertRaisesRegex(M.Refused, "zip_overlapping_payload"):
            inspect_inner(bytes(overlap))

    def test_duplicate_case_traversal_and_alias_zip_members_refuse(self):
        for rows in [
            [("A", b"x", 0o100644), ("a", b"y", 0o100644)],
            [("../escape", b"x", 0o100644)],
            [("C:/escape", b"x", 0o100644)],
            [("x\\escape", b"x", 0o100644)],
            [("link", b"target", 0o120777)],
            [("a", b"x", 0o100644), ("a/b", b"y", 0o100644)],
        ]:
            with self.subTest(names=[x[0] for x in rows]), self.assertRaises(M.Refused):
                raw = zip_bytes(rows)
                M.compile_archive(Original(raw), pin(raw))

    def test_implicit_parent_spelling_collisions_refuse_without_extraction(self):
        cases = [
            [("A/x", b"x", 0o100644), ("a/y", b"y", 0o100644)],
            [("Root/A/x", b"x", 0o100644), ("Root/a/y", b"y", 0o100644)],
            # Explicit-parent protection remains necessary across punctuation.
            [("A/", b"", 0o040755), ("a-extra", b"z", 0o100644), ("a/x", b"x", 0o100644)],
        ]
        for rows in cases:
            for label in ("gradle", "sdk-platform", "sdk-build-tools", "aapt2"):
                for ordered in (rows, list(reversed(rows))):
                    with self.subTest(label=label, names=[r[0] for r in ordered]), self.assertRaisesRegex(M.Refused, "case_colliding_member_parent"):
                        publish(zip_bytes(ordered), label)
        jdk = tar_bytes([("Test.jdk/A/x", b"x", tarfile.REGTYPE, ""),
                         ("Test.jdk/a/y", b"y", tarfile.REGTYPE, "")],
                        format_=tarfile.GNU_FORMAT)
        with self.assertRaisesRegex(M.Refused, "case_colliding_member_parent"):
            publish(jdk, "jdk")

    def test_consistent_implicit_parents_and_sealed_jar_namespace_remain_valid(self):
        rows = [("A/y", b"y", 0o100644), ("B/x", b"b", 0o100644), ("A/x", b"x", 0o100644)]
        for ordered in (rows, list(reversed(rows))):
            _, _, data, _ = publish(zip_bytes(ordered))
            self.assertEqual([row[0] for row in data["rows"]], ["A/x", "A/y", "B/x"])
        _, _, jar, _ = publish(zip_bytes([("A/x", b"x", 0o100644), ("a/y", b"y", 0o100644)]), "bundletool")
        self.assertEqual([row[0] for row in jar["rows"]], ["A/x", "a/y"])
        self.assertFalse(jar["supplierAuthority"])
        self.assertFalse(jar["nativeClosure"])

    def test_sealed_bundletool_class_names_do_not_become_apfs_paths(self):
        raw = zip_bytes([("r8/a.class", b"a", 0o100644),
                         ("r8/A.class", b"A", 0o100644)])
        _, _, data, _ = publish(raw, "bundletool")
        self.assertEqual([row[0] for row in data["rows"]], ["r8/A.class", "r8/a.class"])
        for label in ("gradle", "sdk-platform", "sdk-build-tools", "aapt2"):
            with self.subTest(label=label), self.assertRaisesRegex(M.Refused, "case_colliding"):
                publish(raw, label)
        duplicate = raw.replace(b"r8/a.class", b"r8/A.class")
        with self.assertRaisesRegex(M.Refused, "duplicate_or_case_colliding"):
            publish(duplicate, "bundletool")
        for rows in [
            [("a", b"x", 0o100644), ("a/b", b"y", 0o100644)],
            [("../escape", b"x", 0o100644)],
            [("/absolute", b"x", 0o100644)],
            [("a//b", b"x", 0o100644)],
        ]:
            with self.subTest(rows=rows), self.assertRaises(M.Refused):
                publish(zip_bytes(rows), "bundletool")

    def test_old_unix_extra_has_exact_local_central_common_bytes(self):
        common = bytes.fromhex("d0036966d0036966")
        def extra(payload, tag=0x5855):
            return struct.pack("<HH", tag, len(payload)) + payload
        local = extra(common + bytes.fromhex("f5011400"))
        central = extra(common)
        _, _, data, _ = publish(zip_extra_bytes(local, central), "sdk-build-tools")
        self.assertEqual(data["rows"][0][4], hashlib.sha256(b"x").hexdigest())
        for left, right in [
            (extra(common), central),              # Local must include uid/gid.
            (local, extra(common + b"\0" * 4)),    # Central must not.
            (local, b""), (b"", central),           # Both-presence is required.
            (extra(b"\1" + common[1:] + b"\0" * 4), central),
            (local + local, central), (local, central + central),
            (extra(b"\0", 0x9999), b""),           # Not an unknown-tag escape.
            (local[:-1], central),                # Declared-size truncation.
        ]:
            with self.subTest(local=left.hex(), central=right.hex()), self.assertRaises(M.Refused):
                publish(zip_extra_bytes(left, right), "sdk-build-tools")

    def test_simple_gnu_directory_special_bit_is_only_archival_data(self):
        raw = tar_bytes([("Test.jdk", b"", tarfile.DIRTYPE, ""),
                         ("Test.jdk/data", b"x", tarfile.REGTYPE, "")],
                        format_=tarfile.GNU_FORMAT)
        tar = gzip.decompress(raw)
        self.assertEqual(tar[257:265], b"ustar  \0")
        valid = tar_header_change(tar, 0, [(100, b"0002755\0")])
        _, _, data, _ = publish(gzip.compress(valid, mtime=0), "jdk")
        self.assertEqual(data["rows"][0][2], 0o042755)
        self.assertEqual((data["members"], data["files"]), (2, 1))
        changes = [
            (0, [(345, b"x")]),                   # GNU extension/prefix not guessed.
            (0, [(100, b"0004755\0")]),            # No setuid.
            (0, [(100, b"0001755\0")]),            # No sticky directory.
            (0, [(100, b"0002700\0")]),            # Only observed02755 exception.
            (512, [(100, b"0002755\0")]),          # No special mode on a file.
            (0, [(156, b"L")]), (0, [(156, b"K")]),
            (0, [(156, b"S")]), (0, [(156, b"2")]),
            (0, [(156, b"x")]),                   # No GNU-extension fallback.
            (512, [(257, b"ustar\0" + b"00")]),  # No mixed dialects.
        ]
        for offset, edits in changes:
            with self.subTest(offset=offset, edits=edits), self.assertRaises(M.Refused):
                changed = tar_header_change(valid, offset, edits)
                publish(gzip.compress(changed, mtime=0), "jdk")
        # POSIX mode2755 is not the observed GNU-directory exception either.
        posix = tar_header_change(valid, 0, [(257, b"ustar\0" + b"00")])
        with self.assertRaises(M.Refused):
            publish(gzip.compress(posix, mtime=0), "jdk")

    def test_pin_local_header_crc_extent_and_zip64_refuse(self):
        raw = zip_bytes([("a", b"payload", 0o100644)], method=zipfile.ZIP_STORED)
        bad_pin = M.Pin("gradle", len(raw), "f" * 64)
        with self.assertRaisesRegex(M.Refused, "original_archive_sha256"):
            M.compile_archive(Original(raw), bad_pin)
        central = raw.index(b"PK\x01\x02")
        changes = []
        value = bytearray(raw); value[30] = ord("b"); changes.append(value)
        value = bytearray(raw); value[31] ^= 1; changes.append(value)  # Payload CRC failure.
        value = bytearray(raw); struct.pack_into("<I", value, central + 42, 1); changes.append(value)
        value = bytearray(raw); struct.pack_into("<I", value, central + 24, 0xFFFFFFFF); changes.append(value)
        value = bytearray(raw); struct.pack_into("<H", value, central + 8, 1); changes.append(value)
        changes.append(bytearray(raw + b"trailing"))
        for value in changes:
            with self.subTest(digest=hashlib.sha256(value).hexdigest()), self.assertRaises(M.Refused):
                changed = bytes(value)
                M.compile_archive(Original(changed), pin(changed))

    def test_central_preflight_count_and_member_growth_are_bounded(self):
        raw = zip_bytes([("a", b"xx", 0o100644), ("b", b"y", 0o100644)])
        value = bytearray(raw); end = value.rindex(b"PK\x05\x06")
        struct.pack_into("<HH", value, end + 8, M.ENTRY_LIMIT + 1, M.ENTRY_LIMIT + 1)
        changed = bytes(value); owner = Original(changed)
        with self.assertRaisesRegex(M.Refused, "zip_directory_extent"):
            M.compile_archive(owner, pin(changed))
        self.assertEqual(len(owner.calls), 2)  # Authentication + bounded EOCD window; no roster.
        for constant, limit in (("FILE_LIMIT", 1), ("FILE_COUNT", 1), ("ROSTER_LIMIT", 1), ("EXPANDED_LIMIT", 1)):
            with self.subTest(bound=constant), mock.patch.object(M, constant, limit), self.assertRaises(M.Refused):
                M.compile_archive(Original(raw), pin(raw))

    def test_failed_reads_charge_requests_and_do_not_recover(self):
        raw = zip_bytes([("a", b"payload", 0o100644)])
        owner = Original(raw); owner.short = True
        work = M._Pass(owner, pin(raw))
        with self.assertRaisesRegex(M.Refused, "short_or_invalid"):
            work.read(0, 16)
        self.assertEqual(work.issued, 16)
        owner.short = False
        with self.assertRaisesRegex(M.Refused, "capture_already_failed"):
            work.read(0, 1)

    def test_expansion_and_publication_keep_the_original_endpoint(self):
        raw = zip_bytes([("a", b"payload", 0o100644)])
        for what in ("deadline", "changed"):
            owner = Original(raw); report = M.compile_archive(owner, pin(raw))
            setattr(owner, what, True)
            with self.subTest(what=what), self.assertRaises(M.Refused):
                report.publish(lambda _: self.fail("must refuse before sink"))
            setattr(owner, what, False)
            with self.assertRaisesRegex(M.Refused, "report_finality"):
                report.publish(lambda _: self.fail("latched failure"))
        owner = Original(raw); report = M.compile_archive(owner, pin(raw))
        def endpoint_expires_during_sink(_):
            owner.deadline = True
        with self.assertRaisesRegex(M.Refused, "original_endpoint"):
            report.publish(endpoint_expires_during_sink)
        with self.assertRaisesRegex(M.Refused, "report_finality"):
            report.publish(lambda _: None)

    def test_output_and_sink_failures_cannot_return_partial_receipts(self):
        raw = zip_bytes([("a", b"payload", 0o100644)])
        for bound in ("OUTPUT_LIMIT", "WORKSPACE_LIMIT"):
            owner = Original(raw); report = M.compile_archive(owner, pin(raw))
            with mock.patch.object(M, bound, 1), self.assertRaises(M.Refused):
                report.publish(lambda _: self.fail("bounded before publication"))
        owner = Original(raw); report = M.compile_archive(owner, pin(raw))
        def bad_sink(_): raise OSError("synthetic publication failure")
        with self.assertRaises(OSError):
            report.publish(bad_sink)
        with self.assertRaisesRegex(M.Refused, "report_finality"):
            report.publish(lambda _: None)

    def test_tar_whole_jdk_roster_and_relative_alias_correspond(self):
        raw = tar_bytes([("Test.jdk", b"", tarfile.DIRTYPE, ""),
                         ("Test.jdk/java", b"native fixture", tarfile.REGTYPE, ""),
                         ("Test.jdk/java-link", b"", tarfile.SYMTYPE, "java")])
        _, _, data, _ = publish(raw, "jdk")
        self.assertEqual((data["members"], data["files"], data["aliases"]), (3, 1, 1))
        self.assertEqual(data["rows"][-1][5], "java")
        self.assertEqual(data["rows"][1][4], hashlib.sha256(b"native fixture").hexdigest())

    def test_tar_pax_is_narrow_per_file_metadata_not_native_authority(self):
        raw = tar_bytes([("Test.jdk/data", b"x", tarfile.REGTYPE, "")],
                        pax={"mtime": "1.25"}, format_=tarfile.PAX_FORMAT)
        _, _, data, _ = publish(raw, "jdk")
        self.assertEqual(data["members"], 1)
        self.assertEqual(data["entryHeaders"], 2)
        raw = tar_bytes([("Test.jdk/data", b"x", tarfile.REGTYPE, "")],
                        pax={"SCHILY.xattr.user.unreviewed": "x"}, format_=tarfile.PAX_FORMAT)
        with self.assertRaisesRegex(M.Refused, "pax_unknown"):
            M.compile_archive(Original(raw), pin(raw, "jdk"))

    def test_tar_escape_hardlink_device_or_alias_chain_refuse(self):
        for rows in [
            [("Test.jdk/link", b"", tarfile.SYMTYPE, "../../escape")],
            [("Test.jdk/link", b"", tarfile.LNKTYPE, "Test.jdk/data")],
            [("Test.jdk/device", b"", tarfile.CHRTYPE, "")],
            [("Test.jdk/a", b"", tarfile.SYMTYPE, "b"), ("Test.jdk/b", b"", tarfile.SYMTYPE, "a")],
            [("Test.jdk/f", b"x", tarfile.REGTYPE, ""), ("Test.jdk/f/child", b"y", tarfile.REGTYPE, "")],
        ]:
            with self.subTest(rows=rows), self.assertRaises(M.Refused):
                raw = tar_bytes(rows)
                M.compile_archive(Original(raw), pin(raw, "jdk"))

    def test_gzip_crc_concatenation_and_tar_checksum_refuse(self):
        raw = tar_bytes([("Test.jdk/data", b"x", tarfile.REGTYPE, "")])
        crc = bytearray(raw); crc[-8] ^= 1
        tar = bytearray(gzip.decompress(raw)); tar[0] ^= 1
        for changed in (bytes(crc), raw + raw, gzip.compress(bytes(tar), mtime=0), raw[:-1]):
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()), self.assertRaises((M.Refused, zlib.error)):
                M.compile_archive(Original(changed), pin(changed, "jdk"))

if __name__ == "__main__":
    unittest.main()
