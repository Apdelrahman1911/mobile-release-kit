"""Inert ZIP32 metadata regressions over synthetic bytes, not native AAB tests.

No ZipFile, filesystem, process, decompressor, SDK or bundletool is used. Some
fixtures deliberately lie about payloads; metadata admission must never be
presented as CRC/content, original-object or native-inspector correspondence.
"""
from __future__ import annotations

import binascii
from dataclasses import FrozenInstanceError, replace
import stat
import struct
import unittest
from unittest.mock import patch

from mobile_release import android_zip as policy


def member(name=b"file", **changes):
    name = name.encode("utf-8") if isinstance(name, str) else name
    value = {"name": name, "payload": b"", "flags": 0x0800, "method": 0, "needed": 20,
             "made": (3 << 8) | 20, "extra": b"", "comment": b"", "disk": 0, "external": 0}
    value.update(changes)
    return value


def end_record(*, count, size, offset, comment=b"", **changes):
    fields = {"disk": 0, "directory_disk": 0, "disk_count": count, "count": count,
              "size": size, "offset": offset, "comment_size": len(comment)}
    fields.update(changes)
    return struct.pack("<4s4H2IH", b"PK\x05\x06", fields["disk"], fields["directory_disk"],
                       fields["disk_count"], fields["count"], fields["size"], fields["offset"],
                       fields["comment_size"]) + comment


def zip_bytes(*members, comment=b"", end_changes=None, order=None, prefix=b"", directory_suffix=b""):
    """Tiny byte fixtures only; declared sizes need not match synthetic payloads."""
    local, records = bytearray(prefix), []
    for value in members:
        name, payload = value["name"], value["payload"]
        flags, method = value["flags"], value["method"]
        compressed, expanded = value.get("compressed", len(payload)), value.get("expanded", len(payload))
        crc = value.get("crc", binascii.crc32(payload) if method == 0 else 0)
        offset = len(local)
        local_extra = value.get("local_extra", b"")
        sizes = (0, 0, 0) if flags & 8 else (crc, compressed, expanded)
        local.extend(struct.pack("<4s5H3I2H", b"PK\x03\x04", value["needed"], flags, method, 0, 0,
                                 *sizes, len(name), len(local_extra)))
        local.extend(name + local_extra + payload)
        if flags & 8:
            local.extend(struct.pack("<4s3I", b"PK\x07\x08", crc, compressed, expanded))
        extra, entry_comment = value["extra"], value["comment"]
        records.append(struct.pack("<4s6H3I5H2I", b"PK\x01\x02", value["made"], value["needed"],
                                   flags, method, 0, 0, crc, compressed, expanded,
                                   value.get("name_size", len(name)), value.get("extra_size", len(extra)),
                                   value.get("comment_size", len(entry_comment)), value["disk"], 0,
                                   value["external"], value.get("local_offset", offset)) + name + extra + entry_comment)
    directory = b"".join(records if order is None else [records[index] for index in order]) + directory_suffix
    ending = {"count": len(records), "size": len(directory), "offset": len(local), "comment": comment}
    ending.update(end_changes or {})
    return bytes(local) + directory + end_record(**ending)


def admit(data):
    tail = policy.zip_tail_range(len(data))
    plan = policy.plan_zip_directory(len(data), data[tail.offset:tail.offset + tail.length])
    requested = plan.central_directory
    return policy.inspect_zip_directory(plan, data[requested.offset:requested.offset + requested.length])


def sparse_tail(archive_bytes, ending):
    """Model a large file's small proposed tail, never allocate a large artifact."""
    requested = policy.zip_tail_range(archive_bytes)
    return b"\0" * (requested.length - len(ending)) + ending


class AndroidZipPolicyTests(unittest.TestCase):
    def refused(self, reason, function, *args, **kwargs):
        with self.assertRaises(policy.AndroidZipError) as caught:
            function(*args, **kwargs)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_tail_request_bounds_size_before_any_metadata_retention(self):
        for value in (None, True, False, 22.0, "22"):
            self.refused("input", policy.zip_tail_range, value)
        for value in (-1, 0, 21, policy.MAX_AAB_BYTES + 1):
            self.refused("limit", policy.zip_tail_range, value)
        self.assertEqual(policy.zip_tail_range(22), policy.ZipReadRange(0, 22))
        self.assertEqual(policy.zip_tail_range(policy.MAX_AAB_BYTES),
                         policy.ZipReadRange(policy.MAX_AAB_BYTES - policy.MAX_TAIL_BYTES, policy.MAX_TAIL_BYTES))
        self.assertEqual(policy.MAX_TAIL_BYTES, 65577)

    def test_exact_tail_then_directory_plan_and_immutable_metadata(self):
        raw = zip_bytes(member("base/manifest/AndroidManifest.xml", payload=b"not native XML"),
                        member("base/dex/classes.dex", payload=b"not native DEX"),
                        member("BundleConfig.pb", payload=b"not native protobuf"))
        request = policy.zip_tail_range(len(raw))
        plan = policy.plan_zip_directory(len(raw), raw[request.offset:])
        self.assertEqual(plan.central_directory.offset + plan.central_directory.length, plan.end_offset)
        self.assertEqual(plan.end_offset + 22, len(raw))
        metadata = admit(raw)
        self.assertEqual(metadata.plan, plan)
        self.assertEqual(tuple(item.name for item in metadata.entries),
                         ("base/manifest/AndroidManifest.xml", "base/dex/classes.dex", "BundleConfig.pb"))
        self.assertEqual(metadata.declared_expanded_bytes, sum(item.file_size for item in metadata.entries))
        policy.require_aab_content(metadata)
        self.assertIsInstance(metadata.entries, tuple)
        for value, field in ((request, "offset"), (plan, "entry_count"), (metadata, "entries"),
                             (metadata.entries[0], "name")):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, None)

    def test_comment_end_and_no_comment_fast_path_do_not_choose_numeric_signature_bytes(self):
        metadata = admit(zip_bytes(member("one"), comment=b"c" * 65535))
        self.assertEqual(metadata.plan.archive_bytes - metadata.plan.end_offset, 22 + 65535)
        # Its central offset is the signature's little-endian integer value.
        # A naive rfind would select that field inside the real EOCD.
        offset, size = 0x06054B50, 47
        end = end_record(count=1, size=size, offset=offset)
        archive_bytes = offset + size + 22
        plan = policy.plan_zip_directory(archive_bytes, sparse_tail(archive_bytes, end))
        self.assertEqual(plan.central_directory, policy.ZipReadRange(offset, size))

    def test_truncation_trailers_and_comment_signature_do_not_fall_back(self):
        raw = zip_bytes(member("one"))
        for broken in (raw[:-1], raw + b"trailer", b"x" * len(raw),
                       zip_bytes(member("one"), comment=b"comment PK\x05\x06")):
            self.refused("end", admit, broken)
        tail = policy.zip_tail_range(len(raw))
        self.refused("end", policy.plan_zip_directory, len(raw), raw[tail.offset:][:-1])
        self.refused("input", policy.plan_zip_directory, len(raw), bytearray(raw[tail.offset:]))

    def test_two_end_records_with_eof_terminated_comments_are_ambiguous(self):
        raw = zip_bytes(member("one"))
        parsed = admit(raw).plan
        outer = end_record(count=1, size=parsed.central_directory.length,
                           offset=parsed.central_directory.offset, comment_size=22)
        inner = end_record(count=1, size=parsed.central_directory.length + 22,
                           offset=parsed.central_directory.offset)
        self.refused("end", admit, raw[:-22] + outer + inner)

    def test_multidisk_counts_and_zip64_eocd_or_locator_refuse_before_directory_read(self):
        for fields in ({"disk": 1}, {"directory_disk": 1}, {"disk_count": 0}):
            self.refused("multidisk", admit, zip_bytes(member("one"), end_changes=fields))
        for field in ("count", "disk_count", "size", "offset"):
            value = 0xFFFF if "count" in field else 0xFFFFFFFF
            self.refused("zip64", admit, zip_bytes(member("one"), end_changes={field: value}))
        raw = zip_bytes(member("one"), comment=b"c" * 65535)
        plan = admit(raw).plan
        locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, 31, 1)
        broken = raw[:plan.end_offset] + locator + raw[plan.end_offset:]
        self.refused("zip64", admit, broken)

    def test_directory_and_entry_limits_are_admitted_before_the_proposed_read(self):
        size, offset = policy.MAX_CENTRAL_DIRECTORY_BYTES + 1, 31
        archive_bytes = offset + size + 22
        end = end_record(count=1, size=size, offset=offset)
        self.refused("limit", policy.plan_zip_directory, archive_bytes, sparse_tail(archive_bytes, end))
        # A fabricated dataclass cannot bypass the same fixed limits.
        original = admit(zip_bytes(member("one"))).plan
        for plan in (replace(original, entry_count=True), replace(original, archive_bytes="100")):
            self.refused("input", policy.inspect_zip_directory, plan, b"")
        for plan in (replace(original, entry_count=100001),
                     replace(original, central_directory=policy.ZipReadRange(31, size))):
            self.refused("limit", policy.inspect_zip_directory, plan, b"")
        self.refused("zip64", policy.inspect_zip_directory, replace(original, entry_count=65535), b"")
        self.refused("directory", admit, zip_bytes(member("one"), end_changes={"offset": 1}))
        self.refused("limit", admit, zip_bytes(member("one"), end_changes={"count": 0, "disk_count": 0}))

    def test_directory_read_is_exact_and_records_counts_lengths_and_signatures_are_closed(self):
        raw = zip_bytes(member("first", comment=b"c" * 100))
        metadata = admit(raw)
        request = metadata.plan.central_directory
        data = raw[request.offset:request.offset + request.length]
        for changed in (data[:-1], data + b"x", b"FAIL" + data[4:]):
            self.refused("directory", policy.inspect_zip_directory, metadata.plan, changed)
        self.refused("input", policy.inspect_zip_directory, metadata.plan, memoryview(data))
        self.refused("directory", admit, zip_bytes(member("first", comment=b"c" * 100),
                                                  end_changes={"count": 2, "disk_count": 2}))
        self.refused("directory", admit, zip_bytes(member("first"), member("second"), member("third"),
                                                  end_changes={"count": 2, "disk_count": 2}))
        self.refused("directory", admit, zip_bytes(member("first", comment_size=100)))
        self.refused("directory", admit, zip_bytes(member("first"), directory_suffix=b"PK\x05\x05\0\0"))

    def test_raw_name_byte_bound_precedes_decoding_and_retention(self):
        accepted = admit(zip_bytes(member(b"a" * 4096)))
        self.assertEqual(len(accepted.entries[0].raw_name), 4096)
        with patch.object(policy, "validate_zip_entry_policy", side_effect=AssertionError("must reject earlier")):
            self.refused("limit", admit, zip_bytes(member(b"a" * 4097)))
        self.refused("limit", admit, zip_bytes(member(b"")))  # Cannot meet the minimum directory extent.
        self.refused("name", policy.validate_zip_entry_policy, "", flag_bits=0, external_attr=0, file_size=0)
        self.refused("name", admit, zip_bytes(member(b"\xff", flags=0x0800)))
        # Names are never normalized/truncated as ZipInfo may otherwise do.
        self.refused("name", admit, zip_bytes(member(b"BundleConfig.pb\0other")))

    def test_shared_core_path_type_and_encryption_policy_is_not_a_normalized_path_check(self):
        for name in ("/absolute", "../outside", "a/../b", "a/./b", "a//b", "a\\b", "a//", "./", "C:/root"):
            self.refused("name", admit, zip_bytes(member(name)))
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFBLK, stat.S_IFCHR):
            self.refused("entry", admit, zip_bytes(member("file", external=(kind | 0o600) << 16)))
        for flags in (0x0001, 0x0040, 0x2000):
            self.refused("encryption", admit, zip_bytes(member("file", flags=flags)))
        self.assertEqual(admit(zip_bytes(member("safe spaces", external=(stat.S_IFREG | 0o644) << 16))).entries[0].name,
                         "safe spaces")
        self.assertEqual(admit(zip_bytes(member("safe/", external=(stat.S_IFDIR | 0o755) << 16 | 0x10))).entries[0].name,
                         "safe/")
        for value in (member("file", external=stat.S_IFDIR << 16),
                      member("dir/", external=stat.S_IFREG << 16), member("dir/", payload=b"x"),
                      member("file", external=0x10), member("label", external=0x08)):
            self.refused("entry", admit, zip_bytes(value))

    def test_shared_predicate_has_closed_scalar_inputs_and_unchanged_member_ceiling(self):
        for args in ((None, 0, 0, 0), ("file", True, 0, 0), ("file", 0, -1, 0), ("file", 0, 0, -1)):
            name, flags, external, size = args
            self.refused("input", policy.validate_zip_entry_policy, name, flag_bits=flags,
                         external_attr=external, file_size=size)
        policy.validate_zip_entry_policy("file", flag_bits=0, external_attr=0, file_size=512 * 1024 * 1024)
        self.refused("limit", policy.validate_zip_entry_policy, "file", flag_bits=0,
                     external_attr=0, file_size=512 * 1024 * 1024 + 1)

    def test_duplicate_names_include_equivalent_utf8_cp437_and_offsets_are_not_reused(self):
        self.refused("duplicate", admit, zip_bytes(member("same"), member("same")))
        self.refused("duplicate", admit, zip_bytes(member(b"\xc3\xa9", flags=0x0800), member(b"\x82", flags=0)))
        self.refused("duplicate", admit, zip_bytes(member("first"), member("second", local_offset=0)))
        metadata = admit(zip_bytes(member("first"), member("second"), member("third"), order=[2, 0, 1]))
        self.assertEqual(tuple(entry.name for entry in metadata.entries), ("third", "first", "second"))

    def test_zip64_and_name_override_extra_fields_never_reach_zipinfo_allocation(self):
        for value in (member("file", needed=45), member("file", compressed=0xFFFFFFFF),
                      member("file", expanded=0xFFFFFFFF), member("file", local_offset=0xFFFFFFFF),
                      member("file", disk=0xFFFF), member("file", extra=struct.pack("<HH", 1, 0))):
            self.refused("zip64", admit, zip_bytes(value))
        alternative = b"\x01" + struct.pack("<I", binascii.crc32(b"safe")) + b"../not-the-header-name"
        self.refused("name", admit, zip_bytes(member("safe", extra=struct.pack("<HH", 0x7075, len(alternative)) + alternative)))
        for tag in (0x0017, 0x9901):
            self.refused("encryption", admit, zip_bytes(member("safe", extra=struct.pack("<HH", tag, 0))))
        for extra in (b"x", b"xx", b"xxx", struct.pack("<HH", 0xCAFE, 4) + b"x"):
            self.refused("directory", admit, zip_bytes(member("safe", extra=extra)))
        # Benign bounded opaque extras/comments are not interpreted as paths.
        metadata = admit(zip_bytes(member("safe", extra=struct.pack("<HH", 0xCAFE, 0), comment=b"opaque")))
        self.assertEqual(metadata.entries[0].name, "safe")

    def test_method_flags_and_local_offset_geometry_fail_closed(self):
        for method in (9, 12, 14, 99):
            self.refused("compression", admit, zip_bytes(member("one", method=method)))
        self.refused("compression", admit, zip_bytes(member("one", compressed=1)))
        self.refused("compression", admit, zip_bytes(member("one", method=8, compressed=0)))
        for value in (member("one", needed=21), member("one", flags=0x0010),
                      member("one", flags=0x0002), member("one", expanded=0, crc=1)):
            self.refused("entry", admit, zip_bytes(value))
        for value in (member("one", local_offset=999999), member("one", local_offset=1)):
            self.refused("layout", admit, zip_bytes(value))
        self.refused("layout", admit, zip_bytes(member("one"), prefix=b"prefix"))
        self.refused("layout", admit, zip_bytes(member("first"), member("second", local_offset=1)))
        self.refused("multidisk", admit, zip_bytes(member("one", disk=1)))
        metadata = admit(zip_bytes(member("empty-deflate", method=8, payload=b"\x03\x00", expanded=0,
                                          flags=0x0808, crc=0)))
        self.assertEqual(metadata.entries[0].flag_bits, 0x0808)
        self.assertEqual(metadata.entries[0].compressed_size, 2)

    def test_declared_member_and_total_limits_do_not_allocate_declared_payloads(self):
        def large(name, size):
            return member(name, method=8, payload=b"\x03\x00", expanded=size)
        self.refused("limit", admit, zip_bytes(large("one", policy.MAX_ENTRY_SIZE + 1)))
        exactly = zip_bytes(*(large(str(index), policy.MAX_ENTRY_SIZE) for index in range(4)))
        metadata = admit(exactly)
        self.assertLess(len(exactly), 1024)
        self.assertEqual(metadata.declared_expanded_bytes, policy.MAX_TOTAL_SIZE)
        self.refused("limit", admit, zip_bytes(*(large(str(index), policy.MAX_ENTRY_SIZE) for index in range(5))))

    def test_required_names_preserve_existing_core_rules_without_native_claims(self):
        required = ("base/manifest/", "base/dex/", "BundleConfig.pb")
        # The existing policy observes prefixes, not real protobuf/DEX validity.
        policy.require_aab_content(admit(zip_bytes(*(member(name) for name in required))))
        for missing in required:
            metadata = admit(zip_bytes(*(member(name) for name in required if name != missing)))
            self.refused("content", policy.require_aab_content, metadata)
        self.refused("content", policy.require_aab_content,
                     admit(zip_bytes(member("other/base/manifest/x"), member("base/dex/x"), member("BundleConfig.pb"))))
        self.refused("content", policy.require_aab_content,
                     admit(zip_bytes(member("base/manifest/x"), member("base/dex/x"), member("nested/BundleConfig.pb"))))

    def test_metadata_alone_cannot_detect_payload_crc_failure_or_establish_native_correspondence(self):
        raw = zip_bytes(member("file", payload=b"good"))
        admitted = admit(raw)
        # Replace same-length payload bytes, leaving the complete CD/EOCD intact.
        changed = raw[:34] + b"evil" + raw[38:]
        self.assertEqual(admit(changed), admitted)
        self.assertFalse(hasattr(admitted, "crc_valid"))
        self.assertFalse(hasattr(admitted, "native_valid"))
        self.assertFalse(hasattr(admitted, "artifact_owner"))

    def test_errors_are_fixed_and_do_not_reflect_private_entry_or_parser_data(self):
        marker = "PRIVATE-ENTRY-MARKER"
        errors = [self.refused("name", admit, zip_bytes(member("../" + marker))),
                  self.refused("duplicate", admit, zip_bytes(member(marker), member(marker))),
                  self.refused("encryption", admit, zip_bytes(member(marker, flags=1)))]
        for error in errors:
            self.assertNotIn(marker, str(error))
            self.assertNotIn(marker, error.reason)
            self.assertIsNone(error.__cause__)

    def test_fatal_or_mechanical_metadata_failures_are_not_wrapped_or_retried(self):
        raw = zip_bytes(member("file"))
        requested = policy.zip_tail_range(len(raw))
        fatal = KeyboardInterrupt("private mechanical sentinel")
        with patch.object(policy.struct, "unpack_from", side_effect=fatal) as unpack:
            with self.assertRaises(KeyboardInterrupt) as caught:
                policy.plan_zip_directory(len(raw), raw[requested.offset:])
        self.assertIs(caught.exception, fatal)
        unpack.assert_called_once()
