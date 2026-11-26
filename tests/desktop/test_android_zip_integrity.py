"""Authored in-memory ZIP32 integrity regressions; not native/custody evidence.

Fixtures use only struct-packed bytes, BytesIO and stdlib raw DEFLATE. No files,
ZipFile, native tools, processes or ownership fixtures are involved. Small lowered
quota/fault injections test refusal mechanics without allocating enormous bombs.
"""
from __future__ import annotations

import binascii
from dataclasses import FrozenInstanceError
from io import BytesIO
import struct
import unittest
from unittest.mock import patch
import zlib

from mobile_release import android_zip as policy
from mobile_release import android_zip_integrity as integrity


def deflate(data):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def member(name=b"file", payload=b"data", *, method=0, descriptor=None, **changes):
    name = name.encode("utf-8") if isinstance(name, str) else name
    compressed = changes.pop("compressed_data", deflate(payload) if method == 8 else payload)
    value = {"name": name, "payload": payload, "compressed_data": compressed,
             "flags": 0x0800 | (8 if descriptor is not None else 0), "method": method,
             "needed": 20 if method == 8 else 10, "crc": binascii.crc32(payload),
             "compressed_size": len(compressed), "file_size": len(payload),
             "local_extra": b"", "central_extra": b"", "comment": b"", "external": 0,
             "local": {}, "descriptor": descriptor, "trailing": b""}
    value.update(changes)
    return value


def zip_bytes(*members, order=None, prefix=b"", after_locals=b"", comment=b""):
    local, directory = bytearray(prefix), []
    for value in members:
        offset = len(local)
        name, extra = value.get("local_name", value["name"]), value["local_extra"]
        fields = {"signature": b"PK\x03\x04", "needed": value["needed"], "flags": value["flags"],
                  "method": value["method"], "time": 0, "date": 0,
                  "crc": 0 if value["flags"] & 8 else value["crc"],
                  "compressed_size": 0 if value["flags"] & 8 else value["compressed_size"],
                  "file_size": 0 if value["flags"] & 8 else value["file_size"],
                  "name_size": len(name), "extra_size": len(extra)}
        fields.update(value["local"])
        local.extend(struct.pack("<4s5H3I2H", fields["signature"], fields["needed"], fields["flags"],
                                 fields["method"], fields["time"], fields["date"], fields["crc"],
                                 fields["compressed_size"], fields["file_size"], fields["name_size"],
                                 fields["extra_size"]))
        local.extend(name + extra + value["compressed_data"])
        descriptor = value["descriptor"]
        if descriptor is not None:
            if type(descriptor) is bytes:
                local.extend(descriptor)
            else:
                if descriptor == "signed":
                    local.extend(b"PK\x07\x08")
                elif descriptor != "unsigned":
                    raise AssertionError("unknown synthetic descriptor form")
                local.extend(struct.pack("<3I", value["crc"], value["compressed_size"], value["file_size"]))
        local.extend(value["trailing"])
        extra, entry_comment = value["central_extra"], value["comment"]
        directory.append(struct.pack("<4s6H3I5H2I", b"PK\x01\x02", (3 << 8) | 20, value["needed"],
                                     value["flags"], value["method"], 0, 0, value["crc"],
                                     value["compressed_size"], value["file_size"], len(value["name"]),
                                     len(extra), len(entry_comment), 0, 0, value["external"], offset)
                         + value["name"] + extra + entry_comment)
    local.extend(after_locals)
    central = b"".join(directory if order is None else [directory[index] for index in order])
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, len(directory), len(directory),
                      len(central), len(local), len(comment)) + comment
    return bytes(local) + central + end


def metadata(data):
    requested = policy.zip_tail_range(len(data))
    plan = policy.plan_zip_directory(len(data), data[requested.offset:])
    requested = plan.central_directory
    return policy.inspect_zip_directory(plan, data[requested.offset:requested.offset + requested.length])


class Reader(BytesIO):
    def __init__(self, data, events=None):
        super().__init__(data)
        self.events = [] if events is None else events
        self.read_requests = []
        self.close_calls = 0

    def seek(self, offset, whence=0):
        self.events.append("seek")
        return super().seek(offset, whence)

    def read(self, length=-1):
        self.events.append("read")
        self.read_requests.append((BytesIO.tell(self), length))
        return super().read(length)

    def tell(self):
        self.events.append("tell")
        return super().tell()

    def close(self):
        self.close_calls += 1
        super().close()


class DeflateSpy:
    def __init__(self, stream, calls, events=None, after=None):
        self.stream, self.calls, self.events, self.after = stream, calls, events, after

    def decompress(self, data, max_length):
        if self.events is not None:
            self.events.append("decompress")
        result = self.stream.decompress(data, max_length)
        self.calls.append((len(data), max_length, len(result)))
        if self.after is not None:
            self.after()
        return result

    @property
    def unconsumed_tail(self):
        return self.stream.unconsumed_tail

    @property
    def unused_data(self):
        return self.stream.unused_data

    @property
    def eof(self):
        return self.stream.eof

    def flush(self, *_args):
        raise AssertionError("integrity inspection must never use unbounded flush")


def inspect(data, *, reader=None, checkpoint=None, archive_bytes=None):
    return integrity.inspect_zip_integrity(
        Reader(data) if reader is None else reader,
        archive_bytes=len(data) if archive_bytes is None else archive_bytes,
        checkpoint=(lambda: None) if checkpoint is None else checkpoint,
    )


class AndroidZipIntegrityTests(unittest.TestCase):
    def refused(self, reason, function, *args, **kwargs):
        with self.assertRaises(policy.AndroidZipError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_valid_stored_deflated_empty_and_directory_entries_preserve_central_order(self):
        values = (member("base/manifest/", b""), member("base/dex/classes.dex", b"not native dex", method=8),
                  member("BundleConfig.pb", b"not native protobuf"), member("empty/", b"", method=8))
        raw = zip_bytes(*values, order=[2, 0, 3, 1], comment=b"opaque archive comment")
        reader = Reader(raw)
        result = inspect(raw, reader=reader)
        self.assertEqual(result.metadata, metadata(raw))
        self.assertEqual(result.expanded_bytes, sum(len(value["payload"]) for value in values))
        self.assertEqual(tuple(entry.name for entry in result.metadata.entries),
                         ("BundleConfig.pb", "base/manifest/", "empty/", "base/dex/classes.dex"))
        policy.require_aab_content(result.metadata)
        self.assertFalse(reader.closed)
        self.assertEqual(reader.close_calls, 0)
        for obj, field in ((result, "expanded_bytes"), (result.metadata, "entries"),
                           (result.metadata.entries[0], "crc32")):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, field, None)

    def test_all_io_crc_and_decompression_calls_are_checkpointed_and_chunk_bounded(self):
        payload = b"bounded repeated content" * 10000
        raw = zip_bytes(member("compressed", payload, method=8))
        events, calls = [], []
        reader = Reader(raw, events)
        original_decompress, original_crc = zlib.decompressobj, binascii.crc32

        def check():
            events.append("check")

        def factory(wbits):
            self.assertEqual(wbits, -zlib.MAX_WBITS)
            events.append("decompressobj")
            return DeflateSpy(original_decompress(wbits), calls, events)

        def crc(data, value=0):
            events.append("crc")
            self.assertLessEqual(len(data), integrity.EXPANDED_CHUNK_BYTES)
            return original_crc(data, value)

        with patch.object(integrity.zlib, "decompressobj", side_effect=factory), \
                patch.object(integrity.binascii, "crc32", side_effect=crc):
            result = inspect(raw, reader=reader, checkpoint=check)
        self.assertEqual(result.expanded_bytes, len(payload))
        self.assertGreater(len(calls), 1)
        self.assertEqual(sum(output for _input, _limit, output in calls), len(payload))
        self.assertTrue(any(output == integrity.EXPANDED_CHUNK_BYTES for _input, _limit, output in calls))
        for supplied, limit, output in calls:
            self.assertLessEqual(supplied, integrity.READ_CHUNK_BYTES)
            self.assertTrue(0 < limit <= integrity.EXPANDED_CHUNK_BYTES)
            self.assertLessEqual(output, limit)
        for offset, length in reader.read_requests:
            self.assertTrue(0 < length <= integrity.READ_CHUNK_BYTES)
            self.assertLessEqual(offset + length, len(raw) + (1 if offset == len(raw) else 0))
        for index, event in enumerate(events):
            if event in {"seek", "read", "tell", "decompressobj", "decompress", "crc"}:
                self.assertEqual(events[index - 1], "check")
                self.assertEqual(events[index + 1], "check")

    def test_maximum_local_extra_and_raw_name_are_bounded_before_retention(self):
        extra = struct.pack("<HH", 0xCAFE, 65531) + b"x" * 65531
        raw = zip_bytes(member(b"n" * 4096, b"", local_extra=extra))
        reader = Reader(raw)
        self.assertEqual(inspect(raw, reader=reader).expanded_bytes, 0)
        self.assertTrue(all(0 < length <= integrity.READ_CHUNK_BYTES for _offset, length in reader.read_requests))
        self.refused("limit", inspect, zip_bytes(member("short", local={"name_size": 4097})))
        self.refused("layout", inspect, zip_bytes(member("short", local={"extra_size": 65535})))

    def test_local_interpretation_fields_must_match_the_admitted_central_entry(self):
        for field, value in (("signature", b"NOPE"), ("needed", 20), ("flags", 0), ("method", 8)):
            self.refused("layout", inspect, zip_bytes(member("file", local={field: value})))
        self.refused("zip64", inspect, zip_bytes(member("file", local={"needed": 45})))
        for field in ("compressed_size", "file_size"):
            self.refused("zip64", inspect, zip_bytes(member("file", local={field: 0xFFFFFFFF})))
        for flags in (0x0801, 0x0840, 0x2800):
            self.refused("encryption", inspect, zip_bytes(member("file", local={"flags": flags})))

    def test_non_descriptor_local_crc_and_sizes_are_not_ignored(self):
        for field in ("crc", "compressed_size", "file_size"):
            self.refused("layout", inspect, zip_bytes(member("file", b"abc", local={field: 1})))
        self.refused("layout", inspect, zip_bytes(member("file", b"abc", local={"flags": 0x0808})))

    def test_local_raw_name_must_be_identical_not_a_second_decoded_or_sanitized_view(self):
        self.refused("name", inspect, zip_bytes(member("one", local_name=b"two")))
        self.refused("name", inspect, zip_bytes(member("one", local_name=b"o\0e")))
        self.refused("layout", inspect, zip_bytes(member("\u00e9", local_name=b"\x82")))
        raw = zip_bytes(member(b"\x82", flags=0))
        self.assertEqual(inspect(raw).metadata.entries[0].name, "\u00e9")

    def test_local_extra_framing_and_critical_refusals_reuse_the_frozen_policy(self):
        for tag, reason in ((0x0001, "zip64"), (0x7075, "name"), (0x0017, "encryption"), (0x9901, "encryption")):
            self.refused(reason, inspect, zip_bytes(member("file", local_extra=struct.pack("<HH", tag, 0))))
        for extra in (b"x", struct.pack("<HH", 0xCAFE, 1), struct.pack("<HH", 0xCAFE, 0) + b"x"):
            self.refused("layout", inspect, zip_bytes(member("file", local_extra=extra)))

    def test_opaque_local_and_central_extras_can_legitimately_differ_without_interpretation(self):
        local = struct.pack("<HH", 0x5455, 5) + b"\x01\x01\0\0\0"
        central = struct.pack("<HH", 0x5455, 1) + b"\0"
        raw = zip_bytes(member("file", local_extra=local, central_extra=central,
                               local={"time": 1, "date": 2}, comment=b"opaque member comment"))
        self.assertEqual(inspect(raw).metadata, metadata(raw))

    def test_signed_and_unsigned_zip32_descriptors_and_complete_local_values_are_supported(self):
        for method in (0, 8):
            for form in ("signed", "unsigned"):
                value = member("file", b"descriptor payload", method=method, descriptor=form)
                self.assertEqual(inspect(zip_bytes(value)).expanded_bytes, len(value["payload"]))
                value["local"] = {key: value[key] for key in ("crc", "compressed_size", "file_size")}
                self.assertEqual(inspect(zip_bytes(value)).expanded_bytes, len(value["payload"]))

    def test_descriptor_fields_signature_width_and_mixed_local_placeholders_are_closed(self):
        value = member("file", b"abc", descriptor="signed")
        expected = (value["crc"], value["compressed_size"], value["file_size"])
        forms = [b"NOPE" + struct.pack("<3I", *expected),
                 struct.pack("<IQQ", *expected), b"PK\x07\x08" + struct.pack("<IQQ", *expected),
                 b"PK\x07\x08" + struct.pack("<3I", *expected) + b"x"]
        for index in range(3):
            changed = list(expected)
            changed[index] ^= 1
            forms.append(b"PK\x07\x08" + struct.pack("<3I", *changed))
        for form in forms:
            self.refused("layout", inspect, zip_bytes(member("file", b"abc", descriptor=form)))
        value["local"] = {"crc": value["crc"]}
        self.refused("layout", inspect, zip_bytes(value))
        self.refused("layout", inspect, zip_bytes(member("file", trailing=b"PK\x07\x08" + b"\0" * 12)))

    def test_unsigned_descriptor_crc_equal_to_optional_signature_is_explicitly_ambiguous(self):
        signature_crc = 0x08074B50
        self.refused("layout", inspect,
                     zip_bytes(member("file", b"x", descriptor="unsigned", crc=signature_crc)))
        # The signed 16-byte form is not misparsed as unsigned: this deliberately
        # wrong CRC reaches the actual payload check, not a signature heuristic.
        self.refused("crc", inspect,
                     zip_bytes(member("file", b"x", descriptor="signed", crc=signature_crc)))

    def test_complete_extents_refuse_gaps_unlisted_locals_prefixes_and_extra_overlap(self):
        hidden = struct.pack("<4s5H3I2H", b"PK\x03\x04", 10, 0x0800, 0, 0, 0, 0, 0, 0, 6, 0) + b"hidden"
        for gap in (b"x", hidden):
            self.refused("layout", inspect, zip_bytes(member("first", trailing=gap), member("second")))
            self.refused("layout", inspect, zip_bytes(member("only"), after_locals=gap))
        self.refused("layout", inspect, zip_bytes(member("file"), prefix=b"prefix"))
        self.refused("layout", inspect, zip_bytes(member("file", local={"extra_size": 1})))
        # Signature bytes inside a declared, CRC-checked STORED payload are DATA,
        # not an excuse for heuristic signature scanning or extra entry claims.
        self.assertEqual(inspect(zip_bytes(member("payload", hidden))).expanded_bytes, len(hidden))

    def test_stored_corruption_fails_crc_with_fixed_private_safe_diagnostics(self):
        value = member("PRIVATE-entry-name", b"abc", compressed_data=b"abd")
        error = self.refused("crc", inspect, zip_bytes(value))
        self.assertIsInstance(error, integrity.AndroidZipIntegrityError)
        self.assertEqual(str(error), "An Android ZIP entry failed its CRC integrity check.")
        self.assertNotIn("PRIVATE", str(error))
        self.assertIsNone(error.__cause__)

    def test_deflate_crc_and_actual_size_must_equal_the_same_central_view(self):
        payload = b"raw deflate payload" * 20
        self.refused("crc", inspect, zip_bytes(member("file", payload, method=8, crc=binascii.crc32(payload) ^ 1)))
        for size in (len(payload) - 1, len(payload) + 1):
            self.refused("size", inspect, zip_bytes(member("file", payload, method=8, file_size=size)))

    def test_invalid_wrapped_and_truncated_deflate_never_get_flush_or_eof_success(self):
        payload = b"abcdefg" * 100
        for compressed in (b"\x07\0", zlib.compress(payload), deflate(payload)[:-1]):
            self.refused("compression", inspect,
                         zip_bytes(member("file", payload, method=8, compressed_data=compressed)))

    def test_concatenated_and_trailing_deflate_data_are_refused_even_across_read_boundaries(self):
        payload = b"hello"
        for compressed in (deflate(payload) + b"x", deflate(payload) + deflate(b"second")):
            raw = zip_bytes(member("file", payload, method=8, compressed_data=compressed))
            self.refused("compression", inspect, raw)
            with patch.object(integrity, "READ_CHUNK_BYTES", 3):
                self.refused("compression", inspect, raw)

    def test_bomb_detection_bounds_output_to_declared_remaining_plus_one_and_fixed_member_limit(self):
        payload = b"x" * (4 * integrity.EXPANDED_CHUNK_BYTES)
        raw = zip_bytes(member("bomb", payload, method=8, file_size=1))
        calls, original = [], zlib.decompressobj
        with patch.object(integrity.zlib, "decompressobj",
                          side_effect=lambda wbits: DeflateSpy(original(wbits), calls)):
            self.refused("size", inspect, raw)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1:], (2, 2))
        # Lower only the inspector's fixed ceiling in this inert fault test;
        # production has no caller-selectable limit or large allocation fixture.
        with patch.object(integrity, "MAX_ENTRY_SIZE", 16):
            self.refused("limit", inspect, zip_bytes(member("file", b"x" * 32, method=8)))

    def test_actual_aggregate_quota_is_charged_across_stored_and_deflated_members(self):
        for method in (0, 8):
            raw = zip_bytes(member("first", b"a" * 16, method=method),
                            member("second", b"b" * 16, method=method))
            with patch.object(integrity, "MAX_TOTAL_SIZE", 20):
                self.refused("limit", inspect, raw)

    def test_no_progress_invalid_unconsumed_tail_or_oversized_native_output_fail_closed(self):
        raw = zip_bytes(member("file", b"abcdef", method=8))

        class Faulty:
            unused_data, eof = b"", False

            def __init__(self, fault):
                self.fault, self.calls, self.unconsumed_tail = fault, 0, b""

            def decompress(self, data, maximum):
                self.calls += 1
                if self.fault == "stall":
                    self.unconsumed_tail = data
                    return b""
                if self.fault == "tail-size":
                    self.unconsumed_tail = data + b"x"
                    return b""
                if self.fault == "tail-not-suffix":
                    self.unconsumed_tail = b"x" if not data.endswith(b"x") else b"y"
                    return b""
                self.unconsumed_tail = b""
                return b"x" * (maximum + 1)

        for fault in ("stall", "tail-size", "tail-not-suffix", "output-size"):
            stream = Faulty(fault)
            with patch.object(integrity.zlib, "decompressobj", return_value=stream):
                self.refused("compression", inspect, raw)
            self.assertEqual(stream.calls, 1)

    def test_empty_input_drain_remains_output_bounded_until_explicit_eof(self):
        raw = zip_bytes(member("file", b"abc", method=8))

        class DelayedEnd:
            unconsumed_tail, unused_data, eof = b"", b"", False

            def __init__(self):
                self.calls = []

            def decompress(self, data, maximum):
                self.calls.append((data, maximum))
                index = len(self.calls) - 1
                self.eof = index == 3
                return b"abc"[index:index + 1]

            def flush(self, *_args):
                raise AssertionError("flush is not a bounded drain")

        # Mechanical delayed-EOF injection, not a substitute for the real-zlib
        # fixture tests above. The same small valid ZIP backs the borrowed reader.
        stream = DelayedEnd()
        with patch.object(integrity, "EXPANDED_CHUNK_BYTES", 1), \
                patch.object(integrity.zlib, "decompressobj", return_value=stream):
            self.assertEqual(inspect(raw).expanded_bytes, 3)
        self.assertEqual(len(stream.calls), 4)
        self.assertTrue(stream.calls[0][0])
        self.assertTrue(all(data == b"" for data, _limit in stream.calls[1:]))
        self.assertTrue(all(limit == 1 for _data, limit in stream.calls))

    def test_short_oversized_or_non_bytes_reads_are_not_retried_or_adopted(self):
        raw = zip_bytes(member("file"))
        for transform in (lambda data: data[:-1], lambda data: data + b"x", bytearray, lambda _data: None):
            class BadRead(Reader):
                faults = 0

                def read(self, length=-1):
                    data = super().read(length)
                    if length > 1:
                        self.faults += 1
                        return transform(data)
                    return data

            reader = BadRead(raw)
            self.refused("read", inspect, raw, reader=reader)
            self.assertEqual(reader.faults, 1)
            self.assertFalse(reader.closed)
            self.assertEqual(reader.close_calls, 0)

    def test_reader_position_and_original_size_are_exact_without_size_refresh(self):
        raw = zip_bytes(member("file"))
        for method in ("seek", "tell"):
            reader = Reader(raw)
            with patch.object(reader, method, return_value=True):
                self.refused("read", inspect, raw, reader=reader)
        self.refused("changed", inspect, raw, reader=Reader(raw + b"x"))
        self.refused("read", inspect, raw, reader=Reader(raw[:-1]))
        self.refused("end", inspect, raw + b"x")

    def test_unsupported_metadata_is_refused_before_any_local_header_or_decompressor_use(self):
        for value, reason in ((member("file", central_extra=struct.pack("<HH", 1, 0)), "zip64"),
                              (member("file", central_extra=struct.pack("<HH", 0x7075, 0)), "name"),
                              (member("file", method=99), "compression")):
            raw = zip_bytes(value)
            reader = Reader(raw)
            with patch.object(integrity.zlib, "decompressobj", side_effect=AssertionError("not admitted")):
                self.refused(reason, inspect, raw, reader=reader)
            self.assertNotIn((0, policy.LOCAL_HEADER_BYTES), reader.read_requests)

    def test_final_metadata_rechecks_compare_bytes_not_only_retained_dataclass_fields(self):
        raw = zip_bytes(member("data", b"payload"), comment=b"opaque end comment")
        admitted = metadata(raw)
        payload_offset = policy.LOCAL_HEADER_BYTES + len(admitted.entries[0].raw_name)
        for changed_offset in (admitted.plan.central_directory.offset + 12, len(raw) - 1):
            changed = raw[:changed_offset] + bytes([raw[changed_offset] ^ 1]) + raw[changed_offset + 1:]
            self.assertEqual(metadata(changed), admitted)  # Timestamp/comment excluded from DATA view.

            class MutatingReader(Reader):
                changed = False

                def read(self, length=-1):
                    start = BytesIO.tell(self)
                    data = super().read(length)
                    if not self.changed and start == payload_offset and length == len(b"payload"):
                        position = BytesIO.tell(self)
                        BytesIO.seek(self, changed_offset)
                        BytesIO.write(self, bytes([raw[changed_offset] ^ 1]))
                        BytesIO.seek(self, position)
                        self.changed = True
                    return data

            reader = MutatingReader(raw)
            self.refused("changed", inspect, raw, reader=reader)
            self.assertTrue(reader.changed)

    def test_checkpoint_failure_before_work_and_at_final_veto_propagates_original_exception(self):
        raw = zip_bytes(member("file", b"abc", method=8))
        checks = []
        inspect(raw, checkpoint=lambda: checks.append(None))
        for stop_at in (1, 2, len(checks)):
            class OriginalStop(BaseException):
                pass

            original, reached = OriginalStop("PRIVATE original stop"), []
            reader = Reader(raw)

            def check():
                reached.append(None)
                if len(reached) == stop_at:
                    raise original

            with self.assertRaises(OriginalStop) as caught:
                inspect(raw, reader=reader, checkpoint=check)
            self.assertIs(caught.exception, original)
            self.assertEqual(len(reached), stop_at)
            self.assertFalse(reader.closed)
            if stop_at == 1:
                self.assertEqual(reader.events, [])

    def test_post_read_and_post_decompress_deadline_failures_are_not_data_errors(self):
        raw = zip_bytes(member("file", b"abc", method=8))
        payload_offset = policy.LOCAL_HEADER_BYTES + len(b"file")
        stopped = [False]
        original = RuntimeError("PRIVATE original deadline")

        class StopsAfterRead(Reader):
            def read(self, length=-1):
                start = BytesIO.tell(self)
                data = super().read(length)
                if start == payload_offset:
                    stopped[0] = True
                return data

        def check():
            if stopped[0]:
                raise original

        with self.assertRaises(RuntimeError) as caught:
            inspect(raw, reader=StopsAfterRead(raw), checkpoint=check)
        self.assertIs(caught.exception, original)
        # Even the same exception CLASS as zlib's parser failure must propagate
        # when raised by the owner checkpoint outside the narrow native call.
        stopped[0] = False
        original = zlib.error("PRIVATE owner checkpoint, not compressed data")
        factory = zlib.decompressobj
        with patch.object(integrity.zlib, "decompressobj", side_effect=lambda wbits: DeflateSpy(
                factory(wbits), [], after=lambda: stopped.__setitem__(0, True))):
            with self.assertRaises(zlib.error) as caught:
                inspect(raw, checkpoint=check)
        self.assertIs(caught.exception, original)

    def test_reader_and_unexpected_native_failures_are_not_flattened_or_retried(self):
        raw = zip_bytes(member("file", b"abc", method=8))
        for method in ("seek", "read", "tell"):
            reader = Reader(raw)
            original = OSError("PRIVATE original reader failure")
            with patch.object(reader, method, side_effect=original) as operation:
                with self.assertRaises(OSError) as caught:
                    inspect(raw, reader=reader)
                self.assertIs(caught.exception, original)
                self.assertEqual(operation.call_count, 1)
            self.assertFalse(reader.closed)
        for original in (RuntimeError("PRIVATE native failure"), MemoryError("PRIVATE allocation failure")):
            with patch.object(integrity.zlib, "decompressobj", side_effect=original) as operation:
                with self.assertRaises(type(original)) as caught:
                    inspect(raw)
                self.assertIs(caught.exception, original)
                self.assertEqual(operation.call_count, 1)
        with patch.object(integrity.zlib, "decompressobj", side_effect=zlib.error("PRIVATE zlib details")):
            error = self.refused("compression", inspect, raw)
        self.assertNotIn("PRIVATE", str(error))

    def test_hard_inputs_refuse_before_io_and_checkpoint_cannot_return_a_boolean(self):
        raw = zip_bytes(member("file"))
        for size, reason in ((True, "input"), (22.0, "input"), (21, "limit"), (policy.MAX_AAB_BYTES + 1, "limit")):
            reader = Reader(raw)
            self.refused(reason, inspect, raw, reader=reader, archive_bytes=size)
            self.assertEqual(reader.events, [])
        reader = Reader(raw)
        self.refused("input", integrity.inspect_zip_integrity, reader, archive_bytes=len(raw), checkpoint=42)
        self.refused("input", inspect, raw, reader=reader, checkpoint=lambda: False)
        self.assertEqual(reader.events, [])

    def test_no_path_open_close_zipfile_or_native_aab_claim_follows_from_integrity(self):
        raw = zip_bytes(member("ordinary-file", b"not an Android bundle"))
        reader = Reader(raw)
        with patch("builtins.open", side_effect=AssertionError("no path opens")), \
                patch.object(reader, "close", side_effect=AssertionError("not this helper's close")):
            result = inspect(raw, reader=reader)
        self.assertEqual(result.expanded_bytes, len(b"not an Android bundle"))
        self.refused("content", policy.require_aab_content, result.metadata)
        self.assertFalse(reader.closed)


if __name__ == "__main__":
    unittest.main()
