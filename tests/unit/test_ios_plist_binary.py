"""Original-byte parser contracts, independent of stdlib's permissive decoder."""
from __future__ import annotations

import math
import plistlib
import random
import struct
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline, MAX_INSPECTION_SECONDS
from mobile_release.ios_artifacts import typed_plist
from mobile_release.ios_entitlements import load_plist_dictionary, typed_value

from .ios_entitlement_helpers import binary_dictionary, binary_plist, malformed_binary_cases


class BinaryPlistTests(unittest.TestCase):
    def test_all_malformed_original_objects_reject_at_both_readers_before_stdlib(self):
        with tempfile.TemporaryDirectory(prefix="mrk-binary-contract-") as directory:
            path = Path(directory) / "Info.plist"
            for name, raw in malformed_binary_cases().items():
                path.write_bytes(raw)
                for reader in (lambda: load_plist_dictionary(raw), lambda: typed_plist(path)):
                    with self.subTest(case=name), patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaises(ValidationError) as error:
                        reader()
                    self.assertNotIn("canary", str(error.exception))

    def test_normal_writers_and_all_supported_table_widths_and_physical_orders(self):
        expected = {"x": True}
        for width in range(1, 9):
            for padding in (b"", b"\0\x0f\0"):
                raw = binary_dictionary(b"\x09", offset_width=width, reference_width=width,
                                        order=[2, 0, 1], leading=padding, padding=padding)
                with self.subTest(width=width, padding=padding):
                    self.assertEqual(load_plist_dictionary(raw), expected)
        values = {"": "", "unicode": "مرحبا 😀\x00\r\n", "empty": [[], {}, b""],
                  "array": list(range(512)), "bytes": bytes(range(256)),
                  "date": datetime(2026, 9, 5), "int": (1 << 64) - 1}
        self.assertEqual(load_plist_dictionary(plistlib.dumps(values, fmt=plistlib.FMT_BINARY)), values)
        self.assertEqual(load_plist_dictionary(binary_plist([b"\x09", b"\xd0"], root=1)), {})

    def test_extended_short_lengths_and_empty_utf16_data_arrays(self):
        for width in (1, 2, 4, 8):
            prefix = bytes((0x10 + width.bit_length() - 1,)) + (1).to_bytes(width, "big")
            for tag, body, expected in ((0x4f, b"A", b"A"), (0x5f, b"A", "A"),
                                        (0x6f, b"\0A", "A"), (0xaf, b"\x01", ["x"]),
                                        (0xdf, b"\x01\x01", {"x": "x"})):
                with self.subTest(width=width, tag=tag):
                    self.assertEqual(load_plist_dictionary(binary_dictionary(bytes((tag,)) + prefix + body)), {"x": expected})
        for tag, expected in ((0x40, b""), (0x50, ""), (0x60, ""), (0xa0, []), (0xd0, {})):
            self.assertEqual(load_plist_dictionary(binary_dictionary(bytes((tag,)))), {"x": expected})
        self.assertEqual(load_plist_dictionary(binary_dictionary(b"\x62\xd8\x3d\xde\x00")), {"x": "😀"})
        self.assertEqual(load_plist_dictionary(binary_dictionary(b"\x52\0\x01")), {"x": "\0\x01"})

    def test_integer_width_semantics_and_zero_extended_unsigned_64(self):
        for width in (1, 2, 4, 8):
            marker = 0x10 + width.bit_length() - 1
            expected = -1 if width == 8 else (1 << (8 * width)) - 1
            self.assertEqual(load_plist_dictionary(binary_dictionary(bytes((marker,)) + b"\xff" * width)), {"x": expected})
        for value in (0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            with self.subTest(value=value):
                self.assertEqual(load_plist_dictionary(binary_dictionary(b"\x14" + value.to_bytes(16, "big"))), {"x": value})
        self.assertEqual(load_plist_dictionary(binary_dictionary(b"\x13" + (-(1 << 63)).to_bytes(8, "big", signed=True))), {"x": -(1 << 63)})

    def test_binary_dates_preserve_original_double_bits_without_rounding(self):
        epoch = datetime(2001, 1, 1)
        for seconds in (0.0, 1e-6, -1e-6, .123456, -.123456, .5, -.5, 1.0, -1.0, 810000000.123456,
                        (datetime.min - epoch).total_seconds(), (datetime(9999, 12, 31, 23, 59, 59) - epoch).total_seconds()):
            raw = struct.pack(">d", seconds)
            actual = load_plist_dictionary(binary_dictionary(b"\x33" + raw))["x"]
            with self.subTest(seconds=seconds):
                self.assertEqual(struct.pack(">d", (actual - epoch).total_seconds()), raw)
                self.assertEqual(actual, epoch + timedelta(seconds=seconds))

    def test_real_width_sign_finite_extremes_and_subnormals_are_exact(self):
        for fmt, marker, values in ((">f", 0x22, (0.0, -0.0, 1.5, -1.5, .1, math.ldexp(1, -149), float.fromhex("0x1.fffffep127"))),
                                    (">d", 0x23, (0.0, -0.0, 1.5, -1.5, .1, math.ldexp(1, -1074), float.fromhex("0x1.fffffffffffffp1023")))):
            for value in values:
                encoded = struct.pack(fmt, value)
                expected = struct.unpack(fmt, encoded)[0]
                actual = load_plist_dictionary(binary_dictionary(bytes((marker,)) + encoded))["x"]
                with self.subTest(fmt=fmt, value=value):
                    self.assertEqual(struct.pack(">d", actual), struct.pack(">d", expected))
                    self.assertEqual(typed_value(actual), typed_value(expected))
        self.assertNotEqual(typed_value(-0.0), typed_value(0.0))
        self.assertEqual(typed_value(struct.unpack(">f", struct.pack(">f", 1.5))[0]), typed_value(1.5))
        self.assertNotEqual(typed_value(struct.unpack(">f", struct.pack(">f", .1))[0]), typed_value(.1))

    def test_graph_depth_includes_cached_subtree_height_and_disconnected_components(self):
        # Shared array3 is visited shallow first, then reused inside array4.
        raw = binary_plist([b"\xd2\x01\x02\x03\x04", b"\x51a", b"\x51b", b"\xa1\x05", b"\xa1\x03", b"\x09"])
        with patch("mobile_release.ios_entitlements.MAX_VALUE_DEPTH", 3):
            self.assertEqual(load_plist_dictionary(raw), {"a": [True], "b": [[True]]})
        with patch("mobile_release.ios_entitlements.MAX_VALUE_DEPTH", 2), patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "depth|graph"):
            load_plist_dictionary(raw)
        for disconnected in (False, True):
            objects = [b"\xd0" if disconnected else b"\xd1\x01\x02", b"\x51x"]
            objects += [b"\xa1" + bytes((index + 1,)) for index in range(2, 68)] + [b"\x09"]
            with self.subTest(disconnected=disconnected), patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "depth"):
                load_plist_dictionary(binary_plist(objects))

    def test_expanded_dag_and_raw_reference_budgets_precede_converter_allocation(self):
        # Small acyclic graph with exponentially many expanded leaf occurrences.
        objects = [b"\xd1\x01\x02", b"\x51x"]
        objects += [b"\xa2" + bytes((index + 1,)) * 2 for index in range(2, 19)] + [b"\x09"]
        with patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "expanded"):
            load_plist_dictionary(binary_plist(objects))
        # Four references (including keys), five expanded values, four objects.
        raw = binary_plist([b"\xd1\x01\x02", b"\x51x", b"\xa2\x03\x03", b"\x09"])
        with patch("mobile_release.ios_entitlements.MAX_VALUE_NODES", 5):
            self.assertEqual(load_plist_dictionary(raw), {"x": [True, True]})
        with patch("mobile_release.ios_entitlements.MAX_VALUE_NODES", 4), patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "expanded"):
            load_plist_dictionary(raw)
        huge = binary_dictionary(b"\xaf\x12" + (100001).to_bytes(4, "big"))
        with patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "reference count"):
            load_plist_dictionary(huge)

    def test_large_shared_keys_are_decoded_once_per_object_not_per_reference(self):
        import mobile_release.ios_plist_binary as binary
        key = b"k" * 65536
        # Root is empty; every disconnected dictionary must still be validated.
        objects = [b"\xd0", b"\x5f\x12" + len(key).to_bytes(4, "big") + key, b"\x09"]
        objects.extend([b"\xd1\x01\x02"] * 100)
        with patch.object(binary, "_string", wraps=binary._string) as decode:
            self.assertEqual(load_plist_dictionary(binary_plist(objects)), {})
        self.assertEqual(decode.call_count, 1)

    def test_deadline_expiry_during_binary_decoding_precedes_stdlib(self):
        import mobile_release.ios_plist_binary as binary
        raw = binary_dictionary(b"\x51y")
        original = binary._string
        with patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
            deadline = InspectionDeadline()
            def decode(*args):
                result = original(*args)
                clock.return_value = MAX_INSPECTION_SECONDS
                return result
            with patch.object(binary, "_string", side_effect=decode) as parser, patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "shared time bound"):
                load_plist_dictionary(raw, deadline=deadline)
            self.assertEqual(parser.call_count, 1)

    def test_deadline_interrupts_actual_reference_key_and_graph_traversal(self):
        import mobile_release.ios_plist_binary as binary
        raw = binary_plist([b"\xd2\x01\x02\x03\x03", b"\x51a", b"\x51b", b"\x09"])
        for phase in ("references", "keys", "graph"):
            completed = []
            with self.subTest(phase=phase), patch("mobile_release.inspection.time.monotonic", return_value=0) as clock:
                deadline = InspectionDeadline()
                def expire():
                    completed.append(phase)
                    clock.return_value = MAX_INSPECTION_SECONDS
                class Integers:
                    @staticmethod
                    def from_bytes(data, order):
                        value = int.from_bytes(data, order)
                        if value < 8:  # Actual first reference, not an object offset.
                            expire()
                        return value
                class Keys(set):
                    def add(self, value):
                        super().add(value)
                        expire()
                def key_set(*args):
                    return set(*args) if args else Keys()
                def height(*args):
                    value = max(*args)
                    expire()
                    return value
                name, replacement = {"references": ("int", Integers), "keys": ("set", key_set), "graph": ("max", height)}[phase]
                with patch.object(binary, name, replacement, create=True), patch("plistlib.loads", side_effect=AssertionError("conversion must not run")), self.assertRaisesRegex(ValidationError, "shared time bound"):
                    load_plist_dictionary(raw, deadline=deadline)
                self.assertEqual(completed, [phase])

    def test_seeded_bounded_raw_mutations_never_escape_as_unhandled_exceptions(self):
        source = plistlib.dumps({"x": [1, 2, 3], "data": b"abcd"}, fmt=plistlib.FMT_BINARY)
        generator = random.Random(7007)
        rejected = 0
        for _ in range(500):
            raw = bytearray(source)
            raw[generator.randrange(len(raw))] = generator.randrange(256)
            try:
                load_plist_dictionary(bytes(raw))
            except ValidationError:
                rejected += 1
        self.assertGreater(rejected, 300)


if __name__ == "__main__":
    unittest.main()
