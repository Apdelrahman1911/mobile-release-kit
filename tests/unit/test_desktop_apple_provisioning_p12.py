"""Bounded passive DATA tests; no key/P12 creation, native tools or files."""
from __future__ import annotations

import hashlib
import struct
import unittest

from mobile_release import _desktop_apple_provisioning_p12 as p12
from mobile_release.apple_provisioning_api import ProvisioningError


def frame(leaf=b"public-leaf-data", spki=b"public-spki-data", chain=(b"public-ca-data",)):
    return (p12.MAGIC + struct.pack(">IIB", len(leaf), len(spki), len(chain)) + leaf + spki
            + b"".join(struct.pack(">I", len(item)) + item for item in chain))


class P12PublicExtractionDataTests(unittest.TestCase):
    def test_exact_public_projection_and_required_original_expected_leaf(self):
        leaf, spki, chain = b"public-leaf-data", b"public-spki-data", (b"public-ca-data",)
        expected = hashlib.sha256(leaf).hexdigest()
        self.assertEqual(p12.parse_public_frame(frame(), expected), (leaf, spki, chain))
        colon = ":".join(expected[i:i + 2].upper() for i in range(0, 64, 2))
        self.assertEqual(p12.parse_public_frame(frame(), colon), (leaf, spki, chain))
        for digest in ("", "00" * 32, "xx" * 32, expected + "\n", ":" * 95):
            with self.subTest(digest_shape=len(digest)), self.assertRaises(ProvisioningError):
                p12.parse_public_frame(frame(), digest)

    def test_closed_lengths_and_chain_prevent_partial_ambiguous_or_extra_projection(self):
        expected = hashlib.sha256(b"public-leaf-data").hexdigest()
        ordinary = frame()
        rejected = [ordinary[:-1], ordinary + b"extra", b" " + ordinary, bytearray(ordinary),
                    frame(chain=(b"public-ca-data",) * 2), frame(chain=(b"public-leaf-data",)),
                    frame(chain=(b"x",) * 9), frame(spki=b""), frame(chain=(b"",)),
                    frame(spki=b"x" * (p12.SPKI_LIMIT + 1)),
                    frame(chain=(b"x" * (p12.CERTIFICATE_LIMIT + 1),)),
                    p12.MAGIC + struct.pack(">IIB", 0xffffffff, 1, 0) + b"x"]
        for index, value in enumerate(rejected):
            with self.subTest(case=index), self.assertRaises(ProvisioningError):
                p12.parse_public_frame(value, expected)
        self.assertLess(p12.OUTPUT_LIMIT, p12.PRIVATE_OUTPUT_LIMIT)
        # Decoder returns syntax-bound public facts, not parsed DER, trust or
        # private-key ownership. Only actual admitted helper+C/A/W proves that.
        self.assertEqual(p12.parse_public_frame(frame(chain=()), expected)[2], ())

    def test_profile_mode_private_tuple_is_same_original_and_strictly_bounded(self):
        original = (b"inert-p8", b"ABCDEFGHIJ", b"00112233-4455-6677-8899-aabbccddeeff",
                    b"inert-not-a-p12", b"inert-not-a-secret")
        self.assertIs(p12._material(original), original)
        for value in (original[:3], list(original), original + (b"extra",),
                      (*original[:3], bytearray(original[3]), original[4]),
                      (*original[:3], b"", original[4]),
                      (*original[:3], b"x" * (p12.P12_LIMIT + 1), original[4]),
                      (*original[:4], b"x" * (p12.PASSWORD_LIMIT + 1)),
                      (*original[:4], b"bad\0value"), (*original[:4], b"\xff"),
                      (b"x" * (p12.P8_LIMIT + 1), *original[1:])):
            with self.subTest(parts=len(value)), self.assertRaises(ProvisioningError):
                p12._material(value)
        self.assertEqual(p12.P12_LIMIT, 4 * 1024 * 1024)
        self.assertEqual(p12.PASSWORD_LIMIT, 4096)

    def test_foreign_operation_does_not_start_runtime_or_scratch(self):
        # A lookalike cannot enter the original source/operation graph. This
        # checks an actual closed-type refusal, not a fake successful owner.
        class Foreign:
            def __getattribute__(self, name):
                raise AssertionError("foreign operation must not be inspected")
        with self.assertRaises(ProvisioningError):
            p12.P12Extraction(Foreign())


if __name__ == "__main__":
    unittest.main()
