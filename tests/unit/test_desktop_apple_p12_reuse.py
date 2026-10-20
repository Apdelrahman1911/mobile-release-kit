"""Comparison DATA only; no manufactured native loan, holder or finality."""
import hashlib
import unittest

from mobile_release._desktop_apple_p12_reuse import _compare
from mobile_release.apple_provisioning_api import ProvisioningError


class P12ReuseComparisonTests(unittest.TestCase):
    def test_exact_leaf_and_full_spki_required_not_an_old_hash_only(self):
        leaf, spki = b"synthetic public leaf", b"synthetic full public spki"
        self.assertEqual(_compare(leaf, spki, leaf, spki),
                         (hashlib.sha256(leaf).hexdigest(), hashlib.sha256(spki).hexdigest()))
        for values in ((leaf, spki, leaf + b"x", spki),
                       (leaf, spki, leaf, spki + b"x"),
                       (leaf, spki, hashlib.sha256(leaf).digest(), spki)):
            with self.assertRaises(ProvisioningError):
                _compare(*values)

    def test_missing_oversize_or_mutable_data_is_not_a_current_comparison(self):
        for leaf, spki in ((b"", b"s"), (b"l", b""),
                           (b"l" * (64 * 1024 + 1), b"s"),
                           (b"l", b"s" * (16 * 1024 + 1)),
                           (bytearray(b"l"), b"s")):
            with self.assertRaises(ProvisioningError):
                _compare(leaf, spki, leaf, spki)


if __name__ == "__main__":
    unittest.main()
