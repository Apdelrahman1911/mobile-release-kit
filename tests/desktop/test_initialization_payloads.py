"""Pure layout regressions: no project/CLI/native execution."""
from __future__ import annotations

import unittest

from mobile_release.errors import ValidationError
from mobile_release.initialization_payloads import metadata_skeleton


class InitializationPayloadTests(unittest.TestCase):
    def test_shared_platform_layout_and_cli_default(self):
        config = {"android": {"enabled": True}, "ios": {"enabled": True},
                  "metadata": {"root": "release/store/", "androidLocales": ["en-US"],
                               "iosLocales": ["en-US"]}}
        expected = tuple(sorted((
            "release/store/android/en-US/title.txt",
            "release/store/android/en-US/short_description.txt",
            "release/store/android/en-US/full_description.txt",
            "release/store/android/en-US/changelogs/default.txt",
            "release/store/ios/en-US/description.txt",
            "release/store/ios/en-US/keywords.txt",
            "release/store/ios/en-US/privacy_url.txt",
            "release/store/ios/en-US/support_url.txt",
            "release/store/ios/en-US/release_notes.txt",
            "release/store/review/ios-beta-notes.txt",
            "release/store/review/ios-notes.txt",
            "release/store/testflight/what-to-test.txt",
        )))
        self.assertEqual(metadata_skeleton(config), expected)
        self.assertEqual(metadata_skeleton(config, max_paths=12), expected)
        with self.assertRaises(ValidationError):
            metadata_skeleton(config, max_paths=11)
        config["android"]["enabled"] = False
        self.assertEqual(metadata_skeleton(config, max_paths=8),
                         tuple(path for path in expected if "/android/" not in path))
        config["ios"]["enabled"] = False
        self.assertEqual(metadata_skeleton(config, max_paths=0), ())
        self.assertEqual(metadata_skeleton({}), ())
        # iOS review/TestFlight skeleton exists even without localized text.
        self.assertEqual(metadata_skeleton({"ios": {"enabled": True}}), tuple(sorted((
            "release/store/review/ios-beta-notes.txt",
            "release/store/review/ios-notes.txt",
            "release/store/testflight/what-to-test.txt",
        ))))

    def test_bound_precedes_locale_iteration(self):
        class NoIteration(list):
            def __iter__(self):
                raise AssertionError("path iteration occurred before count admission")
        config = {"android": {"enabled": True},
                  "metadata": {"androidLocales": NoIteration(["en-US"] * 63)}}
        with self.assertRaisesRegex(ValidationError, "exceeds"):
            metadata_skeleton(config, max_paths=250)
        config = {"ios": {"enabled": True},
                  "metadata": {"iosLocales": NoIteration(["en-US"] * 50)}}
        with self.assertRaisesRegex(ValidationError, "exceeds"):
            metadata_skeleton(config, max_paths=250)

    def test_explicit_limit_is_not_a_coercion_or_truncation(self):
        for value in (True, False, -1, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                metadata_skeleton({}, max_paths=value)
        # Custom roots and deterministic sorted output preserve old policy.
        config = {"android": {"enabled": True},
                  "metadata": {"root": "custom/text///", "androidLocales": ["fr", "en"]}}
        paths = metadata_skeleton(config)
        self.assertEqual(len(paths), 8)
        self.assertEqual(paths, tuple(sorted(paths)))
        self.assertTrue(all(path.startswith("custom/text/android/") for path in paths))
        self.assertEqual(metadata_skeleton(config, max_paths=8), paths)
