"""Inert XML/policy regressions: no artifact, process, SDK or Store execution.

The shared manifest policy consumes synthetic strings only. These tests do not
qualify bundletool, its captured bytes, a build owner or a packaged XML runtime.
"""
from __future__ import annotations

import builtins
import unittest
from unittest.mock import patch

from mobile_release import android_manifest as policy
from mobile_release.config import ReleaseVersion
from mobile_release.reporting import Status


def manifest(*, prefix="android", package="org.fixture.app", code="42", name="1.2.3",
             application="<application />", extra="", before=""):
    return (
        f'{before}<manifest xmlns:{prefix}="{policy.ANDROID_NAMESPACE}" '
        f'package="{package}" {prefix}:versionCode="{code}" '
        f'{prefix}:versionName="{name}" {extra}>{application}</manifest>'
    )


class ManifestPolicyTests(unittest.TestCase):
    def findings(self, text, **kwargs):
        return policy.validate_android_manifest(
            text, expected_application_id="org.fixture.app",
            release=ReleaseVersion(name="1.2.3", build=42), **kwargs,
        )

    def assert_rejected(self, text, reason=None):
        with self.assertRaises(policy.ManifestInspectionError) as caught:
            policy.parse_android_manifest(text)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_real_root_and_equivalent_namespace_prefixes(self):
        for prefix in ("android", "a", "release"):
            with self.subTest(prefix=prefix):
                parsed = policy.parse_android_manifest(manifest(prefix=prefix))
                self.assertEqual(parsed, policy.AndroidManifest("org.fixture.app", "42", "1.2.3", False, False))
                self.assertEqual([(f.code, f.status) for f in self.findings(manifest(prefix=prefix))],
                                 [("android.aab.manifest", Status.PASS)])
        # XML identity is the parsed value, not a particular textual encoding.
        self.assertEqual(self.findings(manifest(name="1&#46;2.3"))[0].status, Status.PASS)

    def test_comments_descendants_and_suffix_attributes_cannot_supply_identity(self):
        decoys = (
            '<!-- package="org.fixture.app" android:versionCode="42" android:versionName="1.2.3" -->'
            '<child package="org.fixture.app" android:versionCode="42" android:versionName="1.2.3" />'
            '<application />'
        )
        found = self.findings(manifest(
            package="org.wrong.app", code="7", name="9.9", application=decoys,
            extra='notpackage="org.fixture.app" android:notversionCode="42" android:notversionName="1.2.3"',
        ))
        self.assertEqual({f.code for f in found},
                         {"android.aab.package", "android.aab.versionCode", "android.aab.versionName"})
        self.assertTrue(all(f.status == Status.FAIL for f in found))
        self.assert_rejected("<wrapper>" + manifest() + "</wrapper>", "root")

    def test_missing_wrong_namespace_and_lookalike_identity_reject(self):
        valid = manifest()
        for text in (
            valid.replace('package="org.fixture.app"', 'android:package="org.fixture.app"'),
            valid.replace('android:versionCode="42"', 'versionCode="42"'),
            valid.replace('android:versionName="1.2.3"', 'android:notversionName="1.2.3"'),
            valid.replace(policy.ANDROID_NAMESPACE, "https://example.invalid/android"),
            valid.replace('package="org.fixture.app"', 'package=""'),
        ):
            with self.subTest(text=text):
                self.assert_rejected(text, "identity")
        self.assert_rejected(valid.replace("<manifest ", '<manifest xmlns="urn:other" '), "root")

    def test_release_flags_use_actual_direct_application_and_xml_boolean_values(self):
        for field in ("debuggable", "testOnly"):
            for value in ("true", "1"):
                with self.subTest(field=field, value=value):
                    found = self.findings(manifest(application=f'<application android:{field}="{value}" />'))
                    self.assertEqual([(f.code, f.status) for f in found],
                                     [("android.aab.release-flags", Status.FAIL)])
            for value in ("false", "0"):
                self.assertEqual(self.findings(manifest(application=f'<application android:{field}="{value}" />'))[0].status,
                                 Status.PASS)
            for value in ("TRUE", "False", "@bool/release_flag", "", "false "):
                self.assert_rejected(manifest(application=f'<application android:{field}="{value}" />'), "flags")
        # An unrelated descendant/comment must not change the real application.
        text = manifest(application=(
            '<application android:debuggable="false"><child android:testOnly="true" /></application>'
            '<!-- android:debuggable="true" -->'
        ))
        self.assertEqual(self.findings(text)[0].status, Status.PASS)

    def test_missing_ambiguous_or_namespaced_application_cannot_establish_flags(self):
        for application in ("", "<application /><application />", "<child><application /></child>",
                            '<a:application xmlns:a="urn:other" />'):
            with self.subTest(application=application):
                self.assert_rejected(manifest(application=application), "application")

    def test_malformed_duplicates_and_unbound_prefixes_are_not_repaired(self):
        for text in (
            manifest().replace(' xmlns:android="' + policy.ANDROID_NAMESPACE + '"', ""),
            manifest(extra='package="org.fixture.app"'),
            manifest().replace("</manifest>", ""),
            manifest() + manifest(),
            manifest(name="&unknown;"),
            manifest(extra='xmlns:b="' + policy.ANDROID_NAMESPACE + '" b:versionCode="42"'),
        ):
            with self.subTest(text=text):
                self.assert_rejected(text, "xml")

    def test_declarations_and_external_entities_reject_before_parser_creation(self):
        from xml.parsers import expat
        prefixes = (
            '<!DOCTYPE manifest SYSTEM "file:///never-read">',
            '<!DOCTYPE manifest [<!ENTITY version "1.2.3">]>',
            '<!ENTITY version SYSTEM "https://never-contact.invalid/value">',
        )
        with patch.object(expat, "ParserCreate", side_effect=AssertionError("declarations must reject before parsing")):
            for prefix in prefixes:
                self.assert_rejected(manifest(before=prefix), "xml")

    def test_xml_version_encoding_and_instruction_policy(self):
        self.assertEqual(self.findings(manifest(before='<?xml version="1.0" encoding="UTF-8"?>'))[0].status,
                         Status.PASS)
        for prefix in ('<?xml version="1.1"?>', '<?xml version="1.0" encoding="UTF-16"?>', '<?custom value?>'):
            self.assert_rejected(manifest(before=prefix), "xml")

    def test_input_utf8_and_work_limits_fail_closed(self):
        self.assert_rejected("x" * (policy.MAX_MANIFEST_BYTES + 1), "limit")
        self.assert_rejected("\u03bb" * (policy.MAX_MANIFEST_BYTES // 2 + 1), "limit")
        self.assert_rejected("\ud800", "input")
        self.assert_rejected(b"<manifest />", "input")
        for setting, limit, text in (
            ("MAX_DEPTH", 2, manifest(application="<application><child /></application>")),
            ("MAX_ELEMENTS", 2, manifest(application="<application /><child />")),
            ("MAX_ATTRIBUTES", 2, manifest()),
            ("MAX_TOTAL_ATTRIBUTES", 3, manifest(application='<application label="x" />')),
            ("MAX_NAMESPACES", 1, manifest(extra='xmlns:extra="urn:other"')),
            ("MAX_NAME_CHARS", 8, manifest()),
            ("MAX_VALUE_CHARS", 8, manifest()),
        ):
            with self.subTest(setting=setting), patch.object(policy, setting, limit):
                self.assert_rejected(text, "limit")

    def test_cancellation_and_fatal_callback_errors_never_become_policy_results(self):
        class Interrupted(BaseException):
            pass

        class Guard:
            def __init__(self, stop):
                self.stop, self.calls = stop, 0

            def check(self):
                self.calls += 1
                if self.calls == self.stop:
                    raise Interrupted("original interruption")

        for stop in (1, 4, 8):
            guard = Guard(stop)
            with self.subTest(stop=stop), self.assertRaises(Interrupted):
                self.findings(manifest(application="<application><child /></application>"), cancellation=guard)
            self.assertEqual(guard.calls, stop)
        with patch("xml.parsers.expat.ParserCreate", side_effect=MemoryError("allocation failed")):
            with self.assertRaises(MemoryError):
                self.findings(manifest())

    def test_missing_xml_runtime_refuses_without_regex_fallback(self):
        original_import = builtins.__import__

        def without_xml(name, *args, **kwargs):
            if name == "xml.parsers":
                raise ImportError("synthetic missing module detail")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=without_xml):
            found = self.findings(manifest())
        self.assertEqual([(f.code, f.status) for f in found], [("android.aab.manifest", Status.FAIL)])
        self.assertIn("runtime", found[0].message)
        self.assertIn("XML parser", found[0].remediation)
        self.assertNotIn("synthetic", str(found))

    def test_parser_and_identity_failure_diagnostics_do_not_reflect_input(self):
        marker = "private-fixture-marker"
        for text in (manifest(package=marker), manifest(name=marker), manifest(extra=marker),
                     manifest(application=f'<application android:debuggable="{marker}" />')):
            found = self.findings(text)
            self.assertTrue(found and all(f.status == Status.FAIL for f in found))
            self.assertNotIn(marker, str([f.as_dict() for f in found]))


if __name__ == "__main__":
    unittest.main()
