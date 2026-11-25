"""Task-owned inert saved projects; no Gradle, native actor or network."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from mobile_release._tool_acquisition_spec import AcquisitionError
from mobile_release._tool_requirements_capture import Capture, CONFIG, directory_identity, module_files
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.tool_requirements import FILE_LIMIT


def saved_config(module=":app"):
    return {"schemaVersion": 1, "version": {"source": "version.properties", "nameKey": "VERSION_NAME", "buildKey": "VERSION_CODE"},
            "source": {"candidateBranch": "candidate", "productionBranch": "main"},
            "android": {"enabled": True, "identityStatus": "unverified", "applicationId": "com.example.fixture", "module": module},
            "ios": {"enabled": False}, "metadata": {"root": "metadata", "androidLocales": ["en-US"], "iosLocales": []},
            "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
            "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mrk-tool-source-fixture-")
        self.root = Path(self.temp.name)
        self.write(CONFIG, json.dumps(saved_config()))
        self.write("app/build.gradle.kts", 'plugins { id("com.android.application") }\nandroid { compileSdk = 35 }\nkotlin { jvmToolchain(17) }')
        self.write("build.gradle.kts", 'plugins { id("com.android.application") version "8.9.2" apply false }')
        self.write("gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.5-bin.zip\ndistributionSha256Sum=" + "a" * 64)

    def tearDown(self):
        self.temp.cleanup()  # Only this test's disposable, inert files.

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    @contextmanager
    def captured(self):
        raw = (self.root / CONFIG).read_bytes()
        guard = DefaultCancellation(RuntimeError, "synthetic capture interrupted")
        capture = Capture(self.root, directory_identity(self.root.stat()),
                          {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, guard)
        scope = CleanupScope(guard, capture.close, owns_cancellation=True, first_primary=True)
        try:
            with scope:
                guard.install()
                guard.activate()
                yield capture
        finally:
            scope.__exit__(*sys.exc_info())
        self.assertTrue(capture.closed)

    def test_actual_fixed_capture_keeps_exact_private_footprint_and_source_hints(self):
        with self.captured() as capture:
            result = capture.run()
            self.assertFalse(result["projectCodeExecuted"])
            self.assertEqual(result["android"]["agp"]["value"], "8.9.2")
            self.assertEqual(result["android"]["sdkPlatform"]["value"], "android-35")
            footprint = capture.footprint()
            self.assertEqual(footprint["buildFile"], "app/build.gradle.kts")
            self.assertIn("settings.gradle", footprint["missing"])
            self.assertEqual({row["relative"] for row in footprint["files"]},
                             {CONFIG, "app/build.gradle.kts", "build.gradle.kts", "gradle/wrapper/gradle-wrapper.properties"})
            for row in footprint["files"]:
                self.assertEqual(row["sha256"], hashlib.sha256((self.root / row["relative"]).read_bytes()).hexdigest())
            self.assertNotIn("applicationId", json.dumps(footprint))
            capture.check()

    def test_dotted_and_traversal_module_grammar_refuses_before_any_module_read(self):
        for value in (":.", ":..", ":foo.bar", ":a:..", "::app", ":a/b", ":a\\b", ":é", "", None, ":" + "a:" * 12 + "b"):
            with self.subTest(value=value), self.assertRaises(AcquisitionError):
                module_files(value)
        self.assertEqual(module_files(":"), ("build.gradle", "build.gradle.kts"))
        self.assertEqual(module_files(":mobile:demo-app"), ("mobile/demo-app/build.gradle", "mobile/demo-app/build.gradle.kts"))
        self.write(CONFIG, json.dumps(saved_config(":..")))
        original = Capture._read
        reads = []

        def record(capture, name):
            reads.append(name)
            return original(capture, name)

        with self.captured() as capture, patch.object(Capture, "_read", record), self.assertRaises(AcquisitionError):
            capture.run()
        self.assertEqual(reads, [CONFIG])

    def test_added_negative_input_and_changed_same_file_hash_invalidate(self):
        with self.captured() as capture:
            capture.run()
            self.write("settings.gradle", "// new input")
            with self.assertRaises(AcquisitionError):
                capture.check()
        (self.root / "settings.gradle").unlink()
        with self.captured() as capture:
            capture.run()
            path = self.root / "app/build.gradle.kts"
            before = path.stat()
            path.write_text(path.read_text().replace("35", "34"))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaises(AcquisitionError):
                capture.check()

    def test_symlink_and_oversized_leaf_refuse_without_execution_or_follow(self):
        path = self.root / "app/build.gradle.kts"
        path.unlink()
        path.symlink_to(self.root / "build.gradle.kts")
        with self.captured() as capture, self.assertRaises(AcquisitionError):
            capture.run()
        path.unlink()
        path.write_text("x" * (FILE_LIMIT + 1))
        with self.captured() as capture, self.assertRaises(AcquisitionError):
            capture.run()

    def test_dynamic_or_ambiguous_project_never_promotes_literal_readiness(self):
        self.write("app/build.gradle.kts", 'plugins { id("com.android.application") }\nandroid { compileSdk = project.extra["sdk"] }')
        with self.captured() as capture:
            result = capture.run()
            self.assertEqual(result["android"]["sdkPlatform"]["state"], "unknown")
        self.write("app/build.gradle", "// ambiguous sibling")
        with self.captured() as capture:
            result = capture.run()
            self.assertEqual(result["android"]["agp"]["state"], "unknown")
            self.assertEqual(result["android"]["gradle"]["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
