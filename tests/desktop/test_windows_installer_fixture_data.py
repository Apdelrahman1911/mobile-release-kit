"""Pure five-case fixture DATA regressions; no payload/native fixture execution."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renderer = load("installer_fixture_data", ROOT / "desktop/tools/windows_installer_fixture_data.py")
existing = load("installer_source_test_data", Path(__file__).with_name("test_windows_installer_source.py"))


class WindowsInstallerFixtureDataTests(unittest.TestCase):
    def cases(self):
        original = existing.WindowsInstallerSourceTests()
        original.setUp()  # existing in-memory DATA assertions, never a real runtime
        result = []
        for name in renderer.CASES:
            admission = copy.deepcopy(original.admission)
            inventory = copy.deepcopy(original.inventory)
            sha = hashlib.sha256(("nonexecuted fixture shell " + name).encode()).hexdigest()
            admission["shell"]["sha256"] = sha
            for row in inventory["files"]:
                if row["role"] == "shell":
                    row["sha256"] = sha
            result.append(original.arguments(inventory, admission))
        return result

    def test_finite_profiles_bind_native_roster_without_staging_or_execution(self):
        cases = self.cases()
        original = copy.deepcopy(cases)
        with patch.object(renderer.profile.staging, "stage", side_effect=AssertionError("No staging")), \
                patch.object(renderer.profile.staging.preparation, "read_checked",
                             side_effect=AssertionError("No payload IO")):
            first = renderer.render_fixture_data(cases)
            self.assertEqual(first, renderer.render_fixture_data(cases))
        self.assertEqual(cases, original)
        self.assertEqual(tuple(first), renderer.OUTPUTS)
        profiles, roster = (first[name] for name in renderer.OUTPUTS)
        rows = profiles.splitlines()
        self.assertEqual(len(rows), 6)
        self.assertTrue(profiles.startswith(renderer.PROFILE_HEADER))
        self.assertIn(("profilesSha256=" + hashlib.sha256(profiles).hexdigest()).encode(), roster)
        for name, raw in zip(renderer.CASES, rows[1:]):
            self.assertIn(("case=" + name + "\nimage=" + hashlib.sha256(raw).hexdigest()).encode(), roster)
        self.assertEqual(sum(line.startswith(b"49\t") for line in roster.splitlines()), 5)

    def test_rehashed_wrong_case_set_does_not_become_a_valid_fixture(self):
        cases = self.cases()
        for invalid in (cases[:4], cases + [cases[0]], [cases[0]] * 5):
            with self.assertRaises(renderer.FixtureDataError):
                renderer.render_fixture_data(invalid)
        changed = self.cases()
        changed[1]["expected_admission"] = "f" * 64
        with self.assertRaises(renderer.FixtureDataError):
            renderer.render_fixture_data(changed)
        # Different runtime/core assertions remain the real validator's concern;
        # the compatible-set seam additionally refuses any other opaque change.
        original = existing.WindowsInstallerSourceTests()
        original.setUp()
        admission = copy.deepcopy(original.admission)
        inventory = copy.deepcopy(original.inventory)
        admission["webview2"]["sha256"] = "f" * 64
        for row in inventory["files"]:
            if row["role"] == "webview2":
                row["sha256"] = "f" * 64
        changed = self.cases()
        changed[-1] = original.arguments(inventory, admission)
        with self.assertRaises(renderer.FixtureDataError):
            renderer.render_fixture_data(changed)

    def test_fixture_budget_is_stricter_than_production_not_a_supplier_override(self):
        cases = self.cases()
        with patch.object(renderer, "MAX_INPUT_BYTES", 1):
            with self.assertRaises(renderer.FixtureDataError):
                renderer.render_fixture_data(cases)
        # Returned profile bytes do not confer native/source/process authority.
        self.assertNotIn(b"nativeQualified", renderer.render_fixture_data(cases)[renderer.OUTPUTS[0]])

    def test_fixture_feature_cannot_be_reached_from_shipping_profiles(self):
        # A real feature-graph contract, not native execution or a success receipt.
        import tomllib
        manifests = (
            (ROOT / "desktop/src-tauri/Cargo.toml", "windows-installer-protected-fixture",
             {"windows-installer-profile", "mrk-windows-installed-native/installer-protected-fixture"}),
            (ROOT / "desktop/native/windows-installed-native/Cargo.toml", "installer-protected-fixture",
             {"installer-acquisition", "runtime-publication", "qualification-result"}),
        )
        for path, fixture, expected in manifests:
            features = tomllib.loads(path.read_text(encoding="utf-8"))["features"]
            self.assertEqual(set(features[fixture]), expected)
            for start in features:
                if start == fixture:
                    continue
                reached, pending = set(), [start]
                while pending:
                    current = pending.pop()
                    if current in reached:
                        continue
                    reached.add(current)
                    pending.extend(value for value in features.get(current, ()) if value in features)
                self.assertNotIn(fixture, reached, (path.name, start))


if __name__ == "__main__":
    unittest.main()
