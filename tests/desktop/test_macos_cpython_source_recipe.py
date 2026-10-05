"""Fixed SOURCE-only recipe regressions; no build/archive/host execution."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).absolute().parents[2]
MODULE_PATH = ROOT / "desktop/tools/macos_cpython_source_recipe.py"
SPEC = importlib.util.spec_from_file_location("mrk_macos_cpython_recipe_data", MODULE_PATH)
RECIPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECIPE
SPEC.loader.exec_module(RECIPE)


class MacPythonSourceRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = (ROOT / "desktop/macos-cpython-source-inputs/source-lock.json").read_bytes()
        cls.intel_lock = (ROOT / "desktop/macos-cpython-source-inputs/source-lock-intel.json").read_bytes()
        cls.inventory = (ROOT / "desktop/cpython-source-inputs/cpython-source-inventory.json").read_bytes()

    def test_exact_arm_nomination_does_not_admit_intel_or_modified_inputs(self):
        rows = RECIPE.source_nomination(self.lock, RECIPE.ARM_TARGET)
        self.assertEqual(tuple(row.component for row in rows), ("cpython", "libffi", "openssl", "zlib"))
        self.assertEqual(tuple(row.version for row in rows), ("3.14.7", "3.4.8", "3.5.8", "1.3.2"))
        # Two exact nominations may select the same public source, but neither
        # target's lock can authorize the other's producer or native evidence.
        self.assertEqual(RECIPE.target_description(RECIPE.INTEL_TARGET).architecture, "x86_64")
        self.assertEqual(RECIPE.source_nomination(self.intel_lock, RECIPE.INTEL_TARGET), rows)
        for lock, target in ((self.lock, RECIPE.INTEL_TARGET), (self.intel_lock, RECIPE.ARM_TARGET)):
            with self.subTest(target=target), self.assertRaises(RECIPE.RecipeRefused):
                RECIPE.source_nomination(lock, target)
        for target in ("arm64-apple-darwin", "x86_64-unknown-linux-gnu", True):
            with self.subTest(target=target), self.assertRaises(RECIPE.RecipeRefused):
                RECIPE.source_nomination(self.lock, target)
        # Preserve even nomination/approval distinction: adjacent edited JSON is
        # not admitted simply because its four archive hashes still match.
        for lock, target in ((self.lock, RECIPE.ARM_TARGET), (self.intel_lock, RECIPE.INTEL_TARGET)):
            for body in (lock + b"\n", lock.replace(b'"gil": true', b'"gil":false'),
                         lock.replace(b'"nativeBuild": false', b'"nativeBuild": true ')):
                self.assertNotEqual(body, lock)
                with self.subTest(target=target, length=len(body)), self.assertRaises(RECIPE.RecipeRefused):
                    RECIPE.source_nomination(body, target)

    def test_fixed_complete_inventory_produces_only_source_bound_stdlib(self):
        rows = RECIPE.stdlib_projection(self.lock, self.inventory, RECIPE.ARM_TARGET)
        self.assertEqual(RECIPE.stdlib_projection(self.intel_lock, self.inventory, RECIPE.INTEL_TARGET), rows)
        self.assertEqual((len(rows), sum(row.size for row in rows)), (555, 10_374_402))
        destinations = [row.destination for row in rows]
        self.assertEqual(destinations, sorted(set(destinations)))
        self.assertTrue(all(row.source.startswith("Lib/") and row.mode == 0o444 for row in rows))
        self.assertIn("python/lib/python3.14/urllib/request.py", destinations)
        self.assertIn("python/lib/python3.14/ctypes/__init__.py", destinations)
        self.assertFalse(any("/test/" in value or value.endswith((".pyc", ".so", ".dylib"))
                             for value in destinations))
        # No binary/generated sysconfig/notice or native receipt is invented.
        self.assertNotIn("python/bin/python3", destinations)
        self.assertFalse(any("_sysconfigdata_" in value for value in destinations))
        for body in (self.inventory[:-1], self.inventory.replace(b'"size":526', b'"size":527', 1)):
            self.assertNotEqual(body, self.inventory)
            with self.assertRaises(RECIPE.RecipeRefused):
                RECIPE.stdlib_projection(self.lock, body, RECIPE.ARM_TARGET)

    def test_projection_refuses_alias_paths_native_pruning_and_generated_substitution(self):
        refused = ("/ssl.py", "../ssl.py", "ctypes//__init__.py", "ctypes/./__init__.py",
                   "ctypes/../ssl.py", "ctypes\\__init__.py", "bad\x00.py", "bad\n.py",
                   "test/unexpected.dylib", "test/libbad.so.3", "foreign.pyd", "foreign.dll",
                   "_sysconfigdata__darwin_darwin.py", "_sysconfig_vars__darwin_darwin.py",
                   "con.py", "unicode-\u00e9.py", "segment/" * 14 + "leaf.py")
        for name in refused:
            with self.subTest(name=name), self.assertRaises(RECIPE.RecipeRefused):
                RECIPE.stdlib_destination(name)
        for name in ("test/example.py", "ensurepip/__init__.py", "tkinter/__init__.py",
                     "site-packages/extra.py", "__pycache__/os.cpython-314.pyc", "old.pyo", "README.rst"):
            with self.subTest(name=name):
                self.assertIsNone(RECIPE.stdlib_destination(name))


if __name__ == "__main__":
    unittest.main()
