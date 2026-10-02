"""Actual bootstrap function DATA; no runtime/process/native qualification."""
from __future__ import annotations

import ast
from pathlib import Path
import posixpath
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2] / "desktop" / "android_build_bootstrap.py"


class AndroidBootstrapTests(unittest.TestCase):
    def invoke(self, *, platform="darwin", machine="arm64", isolated=True, no_site=True,
               bytecode=False, version=(3, 11), core="/protected/core.zip",
               filename="/protected/android_build_bootstrap.py", extra=False,
               uname_error=False):
        # Compile only the actual two function bodies as DATA. No module top-level
        # entry, filesystem/core acquisition, native command or subprocess runs.
        parsed = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
        definitions = [node for node in parsed.body
                       if isinstance(node, ast.FunctionDef) and node.name in {"_supported_host", "main"}]
        self.assertEqual([node.name for node in definitions], ["_supported_host", "main"])
        calls = []
        model_sys = SimpleNamespace(platform=platform, flags=SimpleNamespace(isolated=isolated, no_site=no_site),
                                    dont_write_bytecode=not bytecode, version_info=version,
                                    argv=["bootstrap", core] + (["extra"] if extra else []),
                                    path=["fixed-stdlib"])

        def uname():
            calls.append("uname")
            if uname_error:
                raise OSError("inert unavailable native observation")
            return SimpleNamespace(machine=machine)

        def clock():
            calls.append("clock")
            return 123.25

        engine = ModuleType("mobile_release._desktop_android_build_engine")

        def enter(*, started):
            calls.append(("engine", started))
            return 0

        engine.main = enter
        namespace = {"sys": model_sys, "os": SimpleNamespace(uname=uname, path=posixpath),
                     "time": SimpleNamespace(monotonic=clock), "__file__": filename}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), str(SOURCE), "exec"), namespace)
        # Replace just the closed engine import. A denied gate must never enter it.
        with patch.dict(sys.modules, {engine.__name__: engine}):
            result = namespace["main"]()
        return result, calls, model_sys.path

    def test_actual_bootstrap_accepts_native_mac_arm64_and_preserves_linux_clock(self):
        for platform, machine in (("darwin", "arm64"), ("linux", "x86_64")):
            with self.subTest(platform=platform):
                result, calls, path = self.invoke(platform=platform, machine=machine)
                self.assertEqual(result, 0)
                self.assertEqual(calls[0], "clock")
                self.assertEqual(calls.count("clock"), 1)
                self.assertEqual(calls[-1], ("engine", 123.25))
                self.assertEqual(path, ["/protected/core.zip", "fixed-stdlib"])
                self.assertEqual(calls.count("uname"), int(platform == "darwin"))

    def test_unsupported_or_unisolated_entry_never_imports_core_or_changes_path(self):
        refusals = [
            {"platform": "win32"}, {"platform": "darwin", "machine": "x86_64"},
            {"platform": "darwin", "machine": "aarch64"}, {"uname_error": True},
            {"isolated": False}, {"no_site": False}, {"bytecode": True},
            {"version": (3, 10)}, {"core": "relative-core.zip"},
            {"filename": "relative-bootstrap.py"}, {"extra": True},
        ]
        for options in refusals:
            with self.subTest(options=options):
                result, calls, path = self.invoke(**options)
                self.assertEqual(result, 78)
                self.assertEqual(calls[0], "clock")
                self.assertFalse(any(isinstance(call, tuple) for call in calls))
                self.assertEqual(path, ["fixed-stdlib"])


if __name__ == "__main__":
    unittest.main()
