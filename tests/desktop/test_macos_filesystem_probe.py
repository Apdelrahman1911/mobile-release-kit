"""DATA-only tests of the actual workflow parser; no diskutil/native execution."""
from __future__ import annotations

import ast
import re
import textwrap
import unittest
from pathlib import Path


class MacFilesystemProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/desktop-macos-installed.yml").read_text()
        body = workflow.split("<<'PY_DATA_CONTRACTS'\n", 1)[1].split("          PY_DATA_CONTRACTS\n", 1)[0]
        parsed = ast.parse(textwrap.dedent(body))
        functions = [node for node in parsed.body
                     if isinstance(node, ast.FunctionDef) and node.name == "filesystem_device"]
        if len(functions) != 1:
            raise AssertionError("expected the single actual filesystem-device parser")
        # Execute only the pure parser definition, never workflow commands.
        namespace = {"re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "workflow-filesystem-parser", "exec"), namespace)
        cls.parse_device = staticmethod(namespace["filesystem_device"])

    @staticmethod
    def row(device="/dev/disk3s5", mount="/System/Volumes/Data", available="Available"):
        return (f"Filesystem 1024-blocks Used {available} Capacity Mounted on\n"
                f"{device} 100000 20000 80000 20% {mount}\n").encode()

    def test_documented_layouts_keep_one_exact_device_and_mountpoint(self):
        for available in ("Available", "Avail"):
            for device, mount in (("/dev/disk3s5", "/System/Volumes/Data"),
                                  ("/dev/disk2s1s1", "/Volumes/Test Data")):
                with self.subTest(available=available, device=device, mount=mount):
                    self.assertEqual(self.parse_device(self.row(device, mount, available)),
                                     {"device": device, "reportedMountPoint": mount})

    def test_ambiguous_nondevice_and_malformed_output_is_refused(self):
        valid = self.row()
        invalid = (
            b"", valid.splitlines(keepends=True)[0], valid + valid.splitlines(keepends=True)[1],
            self.row("overlay"), self.row("/Users/runner/work/_temp"),
            self.row("Snapshot@/dev/disk3s5"), self.row(mount="relative"),
            self.row(mount="/Volumes/Test\x00Data"), self.row(mount="/Volumes/Test\nData"),
            valid.replace(b"20%", b"unknown"), valid.replace(b"80000", b"-"),
            valid.replace(b"1024-blocks", b"512-blocks"),
            valid.replace(b"Capacity Mounted", b"Capacity iused ifree %iused Mounted"),
            valid[:-1], valid.replace(b"\n", b"\r\n"), b"\xff\n",
        )
        for data in invalid:
            with self.subTest(data=data):
                with self.assertRaises((ValueError, UnicodeError)):
                    self.parse_device(data)


if __name__ == "__main__":
    unittest.main()
