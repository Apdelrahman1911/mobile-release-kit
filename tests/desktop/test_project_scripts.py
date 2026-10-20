"""Passive DATA and tiny disposable source files only; never run a script."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mobile_release.api import _snapshot
from mobile_release.api._project_scripts import (
    conventional_script, process_access_identity, project_script_hints,
)
from mobile_release.discovery import parse_project_sources

BUILD = 'plugins { id("com.android.application") }\nandroid { defaultConfig { applicationId = "org.example.inert" } }\n'
IDENTITY = (1000, frozenset({1000}))


def write(root: Path, relative: str, text: str, mode: int = 0o600) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)  # Fixture setup only. The product never changes a script.


class ProjectScriptTests(unittest.TestCase):
    def test_actual_snapshot_same_scan_exports_only_names_and_fixed_hints(self):
        with tempfile.TemporaryDirectory(prefix="mrk-script-fixture-") as folder:
            root = Path(folder)
            write(root, "composeApp/build.gradle.kts", BUILD)
            write(root, "scripts/check.sh", "#!/bin/sh\n# PRIVATE_SCRIPT_CONTENT_NEVER_EXPORT\nprintf do-not-run\n", 0o700)
            write(root, "scripts/unrecognized.sh", "PRIVATE_UNRECOGNIZED_CONTENT", 0o700)
            with patch.object(subprocess, "Popen", side_effect=AssertionError("no script execution")):
                result = _snapshot.project_snapshot(str(root))
            scripts = result["scriptDiscovery"]
            self.assertEqual(scripts["platforms"], ["android"])
            self.assertFalse(scripts["sourcePartial"])
            self.assertEqual(scripts["candidates"], [{"path": "scripts/check.sh", "purposeHint": "check", "status": "direct-candidate", "shell": "sh"}])
            self.assertEqual(scripts["assurance"]["releaseReadiness"], "unknown")
            self.assertTrue(all(scripts["assurance"][key] is False for key in ("projectCodeExecuted", "toolsProbed", "writesPerformed")))
            self.assertNotIn("PRIVATE_SCRIPT_CONTENT", json.dumps(result))
            self.assertNotIn("PRIVATE_UNRECOGNIZED", json.dumps(result))
            self.assertNotIn("scriptDiscovery", result["discovery"]["hints"])

    def test_headers_modes_and_user_membership_never_insert_a_shell(self):
        sources = {"app/build.gradle.kts": BUILD, "scripts/check.sh": "#!/bin/sh\nexit 0\n",
                   "prepare.sh": "#!/bin/bash\n", "build.sh": "#!/usr/bin/env bash\n",
                   "iosApp/prepare.sh": "echo no-header\n", "scripts/preflight.sh": "#!/bin/sh\n"}
        modes = {path: (stat.S_IFREG | 0o700, 1000, 1000) for path in sources}
        modes["prepare.sh"] = (stat.S_IFREG | 0o600, 1000, 1000)
        modes["scripts/preflight.sh"] = (stat.S_IFREG | 0o720, 1000, 1000)
        result = project_script_hints(sources, modes, parse_project_sources(sources, ()), partial=False, identity=IDENTITY)
        rows = {row["path"]: row for row in result["candidates"]}
        self.assertEqual(rows["scripts/check.sh"]["status"], "direct-candidate")
        self.assertEqual(rows["prepare.sh"]["status"], "not-executable")
        self.assertEqual(rows["build.sh"]["status"], "unsupported-shebang")
        self.assertEqual(rows["iosApp/prepare.sh"]["status"], "unsupported-shebang")
        self.assertEqual(rows["scripts/preflight.sh"]["status"], "unsupported-mode")
        self.assertNotIn("argv", json.dumps(result))
        modes["scripts/check.sh"] = (stat.S_IFREG | 0o010, 99, 999)
        denied = project_script_hints(sources, modes, {}, partial=False, identity=IDENTITY)
        self.assertEqual(next(row for row in denied["candidates"] if row["path"] == "scripts/check.sh")["status"], "not-executable")
        unknown = project_script_hints(sources, modes, {}, partial=False, identity=None)
        self.assertTrue(all(row["status"] == "permissions-unavailable" for row in unknown["candidates"]))

    def test_partial_and_truncated_hints_are_explicit_not_complete_inventory(self):
        sources = {f"{directory}/{name}.sh": "#!/bin/sh\n" for directory in ("scripts", "app/scripts", "iosApp/scripts")
                   for name in ("prepare", "prepare-ios", "check", "preflight", "build", "build-ios")}
        result = project_script_hints(sources, {}, {}, partial=True, identity=IDENTITY)
        self.assertTrue(result["sourcePartial"])
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["candidates"]), 16)
        self.assertEqual(result["platforms"], [])
        self.assertEqual(result["coverage"], "conventional-paths-only")
        # Saved enabled flags are not native-layout observations.
        foreign = project_script_hints(sources, {}, {"android": {"enabled": True}, "ios": {}}, partial=False, identity=None)
        self.assertEqual(foreign["platforms"], [])

    def test_original_reader_prunes_private_links_and_unrecognized_layouts(self):
        with tempfile.TemporaryDirectory(prefix="mrk-script-pruning-") as folder:
            root = Path(folder)
            write(root, "app/build.gradle.kts", BUILD)
            write(root, "private/check.sh", "PRIVATE_MATERIAL_NOT_READ", 0o700)
            write(root, "custom/scripts/check.sh", "CUSTOM_MATERIAL_NOT_READ", 0o700)
            (root / "scripts").mkdir()
            (root / "scripts/check.sh").symlink_to(root / "private/check.sh")
            with patch.object(subprocess, "Popen", side_effect=AssertionError("no project process")):
                result = _snapshot.project_snapshot(str(root))
            self.assertEqual(result["scriptDiscovery"]["candidates"], [])
            self.assertTrue(result["scriptDiscovery"]["sourcePartial"])
            self.assertNotIn("MATERIAL_NOT_READ", json.dumps(result))
        for path in ("../check.sh", "/check.sh", "scripts//check.sh", "scripts/../check.sh", "scripts/check.sh/", "release/private/check.sh", "scripts/CHECK.sh"):
            self.assertFalse(conventional_script(path), path)

    def test_no_new_file_probe_in_projection_and_unsettled_root_has_no_presets(self):
        sources = {"app/build.gradle.kts": BUILD, "scripts/check.sh": "#!/bin/sh\n"}
        config = {"path": "release/mobile-release.json", "state": "missing", "content": None, "data": None, "issues": []}
        with patch.object(os, "open", side_effect=AssertionError("no assembly file reads")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("no execution")):
            unsettled = _snapshot._assemble_snapshot("/inert", "2026-10-20T00:00:00Z", _snapshot._Inventory(sources=sources), config.copy())
            self.assertNotIn("scriptDiscovery", unsettled)
            settled = _snapshot._assemble_snapshot("/inert", "2026-10-20T00:00:00Z", _snapshot._Inventory(sources=sources, root_settled=True), config.copy())
            self.assertEqual(settled["scriptDiscovery"]["candidates"][0]["status"], "permissions-unavailable")

    def test_process_metadata_refuses_unavailable_or_unbounded_groups(self):
        with patch.object(os, "getgroups", return_value=list(range(1025))):
            self.assertIsNone(process_access_identity())
        with patch.object(os, "getgroups", side_effect=OSError("inert unavailable")):
            self.assertIsNone(process_access_identity())


if __name__ == "__main__":
    unittest.main()
