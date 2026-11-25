"""#29: the macOS package's third-party notices match the lockfiles."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macos_third_party_notices", ROOT / "desktop/tools/macos_third_party_notices.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class ThirdPartyNoticesData(unittest.TestCase):
    def test_notices_are_current_for_every_lockfile(self):
        inputs = M.check()
        self.assertEqual(set(inputs["lockfiles"]), set(M.lockfiles()))
        self.assertEqual(inputs["targets"], ["aarch64-apple-darwin", "x86_64-apple-darwin"])

    def test_every_component_is_listed_and_texts_are_verbatim(self):
        inputs = json.loads((M.OUTPUT / M.INPUTS_NAME).read_text())
        notice = (M.OUTPUT / M.NOTICE_NAME).read_text()
        names = {(c["kind"], c["name"]) for c in inputs["components"]}
        for package in ("react", "react-dom", "scheduler", "@tauri-apps/api", "vite"):
            self.assertIn(("npm", package), names)
        for crate in ("tokio", "serde", "tauri"):
            self.assertIn(("crate", crate), names)
        for component in inputs["components"]:
            self.assertIn(f"{component['name']} {component['version']} (", notice)
        # Components with no licence file of their own get a verbatim reference.
        if any(not c["files"] for c in inputs["components"]):
            self.assertIn("publish no separate licence file", notice)
        self.assertNotIn("/Users/", notice)

    def test_stager_ships_the_notices_only_while_current(self):
        sys.path.insert(0, str(ROOT / "desktop/tools"))
        import stage_macos_installed as stager
        self.assertEqual(stager.THIRD_PARTY_NOTICES, "Contents/Resources/THIRD-PARTY-NOTICES.txt")
        self.assertEqual(set(stager.THIRD_PARTY_LOCKFILES), set(M.lockfiles()))
        self.assertEqual(stager.third_party_notices(), (M.OUTPUT / M.NOTICE_NAME).read_bytes())


if __name__ == "__main__":
    unittest.main()
