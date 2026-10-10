"""Closed SOURCE regression for the installed observer's current root modules."""
from pathlib import Path
import re
import unittest


class InstalledShellModuleMirror(unittest.TestCase):
    def test_current_required_modules_are_mirrored_without_role_features(self):
        root = Path(__file__).resolve().parents[2]
        source = root / "desktop/src-tauri/src"
        library = (source / "lib.rs").read_text().splitlines()
        observer = (root / "desktop/src-tauri/tests/installed_shell_observation.rs").read_text().splitlines()
        required = (
            "artifact_inspection_protocol", "project_initialization_edit_protocol",
            "github_setup_protocol", "github_setup_session",
            "github_history_protocol", "github_history_session", "macos_remove_protocol",
        )
        for name in required:
            with self.subTest(module=name):
                declaration = re.compile(r"(?:pub )?mod " + re.escape(name) + r";")
                positions = [i for i, line in enumerate(library) if declaration.fullmatch(line)]
                self.assertEqual(len(positions), 1)
                self.assertFalse(library[positions[0] - 1].lstrip().startswith("#[cfg"))
                expected = '#[path = "../src/' + name + '.rs"] mod ' + name + ';'
                self.assertEqual(observer.count(expected), 1)
                self.assertFalse(observer[observer.index(expected) - 1].lstrip().startswith("#[cfg"))
                self.assertTrue((source / (name + ".rs")).is_file())
        # These genuine protocol children already exist; neither adds a root
        # declaration, compiler feature, command owner or runtime entrypoint.
        setup = (source / "github_setup_protocol.rs").read_text()
        for child in ("secret", "variable"):
            filename = "github_setup_" + child + "_protocol.rs"
            self.assertEqual(setup.count('#[path = "' + filename + '"]\nmod ' + child + ';'), 1)
            self.assertTrue((source / filename).is_file())


if __name__ == "__main__":
    unittest.main()
