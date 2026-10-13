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
            "macos_remove_producer",
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
        # Explicit current reachable removal dependency, not a claim that this
        # fixed regression discovers every Rust module or cfg(test) dependency.
        asset_session = (source / "asset_session.rs").read_text()
        self.assertEqual(asset_session.count(
            '#[path = "asset_session_macos_removal.rs"]\npub(crate) mod macos_removal;'), 1)
        removal = (source / "asset_session_macos_removal.rs").read_text()
        self.assertEqual(removal.count("macos_remove_producer::RemovalData,"), 1)
        self.assertEqual(removal.count("crate::macos_remove_producer::DESCRIPTOR_LIMIT"), 1)
        # These genuine protocol children already exist; neither adds a root
        # declaration, compiler feature, command owner or runtime entrypoint.
        setup = (source / "github_setup_protocol.rs").read_text()
        for child in ("secret", "variable"):
            filename = "github_setup_" + child + "_protocol.rs"
            self.assertEqual(setup.count('#[path = "' + filename + '"]\nmod ' + child + ';'), 1)
            self.assertTrue((source / filename).is_file())

    def test_current_native_panel_kinds_have_closed_observer_matches(self):
        root = Path(__file__).resolve().parents[2]
        native = (root / "desktop/native/macos-installed-native/src/lib.rs").read_text()
        observer = (root / "desktop/src-tauri/src/installed_shell_observation_macos.rs").read_text()
        declarations = re.findall(r"pub enum PanelKind \{ ([^{}]+) \}", native)
        self.assertEqual(len(declarations), 1)
        self.assertEqual(tuple(part.strip() for part in declarations[0].split(",")), (
            "Project", "Quit", "File", "VersionSource", "IosProject", "IosWorkspace",
            "MetadataRoot", "EvidenceFolder", "PublicImages", "AndroidJdk", "AndroidSdk",
            "AndroidGradle", "ArtifactAab", "ArtifactIpa", "ArtifactArchive", "ArtifactDsyms",
        ))
        sample = observer.split("impl PanelSample {", 1)[1].split("\nfn same_panel_action_returned", 1)[0]
        scope = observer.split("pub(super) fn open_identity_scope(", 1)[1].split(
            "pub(super) fn open_identity_target(", 1)[0]
        target = observer.split("pub(super) fn open_identity_target(", 1)[1].split(
            "pub(super) fn completion_returned(", 1)[0]
        prefix = "mrk_macos_installed_native::PanelKind::"
        variants = (
            ("ArtifactAab", "artifact-aab"), ("ArtifactIpa", "artifact-ipa"),
            ("ArtifactArchive", "artifact-archive"), ("ArtifactDsyms", "artifact-dsyms"),
        )
        for name, label in variants:
            with self.subTest(kind=name):
                self.assertEqual(sample.count(prefix + name + ' => "' + label + '"'), 1)
        # These diagnostic-only kinds gain no original selection identity/path.
        negative = "\n".join("                | " + prefix + name for name, _ in variants)
        self.assertEqual(scope.count(negative + " => false,"), 1)
        self.assertEqual(target.count(negative + " => None,"), 1)


if __name__ == "__main__":
    unittest.main()
