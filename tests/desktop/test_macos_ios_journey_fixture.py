"""Real iOS-only typed version transaction on disposable Xcode source.

The separately recorded Xcode builds verify expansion into bundle metadata.
This unit needs no Xcode process, device, account or signing material.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_release import init_transaction as tx, release_version_edit as version
from mobile_release.config import parse_config_text
from mobile_release.project_identity import IdentitySelection
from fixture_identity_edit import apply_new_identity
from test_saved_text_recovery import _live_lease

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/macos_ios_journey"


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX registered-root test fixture")
class IOSJourneyFixtureTests(unittest.TestCase):
    def test_buildable_xcode_fixture_identity_edit_preserves_info_and_application_source(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ios-identity-journey-",
                dir="/private/tmp" if sys.platform == "darwin" else None) as directory:
            root = Path(directory) / "project"
            shutil.copytree(FIXTURE, root)
            project = "MRKFixture.xcodeproj/project.pbxproj"
            before = {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_ino)
                      for p in root.rglob("*") if p.is_file() and p.relative_to(root).as_posix() not in
                      {project, "release/mobile-release.json"}}
            original = (root / project).read_bytes()
            apply_new_identity(root, IdentitySelection("ios", "MRKFixture", "MRKFixture.xcodeproj", "unknown"),
                               "org.mrk.changediosfixture")
            self.assertEqual((root / project).read_bytes(), original.replace(b"org.mrk.iosfixture", b"org.mrk.changediosfixture"))
            self.assertEqual(parse_config_text((root / "release/mobile-release.json").read_text())["ios"]["bundleId"],
                             "org.mrk.changediosfixture")
            self.assertEqual({name: ((root / name).read_bytes(), (root / name).stat().st_ino) for name in before}, before)
            self.assertFalse(any((root / name).exists() for name in tx.ALL_STATE_NAMES))

    def test_ios_only_version_edit_preserves_xcode_source_and_settles_originals(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ios-source-journey-",
                dir="/private/tmp" if sys.platform == "darwin" else None) as directory:
            root = Path(directory) / "project"
            shutil.copytree(FIXTURE, root)
            config = parse_config_text((root / "release/mobile-release.json").read_text())
            self.assertEqual(config["android"], {"enabled": False})
            self.assertTrue(config["ios"]["enabled"])
            target = "public/version.xcconfig"
            before = {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_ino)
                      for p in root.rglob("*") if p.is_file() and p.relative_to(root).as_posix() != target}
            with _live_lease(root, "version", restoring=False) as (lease, guard):
                checkout = version.capture_release_version_edit(lease)
                self.assertTrue(checkout.selection.ios_enabled)
                prepared = version.prepare_release_version_edit(lease, checkout, checkout.revision,
                    checkout.baseline, "edit", {"name": "2.3.4", "build": "8"})
                self.assertTrue(prepared.view["validation"]["valid"])
                outcome = version.apply_release_version_edit(lease, prepared)
                self.assertEqual((outcome.effect, outcome.journal, outcome.resources, outcome.reason),
                                 ("committed", "clean", "settled", "none"))
            self.assertTrue(lease.closed)
            self.assertEqual(guard.handler_state, "RESTORED")
            self.assertEqual((root / target).read_text(), "VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n")
            self.assertTrue(all(not (root / name).exists() for name in tx.ALL_STATE_NAMES))
            self.assertEqual({name: ((root / name).read_bytes(), (root / name).stat().st_ino)
                              for name in before}, before)
