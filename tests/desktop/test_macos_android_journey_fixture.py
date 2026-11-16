"""Real typed version edit on disposable Android source, without Gradle or a device.

The separate recorded Gradle smoke verifies the edited file reaches the APK.
This regression enters only the existing registered-root/transaction owners.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_release import init_transaction as tx, release_version_edit as version
from mobile_release.config import parse_config_text
from test_saved_text_recovery import _live_lease

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/macos_android_journey"


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX registered-root test fixture")
class AndroidJourneyFixtureTests(unittest.TestCase):
    def test_android_only_saved_version_edit_is_atomic_and_preserves_other_source(self):
        with tempfile.TemporaryDirectory(prefix="mrk-android-source-journey-",
                dir="/private/tmp" if sys.platform == "darwin" else None) as directory:
            root = Path(directory) / "project"
            shutil.copytree(FIXTURE, root)
            config = parse_config_text((root / "release/mobile-release.json").read_text())
            self.assertEqual(config["ios"], {"enabled": False})
            self.assertTrue(config["android"]["enabled"])
            source = "public/version.properties"
            before = {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_ino)
                      for p in root.rglob("*") if p.is_file() and p.relative_to(root).as_posix() != source}
            with _live_lease(root, "version", restoring=False) as (lease, guard):
                checkout = version.capture_release_version_edit(lease)
                plan = version.prepare_release_version_edit(lease, checkout, checkout.revision,
                    checkout.baseline, "edit", {"name": "2.3.4", "build": "8"})
                self.assertTrue(plan.view["validation"]["valid"])
                result = version.apply_release_version_edit(lease, plan)
                self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                                 ("committed", "clean", "settled", "none"))
            self.assertTrue(lease.closed)
            self.assertEqual(guard.handler_state, "RESTORED")
            self.assertEqual((root / source).read_text(), "VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n")
            self.assertTrue(all(not (root / name).exists() for name in tx.ALL_STATE_NAMES))
            self.assertEqual({name: ((root / name).read_bytes(), (root / name).stat().st_ino)
                              for name in before}, before)
