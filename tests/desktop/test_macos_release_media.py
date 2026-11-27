import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from desktop.tools import macos_release_media as media
from desktop.tools import macos_release_ui as ui


class FrozenMediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.names = media.image_names("0.2.13")
        for name in self.names:
            (self.root / name).write_text(name)
        self.package = dict(bytes=10, sha256="e" * 64, descriptorSha256="f" * 64,
                            signatureSha256="1" * 64, developerIdApplicationLeafSha256="2" * 64)
        self.manifest = dict(schemaVersion=1, version="0.2.13", release="macos26-arm64-desktop-19",
                             target=media.TARGET, sourceCommit="a" * 40, sourceTree="b" * 40,
                             buildRun="100", buildAttempt="1", carrierRun="101", carrierAttempt="1",
                             images={name: media.record(self.root / name) for name in self.names},
                             packages={role + ".pkg": self.package.copy() for role in ("Install", "Remove")})
        self.write_manifest()

    def write_manifest(self):
        (self.root / media.MANIFEST).write_bytes(media.dump(self.manifest))
        (self.root / media.CHECKSUMS).write_bytes(media.checksum_bytes(self.root, (*self.names, media.MANIFEST)))

    def verify(self, source="a" * 40, tree="b" * 40, build="100", carrier="101"):
        return media.verify_frozen(self.root, source, tree, build, carrier)

    def test_rejects_wrong_source_tree_or_original_run(self):
        self.assertEqual(self.verify(), self.manifest)
        for changed in ({"source": "c" * 40}, {"tree": "c" * 40}, {"build": "109"}, {"carrier": "109"}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "release-manifest-source"):
                self.verify(**changed)

    def test_rejects_modified_media_and_unknown_asset(self):
        (self.root / "stale.dmg").write_bytes(b"another candidate")
        with self.assertRaisesRegex(ValueError, "release-asset-roster"):
            self.verify()
        (self.root / "stale.dmg").unlink()
        (self.root / self.names[0]).write_bytes(b"a replacement installer")
        with self.assertRaisesRegex(ValueError, "release-image-digests"):
            self.verify()

    def test_checksums_and_strict_media_leaves(self):
        (self.root / media.CHECKSUMS).write_text("wrong\n")
        with self.assertRaisesRegex(ValueError, "release-checksums"):
            self.verify()
        self.write_manifest()
        image = self.root / self.names[0]
        original = self.root / "original"
        image.rename(original)
        image.symlink_to(original)
        with self.assertRaises(OSError):
            media.record(image)

    def test_ui_qualification_binds_the_complete_proof_and_modes(self):
        manifest = self.verify()
        frozen = {key: manifest[key] for key in ("sourceCommit", "sourceTree", "buildRun", "carrierRun", "carrierAttempt")}
        frozen.update(manifestSha256=media.record(self.root / media.MANIFEST)["sha256"],
                      installSha256=self.package["sha256"], removeSha256=self.package["sha256"])
        modes = ["fresh", "update-credentials", "archived-upgrade", "uninstaller", "delete-data", "performance-long",
                 "workspace-xctest", "recovery-xctest", "core-recovery", "post-reinstall-prepare"]
        proof = dict(qualificationRun="102", qualificationAttempt="1", frozenRelease=frozen, modes=modes)
        path = self.root / "QUALIFIED.json"

        def verify(value, carrier_attempt="1"):
            path.write_bytes(media.dump(value))
            media.verify_qualification(self.root, manifest, path, "102", "1", carrier_attempt)

        verify(proof)
        for key, value in frozen.items():
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "release-qualification-identity"):
                verify(dict(proof, frozenRelease=dict(frozen, **{key: "0" * len(value)})))
        for changed in ({"qualificationRun": "103"}, {"qualificationAttempt": "2"}, {"unexpected": True}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "release-qualification-identity"):
                verify(dict(proof, **changed))
        with self.assertRaisesRegex(ValueError, "release-qualification-identity"):
            verify(proof, carrier_attempt="2")
        for invalid in (modes[:-1], modes[:-1] + modes[:1], modes[:-1] + ["unknown"], modes[:-1] + [{}]):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "release-qualification-modes"):
                verify(dict(proof, modes=invalid))

    def test_ui_result_binds_selected_suite_and_requires_its_exact_roster(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (self.root / "observer-status").write_text("0\n")
        (evidence / "trace.jsonl").write_text('{}\n')
        result = {key: self.manifest[key] for key in ("sourceCommit", "sourceTree", "buildRun", "carrierRun")}
        result.update(manifestSha256=ui.file_hash(self.root / media.MANIFEST),
                      packageSha256=self.package["sha256"], removeSha256=self.package["sha256"],
                      suite="metadata", scenarios={name: {"status": "Passed"} for name in ui.SUITE_SCENARIOS["metadata"]})

        def verify(value, suite="metadata"):
            (evidence / "RESULT.json").write_bytes(media.dump(value))
            with patch.dict("os.environ", {"GITHUB_SHA": "3" * 40}), patch("builtins.print"):
                ui.verify_observation(self.root, self.root, suite)

        verify(result)
        with self.assertRaisesRegex(AssertionError, "observation-suite-identity"):
            verify(result, "projects")
        with self.assertRaisesRegex(AssertionError, "observation-scenario-roster"):
            verify(dict(result, scenarios=dict(result["scenarios"], unexpected={"status": "Passed"})))
        row = "metadata-negative-cancel-save-readback"
        missing_row = {name: value for name, value in result["scenarios"].items() if name != row}
        with self.assertRaisesRegex(AssertionError, "observation-scenario-roster"):
            verify(dict(result, scenarios=missing_row))
        with self.assertRaisesRegex(AssertionError, "observation-scenario-failure"):
            verify(dict(result, scenarios=dict(result["scenarios"], **{row: {"status": "Failed"}})))

    def test_ui_folder_picker_cancel_expects_the_current_project(self):
        drive = ui.UI(None, self.root, {})
        for project, button, heading in (
            (None, "Choose project folder", ui.PAGE_HEADINGS["Overview"]),
            ("Original project", "Open another project folder", "Original project"),
        ):
            with self.subTest(project=project), patch.object(drive, "click") as click, patch.object(drive, "node") as node:
                drive.project_name = project
                drive.pick(self.root / "Other project", cancel=True)
                self.assertEqual(click.call_args_list[0].args, (button,))
                click.assert_called_with("Cancel", category="button")
                node.assert_called_with(heading, category="heading")
                self.assertEqual(drive.project_name, project)

    def test_ui_click_reobserves_only_a_rejected_stale_snapshot(self):
        class DriverError(Exception):
            def __init__(self, status, code):
                self.status = status
                self.payload = {"error": {"code": code}}

        drive = ui.UI(None, self.root, {})
        stale = DriverError(409, "stale_snapshot")
        with patch.object(drive, "reveal", return_value=("snapshot", {"id": "node"})) as reveal, \
                patch.object(drive, "command", side_effect=[stale, None]) as command, patch.object(ui.time, "sleep"):
            drive.click("Original target", category="button")
            self.assertEqual(reveal.call_count, 2)
            self.assertEqual(command.call_count, 2)
        for failure in (DriverError(409, "replay_unavailable"), DriverError(504, "driver_timeout")):
            with self.subTest(failure=failure.payload), patch.object(drive, "reveal", return_value=("snapshot", {"id": "node"})), \
                    patch.object(drive, "command", side_effect=failure) as command, self.assertRaises(DriverError):
                drive.click("Original target", category="button")
            command.assert_called_once()

    def test_remove_producer_must_link_the_exact_install(self):
        source = "a" * 40
        version = self.manifest["version"]
        release = self.manifest["release"]
        current = dict(sourceCommit=source, release=release, packageVersion=version,
                       packageSha256=self.package["sha256"], inventorySha256="3" * 64,
                       signingPolicySha256="4" * 64)
        install = {}, self.package, dict(target=media.TARGET, releaseSet={"current": current})
        removal = dict(current, target=media.TARGET, installedProducerSha256=self.package["descriptorSha256"],
                       installedInventorySha256=current["inventorySha256"])
        def pair(descriptor):
            media.package_identities(install, ({}, self.package, descriptor),
                                     source=source, release=release, version=version)
        pair(removal)
        for key in ("installedProducerSha256", "installedInventorySha256", "signingPolicySha256"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "release-matching-pair"):
                pair(dict(removal, **{key: "0" * 64}))

    def test_draft_must_be_private_and_each_asset_must_match_the_frozen_roster(self):
        expected = {path.name: media.record(path) for path in self.root.iterdir()}
        rows = [dict(id=index, name=name, state="uploaded", size=record["bytes"], digest="sha256:" + record["sha256"])
                for index, (name, record) in enumerate(expected.items(), 1)]
        draft = dict(draft=True, prerelease=True, published_at=None, tag_name="desktop-v0.2.13",
                     target_commitish=self.manifest["sourceCommit"], assets=rows)
        self.assertEqual(media.draft_assets(draft, self.manifest, expected), rows)
        for changed in (dict(draft=False), dict(prerelease=False), dict(target_commitish="main"),
                        dict(assets=rows + [dict(rows[0], name="old.dmg")]),
                        dict(assets=[dict(rows[0], digest="sha256:" + "0" * 64), *rows[1:]])):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "release-(private-)?draft"):
                media.draft_assets(dict(draft, **changed), self.manifest, expected)
