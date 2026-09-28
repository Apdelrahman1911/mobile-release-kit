"""Real image import/rename failure fixtures; not shared-host-safe by default.

Run only in the lead's reviewed Linux filesystem boundary. Every path is under
one TemporaryDirectory supplied by the recovery fixture; actual original root
leases, bounded observations and the production rename/rollback writer are
used. No native picker, subprocess, signing material, network or Store is used.
The object-exclusion test checks actual stat DATA, not mount capability/evidence.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import metadata_images_edit as edit
from mobile_release import metadata_images_recovery as recovery
from test_metadata_images import png, selected
from test_metadata_images_recovery import (_FixturePause, _facts, _live_lease,
                                          _prepare_recovery, _project, _source_objects,
                                          _stage, FOLDER)


def _batch():
    return (selected(png(pixel=1), identity="a" * 32, name="01.png"),
            selected(png(pixel=2), identity="b" * 32, name="02.png"))


def _capture(lease, root, batch):
    return edit.capture_metadata_images_edit(lease, "android", "en-US", "phoneScreenshots", batch, [],
                                             _source_objects(root, batch))


def _prepare(lease, checkout, batch, replacements=None):
    return edit.prepare_metadata_images_edit(lease, checkout, checkout.revision, checkout.baseline,
        [{"itemId": row.item_id, "replaceExisting": (replacements or [False] * len(batch))[index]}
         for index, row in enumerate(batch)])


def _journal_absent(root):
    return all(not (root / name).exists() for name in tx.IMAGE_STATE_NAMES)


class MetadataImagesEditTests(unittest.TestCase):
    def test_new_directory_import_is_one_shot_and_preserves_original_sources_and_saved_inputs(self):
        with _project(empty=True) as root:
            batch = _batch()
            saved = {path: _facts(root / path) for path in ("release/mobile-release.json", ".gitignore")}
            with _live_lease(root, restoring=False) as (lease, guard):
                checkout = _capture(lease, root, batch)
                source = {path: _facts(path) for path in (root.parent / "sources").iterdir()}
                self.assertTrue(checkout.view["valid"])
                self.assertEqual(checkout.view["finalOrder"], [FOLDER + "/01.png", FOLDER + "/02.png"])
                self.assertFalse(checkout.view["assurance"]["storeContacted"])
                prepared = _prepare(lease, checkout, batch)
                self.assertEqual(edit.apply_metadata_images_edit(lease, prepared),
                                 shared.CoreEditOutcome("committed", "clean", "settled", "none"))
                self.assertEqual(edit.apply_metadata_images_edit(lease, prepared).reason, "invalid_params")
                with self.assertRaises(shared.ConfigEditFailure):
                    _prepare(lease, checkout, batch)
                self.assertFalse(guard.lifetime_ledger.fatal)
            self.assertTrue(_journal_absent(root))
            for row in batch:
                self.assertEqual((root / FOLDER / row.display_name).read_bytes(), row.data)
            for path, facts in source.items():
                self.assertEqual(_facts(path), facts)
            for path, facts in saved.items():
                self.assertEqual(_facts(root / path), facts)

    def test_changed_sibling_target_or_saved_configuration_is_not_a_second_preview_or_write(self):
        for change in ("config", "ignore", "target", "sibling", "namespace"):
            for step in ("prepare", "apply"):
                with self.subTest(change=change, step=step), _project(empty=True) as root:
                    batch = _batch()
                    with _live_lease(root, restoring=False) as (lease, _):
                        checkout = _capture(lease, root, batch)
                        prepared = _prepare(lease, checkout, batch) if step == "apply" else None
                        if change == "config":
                            path = root / "release/mobile-release.json"
                            value = json.loads(path.read_text()); value["metadata"]["root"] = "public/other-store"
                            path.write_text(json.dumps(value), encoding="utf-8")
                        elif change == "ignore":
                            path = root / ".gitignore"; path.write_text(path.read_text() + "# user edit\n", encoding="utf-8")
                        else:
                            folder = root / FOLDER; folder.mkdir(parents=True)
                            if change == "namespace":
                                path = root / "public"; path.chmod(0o700)
                            else:
                                path = folder / ("01.png" if change == "target" else "user.png")
                                path.write_bytes(png(pixel=9))
                        observed = _facts(path)
                        if step == "prepare":
                            with self.assertRaises(shared.ConfigEditFailure) as failure:
                                _prepare(lease, checkout, batch)
                            outcome = failure.exception.outcome
                        else:
                            outcome = edit.apply_metadata_images_edit(lease, prepared)
                        self.assertEqual(outcome.reason, "stale_revision")
                        self.assertEqual(outcome.effect, "not_started")
                        self.assertEqual(outcome.journal, "not_created")
                        self.assertEqual(_facts(path), observed)
                        self.assertTrue(_journal_absent(root))
                        self.assertFalse((root / FOLDER / "02.png").exists())

    def test_private_original_object_exclusions_protect_a_target_even_without_a_relative_source_name(self):
        for boundary in ("preview", "writer"):
            with self.subTest(boundary=boundary), _project(empty=True) as root:
                folder = root / FOLDER; folder.mkdir(parents=True)
                first, second = folder / "01.png", folder / "02.png"
                first.write_bytes(png(pixel=1)); second.write_bytes(png(pixel=2))
                # Native can select a file bind-mounted elsewhere with a
                # different basename. This core test does NOT perform a mount;
                # it provides actual held original identity exclusion DATA.
                batch = (selected(first.read_bytes(), identity="a" * 32, name="02.png"),
                         selected(png(pixel=3), identity="b" * 32, name="01.png"))
                objects = _source_objects(root, batch)
                original = first.stat(); objects[0] = {"device": str(original.st_dev), "inode": str(original.st_ino)}
                before = {path: _facts(path) for path in (first, second)}
                with _live_lease(root, restoring=False) as (lease, _):
                    checkout = edit.capture_metadata_images_edit(lease, "android", "en-US", "phoneScreenshots", batch, [], objects)
                    self.assertTrue(checkout.view["valid"])
                    self.assertFalse(checkout.view["files"][1]["canReplace"])
                    self.assertNotIn("protectedObjects", json.dumps(checkout.view))
                    self.assertNotIn("protectedSources", json.dumps(checkout.view))
                    if boundary == "preview":
                        with self.assertRaises(shared.ConfigEditFailure) as failure:
                            _prepare(lease, checkout, batch, [True, True])
                        self.assertEqual(failure.exception.outcome.reason, "invalid_params")
                    else:
                        with self.assertRaises(tx.InitOperationFailure) as failure:
                            with lease.workspace_scope(checkout._revision) as workspace:
                                workspace.apply_metadata_images_typed([(row.observed(), item.data)
                                    for row, item in zip(checkout._files, batch)])
                        self.assertEqual(failure.exception.outcome.reason, "invalid_params")
                self.assertTrue(_journal_absent(root))
                for path, facts in before.items():
                    self.assertEqual(_facts(path), facts)

    def test_directory_move_lost_return_preserves_owned_transition_for_original_and_restart_rollback(self):
        for restoring in (False, True):
            with self.subTest(restoring=restoring), _project(empty=True) as root:
                if restoring:
                    _stage(root, "mixed", empty=True)
                supplied = tx._rename_function
                calls = []

                def rename_function():
                    original = supplied()

                    def rename(source_fd, source, destination_fd, destination):
                        result = original(source_fd, source, destination_fd, destination)
                        candidate = destination if restoring else source
                        if candidate.startswith("directory-") and not calls:
                            calls.append(candidate)
                            raise _FixturePause("original directory rename succeeded but lost its return")
                        return result
                    return rename

                with _live_lease(root, restoring=restoring) as (lease, _):
                    if restoring:
                        checkout, prepared = _prepare_recovery(lease)
                    else:
                        batch = _batch(); checkout = _capture(lease, root, batch); prepared = _prepare(lease, checkout, batch)
                    with patch.object(tx, "_rename_function", rename_function):
                        outcome = (recovery.apply_metadata_images_recovery(lease, prepared) if restoring
                                   else edit.apply_metadata_images_edit(lease, prepared))
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(outcome.reason, "filesystem_error")
                    self.assertEqual(outcome.resources, "settled")
                    if restoring:
                        self.assertEqual((outcome.effect, outcome.journal), ("unknown", "recovery_required"))
                    else:
                        self.assertEqual((outcome.effect, outcome.journal), ("rolled_back", "clean"))
                if restoring:
                    with _live_lease(root, restoring=True) as (lease, _):
                        _, prepared = _prepare_recovery(lease)
                        self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared),
                                         shared.CoreEditOutcome("rolled_back", "clean", "settled", "none"))
                self.assertTrue(_journal_absent(root)); self.assertFalse((root / "public").exists())

    def test_failure_after_committed_marker_never_retries_import_or_claims_false_success(self):
        with _project(empty=True) as root:
            batch = _batch()
            move = tx.InitWorkspace._move
            install = tx.InitWorkspace._install
            calls = {"commit": 0, "install": 0}

            def observed_move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
                result = move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
                if destination == "COMMITTED":
                    calls["commit"] += 1
                return result

            def moved(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
                result = observed_move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
                if destination == "COMMITTED":
                    raise _FixturePause("the exact terminal marker was published before the lost return")
                return result

            def installed(workspace, fd, plan):
                calls["install"] += 1
                return install(workspace, fd, plan)

            # Count-only observation outlives the failing attempt. Recovery
            # must not install images or publish a second COMMITTED marker.
            with patch.object(tx.InitWorkspace, "_move", observed_move), patch.object(tx.InitWorkspace, "_install", installed):
                with _live_lease(root, restoring=False) as (lease, _):
                    checkout = _capture(lease, root, batch); prepared = _prepare(lease, checkout, batch)
                    with patch.object(tx.InitWorkspace, "_move", moved):
                        outcome = edit.apply_metadata_images_edit(lease, prepared)
                    self.assertEqual(outcome, shared.CoreEditOutcome("committed", "recovery_required", "settled", "filesystem_error"))
                    self.assertEqual(edit.apply_metadata_images_edit(lease, prepared).reason, "invalid_params")
                self.assertEqual(calls, {"commit": 1, "install": 1})
                self.assertEqual([name for name in tx.IMAGE_STATE_NAMES if (root / name).exists()], [tx.IMAGE_READY])
                self.assertTrue((root / tx.IMAGE_READY / "COMMITTED").is_file())
                installed_images = {}
                for row in batch:
                    path = root / FOLDER / row.display_name
                    self.assertEqual(path.read_bytes(), row.data)
                    installed_images[path] = (row.data, _facts(path))
                # The original lost-return injection and lease are retired;
                # only a fresh recovery capability may clean the journal.
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout, prepared = _prepare_recovery(lease)
                    self.assertEqual(checkout.view["action"], "committed_cleanup")
                    self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared),
                                     shared.CoreEditOutcome("committed", "clean", "settled", "none"))
                self.assertEqual(calls, {"commit": 1, "install": 1})
                self.assertTrue(_journal_absent(root))
                for path, (data, facts) in installed_images.items():
                    self.assertEqual(path.read_bytes(), data)
                    self.assertEqual(_facts(path), facts)

    def test_image_only_limit_accepts_a_header_checked_image_larger_than_unchanged_global_limit(self):
        with _project(empty=True) as root:
            body = png(); body += b"\0" * (8 * 1024 * 1024 + 1 - len(body))
            batch = (selected(body),)
            self.assertEqual(tx.MAX_FILE_BYTES, 8 * 1024 * 1024)
            with _live_lease(root, restoring=False) as (lease, _):
                checkout = _capture(lease, root, batch)
                self.assertTrue(checkout.view["files"][0]["selected"]["headerChecked"])
                self.assertFalse(checkout.view["assurance"]["fullDecode"])
                prepared = _prepare(lease, checkout, batch)
                self.assertEqual(edit.apply_metadata_images_edit(lease, prepared),
                                 shared.CoreEditOutcome("committed", "clean", "settled", "none"))
            self.assertEqual((root / FOLDER / "01.png").read_bytes(), body)
            self.assertTrue(_journal_absent(root))


if __name__ == "__main__":
    unittest.main()
