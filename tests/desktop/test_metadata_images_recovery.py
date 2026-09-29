"""Genuine image restart/failure fixtures, not passive/native qualification.

The lead must run this class only in its reviewed Linux filesystem boundary.
Each fixture uses its own TemporaryDirectory, the real cancellation/root-lock
owner, and the existing image staging/rename/rollback primitives. No subprocess,
external signal, native picker, signing input, network or Store is exercised.
Original import receipts are produced by staging, never forged for recovery.
"""
from __future__ import annotations

import copy
import json
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import metadata_images as images
from mobile_release import metadata_images_edit as edit
from mobile_release import metadata_images_recovery as recovery
from mobile_release.errors import ValidationError
from test_metadata_images import png, selected
from test_metadata_text import config


FOLDER = "public/store/android/en-US/images/phoneScreenshots"
OLD = b"original malformed image that an explicit replacement may repair"
KEPT, SIBLING = png(pixel=3), png(pixel=4)
NEW = (png(pixel=1), png(pixel=2), KEPT)


class _FixturePause(Exception):
    """A deterministic failure at an original operation boundary."""


def _facts(path: Path):
    value = path.stat()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def _live_lease(root: Path, *, restoring: bool):
    from mobile_release.cancellation import CleanupScope, DefaultCancellation
    from mobile_release.init_workspace_custody import InitRootLease

    value = root.stat()
    guard = DefaultCancellation(ValidationError, "image recovery fixture cleanup failed")
    lease = InitRootLease(root, cancellation=guard, profile=tx.TypedEditProfile.METADATA_IMAGES,
                          image_recovery=restoring,
                          registered_identity={"device": value.st_dev, "inode": value.st_ino,
                                               "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid})
    cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
    try:
        with cleanup:
            guard.install(); guard.activate(); lease.acquire()
            yield lease, guard
    finally:
        cleanup.__exit__(*sys.exc_info())
        if not lease.closed or guard.handler_state != "RESTORED":
            raise AssertionError("original fixture lease/handler did not settle")


@contextmanager
def _project(*, empty: bool = False):
    # The parent container also owns intentionally renamed roots used by the
    # stale-root tests, so failures cannot strand an untracked temporary tree.
    with tempfile.TemporaryDirectory(prefix="mrk-image-restart-") as directory:
        root = Path(directory) / "project"
        (root / "release").mkdir(parents=True)
        (root / "release/mobile-release.json").write_text(json.dumps(config()), encoding="utf-8")
        (root / ".gitignore").write_text("\n".join(tx.IGNORE_LINES) + "\n", encoding="utf-8")
        if not empty:
            folder = root / FOLDER
            folder.mkdir(parents=True)
            (folder / "01.png").write_bytes(OLD); (folder / "01.png").chmod(0o640)
            (folder / "03.png").write_bytes(KEPT)
            (folder / "04.png").write_bytes(SIBLING)
        yield root


def _source_objects(root: Path, batch):
    """Actual fixture-owned originals; no native-selection evidence is claimed."""
    folder = root.parent / "sources"
    folder.mkdir(exist_ok=True)
    result = []
    for row in batch:
        path = folder / f"{row.item_id}.png"
        path.write_bytes(row.data)
        value = path.stat()
        result.append({"device": str(value.st_dev), "inode": str(value.st_ino)})
    return result


def _stage(root: Path, phase: str, *, empty: bool = False):
    """Produce persisted state with the actual original writer, then close it."""
    batch = tuple(selected(raw, identity=f"{index + 1:032x}", name=f"{index + 1:02}.png")
                  for index, raw in enumerate(NEW[:2] if empty else NEW))
    with _live_lease(root, restoring=False) as (lease, guard):
        checkout = edit.capture_metadata_images_edit(lease, "android", "en-US", "phoneScreenshots", batch, [],
                                                     _source_objects(root, batch))
        choices = [{"itemId": row.item_id, "replaceExisting": index == 0 and not empty}
                   for index, row in enumerate(batch)]
        prepared = edit.prepare_metadata_images_edit(lease, checkout, checkout.revision, checkout.baseline, choices)
        if not prepared.view["valid"]:
            raise AssertionError("original image fixture must first pass real preparation")
        with lease.workspace_scope(checkout._revision) as workspace:
            workspace.rename = tx._rename_function()
            changes = [(row.observed(), payload) for row, payload in zip(checkout._files, prepared._payloads)]
            before_ready = phase.startswith("preparing")
            original_state_move = workspace._state_move

            def state_move(old, new):
                if before_ready and (old, new) == (tx.IMAGE_PREPARING, tx.IMAGE_READY):
                    raise _FixturePause("after complete staging, before READY")
                return original_state_move(old, new)

            with patch.object(workspace, "_state_move", state_move):
                try:
                    plan = workspace._prepare(changes)
                except _FixturePause:
                    if not before_ready:
                        raise
                    with workspace._private(tx.IMAGE_PREPARING) as fd:
                        plan = workspace._load(fd)
            if not before_ready and phase != "ready_old":
                with workspace._private(tx.IMAGE_READY) as fd:
                    original_move = workspace._move
                    stopping = "new-0" if phase == "between" or empty else "new-1"

                    def move(source_fd, source, destination_fd, destination, expected, **kwargs):
                        if phase in {"mixed", "between", "rolled_back", "rolled_back_partial"} and source == stopping:
                            raise _FixturePause("before one new file installation")
                        return original_move(source_fd, source, destination_fd, destination, expected, **kwargs)

                    workspace._installing = True
                    try:
                        with patch.object(workspace, "_move", move):
                            try:
                                workspace._install(fd, plan)
                            except _FixturePause:
                                if phase not in {"mixed", "between", "rolled_back", "rolled_back_partial"}:
                                    raise
                    finally:
                        workspace._installing = False
                    if phase.startswith("rolled_back"):
                        workspace._rollback(fd, plan)
            if phase.endswith("_partial"):
                original_state_move(workspace.state(), tx.IMAGE_CLEANUP)
                original_unlink = workspace._unlink
                removed = []

                def unlink(name, **kwargs):
                    original_unlink(name, **kwargs)
                    if name not in tx.CONTROLS and name != tx.IMAGE_CLEANUP:
                        removed.append(name)
                        raise _FixturePause("after one actual DATA cleanup, before controls")

                with patch.object(workspace, "_unlink", unlink):
                    try:
                        workspace._cleanup()
                    except _FixturePause:
                        pass
                if len(removed) != 1:
                    raise AssertionError("partial-cleanup fixture did not remove exactly one DATA entry")
            if guard.lifetime_ledger.fatal:
                raise AssertionError("fixture staging lost custody")
            return plan


def _prepare_recovery(lease):
    checkout = recovery.capture_metadata_images_recovery(lease)
    prepared = recovery.prepare_metadata_images_recovery(lease, checkout, checkout.revision, checkout.baseline, [])
    return checkout, prepared


class MetadataImagesRecoveryFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith("linux"), "this explicit native fixture profile is Linux-only")

    def _assert_clean(self, root, *, empty=False, committed=False):
        self.assertTrue(all(not (root / state).exists() for state in tx.ALL_STATE_NAMES))
        if empty and not committed:
            self.assertFalse((root / "public").exists())
            return
        folder = root / FOLDER
        self.assertEqual((folder / "01.png").read_bytes(), NEW[0] if committed else OLD)
        if committed:
            self.assertEqual((folder / "02.png").read_bytes(), NEW[1])
        else:
            self.assertFalse((folder / "02.png").exists())
        if not empty:
            self.assertEqual((folder / "03.png").read_bytes(), KEPT)
            self.assertEqual((folder / "04.png").read_bytes(), SIBLING)

    def test_00_actual_mixed_ready_rollback_preserves_old_identity_and_readonly_facts(self):
        with _project() as root:
            original = _facts(root / FOLDER / "01.png")
            unchanged = {path: _facts(root / path) for path in (
                "release/mobile-release.json", ".gitignore", FOLDER + "/03.png", FOLDER + "/04.png")}
            _stage(root, "mixed")
            self.assertEqual((root / FOLDER / "01.png").read_bytes(), NEW[0])
            with _live_lease(root, restoring=True) as (lease, guard):
                checkout, prepared = _prepare_recovery(lease)
                self.assertEqual(checkout.view["action"], "rollback")
                self.assertEqual(prepared.view, checkout.view)
                self.assertIsInstance(checkout._revision, recovery.ImageRecoveryRevision)
                self.assertIsNone(lease._revision)
                with patch.object(tx.InitWorkspace, "recover", side_effect=AssertionError("not generic recovery")), \
                        patch.object(tx.InitWorkspace, "_fixed_recovery", side_effect=AssertionError("not original import recovery")), \
                        patch.object(tx.InitWorkspace, "_install", side_effect=AssertionError("never retry import")):
                    outcome = recovery.apply_metadata_images_recovery(lease, prepared)
                for scope in lease._scopes:
                    workspace = scope.workspace
                    self.assertFalse(workspace._workflow_complete)
                    self.assertIsNone(workspace._workflow_header)
                    self.assertIsNone(workspace._workflow_plan)
                    self.assertEqual(workspace._workflow_controls, {})
                    self.assertEqual(workspace._creation, {"state": "NEW"})
                    self.assertFalse(workspace._install_started)
                    self.assertIsNone(workspace._rooted_revision)
                    self.assertEqual(workspace._captured, {})
                self.assertEqual(outcome, shared.CoreEditOutcome("rolled_back", "clean", "settled", "none"))
                self.assertFalse(guard.lifetime_ledger.fatal)
            self._assert_clean(root)
            self.assertEqual(_facts(root / FOLDER / "01.png")[:-1], original[:-1])
            for path, facts in unchanged.items():
                self.assertEqual(_facts(root / path), facts)

    def test_complete_preparing_between_and_owned_new_directory_states(self):
        for phase, empty, action, effect in (
            ("preparing", False, "preparing_cleanup", "not_started"),
            ("preparing", True, "preparing_cleanup", "not_started"),
            ("between", False, "rollback", "rolled_back"),
            ("mixed", True, "rollback", "rolled_back"),
        ):
            with self.subTest(phase=phase, empty=empty), _project(empty=empty) as root:
                _stage(root, phase, empty=empty)
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout, prepared = _prepare_recovery(lease)
                    self.assertEqual(checkout.view["action"], action)
                    self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared),
                                     shared.CoreEditOutcome(effect, "clean", "settled", "none"))
                self._assert_clean(root, empty=empty)

    def test_committed_and_rolled_back_cleanup_accept_only_complete_controls_and_admitted_data_subset(self):
        for phase in ("committed", "committed_partial", "rolled_back", "rolled_back_partial", "preparing_partial"):
            with self.subTest(phase=phase), _project() as root:
                _stage(root, phase)
                committed = phase.startswith("committed")
                expected_effect = "committed" if committed else "not_started" if phase.startswith("preparing") else "rolled_back"
                state = tx.IMAGE_CLEANUP if phase.endswith("partial") else tx.IMAGE_READY
                self.assertTrue((root / state / "plan.json").exists())
                public = {path: _facts(path) for path in (root / FOLDER).iterdir()}
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout, prepared = _prepare_recovery(lease)
                    self.assertEqual(checkout.view["action"], "committed_cleanup" if committed else
                                     "preparing_cleanup" if phase.startswith("preparing") else "rolled_back_cleanup")
                    self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared),
                                     shared.CoreEditOutcome(expected_effect, "clean", "settled", "none"))
                self._assert_clean(root, committed=committed)
                for path, facts in public.items():
                    self.assertEqual(_facts(path), facts)

    def test_incomplete_contradictory_or_foreign_control_proof_is_conflict_not_cleanup_authority(self):
        for change in ("missing_plan", "missing_pending", "duplicate_terminal", "foreign_domain", "unknown_entry"):
            with self.subTest(change=change), _project() as root:
                _stage(root, "committed_partial")
                journal = root / tx.IMAGE_CLEANUP
                if change == "missing_plan":
                    (journal / "plan.json").unlink()
                elif change == "missing_pending":
                    (journal / "rollback.pending").unlink()
                elif change == "duplicate_terminal":
                    (journal / "commit.pending").write_bytes((journal / "COMMITTED").read_bytes())
                elif change == "foreign_domain":
                    header = json.loads((journal / "header.json").read_bytes())
                    header["domain"] = "metadata_text"
                    (journal / "header.json").write_bytes(tx._json(header))
                else:
                    (journal / "user-note.txt").write_bytes(b"user content must remain")
                before = {path.name: path.read_bytes() for path in journal.iterdir() if path.is_file()}
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout = recovery.capture_metadata_images_recovery(lease)
                    self.assertEqual(checkout.view["state"], "conflict")
                    self.assertIsNone(checkout.view["platform"])
                    self.assertEqual(checkout.view["files"], [])
                    self.assertIsNone(lease._image_recovery)
                    with self.assertRaises(shared.ConfigEditFailure):
                        recovery.prepare_metadata_images_recovery(lease, checkout, checkout.revision, checkout.baseline, [])
                self.assertEqual({path.name: path.read_bytes() for path in journal.iterdir() if path.is_file()}, before)

    def test_changed_saved_dependencies_targets_and_portable_alias_refuse_without_public_effects(self):
        for change in ("config", "ignore", "readonly", "target", "alias", "root_header", "image_limit", "batch_limit"):
            with self.subTest(change=change), _project() as root:
                _stage(root, "mixed")
                journal = root / tx.IMAGE_READY
                if change == "config":
                    value = config("another/public/store")
                    (root / "release/mobile-release.json").write_text(json.dumps(value), encoding="utf-8")
                elif change == "ignore":
                    with (root / ".gitignore").open("ab") as handle:
                        handle.write(b"# user edit\n")
                elif change in {"readonly", "target"}:
                    (root / FOLDER / ("04.png" if change == "readonly" else "01.png")).write_bytes(png(pixel=7))
                elif change == "alias":
                    (root / FOLDER / "01.PNG").write_bytes(png(pixel=7))
                elif change == "root_header":
                    value = json.loads((journal / "header.json").read_bytes())
                    value["root"]["inode"] += 1
                    (journal / "header.json").write_bytes(tx._json(value))
                elif change == "image_limit":
                    value = json.loads((journal / "plan.json").read_bytes())
                    value["files"][0]["after"]["size"] = images.MAX_IMAGE_BYTES + 1
                    (journal / "plan.json").write_bytes(tx._json(value))
                before = {path.name: path.read_bytes() for path in (root / FOLDER).iterdir()}
                with _live_lease(root, restoring=True) as (lease, _):
                    with patch.object(recovery, "MAX_BATCH_BYTES", 1 if change == "batch_limit" else images.MAX_BATCH_BYTES):
                        try:
                            checkout = recovery.capture_metadata_images_recovery(lease)
                        except shared.ConfigEditFailure as error:
                            # A portable alias is a live namespace conflict,
                            # not a deterministic journal-DATA-only failure.
                            self.assertEqual(change, "alias")
                            self.assertNotEqual(error.outcome.reason, "none")
                        else:
                            self.assertEqual(checkout.view["state"], "conflict")
                    self.assertIsNone(lease._image_recovery)
                self.assertEqual({path.name: path.read_bytes() for path in (root / FOLDER).iterdir()}, before)
                self.assertTrue(journal.exists())

    def test_current_revision_rechecks_config_siblings_targets_and_journal_identity_before_apply(self):
        for change in ("config", "ignore", "sibling", "target", "journal", "root"):
            with self.subTest(change=change), _project() as root:
                _stage(root, "committed" if change == "root" else "mixed")
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout, prepared = _prepare_recovery(lease)
                    if change in {"config", "ignore"}:
                        path = root / ("release/mobile-release.json" if change == "config" else ".gitignore")
                        path.write_bytes(path.read_bytes() + b" ")
                    elif change in {"sibling", "target"}:
                        (root / FOLDER / ("04.png" if change == "sibling" else "01.png")).write_bytes(png(pixel=8))
                    elif change == "journal":
                        old = root / tx.IMAGE_READY
                        moved = root.parent / "original-journal"
                        old.rename(moved); old.mkdir(mode=0o700)
                        for path in moved.iterdir():
                            path.rename(old / path.name)
                    else:
                        root.chmod(0o750 if stat.S_IMODE(root.stat().st_mode) != 0o750 else 0o700)
                    outcome = recovery.apply_metadata_images_recovery(lease, prepared)
                    self.assertEqual(outcome.reason, "stale_revision")
                    self.assertNotEqual(outcome.journal, "clean")
                    if change == "root":
                        self.assertEqual((outcome.effect, outcome.journal), ("committed", "recovery_required"))
                    self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared).reason, "invalid_params")
                self.assertTrue((root / tx.IMAGE_READY).exists())

    def test_one_shot_consent_immutable_authority_and_discard_do_not_erase_inspected_commit(self):
        for bad in ("choices", "baseline", "revision", "none"):
            with self.subTest(bad=bad), _project() as root:
                _stage(root, "committed")
                with _live_lease(root, restoring=True) as (lease, _):
                    checkout = recovery.capture_metadata_images_recovery(lease)
                    authority = checkout._revision
                    for value in (checkout, authority):
                        with self.assertRaises(TypeError):
                            copy.copy(value)
                        with self.assertRaises(TypeError):
                            copy.deepcopy(value)
                        with self.assertRaises(AttributeError):
                            value._token = "f" * 32
                    with self.assertRaises(TypeError):
                        recovery.ImageRecoveryRevision()
                    baseline, revision, choices = checkout.baseline, checkout.revision, []
                    if bad == "baseline": baseline["inventorySha256"] = "0" * 64
                    if bad == "revision": revision = "f" * 32
                    if bad == "choices": choices = [{"action": "rollback"}]
                    if bad == "none":
                        recovery.discard_metadata_images_recovery(checkout)
                    with self.assertRaises(shared.ConfigEditFailure):
                        recovery.prepare_metadata_images_recovery(lease, checkout, revision, baseline, choices)
                    with self.assertRaises(shared.ConfigEditFailure):
                        recovery.prepare_metadata_images_recovery(lease, checkout, checkout.revision, checkout.baseline, [])
                    self.assertEqual(len(lease._scopes), 1)
                    current = lease.last_outcome
                    self.assertEqual((current.effect, current.journal, current.reason),
                                     ("committed", "recovery_required", "pending_state"))
                    self.assertIsNone(lease._scopes[-1].workspace._terminal_seen)
                self.assertTrue((root / tx.IMAGE_READY / "COMMITTED").exists())

    def test_idle_and_unreadable_configuration_never_manufacture_usable_baseline_or_recovery(self):
        with _project() as root:
            with _live_lease(root, restoring=True) as (lease, _):
                checkout = recovery.capture_metadata_images_recovery(lease)
                self.assertEqual(checkout.view, recovery._view(None))
                self.assertIsNone(checkout._revision)
                self.assertEqual(checkout.baseline["config"], images.content_digest((root / "release/mobile-release.json").read_bytes()))
                with self.assertRaises(shared.ConfigEditFailure):
                    recovery.prepare_metadata_images_recovery(lease, checkout, checkout.revision, checkout.baseline, [])
            (root / "release/mobile-release.json").unlink()
            with _live_lease(root, restoring=True) as (lease, _):
                with self.assertRaises(shared.ConfigEditFailure) as error:
                    recovery.capture_metadata_images_recovery(lease)
                self.assertEqual(error.exception.outcome.reason, "invalid_config")
                self.assertIsNone(lease._image_recovery)

    def test_original_stop_after_owned_rollback_move_preserves_failure_and_requires_new_recovery(self):
        with _project() as root:
            _stage(root, "mixed")
            outcomes = []
            observed = []
            with self.assertRaises(KeyboardInterrupt):
                with _live_lease(root, restoring=True) as (lease, guard):
                    _, prepared = _prepare_recovery(lease)
                    original_move = tx.InitWorkspace._move

                    def move(workspace, *args, **kwargs):
                        result = original_move(workspace, *args, **kwargs)
                        if workspace._image_recovery is not None and not observed:
                            observed.append(args[1])
                            guard.cancelled = True
                        return result

                    with patch.object(tx.InitWorkspace, "_move", move):
                        outcomes.append(recovery.apply_metadata_images_recovery(lease, prepared))
            self.assertEqual(len(observed), 1)
            self.assertEqual(outcomes, [shared.CoreEditOutcome("unknown", "recovery_required", "settled", "cancelled")])
            self.assertTrue((root / tx.IMAGE_READY).exists())
            with _live_lease(root, restoring=True) as (lease, _):
                _, prepared = _prepare_recovery(lease)
                self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared).reason, "none")
            self._assert_clean(root)

    def test_terminal_fsync_failure_keeps_rolled_back_fact_without_cleanup_or_false_success(self):
        with _project() as root:
            _stage(root, "mixed")
            with _live_lease(root, restoring=True) as (lease, _):
                _, prepared = _prepare_recovery(lease)
                original_fsync = tx.InitWorkspace._fsync
                failures = []

                def fsync(workspace, fd):
                    original_fsync(workspace, fd)
                    if (workspace._image_recovery is not None and workspace._publishing_terminal == "ROLLED_BACK"
                            and workspace._terminal_seen == "ROLLED_BACK" and not failures):
                        failures.append(fd)
                        raise OSError("synthetic terminal durability interruption")

                with patch.object(tx.InitWorkspace, "_fsync", fsync), \
                        patch.object(tx.InitWorkspace, "_cleanup", side_effect=AssertionError("no cleanup after uncertain durability")):
                    outcome = recovery.apply_metadata_images_recovery(lease, prepared)
                self.assertEqual(outcome, shared.CoreEditOutcome("rolled_back", "recovery_required", "settled", "filesystem_error"))
                self.assertEqual(len(failures), 1)
            self.assertTrue((root / tx.IMAGE_READY / "ROLLED_BACK").exists())
            self.assertEqual((root / FOLDER / "01.png").read_bytes(), OLD)

    def test_cleanup_failure_after_owned_deletion_is_not_retried_and_new_inspection_can_finish(self):
        with _project() as root:
            _stage(root, "committed")
            with _live_lease(root, restoring=True) as (lease, _):
                _, prepared = _prepare_recovery(lease)
                original_unlink = tx.InitWorkspace._unlink
                removed = []

                def unlink(workspace, name, **kwargs):
                    original_unlink(workspace, name, **kwargs)
                    if workspace._image_recovery is not None:
                        removed.append(name)
                        raise OSError("synthetic lost cleanup return")

                with patch.object(tx.InitWorkspace, "_unlink", unlink):
                    outcome = recovery.apply_metadata_images_recovery(lease, prepared)
                self.assertEqual(outcome, shared.CoreEditOutcome("committed", "recovery_required", "settled", "filesystem_error"))
                self.assertEqual(removed, ["old-0"])
            with _live_lease(root, restoring=True) as (lease, _):
                checkout, prepared = _prepare_recovery(lease)
                self.assertEqual(checkout.view["action"], "committed_cleanup")
                self.assertEqual(recovery.apply_metadata_images_recovery(lease, prepared).reason, "none")
            self._assert_clean(root, committed=True)

    def test_actual_committed_target_is_checked_again_before_last_backup_cleanup(self):
        with _project() as root:
            _stage(root, "committed")
            with _live_lease(root, restoring=True) as (lease, _):
                _, prepared = _prepare_recovery(lease)
                original_move = tx.InitWorkspace._state_move

                def state_move(workspace, old, new):
                    original_move(workspace, old, new)
                    if workspace._image_recovery is not None:
                        (root / FOLDER / "01.png").write_bytes(png(pixel=9))

                with patch.object(tx.InitWorkspace, "_state_move", state_move):
                    outcome = recovery.apply_metadata_images_recovery(lease, prepared)
                self.assertEqual(outcome.reason, "stale_revision")
                self.assertEqual(outcome.journal, "recovery_required")
            self.assertEqual((root / tx.IMAGE_CLEANUP / "old-0").read_bytes(), OLD)
            self.assertEqual((root / FOLDER / "01.png").read_bytes(), png(pixel=9))


class WindowsImageBackendAdmissionDataTests(unittest.TestCase):
    """Pure negative preflight, not a Windows mutation/lease qualification."""

    def test_import_and_recovery_root_data_refuse_before_posix_path_or_writer_use(self):
        from mobile_release import _desktop_edit_engine as engine
        from mobile_release import _desktop_images_protocol as wire
        from test_metadata_images_protocol import decode
        from test_metadata_images import no_io
        identity = {"volumeSerial": "9", "fileId": "008102830485068708890a8b0c8d0e8f"}
        with no_io(), patch.object(engine, "Path", side_effect=AssertionError("POSIX normalization before admission")), \
                patch.object(engine, "_root", side_effect=AssertionError("POSIX root before admission")), \
                patch.object(engine, "InitRootLease", side_effect=AssertionError("writer before admission")):
            request = decode(0, "open", {"root": r"C:\project", "registeredIdentity": identity, "intent": "recover"})
            self.assertEqual(request.protocol, wire.PROTOCOL)
            for root in (r"C:\project", r"\\?\c:\project"):
                with self.assertRaises(shared.ConfigEditFailure) as failure:
                    engine._admit_image_backend(root, identity)
                self.assertEqual(failure.exception.outcome.reason, "unsupported_platform")
            with self.assertRaises(shared.ConfigEditFailure) as failure:
                engine._admit_image_backend("/posix", identity)
            self.assertEqual(failure.exception.outcome.reason, "invalid_params")

    def test_existing_posix_backend_receives_unchanged_five_root_facts(self):
        from mobile_release import _desktop_edit_engine as engine
        from test_metadata_images import no_io
        identity = {"device": "1", "inode": "2", "mode": 0o40700, "uid": 1000, "gid": 1001}
        with no_io():
            accepted = engine._admit_image_backend("/inert/project", identity)
            self.assertEqual(accepted.family, "posix")
            self.assertEqual(accepted.posix_values(), {"device": 1, "inode": 2, "mode": 0o40700, "uid": 1000, "gid": 1001})


if __name__ == "__main__":
    unittest.main()
