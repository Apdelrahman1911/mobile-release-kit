"""Actual guarded workflow recovery tests, not passive/native qualification.

Run only in the separately admitted Linux/macOS filesystem boundary. The donor
journal is produced by the real typed workflow Apply; only fault timing and its
automatic recovery are interrupted. No subprocess or alternate rollback engine.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import github_workflow_recovery as recovery
from mobile_release import init_transaction as tx
from mobile_release.api import _github_setup as setup
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config_edit import ConfigEditFailure
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease, LockedInitScope, _failure
from mobile_release.workflow_payloads import render_workflow_caller

PROFILE = tx.TypedEditProfile.GITHUB_WORKFLOWS


def full9(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def namespace(root):
    result = {}
    for path in (root, *sorted(root.rglob("*"))):
        value = path.lstat()
        result[path.relative_to(root).as_posix()] = (full9(value), path.read_bytes() if stat.S_ISREG(value.st_mode) else None)
    return result


def forbidden(*_args, **_kwargs):
    raise AssertionError("recovery must not render, stage, reopen/relock, or inspect public committed callers")


class WorkflowRecoveryFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith("linux") or sys.platform == "darwin")
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-workflow-recovery-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.resource_raw, resource = setup._resource()
        self.old = tuple(render_workflow_caller(resource["workflows"][identity].encode(), "old/toolkit", "a" * 40)
                         for identity, _ in tx.WORKFLOWS)
        self.new = tuple(render_workflow_caller(resource["workflows"][identity].encode(), "new/toolkit", "b" * 40)
                         for identity, _ in tx.WORKFLOWS)
        callers = self.root / ".github" / "workflows"
        callers.mkdir(parents=True)
        self.initial = (self.old[0], None, self.new[2], self.old[3])
        self.modes = (0o640, None, 0o644, 0o604)
        for path, raw, mode in zip(PROFILE.paths, self.initial, self.modes):
            if raw is not None:
                target = self.root / path
                target.write_bytes(raw)
                target.chmod(mode)
        self.sentinel = callers / "unrelated.yml"
        self.sentinel.write_bytes(b"# unrelated user workflow\n")
        self.originals = {path: (self.root / path).stat() for path, raw in zip(PROFILE.paths, self.initial) if raw is not None}
        self.sentinel_before = full9(self.sentinel.stat())

    @contextmanager
    def lease(self, *, recover=False):
        registered = self.root.stat()
        guard = DefaultCancellation(ValidationError, "workflow recovery test custody failed")
        lease = InitRootLease(self.root, cancellation=guard, profile=PROFILE, workflow_recovery=recover,
                              registered_identity={"device": registered.st_dev, "inode": registered.st_ino,
                                                   "mode": registered.st_mode, "uid": registered.st_uid, "gid": registered.st_gid})
        cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
        try:
            with cleanup:
                guard.install()
                guard.activate()
                lease.acquire()
                yield lease
        finally:
            cleanup.__exit__(*sys.exc_info())
        self.assertTrue(lease.closed)
        self.assertFalse(guard.lifetime_ledger.fatal)
        self.assertEqual(guard.handler_state, "RESTORED")

    def pending(self, point="mixed"):
        first = PROFILE.paths[0].rsplit("/", 1)[-1]
        created = PROFILE.paths[1].rsplit("/", 1)[-1]
        target = {"between": (first, "old-0"), "mixed": ("new-1", created),
                  "committed": ("commit.pending", "COMMITTED")}.get(point)
        original_move, original_state = tx.InitWorkspace._move, tx.InitWorkspace._state_move
        failure = OSError("test-only stopped typed transaction")
        stopped = False

        def move(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            nonlocal stopped
            value = original_move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            if (source, destination) == target and not stopped:
                stopped = True
                raise failure
            return value

        def state(owner, old, new):
            nonlocal stopped
            if point == "preparing" and old == tx.PREPARING and new == tx.READY and not stopped:
                stopped = True
                raise failure
            return original_state(owner, old, new)

        with self.lease() as lease:
            with lease.workspace_scope() as workspace:
                originals = tuple(workspace.observe(path, limit=limit)
                                  for path, limit in zip(PROFILE.paths, PROFILE.observation_limits))
                revision = lease.bind_revision(workspace, originals)
            with patch.object(tx.InitWorkspace, "_move", move), patch.object(tx.InitWorkspace, "_state_move", state), patch.object(
                tx.InitWorkspace, "_fixed_recovery", return_value=None
            ):
                with self.assertRaises(tx.InitOperationFailure) as caught:
                    with lease.workspace_scope(revision) as workspace:
                        workspace.apply_workflows_typed(
                            [(item, None if index == 2 else self.new[index]) for index, item in enumerate(originals)],
                            resource_sha256=hashlib.sha256(self.resource_raw).hexdigest())
                self.assertIs(workspace._primary, failure)
                self.assertEqual(caught.exception.outcome.journal, "recovery_required")
        self.assertTrue(stopped)
        self.assertTrue((self.root / (tx.PREPARING if point == "preparing" else tx.READY)).is_dir())

    def prepared(self, lease):
        checkout = recovery.capture_github_workflow_recovery(lease)
        self.assertEqual(checkout.view["state"], "recoverable")
        before = namespace(self.root)
        plan = recovery.prepare_github_workflow_recovery(lease, checkout, checkout.revision)
        self.assertEqual(namespace(self.root), before, "Inspect and Prepare are read-only")
        return checkout, plan

    def assert_restored(self):
        self.assertFalse(any((self.root / state).exists() for state in tx.ALL_STATE_NAMES))
        for index, path in enumerate(PROFILE.paths):
            target = self.root / path
            if self.initial[index] is None:
                self.assertFalse(target.exists())
            else:
                self.assertEqual(target.read_bytes(), self.initial[index])
                self.assertEqual(target.stat().st_ino, self.originals[path].st_ino)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), self.modes[index])
        self.assertEqual(full9((self.root / PROFILE.paths[2]).stat()), full9(self.originals[PROFILE.paths[2]]))
        self.assertEqual(full9(self.sentinel.stat()), self.sentinel_before)

    def test_fresh_untyped_borrow_uses_original_engine_once_and_never_recreates_apply(self):
        self.pending("between")
        seen = []
        original = tx.InitWorkspace.recover

        def recover(workspace):
            self.assertIsNone(workspace._typed_profile)
            self.assertEqual(workspace._creation["state"], "NEW")
            self.assertIs(workspace._scope.workspace, workspace)
            self.assertEqual(workspace.fd, workspace._scope.fd)
            seen.append(workspace)
            return original(workspace)

        with self.lease(recover=True) as lease, patch.object(tx.InitWorkspace, "__enter__", forbidden), patch.object(
            tx.InitWorkspace, "_prepare", forbidden
        ), patch.object(tx.InitWorkspace, "_install", forbidden), patch.object(setup, "_resource", forbidden), patch.object(
            tx.InitWorkspace, "recover", recover
        ):
            checkout, plan = self.prepared(lease)
            result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("rolled_back", "clean", "settled", "none"))
            self.assertEqual(len(seen), 1)
            self.assertIsNot(seen[0], lease._scopes[0].workspace)
            self.assertEqual(seen[0]._creation["state"], "NEW")
            self.assertEqual(recovery.apply_github_workflow_recovery(lease, plan).reason, "invalid_params")
            self.assertEqual(len(seen), 1)
            self.assertIsNot(checkout.revision, plan.token)
        self.assert_restored()

    def test_committed_cleanup_does_not_read_or_revert_later_public_callers(self):
        self.pending("committed")
        later = self.root / PROFILE.paths[0]
        later.write_bytes(b"# later custom caller, not canonical\n")
        (self.root / PROFILE.paths[1]).unlink()
        later_before = full9(later.stat())
        with self.lease(recover=True) as lease, patch.object(tx.InitWorkspace, "_current", forbidden), patch.object(
            recovery, "_current", forbidden
        ), patch.object(setup, "_resource", forbidden):
            _, plan = self.prepared(lease)
            self.assertEqual(plan.view["action"], "committed_cleanup")
            result = recovery.apply_github_workflow_recovery(lease, plan)
        self.assertEqual((result.effect, result.journal, result.resources, result.reason), ("committed", "clean", "settled", "none"))
        self.assertEqual(later.read_bytes(), b"# later custom caller, not canonical\n")
        self.assertEqual(full9(later.stat()), later_before)
        self.assertFalse((self.root / PROFILE.paths[1]).exists())
        self.assertFalse(any((self.root / state).exists() for state in tx.ALL_STATE_NAMES))

    def test_control_substitution_at_engine_load_cannot_retarget_generic_recover(self):
        self.pending("between")
        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            original = tx.InitWorkspace._load
            after = None

            def load(workspace, fd):
                nonlocal after
                if workspace._workflow_recovery_guard is None or after is not None:
                    return original(workspace, fd)
                # Initial guard.check has already succeeded. The per-read hook,
                # not merely final recheck or Apply entry, must bind consumption.
                journal = self.root / tx.READY
                data = json.loads((journal / "plan.json").read_bytes())
                data["files"][0]["path"] = ".github/workflows/unapproved.yml"
                # A self-consistent generic plan/marker set could restore old-0
                # at this other absent caller. The new guard must refuse it.
                (journal / "plan.json").write_bytes(tx._json(data))
                for marker, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                    (journal / pending).write_bytes(workspace._marker(data, marker))
                after = namespace(self.root)
                return original(workspace, fd)

            with patch.object(tx.InitWorkspace, "_load", load):
                result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertIsNotNone(after)
            self.assertEqual(result.reason, "stale_revision")
            self.assertEqual(result.journal, "recovery_required")
            self.assertEqual(namespace(self.root), after)
            self.assertFalse((self.root / ".github/workflows/unapproved.yml").exists())
            self.assertEqual((self.root / tx.READY / "old-0").read_bytes(), self.old[0])
            self.assertEqual(recovery.apply_github_workflow_recovery(lease, plan).reason, "stale_revision")
            # First failure stays first; repeat consumption performs no IO.
            self.assertEqual(namespace(self.root), after)

    def test_private_replacement_after_cleanup_capture_is_preserved_not_adopted(self):
        self.pending("committed")
        original = recovery._RestorationGuard.cleanup_entry
        after = None

        def entry(guard, workspace, fd, name, directory, binding):
            nonlocal after
            original(guard, workspace, fd, name, directory, binding)
            if name == "old-0" and after is None:
                temporary = self.root / "replacement.tmp"
                temporary.write_bytes(b"unrelated replacement in private namespace\n")
                os.replace(temporary, self.root / tx.CLEANUP / "old-0")
                after = namespace(self.root)

        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            with patch.object(recovery._RestorationGuard, "cleanup_entry", entry):
                result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertIsNotNone(after)
            self.assertEqual((result.effect, result.journal, result.reason), ("committed", "recovery_required", "stale_revision"))
            self.assertEqual(namespace(self.root), after)
            self.assertEqual((self.root / tx.CLEANUP / "old-0").read_bytes(), b"unrelated replacement in private namespace\n")

    def test_later_failed_lock_acquisition_preserves_inspected_commit_and_journal(self):
        self.pending("committed")
        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            before = namespace(self.root)
            with patch.object(LockedInitScope, "acquire", side_effect=_failure("busy")):
                result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "recovery_required", "settled", "busy"))
            self.assertIsNone(lease._scopes[-1].workspace)
            self.assertEqual(namespace(self.root), before)

    def test_vanished_inspected_journal_is_unknown_not_never_created(self):
        self.pending("committed")
        with self.lease(recover=True) as lease:
            checkout = recovery.capture_github_workflow_recovery(lease)
            self.assertEqual(checkout.view["action"], "committed_cleanup")
            (self.root / tx.READY).rename(self.root / "preserved-journal")
            after = namespace(self.root)
            with self.assertRaises(ConfigEditFailure) as caught:
                recovery.prepare_github_workflow_recovery(lease, checkout, checkout.revision)
            result = caught.exception.outcome
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "unknown", "settled", "stale_revision"))
            retained = lease.last_outcome
            self.assertEqual((retained.effect, retained.journal), ("committed", "unknown"))
            self.assertEqual(namespace(self.root), after)

    def test_replacement_terminal_cannot_downgrade_inspected_committed_fact(self):
        self.pending("committed")
        journal = self.root / tx.CLEANUP
        (self.root / tx.READY).rename(journal)
        for name in ("old-0", "old-3"):
            (journal / name).unlink()
        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            self.assertEqual(plan.view["action"], "committed_cleanup")
            # Separately self-consistent terminal CLEANUP, but not the inspected
            # one. Both decisions permit no DATA at this partial-cleanup point.
            (journal / "COMMITTED").rename(journal / "commit.pending")
            (journal / "rollback.pending").rename(journal / "ROLLED_BACK")
            after = namespace(self.root)
            result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "recovery_required", "settled", "stale_revision"))
            self.assertEqual(lease.last_outcome.effect, "committed")
            self.assertEqual(namespace(self.root), after)

    def test_complete_preparing_and_partial_cleanup_keep_original_callers(self):
        for partial_cleanup in (False, True):
            with self.subTest(partial_cleanup=partial_cleanup):
                self.pending("preparing")
                if partial_cleanup:
                    journal = self.root / tx.CLEANUP
                    (self.root / tx.PREPARING).rename(journal)
                    (journal / "new-1").unlink()
                with self.lease(recover=True) as lease:
                    _, plan = self.prepared(lease)
                    self.assertEqual(plan.view["action"], "preparing_cleanup")
                    for index, row in enumerate(plan.view["files"]):
                        summary = row["before"]
                        if self.initial[index] is None:
                            self.assertIsNone(summary)
                        else:
                            self.assertEqual(summary, {"size": len(self.initial[index]), "mode": self.modes[index],
                                                       "sha256": hashlib.sha256(self.initial[index]).hexdigest()})
                    result = recovery.apply_github_workflow_recovery(lease, plan)
                self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                                 ("not_started", "clean", "settled", "none"))
                self.assert_restored()

    def test_unclassified_shared_name_suffixes_are_read_only_refusals(self):
        for state, leaf in ((tx.PREPARING, None), (tx.PREPARING, "header.json"), (tx.CLEANUP, "COMMITTED")):
            with self.subTest(state=state, leaf=leaf):
                journal = self.root / state
                journal.mkdir(mode=0o700)
                if leaf is not None:
                    (journal / leaf).write_bytes(b'{"truncated":')
                    (journal / leaf).chmod(0o600)
                before = namespace(self.root)
                with self.lease(recover=True) as lease:
                    checkout = recovery.capture_github_workflow_recovery(lease)
                    self.assertEqual(checkout.view["state"], "conflict")
                    self.assertIsNone(checkout._revision)
                    self.assertEqual(lease.last_outcome.journal, "recovery_required")
                    with self.assertRaises(ConfigEditFailure):
                        recovery.prepare_github_workflow_recovery(lease, checkout, checkout.revision)
                    self.assertEqual(namespace(self.root), before)
                if leaf is not None:
                    (journal / leaf).unlink()
                journal.rmdir()

    def test_recovery_mode_denies_ordinary_scopes_apply_and_discarded_grants(self):
        self.pending()
        before = namespace(self.root)
        with self.lease(recover=True) as lease:
            with self.assertRaises(tx.InitOperationFailure):
                with lease.workspace_scope():
                    self.fail("ordinary edit scope admitted a recovery lease")
            checkout, plan = self.prepared(lease)
            for authority in (checkout, plan):
                for operation in (copy.copy, copy.deepcopy):
                    with self.assertRaises(TypeError):
                        operation(authority)
            snapshot = plan.view
            snapshot["files"][0]["path"] = "unapproved"
            self.assertEqual(plan.view["files"][0]["path"], PROFILE.paths[0])
            recovery.discard_github_workflow_recovery(plan)
            result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual(result.reason, "invalid_params")
            self.assertEqual(namespace(self.root), before)
        with self.lease(recover=True) as lease:
            with lease.workflow_recovery_scope() as workspace:
                with self.assertRaises(tx.InitOperationFailure):
                    workspace.apply([])
                with self.assertRaises(tx.InitOperationFailure):
                    workspace.apply_workflows_typed([], resource_sha256="a" * 64)
                with self.assertRaises(ValidationError):
                    workspace.recover()
                self.assertEqual(workspace._creation["state"], "NEW")
            self.assertEqual(namespace(self.root), before)

    def test_lost_rollback_rename_return_keeps_first_error_and_stops_new_effects(self):
        self.pending()
        original_factory = tx._rename_function
        failure = OSError("original rename return lost")
        calls = []

        def factory():
            native = original_factory()

            def rename(source_fd, source, destination_fd, destination):
                calls.append((source, destination))
                native(source_fd, source, destination_fd, destination)
                if source == "old-0":
                    raise failure
            return rename

        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            with patch.object(tx, "_rename_function", factory):
                result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual(result.reason, "filesystem_error")
            self.assertEqual(result.journal, "recovery_required")
            self.assertIs(lease._scopes[-1].workspace._primary, failure)
            self.assertEqual(calls[-1][0], "old-0")
            self.assertTrue((self.root / tx.READY / "rollback.pending").is_file())
            self.assertFalse((self.root / tx.READY / "ROLLED_BACK").exists())
        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertEqual(result.reason, "none")
        self.assert_restored()

    def test_existing_move_reconciliation_restores_actual_captured_user_object(self):
        self.pending()
        original_factory = tx._rename_function
        leaf = PROFILE.paths[1].rsplit("/", 1)[-1]
        user_inode = None

        def factory():
            native = original_factory()

            def rename(source_fd, source, destination_fd, destination):
                nonlocal user_inode
                if source == leaf and destination == "new-1" and user_inode is None:
                    temporary = self.root / "caller.tmp"
                    temporary.write_bytes(b"# concurrent user replacement\n")
                    user_inode = temporary.stat().st_ino
                    os.replace(temporary, self.root / PROFILE.paths[1])
                native(source_fd, source, destination_fd, destination)
            return rename

        with self.lease(recover=True) as lease:
            _, plan = self.prepared(lease)
            with patch.object(tx, "_rename_function", factory):
                result = recovery.apply_github_workflow_recovery(lease, plan)
            self.assertIsNotNone(user_inode)
            self.assertNotEqual(result.reason, "none")
            self.assertEqual(result.journal, "recovery_required")
            self.assertEqual((self.root / PROFILE.paths[1]).read_bytes(), b"# concurrent user replacement\n")
            self.assertEqual((self.root / PROFILE.paths[1]).stat().st_ino, user_inode)
            self.assertTrue((self.root / tx.READY / "rollback.pending").is_file())
            self.assertFalse((self.root / tx.READY / "ROLLED_BACK").exists())

    def test_late_scope_close_error_cannot_turn_recovery_into_success(self):
        self.pending()
        original = LockedInitScope.close
        failure = OSError("original scope close publication failed")
        fired = False

        def close(scope):
            nonlocal fired
            original(scope)
            if scope.workspace is not None and scope.workspace._journal_clean and not fired:
                fired = True
                raise failure

        # The inner recovery result cannot discharge the original outer
        # cancellation ledger's permanent close-failure latch.
        with self.assertRaisesRegex(ValidationError, "^workflow recovery test custody failed$"):
            with self.lease(recover=True) as lease:
                _, plan = self.prepared(lease)
                with patch.object(LockedInitScope, "close", close):
                    result = recovery.apply_github_workflow_recovery(lease, plan)
                self.assertTrue(fired)
                self.assertEqual((result.effect, result.journal), ("rolled_back", "clean"))
                self.assertEqual(result.resources, "unknown")
                self.assertNotEqual(result.reason, "none")
        self.assertTrue(lease.closed)
        self.assertEqual(lease.guard.handler_state, "RESTORED")
        self.assertTrue(lease.guard.lifetime_ledger.fatal)
        self.assert_restored()


if __name__ == "__main__":
    unittest.main()
