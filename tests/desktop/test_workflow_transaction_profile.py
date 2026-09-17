"""Inert tests for the closed workflow transaction profile.

No real root lease, file transaction, process, signal handler or native API is
acquired. Filesystem entry points are traps; the few observations below are
explicit in-memory stat/read results. These checks cannot qualify native writes.
"""
from __future__ import annotations

import builtins
import copy
import hashlib
import importlib
import os
import stat
import sys
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import init_transaction as tx
from mobile_release.errors import ValidationError

PROFILE = tx.TypedEditProfile.GITHUB_WORKFLOWS
ROOT = {"device": 9, "inode": 10, "mode": stat.S_IFDIR | 0o750, "uid": 1001, "gid": 1002}


def forbidden(*_args, **_kwargs):
    raise AssertionError("no actual filesystem/native operation is admitted")


@contextmanager
def no_io():
    with ExitStack() as stack:
        stack.enter_context(patch.object(builtins, "open", side_effect=forbidden))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "scandir",
                     "mkdir", "rename", "replace", "unlink", "rmdir", "fsync", "fchmod", "urandom",
                     "pipe", "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
            stack.enter_context(patch.object(os, name, create=True, side_effect=forbidden))
        for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            stack.enter_context(patch.object(Path, name, side_effect=forbidden))
        stack.enter_context(patch.object(tx, "_rename_function", side_effect=forbidden))
        yield


def directory(value):
    assert stat.S_ISDIR(value.st_mode)
    return dict(device=value.st_dev, inode=value.st_ino, mode=stat.S_IMODE(value.st_mode),
                uid=value.st_uid, gid=value.st_gid)


class InertGuard:
    def __init__(self):
        self.lifetime_ledger = SimpleNamespace(fatal=False)

    def _check_owner(self):
        return None

    def deferred(self, **_kwargs):
        return nullcontext()


class InertDirectory:
    def __init__(self, *_args, **_kwargs):
        self.fd = 401  # A sentinel, never an opened or closed descriptor.

    def check(self):
        return None

    acquire = close = forbidden


@contextmanager
def inert_custody():
    # Import the real lease definitions against inert native dependencies.
    # No production injection hook or alternative lease implementation exists.
    build = ModuleType("mobile_release.build_inputs")
    build.BuildInputError = ValidationError
    build._Directory = InertDirectory
    build._FD = forbidden
    build._attempt_all = forbidden
    build._build_pending_names_locked = forbidden
    build._init_pending_names_locked = forbidden
    build._directory = directory
    cancel = ModuleType("mobile_release.cancellation")
    cancel.CleanupScope = forbidden
    cancel.DefaultCancellation = InertGuard
    package = importlib.import_module("mobile_release")
    with patch.dict(sys.modules), patch.object(package, "init_workspace_custody", None, create=True):
        sys.modules.pop("mobile_release.init_workspace_custody", None)
        sys.modules[build.__name__] = build
        sys.modules[cancel.__name__] = cancel
        custody = importlib.import_module("mobile_release.init_workspace_custody")
        with no_io():
            yield custody


def stat_value(*, inode=10, mode=stat.S_IFDIR | 0o750, uid=1001, gid=1002):
    return SimpleNamespace(st_dev=9, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid)


def binding(data: bytes, inode: int) -> dict:
    return dict(device=9, inode=inode, mode=0o644, size=len(data), sha256=hashlib.sha256(data).hexdigest())


def workspace(profile=PROFILE):
    owner = tx.InitWorkspace(Path("/inert-not-opened"))
    owner._typed_profile = profile
    owner._guard = InertGuard()
    owner._scope = object()
    owner._checkpoint = lambda: None
    owner._root_check = lambda: None
    owner.root_identity = dict(device=9, inode=10, mode=0o750)
    owner.fd = 400
    owner.flags = 0
    owner.require_clean = lambda: None
    return owner


def journal_fixture():
    owner = workspace()
    header = {"schemaVersion": 1, "transactionId": "a" * 32, "root": dict(owner.root_identity)}
    directories = [{"path": path, "before": None,
                    "after": dict(device=9, inode=20 + i, mode=0o755)}
                   for i, path in enumerate(PROFILE.directories)]
    files = [{"path": path, "before": None, "after": binding(f"generated-{i}\n".encode(), 30 + i)}
             for i, path in enumerate(PROFILE.paths)]
    plan = {**header, "directories": directories, "files": files}
    contents = {"header.json": tx._json(header), "plan.json": tx._json(plan),
                "commit.pending": owner._marker(plan, "COMMITTED"),
                "rollback.pending": owner._marker(plan, "ROLLED_BACK")}
    values = {name: (binding(data, 50 + i), data) for i, (name, data) in enumerate(contents.items())}
    owner._read = lambda _fd, name, _limit=tx.MAX_FILE_BYTES: values.get(name)
    owner._bind_workflow_controls(400, contents["header.json"], contents["plan.json"], plan)
    owner._workflow_complete = True
    return owner, plan, values


class WorkflowTransactionProfileTests(unittest.TestCase):
    def test_nested_missing_facts_survive_preloaded_revision_and_stale_ancestors_refuse(self):
        with inert_custody():
            for existing in (0, 1, 2):
                with self.subTest(existing_ancestors=existing):
                    owner = workspace()
                    original = [stat_value(inode=20 + i) if i < existing else None for i in range(2)]
                    expected = {path: tx._dir_identity(value) if value else None
                                for path, value in zip(PROFILE.directories, original)}
                    owner.parents = copy.deepcopy(expected)
                    owner._alias = lambda *_args: None
                    owner._descriptor = lambda *_args, **_kwargs: nullcontext(500)
                    def observed(_fd, name):
                        return original[0 if name == ".github" else 1]
                    with patch.object(tx, "_stat", side_effect=observed), patch.object(os, "fstat") as fstat:
                        fstat.side_effect = [value for value in original if value for _ in range(2)]
                        with owner._parent(PROFILE.paths[0], planning=True) as parent:
                            self.assertEqual(parent is None, existing < 2)
                        self.assertEqual(fstat.call_count, 2 * existing)
                    self.assertEqual(owner.parents, expected)
                    self.assertEqual(owner._parent_facts,
                                     {path: tuple(sorted(directory(value).items())) if value else None
                                      for path, value in zip(PROFILE.directories, original)})
            owner = workspace()
            owner.parents = {path: None for path in PROFILE.directories}
            owner._alias = lambda *_args: None
            with patch.object(tx, "_stat", return_value=stat_value(inode=99)):
                with self.assertRaises(ValidationError):
                    with owner._parent(PROFILE.paths[0], planning=True):
                        self.fail("new ancestor was adopted")
            owner.parents = {".github": None, ".github/workflows": dict(device=9, inode=21, mode=0o750)}
            with patch.object(tx, "_stat", return_value=None):
                with self.assertRaises(ValidationError):
                    with owner._parent(PROFILE.paths[0], planning=True):
                        self.fail("inconsistent descendant was accepted")

    def test_registered_root_compares_full_mode_uid_gid_and_original_descriptor(self):
        with inert_custody() as custody:
            lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(),
                                          profile=PROFILE, registered_identity=dict(ROOT))
            lease._acquired = True
            with patch.object(os, "fstat", return_value=stat_value()) as fstat:
                lease.check()
                fstat.assert_called_once_with(401)
            for changed in (stat_value(inode=11), stat_value(mode=stat.S_IFREG | 0o750),
                            stat_value(mode=stat.S_IFDIR | 0o700), stat_value(uid=1003), stat_value(gid=1003)):
                with self.subTest(changed=changed), patch.object(os, "fstat", return_value=changed):
                    with self.assertRaises(tx.InitOperationFailure) as caught:
                        lease.check()
                    self.assertEqual(caught.exception.outcome.reason, "stale_revision")
            for bad in ({**ROOT, "mode": 0o750}, {**ROOT, "uid": True}, {**ROOT, "inode": 0},
                        {**ROOT, "device": 2**64}, {**ROOT, "gid": 2**32}, {**ROOT, "extra": 1}):
                with self.subTest(identity=bad), self.assertRaises(tx.InitOperationFailure):
                    custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(),
                                          profile=PROFILE, registered_identity=bad)

    def test_workflow_revision_is_profile_bound_and_keeps_both_absences(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex="b" * 32)):
            lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(),
                                          profile=PROFILE, registered_identity=dict(ROOT))
            lease._acquired = True
            owner = workspace()
            owner.parents = {path: None for path in PROFILE.directories}
            owner._parent_facts = dict(owner.parents)
            originals = tuple(tx.ObservedFile(path, None, None) for path in PROFILE.paths)
            owner._captured = {item.path: item for item in originals}
            owner._raw_observations = {item.path: None for item in originals}
            lease._active = SimpleNamespace(workspace=owner)
            revision = lease.bind_revision(owner, originals)
            self.assertIs(revision.profile, PROFILE)
            self.assertEqual(revision.missing_workflow_directories, PROFILE.directories)
            with self.assertRaises(tx.InitOperationFailure):
                _ = revision.release_directory_absent
            with self.assertRaises((AttributeError, TypeError)):
                revision._profile = tx.TypedEditProfile.CONFIGURATION
            with self.assertRaises(tx.InitOperationFailure):
                lease._recheck(workspace(tx.TypedEditProfile.CONFIGURATION), revision)

    def test_typed_facades_refuse_cross_profile_and_consume_the_attempt(self):
        with no_io():
            for original, wrong, correct in (
                (PROFILE, "apply_typed", "apply_workflows_typed"),
                (tx.TypedEditProfile.CONFIGURATION, "apply_workflows_typed", "apply_typed"),
            ):
                owner = workspace(original)
                with self.assertRaises(tx.InitOperationFailure):
                    getattr(owner, wrong)([])
                self.assertTrue(owner._typed_claimed)
                with self.assertRaises(tx.InitOperationFailure):
                    getattr(owner, correct)([])

    def test_workflow_noop_requires_all_four_preserved_originals_without_native_probe(self):
        with no_io():
            owner = workspace()
            originals = [tx.ObservedFile(path, binding(b"exact original", 30 + i), b"exact original")
                         for i, path in enumerate(PROFILE.paths)]
            owner._captured = {item.path: item for item in originals}
            owner.parents = {path: dict(device=9, inode=20 + i, mode=0o755)
                             for i, path in enumerate(PROFILE.directories)}
            owner._current = lambda path: owner._captured[path].before
            result = owner.apply_workflows_typed([(item, None) for item in originals])
            self.assertEqual((result.effect, result.journal, result.reason), ("unchanged", "not_created", "none"))

    def test_workflow_facade_rejects_replacement_missing_payload_extra_path_and_oversize(self):
        with no_io():
            for case in ("replace", "missing", "extra", "oversize", "reorder"):
                owner = workspace()
                originals = [tx.ObservedFile(path, None, None) for path in PROFILE.paths]
                if case == "replace":
                    originals[0] = tx.ObservedFile(PROFILE.paths[0], binding(b"old", 30), b"old")
                owner._captured = {item.path: item for item in originals}
                owner.parents = {path: None for path in PROFILE.directories}
                changes = [(item, b"generated") for item in originals]
                if case == "missing": changes[0] = (originals[0], None)
                if case == "extra": owner._captured["unrelated.yml"] = tx.ObservedFile("unrelated.yml", None, None)
                if case == "oversize": changes[0] = (originals[0], b"a" * (16 * 1024 + 1))
                if case == "reorder": changes.reverse()
                owner._current = Mock(side_effect=forbidden)
                with self.subTest(case=case), self.assertRaises(tx.InitOperationFailure):
                    owner.apply_workflows_typed(changes)
                owner._current.assert_not_called()
                self.assertEqual(owner._creation["state"], "NEW")

    def test_recovery_accepts_only_original_canonical_control_bytes_and_bindings(self):
        with no_io():
            for mutation in ("header", "plan", "same_bytes_new_inode", "extra_path"):
                owner, plan, values = journal_fixture()
                self.assertEqual(owner._load(400), plan)
                if mutation == "header":
                    data = tx._json({**{k: plan[k] for k in ("schemaVersion", "transactionId", "root")},
                                     "transactionId": "c" * 32})
                    values["header.json"] = (binding(data, 50), data)
                elif mutation in {"plan", "extra_path"}:
                    changed = copy.deepcopy(plan)
                    changed["files"][0]["path"] = (".github/workflows/other.yml" if mutation == "extra_path"
                                                       else PROFILE.paths[1])
                    data = tx._json(changed)
                    values["plan.json"] = (binding(data, 51), data)
                else:
                    old, data = values["plan.json"]
                    values["plan.json"] = ({**old, "inode": old["inode"] + 100}, data)
                with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                    owner._load(400)

    def test_marker_rename_keeps_original_identity_and_changed_marker_never_authorizes(self):
        with no_io():
            owner, plan, values = journal_fixture()
            self.assertIsNone(owner._terminal(400, plan))
            values["COMMITTED"] = values.pop("commit.pending")
            self.assertEqual(owner._terminal(400, plan), "COMMITTED")
            old, data = values["COMMITTED"]
            values["COMMITTED"] = ({**old, "inode": old["inode"] + 100}, data)
            with self.assertRaises(ValidationError):
                owner._terminal(400, plan)
            for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                for changed in (False, True):
                    with self.subTest(publication=state, changed_after_terminal_check=changed):
                        owner, plan, values = journal_fixture()
                        original_terminal = owner._terminal
                        def terminal(fd, candidate):
                            result = original_terminal(fd, candidate)
                            if changed:
                                old, data = values[pending]
                                values[pending] = ({**old, "inode": old["inode"] + 100}, data)
                            return result
                        owner._terminal = terminal
                        owner._binding = lambda _fd, name, **_kwargs: values[name][0]
                        owner._handoff = lambda: nullcontext()
                        owner._move = Mock()
                        if changed:
                            with self.assertRaises(ValidationError):
                                owner._publish_terminal(400, plan, state)
                            owner._move.assert_not_called()
                            self.assertFalse(owner._terminal_durable)
                        else:
                            owner._publish_terminal(400, plan, state)
                            owner._move.assert_called_once_with(400, pending, 400, state,
                                                                owner._workflow_controls[pending])
                            self.assertIs(owner._move.call_args.args[-1], owner._workflow_controls[pending])

    def test_incomplete_preparing_retains_without_pattern_cleanup_or_retry(self):
        with no_io():
            owner = workspace()
            owner._creation["state"] = "CREATED"
            owner.private_identity = dict(device=9, inode=99, mode=0o700)
            owner.recover = Mock(side_effect=forbidden)
            with self.assertRaises(ValidationError):
                owner._fixed_recovery()
            owner.recover.assert_not_called()
            self.assertEqual(owner.current_outcome().journal, "recovery_required")
            self.assertTrue(owner._recovery_claimed)
            owner._workflow_complete = True
            with self.assertRaises(ValidationError):
                owner._fixed_recovery()
            owner.recover.assert_not_called()

    def test_complete_preparing_rejects_unowned_numbered_slot_before_any_cleanup(self):
        with no_io():
            owner, _plan, values = journal_fixture()
            owner._list = lambda _fd: [*values, "new-17"]
            owner._locations = Mock(side_effect=forbidden)
            with self.assertRaises(ValidationError):
                owner._preparing_inventory(400)
            owner._locations.assert_not_called()

    def test_cleanup_rejects_replaced_proof_before_any_destructive_operation(self):
        with no_io():
            owner, _plan, values = journal_fixture()
            owner._private = lambda _state: nullcontext(400)
            owner._unlink = Mock(side_effect=forbidden)
            old, data = values["header.json"]
            values["header.json"] = ({**old, "inode": old["inode"] + 1}, data)
            with self.assertRaises(ValidationError):
                owner._cleanup()
            owner._unlink.assert_not_called()
            for state, unused in (("COMMITTED", "rollback.pending"), ("ROLLED_BACK", "commit.pending")):
                for when in ("unchanged", "capture", "marker_reread", "consuming_check", "missing_unused"):
                    with self.subTest(state=state, changed_at=when):
                        owner, _plan, values = journal_fixture()
                        values[state] = values.pop("commit.pending" if state == "COMMITTED" else "rollback.pending")
                        owner._private = lambda _state: nullcontext(400)
                        owner._list = lambda _fd: list(values)
                        owner._fsync = lambda _fd: None
                        changed_name = unused if when in {"consuming_check", "missing_unused"} else state
                        changed = False
                        def replace_original():
                            nonlocal changed
                            old, data = values[changed_name]
                            values[changed_name] = ({**old, "inode": old["inode"] + 100}, data)
                            changed = True
                        original_terminal = owner._terminal
                        def terminal(fd, candidate):
                            nonlocal changed
                            result = original_terminal(fd, candidate)
                            if when == "capture":
                                replace_original()
                            elif when == "missing_unused":
                                values.pop(unused)
                                changed = True
                            return result
                        owner._terminal = terminal
                        state_reads = 0
                        def read(_fd, name, _limit=tx.MAX_FILE_BYTES):
                            nonlocal state_reads
                            if name == state:
                                state_reads += 1
                                # Initial terminal, entry capture, later marker validation.
                                if when == "marker_reread" and state_reads == 3:
                                    replace_original()
                            return values.get(name)
                        owner._read = read
                        owner._binding = lambda _fd, name, **_kwargs: values[name][0] if name in values else None
                        def private_check(_fd, _state):
                            if when == "consuming_check" and not changed:
                                replace_original()
                        owner._private_check = private_check
                        def unlink(name, **_kwargs):
                            if name != tx.CLEANUP:
                                values.pop(name)
                        owner._unlink = Mock(side_effect=unlink)
                        with patch.object(tx, "_stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644)):
                            if when == "unchanged":
                                owner._cleanup()
                                self.assertTrue(owner._journal_clean)
                                self.assertFalse(values)
                            else:
                                with self.assertRaises(ValidationError):
                                    owner._cleanup()
                                self.assertTrue(changed)
                                if when == "missing_unused":
                                    self.assertNotIn(unused, values)
                                    self.assertTrue(values)
                                    owner._unlink.assert_not_called()
                                else:
                                    self.assertIn(changed_name, values)
                                self.assertFalse(owner._journal_clean)
                                self.assertNotIn(changed_name, [call.args[0] for call in owner._unlink.call_args_list])


if __name__ == "__main__":
    unittest.main()
