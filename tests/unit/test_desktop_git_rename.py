"""Actual fixed worker/FD/dispatch with explicitly INERT Git/C-A-W outcomes.

Run against the two accompanying Root hooks. No process/JDK/native/Store runs;
neither fixture snapshots nor modeled ledger returns confer native authority.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
import stat
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import _desktop_git_rename as codec
from mobile_release import git_repository_rename as rename
from mobile_release import git_rename_transaction as tx
from mobile_release import git_service as core
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
import test_desktop_git_local_protocol as old_wire
import test_git_repository_rename as fixture


def row(phase="prepare"):
    value = old_wire.fixture(phase=phase)
    value["action"] = {"kind": "branch-rename", "expectedRevision": "a" * 64,
                       "expectedReferenceRevision": "c" * 64, "name": "next"}
    value["rename"] = None
    if phase == "apply":
        parent = [1, 3, stat.S_IFDIR | 0o700, 1001, 1001, 1, 32, 123, 456]
        lock = [1, 4, stat.S_IFREG | 0o600, 1001, 1001, 1, 0, 123, 456]
        target = list(lock); target[1] += 1
        snapshot = {"identity": [1, 6, stat.S_IFREG | 0o644, 1001, 1001, 1, 41, 123, 456], "sha256": "2" * 64}
        value["rename"] = {"sourceRef": "refs/heads/main", "refLocks": {
            "sourceIdentity": lock, "targetIdentity": target, "parentBefore": list(parent), "parentLocked": list(parent)},
            "ref": snapshot, "branchLog": snapshot, "headLog": snapshot}
    return value


class RenameProtocolTests(unittest.TestCase):
    def test_required_closed_rename_projection_and_old_actions_unchanged(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(old_wire.frame(row(phase)))
            self.assertIs(type(request.action), codec.Action)
            self.assertEqual(request.rename_sources is None, phase == "prepare")
        for action in ("stage", "unstage", "commit"):
            original = old_wire.fixture(action)
            self.assertIsNone(wire.parse_request(old_wire.frame(original)).rename_sources)
            original["rename"] = None
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(original))
        for mutate in (lambda v: v.pop("rename"), lambda v: v["action"].update(force=False),
                       lambda v: v["action"].update(identity=None), lambda v: v["action"].update(name="../new")):
            value = row(); mutate(value)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))

    def test_same_parent_actual_locks_bounds_and_logging_pair_are_required(self):
        for mutate in (
            lambda v: v["rename"].update(sourceRef="refs/heads/topic/main"),
            lambda v: v["rename"].update(sourceRef="refs/heads/NEXT"),
            lambda v: v["rename"]["refLocks"].update(fd=12),
            lambda v: v["rename"]["refLocks"]["sourceIdentity"].__setitem__(5, 2),
            lambda v: v["rename"]["refLocks"]["targetIdentity"].__setitem__(1, 4),
            lambda v: v["rename"]["refLocks"]["parentLocked"].__setitem__(1, 90),
            lambda v: v["rename"].update(branchLog=None),
            lambda v: v["native"]["files"].update(index=None),
        ):
            value = row("apply"); mutate(value)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))
        value = row("apply"); value["rename"].update(branchLog=None, headLog=None)
        wire.parse_request(old_wire.frame(value))  # Actual retained review must still match.

    def test_phase_path_and_reason_changes_do_not_expand_other_actions(self):
        self.assertTrue(codec.Progress("ref-returned", (".git/mrk-git-fixture/index",)).valid("rename-ref-returned"))
        for path in ("/tmp/private", ".git/config", "../index", ".git/mrk-git-x/../index", ".git/mrk-git-x/HEAD"):
            self.assertFalse(codec.Progress("ref-returned", (path,)).valid("rename-ref-returned"))
        self.assertFalse(codec.Progress("ref-returned", ()).valid("rename-head-returned"))
        request = wire.parse_request(old_wire.frame(row()))
        old = wire.parse_request(old_wire.frame(old_wire.fixture()))
        for reason in rename.REASONS:
            wire.terminal(request, "refused", reason=reason, first_failure_ns=request.work_end_ns, cleanup_end_ns=request.hard_end_ns)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(old, "refused", reason=reason, first_failure_ns=old.work_end_ns, cleanup_end_ns=old.hard_end_ns)


class RenameWorkerTests(unittest.TestCase):
    setUp = fixture.RenameTests.setUp
    write = fixture.RenameTests.write
    repo = fixture.RenameTests.repo
    prepared = fixture.RenameTests.prepared
    close_inert_descriptors = fixture.RenameTests.close_inert_descriptors

    @contextmanager
    def operation(self, phase="apply"):
        _, review, _ = self.prepared()
        lock, native = None, None
        value = row(phase)
        value["action"] = codec.Action(review.plan._snapshot.public.revision, review.plan.reference_revision, "next").as_dict()
        if phase == "apply": value["reviewDigest"] = review.digest
        tool = self.base / "inert-tool"; tool.write_bytes(b"not an executable; synthetic DATA")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        if phase == "apply":
            lock = tx.RefLocks(self.root, "refs/heads/main", "refs/heads/next"); lock.acquire()
            parent = lambda stamp: (stamp[0], stamp[1], stamp[2], stamp[6], stamp[7],
                lock.parent.stat().st_nlink, stamp[3], stamp[4], stamp[5])
            native = codec.Sources("refs/heads/main", codec.RefLocks(*(fields.identity(p.stat()) for p in lock.paths),
                parent(lock.parent_before), parent(lock.parent_current)), snapshot(self.root / ".git/refs/heads/main"),
                snapshot(self.root / ".git/logs/refs/heads/main"), snapshot(self.root / ".git/logs/HEAD"))
        # Fake native projection/root/uid DATA only; ordinary native admission
        # rejects this non-provider tool. The parent still owns the real FDs.
        request = replace(wire.parse_request(old_wire.frame(value)), uid=os.getuid(), gid=os.getgid(), root=self.root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in
                              (self.root, self.root / ".git", self.root / ".git/objects")),
            tool=snapshot(tool), files=tuple(snapshot(self.root / ".git" / n) for n in ("HEAD", "config", "index")), rename_sources=native)
        engine = _Engine(time.monotonic()); source, guard = engine.input, engine.guard
        engine.request = source.initial = request; source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)
        operation = engine.operation = GitLocalOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        def fake_return(argv, **options):
            command = object(); guard.lifetime_ledger._bind_command(command)
            result = self.fake(argv, **options)
            guard.lifetime_ledger._finish_command(command, dispatched=True, contained=True, cleanup_complete=True)
            return result
        try:
            with patch.object(guard, "check", return_value=None), \
                    patch("mobile_release._command_process.run_command", side_effect=fake_return) as calls:
                yield operation, calls
        finally:
            if operation.repository is not None: self.repositories.append(operation.repository)
            operation.cleanup(); source.close()
            if lock is not None and not lock.closed:
                transaction = None if operation.repository is None else operation.repository._transaction
                moved = next((v for v in transaction.returns if v.step == "ref"), None) if transaction else None
                if moved: lock.moved(moved)
                self.assertTrue(lock.close())  # Exact fixture-owned locks, not a native finality receipt.

    @staticmethod
    def ack(operation):
        return (b"MRK-GIT-LOCAL-ACK/1 " + operation.request.digest.encode() + b" "
                + operation.source.candidate.digest.encode() + b" 5\n")

    def test_actual_prepare_only_review_without_candidate_or_diff(self):
        with self.operation("prepare") as (op, calls):
            op.admit(); op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.review), rename.RenameReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result)
            self.assertFalse(op.source.candidate_claimed); self.assertEqual(self.fake.rename_calls, 0)
            encoded = wire.terminal(op.request, "ok", reason=None, review=op.review,
                first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(encoded)["result"], {"review": op.review.as_dict()})
            self.assertEqual(calls.call_count, op.calls)

    def test_actual_apply_ack_retains_moved_unlinked_and_unchanged_original_fds(self):
        with self.operation() as (op, calls):
            op.admit()
            original = {name: (slot, slot.fd) for name, slot in op.rename_state.sources.items()}
            with patch.object(op.engine, "write") as output, patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(op.result.state, "succeeded"); self.assertEqual(op.publication(), "rename-config-returned")
            output.assert_called_once(); self.assertEqual(self.fake.rename_calls, 1)
            self.assertEqual(op.rename_state.progress, codec.Progress("config-returned", ()))
            for name, (slot, fd) in original.items():
                self.assertIs(op.rename_state.sources[name], slot); self.assertEqual(slot.fd, fd)
                expected_links = 1 if name in (".git/index", ".git/refs/heads/main") else 0
                self.assertEqual(os.fstat(fd).st_nlink, expected_links, name)
            moved = op.rename_state.successors["ref"]
            self.assertEqual(moved.identity[1], os.fstat(original[".git/refs/heads/main"][1]).st_ino)
            self.assertEqual(calls.call_count, op.calls)
            encoded = wire.terminal(op.request, "ok", reason=None, result=op.result, publication=op.publication(),
                progress=op.rename_state.progress, first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(encoded)["result"]["effectPhase"], "config-returned")
            op.cleanup(); self.assertTrue(op.closed)
            self.assertTrue(all(slot.closed for slot, _ in original.values()))
            self.assertTrue((self.root / ".git/refs/heads/main.lock").exists())
            self.assertTrue((self.root / ".git/refs/heads/next.lock").exists())

    def test_retained_native_snapshot_mismatch_never_makes_candidates(self):
        with self.operation() as (op, _):
            op.admit()
            op.request = replace(op.request, rename_sources=replace(op.request.rename_sources, head_log=None))
            with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.source.candidate_claimed); self.assertEqual(self.fake.rename_calls, 0)

    def test_lost_ack_keeps_sources_no_original_publication_no_replay(self):
        with self.operation() as (op, _):
            op.admit()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=KeyboardInterrupt("inert ACK loss")):
                with self.assertRaises(KeyboardInterrupt): op.run()
            self.assertTrue(op.source.candidate_claimed); self.assertFalse(op.source.candidate_returned)
            self.assertEqual(op.repository._transaction.returns, [])
            self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)

    def test_unjoined_inert_command_never_grants_publication_or_successor(self):
        with self.operation() as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake):
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.returned); self.assertFalse(op.rename_state.successors)
            self.assertEqual(self.fake.rename_calls, 0)

    def test_known_partial_ref_prefix_is_recovery_not_success_and_index_untouched(self):
        with self.operation() as (op, _):
            op.admit(); publish = tx.RenameTransaction.publish
            def stop_at_head(transaction, step):
                if step == "head-log": raise core.GitError("authorization")
                return publish(transaction, step)
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)), \
                    patch.object(tx.RenameTransaction, "publish", stop_at_head):
                op.run()
            self.assertTrue(op.returned); self.assertEqual(op.result.state, "recovery-required")
            self.assertEqual(op.publication(), "rename-ref-returned")
            self.assertTrue(op.rename_state.progress.retained)
            self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
            self.assertEqual((self.root / ".git/index").read_bytes(), fixture.fixture.OLD_INDEX)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(op.request, "ok", reason=None, result=replace(op.result, state="succeeded", reason=None),
                    publication=op.publication(), progress=op.rename_state.progress, first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
