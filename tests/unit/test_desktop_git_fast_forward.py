"""Same worker/real disposable FD custody, inert Git/C-A-W returns only.

No subprocess/native grant/Store or finality is qualified by these tests.
Run against the exact accompanying parent hooks, not a substitute worker.
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
from mobile_release import git_fast_forward_worker as codec
from mobile_release import git_fast_forward_transaction as tx
from mobile_release import git_repository_fast_forward as ff
from mobile_release import git_service as core
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
import test_desktop_git_local_protocol as old_wire
import test_git_repository_fast_forward as fixture


def row(phase="prepare"):
    value = old_wire.fixture(phase=phase)
    value["action"] = {"kind": "fast-forward", "expectedRevision": "a" * 64,
        "expectedReferenceRevision": "c" * 64, "targetRef": fixture.REF, "targetOid": fixture.TARGET}
    value["fastForward"] = None
    if phase == "apply":
        parent = [1, 3, stat.S_IFDIR | 0o700, 1001, 1001, 1, 32, 123, 456]
        lock = [1, 4, stat.S_IFREG | 0o600, 1001, 1001, 1, 0, 123, 456]
        file = {"identity": [1, 5, stat.S_IFREG | 0o644, 1001, 1001, 1, 12, 123, 456], "sha256": "2" * 64}
        value["fastForward"] = {"targetLock": {"identity": lock, "parentBefore": list(parent), "parentLocked": list(parent)},
            "headLog": file, "branchLog": file, "currentRef": {"path": "refs/heads/main", "snapshot": file},
            "files": [{"path": "a.txt", "snapshot": file}]}
    return value


class FastForwardProtocolTests(unittest.TestCase):
    def setUp(self):
        denied = patch("subprocess.Popen", side_effect=AssertionError("No process in codec tests"))
        denied.start(); self.addCleanup(denied.stop)

    def test_closed_kind_cached_target_and_sealed_sources_do_not_widen_old_requests(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(old_wire.frame(row(phase)))
            self.assertIs(type(request.action), codec.Action)
            self.assertEqual(request.action.as_dict(), row()["action"])
            self.assertEqual(request.fast_forward_sources is None, phase == "prepare")
        for name in ("stage", "unstage", "commit"):
            original = old_wire.fixture(name)
            self.assertIsNone(wire.parse_request(old_wire.frame(original)).fast_forward_sources)
            original["fastForward"] = None
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(original))
        for field, value in (("targetRef", "refs/heads/next"), ("targetRef", "refs/remotes/origin/HEAD"),
                             ("targetOid", None), ("force", False), ("fetch", True), ("identity", None)):
            invalid = row(); invalid["action"][field] = value
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(invalid))

    def test_only_actual_native_comparison_roster_is_accepted(self):
        for mutate in (
            lambda v: v["fastForward"]["targetLock"].update(fd=42),
            lambda v: v["fastForward"]["targetLock"]["identity"].__setitem__(5, 2),
            lambda v: v["fastForward"]["targetLock"]["parentLocked"].__setitem__(1, 99),
            lambda v: v["fastForward"]["currentRef"].update(path=fixture.REF),
            lambda v: v["fastForward"]["files"][0].update(path=".git/config"),
            lambda v: v["fastForward"]["files"].append(v["fastForward"]["files"][0]),
            lambda v: v["native"]["files"].update(index=None),
        ):
            value = row("apply"); mutate(value)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))
        invalid = row(); invalid["fastForward"] = row("apply")["fastForward"]
        with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(invalid))

    def test_recovery_is_closed_data_not_success_or_a_cross_family_receipt(self):
        for path in ("/tmp/private", "../a", ".git/mrk-git-fixture/HEAD", ".git/mrk-git-fixture/secret"):
            self.assertFalse(codec.Progress("worktree-returned", (path,)).valid("ff-worktree-returned"))
        progress = codec.Progress("index-returned", (".git/mrk-git-fixture/index",))
        self.assertTrue(progress.valid("ff-index-returned"))
        self.assertFalse(progress.valid("ff-ref-returned"))
        old = wire.parse_request(old_wire.frame(old_wire.fixture()))
        request = wire.parse_request(old_wire.frame(row()))
        for reason in ff.REASONS:
            self.assertEqual(json.loads(wire.terminal(request, "refused", reason=reason,
                first_failure_ns=request.work_end_ns, cleanup_end_ns=request.hard_end_ns))["reason"], reason)
            with self.assertRaises(wire.ProtocolError): wire.terminal(old, "refused", reason=reason,
                first_failure_ns=old.work_end_ns, cleanup_end_ns=old.hard_end_ns)


class FastForwardWorkerTests(unittest.TestCase):
    setUp = fixture.FastForwardTests.setUp
    write = fixture.FastForwardTests.write
    repo = fixture.FastForwardTests.repo
    prepared = fixture.FastForwardTests.prepared
    close_inert_descriptors = fixture.FastForwardTests.close_inert_descriptors

    @contextmanager
    def operation(self, phase="apply"):
        _, review, _ = self.prepared()
        lock, native = None, None
        value = row(phase)
        value["action"] = codec.Action(review.plan._snapshot.public.revision, review.plan.reference_revision,
                                       fixture.REF, fixture.TARGET).as_dict()
        if phase == "apply": value["reviewDigest"] = review.digest
        tool = self.base / "inert-tool"; tool.write_bytes(b"not executable; fixture DATA")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        if phase == "apply":
            # This fixture owns a real private lock, never native authority.
            lock = tx.TrackingLock(self.root, fixture.REF); lock.acquire()
            parent = lambda stamp: (stamp[0], stamp[1], stamp[2], stamp[6], stamp[7],
                                    lock.path.parent.stat().st_nlink, stamp[3], stamp[4], stamp[5])
            native = codec.Sources(codec.TargetLock(fields.identity(lock.path.stat()), parent(lock.parent_before),
                parent(lock.parent_locked)), snapshot(self.root / ".git/logs/HEAD"),
                snapshot(self.root / ".git/logs/refs/heads/main"), snapshot(self.root / ".git/refs/heads/main"),
                tuple(snapshot(self.root / name) for name in review.plan.changed))
        request = replace(wire.parse_request(old_wire.frame(value)), uid=os.getuid(), gid=os.getgid(), root=self.root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in
                              (self.root, self.root / ".git", self.root / ".git/objects")),
            tool=snapshot(tool), files=tuple(snapshot(self.root / ".git" / name) for name in ("HEAD", "config", "index")),
            fast_forward_sources=native)
        engine = _Engine(time.monotonic()); source, guard = engine.input, engine.guard
        engine.request = source.initial = request; source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)
        operation = engine.operation = GitLocalOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        def fake_return(argv, **options):
            record = object(); guard.lifetime_ledger._bind_command(record)
            result = self.fake(argv, **options)
            guard.lifetime_ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)
            return result
        try:
            with patch.object(guard, "check", return_value=None), \
                    patch("mobile_release._command_process.run_command", side_effect=fake_return) as calls:
                yield operation, calls
        finally:
            if operation.repository is not None: self.repositories.append(operation.repository)
            operation.cleanup(); source.close()
            if lock is not None and not lock.closed: self.assertTrue(lock.close())

    @staticmethod
    def ack(operation):
        return (b"MRK-GIT-LOCAL-ACK/1 " + operation.request.digest.encode() + b" "
                + operation.source.candidate.digest.encode() + b" 5\n")

    def test_prepare_uses_same_worker_and_returns_only_a_fresh_cached_tip_review(self):
        with self.operation("prepare") as (op, calls):
            op.admit(); op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.review), ff.FastForwardReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result); self.assertFalse(op.source.candidate_claimed)
            self.assertEqual((self.fake.checkout_count, self.fake.cas_count), (0, 0))
            encoded = wire.terminal(op.request, "ok", reason=None, review=op.review,
                first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(encoded)["result"], {"review": op.review.as_dict()})
            self.assertEqual(calls.call_count, op.calls)

    def test_actual_apply_keeps_old_log_fds_and_unchanged_head_with_separate_successors(self):
        with self.operation() as (op, calls):
            op.admit(); old = {name: (source, source.fd) for name, source in op.fast_forward_state.sources.items()}
            with patch.object(op.engine, "write") as out, patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertEqual((op.result.state, op.result.settlement), ("succeeded", "settled"))
            self.assertEqual(op.publication(), "ff-ref-returned"); self.assertTrue(op.source.candidate_returned)
            self.assertEqual((self.fake.checkout_count, self.fake.cas_count), (1, 1)); out.assert_called_once()
            for name, (source, fd) in old.items():
                self.assertIs(op.fast_forward_state.sources[name], source); self.assertEqual(source.fd, fd)
                successor = op.fast_forward_state.successors[name]
                if name.startswith(".git/logs/"):
                    self.assertEqual(os.fstat(fd).st_ino, successor.identity[1])  # Original appended by actual-CAS fixture.
                else:
                    self.assertEqual(os.fstat(fd).st_nlink, 0)
                    self.assertNotEqual(os.fstat(fd).st_ino, successor.identity[1])
            self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
            self.assertEqual(calls.call_count, op.calls)
            body = wire.terminal(op.request, "ok", reason=None, result=op.result, publication=op.publication(),
                progress=op.fast_forward_state.progress, first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(body)["result"]["effectPhase"], "ref-returned")
            op.cleanup(); self.assertTrue(op.closed)
            self.assertTrue((self.root / (".git/" + fixture.REF + ".lock")).exists())
            for source, fd in old.values():
                self.assertTrue(source.closed)
                with self.assertRaises(OSError): os.fstat(fd)

    def test_current_review_sources_cannot_be_replaced_by_parsed_equal_count(self):
        with self.operation() as (op, _):
            op.admit(); op.request = replace(op.request, fast_forward_sources=replace(op.request.fast_forward_sources, files=()))
            with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.source.candidate_claimed); self.assertEqual(self.fake.checkout_count, 0)

    def test_lost_ack_retains_candidate_and_cannot_reenter_or_checkout(self):
        with self.operation() as (op, _):
            op.admit(); lost = KeyboardInterrupt("inert lost ACK")
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lost):
                with self.assertRaises(KeyboardInterrupt) as caught: op.run()
            self.assertIs(caught.exception, lost); self.assertTrue(op.source.candidate_claimed)
            self.assertFalse(op.source.candidate_returned); self.assertEqual((self.fake.checkout_count, self.fake.cas_count), (0, 0))
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)

    def test_unreturned_command_never_mints_checkout_or_source_successors(self):
        with self.operation() as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake):
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.returned); self.assertFalse(op.fast_forward_state.successors)
            self.assertEqual((self.fake.checkout_count, self.fake.cas_count), (0, 0))
