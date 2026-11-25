"""Closed switch worker/codec with real private FDs and inert Git returns.

Run against the accompanying exact two Root hooks/full-source projection.
Popen is forbidden; fake ledger facts below test original call routing only,
NOT real C/A/W/native SourceBook/Store admission, ACK or finality.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import _desktop_git_switch as codec
from mobile_release import git_repository_switch as core_switch
from mobile_release import git_service as core
from mobile_release import git_switch_transaction as tx
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
import test_desktop_git_local_protocol as old_wire
import test_git_repository_switch as fixture


def row(*, phase="prepare"):
    value = old_wire.fixture(phase=phase)
    value["action"] = {"kind": "branch-switch", "expectedRevision": "a" * 64,
                       "expectedReferenceRevision": "c" * 64, "name": "next"}
    value["switch"] = None
    if phase == "apply":
        parent = [1, 3, stat.S_IFDIR | 0o700, 1001, 1001, 1, 32, 123, 456]
        lock = [1, 4, stat.S_IFREG | 0o600, 1001, 1001, 1, 0, 123, 456]
        file = {"identity": [1, 5, stat.S_IFREG | 0o644, 1001, 1001, 1, 12, 123, 456], "sha256": "2" * 64}
        value["switch"] = {"targetLock": {"identity": lock, "parentBefore": list(parent), "parentLocked": list(parent)},
                           "headLog": file, "files": [{"path": "a.txt", "snapshot": file}]}
    return value


class SwitchProtocolTests(unittest.TestCase):
    def setUp(self):
        denied = patch("subprocess.Popen", side_effect=AssertionError("No process in codec tests"))
        denied.start(); self.addCleanup(denied.stop)

    def test_switch_only_exact_tag_and_extra_sealed_sources_preserve_old_shapes(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(old_wire.frame(row(phase=phase)))
            self.assertIs(type(request.action), codec.Action)
            self.assertEqual(request.action.as_dict(), row()["action"])
            self.assertEqual(request.switch_sources is None, phase == "prepare")
        for name in ("stage", "unstage", "commit"):
            original = old_wire.fixture(name)
            self.assertIsNone(wire.parse_request(old_wire.frame(original)).switch_sources)
            original["switch"] = None
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(original))
        value = row(); del value["switch"]
        with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))
        for field, value in (("paths", []), ("force", False), ("discard", False), ("identity", None)):
            malformed = row(); malformed["action"][field] = value
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(malformed))

    def test_closed_native_target_lock_and_file_bounds_not_a_caller_path_grant(self):
        for field, value in (("files", []), ("headLog", None)):
            data = row(phase="apply"); data["switch"][field] = value
            wire.parse_request(old_wire.frame(data))  # Fresh retained-review match is still mandatory.
        for mutate in (
            lambda v: v["switch"].update(target="refs/heads/arbitrary"),
            lambda v: v["switch"]["targetLock"].update(fd=42),
            lambda v: v["switch"]["targetLock"]["identity"].__setitem__(5, 2),
            lambda v: v["switch"]["targetLock"]["identity"].__setitem__(2, stat.S_IFREG | 0o644),
            lambda v: v["switch"]["targetLock"]["parentLocked"].__setitem__(1, 99),
            lambda v: v["switch"]["files"][0].update(path=".git/config"),
            lambda v: v["switch"]["files"].append(v["switch"]["files"][0]),
            lambda v: v["native"]["files"].update(index=None),
        ):
            data = row(phase="apply"); mutate(data)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(data))
        data = row(); data["switch"] = row(phase="apply")["switch"]
        with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(data))

    def test_fixed_progress_refuses_raw_paths_wrong_stage_and_cross_action(self):
        for path in ("/tmp/private", "../a", ".git/mrk-git-fixture/secret", ".git/mrk-git-fixture/../HEAD"):
            self.assertFalse(codec.Progress("worktree-returned", (path,)).valid("switch-checkout-returned"))
        progress = codec.Progress("worktree-returned", (".git/mrk-git-fixture/HEAD",))
        self.assertTrue(progress.valid("switch-checkout-returned"))
        self.assertFalse(progress.valid("switch-index-returned"))
        original = wire.parse_request(old_wire.frame(old_wire.fixture()))
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(original, "refused", reason="authorization", progress=progress,
                          first_failure_ns=original.work_end_ns, cleanup_end_ns=original.hard_end_ns)

    def test_fixed_switch_reasons_do_not_expand_old_actions(self):
        request = wire.parse_request(old_wire.frame(row()))
        old = wire.parse_request(old_wire.frame(old_wire.fixture()))
        for reason in core_switch._REASONS:
            body = wire.terminal(request, "refused", reason=reason,
                first_failure_ns=request.work_end_ns, cleanup_end_ns=request.hard_end_ns)
            self.assertEqual(json.loads(body)["reason"], reason)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(old, "refused", reason=reason,
                    first_failure_ns=old.work_end_ns, cleanup_end_ns=old.hard_end_ns)


class SwitchWorkerTests(unittest.TestCase):
    # Borrow helpers only. Do NOT collect/rerun the older core suites.
    setUp = fixture.SwitchTests.setUp
    write = fixture.SwitchTests.write
    repo = fixture.SwitchTests.repo
    prepared = fixture.SwitchTests.prepared
    close_inert_descriptors = fixture.SwitchTests.close_inert_descriptors

    @contextmanager
    def operation(self, *, phase="apply"):
        _, review, _ = self.prepared()
        lock = None
        value = row(phase=phase)
        value["action"] = codec.Action(review.plan._snapshot.public.revision, review.plan.reference_revision, "next").as_dict()
        if phase == "apply": value["reviewDigest"] = review.digest
        tool = self.base / "inert-tool"; tool.write_bytes(b"not executable; fixture DATA")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        native = None
        if phase == "apply":
            # Actual disposable lock only; stands in for NO native authority.
            lock = tx.TargetLock(self.root, "refs/heads/next"); lock.acquire()
            parent = lambda stamp: (stamp[0], stamp[1], stamp[2], stamp[6], stamp[7],
                                    lock.path.parent.stat().st_nlink, stamp[3], stamp[4], stamp[5])
            native = codec.Sources(codec.TargetLock(fields.identity(lock.path.stat()), parent(lock.parent_before),
                                  parent(lock.parent_locked)), snapshot(self.root / ".git/logs/HEAD") if (self.root / ".git/logs/HEAD").exists() else None,
                                  tuple(snapshot(self.root / name) for name in review.plan.changed))
        # Explicit fake DATA for UID/root/provider projections only. Production
        # rejects UID0/non-provider; no fixture becomes a native capability.
        request = replace(wire.parse_request(old_wire.frame(value)), uid=os.getuid(), gid=os.getgid(), root=self.root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in
                              (self.root, self.root / ".git", self.root / ".git/objects")),
            tool=snapshot(tool), files=tuple(snapshot(self.root / ".git" / name) for name in ("HEAD", "config", "index")),
            switch_sources=native)
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
            # Only this inert fixture owns the target lock. Worker must never
            # close it; native production closes its same original SourceBook.
            if lock is not None and not lock.closed:
                self.assertTrue(lock.close())

    @staticmethod
    def ack(operation):
        return (b"MRK-GIT-LOCAL-ACK/1 " + operation.request.digest.encode() + b" "
                + operation.source.candidate.digest.encode() + b" 5\n")

    def test_actual_prepare_has_closed_review_no_fake_diff_or_effect_sources(self):
        with self.operation(phase="prepare") as (op, calls):
            op.admit(); op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.review), core_switch.SwitchReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result); self.assertFalse(op.source.candidate_claimed)
            self.assertIsNone(op.request.switch_sources); self.assertEqual(self.fake.checkout_count, 0)
            body = wire.terminal(op.request, "ok", reason=None, review=op.review,
                                 first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(body)["result"], {"review": op.review.as_dict()})
            self.assertEqual(calls.call_count, op.calls)

    def test_actual_apply_one_ack_four_private_commands_and_all_old_fds_retained(self):
        with self.operation() as (op, calls):
            op.admit()
            old = {name: (source, source.fd) for name, source in op.switch_state.sources.items()}
            with patch.object(op.engine, "write") as output, patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(op.result.state, "succeeded"); self.assertEqual(op.publication(), "switch-index-returned")
            self.assertEqual(op.switch_state.progress, codec.Progress("index-returned", ()))
            output.assert_called_once(); self.assertEqual(self.fake.checkout_count, 1)
            executed = [call[0][0] for call in self.fake.calls
                        if call[1] == op.repository._transaction.exec_view.root]
            self.assertEqual(executed, ["read-tree", "ls-files", "symbolic-ref", "switch"])
            for name, (source, fd) in old.items():
                self.assertIs(op.switch_state.sources[name], source); self.assertEqual(source.fd, fd)
                self.assertEqual(os.fstat(fd).st_nlink, 0)
                self.assertNotEqual(os.fstat(fd).st_ino, op.switch_state.successors[name].identity[1])
            self.assertEqual(calls.call_count, op.calls)
            self.assertTrue((self.root / ".git/refs/heads/next.lock").exists())
            encoded = wire.terminal(op.request, "ok", reason=None, result=op.result, publication=op.publication(),
                progress=op.switch_state.progress, first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(encoded)["result"]["effectPhase"], "index-returned")
            op.cleanup(); self.assertTrue(op.closed)
            for source, fd in old.values():
                self.assertTrue(source.closed)
                with self.assertRaises(OSError): os.fstat(fd)
            self.assertTrue((self.root / ".git/refs/heads/next.lock").exists())

    def test_native_retained_files_must_match_fresh_review_before_private_write(self):
        with self.operation() as (op, _):
            op.admit()
            op.request = replace(op.request, switch_sources=replace(op.request.switch_sources, files=()))
            with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(self.fake.checkout_count, 0)
            self.assertFalse(any(call[0][0] in ("read-tree", "switch") for call in self.fake.calls))

    def test_lost_ack_never_checkouts_or_retries_and_keeps_original_lock(self):
        with self.operation() as (op, _):
            op.admit(); lost = KeyboardInterrupt("inert lost ACK")
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lost):
                with self.assertRaises(KeyboardInterrupt) as caught: op.run()
            self.assertIs(caught.exception, lost)
            self.assertTrue(op.source.candidate_claimed); self.assertFalse(op.source.candidate_returned)
            self.assertEqual(self.fake.checkout_count, 0)
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)
            self.assertTrue((self.root / ".git/refs/heads/next.lock").exists())

    def test_unjoined_fake_command_cannot_publish_receipt_or_admit_successors(self):
        with self.operation() as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake):
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.returned); self.assertFalse(op.switch_state.successors)
            self.assertEqual(self.fake.checkout_count, 0)

    def test_known_partial_checkout_exposes_fixed_phase_and_retained_candidates_not_success(self):
        with self.operation() as (op, _):
            op.admit()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)), \
                    patch.object(tx.SwitchTransaction, "publish_metadata", side_effect=core.GitError("authorization")):
                op.run()
            self.assertTrue(op.returned); self.assertEqual(op.result.state, "recovery-required")
            self.assertEqual(op.publication(), "switch-checkout-returned")
            self.assertEqual(op.switch_state.progress.phase, "worktree-returned")
            self.assertTrue(op.switch_state.progress.retained)
            self.assertLessEqual(len(op.switch_state.progress.retained), 5)
            body = wire.terminal(op.request, "ok", reason=None, result=op.result, publication=op.publication(),
                progress=op.switch_state.progress, first_failure_ns=op.request.work_end_ns, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(body)["result"]["state"], "recovery-required")
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(op.request, "ok", reason=None, result=replace(op.result, state="succeeded", reason=None),
                    publication=op.publication(), progress=op.switch_state.progress,
                    first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)

    def test_candidate_string_types_and_exact_hash_binding_are_closed(self):
        with self.operation() as (op, _):
            op.admit()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            intent = op.result.intent
            for field, value in (("expected_ref", None), ("target_oid", 7), ("candidate_index", "not-a-digest"),
                                 ("candidate_head", "e" * 64), ("footprint", "d" * 64)):
                with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                    wire.candidate(op.request, op.review, replace(intent, **{field: value}))

    def test_matching_replaced_name_without_actual_checkout_receipt_is_refused(self):
        with self.operation() as (op, _):
            op.admit()
            fixture.FakeSwitch.atomic(self.root / "a.txt", self.fake.after_files["a.txt"])
            with self.assertRaises(fields.ProtocolError): op.source_post(hash_files=True)
            self.assertFalse(op.switch_state.successors)
            self.assertEqual(self.fake.checkout_count, 0)

    def test_second_cleanup_cannot_reclose_old_or_successor_descriptors(self):
        with self.operation() as (op, _):
            op.admit()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            op.cleanup(); self.assertTrue(op.closed)
            with patch("os.close", side_effect=AssertionError("No repeated close")):
                op.cleanup()

    def test_absent_original_log_admits_only_actual_metadata_successor(self):
        (self.root / ".git/logs/HEAD").unlink()
        with self.operation() as (op, _):
            op.admit()
            self.assertNotIn(".git/logs/HEAD", op.switch_state.sources)
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertEqual(op.result.state, "succeeded")
            self.assertIn(".git/logs/HEAD", op.switch_state.successors)
            self.assertEqual(op.switch_state.accepted[".git/logs/HEAD"][0].kind, "absent")

    def test_same_tree_still_requires_ack_and_head_log_index_receipts(self):
        self.fake.after_files = dict(self.fake.before_files); self.fake.refresh_entries()
        with self.operation() as (op, _):
            op.admit()
            self.assertEqual(op.request.switch_sources.files, ())
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertEqual(op.result.state, "succeeded"); self.assertEqual(self.fake.checkout_count, 1)
            self.assertEqual(set(op.switch_state.successors), {".git/HEAD", ".git/logs/HEAD", ".git/index"})
            self.assertEqual(op.publication(), "switch-index-returned")

    def test_stop_after_ack_does_not_checkout_or_forge_publication(self):
        with self.operation() as (op, _):
            op.admit()
            original = op.check_current
            def current(*args):
                if op.source.candidate_returned:
                    raise core.GitError("authorization")
                return original(*args)
            with patch.object(op, "check_current", side_effect=current), patch.object(op.engine, "write"), \
                    patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertEqual(self.fake.checkout_count, 0)
            self.assertEqual(op.result.state, "recovery-required")
            self.assertEqual(op.publication(), "not-reported")
            self.assertFalse(op.switch_state.successors)
