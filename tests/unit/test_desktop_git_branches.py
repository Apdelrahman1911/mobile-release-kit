"""Branch codecs and actual fixed-worker paths with inert private Git replies.

Run against the exact four Root Python hooks (or their full-source projection).
Popen is forbidden. Ledger writes below are explicitly fake DATA, not native
source admission, C/A/W containment, consent, durable ACK or finality evidence.
No inherited fixture test collection or user repository is run.
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

from mobile_release import _desktop_git_branches as branch
from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as read_wire
from mobile_release import git_repository_branches as core_branch
from mobile_release import git_service as core
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
from mobile_release.desktop_git_read import GitReadOperation, _Engine as ReadEngine
import test_desktop_git_local_protocol as old_wire
import test_git_repository_branches as fixture


def row(*, phase="prepare"):
    value = old_wire.fixture(phase=phase)
    value["action"] = {"kind": "branch-create", "expectedRevision": "a" * 64,
                       "expectedReferenceRevision": "c" * 64, "name": "next"}
    return value


def compared(*, phase="apply"):
    value = row(phase=phase)
    selected = wire.action(value["action"])
    observed = core.Observation(selected.expected_revision, "1" * 40, "refs/heads/main", (), (), ())
    index = core._Stamp("file", (1, 3, stat.S_IFREG | 0o600, 12, 123, 456), "2" * 64)
    snapshot = core._Snapshot(observed, {}, index, b"inert index", {}, {}, {}, {})
    logging = core_branch._LogPolicy(True, Path("/fixture/project/.git/logs/refs/heads/next"), (),
                                    core.CommitIdentity("Fixture", "fixture@example.invalid"))
    plan = core_branch.BranchCreatePlan(selected.name, selected.expected_reference_revision, object(), snapshot, logging)
    review = core_branch.BranchReview(plan, core_branch._review_digest(plan))
    if phase == "apply":
        value["reviewDigest"] = review.digest
    request = wire.parse_request(old_wire.frame(value))
    intent = core_branch.BranchIntent(selected.expected_revision, selected.expected_reference_revision,
        observed.branch, observed.head, index.digest, plan.target, observed.head)
    return request, review, intent


class BranchProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("No actual process in branch DATA tests"))
        guard.start(); self.addCleanup(guard.stop)

    def test_exact_new_tag_preserves_each_old_required_shape(self):
        request = wire.parse_request(old_wire.frame(row()))
        self.assertIs(type(request.action), branch.Action)
        self.assertEqual(request.action.as_dict(), row()["action"])
        for kind in ("stage", "unstage", "commit"):
            original = old_wire.fixture(kind)
            self.assertIs(type(wire.parse_request(old_wire.frame(original)).action), wire.Action)
            for field in ("paths", "message", "identity"):
                malformed = old_wire.fixture(kind); del malformed["action"][field]
                with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(malformed))
        for field, value in (("paths", []), ("message", None), ("identity", None), ("force", False),
                             ("expectedTargetAbsent", True)):
            malformed = row(); malformed["action"][field] = value
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(malformed))
        for field, value in (("name", "-d"), ("name", "main.lock"), ("expectedReferenceRevision", None)):
            malformed = row(); malformed["action"][field] = value
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(malformed))

    def test_review_and_candidate_bind_name_ref_inventory_and_head(self):
        request, review, intent = compared()
        sent = wire.candidate(request, review, intent)
        self.assertIs(sent.request, request); self.assertIs(sent.intent, intent)
        self.assertEqual(json.loads(sent.raw)["intent"], intent.as_dict())
        self.assertNotIn(b"fixture@example", sent.raw)
        self.assertNotIn("diff", review.as_dict())
        for action in (replace(request.action, name="other"),
                       replace(request.action, expected_reference_revision="d" * 64)):
            with self.assertRaises(wire.ProtocolError): wire.matches_review(replace(request, action=action), review)
        for changed in (replace(intent, target_ref="refs/heads/other"),
                        replace(intent, expected_reference_revision="d" * 64),
                        replace(intent, candidate_ref_oid="4" * 40), replace(intent, expected_head=None)):
            with self.assertRaises(wire.ProtocolError): wire.candidate(request, review, changed)
        ack = b"MRK-GIT-LOCAL-ACK/1 " + request.digest.encode() + b" " + sent.digest.encode() + b" 5\n"
        self.assertEqual(wire.acknowledged(request, sent, ack), 5)
        with self.assertRaises(wire.ProtocolError): wire.acknowledged(replace(request), sent, ack)

    def test_prepared_branch_has_explicit_ref_review_not_empty_diff(self):
        request, review, _ = compared(phase="prepare")
        encoded = wire.terminal(request, "ok", reason=None, review=review,
            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        self.assertEqual(json.loads(encoded)["result"], {"review": review.as_dict()})
        fabricated = core.Diff(request.action.expected_revision, False, (), "", None)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, review=review, diff=fabricated,
                first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)

    def test_positive_branch_terminal_is_distinct_and_never_candidate_readback_authority(self):
        request, review, intent = compared()
        result = core.MutationResult(request.id, request.action.kind, "succeeded", "settled", None,
                                     review.plan._snapshot.public, intent)
        def encode(**changes):
            return wire.terminal(request, "ok", reason=None, result=changes.pop("result", result),
                publication=changes.pop("publication", branch.PUBLICATION), first_failure_ns=None,
                cleanup_end_ns=request.hard_end_ns, **changes)
        self.assertEqual(json.loads(encode())["publication"], "branch-ref-returned")
        for publication in ("not-reported", "ref-returned", "index-returned"):
            with self.assertRaises(wire.ProtocolError): encode(publication=publication)
        for changed in (replace(result, intent=None), replace(result, settlement="unknown"),
                        replace(result, intent=replace(intent, candidate_ref_oid="4" * 40)),
                        replace(result, observation=replace(result.observation, head="4" * 40))):
            with self.assertRaises(wire.ProtocolError): encode(result=changed)

    def test_branch_reasons_are_fixed_and_do_not_expand_other_actions(self):
        request, _, _ = compared(phase="prepare")
        for reason in core_branch.BRANCH_REASONS:
            raw = wire.terminal(request, "refused", reason=reason, first_failure_ns=request.work_end_ns,
                                cleanup_end_ns=request.hard_end_ns)
            self.assertEqual(json.loads(raw)["reason"], reason)
            old_request = wire.parse_request(old_wire.frame(old_wire.fixture()))
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(old_request, "refused", reason=reason, first_failure_ns=request.work_end_ns,
                              cleanup_end_ns=request.hard_end_ns)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "refused", reason="private exception text", first_failure_ns=request.work_end_ns,
                          cleanup_end_ns=request.hard_end_ns)

    def test_branch_list_uses_existing_read_envelope_and_closed_empty_options(self):
        value = row(); del value["phase"], value["reviewDigest"], value["journalRevision"]
        value["protocol"] = read_wire.PROTOCOL
        value["action"] = {"kind": "branches", "expectedRevision": "a" * 64, "paths": [], "staged": False}
        request = read_wire.parse_request(old_wire.frame(value))
        result = core_branch.Branches("a" * 64, "b" * 64, "1" * 40, "refs/heads/main",
                                     (core_branch.Branch("refs/heads/main", "1" * 40),))
        encoded = read_wire.terminal(request, "ok", reason=None, result=result,
            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        self.assertEqual(json.loads(encoded)["result"], result.as_dict())
        for field, changed in (("paths", ["file"]), ("staged", True), ("expectedRevision", None)):
            malformed = dict(value); malformed["action"] = {**value["action"], field: changed}
            with self.assertRaises(read_wire.ProtocolError): read_wire.parse_request(old_wire.frame(malformed))


class BranchWorkerTests(unittest.TestCase):
    # Helpers only: never inherit/run the old core test class.
    setUp = fixture.BranchTests.setUp
    write = fixture.BranchTests.write
    repo = fixture.BranchTests.repo
    prepared = fixture.BranchTests.prepared
    release_fixture_descriptors = fixture.BranchTests.release_fixture_descriptors

    @contextmanager
    def operation(self, *, phase="apply", read_only=False):
        _, review, _ = self.prepared()
        value = row(phase=phase)
        value["action"] = branch.Action(review.plan._snapshot.public.revision,
                                       review.plan.reference_revision, "next").as_dict()
        if phase == "apply": value["reviewDigest"] = review.digest
        if read_only:
            del value["phase"], value["reviewDigest"], value["journalRevision"]
            value["protocol"] = read_wire.PROTOCOL
            value["action"] = {"kind": "branches", "expectedRevision": review.plan._snapshot.public.revision,
                               "paths": [], "staged": False}
        tool = self.base / "inert-tool"; tool.write_bytes(b"not executable, DATA only")
        def snapshot(path):
            return read_wire.FileSnapshot(path, read_wire.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        # Explicit DATA substitution. Production correctly refuses UID0 and
        # this non-provider file; no native capability is represented here.
        codec = read_wire if read_only else wire
        request = replace(codec.parse_request(old_wire.frame(value)), uid=os.getuid(), gid=os.getgid(), root=self.root,
            directories=tuple((p, read_wire.directory_identity(p.stat())) for p in
                              (self.root, self.root / ".git", self.root / ".git/objects")),
            tool=snapshot(tool), files=tuple(snapshot(self.root / ".git" / n) for n in ("HEAD", "config", "index")))
        engine = (ReadEngine if read_only else _Engine)(time.monotonic()); source, guard = engine.input, engine.guard
        engine.request = source.initial = request; source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)  # No FD0/signal acquisition.
        operation = engine.operation = (GitReadOperation(request, source, guard) if read_only else
                                        GitLocalOperation(request, source, guard, engine))
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

    @staticmethod
    def ack(operation):
        return (b"MRK-GIT-LOCAL-ACK/1 " + operation.request.digest.encode() + b" "
                + operation.source.candidate.digest.encode() + b" 5\n")

    def test_actual_worker_prepare_uses_fresh_branch_core_without_diff_or_handoff(self):
        with self.operation(phase="prepare") as (op, calls):
            op.admit()
            with patch.object(op.engine, "write") as output: op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.review), core_branch.BranchReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result)
            output.assert_not_called(); self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(calls.call_count, op.calls)

    def test_actual_read_worker_lists_branches_without_mutation_admission(self):
        with self.operation(read_only=True) as (op, calls):
            op.admit(); op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.result), core_branch.Branches)
            self.assertEqual([entry.ref for entry in op.result.branches], ["refs/heads/main"])
            self.assertEqual(calls.call_count, op.calls)
            self.assertFalse(any(call[0][0] == "update-ref" for call in self.fake.calls))
            self.assertIsNone(op.repository._transaction)

    def test_actual_worker_single_ack_cas_preserves_and_closes_original_index(self):
        with self.operation() as (op, calls):
            op.admit(); old = op.index_original; fd = old.fd
            with patch.object(op.engine, "write") as output, \
                    patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(op.result.state, "succeeded"); output.assert_called_once()
            self.assertEqual(op.publication(), branch.PUBLICATION)
            self.assertIs(op.index_original, old); self.assertEqual(old.fd, fd)
            self.assertEqual(os.fstat(fd).st_nlink, 1); self.assertIsNone(op.index_successor)
            self.assertEqual(calls.call_count, op.calls)
            self.assertEqual(sum(call[0][0] == "update-ref" for call in self.fake.calls), 1)
            op.cleanup(); self.assertTrue(old.closed)
            with self.assertRaises(OSError): os.fstat(fd)

    def test_lost_candidate_ack_never_publishes_or_becomes_retryable(self):
        with self.operation() as (op, _):
            op.admit(); lost = KeyboardInterrupt("synthetic branch ACK lost")
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lost):
                with self.assertRaises(KeyboardInterrupt) as error: op.run()
                self.assertIs(error.exception, lost)
            self.assertTrue(op.source.candidate_claimed); self.assertFalse(op.source.candidate_returned)
            self.assertFalse(any(call[0][0] == "update-ref" for call in self.fake.calls))
            self.assertEqual(op.publication(), "not-reported")
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)

    def test_unpublished_caw_result_never_supplies_branch_receipt(self):
        with self.operation(phase="prepare") as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake):
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.returned)
            self.assertFalse(any(call[0][0] == "update-ref" for call in self.fake.calls))
