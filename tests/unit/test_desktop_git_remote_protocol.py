"""Strict Fetch DATA/private-frame tests; no actual source/FD/process/network."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_remote_protocol as wire
from mobile_release import _git_remote_private_protocol as private
from mobile_release import git_repository_fetch as fetch
from mobile_release import git_fetch_transaction as tx
from mobile_release import git_repository_local as local
from mobile_release import git_service as core
from mobile_release.git_remote_transport import Target
from mobile_release.git_remote_wire import Selection
import test_desktop_git_local_protocol as local_fixture


def frame(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture(*, phase="prepare"):
    row = local_fixture.fixture(phase=phase)
    row["protocol"] = wire.PROTOCOL
    row["action"] = {"kind": "fetch", "expectedRevision": "a" * 64, "expectedReferenceRevision": "c" * 64,
        "remote": "origin", "reference": "refs/heads/main", "connectionSessionId": "connection-fixture",
        "expectedConnectionRevision": 8}
    row["target"] = {"repository": "fixture/project", "login": "selected-user", "accountId": "11", "repositoryId": "22",
                     "reference": "refs/heads/main", "oid": "7" * 40 if phase == "apply" else None}
    return row


def compared():
    row = fixture(phase="apply")
    request = wire.parse_request(frame(row))
    before = core.Observation(request.action.expected_revision, "1" * 40, "refs/heads/main", (), ("origin",), ())
    index = core._Stamp("file", (1, 3, stat.S_IFREG | 0o600, 12, 123, 456), "2" * 64)
    snapshot = core._Snapshot(before, {}, index, b"inert index", {}, {}, {}, {})
    logging = fetch._Log(Path("/inert/log"), core._ABSENT, b"", (), False,
                         core.CommitIdentity("Fixture", "fixture@example.invalid"))
    plan = fetch.FetchPlan("origin", request.target, request.action.expected_reference_revision,
                           "6" * 40, object(), snapshot, logging)
    review = fetch.FetchReview(plan, fetch._review_digest(plan))
    row["reviewDigest"] = review.digest
    request = wire.parse_request(frame(row))
    intent = fetch.FetchIntent(review.digest, before.revision, plan.reference_revision, before.branch, before.head,
        index.digest, plan.target_ref, plan.expected_target, plan.target.selected.oid, "8" * 40, "9" * 64, 100, "0" * 64, 50)
    return request, review, intent


def keep(sent):
    size = len(b"mrk-git-fetch/1 " + sent.intent.review_digest.encode() + b"\n")
    identity = (1, 9, stat.S_IFREG | 0o600, size, 10, 11, os.getuid(), os.getgid(), 1)
    parent = (1, 8, stat.S_IFDIR | 0o700, 0, 10, 11, os.getuid(), os.getgid())
    return tx.BorrowedKeep(sent.intent.pack_oid, sent.intent.review_digest, identity, parent, parent)


def ack(request, sent, marker=None):
    marker = marker or keep(sent)
    return {"protocol": wire.PROTOCOL, "kind": "ack", "id": request.id, "digest": request.digest,
        "candidateDigest": sent.digest, "journalRevision": request.journal_revision + 1,
        "keep": {"packOid": marker.pack_oid, "reviewDigest": marker.review_digest,
                 "identity": list(marker.identity), "parentBefore": list(marker.parent_before), "parentAfter": list(marker.parent_after)}}


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("no process in Fetch DATA tests"))
        guard.start(); self.addCleanup(guard.stop)

    def test_exact_prepare_apply_source_fields_are_comparisons_only(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(frame(fixture(phase=phase)))
            self.assertEqual((request.phase, request.action.kind, request.target.account_id), (phase, "fetch", "11"))
            self.assertEqual(request.tool.path, wire.TOOL_PATH)
            self.assertNotIn("selected-user", repr(request))
            self.assertNotIn("selected-user", repr(request.target))
        for key, value in (("token", "synthetic"), ("argv", []), ("credential", {}), ("url", "https://other.invalid")):
            row = fixture(); row[key] = value
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))

    def test_wrong_phase_target_or_control_cannot_upgrade_metadata(self):
        for phase, field, value in (("prepare", "reviewDigest", "a" * 64), ("prepare", "journalRevision", 1),
                                   ("apply", "journalRevision", None), ("apply", "reviewDigest", None)):
            row = fixture(phase=phase); row[field] = value
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        for phase in ("prepare", "apply"):
            row = fixture(phase=phase); row["target"]["oid"] = "7" * 40 if phase == "prepare" else None
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        row = fixture(); row["target"]["reference"] = "refs/heads/other"
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(row))

    def test_public_action_matches_frozen_remote_ref_connection_bounds(self):
        for field, values in (("remote", ("-x", "origin/path", "x" * 65)),
            ("reference", ("main", "refs/heads/../x", "refs/heads/é", "refs/heads/" + "a" * 256)),
            ("connectionSessionId", ("", "with space", "x" * 65)),
            ("expectedConnectionRevision", (0, True, (1 << 32) - 1))):
            for value in values:
                row = fixture(); row["action"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(frame(row))

    def test_duplicate_secret_or_extra_lines_do_not_echo_input(self):
        raw = frame(fixture())
        for bad in (raw + b"\n", raw.replace(b'"phase":', b'"phase":"apply","phase":'), b"x" * (wire.REQUEST_LIMIT + 1)):
            with self.assertRaises(wire.ProtocolError) as caught:
                wire.parse_request(bad)
            self.assertLess(len(str(caught.exception)), 100)
        request = wire.parse_request(raw)
        go = {"protocol": wire.PROTOCOL, "kind": "go", "id": request.id, "digest": request.digest, "token": "inert-not-a-credential"}
        self.assertEqual(wire.private_go(request, frame(go)), go["token"])
        go["digest"] = "0" * 64
        with self.assertRaises(wire.ProtocolError) as caught:
            wire.private_go(request, frame(go))
        self.assertNotIn(go["token"], str(caught.exception))

    def test_same_candidate_exact_ack_and_native_keep_are_not_interchangeable(self):
        request, review, intent = compared()
        sent = wire.candidate(request, review, intent)
        self.assertEqual(sent.digest, hashlib.sha256(sent.raw).hexdigest())
        revision, marker = wire.acknowledged(request, sent, frame(ack(request, sent)))
        self.assertEqual(revision, request.journal_revision + 1)
        self.assertEqual(marker.pack_oid, intent.pack_oid)
        for field, value in (("candidateDigest", "a" * 64), ("journalRevision", revision + 1), ("id", "foreign")):
            row = ack(request, sent); row[field] = value
            with self.assertRaises(wire.ProtocolError):
                wire.acknowledged(request, sent, frame(row))
        row = ack(request, sent); row["keep"]["packOid"] = "1" * 40
        with self.assertRaises(wire.ProtocolError):
            wire.acknowledged(request, sent, frame(row))

    def test_changed_complete_intent_or_equal_tip_is_not_a_candidate(self):
        request, review, intent = compared()
        for change in (dict(expected_target="5" * 40), dict(expected_index="3" * 64), dict(target_ref="refs/remotes/origin/other"),
                       dict(candidate_ref_oid=intent.expected_target), dict(pack_bytes=tx.FILE_LIMIT + 1)):
            with self.assertRaises(wire.ProtocolError):
                wire.candidate(request, review, replace(intent, **change))

    def test_terminal_requires_actual_positive_publication_not_only_success_data(self):
        request, review, intent = compared()
        result = core.MutationResult(request.id, "fetch", "succeeded", "settled", None, None, intent)
        values = dict(result=result, effect_phase="ref-published", first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, **values)
        sent = wire.candidate(request, review, intent)
        stamp = core._Stamp("file", (1, 9, stat.S_IFREG | 0o600, 41, 10, 11), "1" * 64)
        reference = local._RefSuccessor(intent.target_ref, intent.candidate_ref_oid, stamp, (1, 8, stat.S_IFDIR | 0o700, 0, 10, 11))
        returned = tx.Publication(intent, reference, (1,) * 9, (2,) * 9, keep(sent), None, None, "ref-published")
        row = json.loads(wire.terminal(request, "ok", reason=None, publication=returned, **values))
        self.assertEqual(row["publication"]["reference"]["name"], intent.target_ref)
        self.assertIsNone(row["result"]["observation"])

    def test_unknown_never_becomes_a_settled_core_failure_or_exposes_intent(self):
        request, _, intent = compared()
        for reason in ("unknown", "cleanup-unknown"):
            result = core.MutationResult(request.id, "fetch", "recovery-required", "settled", reason, None, intent)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, result=result, first_failure_ns=95_000_000_000,
                              cleanup_end_ns=105_000_000_000)
        row = json.loads(wire.terminal(request, "cleanup-unknown", reason="unknown", first_failure_ns=None,
                                       cleanup_end_ns=request.hard_end_ns))
        self.assertIsNone(row["result"])
        self.assertIsNone(row["publication"])


class PrivateTests(unittest.TestCase):
    def binding(self):
        return private.Binding("fixture", "a" * 64, "origin", Target("fixture/project", "selected-user", "11", "22",
            Selection("refs/heads/main", "7" * 40)), 100_000_000_000, 110_000_000_000, bytes(16), (1001, 2, 3))

    def test_exact_private_challenge_and_eight_field_request_roundtrip(self):
        binding = self.binding()
        self.assertEqual(private.challenge(binding.challenge()), binding)
        for action in ("get", "store", "erase"):
            request = binding.request(action)
            self.assertEqual(len(json.loads(request)), 8)
            self.assertEqual(binding.accept_request(request), action)
        self.assertNotIn("selected-user", repr(binding))

    def test_wrong_source_clock_or_request_identity_refuses_without_echo(self):
        binding = self.binding()
        for change in (dict(operation_id="contains spaces"), dict(hard_end_ns=binding.work_end_ns + 1), dict(identity=(True, 2, 3))):
            with self.assertRaises(private.PrivateError):
                replace(binding, **change)
        for key, value in (("accountId", "12"), ("remote", "other"), ("login", "other"), ("repository", "other/project")):
            row = json.loads(binding.request()); row[key] = value
            with self.assertRaises(private.PrivateError):
                binding.accept_request(frame(row))
        raw = binding.challenge().replace(b'"nonce":', b'"nonce":"bad","nonce":')
        with self.assertRaises(private.PrivateError):
            private.challenge(raw)

    def test_private_grant_is_bounded_exact_digest_and_never_in_error(self):
        binding = self.binding()
        value = "inert-not-a-token"
        self.assertEqual(binding.accept_grant(binding.grant(value)), value)
        for value in ("", "x" * 4097, "token\nmore", "a b", "é"):
            with self.assertRaises(private.PrivateError) as caught:
                binding.grant(value)
            self.assertEqual(str(caught.exception), "The original private Git credential dialogue was refused.")
        raw = binding.grant("inert-not-a-token").replace(b'"a' + b"a" * 63 + b'"', b'"b' + b"b" * 63 + b'"')
        with self.assertRaises(private.PrivateError):
            binding.accept_grant(raw)


if __name__ == "__main__":
    unittest.main()
