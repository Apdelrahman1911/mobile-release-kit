"""Finite GitLocal DATA tests only; no process, source admission or journal.

Synthetic private core objects below exercise comparison/codec rules, not an
original native prepare, consent, Store ACK or process-finality capability.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import stat
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import git_repository_local as local
from mobile_release import git_service as core


def frame(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture(kind="stage", *, phase="prepare"):
    def file(uid, mode=0o600):
        return {"identity": [1, 2, stat.S_IFREG | mode, uid, 1001, 1, 12, 123, 456], "sha256": "a" * 64}
    directory = [1, 2, stat.S_IFDIR | 0o700, 1001, 1001]
    commit = kind == "commit"
    return {"protocol": wire.PROTOCOL, "id": "local-fixture", "phase": phase,
        "action": {"kind": kind, "expectedRevision": "a" * 64, "paths": [] if commit else ["a.txt"],
                   "message": "Reviewed staged set\n" if commit else None,
                   "identity": {"name": "Fixture", "email": "fixture@example.invalid"} if commit else None},
        "reviewDigest": "b" * 64 if phase == "apply" else None, "journalRevision": 4 if phase == "apply" else None,
        "context": {"projectId": "runtime-alias", "generation": 1, "revision": "2"},
        "native": {"uid": 1001, "gid": 1001, "root": "/fixture/project",
            "directories": {name: list(directory) for name in ("root", "git", "objects")},
            "tool": file(0, 0o755), "files": {name: file(1001) for name in ("HEAD", "config", "index")}},
        "clock": {"workEndNs": 100_000_000_000, "hardEndNs": 110_000_000_000}}


def compared(kind="stage", *, phase="apply", unborn=False):
    value = fixture(kind, phase=phase)
    selected = wire.action(value["action"])
    before = core.Observation(selected.expected_revision, None if unborn else "1" * 40,
        "refs/heads/main", (), (), ())
    index = core._Stamp("file", (1, 3, stat.S_IFREG | 0o600, 12, 123, 456), "2" * 64)
    snapshot = core._Snapshot(before, {}, index, b"inert index", {}, {}, {}, {})
    paths = ("a.txt", "b.txt") if kind == "commit" else selected.paths
    plan = core.GitPlan(kind, paths, object(), snapshot, {}, selected.message, selected.identity)
    review = local.LocalReview(plan, local._review_digest(plan))
    if phase == "apply":
        value["reviewDigest"] = review.digest
    request = wire.parse_request(frame(value))
    intent = core.PublicationIntent(kind, selected.expected_revision, before.branch, before.head, index.digest,
                                   None if kind == "commit" else "3" * 64, "4" * 40 if kind == "commit" else None)
    return request, review, intent


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("No process in GitLocal DATA tests"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_closed_three_actions_never_command_or_path_provider_endpoint(self):
        for kind in ("stage", "unstage", "commit"):
            request = wire.parse_request(frame(fixture(kind)))
            self.assertEqual(request.action.kind, kind)
            self.assertEqual(str(request.tool.path), "/Library/Developer/CommandLineTools/usr/bin/git")
            self.assertEqual(request.project_id, "runtime-alias")
            self.assertNotIn("Fixture", repr(request))
            self.assertNotIn("fixture@example", repr(request.action))
        for kind in ("add", "reset", "fetch", "push", "branch", "checkout", "config", None, ["stage"]):
            with self.subTest(kind=kind), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(fixture(kind)))
        for key, value in (("argv", ["git", "status"]), ("environment", {}), ("executable", "/usr/bin/git"),
                           ("authority", True), ("storedProjectId", "a" * 32)):
            row = fixture(); row["native"][key] = value
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))

    def test_prepare_has_no_journal_or_candidate_authority_and_apply_binds_revision(self):
        for phase in ("prepare", "apply"):
            for field, bad in (("reviewDigest", None if phase == "apply" else "b" * 64),
                               ("journalRevision", None if phase == "apply" else 4)):
                row = fixture(phase=phase); row[field] = bad
                with self.subTest(phase=phase, field=field), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(frame(row))
        for revision in (0, -1, True, 1 << 64, (1 << 64) - 1, "4", 4.0):
            row = fixture(phase="apply"); row["journalRevision"] = revision
            with self.subTest(revision=revision), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))

    def test_stage_paths_are_explicit_sorted_bounded_and_commit_paths_are_whole_index(self):
        for paths in ([], ["b", "a"], ["a", "a"], [".git/config"], ["../a"], ["/a"],
                      ["a\nother"], ["a/" * 33 + "file"], ["\ud800"], [f"{n:02}" for n in range(65)]):
            row = fixture(); row["action"]["paths"] = paths
            with self.subTest(paths=paths), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        row = fixture("commit"); row["action"]["paths"] = ["a.txt"]
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(row))
        row = fixture(); row["action"]["message"] = "not a staging option"
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(row))

    def test_commit_inputs_are_literal_bounded_and_secret_patterns_refuse(self):
        for message in ("", "  ", "x" * 4097, "line\rreturn", "x\0y", "ghp_" + "x" * 30,
                        "-----BEGIN PRIVATE KEY-----", "\ud800"):
            row = fixture("commit"); row["action"]["message"] = message
            with self.subTest(length=len(message)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        row = fixture("commit"); row["action"]["message"] = "--not-a-Git-option\nsecond line"
        self.assertEqual(wire.parse_request(frame(row)).action.message, row["action"]["message"])
        for identity in (None, {"name": "a", "email": "b", "sign": True},
                         {"name": "a\nb", "email": "a@example.invalid"}, {"name": "", "email": "a"}):
            row = fixture("commit"); row["action"]["identity"] = identity
            with self.subTest(identity=identity), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))

    def test_current_native_snapshot_shape_and_single_original_clock(self):
        for field, replacement in (("uid", 0), ("root", "/a/../b"), ("root", "/a//b")):
            row = fixture(); row["native"][field] = replacement
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        for index, replacement in ((2, stat.S_IFREG | 0o4755), (3, 1001), (5, 2), (6, wire.TOOL_LIMIT + 1)):
            row = fixture(); row["native"]["tool"]["identity"][index] = replacement
            with self.subTest(index=index), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        for value in (True, 0, 100_000_000_000, 111_000_000_000, 1 << 63):
            row = fixture(); row["clock"]["hardEndNs"] = value
            with self.subTest(value=value), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))

    def test_duplicate_nested_coalesced_float_and_oversized_input_refuse(self):
        raw = frame(fixture())
        for bad in (raw + raw, raw + b"\n", b"x" * (wire.REQUEST_LIMIT + 1),
                    raw.replace(b'"generation":1', b'"generation":1,"generation":1'),
                    raw.replace(b'"generation":1', b'"generation":1.0'),
                    b'{"a":' * 10 + b"null" + b"}" * 10 + b"\n"):
            with self.subTest(length=len(bad)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(bad)

    def test_ready_and_go_match_exact_request_bytes_not_an_alias(self):
        request = wire.parse_request(frame(fixture()))
        self.assertEqual(json.loads(wire.ready(request))["digest"], hashlib.sha256(frame(fixture())).hexdigest())
        self.assertEqual(wire.go(request), b"MRK-GIT-LOCAL-GO/1 " + request.digest.encode() + b"\n")

    def test_candidate_binds_full_review_and_exact_original_index_head_ref(self):
        for kind in ("stage", "unstage", "commit"):
            request, review, intent = compared(kind)
            sent = wire.candidate(request, review, intent)
            self.assertEqual(json.loads(sent.raw)["intent"], intent.as_dict())
            self.assertEqual(sent.digest, hashlib.sha256(sent.raw).hexdigest())
            for changed in (replace(intent, expected_index="f" * 64), replace(intent, expected_head="5" * 40),
                            replace(intent, expected_ref="refs/heads/other"), replace(intent, action="reset")):
                with self.subTest(kind=kind), self.assertRaises(wire.ProtocolError):
                    wire.candidate(request, review, changed)
        request, review, intent = compared("commit")
        review.plan._message = "changed draft"
        with self.assertRaises(wire.ProtocolError):
            wire.candidate(request, review, intent)

    def test_only_one_candidate_shape_and_no_prepare_candidate(self):
        for kind, changes in (("stage", {"candidate_commit": "4" * 40}),
                              ("commit", {"candidate_index": "3" * 64}), ("commit", {"candidate_commit": "bad"})):
            request, review, intent = compared(kind)
            with self.subTest(kind=kind), self.assertRaises(wire.ProtocolError):
                wire.candidate(request, review, replace(intent, **changes))
        request, review, intent = compared(phase="prepare")
        with self.assertRaises(wire.ProtocolError):
            wire.candidate(request, review, intent)

    def test_ack_exact_request_candidate_and_next_native_revision(self):
        request, review, intent = compared()
        sent = wire.candidate(request, review, intent)
        prefix = b"MRK-GIT-LOCAL-ACK/1 " + request.digest.encode() + b" " + sent.digest.encode() + b" "
        good = prefix + b"5\n"
        self.assertEqual(wire.acknowledged(request, sent, good), 5)
        # This codec is deliberately stateless; the actual input owns its
        # consumed latch. A reconstructed equal Request is not the original.
        with self.assertRaises(wire.ProtocolError):
            wire.acknowledged(replace(request), sent, good)
        for bad in (prefix + b"4\n", prefix + b"05\n", prefix + b"6\n", good + good,
                    good.replace(sent.digest.encode(), b"f" * 64), good + b"\n", b"GO\n"):
            with self.subTest(length=len(bad)), self.assertRaises(wire.ProtocolError):
                wire.acknowledged(request, sent, bad)

    def test_prepare_terminal_exposes_review_and_diff_not_draft_identity(self):
        request, review, _ = compared("commit", phase="prepare")
        diff = core.Diff(request.action.expected_revision, True, review.plan.paths, "inert diff", None)
        raw = wire.terminal(request, "ok", reason=None, review=review, diff=diff,
                            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        self.assertNotIn(b"fixture@example", raw)
        self.assertNotIn(b"Reviewed staged set", raw)
        self.assertTrue(json.loads(raw)["result"]["review"]["wholeIndex"])
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, review=review, diff=replace(diff, staged=False),
                          first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)

    def test_success_requires_positive_publication_but_never_proves_native_finality(self):
        request, _, intent = compared()
        observation = core.Observation("c" * 64, intent.expected_head, intent.expected_ref, (), (), ())
        result = core.MutationResult(request.id, "stage", "succeeded", "settled", None, observation, intent)
        raw = wire.terminal(request, "ok", reason=None, result=result, publication="index-returned",
                            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        self.assertNotIn("nativeFinality", json.loads(raw))
        for publication in ("not-reported", "ref-returned"):
            with self.subTest(publication=publication), self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, result=result, publication=publication,
                              first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, result=replace(result, settlement="unknown"),
                          publication="index-returned", first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)

    def test_failure_is_not_no_effect_and_first_failure_cleanup_cannot_renew(self):
        request, _, intent = compared()
        result = core.MutationResult(request.id, "stage", "recovery-required", "settled", "authorization", None, intent)
        raw = wire.terminal(request, "ok", reason=None, result=result, first_failure_ns=99_000_000_000,
                            cleanup_end_ns=109_000_000_000)
        self.assertEqual(json.loads(raw)["publication"], "not-reported")
        self.assertIsNotNone(json.loads(raw)["result"]["intent"])
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, result=result, first_failure_ns=99_000_000_000,
                          cleanup_end_ns=110_000_000_000)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "cleanup-unknown", reason="unknown", result=result,
                          first_failure_ns=None, cleanup_end_ns=request.hard_end_ns)
